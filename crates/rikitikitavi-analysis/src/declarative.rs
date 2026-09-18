//! User-extensible declarative checks (CP-11).
//!
//! A YAML rule file matches simple, total predicates over facts a scan already
//! collected — per device: open ports (service/version/banner), device type,
//! and the findings already raised — and emits a [`Finding`]. No code
//! execution, no regex: patterns are plain case-insensitive substrings with a
//! bounded length, so a rule file cannot loop, panic or wedge the scan.

use rikitikitavi_core::{Confidence, Severity};
use rikitikitavi_models::{Device, DeviceType, Finding, Remediation};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

/// Producing-module name stamped on every declarative finding. Fingerprint input.
const SCANNER: &str = "declarative";

/// Byte cap on a substring pattern (`banner_contains`, `has_finding`). Bounds
/// match cost and keeps rule files honest.
const MAX_PATTERN_BYTES: usize = 200;

/// Cap on rules per file.
const MAX_RULES: usize = 1000;

/// Cap on predicates per rule (across `all` and `any`).
const MAX_PREDICATES: usize = 64;

/// Version components compared by [`version_lt`]; beyond this the tail is ignored.
const MAX_VERSION_COMPONENTS: usize = 8;

/// One user rule: an identity, a match expression, and the finding to emit.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable slug, for the author's own reference.
    pub id: String,
    /// Finding title (fingerprint input — keep it version-free).
    pub title: String,
    /// Finding description.
    #[serde(default)]
    pub description: String,
    /// Finding severity: `info` | `low` | `medium` | `high` | `critical`.
    pub severity: Severity,
    /// Finding confidence: `inferred` | `probable` (capped — see [`run_rules`]).
    #[serde(default)]
    pub confidence: Option<Confidence>,
    /// Optional CWE id, e.g. `CWE-319`.
    #[serde(default)]
    pub cwe: Option<String>,
    /// Optional external references.
    #[serde(default)]
    pub references: Vec<String>,
    /// Optional remediation guidance.
    #[serde(default)]
    pub remediation: Option<RuleRemediation>,
    /// Match expression. A bare list is an implicit `all`.
    #[serde(rename = "match")]
    pub match_expr: Match,
}

/// Remediation block in a rule file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleRemediation {
    /// Summary line.
    pub description: String,
    /// Ordered steps.
    #[serde(default)]
    pub steps: Vec<String>,
    /// Free-text effort estimate.
    #[serde(default)]
    pub effort: Option<String>,
}

/// A rule's match expression.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Match {
    /// Implicit `all`: every predicate must hold.
    List(Vec<Predicate>),
    /// Explicit clauses.
    Clauses(MatchClauses),
}

/// `all` (every predicate holds) and `any` (at least one holds). A rule matches
/// a device when `all` holds and, if `any` is non-empty, at least one of `any`
/// holds.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchClauses {
    #[serde(default)]
    all: Vec<Predicate>,
    #[serde(default)]
    any: Vec<Predicate>,
}

/// A single, total predicate over one device's facts. Externally tagged: each
/// predicate is a one-key map, e.g. `{ port_open: 23 }`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    /// Device has this TCP/UDP port open.
    PortOpen(u16),
    /// Device type equals this wire name (`camera`, `nas`, `iot`, ...).
    DeviceTypeIs(String),
    /// Device already has a finding whose scanner id equals, or whose title
    /// contains (case-insensitive), this text.
    HasFinding(String),
    /// A banner/service/version on the device contains this text.
    BannerContains(BannerMatch),
    /// A service's parsed version is strictly below the given version.
    ServiceVersionLt(VersionMatch),
}

/// `banner_contains` payload: a bare string, or `{ port, text }` to scope it.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum BannerMatch {
    /// Match any open port's banner/service/version.
    Text(String),
    /// Match only the named port.
    Scoped {
        #[serde(default)]
        port: Option<u16>,
        text: String,
    },
}

/// `service_version_lt` payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionMatch {
    /// Restrict to this port.
    #[serde(default)]
    port: Option<u16>,
    /// Restrict to ports whose service name contains this (case-insensitive).
    #[serde(default)]
    service: Option<String>,
    /// Exclusive upper bound; dotted-numeric comparison. Accepts an unquoted
    /// number (`9.6`) or a string (`"1.27.0"`).
    #[serde(deserialize_with = "scalar_to_string")]
    version: String,
}

/// Deserialize a YAML scalar (string, integer or float) to its string form, so
/// an unquoted `version: 9.6` is accepted alongside `version: "1.27.0"`.
fn scalar_to_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    use serde::de::Error as _;
    match serde_yaml_ng::Value::deserialize(d)? {
        serde_yaml_ng::Value::String(s) => Ok(s),
        serde_yaml_ng::Value::Number(n) => Ok(n.to_string()),
        other => Err(D::Error::custom(format!(
            "expected a version scalar, got {other:?}"
        ))),
    }
}

/// A rule file: a bare list of rules, or `{ rules: [ ... ] }`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RuleFile {
    Wrapped { rules: Vec<Rule> },
    Bare(Vec<Rule>),
}

/// Parse and validate a rule file. Fails on malformed YAML, an over-long
/// pattern, an unknown device type, an empty match, or the size caps.
pub fn load_rules(path: &Path) -> anyhow::Result<Vec<Rule>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read rules file {}: {e}", path.display()))?;
    parse_rules(&text)
}

/// Parse and validate rules from YAML text.
pub fn parse_rules(text: &str) -> anyhow::Result<Vec<Rule>> {
    let file: RuleFile = serde_yaml_ng::from_str(text)?;
    let rules = match file {
        RuleFile::Wrapped { rules } | RuleFile::Bare(rules) => rules,
    };
    anyhow::ensure!(
        rules.len() <= MAX_RULES,
        "too many rules: {} (max {MAX_RULES})",
        rules.len()
    );
    for rule in &rules {
        validate_rule(rule)?;
    }
    Ok(rules)
}

/// Load a rule file and evaluate it against a scan's devices and findings.
pub fn evaluate_rule_file(
    path: &Path,
    devices: &[Device],
    existing: &[Finding],
) -> anyhow::Result<Vec<Finding>> {
    let rules = load_rules(path)?;
    let findings = run_rules(&rules, devices, existing);
    tracing::info!(
        rules = rules.len(),
        findings = findings.len(),
        "declarative rules evaluated"
    );
    Ok(findings)
}

/// Evaluate rules against every device; emit one [`Finding`] per match.
///
/// Confidence is clamped to at most [`Confidence::Probable`]: a rule reasons
/// over already-collected facts, it does not perform a fresh protocol exchange,
/// so it may never claim `Confirmed`.
#[must_use]
pub fn run_rules(rules: &[Rule], devices: &[Device], existing: &[Finding]) -> Vec<Finding> {
    let index = FindingIndex::build(existing);
    let mut out = Vec::new();
    for device in devices {
        let facts = DeviceFacts::new(device, &index);
        for rule in rules {
            if rule_matches(&rule.match_expr, &facts) {
                out.push(build_finding(rule, device));
            }
        }
    }
    out
}

/// Per-device view of the findings already raised, keyed by IP.
struct FindingIndex {
    by_ip: HashMap<IpAddr, FindingFacts>,
}

#[derive(Default)]
struct FindingFacts {
    scanners: Vec<String>,
    titles: Vec<String>,
}

impl FindingIndex {
    fn build(existing: &[Finding]) -> Self {
        let mut by_ip: HashMap<IpAddr, FindingFacts> = HashMap::new();
        for f in existing {
            if let Some(ip) = f.affected_ip {
                let e = by_ip.entry(ip).or_default();
                e.scanners.push(f.scanner.to_ascii_lowercase());
                e.titles.push(f.title.to_ascii_lowercase());
            }
        }
        Self { by_ip }
    }
}

/// Facts one rule sees for one device.
struct DeviceFacts<'a> {
    device: &'a Device,
    findings: Option<&'a FindingFacts>,
}

impl<'a> DeviceFacts<'a> {
    fn new(device: &'a Device, index: &'a FindingIndex) -> Self {
        Self {
            device,
            findings: index.by_ip.get(&device.ip),
        }
    }
}

/// A device satisfies a match when every `all` predicate holds and, if `any` is
/// present, at least one `any` predicate holds.
fn rule_matches(expr: &Match, facts: &DeviceFacts) -> bool {
    let (all, any): (&[Predicate], &[Predicate]) = match expr {
        Match::List(list) => (list, &[]),
        Match::Clauses(c) => (&c.all, &c.any),
    };
    let all_ok = all.iter().all(|p| eval(p, facts));
    let any_ok = any.is_empty() || any.iter().any(|p| eval(p, facts));
    all_ok && any_ok
}

/// Evaluate one predicate against one device.
fn eval(pred: &Predicate, facts: &DeviceFacts) -> bool {
    let dev = facts.device;
    match pred {
        Predicate::PortOpen(port) => dev.open_ports.iter().any(|p| p.port == *port),
        Predicate::DeviceTypeIs(name) => {
            DeviceType::from_name(&name.to_ascii_lowercase()).is_some_and(|t| t == dev.device_type)
        }
        Predicate::HasFinding(needle) => facts.findings.is_some_and(|f| {
            let lower = needle.to_ascii_lowercase();
            f.scanners.contains(&lower) || f.titles.iter().any(|t| t.contains(&lower))
        }),
        Predicate::BannerContains(m) => {
            let (port, text) = match m {
                BannerMatch::Text(t) => (None, t),
                BannerMatch::Scoped { port, text } => (*port, text),
            };
            let needle = text.to_ascii_lowercase();
            dev.open_ports
                .iter()
                .filter(|p| port.is_none_or(|want| p.port == want))
                .any(|p| port_text_contains(p, &needle))
        }
        Predicate::ServiceVersionLt(m) => dev
            .open_ports
            .iter()
            .filter(|p| m.port.is_none_or(|want| p.port == want))
            .filter(|p| service_matches(p.service.as_deref(), m.service.as_deref()))
            .any(|p| {
                p.version
                    .as_deref()
                    .is_some_and(|v| version_lt(v, &m.version))
            }),
    }
}

/// True when any of a port's service, version or banner contains `needle`
/// (already lowercased).
fn port_text_contains(port: &rikitikitavi_models::device::OpenPort, needle: &str) -> bool {
    let hit = |o: Option<&String>| o.is_some_and(|s| s.to_ascii_lowercase().contains(needle));
    hit(port.service.as_ref()) || hit(port.version.as_ref()) || hit(port.banner.as_ref())
}

/// A port's service satisfies an optional service filter (case-insensitive
/// substring). An absent filter matches any service.
fn service_matches(service: Option<&str>, filter: Option<&str>) -> bool {
    filter.is_none_or(|f| {
        service.is_some_and(|s| s.to_ascii_lowercase().contains(&f.to_ascii_lowercase()))
    })
}

/// Build the finding for a matched device.
fn build_finding(rule: &Rule, device: &Device) -> Finding {
    let confidence = rule
        .confidence
        .unwrap_or(Confidence::Inferred)
        .min(Confidence::Probable);

    let mut finding = Finding::new(SCANNER, &rule.title, &rule.description, rule.severity)
        .with_ip(device.ip)
        .with_confidence(confidence);

    if let Some(mac) = device.mac {
        finding = finding.with_mac(mac);
    }
    if let Some(host) = device.hostname.as_ref() {
        finding = finding.with_hostname(host.clone());
    }
    if let Some(port) = rule_port(&rule.match_expr) {
        finding = finding.with_port(port);
    }
    if let Some(cwe) = rule.cwe.as_ref() {
        finding = finding.with_cwe(cwe.clone());
    }
    if !rule.references.is_empty() {
        finding = finding.with_references(rule.references.clone());
    }
    if let Some(rem) = rule.remediation.as_ref() {
        finding = finding.with_remediation(Remediation {
            description: rem.description.clone(),
            steps: rem.steps.clone(),
            effort: rem.effort.clone(),
        });
    }
    finding
}

/// A single distinct port named across the rule's predicates, else `None`.
fn rule_port(expr: &Match) -> Option<u16> {
    let preds: &[Predicate] = match expr {
        Match::List(list) => list,
        Match::Clauses(c) => &c.all,
    };
    let mut found: Option<u16> = None;
    for p in preds {
        let port = match p {
            Predicate::PortOpen(port) => Some(*port),
            Predicate::BannerContains(BannerMatch::Scoped { port, .. })
            | Predicate::ServiceVersionLt(VersionMatch { port, .. }) => *port,
            _ => None,
        };
        if let Some(port) = port {
            match found {
                None => found = Some(port),
                Some(prev) if prev != port => return None,
                Some(_) => {}
            }
        }
    }
    found
}

/// Dotted-numeric less-than: split each string on non-digits and compare the
/// numeric components. Missing tail components read as zero; a leading `v` and
/// any suffix are ignored. Total (no panic on any input).
fn version_lt(left: &str, right: &str) -> bool {
    let lhs = version_key(left);
    let rhs = version_key(right);
    let len = lhs.len().max(rhs.len());
    (0..len)
        .find_map(|i| {
            let l = lhs.get(i).copied().unwrap_or(0);
            let r = rhs.get(i).copied().unwrap_or(0);
            (l != r).then_some(l < r)
        })
        .unwrap_or(false)
}

/// Numeric components of a version string, saturating and capped.
fn version_key(s: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let mut cur: Option<u64> = None;
    for b in s.bytes() {
        if b.is_ascii_digit() {
            let d = u64::from(b - b'0');
            cur = Some(cur.map_or(d, |v| v.saturating_mul(10).saturating_add(d)));
        } else if let Some(v) = cur.take() {
            out.push(v);
            if out.len() >= MAX_VERSION_COMPONENTS {
                return out;
            }
        }
    }
    if let Some(v) = cur {
        out.push(v);
    }
    out
}

/// Validate one rule: non-empty identity, bounded patterns, resolvable device
/// types, a non-empty match, and the predicate cap.
fn validate_rule(rule: &Rule) -> anyhow::Result<()> {
    anyhow::ensure!(!rule.id.trim().is_empty(), "a rule has an empty id");
    anyhow::ensure!(
        !rule.title.trim().is_empty(),
        "rule {:?} has an empty title",
        rule.id
    );

    let (all, any): (&[Predicate], &[Predicate]) = match &rule.match_expr {
        Match::List(list) => (list, &[]),
        Match::Clauses(c) => (&c.all, &c.any),
    };
    anyhow::ensure!(
        !all.is_empty() || !any.is_empty(),
        "rule {:?} has an empty match",
        rule.id
    );
    anyhow::ensure!(
        all.len() + any.len() <= MAX_PREDICATES,
        "rule {:?} has too many predicates (max {MAX_PREDICATES})",
        rule.id
    );

    for pred in all.iter().chain(any) {
        validate_predicate(rule, pred)?;
    }
    Ok(())
}

/// Bound pattern lengths and reject an unknown device-type name.
fn validate_predicate(rule: &Rule, pred: &Predicate) -> anyhow::Result<()> {
    let check_len = |s: &str| -> anyhow::Result<()> {
        anyhow::ensure!(
            s.len() <= MAX_PATTERN_BYTES,
            "rule {:?}: pattern exceeds {MAX_PATTERN_BYTES} bytes",
            rule.id
        );
        anyhow::ensure!(!s.is_empty(), "rule {:?}: empty pattern", rule.id);
        Ok(())
    };
    match pred {
        Predicate::PortOpen(_) => {}
        Predicate::DeviceTypeIs(name) => {
            anyhow::ensure!(
                DeviceType::from_name(&name.to_ascii_lowercase()).is_some(),
                "rule {:?}: unknown device_type {name:?}",
                rule.id
            );
        }
        Predicate::HasFinding(text) => check_len(text)?,
        Predicate::BannerContains(BannerMatch::Text(text) | BannerMatch::Scoped { text, .. }) => {
            check_len(text)?;
        }
        Predicate::ServiceVersionLt(m) => {
            check_len(&m.version)?;
            if let Some(service) = m.service.as_deref() {
                check_len(service)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
