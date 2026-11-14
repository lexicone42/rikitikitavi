//! `verify`: replay the scanners behind prior findings against only the affected hosts.

use crate::runner::{self, ReplayOutcome};
use rikitikitavi_core::Severity;
use rikitikitavi_models::config::{ExclusionSet, PortRange, ScanConfig, ScanIntensity};
use rikitikitavi_models::device::{OpenPort, PortProtocol};
use rikitikitavi_models::{Device, Finding, FindingFingerprint, ScanContext, ScanResults};
use rikitikitavi_scanners::Scanner;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing::Instrument as _;

/// Scanners whose probes go only to hosts in `discovered_devices` or inside `target_network`.
pub const REPLAYABLE: &[&str] = &[
    "cast",
    "credentials",
    "database",
    "http_audit",
    "kasa",
    "media_server",
    "mgmt-plane",
    "modbus",
    "mqtt",
    "nuclei-detect",
    "papercut",
    "ports",
    "print3d",
    "printers",
    "router",
    "rtsp",
    "services",
    "smb",
    "snmp",
    "ssl",
    "tr069",
];

/// Replayable scanners that take their targets from the ARP/neighbour table.
const ARP_DRIVEN: &[&str] = &["ports"];

/// Ports tried for liveness after the host's own known ports.
const FALLBACK_PROBE_PORTS: &[u16] = &[80, 443, 22];

/// Cap on TCP connects per liveness check.
const MAX_LIVENESS_PROBES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Resolved,
    StillPresent,
    Inconclusive,
}

impl Verdict {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Resolved => "RESOLVED",
            Self::StillPresent => "STILL PRESENT",
            Self::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// Which prior findings to verify.
#[derive(Debug, Default)]
pub struct Selection {
    pub min_severity: Option<Severity>,
    pub ips: Vec<IpAddr>,
    /// Fingerprint hex or finding UUID.
    pub findings: Vec<String>,
}

/// Default minimum severity when neither `--severity` nor `--finding` is given.
pub const DEFAULT_MIN_SEVERITY: Severity = Severity::Low;

/// Findings matching every given filter. A `--finding` token that matches nothing is an error.
pub fn select<'a>(findings: &'a [Finding], sel: &Selection) -> anyhow::Result<Vec<&'a Finding>> {
    let fps: Vec<Option<FindingFingerprint>> =
        sel.findings.iter().map(|t| t.parse().ok()).collect();
    for (token, fp) in sel.findings.iter().zip(&fps) {
        let hit = findings
            .iter()
            .any(|f| Some(f.fingerprint()) == *fp || f.id.to_string() == *token);
        anyhow::ensure!(
            hit,
            "no finding in the latest scan matches --finding {token}"
        );
    }
    let min = sel
        .min_severity
        .or_else(|| sel.findings.is_empty().then_some(DEFAULT_MIN_SEVERITY));
    Ok(findings
        .iter()
        .filter(|f| min.is_none_or(|m| f.severity >= m))
        .filter(|f| sel.ips.is_empty() || f.affected_ip.is_some_and(|ip| sel.ips.contains(&ip)))
        .filter(|f| {
            sel.findings.is_empty()
                || sel
                    .findings
                    .iter()
                    .zip(&fps)
                    .any(|(t, fp)| Some(f.fingerprint()) == *fp || f.id.to_string() == *t)
        })
        .collect())
}

/// One prior finding and its verdict.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyItem {
    pub fingerprint: String,
    pub scanner: String,
    pub title: String,
    pub severity: Severity,
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Findings skipped because an accepted-risk entry covers them.
#[derive(Debug, Clone, Serialize)]
pub struct AcceptedItem {
    pub fingerprint: String,
    pub title: String,
    pub ip: Option<IpAddr>,
    pub reason: String,
    pub expires: chrono::NaiveDate,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub baseline_scanned_at: chrono::DateTime<chrono::Utc>,
    pub resolved: usize,
    pub still_present: usize,
    pub inconclusive: usize,
    pub items: Vec<VerifyItem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub accepted: Vec<AcceptedItem>,
}

impl VerifyReport {
    fn new(baseline: &ScanResults, items: Vec<VerifyItem>) -> Self {
        let count = |v: Verdict| items.iter().filter(|i| i.verdict == v).count();
        let accepted = baseline
            .accepted
            .iter()
            .map(|a| AcceptedItem {
                fingerprint: a.fingerprint.to_string(),
                title: a.finding.title.clone(),
                ip: a.finding.affected_ip,
                reason: a.reason.clone(),
                expires: a.expires,
            })
            .collect();
        Self {
            baseline_scanned_at: baseline.scanned_at,
            resolved: count(Verdict::Resolved),
            still_present: count(Verdict::StillPresent),
            inconclusive: count(Verdict::Inconclusive),
            items,
            accepted,
        }
    }

    /// 0 all resolved (or nothing selected), 3 any still present, 4 only inconclusive remain.
    pub const fn exit_code(&self) -> i32 {
        if self.still_present > 0 {
            EXIT_STILL_PRESENT
        } else if self.inconclusive > 0 {
            EXIT_INCONCLUSIVE
        } else {
            0
        }
    }
}

pub const EXIT_STILL_PRESENT: i32 = 3;
pub const EXIT_INCONCLUSIVE: i32 = 4;

/// What the replay saw on one host.
#[derive(Debug, Default)]
pub struct HostOutcome {
    pub alive: bool,
    pub in_arp: bool,
    pub runs: HashMap<String, ReplayOutcome>,
}

/// Inputs shared by every host.
pub struct VerifyEnv<'a> {
    /// Intensity, perspective, parallelism and exclusions for every replay.
    pub config: ScanConfig,
    pub gateway: Option<IpAddr>,
    pub lookup: &'a dyn Fn(&str) -> Option<&'a dyn Scanner>,
    pub liveness_timeout: Duration,
    pub read_arp: &'a dyn Fn() -> Vec<IpAddr>,
}

/// Reason a finding cannot be replayed, decided before any probe.
fn precheck(
    f: &Finding,
    env: &VerifyEnv<'_>,
    exclusions: &ExclusionSet,
    excluded: &HashSet<IpAddr>,
    device: Option<&Device>,
) -> Option<String> {
    let Some(ip) = f.affected_ip else {
        return Some("finding has no host address".to_owned());
    };
    if exclusions.excludes_ip(ip)
        || excluded.contains(&ip)
        || device.is_some_and(|d| exclusions.excludes_device(d))
    {
        return Some("host excluded by scan config".to_owned());
    }
    if !REPLAYABLE.contains(&f.scanner.as_str()) {
        return Some(format!(
            "`{}` findings cannot be replayed by a unicast probe",
            f.scanner
        ));
    }
    let Some(scanner) = (env.lookup)(&f.scanner) else {
        return Some(format!("scanner `{}` is not available", f.scanner));
    };
    if !scanner
        .supported_perspectives()
        .contains(&env.config.perspective)
    {
        return Some(format!(
            "`{}` does not run from the {} perspective",
            f.scanner, env.config.perspective
        ));
    }
    if f.scanner == "credentials" && env.config.intensity != ScanIntensity::Aggressive {
        return Some("login checks need --aggressive".to_owned());
    }
    if f.scanner == "router" && env.gateway != Some(ip) {
        return Some("router checks run only against the current gateway".to_owned());
    }
    None
}

/// Verdict for `f` from what the replay saw on its host.
pub fn classify(f: &Finding, host: &HostOutcome) -> (Verdict, Option<String>) {
    let inconclusive = |why: String| (Verdict::Inconclusive, Some(why));
    if !host.alive {
        return inconclusive("host unreachable (no TCP answer, not in ARP table)".to_owned());
    }
    if ARP_DRIVEN.contains(&f.scanner.as_str()) && !host.in_arp {
        return inconclusive(format!(
            "host not in ARP/neighbour table; `{}` takes targets from it",
            f.scanner
        ));
    }
    match host.runs.get(&f.scanner) {
        None => inconclusive(format!("`{}` did not run", f.scanner)),
        Some(ReplayOutcome::Failed(e)) => inconclusive(format!("`{}` failed: {e}", f.scanner)),
        Some(ReplayOutcome::TimedOut) => inconclusive(format!("`{}` timed out", f.scanner)),
        Some(ReplayOutcome::Completed(found)) => {
            let fp = f.fingerprint();
            if found.iter().any(|n| n.fingerprint() == fp) {
                (Verdict::StillPresent, None)
            } else if let Some(n) = found.iter().find(|n| is_variant(f, n)) {
                (Verdict::StillPresent, Some(format!("now: {}", n.title)))
            } else {
                (Verdict::Resolved, None)
            }
        }
    }
}

/// Same scanner, host, port and CWE; a CWE is required when there is no port.
fn is_variant(old: &Finding, new: &Finding) -> bool {
    old.scanner == new.scanner
        && old.affected_ip == new.affected_ip
        && old.affected_port == new.affected_port
        && old.cwe_id == new.cwe_id
        && (old.affected_port.is_some() || old.cwe_id.is_some())
}

/// TCP connect to `ports`; a refused connect also counts as alive.
pub async fn tcp_alive(ip: IpAddr, ports: &[u16], timeout: Duration) -> bool {
    for &port in ports.iter().take(MAX_LIVENESS_PROBES) {
        match tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect(SocketAddr::new(ip, port)),
        )
        .await
        {
            Ok(Ok(_)) => return true,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => return true,
            _ => {}
        }
    }
    false
}

/// Prior device record for `ip` with every finding port added as an open TCP port.
fn narrowed_device(ip: IpAddr, baseline: &ScanResults, findings: &[&Finding]) -> Device {
    let mut device = baseline
        .devices
        .iter()
        .find(|d| d.ip == ip)
        .cloned()
        .unwrap_or_else(|| Device::new(ip));
    for port in findings.iter().filter_map(|f| f.affected_port) {
        if !device.open_ports.iter().any(|p| p.port == port) {
            device.open_ports.push(OpenPort {
                port,
                protocol: PortProtocol::Tcp,
                service: None,
                version: None,
                banner: None,
            });
        }
    }
    device
}

/// Context that reaches only `device`: `/32` (or `/128`) target network, one device, its ports.
fn narrowed_context(device: Device, env: &VerifyEnv<'_>, scanners: &[&str]) -> ScanContext {
    let prefix = if device.ip.is_ipv4() { 32 } else { 128 };
    let ports: Vec<u16> = device
        .open_ports
        .iter()
        .map(|p| p.port)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    ScanContext {
        target_network: format!("{}/{prefix}", device.ip).parse().ok(),
        gateway: env.gateway,
        perspective: env.config.perspective,
        network_mode: rikitikitavi_core::NetworkMode::Auto,
        config: ScanConfig {
            port_scan_range: PortRange::Custom(ports),
            modules: Some(scanners.iter().map(|s| (*s).to_owned()).collect()),
            ..env.config.clone()
        },
        discovered_devices: vec![device],
    }
}

async fn probe_host(device: Device, scanners: &[&str], env: &VerifyEnv<'_>) -> HostOutcome {
    let ip = device.ip;
    let mut ports: Vec<u16> = device.open_ports.iter().map(|p| p.port).collect();
    ports.extend(FALLBACK_PROBE_PORTS);
    ports.dedup();
    let tcp = tcp_alive(ip, &ports, env.liveness_timeout).await;
    let in_arp = (env.read_arp)().contains(&ip);
    let mut outcome = HostOutcome {
        alive: tcp || in_arp,
        in_arp,
        runs: HashMap::new(),
    };
    if !outcome.alive {
        return outcome;
    }
    let ctx = narrowed_context(device, env, scanners);
    let runs = futures::future::join_all(scanners.iter().filter_map(|id| {
        let scanner = (env.lookup)(id)?;
        let ctx = &ctx;
        Some(async move { ((*id).to_owned(), runner::replay_scanner(scanner, ctx).await) })
    }))
    .await;
    outcome.runs.extend(runs);
    outcome
}

/// Classify `selected` (findings of `baseline`). Hosts are probed one at a time.
pub async fn verify(
    baseline: &ScanResults,
    selected: &[&Finding],
    env: &VerifyEnv<'_>,
) -> anyhow::Result<VerifyReport> {
    let exclusions = env.config.exclusions()?;
    let excluded = runner::arp_ips_of_excluded_macs(&exclusions);

    let mut verdicts: HashMap<usize, (Verdict, Option<String>)> = HashMap::new();
    let mut by_host: BTreeMap<IpAddr, Vec<(usize, &Finding)>> = BTreeMap::new();
    for (i, f) in selected.iter().enumerate() {
        let device = f
            .affected_ip
            .and_then(|ip| baseline.devices.iter().find(|d| d.ip == ip));
        if let Some(why) = precheck(f, env, &exclusions, &excluded, device) {
            verdicts.insert(i, (Verdict::Inconclusive, Some(why)));
        } else if let Some(ip) = f.affected_ip {
            by_host.entry(ip).or_default().push((i, f));
        }
    }

    let span = runner::verify_span(selected.len(), by_host.len());
    async {
        for (ip, items) in &by_host {
            let findings: Vec<&Finding> = items.iter().map(|(_, f)| *f).collect();
            let scanners: Vec<&str> = findings
                .iter()
                .map(|f| f.scanner.as_str())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let device = narrowed_device(*ip, baseline, &findings);
            let host = probe_host(device, &scanners, env).await;
            for (i, f) in items {
                verdicts.insert(*i, classify(f, &host));
            }
        }
    }
    .instrument(span.clone())
    .await;

    let items: Vec<VerifyItem> = selected
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let (verdict, note) = verdicts
                .remove(&i)
                .unwrap_or_else(|| (Verdict::Inconclusive, Some("not probed".to_owned())));
            VerifyItem {
                fingerprint: f.fingerprint().to_string(),
                scanner: f.scanner.clone(),
                title: f.title.clone(),
                severity: f.severity,
                ip: f.affected_ip,
                port: f.affected_port,
                verdict,
                note,
            }
        })
        .collect();
    let report = VerifyReport::new(baseline, items);
    span.record("resolved", report.resolved);
    span.record("still_present", report.still_present);
    span.record("inconclusive", report.inconclusive);
    Ok(report)
}

/// Text table: one block per host, findings without a host last.
pub fn write_text<W: std::io::Write>(
    out: &mut W,
    report: &VerifyReport,
    baseline: &ScanResults,
) -> std::io::Result<()> {
    writeln!(
        out,
        "Verified {} finding(s) from the scan of {}",
        report.items.len(),
        report.baseline_scanned_at.format("%Y-%m-%d %H:%M")
    )?;
    let mut groups: BTreeMap<Option<IpAddr>, Vec<&VerifyItem>> = BTreeMap::new();
    for item in &report.items {
        groups.entry(item.ip).or_default().push(item);
    }
    let mut ordered: Vec<_> = groups.iter().filter(|(ip, _)| ip.is_some()).collect();
    ordered.extend(groups.iter().filter(|(ip, _)| ip.is_none()));
    for (ip, items) in ordered {
        writeln!(out)?;
        match ip {
            Some(ip) => {
                let label = baseline
                    .devices
                    .iter()
                    .find(|d| d.ip == *ip)
                    .map_or_else(String::new, crate::device_identity_label);
                writeln!(out, "{ip}  {label}")?;
            }
            None => writeln!(out, "(no host)")?,
        }
        for item in items {
            let port = item
                .port
                .map_or_else(String::new, |p| format!(" (port {p})"));
            writeln!(
                out,
                "  {:<13}  {:<8}  {}{port}  [{}]",
                item.verdict.label(),
                item.severity.to_string(),
                item.title,
                item.fingerprint
            )?;
            if let Some(note) = &item.note {
                writeln!(out, "  {:<13}  {:<8}  {note}", "", "")?;
            }
        }
    }
    if !report.accepted.is_empty() {
        writeln!(out)?;
        writeln!(out, "Accepted (not verified):")?;
        for a in &report.accepted {
            let ip = a.ip.map_or_else(String::new, |ip| format!("{ip}  "));
            writeln!(
                out,
                "  {ip}{}  [{}]  {} (expires {})",
                a.title, a.fingerprint, a.reason, a.expires
            )?;
        }
    }
    writeln!(out)?;
    writeln!(
        out,
        "Summary: {} resolved, {} still present, {} inconclusive",
        report.resolved, report.still_present, report.inconclusive
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rikitikitavi_core::{Perspective, ScanError};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn finding(scanner: &str, title: &str, host: &str, port: u16) -> Finding {
        Finding::new(scanner, title, "d", Severity::High)
            .with_ip(ip(host))
            .with_port(port)
    }

    fn alive_with(scanner: &str, outcome: ReplayOutcome) -> HostOutcome {
        HostOutcome {
            alive: true,
            in_arp: true,
            runs: HashMap::from([(scanner.to_owned(), outcome)]),
        }
    }

    #[test]
    fn offline_host_is_never_resolved() {
        let f = finding("http_audit", "Admin panel", "10.0.0.5", 80);
        let mut host = alive_with("http_audit", ReplayOutcome::Completed(Vec::new()));
        host.alive = false;
        host.in_arp = false;
        assert_eq!(classify(&f, &host).0, Verdict::Inconclusive);
    }

    #[test]
    fn clean_replay_resolves_and_matching_replay_is_still_present() {
        let f = finding("http_audit", "Admin panel", "10.0.0.5", 80);
        let clean = alive_with("http_audit", ReplayOutcome::Completed(Vec::new()));
        assert_eq!(classify(&f, &clean).0, Verdict::Resolved);
        let again = alive_with("http_audit", ReplayOutcome::Completed(vec![f.clone()]));
        assert_eq!(classify(&f, &again).0, Verdict::StillPresent);
    }

    #[test]
    fn error_timeout_and_missing_run_are_inconclusive() {
        let f = finding("ssl", "Expired cert", "10.0.0.5", 443);
        for outcome in [
            ReplayOutcome::Failed("boom".to_owned()),
            ReplayOutcome::TimedOut,
        ] {
            assert_eq!(
                classify(&f, &alive_with("ssl", outcome)).0,
                Verdict::Inconclusive
            );
        }
        let other = alive_with("smb", ReplayOutcome::Completed(Vec::new()));
        assert_eq!(classify(&f, &other).0, Verdict::Inconclusive);
    }

    #[test]
    fn retitled_finding_on_same_port_and_cwe_is_still_present() {
        let old = finding("ssl", "3 weak ciphers", "10.0.0.5", 443).with_cwe("CWE-327");
        let new = finding("ssl", "4 weak ciphers", "10.0.0.5", 443).with_cwe("CWE-327");
        let (v, note) = classify(
            &old,
            &alive_with("ssl", ReplayOutcome::Completed(vec![new])),
        );
        assert_eq!(v, Verdict::StillPresent);
        assert!(note.unwrap().contains("4 weak ciphers"));
    }

    #[test]
    fn arp_driven_scanner_needs_arp_entry() {
        let f = finding("ports", "Telnet open", "10.0.0.5", 23);
        let mut host = alive_with("ports", ReplayOutcome::Completed(Vec::new()));
        host.in_arp = false;
        assert_eq!(classify(&f, &host).0, Verdict::Inconclusive);
        host.in_arp = true;
        assert_eq!(classify(&f, &host).0, Verdict::Resolved);
    }

    #[test]
    fn select_filters_by_severity_ip_and_id() {
        let a = finding("ssl", "A", "10.0.0.1", 443);
        let b = Finding::new("ssl", "B", "d", Severity::Info).with_ip(ip("10.0.0.2"));
        let c = finding("smb", "C", "10.0.0.2", 445);
        let all = vec![a, b.clone(), c.clone()];
        let titles = |sel: &Selection| -> Vec<String> {
            select(&all, sel)
                .unwrap()
                .iter()
                .map(|f| f.title.clone())
                .collect()
        };
        assert_eq!(titles(&Selection::default()), ["A", "C"]);
        let by_ip = Selection {
            ips: vec![ip("10.0.0.2")],
            min_severity: Some(Severity::Info),
            ..Selection::default()
        };
        assert_eq!(titles(&by_ip), ["B", "C"]);
        let fingerprinted = Selection {
            findings: vec![b.fingerprint().to_string()],
            ..Selection::default()
        };
        assert_eq!(
            titles(&fingerprinted),
            ["B"],
            "--finding bypasses the default floor"
        );
        let by_uuid = Selection {
            findings: vec![c.id.to_string()],
            ..Selection::default()
        };
        assert_eq!(titles(&by_uuid), ["C"]);
        let unknown = Selection {
            findings: vec!["00000000000000ff".to_owned()],
            ..Selection::default()
        };
        assert!(select(&all, &unknown).is_err());
    }

    #[test]
    fn exit_codes() {
        let base = ScanResults::default();
        let item = |verdict| VerifyItem {
            fingerprint: String::new(),
            scanner: String::new(),
            title: String::new(),
            severity: Severity::High,
            ip: None,
            port: None,
            verdict,
            note: None,
        };
        let code = |vs: &[Verdict]| {
            VerifyReport::new(&base, vs.iter().map(|v| item(*v)).collect()).exit_code()
        };
        assert_eq!(code(&[]), 0);
        assert_eq!(code(&[Verdict::Resolved]), 0);
        assert_eq!(code(&[Verdict::Resolved, Verdict::Inconclusive]), 4);
        assert_eq!(code(&[Verdict::Inconclusive, Verdict::StillPresent]), 3);
        assert_ne!(EXIT_STILL_PRESENT, 2);
        assert_ne!(EXIT_INCONCLUSIVE, 2);
    }

    #[test]
    fn narrowed_context_reaches_only_the_host() {
        let f = finding("http_audit", "Admin panel", "10.0.0.5", 8080);
        let base = ScanResults {
            devices: vec![Device::new(ip("10.0.0.5")), Device::new(ip("10.0.0.6"))],
            ..Default::default()
        };
        let lookup = |_: &str| -> Option<&dyn Scanner> { None };
        let arp = Vec::new;
        let env = env(&lookup, &arp);
        let ctx = narrowed_context(
            narrowed_device(ip("10.0.0.5"), &base, &[&f]),
            &env,
            &["http_audit"],
        );
        let net = ctx.target_network.unwrap();
        assert!(net.contains(ip("10.0.0.5")));
        assert!(!net.contains(ip("10.0.0.6")));
        assert_eq!(ctx.discovered_devices.len(), 1);
        assert!(matches!(&ctx.config.port_scan_range, PortRange::Custom(p) if p == &[8080]));
        assert_eq!(
            ctx.config.modules.as_deref(),
            Some(&["http_audit".to_owned()][..])
        );
    }

    fn env<'a>(
        lookup: &'a dyn Fn(&str) -> Option<&'a dyn Scanner>,
        read_arp: &'a dyn Fn() -> Vec<IpAddr>,
    ) -> VerifyEnv<'a> {
        VerifyEnv {
            config: ScanConfig {
                intensity: ScanIntensity::Active,
                perspective: Perspective::Unauthenticated,
                ..ScanConfig::default()
            },
            gateway: None,
            lookup,
            liveness_timeout: Duration::from_millis(300),
            read_arp,
        }
    }

    /// Reports `Admin panel` on every device whose port is the listener's.
    struct FakeAudit {
        report_port: Option<u16>,
    }

    #[async_trait::async_trait]
    impl Scanner for FakeAudit {
        fn id(&self) -> &'static str {
            "http_audit"
        }
        fn name(&self) -> &'static str {
            "fake"
        }
        fn supported_perspectives(&self) -> &[Perspective] {
            &[Perspective::Unauthenticated]
        }
        async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
            Ok(ctx
                .discovered_devices
                .iter()
                .filter_map(|d| {
                    let port = self.report_port?;
                    Some(
                        Finding::new("http_audit", "Admin panel", "d", Severity::High)
                            .with_ip(d.ip)
                            .with_port(port),
                    )
                })
                .collect())
        }
    }

    #[tokio::test]
    async fn end_to_end_against_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let present = finding("http_audit", "Admin panel", "127.0.0.1", port);
        let mdns = Finding::new("mdns", "AirPlay", "d", Severity::Medium).with_ip(ip("127.0.0.1"));
        let offline = finding("http_audit", "Admin panel", "192.0.2.1", 80);
        let base = ScanResults {
            findings: vec![present.clone(), mdns.clone(), offline.clone()],
            ..Default::default()
        };
        let selected: Vec<&Finding> = base.findings.iter().collect();
        let arp = Vec::new;

        let still = FakeAudit {
            report_port: Some(port),
        };
        let lookup = |id: &str| -> Option<&dyn Scanner> {
            (id == "http_audit").then_some(&still as &dyn Scanner)
        };
        let report = verify(&base, &selected, &env(&lookup, &arp)).await.unwrap();
        let verdicts: Vec<Verdict> = report.items.iter().map(|i| i.verdict).collect();
        assert_eq!(
            verdicts,
            [
                Verdict::StillPresent,
                Verdict::Inconclusive,
                Verdict::Inconclusive
            ]
        );
        assert_eq!(report.exit_code(), EXIT_STILL_PRESENT);

        let fixed = FakeAudit { report_port: None };
        let lookup = |id: &str| -> Option<&dyn Scanner> {
            (id == "http_audit").then_some(&fixed as &dyn Scanner)
        };
        let report = verify(&base, &selected[..1], &env(&lookup, &arp))
            .await
            .unwrap();
        assert_eq!(report.items[0].verdict, Verdict::Resolved);
        assert_eq!(report.exit_code(), 0);

        let report = verify(&base, &selected[2..], &env(&lookup, &arp))
            .await
            .unwrap();
        assert_eq!(report.items[0].verdict, Verdict::Inconclusive);
        assert_eq!(report.exit_code(), EXIT_INCONCLUSIVE);
        drop(listener);
    }

    #[test]
    fn excluded_host_and_aggressive_only_checks_are_prechecked() {
        let lookup = |_: &str| -> Option<&dyn Scanner> { None };
        let arp = Vec::new;
        let mut e = env(&lookup, &arp);
        e.config.excluded_devices = vec!["10.0.0.9".to_owned()];
        let ex = e.config.exclusions().unwrap();
        let f = finding("ssl", "x", "10.0.0.9", 443);
        assert!(
            precheck(&f, &e, &ex, &HashSet::new(), None)
                .unwrap()
                .contains("excluded")
        );
        let creds = finding("credentials", "Default login", "10.0.0.8", 22);
        let fake = FakeAudit { report_port: None };
        let lookup = |_: &str| -> Option<&dyn Scanner> { Some(&fake as &dyn Scanner) };
        let mut e = env(&lookup, &arp);
        e.config.perspective = Perspective::Unauthenticated;
        assert!(
            precheck(&creds, &e, &ExclusionSet::default(), &HashSet::new(), None)
                .unwrap()
                .contains("--aggressive")
        );
    }

    #[test]
    fn replayable_ids_are_registered() {
        let registry = rikitikitavi_scanners::ScannerRegistry::new();
        for id in REPLAYABLE {
            assert!(registry.get(id).is_some(), "{id} not registered");
        }
    }
}
