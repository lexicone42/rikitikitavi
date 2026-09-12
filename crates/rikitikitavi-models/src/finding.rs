use crate::DeviceHint;
use chrono::{DateTime, Utc};
use rikitikitavi_core::{Confidence, Severity};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use uuid::Uuid;

/// Serde default for `Finding::confidence` (also used by `Finding::new`).
const fn default_confidence() -> Confidence {
    Confidence::Probable
}

/// Finding identity across scan runs: hash of `(scanner, title, affected_ip, affected_port)`.
/// Description, severity and service are excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingFingerprint(u64);

impl FindingFingerprint {
    /// The raw 64-bit fingerprint value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for FindingFingerprint {
    /// 16-char lowercase hex, e.g. `01a2b3c4d5e6f708` (baseline/suppression file form).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl std::str::FromStr for FindingFingerprint {
    type Err = std::num::ParseIntError;

    /// Parses the [`Display`](std::fmt::Display) hex form; `0x` prefix optional.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let hex = s.strip_prefix("0x").unwrap_or(s);
        u64::from_str_radix(hex, 16).map(Self)
    }
}

/// FNV-1a 64-bit hasher. Stable across Rust releases (unlike `DefaultHasher`),
/// so persisted fingerprints in baseline files remain valid.
struct Fnv1a64(u64);

impl Fnv1a64 {
    const fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Hasher for Fnv1a64 {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

/// A security finding produced by a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique finding ID.
    pub id: Uuid,
    /// Scanner module that produced this finding.
    pub scanner: String,
    /// Short title.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// Severity level.
    pub severity: Severity,
    /// Evidence strength; defaults to `Probable`.
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    /// Affected device IP (if applicable).
    pub affected_ip: Option<IpAddr>,
    /// Affected device MAC (if applicable).
    pub affected_mac: Option<String>,
    /// Affected device hostname.
    pub affected_hostname: Option<String>,
    /// Affected port (if applicable).
    pub affected_port: Option<u16>,
    /// Affected service name.
    pub affected_service: Option<String>,
    /// Remediation guidance.
    pub remediation: Option<Remediation>,
    /// CWE ID if applicable.
    pub cwe_id: Option<String>,
    /// CVE IDs if applicable.
    pub cve_ids: Vec<String>,
    /// Any CVE is in the CISA KEV catalog. Set during enrichment.
    #[serde(default)]
    pub is_kev: bool,
    /// Highest EPSS 30-day exploitation probability (0.0–1.0) among the CVEs. Set during enrichment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    /// External references.
    pub references: Vec<String>,
    /// Proof-of-concept evidence (banner, login prompt, directory listing, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Hint about the device that produced this finding, for enrichment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_hint: Option<DeviceHint>,
    /// When the finding was discovered.
    pub discovered_at: DateTime<Utc>,
}

impl Finding {
    /// Create a new finding with required fields, defaulting the rest.
    pub fn new(scanner: &str, title: &str, description: &str, severity: Severity) -> Self {
        Self {
            id: Uuid::new_v4(),
            scanner: scanner.to_owned(),
            title: title.to_owned(),
            description: description.to_owned(),
            severity,
            confidence: default_confidence(),
            affected_ip: None,
            affected_mac: None,
            affected_hostname: None,
            affected_port: None,
            affected_service: None,
            remediation: None,
            cwe_id: None,
            cve_ids: Vec::new(),
            is_kev: false,
            epss: None,
            references: Vec::new(),
            evidence: None,
            device_hint: None,
            discovered_at: Utc::now(),
        }
    }

    /// Builder-style setter for affected IP.
    #[must_use]
    pub const fn with_ip(mut self, ip: IpAddr) -> Self {
        self.affected_ip = Some(ip);
        self
    }

    /// Builder-style setter for affected port.
    #[must_use]
    pub const fn with_port(mut self, port: u16) -> Self {
        self.affected_port = Some(port);
        self
    }

    /// Builder-style setter for affected MAC address.
    #[must_use]
    pub fn with_mac(mut self, mac: impl Into<String>) -> Self {
        self.affected_mac = Some(mac.into());
        self
    }

    /// Builder-style setter for affected hostname.
    #[must_use]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.affected_hostname = Some(hostname.into());
        self
    }

    /// Builder-style setter for affected service name.
    #[must_use]
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.affected_service = Some(service.into());
        self
    }

    /// Builder-style setter for evidence confidence.
    #[must_use]
    pub const fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Builder-style setter for CWE ID.
    #[must_use]
    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe_id = Some(cwe.into());
        self
    }

    /// Builder-style setter for CVE IDs (e.g. `["CVE-2024-6387"]`).
    #[must_use]
    pub fn with_cve_ids(mut self, ids: Vec<String>) -> Self {
        self.cve_ids = ids;
        self
    }

    /// Builder-style setter for external references.
    #[must_use]
    pub fn with_references(mut self, refs: Vec<String>) -> Self {
        self.references = refs;
        self
    }

    /// Builder-style setter for remediation.
    #[must_use]
    pub fn with_remediation(mut self, remediation: Remediation) -> Self {
        self.remediation = Some(remediation);
        self
    }

    /// Builder-style setter for optional remediation (no-op if `None`).
    #[must_use]
    pub fn with_opt_remediation(mut self, remediation: Option<Remediation>) -> Self {
        if remediation.is_some() {
            self.remediation = remediation;
        }
        self
    }

    /// Hash of `(scanner, title, affected_ip, affected_port)`.
    pub fn fingerprint(&self) -> FindingFingerprint {
        let mut hasher = Fnv1a64::new();
        self.scanner.hash(&mut hasher);
        self.title.hash(&mut hasher);
        self.affected_ip.hash(&mut hasher);
        self.affected_port.hash(&mut hasher);
        FindingFingerprint(hasher.finish())
    }

    /// Builder-style setter for `PoC` evidence (truncated to 256 chars at a char boundary).
    #[must_use]
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        let s = evidence.into();
        if s.len() <= 256 {
            self.evidence = Some(s);
        } else {
            // Last char boundary at or before byte 256 (`floor_char_boundary` is above MSRV).
            let mut end = 256;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            self.evidence = Some(s[..end].to_owned());
        }
        self
    }

    /// Builder-style setter for device identification hint.
    #[must_use]
    pub fn with_device_hint(mut self, hint: DeviceHint) -> Self {
        self.device_hint = Some(hint);
        self
    }
}

impl PartialEq for Finding {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.scanner == other.scanner
            && self.title == other.title
            && self.description == other.description
            && self.severity == other.severity
            && self.affected_ip == other.affected_ip
            && self.affected_mac == other.affected_mac
            && self.affected_hostname == other.affected_hostname
            && self.affected_port == other.affected_port
            && self.affected_service == other.affected_service
            && self.cwe_id == other.cwe_id
            && self.cve_ids == other.cve_ids
            && self.references == other.references
            && self.evidence == other.evidence
            && self.device_hint == other.device_hint
    }
}

/// Remediation guidance for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remediation {
    /// Human-readable remediation steps.
    pub description: String,
    /// Step-by-step instructions.
    pub steps: Vec<String>,
    /// Estimated effort (e.g., "5 minutes", "requires hardware change").
    pub effort: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn fingerprint_display_hex_roundtrips_through_parse() {
        use std::str::FromStr;
        let f = Finding::new("ports", "Telnet open", "d", Severity::High)
            .with_ip("192.168.1.1".parse().unwrap())
            .with_port(23);
        let fp = f.fingerprint();
        let hex = fp.to_string();
        assert_eq!(hex.len(), 16, "fingerprint renders as 16 hex chars");
        assert_eq!(FindingFingerprint::from_str(&hex).unwrap(), fp);
        // 0x prefix is accepted too.
        assert_eq!(
            FindingFingerprint::from_str(&format!("0x{hex}")).unwrap(),
            fp
        );
        // Deterministic for the same identity fields.
        assert_eq!(f.fingerprint(), f.fingerprint());
    }

    #[test]
    fn confidence_defaults_to_probable_and_builder_overrides() {
        let f = Finding::new("s", "t", "d", Severity::Low);
        assert_eq!(f.confidence, Confidence::Probable);
        let c = f.with_confidence(Confidence::Confirmed);
        assert_eq!(c.confidence, Confidence::Confirmed);
    }

    #[test]
    fn confidence_survives_json_roundtrip_and_defaults_when_absent() {
        let f = Finding::new("s", "t", "d", Severity::High).with_confidence(Confidence::Confirmed);
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.confidence, Confidence::Confirmed);

        // A finding serialized before this field existed must still deserialize.
        let legacy = r#"{"id":"00000000-0000-0000-0000-000000000000","scanner":"s","title":"t","description":"d","severity":"low","affected_ip":null,"affected_mac":null,"affected_hostname":null,"affected_port":null,"affected_service":null,"remediation":null,"cwe_id":null,"cve_ids":[],"references":[],"discovered_at":"2026-07-02T00:00:00Z"}"#;
        let parsed: Finding = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.confidence, Confidence::Probable);
    }

    fn arb_severity() -> impl Strategy<Value = Severity> {
        prop_oneof![
            Just(Severity::Info),
            Just(Severity::Low),
            Just(Severity::Medium),
            Just(Severity::High),
            Just(Severity::Critical),
        ]
    }

    fn arb_ip() -> impl Strategy<Value = IpAddr> {
        prop_oneof![
            any::<u32>().prop_map(|n| IpAddr::V4(std::net::Ipv4Addr::from(n))),
            any::<u128>().prop_map(|n| IpAddr::V6(std::net::Ipv6Addr::from(n))),
        ]
    }

    fn arb_confidence() -> impl Strategy<Value = Confidence> {
        prop_oneof![
            Just(Confidence::Inferred),
            Just(Confidence::Probable),
            Just(Confidence::Confirmed),
        ]
    }

    fn edited(f: &Finding, edit: impl FnOnce(&mut Finding)) -> Finding {
        let mut g = f.clone();
        edit(&mut g);
        g
    }

    /// Arbitrary text, biased toward the `0x`/whitespace/case forms `from_str` accepts.
    fn arb_fingerprint_text() -> impl Strategy<Value = String> {
        prop_oneof!["\\PC{0,40}", "[ \\t]{0,2}(0x)?[0-9a-fA-F]{0,20}[ \\t]{0,2}",]
    }

    fn arb_finding() -> impl Strategy<Value = Finding> {
        (
            "[a-z]{1,10}",
            "[a-zA-Z0-9 ]{1,30}",
            "[a-zA-Z0-9 ]{1,60}",
            arb_severity(),
            proptest::option::of(arb_ip()),
            proptest::option::of(0_u16..=u16::MAX),
            proptest::option::of("[A-Z]{3,4}-[0-9]{1,5}"),
            proptest::option::of("[a-zA-Z0-9 ._:-]{1,100}"),
        )
            .prop_map(|(scanner, title, desc, sev, ip, port, cwe, evidence)| {
                let mut f = Finding::new(&scanner, &title, &desc, sev);
                if let Some(ip) = ip {
                    f = f.with_ip(ip);
                }
                if let Some(port) = port {
                    f = f.with_port(port);
                }
                if let Some(cwe) = cwe {
                    f = f.with_cwe(cwe);
                }
                if let Some(evidence) = evidence {
                    f = f.with_evidence(evidence);
                }
                f
            })
    }

    #[test]
    fn fingerprint_same_key_fields() {
        let f1 = Finding::new("ports", "Open port", "desc A", Severity::Low)
            .with_ip("10.0.0.1".parse().unwrap())
            .with_port(22);
        let f2 = Finding::new("ports", "Open port", "desc B", Severity::High)
            .with_ip("10.0.0.1".parse().unwrap())
            .with_port(22)
            .with_service("SSH");
        // Description, severity and service do not affect the fingerprint.
        assert_eq!(f1.fingerprint(), f2.fingerprint());
    }

    #[test]
    fn fingerprint_different_scanner() {
        let f1 = Finding::new("ports", "Open port", "desc", Severity::Low)
            .with_ip("10.0.0.1".parse().unwrap())
            .with_port(22);
        let f2 = Finding::new("services", "Open port", "desc", Severity::Low)
            .with_ip("10.0.0.1".parse().unwrap())
            .with_port(22);
        assert_ne!(f1.fingerprint(), f2.fingerprint());
    }

    #[test]
    fn fingerprint_different_title() {
        let f1 = Finding::new("ports", "Open SSH", "desc", Severity::Low)
            .with_ip("10.0.0.1".parse().unwrap())
            .with_port(22);
        let f2 = Finding::new("ports", "Weak SSH", "desc", Severity::Low)
            .with_ip("10.0.0.1".parse().unwrap())
            .with_port(22);
        assert_ne!(f1.fingerprint(), f2.fingerprint());
    }

    #[test]
    fn fingerprint_different_ip() {
        let f1 = Finding::new("ports", "Open", "d", Severity::Low)
            .with_ip("10.0.0.1".parse().unwrap())
            .with_port(22);
        let f2 = Finding::new("ports", "Open", "d", Severity::Low)
            .with_ip("10.0.0.2".parse().unwrap())
            .with_port(22);
        assert_ne!(f1.fingerprint(), f2.fingerprint());
    }

    #[test]
    fn fingerprint_different_port() {
        let f1 = Finding::new("ports", "Open", "d", Severity::Low)
            .with_ip("10.0.0.1".parse().unwrap())
            .with_port(22);
        let f2 = Finding::new("ports", "Open", "d", Severity::Low)
            .with_ip("10.0.0.1".parse().unwrap())
            .with_port(23);
        assert_ne!(f1.fingerprint(), f2.fingerprint());
    }

    #[test]
    fn fingerprint_no_ip_no_port() {
        let f1 = Finding::new("network", "No DNS", "desc", Severity::Info);
        let f2 = Finding::new("network", "No DNS", "desc", Severity::Medium);
        // Same key fields (both have None ip/port) → same fingerprint
        assert_eq!(f1.fingerprint(), f2.fingerprint());
    }

    proptest! {
        /// JSON roundtrip: serialize then deserialize a Finding produces equivalent data.
        #[test]
        fn prop_finding_json_roundtrip(finding in arb_finding()) {
            let json = serde_json::to_string(&finding).expect("serialize");
            let recovered: Finding = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(finding, recovered);
        }

        /// Every Finding has a non-empty scanner and title.
        #[test]
        fn prop_finding_builder_invariants(finding in arb_finding()) {
            assert!(!finding.scanner.is_empty());
            assert!(!finding.title.is_empty());
            assert!(!finding.description.is_empty());
        }

        /// `Display` is exactly 16 lowercase hex chars.
        #[test]
        fn prop_fingerprint_display_is_16_lowercase_hex(v in any::<u64>()) {
            let s = FindingFingerprint(v).to_string();
            prop_assert_eq!(s.len(), 16);
            prop_assert!(s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        }

        /// `Display` then `FromStr` recovers the value; `0x`, whitespace, uppercase and unpadded forms parse the same.
        #[test]
        fn prop_fingerprint_display_parse_roundtrip(v in any::<u64>()) {
            let fp = FindingFingerprint(v);
            let hex = fp.to_string();
            let forms = [
                hex.clone(),
                format!("0x{hex}"),
                format!("  {hex}\t"),
                hex.to_ascii_uppercase(),
                format!("{v:x}"),
                format!("0x{v:X}"),
            ];
            for form in forms {
                prop_assert_eq!(form.parse::<FindingFingerprint>(), Ok(fp), "form {:?}", form);
            }
        }

        /// `from_str` never panics; any accepted value re-renders and re-parses to itself.
        #[test]
        fn prop_fingerprint_from_str_total(s in arb_fingerprint_text()) {
            if let Ok(fp) = s.parse::<FindingFingerprint>() {
                prop_assert_eq!(fp.to_string().parse::<FindingFingerprint>(), Ok(fp));
            }
        }

        /// JSON round-trip preserves the fingerprint value.
        #[test]
        fn prop_fingerprint_json_roundtrip(v in any::<u64>()) {
            let fp = FindingFingerprint(v);
            let json = serde_json::to_string(&fp).unwrap();
            prop_assert_eq!(serde_json::from_str::<FindingFingerprint>(&json).unwrap(), fp);
        }

        /// Fingerprint survives a JSON round-trip of the whole finding.
        #[test]
        fn prop_fingerprint_survives_finding_json_roundtrip(f in arb_finding()) {
            let back: Finding = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
            prop_assert_eq!(back.fingerprint(), f.fingerprint());
        }

        /// Fingerprint ignores id, description, severity, confidence, evidence, service, MAC, hostname, CWE, timestamp.
        #[test]
        fn prop_fingerprint_invariant_under_non_key_fields(
            f in arb_finding(),
            desc in "[a-zA-Z0-9 ]{0,60}",
            sev in arb_severity(),
            conf in arb_confidence(),
            evidence in proptest::option::of("[a-zA-Z0-9 ._:-]{0,100}"),
            service in proptest::option::of("[a-z]{0,10}"),
            mac in proptest::option::of("[0-9a-f:]{0,17}"),
            host in proptest::option::of("[a-z0-9.-]{0,30}"),
            cwe in proptest::option::of("CWE-[0-9]{1,4}"),
        ) {
            let mut g = f.clone();
            g.id = Uuid::new_v4();
            g.description = desc;
            g.severity = sev;
            g.confidence = conf;
            g.evidence = evidence;
            g.affected_service = service;
            g.affected_mac = mac;
            g.affected_hostname = host;
            g.cwe_id = cwe;
            g.discovered_at = Utc::now();
            prop_assert_eq!(g.fingerprint(), f.fingerprint());
        }

        /// Fingerprint changes when scanner, title, IP or port changes.
        #[test]
        fn prop_fingerprint_depends_on_key_fields(
            f in arb_finding(),
            scanner in "[a-z]{1,10}",
            title in "[a-zA-Z0-9 ]{1,30}",
            ip in proptest::option::of(arb_ip()),
            port in proptest::option::of(any::<u16>()),
        ) {
            let fp = f.fingerprint();
            if scanner != f.scanner {
                prop_assert_ne!(edited(&f, |g| g.scanner = scanner).fingerprint(), fp);
            }
            if title != f.title {
                prop_assert_ne!(edited(&f, |g| g.title = title).fingerprint(), fp);
            }
            if ip != f.affected_ip {
                prop_assert_ne!(edited(&f, |g| g.affected_ip = ip).fingerprint(), fp);
            }
            if port != f.affected_port {
                prop_assert_ne!(edited(&f, |g| g.affected_port = port).fingerprint(), fp);
            }
        }

        /// `with_evidence` stores a prefix of the input, at most 256 bytes, cut at a char boundary (so >= 253 when truncated).
        #[test]
        fn prop_with_evidence_truncates_at_char_boundary(s in "\\PC{0,300}") {
            let f = Finding::new("s", "t", "d", Severity::Info).with_evidence(s.clone());
            let e = f.evidence.unwrap();
            prop_assert!(e.len() <= 256);
            prop_assert!(s.starts_with(&e));
            prop_assert!(e.len() >= s.len().min(253));
        }
    }
}

#[cfg(test)]
mod hasher_tests {
    use super::*;

    #[test]
    fn fnv1a64_matches_reference_vectors() {
        let mut h = Fnv1a64::new();
        assert_eq!(h.finish(), 0xcbf2_9ce4_8422_2325);
        h.write(b"a");
        assert_eq!(h.finish(), 0xaf63_dc4c_8601_ec8c);
    }

    /// Pinned value: FNV-1a over `(scanner, title, ip, port)` must not drift across releases.
    #[test]
    fn fingerprint_known_answer() {
        let f = Finding::new("ports", "Telnet open", "d", Severity::High)
            .with_ip("192.168.1.1".parse().unwrap())
            .with_port(23);
        assert_eq!(f.fingerprint().to_string(), "9919305a61aa445c");
    }

    #[test]
    fn fingerprint_is_deterministic_across_calls() {
        let f = Finding::new("ports", "Telnet open", "d", Severity::High)
            .with_ip("192.168.1.1".parse().unwrap())
            .with_port(23);
        assert_eq!(f.fingerprint(), f.fingerprint());
    }
}
