use crate::DeviceHint;
use chrono::{DateTime, Utc};
use rikitikitavi_core::Severity;
use serde::{Deserialize, Serialize};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::IpAddr;
use uuid::Uuid;

/// Semantic identity of a finding — same problem on same target.
///
/// Uses `(scanner, title, affected_ip, affected_port)` to identify "the same
/// issue" across scan runs. Deliberately excludes description, severity, and
/// service — those can change without it being a "different" finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingFingerprint(u64);

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
            affected_ip: None,
            affected_mac: None,
            affected_hostname: None,
            affected_port: None,
            affected_service: None,
            remediation: None,
            cwe_id: None,
            cve_ids: Vec::new(),
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

    /// Compute a fingerprint that identifies "the same problem on the same
    /// target" across scan runs.
    pub fn fingerprint(&self) -> FindingFingerprint {
        let mut hasher = DefaultHasher::new();
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
            // Find the last char boundary at or before byte 256 (MSRV-safe
            // alternative to `str::floor_char_boundary`).
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
        prop_oneof![(0_u32..=u32::MAX).prop_map(|n| IpAddr::V4(std::net::Ipv4Addr::from(n))),]
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
        // Same (scanner, title, ip, port) → same fingerprint despite
        // different description, severity, and service.
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
    }
}
