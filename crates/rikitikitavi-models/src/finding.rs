use chrono::{DateTime, Utc};
use rikitikitavi_core::Severity;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

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
        prop_oneof![
            (0_u32..=u32::MAX).prop_map(|n| IpAddr::V4(std::net::Ipv4Addr::from(n))),
        ]
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
            .prop_map(
                |(scanner, title, desc, sev, ip, port, cwe, evidence)| {
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
                },
            )
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
