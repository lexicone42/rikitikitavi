use std::collections::HashMap;

use chrono::{DateTime, Utc};
use rikitikitavi_core::Severity;
use rikitikitavi_models::{Device, Finding, FindingFingerprint, ScanResults};
use serde::{Deserialize, Serialize};

/// A finding whose severity changed between scan runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityChange {
    pub finding: Finding,
    pub old_severity: Severity,
    pub new_severity: Severity,
}

/// Differences between two scan runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanDiff {
    /// Findings present in the new scan but not the old.
    pub new_findings: Vec<Finding>,
    /// Findings present in the old scan but not the new (resolved).
    pub resolved_findings: Vec<Finding>,
    /// Findings present in both scans with unchanged severity.
    pub unchanged_findings: Vec<Finding>,
    /// Findings present in both but with different severity.
    pub severity_changes: Vec<SeverityChange>,
    /// Devices present in the new scan but not the old.
    pub new_devices: Vec<Device>,
    /// Devices present in the old scan but not the new.
    pub disappeared_devices: Vec<Device>,
    /// Devices present in both scans.
    pub unchanged_devices: Vec<Device>,
    /// When the baseline (old) scan was performed.
    pub baseline_time: Option<DateTime<Utc>>,
    /// When the current (new) scan was performed.
    pub current_time: Option<DateTime<Utc>>,
}

impl ScanDiff {
    /// Whether anything changed between the two scans.
    pub const fn has_changes(&self) -> bool {
        !self.new_findings.is_empty()
            || !self.resolved_findings.is_empty()
            || !self.severity_changes.is_empty()
            || !self.new_devices.is_empty()
            || !self.disappeared_devices.is_empty()
    }

    /// Human-readable one-line summary of what changed.
    pub fn summary_line(&self) -> String {
        format!(
            "+{} new, -{} resolved, {} changed, +{} devices, -{} devices",
            self.new_findings.len(),
            self.resolved_findings.len(),
            self.severity_changes.len(),
            self.new_devices.len(),
            self.disappeared_devices.len(),
        )
    }
}

/// Diff two scan results using fingerprint-based comparison.
///
/// Findings are matched by `(scanner, title, affected_ip, affected_port)`.
/// Devices are matched by MAC address (preferred) or IP.
pub fn diff_scan_results(old: &ScanResults, new: &ScanResults) -> ScanDiff {
    // ── Finding diff ────────────────────────────────────────────────
    let old_map: HashMap<FindingFingerprint, &Finding> =
        old.findings.iter().map(|f| (f.fingerprint(), f)).collect();

    let new_map: HashMap<FindingFingerprint, &Finding> =
        new.findings.iter().map(|f| (f.fingerprint(), f)).collect();

    let mut new_findings = Vec::new();
    let mut unchanged_findings = Vec::new();
    let mut severity_changes = Vec::new();

    for (fp, finding) in &new_map {
        if let Some(old_finding) = old_map.get(fp) {
            if old_finding.severity == finding.severity {
                unchanged_findings.push((*finding).clone());
            } else {
                severity_changes.push(SeverityChange {
                    finding: (*finding).clone(),
                    old_severity: old_finding.severity,
                    new_severity: finding.severity,
                });
            }
        } else {
            new_findings.push((*finding).clone());
        }
    }

    let resolved_findings: Vec<Finding> = old_map
        .iter()
        .filter(|(fp, _)| !new_map.contains_key(fp))
        .map(|(_, f)| (*f).clone())
        .collect();

    // ── Device diff ─────────────────────────────────────────────────
    let old_device_map: HashMap<_, &Device> =
        old.devices.iter().map(|d| (d.fingerprint(), d)).collect();

    let new_device_map: HashMap<_, &Device> =
        new.devices.iter().map(|d| (d.fingerprint(), d)).collect();

    let new_devices: Vec<Device> = new_device_map
        .iter()
        .filter(|(fp, _)| !old_device_map.contains_key(fp))
        .map(|(_, d)| (*d).clone())
        .collect();

    let disappeared_devices: Vec<Device> = old_device_map
        .iter()
        .filter(|(fp, _)| !new_device_map.contains_key(fp))
        .map(|(_, d)| (*d).clone())
        .collect();

    let unchanged_devices: Vec<Device> = new_device_map
        .iter()
        .filter(|(fp, _)| old_device_map.contains_key(fp))
        .map(|(_, d)| (*d).clone())
        .collect();

    ScanDiff {
        new_findings,
        resolved_findings,
        unchanged_findings,
        severity_changes,
        new_devices,
        disappeared_devices,
        unchanged_devices,
        baseline_time: Some(old.scanned_at),
        current_time: Some(new.scanned_at),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_core::Severity;
    use rikitikitavi_models::Device;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn make_finding(scanner: &str, title: &str, sev: Severity, addr: &str, port: u16) -> Finding {
        Finding::new(scanner, title, "desc", sev)
            .with_ip(addr.parse().unwrap())
            .with_port(port)
    }

    fn make_results(findings: Vec<Finding>, devices: Vec<Device>) -> ScanResults {
        ScanResults {
            findings,
            devices,
            ..Default::default()
        }
    }

    #[test]
    fn empty_vs_empty() {
        let diff = diff_scan_results(&make_results(vec![], vec![]), &make_results(vec![], vec![]));
        assert!(!diff.has_changes());
        assert!(diff.new_findings.is_empty());
        assert!(diff.resolved_findings.is_empty());
        assert!(diff.unchanged_findings.is_empty());
        assert!(diff.severity_changes.is_empty());
    }

    #[test]
    fn identical_scans() {
        let f1 = make_finding("ports", "SSH open", Severity::Medium, "10.0.0.1", 22);
        let f2 = make_finding("ports", "SSH open", Severity::Medium, "10.0.0.1", 22);
        let old = make_results(vec![f1], vec![]);
        let new = make_results(vec![f2], vec![]);
        let diff = diff_scan_results(&old, &new);
        assert!(!diff.has_changes());
        assert_eq!(diff.unchanged_findings.len(), 1);
    }

    #[test]
    fn all_new_findings() {
        let old = make_results(vec![], vec![]);
        let new = make_results(
            vec![make_finding(
                "ports",
                "SSH open",
                Severity::Medium,
                "10.0.0.1",
                22,
            )],
            vec![],
        );
        let diff = diff_scan_results(&old, &new);
        assert!(diff.has_changes());
        assert_eq!(diff.new_findings.len(), 1);
        assert!(diff.resolved_findings.is_empty());
    }

    #[test]
    fn all_resolved() {
        let old = make_results(
            vec![make_finding(
                "ports",
                "SSH open",
                Severity::Medium,
                "10.0.0.1",
                22,
            )],
            vec![],
        );
        let new = make_results(vec![], vec![]);
        let diff = diff_scan_results(&old, &new);
        assert!(diff.has_changes());
        assert_eq!(diff.resolved_findings.len(), 1);
        assert!(diff.new_findings.is_empty());
    }

    #[test]
    fn disjoint_scans() {
        let old = make_results(
            vec![make_finding(
                "ports",
                "SSH open",
                Severity::Medium,
                "10.0.0.1",
                22,
            )],
            vec![],
        );
        let new = make_results(
            vec![make_finding(
                "ssl",
                "Expired cert",
                Severity::High,
                "10.0.0.1",
                443,
            )],
            vec![],
        );
        let diff = diff_scan_results(&old, &new);
        assert!(diff.has_changes());
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.resolved_findings.len(), 1);
        assert!(diff.unchanged_findings.is_empty());
    }

    #[test]
    fn overlapping_scans() {
        let shared = make_finding("ports", "SSH open", Severity::Medium, "10.0.0.1", 22);
        let old_only = make_finding("ssl", "Expired cert", Severity::High, "10.0.0.1", 443);
        let new_only = make_finding("dns", "No DNSSEC", Severity::Low, "10.0.0.1", 53);

        let old = make_results(vec![shared.clone(), old_only], vec![]);
        let new = make_results(vec![shared, new_only], vec![]);
        let diff = diff_scan_results(&old, &new);

        assert_eq!(diff.unchanged_findings.len(), 1);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.resolved_findings.len(), 1);
    }

    #[test]
    fn severity_change_detection() {
        let old = make_results(
            vec![make_finding(
                "ports",
                "SSH open",
                Severity::Low,
                "10.0.0.1",
                22,
            )],
            vec![],
        );
        let new = make_results(
            vec![make_finding(
                "ports",
                "SSH open",
                Severity::High,
                "10.0.0.1",
                22,
            )],
            vec![],
        );
        let diff = diff_scan_results(&old, &new);
        assert!(diff.has_changes());
        assert_eq!(diff.severity_changes.len(), 1);
        assert_eq!(diff.severity_changes[0].old_severity, Severity::Low);
        assert_eq!(diff.severity_changes[0].new_severity, Severity::High);
        assert!(diff.unchanged_findings.is_empty());
        assert!(diff.new_findings.is_empty());
    }

    #[test]
    fn device_new_disappeared_unchanged() {
        let d1 = Device::new(ip("10.0.0.1")).with_mac("aa:bb:cc:dd:ee:ff");
        let d2 = Device::new(ip("10.0.0.2")).with_mac("11:22:33:44:55:66");
        let d3 = Device::new(ip("10.0.0.3")).with_mac("77:88:99:aa:bb:cc");

        let old = make_results(vec![], vec![d1.clone(), d2]);
        let new = make_results(vec![], vec![d1, d3]);
        let diff = diff_scan_results(&old, &new);

        assert_eq!(diff.unchanged_devices.len(), 1);
        assert_eq!(diff.new_devices.len(), 1);
        assert_eq!(diff.disappeared_devices.len(), 1);
        assert_eq!(diff.new_devices[0].ip, ip("10.0.0.3"));
        assert_eq!(diff.disappeared_devices[0].ip, ip("10.0.0.2"));
    }

    #[test]
    fn summary_line_format() {
        let diff = ScanDiff {
            new_findings: vec![make_finding("a", "b", Severity::Low, "10.0.0.1", 1)],
            resolved_findings: vec![],
            severity_changes: vec![],
            new_devices: vec![Device::new(ip("10.0.0.2"))],
            ..Default::default()
        };
        assert_eq!(
            diff.summary_line(),
            "+1 new, -0 resolved, 0 changed, +1 devices, -0 devices"
        );
    }

    // ── Property-based tests ────────────────────────────────────────

    fn arb_severity() -> impl Strategy<Value = Severity> {
        prop_oneof![
            Just(Severity::Info),
            Just(Severity::Low),
            Just(Severity::Medium),
            Just(Severity::High),
            Just(Severity::Critical),
        ]
    }

    fn arb_finding() -> impl Strategy<Value = Finding> {
        (
            prop_oneof![Just("ports"), Just("ssl"), Just("dns"), Just("creds")],
            prop_oneof![Just("Open"), Just("Weak"), Just("Expired"), Just("Default")],
            arb_severity(),
            (1_u8..5_u8),
            prop_oneof![Just(22_u16), Just(80), Just(443), Just(53)],
        )
            .prop_map(|(scanner, title, sev, host, port)| {
                make_finding(scanner, title, sev, &format!("10.0.0.{host}"), port)
            })
    }

    proptest! {
        /// Diffing a scan against itself produces zero changes.
        #[test]
        fn prop_diff_with_self_no_changes(
            findings in proptest::collection::vec(arb_finding(), 0..20)
        ) {
            let results = make_results(findings, vec![]);
            let diff = diff_scan_results(&results, &results);
            assert!(!diff.has_changes());
        }

        /// new + resolved + unchanged + severity_changed covers all findings.
        #[test]
        fn prop_diff_covers_all_findings(
            old_findings in proptest::collection::vec(arb_finding(), 0..15),
            new_findings in proptest::collection::vec(arb_finding(), 0..15),
        ) {
            let old = make_results(old_findings, vec![]);
            let new = make_results(new_findings.clone(), vec![]);
            let diff = diff_scan_results(&old, &new);

            // Every new finding is accounted for in some category
            let accounted = diff.new_findings.len()
                + diff.unchanged_findings.len()
                + diff.severity_changes.len();

            // The number of unique fingerprints in new determines the total
            let unique_new: std::collections::HashSet<_> = new_findings
                .iter()
                .map(rikitikitavi_models::Finding::fingerprint)
                .collect();
            assert_eq!(accounted, unique_new.len());
        }
    }
}
