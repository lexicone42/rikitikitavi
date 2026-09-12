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

/// Diffs two scan results. Findings match by [`FindingFingerprint`]; devices by
/// [`Device::fingerprint`] (MAC, else IP). Output order is unspecified.
pub fn diff_scan_results(old: &ScanResults, new: &ScanResults) -> ScanDiff {
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
    use rikitikitavi_models::{Device, DeviceFingerprint};
    use std::collections::HashSet;
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

    const SCANNERS: &[&str] = &["ports", "ssl", "dns", "creds"];
    const TITLES: &[&str] = &["Open", "Weak", "Expired", "Default"];
    const PORTS: &[u16] = &[22, 80, 443, 53];

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
            proptest::sample::select(SCANNERS),
            proptest::sample::select(TITLES),
            arb_severity(),
            (1_u8..5_u8),
            proptest::sample::select(PORTS),
        )
            .prop_map(|(scanner, title, sev, host, port)| {
                make_finding(scanner, title, sev, &format!("10.0.0.{host}"), port)
            })
    }

    /// Keyed by fingerprint components, so fingerprints within one scan are unique.
    fn arb_unique_findings() -> impl Strategy<Value = Vec<Finding>> {
        proptest::collection::hash_map(
            (
                0..SCANNERS.len(),
                0..TITLES.len(),
                1_u8..5_u8,
                0..PORTS.len(),
            ),
            arb_severity(),
            0..12,
        )
        .prop_map(|m| {
            m.into_iter()
                .map(|((s, t, host, p), sev)| {
                    make_finding(
                        SCANNERS[s],
                        TITLES[t],
                        sev,
                        &format!("10.0.0.{host}"),
                        PORTS[p],
                    )
                })
                .collect()
        })
    }

    fn arb_device() -> impl Strategy<Value = Device> {
        (1_u8..5_u8, proptest::option::of(0_u8..3_u8)).prop_map(|(host, mac)| {
            let addr = ip(&format!("10.0.0.{host}"));
            mac.map_or_else(
                || Device::new(addr),
                |m| Device::new(addr).with_mac(format!("aa:bb:cc:dd:ee:{m:02x}")),
            )
        })
    }

    fn finding_fps(findings: &[Finding]) -> HashSet<FindingFingerprint> {
        findings.iter().map(Finding::fingerprint).collect()
    }

    fn device_fps(devices: &[Device]) -> HashSet<DeviceFingerprint> {
        devices.iter().map(Device::fingerprint).collect()
    }

    /// Two finding sets: identical, one severity flipped, or independent.
    fn arb_finding_pair() -> impl Strategy<Value = (Vec<Finding>, Vec<Finding>)> {
        arb_unique_findings().prop_flat_map(|a| {
            let flipped = (Just(a.clone()), 0..a.len().max(1)).prop_map(|(mut b, i)| {
                if let Some(f) = b.get_mut(i) {
                    f.severity = if f.severity == Severity::Critical {
                        Severity::Info
                    } else {
                        Severity::Critical
                    };
                }
                b
            });
            let b = prop_oneof![Just(a.clone()), flipped, arb_unique_findings()];
            (Just(a), b)
        })
    }

    /// Two device sets: identical or independent.
    fn arb_device_pair() -> impl Strategy<Value = (Vec<Device>, Vec<Device>)> {
        proptest::collection::vec(arb_device(), 0..6).prop_flat_map(|a| {
            let b = prop_oneof![
                Just(a.clone()),
                proptest::collection::vec(arb_device(), 0..6)
            ];
            (Just(a), b)
        })
    }

    proptest! {
        /// diff(a, b) mirrors diff(b, a): new<->resolved, new_devices<->disappeared,
        /// unchanged equal, severity changes swapped.
        #[test]
        fn prop_diff_symmetric(
            a_findings in proptest::collection::vec(arb_finding(), 0..15),
            b_findings in proptest::collection::vec(arb_finding(), 0..15),
            a_devices in proptest::collection::vec(arb_device(), 0..6),
            b_devices in proptest::collection::vec(arb_device(), 0..6),
        ) {
            let a = make_results(a_findings, a_devices);
            let b = make_results(b_findings, b_devices);
            let ab = diff_scan_results(&a, &b);
            let ba = diff_scan_results(&b, &a);

            prop_assert_eq!(finding_fps(&ab.new_findings), finding_fps(&ba.resolved_findings));
            prop_assert_eq!(finding_fps(&ab.resolved_findings), finding_fps(&ba.new_findings));
            prop_assert_eq!(
                finding_fps(&ab.unchanged_findings),
                finding_fps(&ba.unchanged_findings)
            );

            let ab_changes: HashSet<_> = ab
                .severity_changes
                .iter()
                .map(|c| (c.finding.fingerprint(), c.old_severity, c.new_severity))
                .collect();
            let ba_swapped: HashSet<_> = ba
                .severity_changes
                .iter()
                .map(|c| (c.finding.fingerprint(), c.new_severity, c.old_severity))
                .collect();
            prop_assert_eq!(ab_changes, ba_swapped);

            prop_assert_eq!(device_fps(&ab.new_devices), device_fps(&ba.disappeared_devices));
            prop_assert_eq!(device_fps(&ab.disappeared_devices), device_fps(&ba.new_devices));
            prop_assert_eq!(device_fps(&ab.unchanged_devices), device_fps(&ba.unchanged_devices));
            prop_assert_eq!(ab.has_changes(), ba.has_changes());
        }

        /// `has_changes()` is false exactly when both scans have the same finding
        /// fingerprints with equal severities and the same device fingerprints.
        #[test]
        fn prop_has_changes_iff_scans_differ(
            (a_findings, b_findings) in arb_finding_pair(),
            (a_devices, b_devices) in arb_device_pair(),
        ) {
            let a_sev: HashMap<_, _> = a_findings
                .iter()
                .map(|f| (f.fingerprint(), f.severity))
                .collect();
            let b_sev: HashMap<_, _> = b_findings
                .iter()
                .map(|f| (f.fingerprint(), f.severity))
                .collect();
            let same = a_sev == b_sev && device_fps(&a_devices) == device_fps(&b_devices);

            let diff = diff_scan_results(
                &make_results(a_findings, a_devices),
                &make_results(b_findings, b_devices),
            );
            prop_assert_eq!(diff.has_changes(), !same);
        }

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

            // Each distinct new fingerprint lands in exactly one category.
            let accounted = diff.new_findings.len()
                + diff.unchanged_findings.len()
                + diff.severity_changes.len();

            let unique_new: std::collections::HashSet<_> = new_findings
                .iter()
                .map(rikitikitavi_models::Finding::fingerprint)
                .collect();
            assert_eq!(accounted, unique_new.len());
        }
    }
}
