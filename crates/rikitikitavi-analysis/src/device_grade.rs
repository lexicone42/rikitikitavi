//! Per-device report cards: one letter grade per host, from that host's findings
//! and its device class.
//!
//! The ladder is the scan-wide one in [`crate::risk_score::risk_grade`], so a device
//! and the network are graded on the same scale (a test pins the two together). Two
//! adjustments are device-scoped: a finding CISA lists as exploited in the wild caps
//! the grade at F, and a device class whose compromise reaches past the device itself
//! costs one letter.
//!
//! This is this tool's own scoring of observable state, not a conformance verdict:
//! ETSI EN 303 645 and the FCC Cyber Trust Mark rest on manufacturer evidence no
//! network scan can see.

use rikitikitavi_core::Severity;
use rikitikitavi_models::{Device, DeviceReportCard, DeviceStatus, DeviceType, Finding, Grade};

/// Device classes graded one letter harder.
///
/// Hubs, routers, access points and NAS boxes hold other devices' credentials or
/// traffic; locks, EV chargers, inverters and thermostats actuate the physical
/// world; cameras, NVRs and doorbells record it.
pub const CLASS_WEIGHTED: &[DeviceType] = &[
    DeviceType::Router,
    DeviceType::AccessPoint,
    DeviceType::Nas,
    DeviceType::Hub,
    DeviceType::SmartLock,
    DeviceType::Thermostat,
    DeviceType::EvCharger,
    DeviceType::Inverter,
    DeviceType::Camera,
    DeviceType::Nvr,
    DeviceType::Doorbell,
];

/// The device class is graded one letter harder.
#[must_use]
pub fn class_weighted(device_type: DeviceType) -> bool {
    CLASS_WEIGHTED.contains(&device_type)
}

/// Worst-first rank for report-card ordering; `NotAssessed` sorts last.
#[must_use]
pub const fn grade_rank(grade: Grade) -> u8 {
    match grade {
        Grade::F => 0,
        Grade::D => 1,
        Grade::C => 2,
        Grade::B => 3,
        Grade::A => 4,
        Grade::NotAssessed => 5,
    }
}

/// Findings attributed to `device`, by IP or by MAC.
fn findings_for<'a>(device: &Device, findings: &'a [Finding]) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| {
            f.affected_ip == Some(device.ip)
                || (device.mac.is_some() && f.affected_mac == device.mac)
        })
        .collect()
}

/// Base letter from severity counts. Same ladder as `risk_grade`.
#[must_use]
pub const fn base_grade(critical: usize, high: usize, medium: usize) -> Grade {
    if critical > 0 {
        Grade::F
    } else if high > 2 {
        Grade::D
    } else if high > 0 {
        Grade::C
    } else if medium > 3 {
        Grade::B
    } else {
        Grade::A
    }
}

/// Grade one device against the findings of a scan.
///
/// A host with no findings and no open ports is [`Grade::NotAssessed`]: nothing was
/// observed, which is not the same as nothing being wrong.
#[must_use]
pub fn grade_device(device: &Device, findings: &[Finding]) -> DeviceReportCard {
    let mine = findings_for(device, findings);

    let count = |s: Severity| mine.iter().filter(|f| f.severity == s).count();
    let (critical, high, medium, low, info) = (
        count(Severity::Critical),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low),
        count(Severity::Info),
    );
    let kev = mine.iter().filter(|f| f.is_kev).count();

    let mut grade = base_grade(critical, high, medium);
    let mut reasons: Vec<String> = Vec::new();

    if mine.is_empty() {
        if device.open_ports.is_empty() {
            grade = Grade::NotAssessed;
            reasons.push("nothing observed on this host".to_owned());
        } else {
            reasons.push(format!(
                "{} open port(s), no findings",
                device.open_ports.len()
            ));
        }
    } else {
        reasons.push(severity_phrase(critical, high, medium, low, info));
    }

    let mut class_applied = false;
    if grade != Grade::NotAssessed
        && class_weighted(device.device_type)
        && critical + high + medium > 0
    {
        grade = grade.step_down();
        class_applied = true;
        reasons.push(format!(
            "{} class graded one letter harder",
            device.device_type
        ));
    }

    if mine
        .iter()
        .any(|f| f.is_kev && f.severity >= Severity::High)
    {
        grade = Grade::F;
        reasons.push("exploited in the wild (CISA KEV)".to_owned());
    }

    DeviceReportCard {
        ip: device.ip,
        mac: device.mac,
        hostname: device.hostname.clone(),
        device_type: device.device_type,
        grade,
        critical,
        high,
        medium,
        low,
        info,
        kev,
        class_weighted: class_applied,
        status: DeviceStatus::Untracked,
        rationale: reasons.join("; "),
    }
}

/// Severity counts as a terse phrase, worst first.
fn severity_phrase(critical: usize, high: usize, medium: usize, low: usize, info: usize) -> String {
    [
        (critical, "critical"),
        (high, "high"),
        (medium, "medium"),
        (low, "low"),
        (info, "info"),
    ]
    .into_iter()
    .filter(|&(n, _)| n > 0)
    .map(|(n, name)| format!("{n} {name}"))
    .collect::<Vec<_>>()
    .join(", ")
}

/// Grade every device: worst grade first, then most actionable findings, then by IP.
#[must_use]
pub fn grade_devices(devices: &[Device], findings: &[Finding]) -> Vec<DeviceReportCard> {
    let mut cards: Vec<DeviceReportCard> =
        devices.iter().map(|d| grade_device(d, findings)).collect();
    cards.sort_by(|a, b| {
        grade_rank(a.grade)
            .cmp(&grade_rank(b.grade))
            .then_with(|| b.actionable().cmp(&a.actionable()))
            .then_with(|| a.ip.cmp(&b.ip))
    });
    cards
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_models::MacAddr;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, n))
    }

    fn device(n: u8, t: DeviceType) -> Device {
        Device {
            device_type: t,
            ..Device::new(ip(n))
        }
    }

    fn finding(n: u8, severity: Severity) -> Finding {
        Finding::new("test", "t", "d", severity).with_ip(ip(n))
    }

    #[test]
    fn base_grade_matches_scan_ladder() {
        for critical in 0..3_usize {
            for high in 0..5_usize {
                for medium in 0..6_usize {
                    let (label, _) = crate::risk_score::risk_grade(critical, high, medium);
                    assert_eq!(
                        base_grade(critical, high, medium).letter(),
                        label.chars().next().unwrap(),
                        "counts {critical}/{high}/{medium}"
                    );
                }
            }
        }
    }

    #[test]
    fn clean_device_with_ports_is_a() {
        let mut d = device(10, DeviceType::Desktop);
        d.open_ports.push(rikitikitavi_models::device::OpenPort {
            port: 22,
            protocol: rikitikitavi_models::device::PortProtocol::Tcp,
            service: None,
            version: None,
            banner: None,
        });
        let card = grade_device(&d, &[]);
        assert_eq!(card.grade, Grade::A);
        assert_eq!(card.total(), 0);
    }

    #[test]
    fn silent_device_is_not_assessed() {
        let card = grade_device(&device(11, DeviceType::Unknown), &[]);
        assert_eq!(card.grade, Grade::NotAssessed);
        assert!(card.rationale.contains("nothing observed"));
    }

    #[test]
    fn critical_finding_is_f() {
        let card = grade_device(
            &device(12, DeviceType::Desktop),
            &[finding(12, Severity::Critical)],
        );
        assert_eq!(card.grade, Grade::F);
        assert_eq!(card.critical, 1);
    }

    #[test]
    fn weighted_class_costs_one_letter() {
        let findings = [finding(13, Severity::High)];
        let plain = grade_device(&device(13, DeviceType::Desktop), &findings);
        let camera = grade_device(&device(13, DeviceType::Camera), &findings);
        assert_eq!(plain.grade, Grade::C);
        assert_eq!(camera.grade, Grade::D);
        assert!(camera.class_weighted);
        assert!(!plain.class_weighted);
    }

    #[test]
    fn weighted_class_without_actionable_findings_keeps_its_grade() {
        let findings = [finding(14, Severity::Info)];
        let card = grade_device(&device(14, DeviceType::Router), &findings);
        assert_eq!(card.grade, Grade::A);
        assert!(!card.class_weighted);
    }

    #[test]
    fn kev_high_finding_forces_f() {
        let kev = Finding {
            is_kev: true,
            ..finding(15, Severity::High)
        };
        let card = grade_device(&device(15, DeviceType::Desktop), &[kev]);
        assert_eq!(card.grade, Grade::F);
        assert_eq!(card.kev, 1);
        assert!(card.rationale.contains("CISA KEV"));
    }

    #[test]
    fn findings_attach_by_mac_as_well_as_ip() {
        let mac = MacAddr::new([0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33]);
        let d = Device {
            mac: Some(mac),
            ..device(16, DeviceType::Desktop)
        };
        let by_mac = Finding {
            affected_mac: Some(mac),
            ..Finding::new("test", "t", "d", Severity::High)
        };
        assert_eq!(grade_device(&d, &[by_mac]).high, 1);
    }

    #[test]
    fn cards_are_ordered_worst_first_and_not_assessed_last() {
        let devices = [
            device(20, DeviceType::Unknown),
            device(21, DeviceType::Desktop),
            device(22, DeviceType::Desktop),
        ];
        let findings = [finding(21, Severity::Critical), finding(22, Severity::High)];
        let cards = grade_devices(&devices, &findings);
        let grades: Vec<Grade> = cards.iter().map(|c| c.grade).collect();
        assert_eq!(grades, vec![Grade::F, Grade::C, Grade::NotAssessed]);
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

    fn arb_type() -> impl Strategy<Value = DeviceType> {
        (0..DeviceType::ALL.len()).prop_map(|i| DeviceType::ALL[i])
    }

    proptest! {
        /// Grading never panics and the counts always add up to the findings attributed.
        #[test]
        fn prop_counts_match_findings(
            severities in proptest::collection::vec(arb_severity(), 0..12),
            dt in arb_type(),
            kev in any::<bool>(),
        ) {
            let d = device(30, dt);
            let findings: Vec<Finding> = severities
                .iter()
                .map(|&s| Finding { is_kev: kev, ..finding(30, s) })
                .collect();
            let card = grade_device(&d, &findings);
            prop_assert_eq!(card.total(), findings.len());
            prop_assert_eq!(card.kev, if kev { findings.len() } else { 0 });
        }

        /// Adding a finding never improves a device's grade.
        #[test]
        fn prop_more_findings_never_improve_the_grade(
            severities in proptest::collection::vec(arb_severity(), 0..8),
            extra in arb_severity(),
            dt in arb_type(),
        ) {
            let d = device(31, dt);
            let mut findings: Vec<Finding> = severities.iter().map(|&s| finding(31, s)).collect();
            let before = grade_device(&d, &findings).grade;
            findings.push(finding(31, extra));
            let after = grade_device(&d, &findings).grade;
            // `NotAssessed` only ever becomes a real grade, never the reverse.
            if before == Grade::NotAssessed {
                prop_assert_ne!(after, Grade::NotAssessed);
            } else {
                prop_assert!(after >= before, "{before:?} -> {after:?}");
            }
        }

        /// A weighted class is never graded better than the same findings on a plain host.
        #[test]
        fn prop_weighted_class_is_never_better(
            severities in proptest::collection::vec(arb_severity(), 0..8),
            dt in arb_type(),
        ) {
            let findings: Vec<Finding> = severities.iter().map(|&s| finding(32, s)).collect();
            let plain = grade_device(&device(32, DeviceType::Desktop), &findings).grade;
            let other = grade_device(&device(32, dt), &findings).grade;
            if class_weighted(dt) {
                prop_assert!(other >= plain, "{plain:?} -> {other:?}");
            } else {
                prop_assert_eq!(other, plain);
            }
        }
    }
}
