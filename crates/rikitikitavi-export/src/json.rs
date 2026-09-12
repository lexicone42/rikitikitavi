use anyhow::Result;
use rikitikitavi_models::ScanResults;
use std::path::Path;

/// Export scan results as a JSON file.
pub fn export_json(results: &ScanResults, path: &Path) -> Result<()> {
    tracing::info!(?path, "exporting JSON report");
    let json = serde_json::to_string_pretty(results)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Serialize scan results to a JSON string.
pub fn to_json_string(results: &ScanResults) -> Result<String> {
    Ok(serde_json::to_string_pretty(results)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_core::Severity;
    use rikitikitavi_models::Finding;

    fn make_results(findings: Vec<Finding>) -> ScanResults {
        ScanResults {
            findings,
            risk_score: 42.0,
            scan_duration_secs: 10,
            ..Default::default()
        }
    }

    #[test]
    fn test_to_json_string_empty() {
        let results = make_results(Vec::new());
        let json = to_json_string(&results).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["findings"].is_array());
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_to_json_string_with_findings() {
        let findings = vec![
            Finding::new("test", "Finding 1", "Desc 1", Severity::High),
            Finding::new("test", "Finding 2", "Desc 2", Severity::Low),
        ];
        let results = make_results(findings);
        let json = to_json_string(&results).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 2);
        assert!((parsed["risk_score"].as_f64().unwrap() - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_json_roundtrip() {
        let findings = vec![
            Finding::new("scanner", "Test", "Desc", Severity::Medium)
                .with_ip("10.0.0.1".parse().unwrap())
                .with_port(443)
                .with_cwe("CWE-295"),
        ];
        let results = make_results(findings);
        let json = to_json_string(&results).unwrap();
        let recovered: ScanResults = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.findings.len(), 1);
        assert_eq!(recovered.findings[0].title, "Test");
        assert!((recovered.risk_score - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_json_output_is_valid() {
        let results = make_results(Vec::new());
        let json = to_json_string(&results).unwrap();
        // Must be valid JSON
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
    }

    proptest! {
        /// to_json_string never panics and always produces valid JSON
        #[test]
        fn prop_json_always_valid(risk in 0.0_f64..=100.0_f64, duration in 0_u64..=3600_u64) {
            let results = ScanResults {
                risk_score: risk,
                scan_duration_secs: duration,
                ..Default::default()
            };
            let json = to_json_string(&results).unwrap();
            assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
        }
    }

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use rikitikitavi_models::device::{OpenPort, PortProtocol};
    use rikitikitavi_models::{Device, DeviceType, MacAddr, Remediation};

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
            any::<u32>().prop_map(|n| IpAddr::V4(Ipv4Addr::from(n))),
            any::<u128>().prop_map(|n| IpAddr::V6(Ipv6Addr::from(n))),
        ]
    }

    /// `k / 1000` for `k in 0..=max`; `serde_json` parses floats best-effort (no `float_roundtrip`), so long mantissas may shift 1 ULP.
    fn arb_short_float(max: u32) -> impl Strategy<Value = f64> {
        (0..=max).prop_map(|k| f64::from(k) / 1000.0)
    }

    /// Any Unicode scalar values, including control characters and quotes.
    fn arb_text() -> impl Strategy<Value = String> {
        proptest::collection::vec(any::<char>(), 0..24)
            .prop_map(|chars| chars.into_iter().collect::<String>())
    }

    fn arb_remediation() -> impl Strategy<Value = Remediation> {
        (
            arb_text(),
            proptest::collection::vec(arb_text(), 0..3),
            proptest::option::of(arb_text()),
        )
            .prop_map(|(description, steps, effort)| Remediation {
                description,
                steps,
                effort,
            })
    }

    fn arb_finding() -> impl Strategy<Value = Finding> {
        (
            (
                arb_text(),
                arb_text(),
                arb_text(),
                arb_severity(),
                proptest::option::of(arb_ip()),
                proptest::option::of(any::<u16>()),
            ),
            (
                proptest::option::of(arb_text()),
                proptest::collection::vec(arb_text(), 0..3),
                proptest::option::of(arb_remediation()),
                proptest::option::of(arb_text()),
                proptest::option::of(arb_text()),
                any::<bool>(),
                proptest::option::of(arb_short_float(1000)),
            ),
        )
            .prop_map(
                |(
                    (scanner, title, desc, severity, ip, port),
                    (cwe, cve_ids, remediation, evidence, hostname, is_kev, epss),
                )| {
                    let mut f = Finding::new(&scanner, &title, &desc, severity)
                        .with_cve_ids(cve_ids)
                        .with_opt_remediation(remediation);
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
                    if let Some(hostname) = hostname {
                        f = f.with_hostname(hostname);
                    }
                    Finding { is_kev, epss, ..f }
                },
            )
    }

    fn arb_open_port() -> impl Strategy<Value = OpenPort> {
        (
            any::<u16>(),
            any::<bool>(),
            proptest::option::of(arb_text()),
            proptest::option::of(arb_text()),
            proptest::option::of(arb_text()),
        )
            .prop_map(|(port, tcp, service, version, banner)| OpenPort {
                port,
                protocol: if tcp {
                    PortProtocol::Tcp
                } else {
                    PortProtocol::Udp
                },
                service,
                version,
                banner,
            })
    }

    fn arb_device() -> impl Strategy<Value = Device> {
        (
            arb_ip(),
            proptest::option::of(any::<[u8; 6]>()),
            proptest::option::of(arb_text()),
            proptest::option::of(arb_text()),
            prop_oneof![
                Just(DeviceType::Router),
                Just(DeviceType::Nas),
                Just(DeviceType::Camera),
                Just(DeviceType::Unknown),
            ],
            proptest::collection::vec(arb_open_port(), 0..3),
            proptest::option::of(arb_text()),
        )
            .prop_map(
                |(ip, mac, hostname, vendor, device_type, open_ports, os_guess)| Device {
                    mac: mac.map(MacAddr::new),
                    hostname,
                    vendor,
                    device_type,
                    open_ports,
                    os_guess,
                    ..Device::new(ip)
                },
            )
    }

    proptest! {
        /// serialize → deserialize → serialize is a fixed point; findings and devices compare equal.
        #[test]
        fn prop_json_roundtrip(
            findings in proptest::collection::vec(arb_finding(), 0..4),
            devices in proptest::collection::vec(arb_device(), 0..4),
            risk_score in arb_short_float(100_000),
            scan_duration_secs in any::<u64>(),
        ) {
            let results = ScanResults {
                findings,
                devices,
                risk_score,
                scan_duration_secs,
                ..Default::default()
            };
            let json = to_json_string(&results).unwrap();
            let recovered: ScanResults = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(&recovered.findings, &results.findings);
            prop_assert_eq!(
                serde_json::to_value(&recovered.devices).unwrap(),
                serde_json::to_value(&results.devices).unwrap()
            );
            prop_assert_eq!(recovered.risk_score.to_bits(), risk_score.to_bits());
            prop_assert_eq!(recovered.scan_duration_secs, scan_duration_secs);
            prop_assert_eq!(recovered.scanned_at, results.scanned_at);
            prop_assert_eq!(to_json_string(&recovered).unwrap(), json);
        }
    }
}
