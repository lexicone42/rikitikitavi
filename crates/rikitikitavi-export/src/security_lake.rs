use std::path::Path;

use anyhow::Result;
use rikitikitavi_models::ScanResults;
use rikitikitavi_models::ocsf::OcsfFinding;

/// Write findings as OCSF 1.1 Vulnerability Finding (class 2002) NDJSON.
pub fn export_ocsf_json(results: &ScanResults, path: &Path) -> Result<()> {
    let ndjson = to_ocsf_ndjson(results)?;
    rikitikitavi_core::fs::write_private(path, ndjson.as_bytes())?;
    Ok(())
}

/// OCSF NDJSON (one object per line); a non-zero scan `risk_score` is copied into each record.
pub fn to_ocsf_ndjson(results: &ScanResults) -> Result<String> {
    let mut buf = String::new();
    for finding in &results.findings {
        let mut ocsf = OcsfFinding::from(finding);
        if results.risk_score > 0.0 {
            ocsf.risk_score = Some(results.risk_score);
        }
        let line = serde_json::to_string(&ocsf)?;
        buf.push_str(&line);
        buf.push('\n');
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_core::Severity;
    use rikitikitavi_models::Finding;

    fn make_finding(scanner: &str, title: &str, severity: Severity) -> Finding {
        Finding::new(scanner, title, "test description", severity)
    }

    fn make_results(findings: Vec<Finding>) -> ScanResults {
        ScanResults {
            risk_score: 42.5,
            findings,
            ..Default::default()
        }
    }

    #[test]
    fn test_empty_results_empty_string() {
        let results = make_results(vec![]);
        let ndjson = to_ocsf_ndjson(&results).unwrap();
        assert!(ndjson.is_empty());
    }

    #[test]
    fn test_single_finding_one_line() {
        let results = make_results(vec![make_finding("ssl", "Weak Cipher", Severity::High)]);
        let ndjson = to_ocsf_ndjson(&results).unwrap();

        assert_eq!(ndjson.lines().count(), 1);
    }

    #[test]
    fn test_each_line_valid_json() {
        let results = make_results(vec![
            make_finding("ssl", "Weak Cipher", Severity::High),
            make_finding("ports", "Open SSH", Severity::Medium),
            make_finding("dns", "DNS Rebinding", Severity::Critical),
        ]);
        let ndjson = to_ocsf_ndjson(&results).unwrap();

        for line in ndjson.lines() {
            let parsed: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("invalid JSON line: {e}\n  line: {line}"));
            assert_eq!(parsed["class_uid"], 2002);
            assert_eq!(parsed["category_uid"], 2);
        }
    }

    #[test]
    fn test_trailing_newline() {
        let results = make_results(vec![make_finding("test", "T", Severity::Low)]);
        let ndjson = to_ocsf_ndjson(&results).unwrap();
        assert!(ndjson.ends_with('\n'));
        // No empty trailing line (split by lines should give exactly 1 entry)
        assert_eq!(ndjson.lines().count(), 1);
    }

    #[test]
    fn test_risk_score_injected() {
        let results = ScanResults {
            risk_score: 75.0,
            findings: vec![make_finding("test", "T", Severity::High)],
            ..Default::default()
        };
        let ndjson = to_ocsf_ndjson(&results).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(ndjson.lines().next().unwrap()).unwrap();
        let score = parsed["risk_score"].as_f64().unwrap();
        assert!((score - 75.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_zero_risk_score_omitted() {
        let results = ScanResults {
            risk_score: 0.0,
            findings: vec![make_finding("test", "T", Severity::Low)],
            ..Default::default()
        };
        let ndjson = to_ocsf_ndjson(&results).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(ndjson.lines().next().unwrap()).unwrap();
        assert!(parsed.get("risk_score").is_none());
    }

    #[test]
    fn test_ocsf_class_fields_in_json() {
        let results = make_results(vec![make_finding("test", "T", Severity::Low)]);
        let ndjson = to_ocsf_ndjson(&results).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(ndjson.lines().next().unwrap()).unwrap();

        assert_eq!(parsed["class_uid"], 2002);
        assert_eq!(parsed["class_name"], "Vulnerability Finding");
        assert_eq!(parsed["category_uid"], 2);
        assert_eq!(parsed["category_name"], "Findings");
        assert_eq!(parsed["activity_id"], 1);
        assert_eq!(parsed["type_uid"], 200_201);
        assert_eq!(parsed["type_name"], "Vulnerability Finding: Create");
    }

    #[test]
    fn test_epoch_ms_in_json_output() {
        let results = make_results(vec![make_finding("test", "T", Severity::Low)]);
        let ndjson = to_ocsf_ndjson(&results).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(ndjson.lines().next().unwrap()).unwrap();

        // `time` should be an integer (epoch ms), not a string
        assert!(parsed["time"].is_i64(), "time should be epoch ms integer");
        assert!(
            parsed["metadata"]["logged_time"].is_i64(),
            "logged_time should be epoch ms integer"
        );
    }

    #[test]
    fn test_file_export() {
        let results = make_results(vec![
            make_finding("ssl", "Weak", Severity::High),
            make_finding("ports", "Open", Severity::Low),
        ]);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.ndjson");
        export_ocsf_json(&results, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
        for line in content.lines() {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_export_ocsf_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.ndjson");
        export_ocsf_json(&make_results(Vec::new()), &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
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

    proptest! {
        /// Arbitrary findings always produce valid NDJSON.
        #[test]
        fn prop_ndjson_always_valid(
            scanner in "[a-z]{1,10}",
            title in "[a-zA-Z0-9 ]{1,30}",
            desc in "[a-zA-Z0-9 ]{1,60}",
            severity in arb_severity(),
            risk in 0.0_f64..100.0,
        ) {
            let finding = Finding::new(&scanner, &title, &desc, severity);
            let results = ScanResults {
                risk_score: risk,
                findings: vec![finding],
                ..Default::default()
            };
            let ndjson = to_ocsf_ndjson(&results).unwrap();
            for line in ndjson.lines() {
                let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
                assert_eq!(parsed["class_uid"], 2002);
            }
        }
    }

    use rikitikitavi_models::Remediation;

    /// Any Unicode scalar values, including newlines and quotes.
    fn arb_text() -> impl Strategy<Value = String> {
        proptest::collection::vec(any::<char>(), 0..24)
            .prop_map(|chars| chars.into_iter().collect::<String>())
    }

    fn arb_finding() -> impl Strategy<Value = Finding> {
        (
            arb_text(),
            arb_text(),
            arb_text(),
            arb_severity(),
            proptest::option::of(any::<u32>().prop_map(|n| std::net::Ipv4Addr::from(n).into())),
            proptest::option::of(any::<u16>()),
            proptest::option::of(arb_text()),
            proptest::collection::vec(arb_text(), 0..3),
            proptest::option::of(arb_text()),
        )
            .prop_map(
                |(scanner, title, desc, severity, ip, port, cwe, cve_ids, fix)| {
                    let mut f = Finding::new(&scanner, &title, &desc, severity)
                        .with_cve_ids(cve_ids)
                        .with_opt_remediation(fix.map(|description| Remediation {
                            description,
                            steps: Vec::new(),
                            effort: None,
                        }));
                    if let Some(ip) = ip {
                        f = f.with_ip(ip);
                    }
                    if let Some(port) = port {
                        f = f.with_port(port);
                    }
                    if let Some(cwe) = cwe {
                        f = f.with_cwe(cwe);
                    }
                    f
                },
            )
    }

    proptest! {
        /// Line i is the OCSF conversion of finding i (modulo per-event `metadata.uid`/`logged_time`), with `risk_score` copied only when > 0.
        #[test]
        fn prop_ndjson_lines_match_conversion(
            findings in proptest::collection::vec(arb_finding(), 0..6),
            risk in prop_oneof![Just(0.0_f64), 0.0_f64..=100.0],
        ) {
            let results = ScanResults {
                risk_score: risk,
                findings,
                ..Default::default()
            };
            let ndjson = to_ocsf_ndjson(&results).unwrap();
            let lines: Vec<&str> = ndjson.lines().collect();
            prop_assert_eq!(lines.len(), results.findings.len());

            for (line, finding) in lines.iter().zip(&results.findings) {
                let mut got: serde_json::Value = serde_json::from_str(line).unwrap();
                let mut expected = OcsfFinding::from(finding);
                if risk > 0.0 {
                    expected.risk_score = Some(risk);
                }
                let mut want: serde_json::Value =
                    serde_json::from_str(&serde_json::to_string(&expected).unwrap()).unwrap();
                for v in [&mut got, &mut want] {
                    let meta = v["metadata"].as_object_mut().unwrap();
                    meta.remove("uid");
                    meta.remove("logged_time");
                }
                let id = finding.id.to_string();
                prop_assert_eq!(got["finding_info"]["uid"].as_str(), Some(id.as_str()));
                prop_assert_eq!(got, want);
            }
        }
    }
}
