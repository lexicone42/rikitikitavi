use std::path::Path;

use anyhow::Result;
use rikitikitavi_models::ScanResults;
use rikitikitavi_models::ocsf::OcsfFinding;

/// Export scan results as OCSF-compliant NDJSON to a file.
///
/// Each finding becomes one line of JSON conforming to the OCSF 1.1
/// Vulnerability Finding schema (class 2002). The `risk_score` from the
/// overall scan is injected into each OCSF record.
pub fn export_ocsf_json(results: &ScanResults, path: &Path) -> Result<()> {
    let ndjson = to_ocsf_ndjson(results)?;
    std::fs::write(path, ndjson)?;
    Ok(())
}

/// Convert scan results to an OCSF NDJSON string (one JSON object per line).
pub fn to_ocsf_ndjson(results: &ScanResults) -> Result<String> {
    let mut buf = String::new();
    for finding in &results.findings {
        let mut ocsf = OcsfFinding::from(finding);
        // Inject the scan-level risk score into each OCSF record.
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
}
