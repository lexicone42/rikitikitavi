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
            devices: Vec::new(),
            attack_paths: Vec::new(),
            risk_score: 42.0,
            scan_duration_secs: 10,
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
                findings: Vec::new(),
                devices: Vec::new(),
                attack_paths: Vec::new(),
                risk_score: risk,
                scan_duration_secs: duration,
            };
            let json = to_json_string(&results).unwrap();
            assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
        }
    }
}
