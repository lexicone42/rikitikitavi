use anyhow::Result;
use rikitikitavi_models::ScanResults;
use std::path::Path;

/// Export scan findings as a CSV file.
///
/// Findings are sorted by severity descending (Critical first).
pub fn export_csv(results: &ScanResults, path: &Path) -> Result<()> {
    tracing::info!(?path, "exporting CSV report");

    // Sort findings by severity descending
    let mut sorted_findings = results.findings.clone();
    sorted_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let mut out = String::from(
        "severity,scanner,title,description,affected_ip,affected_hostname,affected_port,affected_service,cwe_id,cve_ids,remediation,effort,evidence\n"
    );

    for f in &sorted_findings {
        let ip = f.affected_ip.map_or_else(String::new, |ip| ip.to_string());
        let hostname = f.affected_hostname.as_deref().unwrap_or("");
        let port = f.affected_port.map_or_else(String::new, |p| p.to_string());
        let service = f.affected_service.as_deref().unwrap_or("");
        let cwe = f.cwe_id.as_deref().unwrap_or("");
        let cve_ids = f.cve_ids.join(";");
        let remediation = f
            .remediation
            .as_ref()
            .map_or_else(String::new, |r| r.description.clone());
        let effort = f
            .remediation
            .as_ref()
            .and_then(|r| r.effort.as_deref())
            .unwrap_or("");

        out.push_str(&csv_escape(&f.severity.to_string()));
        out.push(',');
        out.push_str(&csv_escape(&f.scanner));
        out.push(',');
        out.push_str(&csv_escape(&f.title));
        out.push(',');
        out.push_str(&csv_escape(&f.description));
        out.push(',');
        out.push_str(&csv_escape(&ip));
        out.push(',');
        out.push_str(&csv_escape(hostname));
        out.push(',');
        out.push_str(&csv_escape(&port));
        out.push(',');
        out.push_str(&csv_escape(service));
        out.push(',');
        out.push_str(&csv_escape(cwe));
        out.push(',');
        out.push_str(&csv_escape(&cve_ids));
        out.push(',');
        let evidence = f.evidence.as_deref().unwrap_or("");

        out.push_str(&csv_escape(&remediation));
        out.push(',');
        out.push_str(&csv_escape(effort));
        out.push(',');
        out.push_str(&csv_escape(evidence));
        out.push('\n');
    }

    std::fs::write(path, out)?;
    Ok(())
}

fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rikitikitavi_core::Severity;
    use rikitikitavi_models::{Finding, Remediation, ScanResults};

    fn make_results(findings: Vec<Finding>) -> ScanResults {
        ScanResults {
            findings,
            ..Default::default()
        }
    }

    #[test]
    fn test_csv_escape_plain() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn test_csv_escape_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn test_csv_escape_quotes() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_csv_sorted_by_severity() {
        let findings = vec![
            Finding::new("test", "Low", "desc", Severity::Low),
            Finding::new("test", "Critical", "desc", Severity::Critical),
            Finding::new("test", "Medium", "desc", Severity::Medium),
        ];
        let results = make_results(findings);
        let tmp = std::env::temp_dir().join("rikitikitavi_csv_test_sorted.csv");
        export_csv(&results, &tmp).unwrap();
        let content = std::fs::read_to_string(&tmp).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // Header + 3 findings
        assert_eq!(lines.len(), 4);
        assert!(lines[1].starts_with("CRITICAL"));
        assert!(lines[2].starts_with("MEDIUM"));
        assert!(lines[3].starts_with("LOW"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_csv_includes_description() {
        let findings = vec![Finding::new(
            "test",
            "Title",
            "A detailed description",
            Severity::High,
        )];
        let results = make_results(findings);
        let tmp = std::env::temp_dir().join("rikitikitavi_csv_test_desc.csv");
        export_csv(&results, &tmp).unwrap();
        let content = std::fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("A detailed description"));
        assert!(content.contains("description")); // header column
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_csv_includes_remediation() {
        let findings = vec![
            Finding::new("test", "Vuln", "desc", Severity::High).with_remediation(Remediation {
                description: "Fix this vulnerability".to_owned(),
                steps: vec!["Step 1".to_owned()],
                effort: Some("5 minutes".to_owned()),
            }),
        ];
        let results = make_results(findings);
        let tmp = std::env::temp_dir().join("rikitikitavi_csv_test_remed.csv");
        export_csv(&results, &tmp).unwrap();
        let content = std::fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("Fix this vulnerability"));
        assert!(content.contains("5 minutes"));
        let _ = std::fs::remove_file(&tmp);
    }

    // ─── Property-based tests ─────────────────────────────────────────

    proptest::proptest! {
        /// CSV escape never panics on arbitrary input.
        #[test]
        fn prop_csv_escape_no_panic(input in proptest::prelude::any::<String>()) {
            let _ = csv_escape(&input);
        }

        /// Escaped output never contains unescaped commas outside of quoted fields.
        #[test]
        fn prop_csv_escape_well_formed(input in proptest::prelude::any::<String>()) {
            let escaped = csv_escape(&input);
            if escaped.starts_with('"') {
                assert!(escaped.ends_with('"'), "quoted field does not end with quote");
            } else {
                assert!(!escaped.contains(','), "unquoted field contains comma");
                assert!(!escaped.contains('"'), "unquoted field contains quote");
                assert!(!escaped.contains('\n'), "unquoted field contains newline");
            }
        }

        /// csv_escape preserves the original content (can be unescaped).
        #[test]
        fn prop_csv_escape_roundtrip(input in proptest::prelude::any::<String>()) {
            let escaped = csv_escape(&input);
            let recovered = if escaped.starts_with('"') && escaped.ends_with('"') {
                escaped[1..escaped.len()-1].replace("\"\"", "\"")
            } else {
                escaped
            };
            assert_eq!(recovered, input, "roundtrip failed for input: {input:?}");
        }
    }
}
