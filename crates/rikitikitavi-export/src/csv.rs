use anyhow::Result;
use rikitikitavi_models::ScanResults;
use std::path::Path;

/// Export findings as CSV, sorted by severity descending.
pub fn export_csv(results: &ScanResults, path: &Path) -> Result<()> {
    tracing::info!(?path, "exporting CSV report");

    let mut sorted_findings = results.findings.clone();
    sorted_findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

    let mut out = String::from(
        "severity,scanner,title,description,affected_ip,affected_hostname,affected_port,affected_service,cwe_id,cve_ids,remediation,effort,evidence\n",
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

/// Leading characters a spreadsheet interprets as a formula (OWASP CSV injection).
const FORMULA_TRIGGERS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// Quotes fields containing `,` `"` CR or LF; prefixes `'` to formula-leading fields.
fn csv_escape(field: &str) -> String {
    let neutralised = if field.starts_with(FORMULA_TRIGGERS) {
        format!("'{field}")
    } else {
        field.to_owned()
    };
    if neutralised.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", neutralised.replace('"', "\"\""))
    } else {
        neutralised
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
    fn test_csv_escape_bare_cr_quoted() {
        assert_eq!(csv_escape("a\rb"), "\"a\rb\"");
    }

    #[test]
    fn test_csv_escape_formula_triggers_prefixed() {
        for (input, expected) in [
            ("=1+1", "'=1+1"),
            ("+cmd", "'+cmd"),
            ("-cmd", "'-cmd"),
            ("@SUM(A1)", "'@SUM(A1)"),
            ("\tx", "'\tx"),
        ] {
            assert_eq!(csv_escape(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn test_csv_escape_leading_cr_prefixed_and_quoted() {
        assert_eq!(csv_escape("\rx"), "\"'\rx\"");
    }

    #[test]
    fn test_csv_escape_formula_with_comma_prefixed_then_quoted() {
        assert_eq!(
            csv_escape("=cmd|' /C calc'!A0,x"),
            "\"'=cmd|' /C calc'!A0,x\""
        );
    }

    #[test]
    fn test_csv_escape_negative_number_prefixed() {
        assert_eq!(csv_escape("-5"), "'-5");
    }

    #[test]
    fn test_csv_escape_trigger_not_at_start_untouched() {
        assert_eq!(csv_escape("a=b"), "a=b");
        assert_eq!(csv_escape("x-5"), "x-5");
        assert_eq!(csv_escape("user@host"), "user@host");
    }

    #[test]
    fn test_csv_export_neutralises_evidence_formula() {
        let findings = vec![
            Finding::new(
                "test",
                "=HYPERLINK(\"http://evil\")",
                "desc",
                Severity::High,
            )
            .with_hostname("@host")
            .with_evidence("=1+1"),
        ];
        let results = make_results(findings);
        let tmp = std::env::temp_dir().join("rikitikitavi_csv_test_formula.csv");
        export_csv(&results, &tmp).unwrap();
        let content = std::fs::read_to_string(&tmp).unwrap();
        let row = content.lines().nth(1).unwrap();
        assert!(
            row.contains(",\"'=HYPERLINK(\"\"http://evil\"\")\","),
            "{row}"
        );
        assert!(row.contains(",'@host,"), "{row}");
        assert!(row.ends_with(",'=1+1"), "{row}");
        let _ = std::fs::remove_file(&tmp);
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
                assert!(!escaped.contains('\r'), "unquoted field contains CR");
            }
        }

        /// The unquoted cell value never starts with a formula trigger.
        #[test]
        fn prop_csv_escape_never_formula_leading(input in proptest::prelude::any::<String>()) {
            let escaped = csv_escape(&input);
            let cell = escaped.strip_prefix('"').unwrap_or(&escaped);
            assert!(!cell.starts_with(FORMULA_TRIGGERS), "formula-leading cell: {escaped:?}");
        }

        /// csv_escape preserves the original content (can be unescaped) apart from the `'` guard.
        #[test]
        fn prop_csv_escape_roundtrip(input in proptest::prelude::any::<String>()) {
            let escaped = csv_escape(&input);
            let recovered = if escaped.starts_with('"') && escaped.ends_with('"') {
                escaped[1..escaped.len()-1].replace("\"\"", "\"")
            } else {
                escaped
            };
            let expected = if input.starts_with(FORMULA_TRIGGERS) {
                format!("'{input}")
            } else {
                input.clone()
            };
            assert_eq!(recovered, expected, "roundtrip failed for input: {input:?}");
        }
    }
}
