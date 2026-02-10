use anyhow::Result;
use rikitikitavi_models::ScanResults;
use std::path::Path;

/// Export scan results as an HTML report.
pub fn export_html(results: &ScanResults, path: &Path) -> Result<()> {
    tracing::info!(?path, "exporting HTML report");

    let html = render_html_report(results);
    std::fs::write(path, html)?;

    Ok(())
}

pub fn render_html_report(results: &ScanResults) -> String {
    // TODO: Implement a proper HTML template
    let findings_count = results.findings.len();
    let devices_count = results.devices.len();

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Rikitikitavi Security Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 0 auto; padding: 2rem; }}
    h1 {{ color: #2d3748; }}
    .summary {{ display: flex; gap: 1rem; margin: 1rem 0; }}
    .stat {{ padding: 1rem; border-radius: 8px; background: #f7fafc; }}
  </style>
</head>
<body>
  <h1>Rikitikitavi Security Report</h1>
  <div class="summary">
    <div class="stat"><strong>{findings_count}</strong> Findings</div>
    <div class="stat"><strong>{devices_count}</strong> Devices</div>
    <div class="stat">Risk Score: <strong>{:.0}</strong>/100</div>
  </div>
  <p>Detailed report generation is not yet implemented.</p>
</body>
</html>"#,
        results.risk_score
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_core::Severity;
    use rikitikitavi_models::Finding;

    fn make_results(findings: Vec<Finding>, risk_score: f64) -> ScanResults {
        ScanResults {
            findings,
            devices: Vec::new(),
            attack_paths: Vec::new(),
            risk_score,
            scan_duration_secs: 0,
        }
    }

    #[test]
    fn test_empty_results_valid_html() {
        let results = make_results(Vec::new(), 0.0);
        let html = render_html_report(&results);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<html>"));
        assert!(html.contains("</html>"));
        assert!(html.contains("<strong>0</strong> Findings"));
        assert!(html.contains("<strong>0</strong> Devices"));
    }

    #[test]
    fn test_html_contains_counts() {
        let findings = vec![
            Finding::new("test", "Finding 1", "Desc 1", Severity::High),
            Finding::new("test", "Finding 2", "Desc 2", Severity::Low),
        ];
        let results = make_results(findings, 65.0);
        let html = render_html_report(&results);
        assert!(html.contains("<strong>2</strong> Findings"));
        assert!(html.contains("65"));
    }

    #[test]
    fn test_html_risk_score_range() {
        let results = make_results(Vec::new(), 75.5);
        let html = render_html_report(&results);
        assert!(html.contains("76")); // Formatted as {:.0}
    }

    #[test]
    fn test_html_special_chars_in_title() {
        // Finding titles with special chars should not break HTML structure
        let findings = vec![Finding::new(
            "test",
            "XSS <script>alert('hi')</script>",
            "Desc with \"quotes\" & <tags>",
            Severity::High,
        )];
        let results = make_results(findings, 50.0);
        let html = render_html_report(&results);
        // The HTML should still be parseable (findings aren't rendered in detail yet)
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("</html>"));
    }

    proptest! {
        /// render_html_report never panics on arbitrary risk scores
        #[test]
        fn prop_render_html_no_panic(risk_score in 0.0_f64..=100.0_f64) {
            let results = make_results(Vec::new(), risk_score);
            let html = render_html_report(&results);
            assert!(html.contains("<!DOCTYPE html>"));
        }
    }
}
