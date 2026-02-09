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

fn render_html_report(results: &ScanResults) -> String {
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
