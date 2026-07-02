use anyhow::Result;
use rikitikitavi_core::Severity;
use rikitikitavi_models::ScanResults;
use std::fmt::Write as FmtWrite;
use std::path::Path;

/// Export scan results as an HTML report.
pub fn export_html(results: &ScanResults, path: &Path) -> Result<()> {
    tracing::info!(?path, "exporting HTML report");

    let html = render_html_report(results);
    std::fs::write(path, html)?;

    Ok(())
}

/// Escape a string for safe inclusion in HTML content.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Map a severity to its CSS class name.
const fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

#[allow(clippy::too_many_lines)]
pub fn render_html_report(results: &ScanResults) -> String {
    let mut html = String::with_capacity(16384);

    // Count findings by severity
    let critical = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    let (grade_label, grade_color) = rikitikitavi_analysis::risk_grade(critical, high, medium);

    // ── HTML head + CSS ──────────────────────────────────────────────
    html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rikitikitavi Security Report</title>
  <style>
    :root {
      --critical: #e53e3e;
      --high: #ed8936;
      --medium: #ecc94b;
      --low: #48bb78;
      --info: #a0aec0;
      --bg: #1a202c;
      --card-bg: #2d3748;
      --text: #e2e8f0;
      --text-muted: #a0aec0;
      --border: #4a5568;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      max-width: 1100px;
      margin: 0 auto;
      padding: 2rem 1rem;
      line-height: 1.6;
    }
    h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
    h2 { font-size: 1.3rem; margin: 1.5rem 0 0.75rem; border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }
    h3 { font-size: 1.1rem; margin: 1rem 0 0.5rem; }
    .header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1.5rem; }
    .header h1 { flex: 1; }
    .grade {
      font-size: 1.4rem;
      font-weight: bold;
      padding: 0.5rem 1rem;
      border-radius: 8px;
      background: var(--card-bg);
    }
    .badges { display: flex; gap: 0.75rem; flex-wrap: wrap; margin: 1rem 0; }
    .badge {
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      font-weight: bold;
      font-size: 0.95rem;
      color: #1a202c;
    }
    .badge.critical { background: var(--critical); }
    .badge.high { background: var(--high); }
    .badge.medium { background: var(--medium); }
    .badge.low { background: var(--low); }
    .badge.info { background: var(--info); }
    .finding-card {
      background: var(--card-bg);
      border-radius: 8px;
      padding: 1rem;
      margin: 0.75rem 0;
      border-left: 4px solid var(--info);
    }
    .finding-card.critical { border-left-color: var(--critical); }
    .finding-card.high { border-left-color: var(--high); }
    .finding-card.medium { border-left-color: var(--medium); }
    .finding-card.low { border-left-color: var(--low); }
    .finding-card .title { font-weight: bold; margin-bottom: 0.3rem; }
    .finding-card .desc { color: var(--text-muted); margin-bottom: 0.5rem; }
    .finding-card .meta { font-size: 0.85rem; color: var(--text-muted); }
    .finding-card .meta a { color: var(--info); }
    .remediation {
      background: rgba(72, 187, 120, 0.1);
      border-radius: 4px;
      padding: 0.5rem 0.75rem;
      margin-top: 0.5rem;
    }
    .remediation strong { color: var(--low); }
    .remediation ol { margin: 0.3rem 0 0 1.2rem; }
    .remediation .effort { font-size: 0.85rem; color: var(--text-muted); margin-top: 0.3rem; }
    details { margin: 0.5rem 0; }
    details > summary {
      cursor: pointer;
      font-weight: bold;
      padding: 0.5rem;
      background: var(--card-bg);
      border-radius: 6px;
    }
    details > summary:hover { opacity: 0.9; }
    table { width: 100%; border-collapse: collapse; margin: 0.75rem 0; }
    th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
    th { background: var(--card-bg); font-weight: bold; }
    .bullets { margin: 0.5rem 0; padding-left: 1.2rem; }
    .bullets li { margin: 0.2rem 0; }
    .footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.85rem; color: var(--text-muted); }
  </style>
</head>
<body>
"#);

    // ── Executive Summary ────────────────────────────────────────────
    let _ = write!(
        html,
        r#"<div class="header">
  <h1>Rikitikitavi Security Report</h1>
  <div class="grade" style="color: var(--{grade_color});">{grade_label}</div>
</div>
<div class="badges">"#,
        grade_color = html_escape(grade_color),
        grade_label = html_escape(grade_label),
    );

    if critical > 0 {
        let _ = write!(
            html,
            r#"<span class="badge critical">{critical} Critical</span>"#
        );
    }
    if high > 0 {
        let _ = write!(html, r#"<span class="badge high">{high} High</span>"#);
    }
    if medium > 0 {
        let _ = write!(html, r#"<span class="badge medium">{medium} Medium</span>"#);
    }
    if low > 0 {
        let _ = write!(html, r#"<span class="badge low">{low} Low</span>"#);
    }
    if info > 0 {
        let _ = write!(html, r#"<span class="badge info">{info} Info</span>"#);
    }
    html.push_str("</div>\n");

    // Critical + High bullet list
    let urgent: Vec<_> = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
        .collect();
    if !urgent.is_empty() {
        html.push_str(r#"<h3>Urgent Findings</h3><ul class="bullets">"#);
        for f in &urgent {
            let ip = f
                .affected_ip
                .map_or_else(|| "-".to_owned(), |ip| ip.to_string());
            let _ = writeln!(
                html,
                "<li><span class=\"badge {cls}\">{sev}</span> {title} ({ip})</li>",
                cls = severity_class(f.severity),
                sev = html_escape(&f.severity.to_string()),
                title = html_escape(&f.title),
                ip = html_escape(&ip),
            );
        }
        html.push_str("</ul>\n");
    }

    // ── Top 5 Priority Actions ────────────────────────────────────────
    if !results.priority_actions.is_empty() {
        html.push_str("<h2>Top 5 Priority Actions</h2>\n");
        for action in &results.priority_actions {
            let cls = severity_class(action.severity);
            let _ = write!(
                html,
                r#"<div class="finding-card {cls}"><div class="title">#{rank} {title}</div>"#,
                rank = action.rank,
                title = html_escape(&action.title),
            );

            let _ = write!(
                html,
                r#"<div class="meta"><span class="badge {cls}">{sev}</span> {devices} device(s), {findings} finding(s)</div>"#,
                sev = html_escape(&action.severity.to_string()),
                devices = action.affected_device_count,
                findings = action.finding_count,
            );

            if !action.steps.is_empty() {
                html.push_str(r#"<div class="remediation"><strong>Steps:</strong><ol>"#);
                for step in &action.steps {
                    let _ = write!(html, "<li>{}</li>", html_escape(step));
                }
                html.push_str("</ol>");
                if let Some(effort) = &action.effort {
                    let _ = write!(
                        html,
                        r#"<div class="effort">Estimated effort: {}</div>"#,
                        html_escape(effort),
                    );
                }
                html.push_str("</div>\n");
            }

            html.push_str("</div>\n");
        }
    }

    // ── Findings by Severity ─────────────────────────────────────────
    html.push_str("<h2>Findings by Severity</h2>\n");

    for &(sev, label) in &[
        (Severity::Critical, "Critical"),
        (Severity::High, "High"),
        (Severity::Medium, "Medium"),
        (Severity::Low, "Low"),
        (Severity::Info, "Informational"),
    ] {
        let sev_findings: Vec<_> = results
            .findings
            .iter()
            .filter(|f| f.severity == sev)
            .collect();
        if sev_findings.is_empty() {
            continue;
        }

        let open_attr = if sev == Severity::Critical || sev == Severity::High {
            " open"
        } else {
            ""
        };
        let _ = write!(
            html,
            r#"<details{open_attr}><summary><span class="badge {cls}">{label}</span> {count} finding(s)</summary>"#,
            cls = severity_class(sev),
            count = sev_findings.len(),
        );

        for f in &sev_findings {
            let _ = write!(
                html,
                r#"<div class="finding-card {cls}">"#,
                cls = severity_class(f.severity)
            );
            let kev_badge = if f.is_kev {
                r#" <span class="badge critical" title="Listed in the CISA Known Exploited Vulnerabilities catalog">⚠ ACTIVELY EXPLOITED</span>"#
            } else {
                ""
            };
            let conf_badge = match f.confidence {
                rikitikitavi_core::Confidence::Confirmed => {
                    r#" <span class="badge low" title="Actively demonstrated during the scan">✓ CONFIRMED</span>"#
                }
                rikitikitavi_core::Confidence::Inferred => {
                    r#" <span class="badge info" title="Heuristic — not directly demonstrated">~ INFERRED</span>"#
                }
                rikitikitavi_core::Confidence::Probable => "",
            };
            let _ = write!(
                html,
                r#"<div class="title">{}{kev_badge}{conf_badge}</div>"#,
                html_escape(&f.title)
            );
            let _ = write!(
                html,
                r#"<div class="desc">{}</div>"#,
                html_escape(&f.description)
            );

            if let Some(evidence) = &f.evidence {
                let _ = write!(
                    html,
                    r#"<div style="font-family:monospace;background:rgba(237,137,54,0.1);padding:0.4rem 0.6rem;border-radius:4px;margin-bottom:0.5rem;font-size:0.9rem;white-space:pre-wrap;">Evidence: {}</div>"#,
                    html_escape(evidence),
                );
            }

            html.push_str(r#"<div class="meta">"#);
            if let Some(cwe) = &f.cwe_id {
                let _ = write!(
                    html,
                    r#"<a href="https://cwe.mitre.org/data/definitions/{num}.html">{cwe}</a> "#,
                    num = cwe.trim_start_matches("CWE-"),
                    cwe = html_escape(cwe),
                );
            }
            if let Some(ip) = f.affected_ip {
                let _ = write!(html, "IP: {} ", html_escape(&ip.to_string()));
            }
            if let Some(port) = f.affected_port {
                let _ = write!(html, "Port: {port} ");
            }
            if !f.cve_ids.is_empty() {
                let cves: Vec<String> = f.cve_ids.iter().map(|c| html_escape(c)).collect();
                let _ = write!(html, "CVEs: {} ", cves.join(", "));
            }
            html.push_str("</div>\n");

            if let Some(remediation) = &f.remediation {
                html.push_str(r#"<div class="remediation">"#);
                let _ = write!(
                    html,
                    "<strong>Fix:</strong> {}",
                    html_escape(&remediation.description)
                );
                if !remediation.steps.is_empty() {
                    html.push_str("<ol>");
                    for step in &remediation.steps {
                        let _ = write!(html, "<li>{}</li>", html_escape(step));
                    }
                    html.push_str("</ol>");
                }
                if let Some(effort) = &remediation.effort {
                    let _ = write!(
                        html,
                        r#"<div class="effort">Estimated effort: {}</div>"#,
                        html_escape(effort)
                    );
                }
                html.push_str("</div>\n");
            }

            html.push_str("</div>\n");
        }
        html.push_str("</details>\n");
    }

    // ── Device Inventory ─────────────────────────────────────────────
    if !results.devices.is_empty() {
        html.push_str("<h2>Device Inventory</h2>\n");
        html.push_str("<table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Type</th><th>Open Ports</th></tr>\n");

        // Sort by finding count per device (most-affected first)
        let mut devices = results.devices.clone();
        devices.sort_by(|a, b| {
            let a_findings = results
                .findings
                .iter()
                .filter(|f| f.affected_ip == Some(a.ip))
                .count();
            let b_findings = results
                .findings
                .iter()
                .filter(|f| f.affected_ip == Some(b.ip))
                .count();
            b_findings.cmp(&a_findings)
        });

        for device in &devices {
            let mac = device.mac.map_or_else(|| "-".to_owned(), |m| m.to_string());
            let vendor = device.vendor.as_deref().unwrap_or("Unknown");
            let device_type = format!("{:?}", device.device_type);
            let _ = writeln!(
                html,
                "<tr><td>{ip}</td><td>{mac}</td><td>{vendor}</td><td>{dtype}</td><td>{ports}</td></tr>",
                ip = html_escape(&device.ip.to_string()),
                mac = html_escape(&mac),
                vendor = html_escape(vendor),
                dtype = html_escape(&device_type),
                ports = device.open_ports.len(),
            );
        }
        html.push_str("</table>\n");
    }

    // ── Attack Paths ─────────────────────────────────────────────────
    if !results.attack_paths.is_empty() {
        html.push_str("<h2>Attack Paths</h2>\n");
        for path in &results.attack_paths {
            let _ = write!(
                html,
                r#"<div class="finding-card {cls}"><div class="title">{name}</div><div class="desc">{desc}</div>"#,
                cls = severity_class(path.severity),
                name = html_escape(&path.name),
                desc = html_escape(&path.description),
            );

            if !path.steps.is_empty() {
                html.push_str("<ol>");
                for step in &path.steps {
                    let technique = step.technique.as_deref().unwrap_or("");
                    let technique_label = if technique.is_empty() {
                        String::new()
                    } else {
                        format!(" <span class=\"meta\">[{}]</span>", html_escape(technique))
                    };
                    let _ = write!(
                        html,
                        "<li><strong>{title}</strong>{tech} — {desc}</li>",
                        title = html_escape(&step.title),
                        tech = technique_label,
                        desc = html_escape(&step.description),
                    );
                }
                html.push_str("</ol>");
            }
            html.push_str("</div>\n");
        }
    }

    // ── Footer ───────────────────────────────────────────────────────
    let _ = write!(
        html,
        r#"<div class="footer">
  Scanned in {duration}s | Risk score: {score:.0}/100 | {total} findings across {devices} devices |
  Generated by <strong>rikitikitavi</strong>
</div>
</body>
</html>"#,
        duration = results.scan_duration_secs,
        score = results.risk_score,
        total = results.findings.len(),
        devices = results.devices.len(),
    );

    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_models::{Finding, Remediation};

    fn make_results(findings: Vec<Finding>, risk_score: f64) -> ScanResults {
        ScanResults {
            findings,
            risk_score,
            ..Default::default()
        }
    }

    #[test]
    fn test_empty_results_valid_html() {
        let results = make_results(Vec::new(), 0.0);
        let html = render_html_report(&results);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<html"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn test_html_executive_summary_shows_critical_high() {
        let findings = vec![
            Finding::new("test", "Critical vuln", "Desc", Severity::Critical),
            Finding::new("test", "High vuln", "Desc", Severity::High),
            Finding::new("test", "Low vuln", "Desc", Severity::Low),
        ];
        let results = make_results(findings, 65.0);
        let html = render_html_report(&results);
        assert!(html.contains("1 Critical"));
        assert!(html.contains("1 High"));
        assert!(html.contains("Urgent Findings"));
        assert!(html.contains("Critical vuln"));
        assert!(html.contains("High vuln"));
    }

    #[test]
    fn test_html_findings_grouped_by_severity() {
        let findings = vec![
            Finding::new("test", "Crit 1", "Desc", Severity::Critical),
            Finding::new("test", "Med 1", "Desc", Severity::Medium),
            Finding::new("test", "Low 1", "Desc", Severity::Low),
        ];
        let results = make_results(findings, 40.0);
        let html = render_html_report(&results);
        // Critical should be in an open details
        assert!(html.contains(r"<details open>"));
        // Medium and Low should be in non-open details
        assert!(html.contains(r#"<details><summary><span class="badge medium">"#));
        assert!(html.contains(r#"<details><summary><span class="badge low">"#));
    }

    #[test]
    fn test_html_escaping() {
        let findings = vec![Finding::new(
            "test",
            "XSS <script>alert('hi')</script>",
            "Desc with \"quotes\" & <tags>",
            Severity::High,
        )];
        let results = make_results(findings, 50.0);
        let html = render_html_report(&results);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&amp;"));
        assert!(html.contains("&lt;tags&gt;"));
    }

    #[test]
    fn test_html_remediation_included() {
        let findings = vec![
            Finding::new("test", "Vuln", "Desc", Severity::High).with_remediation(Remediation {
                description: "Fix it now".to_owned(),
                steps: vec!["Step one".to_owned(), "Step two".to_owned()],
                effort: Some("5 minutes".to_owned()),
            }),
        ];
        let results = make_results(findings, 30.0);
        let html = render_html_report(&results);
        assert!(html.contains("Fix it now"));
        assert!(html.contains("Step one"));
        assert!(html.contains("Step two"));
        assert!(html.contains("5 minutes"));
    }

    #[test]
    fn test_html_contains_counts() {
        let findings = vec![
            Finding::new("test", "Finding 1", "Desc 1", Severity::High),
            Finding::new("test", "Finding 2", "Desc 2", Severity::Low),
        ];
        let results = make_results(findings, 65.0);
        let html = render_html_report(&results);
        assert!(html.contains("2 findings"));
    }

    #[test]
    fn test_html_risk_score_range() {
        let results = make_results(Vec::new(), 75.5);
        let html = render_html_report(&results);
        assert!(html.contains("76"));
    }

    proptest! {
        /// render_html_report never panics on arbitrary risk scores
        #[test]
        fn prop_render_html_no_panic(risk_score in 0.0_f64..=100.0_f64) {
            let results = make_results(Vec::new(), risk_score);
            let html = render_html_report(&results);
            assert!(html.contains("<!DOCTYPE html>"));
        }

        /// html_escape handles arbitrary strings without panicking
        #[test]
        fn prop_html_escape_no_panic(input in ".*") {
            let escaped = html_escape(&input);
            // Must not contain raw < or > (they should be escaped)
            assert!(!escaped.contains('<'));
            assert!(!escaped.contains('>'));
        }
    }
}
