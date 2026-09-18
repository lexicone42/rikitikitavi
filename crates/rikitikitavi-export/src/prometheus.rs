//! Prometheus text exposition format 0.0.4, for `node_exporter`'s textfile collector.
//!
//! Deliberately not `OpenMetrics`: the collector parses with `expfmt.NewTextParser`,
//! which rejects `# EOF`, `_created` series and OpenMetrics-only types, and would
//! publish `node_textfile_scrape_error 1` and drop the file. The collector also
//! ignores nothing and supports no timestamps, so none is ever appended — the scan
//! time is a gauge whose *value* is the epoch second.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use rikitikitavi_core::{Confidence, Severity};
use rikitikitavi_models::{DeviceStatus, Grade, ScanResults};

/// Metric name prefix.
const PREFIX: &str = "rikitikitavi";

/// End-of-life findings are marked with CWE-1104 (use of unmaintained components).
const EOL_CWE: &str = "CWE-1104";

/// Numeric value of a grade, best to worst; `NotAssessed` has no value.
const fn grade_value(grade: Grade) -> Option<f64> {
    match grade {
        Grade::A => Some(4.0),
        Grade::B => Some(3.0),
        Grade::C => Some(2.0),
        Grade::D => Some(1.0),
        Grade::F => Some(0.0),
        Grade::NotAssessed => None,
    }
}

/// Lowercase severity, matching the JSON spelling.
const fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Lowercase confidence.
const fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Inferred => "inferred",
        Confidence::Probable => "probable",
        Confidence::Confirmed => "confirmed",
    }
}

/// Escape a label value: backslash, double quote and newline, per the 0.0.4 spec.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            // Other control characters are legal but unreadable in a metrics file.
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// One `# HELP` / `# TYPE` header.
fn header(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {PREFIX}_{name} {help}");
    let _ = writeln!(out, "# TYPE {PREFIX}_{name} {kind}");
}

/// Render scan results as a Prometheus exposition document.
///
/// `devices_new` is emitted only when a known-devices file classified the hosts;
/// an unknown count is an absent series, not a zero.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_prometheus(results: &ScanResults) -> String {
    let mut out = String::new();

    header(
        &mut out,
        "devices_total",
        "Devices seen in the last scan.",
        "gauge",
    );
    let _ = writeln!(out, "{PREFIX}_devices_total {}", results.devices.len());

    let tracked = results
        .report_cards
        .iter()
        .any(|c| c.status != DeviceStatus::Untracked);
    if tracked {
        let new = results
            .report_cards
            .iter()
            .filter(|c| c.status == DeviceStatus::New)
            .count();
        header(
            &mut out,
            "devices_new",
            "Devices absent from the known-devices file.",
            "gauge",
        );
        let _ = writeln!(out, "{PREFIX}_devices_new {new}");
    }

    header(
        &mut out,
        "findings",
        "Findings by severity and evidence strength.",
        "gauge",
    );
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        for confidence in [
            Confidence::Confirmed,
            Confidence::Probable,
            Confidence::Inferred,
        ] {
            let n = results
                .findings
                .iter()
                .filter(|f| f.severity == severity && f.confidence == confidence)
                .count();
            let _ = writeln!(
                out,
                "{PREFIX}_findings{{severity=\"{}\",confidence=\"{}\"}} {n}",
                severity_label(severity),
                confidence_label(confidence),
            );
        }
    }

    header(
        &mut out,
        "kev_findings_total",
        "Findings whose CVEs are in the CISA KEV catalog.",
        "gauge",
    );
    let _ = writeln!(
        out,
        "{PREFIX}_kev_findings_total {}",
        results.findings.iter().filter(|f| f.is_kev).count()
    );

    header(
        &mut out,
        "eol_findings_total",
        "Findings of end-of-life software (CWE-1104).",
        "gauge",
    );
    let _ = writeln!(
        out,
        "{PREFIX}_eol_findings_total {}",
        results
            .findings
            .iter()
            .filter(|f| f.cwe_id.as_deref() == Some(EOL_CWE))
            .count()
    );

    header(&mut out, "risk_score", "Scan risk score, 0-100.", "gauge");
    let _ = writeln!(out, "{PREFIX}_risk_score {:.1}", results.risk_score);

    header(
        &mut out,
        "scan_duration_seconds",
        "Wall-clock duration of the scan.",
        "gauge",
    );
    let _ = writeln!(
        out,
        "{PREFIX}_scan_duration_seconds {}",
        results.scan_duration_secs
    );

    header(
        &mut out,
        "last_scan_timestamp_seconds",
        "Epoch second the scan finished. A value, never a sample timestamp.",
        "gauge",
    );
    let _ = writeln!(
        out,
        "{PREFIX}_last_scan_timestamp_seconds {}",
        results.scanned_at.timestamp()
    );

    if !results.report_cards.is_empty() {
        header(
            &mut out,
            "devices_by_grade",
            "Devices per report-card grade.",
            "gauge",
        );
        for grade in Grade::ALL {
            let n = results
                .report_cards
                .iter()
                .filter(|c| c.grade == grade)
                .count();
            let _ = writeln!(
                out,
                "{PREFIX}_devices_by_grade{{grade=\"{}\"}} {n}",
                grade.as_str()
            );
        }

        header(
            &mut out,
            "device_grade",
            "Per-device grade as a number: A=4, B=3, C=2, D=1, F=0. Ungraded devices are absent.",
            "gauge",
        );
        for card in &results.report_cards {
            if let Some(value) = grade_value(card.grade) {
                let _ = writeln!(
                    out,
                    "{PREFIX}_device_grade{{ip=\"{}\"}} {value}",
                    escape(&card.ip.to_string())
                );
            }
        }
    }

    header(
        &mut out,
        "device_info",
        "Device identity, always 1. Join on the ip label.",
        "gauge",
    );
    for device in &results.devices {
        let status = results
            .report_cards
            .iter()
            .find(|c| c.ip == device.ip)
            .map_or(DeviceStatus::Untracked, |c| c.status);
        let _ = writeln!(
            out,
            "{PREFIX}_device_info{{ip=\"{ip}\",mac=\"{mac}\",vendor=\"{vendor}\",device_type=\"{dtype}\",hostname=\"{hostname}\",status=\"{status}\"}} 1",
            ip = escape(&device.ip.to_string()),
            mac = escape(&device.mac.map_or_else(String::new, |m| m.to_string())),
            vendor = escape(device.vendor.as_deref().unwrap_or_default()),
            dtype = device.device_type.as_str(),
            hostname = escape(device.hostname.as_deref().unwrap_or_default()),
            status = status.as_str(),
        );
    }

    out
}

/// Temporary path for the atomic write: `<path>.<pid>`.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{}", std::process::id()));
    PathBuf::from(name)
}

/// Write the exposition document to `path`, atomically.
///
/// The textfile collector reads whatever is on disk whenever it scrapes, so the file
/// is written under a temporary name and renamed into place.
pub fn export_prometheus(results: &ScanResults, path: &Path) -> Result<()> {
    tracing::info!(?path, "exporting Prometheus metrics");
    let body = render_prometheus(results);
    let temp = temp_path(path);
    rikitikitavi_core::fs::write_private(&temp, body.as_bytes())
        .with_context(|| format!("writing {}", temp.display()))?;
    if let Err(e) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(e)
            .with_context(|| format!("renaming {} to {}", temp.display(), path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
