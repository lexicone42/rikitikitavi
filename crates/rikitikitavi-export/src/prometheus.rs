//! Prometheus text exposition format 0.0.4, for `node_exporter`'s textfile collector.
//!
//! Not `OpenMetrics`: the collector parses with `expfmt.NewTextParser`, which rejects
//! `# EOF`, `_created` series and OpenMetrics-only types and would drop the file. It
//! supports no sample timestamps either, so the scan time is a gauge whose value is
//! the epoch second.
//!
//! Written 0644, not 0600 like the other exports: `node_exporter` reads it as its own
//! user.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use rikitikitavi_analysis::{Exploitation, ssvc_for};
use rikitikitavi_core::{Confidence, Severity};
use rikitikitavi_models::{DeviceStatus, Finding, Grade, ScanResults};

/// Metric name prefix.
const PREFIX: &str = "rikitikitavi";

/// End-of-life findings are marked with CWE-1104 (use of unmaintained components).
const EOL_CWE: &str = "CWE-1104";

/// The finding's worst Vulnrichment record is the `poc` tier: exploit code, no observed use.
fn poc_tier(finding: &Finding) -> bool {
    ssvc_for(finding).is_some_and(|s| s.exploitation == Exploitation::Poc)
}

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
        "devices",
        "Devices seen in the last scan.",
        "gauge",
    );
    let _ = writeln!(out, "{PREFIX}_devices {}", results.devices.len());

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
        "kev_findings",
        "Findings whose CVEs are in the CISA KEV catalog.",
        "gauge",
    );
    let _ = writeln!(
        out,
        "{PREFIX}_kev_findings {}",
        results.findings.iter().filter(|f| f.is_kev).count()
    );

    header(
        &mut out,
        "poc_findings",
        "Findings with public exploit code, no observed exploitation (CISA Vulnrichment).",
        "gauge",
    );
    let _ = writeln!(
        out,
        "{PREFIX}_poc_findings {}",
        results.findings.iter().filter(|f| poc_tier(f)).count()
    );

    header(
        &mut out,
        "eol_findings",
        "Findings of end-of-life software (CWE-1104).",
        "gauge",
    );
    let _ = writeln!(
        out,
        "{PREFIX}_eol_findings {}",
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

/// Mode of the exposition file.
#[cfg(unix)]
const TEXTFILE_MODE: u32 = 0o644;

/// Write `bytes` to `path` world-readable, creating or truncating it.
fn write_world_readable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(TEXTFILE_MODE);
    }
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    if file.metadata()?.is_file() {
        // The open mode is masked by umask. Devices and pipes keep their mode;
        // filesystems without modes are tolerated.
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(e) = file.set_permissions(std::fs::Permissions::from_mode(TEXTFILE_MODE))
            && !matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
            )
        {
            return Err(e);
        }
    }
    file.write_all(bytes)?;
    file.flush()
}

/// Temporary path for the atomic write: `<path>.<pid>`.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{}", std::process::id()));
    PathBuf::from(name)
}

/// Stderr warning that the 0644 exposition file is world-readable.
///
/// The mode stays 0644 (`node_exporter` reads it as its own user); the file must instead
/// live where only `node_exporter` and the operator can reach it.
#[cfg(unix)]
fn world_readable_warning(path: &Path) -> String {
    format!(
        "warning: {} is world-readable (mode 0644, required by node_exporter's textfile \
         collector) and lists every device on your network; keep it in a directory only \
         node_exporter and the operator can read",
        path.display()
    )
}

/// Write the exposition document to `path`, atomically.
///
/// The textfile collector reads whatever is on disk whenever it scrapes, so the file is
/// written under a temporary name and renamed into place.
///
/// Unless `quiet`, a stderr warning notes that the file is world-readable (0644): the mode
/// is required by the collector, so the fix is to place the file out of other users' reach.
pub fn export_prometheus(results: &ScanResults, path: &Path, quiet: bool) -> Result<()> {
    tracing::info!(?path, "exporting Prometheus metrics");
    let body = render_prometheus(results);
    let temp = temp_path(path);
    write_world_readable(&temp, body.as_bytes())
        .with_context(|| format!("writing {}", temp.display()))?;
    if let Err(e) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(e)
            .with_context(|| format!("renaming {} to {}", temp.display(), path.display()));
    }
    #[cfg(unix)]
    if !quiet {
        eprintln!("{}", world_readable_warning(path));
    }
    #[cfg(not(unix))]
    let _ = quiet;
    Ok(())
}

#[cfg(test)]
mod tests;
