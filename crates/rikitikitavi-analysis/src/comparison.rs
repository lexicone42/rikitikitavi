use rikitikitavi_models::{Finding, ScanResults};

/// Differences between two scan runs.
#[derive(Debug, Clone, Default)]
pub struct ScanDiff {
    /// Findings present in the new scan but not the old.
    pub new_findings: Vec<Finding>,
    /// Findings present in the old scan but not the new (resolved).
    pub resolved_findings: Vec<Finding>,
    /// Findings present in both scans.
    pub unchanged_findings: Vec<Finding>,
}

/// Diff two scan results to find new, resolved, and unchanged findings.
pub fn diff_scan_results(old: &ScanResults, new: &ScanResults) -> ScanDiff {
    // TODO: Implement proper diffing based on finding fingerprints
    // (scanner + title + affected_ip + affected_port)
    tracing::info!(
        old_count = old.findings.len(),
        new_count = new.findings.len(),
        "diffing scan results"
    );

    // Simple placeholder: treat all new findings as new
    ScanDiff {
        new_findings: new.findings.clone(),
        resolved_findings: Vec::new(),
        unchanged_findings: Vec::new(),
    }
}
