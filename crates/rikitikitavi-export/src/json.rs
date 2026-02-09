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
