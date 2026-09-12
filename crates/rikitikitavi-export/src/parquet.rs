use anyhow::Result;
use rikitikitavi_models::ScanResults;
use std::path::Path;

/// Parquet export for AWS Security Lake. Not implemented; always returns `Err`.
pub fn export_parquet(results: &ScanResults, path: &Path) -> Result<()> {
    tracing::info!(?path, "exporting Parquet report");
    let _ = results;
    Err(anyhow::anyhow!("Parquet export not yet implemented"))
}
