use anyhow::Result;
use rikitikitavi_models::ScanResults;
use std::path::Path;

/// Export scan results as a Parquet file for AWS Security Lake ingestion.
pub fn export_parquet(results: &ScanResults, path: &Path) -> Result<()> {
    tracing::info!(?path, "exporting Parquet report");
    let _ = results;
    // TODO: Implement Parquet export using the `parquet` crate
    // - Convert findings to OCSF schema
    // - Write Arrow record batches
    // - Partition by region/account_id/eventDay
    // - Snappy compression
    Err(anyhow::anyhow!("Parquet export not yet implemented"))
}
