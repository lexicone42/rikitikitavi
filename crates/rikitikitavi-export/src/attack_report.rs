use anyhow::Result;
use rikitikitavi_models::AttackPath;
use std::path::Path;

/// Export attack paths as a standalone report.
pub fn export_attack_report(paths: &[AttackPath], output: &Path) -> Result<()> {
    tracing::info!(
        ?output,
        paths_count = paths.len(),
        "exporting attack path report"
    );
    let json = serde_json::to_string_pretty(paths)?;
    std::fs::write(output, json)?;
    Ok(())
}
