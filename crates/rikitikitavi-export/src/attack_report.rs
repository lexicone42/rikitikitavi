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
    rikitikitavi_core::fs::write_private(output, json.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_attack_report_writes_json_array() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attack.json");
        export_attack_report(&[], &path).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(parsed.as_array().is_some_and(Vec::is_empty));
    }

    #[cfg(unix)]
    #[test]
    fn test_export_attack_report_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attack.json");
        export_attack_report(&[], &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
