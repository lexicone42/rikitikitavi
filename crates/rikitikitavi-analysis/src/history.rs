use anyhow::{Context, Result};
use rikitikitavi_models::ScanResults;
use std::path::PathBuf;

/// Maximum number of scan history files to retain.
const MAX_HISTORY: usize = 10;

/// Persistent scan history stored as timestamped JSON files.
///
/// Default location: `~/.local/share/rikitikitavi/scans/` (XDG data dir).
/// Each scan is saved as `scan-YYYYMMDD-HHMMSS.json`, sorted chronologically
/// by filename. Oldest scans beyond `MAX_HISTORY` are pruned automatically.
pub struct ScanHistory {
    data_dir: PathBuf,
}

impl ScanHistory {
    /// Create a history store in the XDG data directory.
    /// Returns `None` if the platform has no data directory.
    pub fn new() -> Option<Self> {
        let dir = dirs::data_dir()?.join("rikitikitavi/scans");
        Some(Self { data_dir: dir })
    }

    /// Create a history store in a specific directory (for testing).
    pub const fn with_dir(path: PathBuf) -> Self {
        Self { data_dir: path }
    }

    /// Save scan results to a timestamped JSON file. Prunes old scans.
    pub fn save(&self, results: &ScanResults) -> Result<PathBuf> {
        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("creating scan history dir: {}", self.data_dir.display()))?;

        let filename = format!(
            "scan-{}.json",
            results.scanned_at.format("%Y%m%d-%H%M%S")
        );
        let path = self.data_dir.join(filename);
        let json = serde_json::to_string_pretty(results)
            .context("serializing scan results")?;
        std::fs::write(&path, json)
            .with_context(|| format!("writing scan file: {}", path.display()))?;
        self.prune()?;
        Ok(path)
    }

    /// Load the most recent scan from history. Returns `None` if no scans exist.
    pub fn load_latest(&self) -> Result<Option<ScanResults>> {
        let scans = self.list_scans()?;
        let Some(latest) = scans.last() else {
            return Ok(None);
        };
        let json = std::fs::read_to_string(latest)
            .with_context(|| format!("reading scan file: {}", latest.display()))?;
        let results: ScanResults = serde_json::from_str(&json)
            .with_context(|| format!("parsing scan file: {}", latest.display()))?;
        Ok(Some(results))
    }

    /// List all scan files, sorted chronologically (oldest first).
    pub fn list_scans(&self) -> Result<Vec<PathBuf>> {
        if !self.data_dir.exists() {
            return Ok(Vec::new());
        }
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&self.data_dir)
            .with_context(|| format!("reading scan history dir: {}", self.data_dir.display()))?
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|ext| ext == "json")
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("scan-"))
            })
            .collect();
        entries.sort();
        Ok(entries)
    }

    /// Remove oldest scans to stay within `MAX_HISTORY`.
    pub fn prune(&self) -> Result<()> {
        let scans = self.list_scans()?;
        if scans.len() > MAX_HISTORY {
            let to_remove = scans.len() - MAX_HISTORY;
            for path in scans.iter().take(to_remove) {
                std::fs::remove_file(path)
                    .with_context(|| format!("pruning old scan: {}", path.display()))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rikitikitavi_core::Severity;
    use rikitikitavi_models::Finding;

    fn sample_results() -> ScanResults {
        ScanResults {
            findings: vec![
                Finding::new("ports", "SSH open", "desc", Severity::Medium),
            ],
            risk_score: 42.0,
            scanned_at: Utc::now(),
            ..Default::default()
        }
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let history = ScanHistory::with_dir(dir.path().to_path_buf());
        let results = sample_results();

        let path = history.save(&results).unwrap();
        assert!(path.exists());

        let loaded = history.load_latest().unwrap().unwrap();
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.findings[0].title, "SSH open");
        assert!((loaded.risk_score - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_dir_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let history = ScanHistory::with_dir(dir.path().to_path_buf());
        assert!(history.load_latest().unwrap().is_none());
    }

    #[test]
    fn nonexistent_dir_returns_none() {
        let history = ScanHistory::with_dir(PathBuf::from("/nonexistent/path/scans"));
        assert!(history.load_latest().unwrap().is_none());
    }

    #[test]
    fn list_scans_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let history = ScanHistory::with_dir(dir.path().to_path_buf());

        // Save 3 scans with different timestamps
        for i in 0..3 {
            let mut results = sample_results();
            results.scanned_at = chrono::DateTime::parse_from_rfc3339(
                &format!("2026-01-0{}T12:00:00Z", i + 1),
            )
            .unwrap()
            .with_timezone(&Utc);
            history.save(&results).unwrap();
        }

        let scans = history.list_scans().unwrap();
        assert_eq!(scans.len(), 3);
        // Filenames sort chronologically
        let names: Vec<String> = scans
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_owned())
            .collect();
        assert!(names[0] < names[1]);
        assert!(names[1] < names[2]);
    }

    #[test]
    fn prune_keeps_max_history() {
        let dir = tempfile::tempdir().unwrap();
        let history = ScanHistory::with_dir(dir.path().to_path_buf());

        // Save 12 scans (exceeds MAX_HISTORY of 10)
        for i in 0..12 {
            let mut results = sample_results();
            results.scanned_at = chrono::DateTime::parse_from_rfc3339(
                &format!("2026-01-{:02}T12:00:00Z", i + 1),
            )
            .unwrap()
            .with_timezone(&Utc);
            history.save(&results).unwrap();
        }

        let scans = history.list_scans().unwrap();
        assert_eq!(scans.len(), MAX_HISTORY);

        // The oldest 2 should have been pruned — first remaining is Jan 3
        let first_name = scans[0].file_name().unwrap().to_str().unwrap();
        assert!(
            first_name.contains("20260103"),
            "expected first scan to be Jan 3, got {first_name}"
        );
    }

    #[test]
    fn load_latest_gets_most_recent() {
        let dir = tempfile::tempdir().unwrap();
        let history = ScanHistory::with_dir(dir.path().to_path_buf());

        for i in 0..3 {
            let mut results = sample_results();
            results.risk_score = f64::from(i);
            results.scanned_at = chrono::DateTime::parse_from_rfc3339(
                &format!("2026-01-0{}T12:00:00Z", i + 1),
            )
            .unwrap()
            .with_timezone(&Utc);
            history.save(&results).unwrap();
        }

        let latest = history.load_latest().unwrap().unwrap();
        assert!((latest.risk_score - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ignores_non_scan_files() {
        let dir = tempfile::tempdir().unwrap();
        let history = ScanHistory::with_dir(dir.path().to_path_buf());

        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(dir.path().join("notes.txt"), "not a scan").unwrap();
        std::fs::write(dir.path().join("other.json"), "{}").unwrap();

        assert!(history.list_scans().unwrap().is_empty());
    }
}
