use anyhow::{Context, Result};
use rikitikitavi_models::config::{AppConfig, MAX_PARALLELISM, ScanConfig};
use std::path::{Path, PathBuf};

/// Configuration plus the file it came from (`None` = built-in defaults).
#[derive(Debug)]
pub struct LoadedConfig {
    pub config: AppConfig,
    pub path: Option<PathBuf>,
}

const DEFAULT_LOCATIONS: [&str; 3] = ["config.yaml", "config.yml", "/etc/rikitikitavi/config.yaml"];

/// Load `path`, else the first existing default location, else defaults.
pub fn load_config(path: Option<&Path>) -> Result<LoadedConfig> {
    let path = path.map(Path::to_path_buf).or_else(|| {
        DEFAULT_LOCATIONS
            .iter()
            .map(Path::new)
            .find(|p| p.exists())
            .map(Path::to_path_buf)
    });
    let Some(p) = path else {
        tracing::info!("no config file found, using defaults");
        return Ok(LoadedConfig {
            config: AppConfig::default(),
            path: None,
        });
    };
    let config = read_config_file(&p)?;
    tracing::info!(path = %p.display(), "loaded configuration");
    Ok(LoadedConfig {
        config,
        path: Some(p),
    })
}

fn read_config_file(p: &Path) -> Result<AppConfig> {
    let contents = std::fs::read_to_string(p)
        .with_context(|| format!("failed to read config file: {}", p.display()))?;
    serde_yaml_ng::from_str(&contents)
        .with_context(|| format!("failed to parse config file: {}", p.display()))
}

/// Validate that the configuration is internally consistent.
pub fn validate_config(config: &AppConfig) -> Result<()> {
    validate_scan_config(&config.scan)?;
    if config.security_lake.enabled {
        if config.security_lake.bucket.is_none() {
            anyhow::bail!("security_lake.bucket is required when security_lake.enabled is true");
        }
        if config.security_lake.region.is_none() {
            anyhow::bail!("security_lake.region is required when security_lake.enabled is true");
        }
    }
    Ok(())
}

/// `parallelism` must be `1..=MAX_PARALLELISM`; exclusion entries must parse.
pub fn validate_scan_config(scan: &ScanConfig) -> Result<()> {
    if !(1..=MAX_PARALLELISM).contains(&scan.parallelism) {
        anyhow::bail!(
            "scan.parallelism must be 1..={MAX_PARALLELISM}, got {}",
            scan.parallelism
        );
    }
    scan.exclusions()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_with(parallelism: usize) -> ScanConfig {
        ScanConfig {
            parallelism,
            ..ScanConfig::default()
        }
    }

    #[test]
    fn parallelism_range_enforced() {
        assert!(validate_scan_config(&scan_with(0)).is_err());
        assert!(validate_scan_config(&scan_with(MAX_PARALLELISM + 1)).is_err());
        assert!(validate_scan_config(&scan_with(1)).is_ok());
        assert!(validate_scan_config(&scan_with(MAX_PARALLELISM)).is_ok());
        let msg = validate_scan_config(&scan_with(0)).unwrap_err().to_string();
        assert_eq!(msg, "scan.parallelism must be 1..=4096, got 0");
    }

    #[test]
    fn invalid_exclusion_entry_rejected() {
        let scan = ScanConfig {
            excluded_networks: vec!["not-a-cidr".to_owned()],
            ..ScanConfig::default()
        };
        let msg = validate_scan_config(&scan).unwrap_err().to_string();
        assert_eq!(msg, "scan.excluded_networks: invalid entry `not-a-cidr`");
        let mut app = AppConfig::default();
        app.scan.excluded_devices = vec!["kitchen".to_owned()];
        assert!(validate_config(&app).is_err());
    }

    #[test]
    fn explicit_path_is_reported() {
        let path = std::env::temp_dir().join(format!(
            "rikitikitavi-cfg-{}-explicit.yaml",
            std::process::id()
        ));
        std::fs::write(&path, "scan:\n  parallelism: 7\n").unwrap();
        let loaded = load_config(Some(&path)).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(loaded.path.as_deref(), Some(path.as_path()));
        assert_eq!(loaded.config.scan.parallelism, 7);
    }

    #[test]
    fn missing_explicit_path_is_error() {
        let path = std::env::temp_dir().join(format!(
            "rikitikitavi-cfg-{}-missing.yaml",
            std::process::id()
        ));
        let msg = load_config(Some(&path)).unwrap_err().to_string();
        assert!(msg.starts_with("failed to read config file: "), "{msg}");
    }
}
