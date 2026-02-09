use anyhow::{Context, Result};
use rikitikitavi_models::config::AppConfig;
use std::path::Path;

/// Load configuration from a YAML file, falling back to defaults.
pub fn load_config(path: Option<&Path>) -> Result<AppConfig> {
    if let Some(p) = path {
        let contents = std::fs::read_to_string(p)
            .with_context(|| format!("failed to read config file: {}", p.display()))?;
        let config: AppConfig = serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse config file: {}", p.display()))?;
        tracing::info!(path = %p.display(), "loaded configuration");
        Ok(config)
    } else {
        // Try default locations
        for candidate in &["config.yaml", "config.yml", "/etc/rikitikitavi/config.yaml"] {
            let p = Path::new(candidate);
            if p.exists() {
                let contents = std::fs::read_to_string(p)?;
                let config: AppConfig = serde_yaml::from_str(&contents)?;
                tracing::info!(path = %p.display(), "loaded configuration from default location");
                return Ok(config);
            }
        }
        tracing::info!("no config file found, using defaults");
        Ok(AppConfig::default())
    }
}

/// Validate that the configuration is internally consistent.
pub fn validate_config(config: &AppConfig) -> Result<()> {
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
