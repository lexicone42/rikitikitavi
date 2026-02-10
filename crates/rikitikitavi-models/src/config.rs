use rikitikitavi_core::{NetworkMode, Perspective};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Full application configuration (deserialized from config.yaml).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AppConfig {
    pub organization: OrganizationConfig,
    pub agent: AgentConfig,
    pub security_lake: SecurityLakeConfig,
    pub scan: ScanConfig,
    pub unifi: UniFiConfig,
    pub apis: ApiConfig,
    pub output: OutputConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OrganizationConfig {
    pub name: Option<String>,
    pub identifier: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub user_email: Option<String>,
    pub device_id: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityLakeConfig {
    pub enabled: bool,
    pub region: Option<String>,
    pub account_id: Option<String>,
    pub bucket: Option<String>,
    pub custom_source_name: Option<String>,
    pub role_arn: Option<String>,
}

/// Scanner-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub perspective: Perspective,
    pub network_mode: NetworkMode,
    pub intensity: ScanIntensity,
    pub timeout_seconds: u64,
    pub parallelism: usize,
    pub excluded_networks: Vec<String>,
    pub excluded_devices: Vec<String>,
    pub port_scan_range: PortRange,
    pub modules: Option<Vec<String>>,
    pub attack_paths: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            perspective: Perspective::default(),
            network_mode: NetworkMode::default(),
            intensity: ScanIntensity::Active,
            timeout_seconds: 300,
            parallelism: 100,
            excluded_networks: Vec::new(),
            excluded_devices: Vec::new(),
            port_scan_range: PortRange::Common,
            modules: None,
            attack_paths: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanIntensity {
    Passive,
    Active,
    Aggressive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PortRange {
    #[default]
    Common,
    Extended,
    Full,
    Custom(Vec<u16>),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UniFiConfig {
    pub mode: UniFiMode,
    pub controller: Option<UniFiControllerConfig>,
    pub cloud: Option<UniFiCloudConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UniFiMode {
    #[default]
    Auto,
    Local,
    Remote,
    Cloud,
    Disabled,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UniFiControllerConfig {
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub api_token: Option<String>,
    pub site: String,
    pub insecure: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UniFiCloudConfig {
    pub enabled: bool,
    pub api_key: Option<String>,
    pub site_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub shodan_api_key: Option<String>,
    pub censys_api_id: Option<String>,
    pub censys_api_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    pub local_report: bool,
    pub report_format: ReportFormat,
    pub report_path: PathBuf,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            local_report: true,
            report_format: ReportFormat::Html,
            report_path: PathBuf::from("./rikitikitavi-report"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Json,
    Html,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            format: "json".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_scan_config_defaults_sensible() {
        let config = ScanConfig::default();
        assert!(config.timeout_seconds > 0);
        assert!(config.parallelism > 0);
        assert!(config.attack_paths);
        assert!(config.modules.is_none());
        assert!(config.excluded_networks.is_empty());
    }

    #[test]
    fn test_app_config_default() {
        let config = AppConfig::default();
        assert!(config.organization.name.is_none());
        assert!(!config.security_lake.enabled);
        assert_eq!(config.output.report_format, ReportFormat::Html);
    }

    #[test]
    fn test_scan_config_yaml_roundtrip() {
        let config = ScanConfig {
            perspective: Perspective::Authenticated,
            intensity: ScanIntensity::Aggressive,
            timeout_seconds: 60,
            parallelism: 50,
            port_scan_range: PortRange::Extended,
            attack_paths: false,
            ..ScanConfig::default()
        };

        let yaml = serde_yaml_ng::to_string(&config).unwrap();
        let recovered: ScanConfig = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(recovered.timeout_seconds, 60);
        assert_eq!(recovered.parallelism, 50);
        assert!(!recovered.attack_paths);
    }

    #[test]
    fn test_partial_deserialization_uses_defaults() {
        let yaml = "timeout_seconds: 120\n";
        let config: ScanConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.timeout_seconds, 120);
        // Other fields should use defaults
        assert_eq!(config.parallelism, 100);
        assert!(config.attack_paths);
    }

    #[test]
    fn test_port_range_custom_roundtrip() {
        let range = PortRange::Custom(vec![22, 80, 443, 8080]);
        let json = serde_json::to_string(&range).unwrap();
        let recovered: PortRange = serde_json::from_str(&json).unwrap();
        if let PortRange::Custom(ports) = recovered {
            assert_eq!(ports, vec![22, 80, 443, 8080]);
        } else {
            panic!("expected Custom variant");
        }
    }

    #[test]
    fn test_scan_intensity_variants() {
        for (variant, expected) in [
            (ScanIntensity::Passive, "\"passive\""),
            (ScanIntensity::Active, "\"active\""),
            (ScanIntensity::Aggressive, "\"aggressive\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let recovered: ScanIntensity = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, variant);
        }
    }

    #[test]
    fn test_unifi_mode_variants() {
        for variant in [
            UniFiMode::Auto,
            UniFiMode::Local,
            UniFiMode::Remote,
            UniFiMode::Cloud,
            UniFiMode::Disabled,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let recovered: UniFiMode = serde_json::from_str(&json).unwrap();
            // Just check roundtrip doesn't panic
            let _ = recovered;
        }
    }

    proptest! {
        /// PortRange::Custom roundtrip with arbitrary Vec<u16>
        #[test]
        fn prop_port_range_custom_roundtrip(ports in proptest::collection::vec(1_u16..=65535_u16, 0..20)) {
            let range = PortRange::Custom(ports.clone());
            let json = serde_json::to_string(&range).unwrap();
            let recovered: PortRange = serde_json::from_str(&json).unwrap();
            if let PortRange::Custom(recovered_ports) = recovered {
                assert_eq!(recovered_ports, ports);
            } else {
                panic!("expected Custom variant");
            }
        }
    }
}
