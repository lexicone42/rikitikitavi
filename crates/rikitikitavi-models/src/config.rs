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
