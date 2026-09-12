use crate::{Device, MacAddr};
use ipnetwork::IpNetwork;
use rikitikitavi_core::{NetworkMode, Perspective};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
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
    /// Whole-scan bound in seconds; 0 = unbounded.
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
            timeout_seconds: 0,
            parallelism: 100,
            excluded_networks: Vec::new(),
            excluded_devices: Vec::new(),
            port_scan_range: PortRange::Common,
            modules: None,
            attack_paths: true,
        }
    }
}

/// Upper bound for `ScanConfig::parallelism`.
pub const MAX_PARALLELISM: usize = 4096;

impl ScanConfig {
    /// `parallelism` clamped to `1..=MAX_PARALLELISM`.
    #[must_use]
    pub const fn effective_parallelism(&self) -> usize {
        if self.parallelism == 0 {
            1
        } else if self.parallelism > MAX_PARALLELISM {
            MAX_PARALLELISM
        } else {
            self.parallelism
        }
    }

    /// Parse `excluded_networks` and `excluded_devices`.
    pub fn exclusions(&self) -> Result<ExclusionSet, ExclusionParseError> {
        ExclusionSet::parse(&self.excluded_networks, &self.excluded_devices)
    }
}

/// Parsed `excluded_networks` (CIDRs) and `excluded_devices` (IPs or MACs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExclusionSet {
    networks: Vec<IpNetwork>,
    ips: Vec<IpAddr>,
    macs: Vec<MacAddr>,
}

impl ExclusionSet {
    /// `networks` entries must be CIDRs; `devices` entries IPs or MACs.
    pub fn parse(networks: &[String], devices: &[String]) -> Result<Self, ExclusionParseError> {
        let mut set = Self::default();
        for entry in networks {
            let net = entry.trim().parse().map_err(|_| ExclusionParseError {
                field: "excluded_networks",
                entry: entry.clone(),
            })?;
            set.networks.push(net);
        }
        for entry in devices {
            let token = entry.trim();
            if let Ok(ip) = token.parse::<IpAddr>() {
                set.ips.push(ip);
            } else if let Ok(mac) = token.parse::<MacAddr>() {
                set.macs.push(mac);
            } else {
                return Err(ExclusionParseError {
                    field: "excluded_devices",
                    entry: entry.clone(),
                });
            }
        }
        Ok(set)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.networks.is_empty() && self.ips.is_empty() && self.macs.is_empty()
    }

    #[must_use]
    pub fn excludes_ip(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip) || self.networks.iter().any(|n| n.contains(ip))
    }

    #[must_use]
    pub fn excludes_mac(&self, mac: MacAddr) -> bool {
        self.macs.contains(&mac)
    }

    #[must_use]
    pub fn excludes_device(&self, device: &Device) -> bool {
        self.excludes_ip(device.ip) || device.mac.is_some_and(|m| self.excludes_mac(m))
    }
}

/// An `excluded_networks` / `excluded_devices` entry that did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExclusionParseError {
    pub field: &'static str,
    pub entry: String,
}

impl std::fmt::Display for ExclusionParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "scan.{}: invalid entry `{}`", self.field, self.entry)
    }
}

impl std::error::Error for ExclusionParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanIntensity {
    Passive,
    Active,
    Aggressive,
}

impl ScanIntensity {
    /// Numeric ordinal for comparison: `Passive` = 0, `Active` = 1, `Aggressive` = 2.
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        match self {
            Self::Passive => 0,
            Self::Active => 1,
            Self::Aggressive => 2,
        }
    }

    /// Returns `true` if this intensity is at least as aggressive as `other`.
    #[must_use]
    pub const fn at_least(self, other: Self) -> bool {
        self.ordinal() >= other.ordinal()
    }

    /// Human-readable scan profile name.
    #[must_use]
    pub const fn profile_name(self) -> &'static str {
        match self {
            Self::Passive => "Quick Scan",
            Self::Active => "Standard Scan",
            Self::Aggressive => "Deep Scan",
        }
    }
}

/// Top 20 most security-relevant ports for quick (Passive) scans.
pub const TOP_20_PORTS: [u16; 20] = [
    22, 23, 53, 80, 443, 445, 993, 995, 1883, 3306, 3389, 5353, 5432, 5900, 6379, 8080, 8443, 8883,
    9200, 27017,
];

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UniFiControllerConfig {
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub api_token: Option<String>,
    /// Controller site name; defaults to `default`.
    pub site: String,
    pub insecure: bool,
}

impl Default for UniFiControllerConfig {
    fn default() -> Self {
        Self {
            url: None,
            username: None,
            password: None,
            api_token: None,
            site: "default".to_owned(),
            insecure: false,
        }
    }
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
        assert_eq!(config.timeout_seconds, 0);
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
    fn test_scan_intensity_ordinal() {
        assert_eq!(ScanIntensity::Passive.ordinal(), 0);
        assert_eq!(ScanIntensity::Active.ordinal(), 1);
        assert_eq!(ScanIntensity::Aggressive.ordinal(), 2);
    }

    #[test]
    fn test_scan_intensity_at_least() {
        assert!(ScanIntensity::Aggressive.at_least(ScanIntensity::Passive));
        assert!(ScanIntensity::Aggressive.at_least(ScanIntensity::Active));
        assert!(ScanIntensity::Aggressive.at_least(ScanIntensity::Aggressive));
        assert!(ScanIntensity::Active.at_least(ScanIntensity::Passive));
        assert!(ScanIntensity::Active.at_least(ScanIntensity::Active));
        assert!(!ScanIntensity::Active.at_least(ScanIntensity::Aggressive));
        assert!(ScanIntensity::Passive.at_least(ScanIntensity::Passive));
        assert!(!ScanIntensity::Passive.at_least(ScanIntensity::Active));
    }

    #[test]
    fn test_scan_intensity_profile_name() {
        assert_eq!(ScanIntensity::Passive.profile_name(), "Quick Scan");
        assert_eq!(ScanIntensity::Active.profile_name(), "Standard Scan");
        assert_eq!(ScanIntensity::Aggressive.profile_name(), "Deep Scan");
    }

    #[test]
    fn test_top_20_ports_count() {
        assert_eq!(super::TOP_20_PORTS.len(), 20);
        // All ports should be valid (> 0)
        for &port in &super::TOP_20_PORTS {
            assert!(port > 0);
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

    #[test]
    fn test_unifi_controller_default_site() {
        assert_eq!(UniFiControllerConfig::default().site, "default");
    }

    #[test]
    fn test_unifi_controller_yaml_omitting_site_uses_default() {
        let yaml = "url: https://192.168.1.1\n";
        let config: UniFiControllerConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.url.as_deref(), Some("https://192.168.1.1"));
        assert_eq!(config.site, "default");

        let yaml = "unifi:\n  controller:\n    url: https://192.168.1.1\n";
        let app: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(app.unifi.controller.unwrap().site, "default");
    }

    #[test]
    fn test_unifi_controller_yaml_explicit_site_kept() {
        let yaml = "site: office\n";
        let config: UniFiControllerConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.site, "office");
    }

    fn owned(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn effective_parallelism_clamps() {
        let with = |parallelism| ScanConfig {
            parallelism,
            ..ScanConfig::default()
        };
        assert_eq!(with(0).effective_parallelism(), 1);
        assert_eq!(
            with(MAX_PARALLELISM + 1).effective_parallelism(),
            MAX_PARALLELISM
        );
        assert_eq!(with(64).effective_parallelism(), 64);
    }

    #[test]
    fn exclusion_set_matches_ip_cidr_and_mac() {
        let set = ExclusionSet::parse(
            &owned(&["10.0.0.0/24", " 2001:db8::/32 "]),
            &owned(&["192.168.1.5", "AA-BB-CC-DD-EE-FF"]),
        )
        .unwrap();
        assert!(!set.is_empty());
        assert!(set.excludes_ip("10.0.0.200".parse().unwrap()));
        assert!(set.excludes_ip("2001:db8::1".parse().unwrap()));
        assert!(!set.excludes_ip("10.0.1.1".parse().unwrap()));
        assert!(set.excludes_ip("192.168.1.5".parse().unwrap()));
        assert!(set.excludes_mac("aa:bb:cc:dd:ee:ff".parse().unwrap()));

        let by_mac = Device::new("192.168.1.9".parse().unwrap()).with_mac("aabb.ccdd.eeff");
        assert!(set.excludes_device(&by_mac));
        let by_ip = Device::new("192.168.1.5".parse().unwrap());
        assert!(set.excludes_device(&by_ip));
        let kept = Device::new("192.168.1.6".parse().unwrap()).with_mac("00:11:22:33:44:55");
        assert!(!set.excludes_device(&kept));
    }

    #[test]
    fn exclusion_set_rejects_bad_entries() {
        let err = ExclusionSet::parse(&owned(&["10.0.0.0/33"]), &[]).unwrap_err();
        assert_eq!(err.field, "excluded_networks");
        assert_eq!(err.entry, "10.0.0.0/33");
        let err = ExclusionSet::parse(&[], &owned(&["printer"])).unwrap_err();
        assert_eq!(err.field, "excluded_devices");
        assert_eq!(
            err.to_string(),
            "scan.excluded_devices: invalid entry `printer`"
        );
    }

    #[test]
    fn exclusion_set_default_is_empty() {
        let set = ScanConfig::default().exclusions().unwrap();
        assert!(set.is_empty());
        assert!(!set.excludes_ip("10.0.0.1".parse().unwrap()));
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
