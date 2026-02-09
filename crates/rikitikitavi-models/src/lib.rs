pub mod attack_path;
pub mod config;
pub mod device;
pub mod finding;
pub mod ocsf;

pub use attack_path::{AttackPath, AttackStep};
pub use config::ScanConfig;
pub use device::{Device, DeviceType};
pub use finding::{Finding, Remediation};
pub use ocsf::OcsfFinding;

use rikitikitavi_core::{NetworkMode, Perspective};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Context passed to every scanner, providing information about the target
/// environment and scan configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanContext {
    /// Target network CIDR.
    pub target_network: Option<ipnetwork::IpNetwork>,
    /// Gateway / router IP.
    pub gateway: Option<IpAddr>,
    /// Scan perspective (attacker model).
    pub perspective: Perspective,
    /// Network access mode.
    pub network_mode: NetworkMode,
    /// Full scan configuration.
    pub config: ScanConfig,
}

/// Aggregated results from a complete scan run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanResults {
    pub findings: Vec<Finding>,
    pub devices: Vec<Device>,
    pub attack_paths: Vec<AttackPath>,
    pub risk_score: f64,
    pub scan_duration_secs: u64,
}
