pub mod attack_path;
pub mod config;
pub mod device;
pub mod finding;
pub mod ocsf;
pub mod priority_action;

pub use attack_path::{AttackPath, AttackStep};
pub use config::ScanConfig;
pub use device::{Device, DeviceType};
pub use finding::{Finding, Remediation};
pub use ocsf::OcsfFinding;
pub use priority_action::PriorityAction;

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
    /// Devices discovered during Phase 1 (network/port/device scanning).
    /// Phase 2 scanners use this to adapt their checks based on what was
    /// actually found on the network (open ports, device types, etc.).
    #[serde(default)]
    pub discovered_devices: Vec<Device>,
}

/// Aggregated results from a complete scan run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanResults {
    pub findings: Vec<Finding>,
    pub devices: Vec<Device>,
    pub attack_paths: Vec<AttackPath>,
    /// Top priority remediation actions (deduplicated and ranked).
    #[serde(default)]
    pub priority_actions: Vec<PriorityAction>,
    pub risk_score: f64,
    pub scan_duration_secs: u64,
}
