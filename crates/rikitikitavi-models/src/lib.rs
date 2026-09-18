pub mod attack_path;
pub mod config;
pub mod device;
pub mod finding;
pub mod mac;
pub mod ocsf;
pub mod priority_action;
pub mod report_card;

pub use attack_path::{AttackPath, AttackStep};
pub use config::ScanConfig;
pub use device::{Device, DeviceFingerprint, DeviceHint, DeviceType};
pub use finding::{Finding, FindingFingerprint, Remediation};
pub use mac::MacAddr;
pub use ocsf::OcsfFinding;
pub use priority_action::PriorityAction;
pub use report_card::{DeviceReportCard, DeviceStatus, Grade};

use chrono::{DateTime, Utc};
use rikitikitavi_core::{NetworkMode, Perspective};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Per-scan context passed to every scanner.
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
    /// Devices found in Phase 1; Phase 2 scanners adapt their checks to them.
    #[serde(default)]
    pub discovered_devices: Vec<Device>,
}

/// Serde default for JSON files that predate `scanned_at`.
fn default_scan_time() -> DateTime<Utc> {
    Utc::now()
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
    /// Per-device grades and tracking status.
    #[serde(default)]
    pub report_cards: Vec<DeviceReportCard>,
    pub risk_score: f64,
    pub scan_duration_secs: u64,
    /// When this scan was performed.
    #[serde(default = "default_scan_time")]
    pub scanned_at: DateTime<Utc>,
}
