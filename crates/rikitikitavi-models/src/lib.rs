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
    /// Absent in files written before this field existed; reads as `Full`.
    #[serde(default)]
    pub kind: ScanKind,
    /// Findings matched by an accepted-risk ledger entry; not in `findings`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted: Vec<AcceptedFinding>,
}

/// What produced a [`ScanResults`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    /// Discovery plus every selected scanner.
    #[default]
    Full,
    /// Replay of prior findings on their hosts only.
    Verify,
    /// Passive `WiFi` capture; no devices.
    Monitor,
}

/// A finding with the ledger entry that accepted it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptedFinding {
    pub finding: Finding,
    #[serde(with = "fingerprint_hex")]
    pub fingerprint: FindingFingerprint,
    pub reason: String,
    pub accepted_on: chrono::NaiveDate,
    pub expires: chrono::NaiveDate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensating: Option<String>,
}

/// [`FindingFingerprint`] as its 16-char hex string.
mod fingerprint_hex {
    use super::FindingFingerprint;
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S: Serializer>(fp: &FindingFingerprint, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(fp)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<FindingFingerprint, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_without_kind_or_accepted_load_as_full() {
        let json = r#"{"findings":[],"devices":[],"attack_paths":[],"risk_score":0.0,
            "scan_duration_secs":1,"scanned_at":"2026-01-01T00:00:00Z"}"#;
        let r: ScanResults = serde_json::from_str(json).unwrap();
        assert_eq!(r.kind, ScanKind::Full);
        assert!(r.accepted.is_empty());
    }

    #[test]
    fn kind_round_trips_and_empty_accepted_is_omitted() {
        let r = ScanResults {
            kind: ScanKind::Verify,
            ..Default::default()
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""kind":"verify""#));
        assert!(!json.contains("accepted"));
        let back: ScanResults = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, ScanKind::Verify);
    }

    #[test]
    fn accepted_fingerprint_serializes_as_hex() {
        let finding = Finding::new(
            "ports",
            "Telnet open",
            "d",
            rikitikitavi_core::Severity::High,
        );
        let fp = finding.fingerprint();
        let a = AcceptedFinding {
            finding,
            fingerprint: fp,
            reason: "isolated VLAN".to_owned(),
            accepted_on: chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            expires: chrono::NaiveDate::from_ymd_opt(2026, 6, 1).unwrap(),
            compensating: None,
        };
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["fingerprint"], fp.to_string());
        let back: AcceptedFinding = serde_json::from_value(v).unwrap();
        assert_eq!(back.fingerprint, fp);
    }
}
