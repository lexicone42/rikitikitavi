use serde::{Deserialize, Serialize};
use std::fmt;

/// Perspective modes for scanning — models attacker access level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Perspective {
    /// What can someone in `WiFi` range see without joining?
    Neighbor,
    /// What can someone who just joined the network do? (default)
    #[default]
    Unauthenticated,
    /// What can someone with user-level credentials see?
    Authenticated,
    /// Full audit with admin access.
    Privileged,
}

impl fmt::Display for Perspective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Neighbor => write!(f, "neighbor"),
            Self::Unauthenticated => write!(f, "unauthenticated"),
            Self::Authenticated => write!(f, "authenticated"),
            Self::Privileged => write!(f, "privileged"),
        }
    }
}

/// Network access modes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
#[derive(Default)]
pub enum NetworkMode {
    /// Auto-detect current connection.
    #[default]
    Auto,
    /// Connect to specific `WiFi`.
    Wifi {
        ssid: Option<String>,
        password: Option<String>,
    },
    /// Use specific ethernet interface.
    Ethernet { interface: Option<String> },
    /// Scan from external perspective.
    External { proxy: Option<String> },
}

/// Finding severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// OCSF severity ID.
    pub const fn ocsf_id(self) -> u8 {
        match self {
            Self::Info => 1,
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
            Self::Critical => 5,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}
