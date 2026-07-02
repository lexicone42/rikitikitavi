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

/// How strongly a finding is evidenced — the difference between "we saw the
/// door standing open" and "the banner suggests the door might be unlocked."
///
/// A home user who gets one wrong scary alert stops trusting the tool, so every
/// finding declares how it was established. Version-banner CVE matches are only
/// `Probable` (backported patches keep old banners); a successful default-cred
/// login or an observed directory listing is `Confirmed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Heuristic or indirect: OUI-only device type, port-open-only, a guess.
    Inferred,
    /// Strong but not demonstrated: banner/version match, header signature.
    Probable,
    /// Actively demonstrated: a login succeeded, a listing/stream was observed,
    /// an unauthenticated service answered.
    Confirmed,
}

impl Confidence {
    /// Short uppercase label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Inferred => "INFERRED",
            Self::Probable => "PROBABLE",
            Self::Confirmed => "CONFIRMED",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}
