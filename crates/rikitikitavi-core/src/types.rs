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

/// Evidence strength of a finding. Ordered `Inferred` < `Probable` < `Confirmed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Heuristic or indirect: OUI-only device type, port-open-only.
    Inferred,
    /// Banner/version match or header signature; not demonstrated.
    Probable,
    /// Demonstrated: successful login, observed listing/stream, unauthenticated response.
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

#[cfg(test)]
mod tests {
    use super::*;

    const SEVERITIES: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    const CONFIDENCES: [Confidence; 3] = [
        Confidence::Inferred,
        Confidence::Probable,
        Confidence::Confirmed,
    ];
    const PERSPECTIVES: [Perspective; 4] = [
        Perspective::Neighbor,
        Perspective::Unauthenticated,
        Perspective::Authenticated,
        Perspective::Privileged,
    ];

    /// `ocsf_id` lies in 1..=5 and is strictly monotone in the derived `Ord`, hence injective.
    #[test]
    fn severity_ocsf_id_in_range_and_monotone() {
        for a in SEVERITIES {
            assert!((1..=5).contains(&a.ocsf_id()), "{a:?}");
            for b in SEVERITIES {
                assert_eq!(a.cmp(&b), a.ocsf_id().cmp(&b.ocsf_id()), "{a:?} vs {b:?}");
            }
        }
    }

    /// `Severity` `Display` is non-empty uppercase ASCII and injective.
    #[test]
    fn severity_display_uppercase_and_injective() {
        for a in SEVERITIES {
            let sa = a.to_string();
            assert!(
                !sa.is_empty() && sa.bytes().all(|c| c.is_ascii_uppercase()),
                "{sa:?}"
            );
            for b in SEVERITIES {
                assert_eq!(a == b, sa == b.to_string(), "{a:?} vs {b:?}");
            }
        }
    }

    /// `Confidence::label` is injective.
    #[test]
    fn confidence_label_injective() {
        for a in CONFIDENCES {
            for b in CONFIDENCES {
                assert_eq!(a == b, a.label() == b.label(), "{a:?} vs {b:?}");
            }
        }
    }

    /// `Perspective` `Display` is non-empty lowercase ASCII and injective.
    #[test]
    fn perspective_display_lowercase_and_injective() {
        for a in PERSPECTIVES {
            let sa = a.to_string();
            assert!(
                !sa.is_empty() && sa.bytes().all(|c| c.is_ascii_lowercase()),
                "{sa:?}"
            );
            for b in PERSPECTIVES {
                assert_eq!(a == b, sa == b.to_string(), "{a:?} vs {b:?}");
            }
        }
    }
}
