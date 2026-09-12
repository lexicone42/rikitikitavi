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
    use proptest::prelude::*;

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

    fn arb_severity() -> impl Strategy<Value = Severity> {
        proptest::sample::select(&SEVERITIES[..])
    }

    fn arb_confidence() -> impl Strategy<Value = Confidence> {
        proptest::sample::select(&CONFIDENCES[..])
    }

    fn arb_perspective() -> impl Strategy<Value = Perspective> {
        proptest::sample::select(&PERSPECTIVES[..])
    }

    proptest! {
        /// `ocsf_id` is strictly monotone in the derived `Ord`, hence injective.
        #[test]
        fn prop_severity_ocsf_id_monotone(a in arb_severity(), b in arb_severity()) {
            prop_assert_eq!(a.cmp(&b), a.ocsf_id().cmp(&b.ocsf_id()));
        }

        /// `ocsf_id` lies in 1..=5.
        #[test]
        fn prop_severity_ocsf_id_in_range(s in arb_severity()) {
            prop_assert!((1..=5).contains(&s.ocsf_id()));
        }

        /// `Severity` `Display` is non-empty uppercase ASCII and injective.
        #[test]
        fn prop_severity_display_injective(a in arb_severity(), b in arb_severity()) {
            let (sa, sb) = (a.to_string(), b.to_string());
            prop_assert!(!sa.is_empty() && sa.bytes().all(|c| c.is_ascii_uppercase()));
            prop_assert_eq!(a == b, sa == sb);
        }

        /// `Confidence::label` equals `Display` and is injective.
        #[test]
        fn prop_confidence_label_equals_display_and_injective(
            a in arb_confidence(),
            b in arb_confidence(),
        ) {
            prop_assert_eq!(a.label(), a.to_string());
            prop_assert_eq!(a == b, a.label() == b.label());
        }

        /// `Perspective` `Display` is lowercase ASCII and injective.
        #[test]
        fn prop_perspective_display_injective(a in arb_perspective(), b in arb_perspective()) {
            let (sa, sb) = (a.to_string(), b.to_string());
            prop_assert!(!sa.is_empty() && sa.bytes().all(|c| c.is_ascii_lowercase()));
            prop_assert_eq!(a == b, sa == sb);
        }
    }
}
