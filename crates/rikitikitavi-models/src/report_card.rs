//! Per-device report card: a letter grade plus the tracking status of the host.
//!
//! The grade is this tool's own scoring of what it observed from the LAN. It is not
//! a conformance verdict against any scheme — ETSI EN 303 645 and the FCC Cyber Trust
//! Mark both rest on manufacturer evidence that no network scan can see.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::IpAddr;

use crate::{DeviceType, MacAddr};

/// Letter grade for one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
    /// Nothing was observed on the host, so no grade is claimed.
    #[default]
    NotAssessed,
}

impl Grade {
    /// Every variant, best first.
    pub const ALL: [Self; 6] = [
        Self::A,
        Self::B,
        Self::C,
        Self::D,
        Self::F,
        Self::NotAssessed,
    ];

    /// Wire and display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::F => "F",
            Self::NotAssessed => "not_assessed",
        }
    }

    /// Single-character form for dense tables; `-` when not assessed.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::A => 'A',
            Self::B => 'B',
            Self::C => 'C',
            Self::D => 'D',
            Self::F => 'F',
            Self::NotAssessed => '-',
        }
    }

    /// Severity class hint for renderers, matching `risk_grade`'s colour hints.
    #[must_use]
    pub const fn color_hint(self) -> &'static str {
        match self {
            Self::A => "info",
            Self::B => "low",
            Self::C => "medium",
            Self::D => "high",
            Self::F => "critical",
            Self::NotAssessed => "none",
        }
    }

    /// One letter worse; `F` and `NotAssessed` are unchanged.
    #[must_use]
    pub const fn step_down(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::C,
            Self::C => Self::D,
            Self::D | Self::F => Self::F,
            Self::NotAssessed => Self::NotAssessed,
        }
    }

    /// Parse a wire name; the single letters are accepted in either case.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|g| g.as_str().eq_ignore_ascii_case(name))
    }
}

impl fmt::Display for Grade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Grade {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Grade {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Ok(Self::from_name(&name).unwrap_or(Self::NotAssessed))
    }
}

/// Whether this host was seen before, in the sense the operator asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceStatus {
    /// Listed in the known-devices file.
    Known,
    /// Not listed in the known-devices file supplied for this scan.
    New,
    /// No known-devices file was supplied, so nothing is claimed.
    #[default]
    Untracked,
}

impl DeviceStatus {
    /// Every variant, in declaration order.
    pub const ALL: [Self; 3] = [Self::Known, Self::New, Self::Untracked];

    /// Wire and display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::New => "new",
            Self::Untracked => "untracked",
        }
    }

    /// Parse a wire name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == name)
    }
}

impl fmt::Display for DeviceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for DeviceStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DeviceStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Ok(Self::from_name(&name).unwrap_or(Self::Untracked))
    }
}

/// One device's grade, the counts behind it, and its tracking status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceReportCard {
    pub ip: IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub device_type: DeviceType,
    pub grade: Grade,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    /// Findings on this device that CISA lists as exploited in the wild.
    pub kev: usize,
    /// The device class cost a letter (it holds other devices' credentials, or
    /// actuates or records the physical world).
    pub class_weighted: bool,
    pub status: DeviceStatus,
    /// Terse statement of what produced the grade.
    pub rationale: String,
}

impl DeviceReportCard {
    /// Findings of Medium or worse.
    #[must_use]
    pub const fn actionable(&self) -> usize {
        self.critical + self.high + self.medium
    }

    /// Total findings behind the grade.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }

    /// Label for dense output: hostname if known, else the IP.
    #[must_use]
    pub fn label(&self) -> String {
        self.hostname.clone().unwrap_or_else(|| self.ip.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn grade_wire_names_round_trip() {
        for g in Grade::ALL {
            assert_eq!(Grade::from_name(g.as_str()), Some(g));
            let json = serde_json::to_string(&g).unwrap();
            let back: Grade = serde_json::from_str(&json).unwrap();
            assert_eq!(back, g);
        }
    }

    #[test]
    fn unknown_grade_name_reads_as_not_assessed() {
        let g: Grade = serde_json::from_str("\"Z\"").unwrap();
        assert_eq!(g, Grade::NotAssessed);
    }

    #[test]
    fn status_wire_names_round_trip() {
        for s in DeviceStatus::ALL {
            assert_eq!(DeviceStatus::from_name(s.as_str()), Some(s));
            let json = serde_json::to_string(&s).unwrap();
            let back: DeviceStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, s);
        }
    }

    #[test]
    fn step_down_saturates_at_f() {
        assert_eq!(Grade::A.step_down(), Grade::B);
        assert_eq!(Grade::D.step_down(), Grade::F);
        assert_eq!(Grade::F.step_down(), Grade::F);
        assert_eq!(Grade::NotAssessed.step_down(), Grade::NotAssessed);
    }

    #[test]
    fn display_matches_wire_name() {
        for g in Grade::ALL {
            assert_eq!(g.to_string(), g.as_str());
        }
        for s in DeviceStatus::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    #[test]
    fn ordering_is_best_first() {
        assert!(Grade::A < Grade::F);
        assert!(Grade::F < Grade::NotAssessed);
    }

    /// Real letter grades, excluding the `NotAssessed` sentinel.
    fn arb_real_grade() -> impl Strategy<Value = Grade> {
        prop::sample::select(vec![Grade::A, Grade::B, Grade::C, Grade::D, Grade::F])
    }

    proptest! {
        /// Survey #7: `Grade::from_name` is a case-insensitive round-trip over the wire names.
        #[test]
        fn prop_grade_from_name_round_trips(g in prop::sample::select(Grade::ALL.to_vec())) {
            let name = g.as_str();
            prop_assert_eq!(Grade::from_name(&name.to_ascii_uppercase()), Some(g));
            prop_assert_eq!(Grade::from_name(&name.to_ascii_lowercase()), Some(g));
        }

        /// Survey #7: `from_name` never panics and `Deserialize` maps unknown names to
        /// `NotAssessed`, known names to themselves.
        #[test]
        fn prop_grade_deserialize_never_panics(s in ".{0,32}") {
            let expected = Grade::from_name(&s).unwrap_or(Grade::NotAssessed);
            let json = serde_json::to_string(&s).unwrap();
            let g: Grade = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(g, expected);
        }

        /// Survey #8: `step_down` never improves a grade; `F` and `NotAssessed` are fixpoints.
        #[test]
        fn prop_step_down_is_monotone(g in prop::sample::select(Grade::ALL.to_vec())) {
            let d = g.step_down();
            prop_assert!(d >= g, "{g:?} -> {d:?}");
            if matches!(g, Grade::F | Grade::NotAssessed) {
                prop_assert_eq!(d, g);
            } else {
                prop_assert!(d > g);
            }
        }

        /// Survey #8: iterating `step_down` from any real grade converges to `F`.
        #[test]
        fn prop_step_down_converges_to_f(g in arb_real_grade()) {
            let mut cur = g;
            for _ in 0..5 {
                cur = cur.step_down();
            }
            prop_assert_eq!(cur, Grade::F);
        }

        /// Survey #9: `DeviceStatus::from_name` round-trips the wire names.
        #[test]
        fn prop_status_from_name_round_trips(s in prop::sample::select(DeviceStatus::ALL.to_vec())) {
            prop_assert_eq!(DeviceStatus::from_name(s.as_str()), Some(s));
        }

        /// Survey #9: `from_name` never panics and `Deserialize` maps unknown names to
        /// `Untracked`, known names to themselves.
        #[test]
        fn prop_status_deserialize_never_panics(s in ".{0,32}") {
            let expected = DeviceStatus::from_name(&s).unwrap_or(DeviceStatus::Untracked);
            let json = serde_json::to_string(&s).unwrap();
            let st: DeviceStatus = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(st, expected);
        }
    }
}
