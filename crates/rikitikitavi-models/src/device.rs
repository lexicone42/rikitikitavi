use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::IpAddr;

use crate::mac::MacAddr;

/// Device identity across scan runs: canonical [`MacAddr`] when known, else IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeviceFingerprint {
    Mac(MacAddr),
    Ip(IpAddr),
}

/// A discovered network device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// IP address.
    pub ip: IpAddr,
    /// MAC address, stored canonically (see [`MacAddr`]).
    pub mac: Option<MacAddr>,
    /// Hostname.
    pub hostname: Option<String>,
    /// OUI vendor name (from MAC lookup).
    pub vendor: Option<String>,
    /// Classified device type.
    pub device_type: DeviceType,
    /// Free-text refinement of `device_type` (model family or role), e.g. `"hue_bridge"`.
    #[serde(default)]
    pub device_subtype: Option<String>,
    /// Open ports discovered.
    pub open_ports: Vec<OpenPort>,
    /// When first seen on the network.
    pub first_seen: DateTime<Utc>,
    /// When last seen on the network.
    pub last_seen: DateTime<Utc>,
    /// Operating system guess.
    pub os_guess: Option<String>,
}

/// Declares [`DeviceType`] once: variant, wire name, human label. `ALL`,
/// `as_str`, `label` and `from_name` are generated from this list.
macro_rules! device_types {
    ($( $(#[$meta:meta])* $variant:ident => $wire:literal, $label:literal ),* $(,)?) => {
        /// Classified device type.
        ///
        /// `as_str`/[`Display`](fmt::Display) give the frozen serde wire name
        /// (`smart_tv`, the legacy `io_t`); [`DeviceType::label`] gives the
        /// human spelling for reports. Unknown wire names deserialize to
        /// [`DeviceType::Unknown`] rather than failing the load.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub enum DeviceType {
            $( $(#[$meta])* $variant, )*
        }

        impl DeviceType {
            /// Every variant, in declaration order.
            pub const ALL: [Self; [$(stringify!($variant)),*].len()] = [$(Self::$variant),*];

            /// Wire name: the serde spelling, frozen for stored scan history.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $wire, )*
                }
            }

            /// Human label for reports and terminal output.
            #[must_use]
            pub const fn label(self) -> &'static str {
                match self {
                    $( Self::$variant => $label, )*
                }
            }

            /// Parse a wire name. `iot` is accepted as an alias for the legacy `io_t`.
            #[must_use]
            pub fn from_name(name: &str) -> Option<Self> {
                match name {
                    "iot" => Some(Self::IoT),
                    $( $wire => Some(Self::$variant), )*
                    _ => None,
                }
            }
        }
    };
}

device_types! {
    Router => "router", "Router",
    Switch => "switch", "Switch",
    AccessPoint => "access_point", "Access Point",
    Desktop => "desktop", "Desktop",
    Laptop => "laptop", "Laptop",
    Phone => "phone", "Phone",
    Tablet => "tablet", "Tablet",
    Server => "server", "Server",
    Nas => "nas", "NAS",
    Printer => "printer", "Printer",
    Camera => "camera", "Camera",
    SmartTv => "smart_tv", "Smart TV",
    /// Wire name is the legacy `snake_case` of `IoT`.
    IoT => "io_t", "IoT",
    GameConsole => "game_console", "Game Console",
    MediaPlayer => "media_player", "Media Player",
    /// Aggregation point holding other devices' credentials (`SmartThings`, Hue, Caseta).
    Hub => "hub", "Hub",
    SmartLock => "smart_lock", "Smart Lock",
    Thermostat => "thermostat", "Thermostat",
    EvCharger => "ev_charger", "EV Charger",
    /// Solar / battery inverter or gateway.
    Inverter => "inverter", "Inverter",
    /// Network video recorder.
    Nvr => "nvr", "NVR",
    Doorbell => "doorbell", "Doorbell",
    Vacuum => "vacuum", "Vacuum",
    SmartPlug => "smart_plug", "Smart Plug",
    Speaker => "speaker", "Speaker",
    /// Networked white goods.
    Appliance => "appliance", "Appliance",
    Printer3d => "printer3d", "3D Printer",
    Sensor => "sensor", "Sensor",
    #[default]
    Unknown => "unknown", "Unknown",
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for DeviceType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DeviceType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Ok(Self::from_name(&name).unwrap_or(Self::Unknown))
    }
}

impl Device {
    /// Create a new device with only an IP address, defaulting everything else.
    pub fn new(ip: IpAddr) -> Self {
        let now = Utc::now();
        Self {
            ip,
            mac: None,
            hostname: None,
            vendor: None,
            device_type: DeviceType::Unknown,
            device_subtype: None,
            open_ports: Vec::new(),
            first_seen: now,
            last_seen: now,
            os_guess: None,
        }
    }

    /// Builder-style setter for MAC address. Accepts any [`MacAddr`] textual form;
    /// an unparseable value is dropped (device then fingerprints by IP).
    #[must_use]
    pub fn with_mac(mut self, mac: impl AsRef<str>) -> Self {
        self.mac = mac.as_ref().parse().ok();
        self
    }

    /// Builder-style setter for device type.
    #[must_use]
    pub const fn with_device_type(mut self, device_type: DeviceType) -> Self {
        self.device_type = device_type;
        self
    }

    /// Builder-style setter for hostname.
    #[must_use]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Builder-style setter for device subtype.
    #[must_use]
    pub fn with_device_subtype(mut self, subtype: impl Into<String>) -> Self {
        self.device_subtype = Some(subtype.into());
        self
    }

    /// MAC fingerprint when known, else IP.
    pub fn fingerprint(&self) -> DeviceFingerprint {
        self.mac
            .map_or(DeviceFingerprint::Ip(self.ip), DeviceFingerprint::Mac)
    }
}

/// An open port on a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPort {
    pub port: u16,
    pub protocol: PortProtocol,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    Tcp,
    Udp,
}

/// Device metadata attached to a finding; the runner merges hints into `Device` by source priority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceHint {
    /// Vendor / manufacturer name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Model name / number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Hostname or friendly name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Classified device type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_type: Option<DeviceType>,
    /// Free-text refinement of `device_type`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_subtype: Option<String>,
    /// Operating system guess from banners / service probes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_guess: Option<String>,
}

impl DeviceHint {
    /// Create an empty hint (all fields `None`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style setter for vendor.
    #[must_use]
    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.vendor = Some(vendor.into());
        self
    }

    /// Builder-style setter for model.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Builder-style setter for hostname.
    #[must_use]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Builder-style setter for device type.
    #[must_use]
    pub const fn with_device_type(mut self, device_type: DeviceType) -> Self {
        self.device_type = Some(device_type);
        self
    }

    /// Builder-style setter for device subtype.
    #[must_use]
    pub fn with_device_subtype(mut self, subtype: impl Into<String>) -> Self {
        self.device_subtype = Some(subtype.into());
        self
    }

    /// Builder-style setter for OS guess.
    #[must_use]
    pub fn with_os_guess(mut self, os_guess: impl Into<String>) -> Self {
        self.os_guess = Some(os_guess.into());
        self
    }

    /// Returns `true` if all fields are `None`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.vendor.is_none()
            && self.model.is_none()
            && self.hostname.is_none()
            && self.device_type.is_none()
            && self.device_subtype.is_none()
            && self.os_guess.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_device_new_defaults() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let device = Device::new(ip);
        assert_eq!(device.ip, ip);
        assert!(device.mac.is_none());
        assert!(device.hostname.is_none());
        assert!(device.vendor.is_none());
        assert_eq!(device.device_type, DeviceType::Unknown);
        assert!(device.open_ports.is_empty());
        assert!(device.os_guess.is_none());
    }

    #[test]
    fn test_device_builder_chain() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let device = Device::new(ip)
            .with_mac("aa:bb:cc:dd:ee:ff")
            .with_hostname("myhost")
            .with_device_type(DeviceType::Router);

        assert_eq!(device.ip, ip);
        assert_eq!(
            device.mac.map(|m| m.to_string()).as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(device.hostname.as_deref(), Some("myhost"));
        assert_eq!(device.device_type, DeviceType::Router);
    }

    #[test]
    fn test_device_json_roundtrip() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let device = Device::new(ip)
            .with_mac("00:11:22:33:44:55")
            .with_device_type(DeviceType::Nas);

        let json = serde_json::to_string(&device).unwrap();
        let recovered: Device = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.ip, device.ip);
        assert_eq!(recovered.mac, device.mac);
        assert_eq!(recovered.device_type, device.device_type);
    }

    #[test]
    fn test_device_type_serialization() {
        for variant in DeviceType::ALL {
            let json = serde_json::to_string(&variant).unwrap();
            let recovered: DeviceType = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, variant);
        }
    }

    /// Wire names of the pre-widening variants are frozen: stored scan history
    /// and suppression baselines depend on them.
    #[test]
    fn device_type_legacy_wire_names_unchanged() {
        let legacy = [
            (DeviceType::Router, "router"),
            (DeviceType::Switch, "switch"),
            (DeviceType::AccessPoint, "access_point"),
            (DeviceType::Desktop, "desktop"),
            (DeviceType::Laptop, "laptop"),
            (DeviceType::Phone, "phone"),
            (DeviceType::Tablet, "tablet"),
            (DeviceType::Server, "server"),
            (DeviceType::Nas, "nas"),
            (DeviceType::Printer, "printer"),
            (DeviceType::Camera, "camera"),
            (DeviceType::SmartTv, "smart_tv"),
            (DeviceType::IoT, "io_t"),
            (DeviceType::GameConsole, "game_console"),
            (DeviceType::MediaPlayer, "media_player"),
            (DeviceType::Unknown, "unknown"),
        ];
        for (variant, name) in legacy {
            assert_eq!(variant.as_str(), name);
            assert_eq!(
                serde_json::to_string(&variant).unwrap(),
                format!("\"{name}\"")
            );
        }
    }

    #[test]
    fn device_type_new_variants_have_wire_names() {
        let added = [
            (DeviceType::Hub, "hub"),
            (DeviceType::SmartLock, "smart_lock"),
            (DeviceType::Thermostat, "thermostat"),
            (DeviceType::EvCharger, "ev_charger"),
            (DeviceType::Inverter, "inverter"),
            (DeviceType::Nvr, "nvr"),
            (DeviceType::Doorbell, "doorbell"),
            (DeviceType::Vacuum, "vacuum"),
            (DeviceType::SmartPlug, "smart_plug"),
            (DeviceType::Speaker, "speaker"),
            (DeviceType::Appliance, "appliance"),
            (DeviceType::Printer3d, "printer3d"),
            (DeviceType::Sensor, "sensor"),
        ];
        for (variant, name) in added {
            assert_eq!(variant.as_str(), name);
            assert_eq!(DeviceType::from_name(name), Some(variant));
        }
    }

    /// `Display` is the JSON spelling, so HTML and text output cannot drift from JSON.
    #[test]
    fn device_type_display_matches_json() {
        for variant in DeviceType::ALL {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(format!("\"{variant}\""), json);
        }
    }

    /// Wire names and labels, written out independently of `device_types!`.
    const WIRE_NAMES: [(DeviceType, &str, &str); 29] = [
        (DeviceType::Router, "router", "Router"),
        (DeviceType::Switch, "switch", "Switch"),
        (DeviceType::AccessPoint, "access_point", "Access Point"),
        (DeviceType::Desktop, "desktop", "Desktop"),
        (DeviceType::Laptop, "laptop", "Laptop"),
        (DeviceType::Phone, "phone", "Phone"),
        (DeviceType::Tablet, "tablet", "Tablet"),
        (DeviceType::Server, "server", "Server"),
        (DeviceType::Nas, "nas", "NAS"),
        (DeviceType::Printer, "printer", "Printer"),
        (DeviceType::Camera, "camera", "Camera"),
        (DeviceType::SmartTv, "smart_tv", "Smart TV"),
        (DeviceType::IoT, "io_t", "IoT"),
        (DeviceType::GameConsole, "game_console", "Game Console"),
        (DeviceType::MediaPlayer, "media_player", "Media Player"),
        (DeviceType::Hub, "hub", "Hub"),
        (DeviceType::SmartLock, "smart_lock", "Smart Lock"),
        (DeviceType::Thermostat, "thermostat", "Thermostat"),
        (DeviceType::EvCharger, "ev_charger", "EV Charger"),
        (DeviceType::Inverter, "inverter", "Inverter"),
        (DeviceType::Nvr, "nvr", "NVR"),
        (DeviceType::Doorbell, "doorbell", "Doorbell"),
        (DeviceType::Vacuum, "vacuum", "Vacuum"),
        (DeviceType::SmartPlug, "smart_plug", "Smart Plug"),
        (DeviceType::Speaker, "speaker", "Speaker"),
        (DeviceType::Appliance, "appliance", "Appliance"),
        (DeviceType::Printer3d, "printer3d", "3D Printer"),
        (DeviceType::Sensor, "sensor", "Sensor"),
        (DeviceType::Unknown, "unknown", "Unknown"),
    ];

    #[test]
    fn device_type_table_covers_every_variant() {
        assert_eq!(WIRE_NAMES.len(), DeviceType::ALL.len());
        for (variant, wire, label) in WIRE_NAMES {
            assert!(
                DeviceType::ALL.contains(&variant),
                "{wire} missing from ALL"
            );
            assert_eq!(variant.as_str(), wire);
            assert_eq!(variant.label(), label);
            assert_eq!(DeviceType::from_name(wire), Some(variant));
        }
    }

    #[test]
    fn device_type_labels_are_distinct_and_human() {
        let mut labels: Vec<&str> = DeviceType::ALL.iter().map(|t| t.label()).collect();
        let total = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), total);
        for t in DeviceType::ALL {
            assert!(!t.label().is_empty());
            assert!(!t.label().contains('_'), "{t} label is a wire name");
        }
        assert_eq!(DeviceType::IoT.label(), "IoT");
        assert_eq!(DeviceType::SmartTv.label(), "Smart TV");
    }

    #[test]
    fn device_type_all_names_are_unique() {
        let mut names: Vec<&str> = DeviceType::ALL.iter().map(|t| t.as_str()).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total);
    }

    #[test]
    fn device_type_from_name_roundtrips_all() {
        for variant in DeviceType::ALL {
            assert_eq!(DeviceType::from_name(variant.as_str()), Some(variant));
        }
        assert_eq!(DeviceType::from_name("no_such_type"), None);
    }

    #[test]
    fn device_type_iot_alias_accepted() {
        assert_eq!(DeviceType::from_name("iot"), Some(DeviceType::IoT));
        let d: DeviceType = serde_json::from_str("\"iot\"").unwrap();
        assert_eq!(d, DeviceType::IoT);
    }

    /// A type written by a newer build must not fail the whole scan-history load.
    #[test]
    fn device_type_unknown_variant_deserializes_to_unknown() {
        let d: DeviceType = serde_json::from_str("\"quantum_toaster\"").unwrap();
        assert_eq!(d, DeviceType::Unknown);
    }

    #[test]
    fn device_reads_json_without_device_subtype() {
        let json = r#"{"ip":"192.168.1.5","mac":null,"hostname":null,"vendor":null,
            "device_type":"io_t","open_ports":[],
            "first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z",
            "os_guess":null}"#;
        let device: Device = serde_json::from_str(json).unwrap();
        assert_eq!(device.device_type, DeviceType::IoT);
        assert!(device.device_subtype.is_none());
    }

    #[test]
    fn device_reads_json_with_unknown_device_type() {
        let json = r#"{"ip":"192.168.1.5","mac":null,"hostname":null,"vendor":null,
            "device_type":"hovercraft","device_subtype":"eel",
            "open_ports":[],
            "first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z",
            "os_guess":null}"#;
        let device: Device = serde_json::from_str(json).unwrap();
        assert_eq!(device.device_type, DeviceType::Unknown);
        assert_eq!(device.device_subtype.as_deref(), Some("eel"));
    }

    #[test]
    fn device_subtype_roundtrip() {
        let device = Device::new("10.0.0.7".parse().unwrap())
            .with_device_type(DeviceType::Hub)
            .with_device_subtype("hue_bridge");
        let json = serde_json::to_string(&device).unwrap();
        assert!(json.contains("\"device_subtype\":\"hue_bridge\""));
        let recovered: Device = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.device_type, DeviceType::Hub);
        assert_eq!(recovered.device_subtype.as_deref(), Some("hue_bridge"));
    }

    #[test]
    fn device_hint_carries_subtype() {
        let hint = DeviceHint::new()
            .with_device_type(DeviceType::EvCharger)
            .with_device_subtype("wall_connector");
        assert!(!hint.is_empty());
        let json = serde_json::to_string(&hint).unwrap();
        let recovered: DeviceHint = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, hint);
    }

    #[test]
    fn test_open_port_roundtrip() {
        let port = OpenPort {
            port: 443,
            protocol: PortProtocol::Tcp,
            service: Some("HTTPS".to_owned()),
            version: Some("1.1".to_owned()),
            banner: None,
        };

        let json = serde_json::to_string(&port).unwrap();
        let recovered: OpenPort = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.port, 443);
        assert_eq!(recovered.protocol, PortProtocol::Tcp);
        assert_eq!(recovered.service.as_deref(), Some("HTTPS"));
    }

    #[test]
    fn test_device_type_default() {
        assert_eq!(DeviceType::default(), DeviceType::Unknown);
    }

    #[test]
    fn fingerprint_uses_mac_when_available() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let device = Device::new(ip).with_mac("aa:bb:cc:dd:ee:ff");
        assert_eq!(
            device.fingerprint(),
            DeviceFingerprint::Mac("aa:bb:cc:dd:ee:ff".parse().unwrap())
        );
    }

    #[test]
    fn fingerprint_is_format_independent() {
        // Same MAC in different textual forms must fingerprint equally.
        let ip = "10.0.0.1".parse().unwrap();
        let a = Device::new(ip).with_mac("AA:BB:CC:DD:EE:FF");
        let b = Device::new(ip).with_mac("aa-bb-cc-dd-ee-ff");
        let c = Device::new(ip).with_mac("aabb.ccdd.eeff");
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(b.fingerprint(), c.fingerprint());
    }

    #[test]
    fn fingerprint_falls_back_to_ip() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let device = Device::new(ip);
        assert_eq!(device.fingerprint(), DeviceFingerprint::Ip(ip));
    }

    #[test]
    fn fingerprint_same_mac_same_fingerprint() {
        let d1 = Device::new("10.0.0.1".parse().unwrap()).with_mac("aa:bb:cc:dd:ee:ff");
        let d2 = Device::new("10.0.0.2".parse().unwrap()).with_mac("aa:bb:cc:dd:ee:ff");
        // Same MAC, different IPs.
        assert_eq!(d1.fingerprint(), d2.fingerprint());
    }

    #[test]
    fn fingerprint_different_mac_different_fingerprint() {
        let d1 = Device::new("10.0.0.1".parse().unwrap()).with_mac("aa:bb:cc:dd:ee:ff");
        let d2 = Device::new("10.0.0.1".parse().unwrap()).with_mac("11:22:33:44:55:66");
        assert_ne!(d1.fingerprint(), d2.fingerprint());
    }

    #[test]
    fn device_hint_builder() {
        let hint = DeviceHint::new()
            .with_vendor("Synology")
            .with_model("DS418play")
            .with_hostname("rudiger")
            .with_device_type(DeviceType::Nas)
            .with_os_guess("Linux (DSM)");

        assert_eq!(hint.vendor.as_deref(), Some("Synology"));
        assert_eq!(hint.model.as_deref(), Some("DS418play"));
        assert_eq!(hint.hostname.as_deref(), Some("rudiger"));
        assert_eq!(hint.device_type, Some(DeviceType::Nas));
        assert_eq!(hint.os_guess.as_deref(), Some("Linux (DSM)"));
        assert!(!hint.is_empty());
    }

    #[test]
    fn device_hint_default_is_empty() {
        let hint = DeviceHint::new();
        assert!(hint.is_empty());
    }

    #[test]
    fn device_hint_partial_is_not_empty() {
        let hint = DeviceHint::new().with_vendor("LG Electronics");
        assert!(!hint.is_empty());
    }

    #[test]
    fn device_hint_json_roundtrip() {
        let hint = DeviceHint::new()
            .with_vendor("Synology")
            .with_device_type(DeviceType::Nas);
        let json = serde_json::to_string(&hint).unwrap();
        let recovered: DeviceHint = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, hint);
    }

    #[test]
    fn device_hint_json_skips_none_fields() {
        let hint = DeviceHint::new().with_vendor("HP");
        let json = serde_json::to_string(&hint).unwrap();
        assert!(json.contains("vendor"));
        assert!(!json.contains("model"));
        assert!(!json.contains("hostname"));
        assert!(!json.contains("device_type"));
        assert!(!json.contains("os_guess"));
    }

    #[test]
    fn device_hint_deserializes_from_empty_object() {
        let hint: DeviceHint = serde_json::from_str("{}").unwrap();
        assert!(hint.is_empty());
    }

    proptest! {
        /// Builder chaining with arbitrary data preserves all fields
        #[test]
        fn prop_device_builder_preserves(
            a in 0_u8..=255_u8,
            b in 0_u8..=255_u8,
            c in 0_u8..=255_u8,
            d in 0_u8..=255_u8,
            mac in "[0-9a-f]{2}(:[0-9a-f]{2}){5}",
            hostname in "[a-z]{1,10}",
        ) {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            let device = Device::new(ip)
                .with_mac(&mac)
                .with_hostname(&hostname);

            assert_eq!(device.ip, ip);
            assert_eq!(device.mac.map(|m| m.to_string()).as_deref(), Some(mac.as_str()));
            assert_eq!(device.hostname.as_deref(), Some(hostname.as_str()));
        }

        /// Any string deserializes to a `DeviceType` without panicking, and only
        /// a real wire name yields a non-`Unknown` variant.
        #[test]
        fn prop_device_type_deserialize_never_panics(name in ".{0,40}") {
            let json = serde_json::to_string(&name).unwrap();
            let parsed: DeviceType = serde_json::from_str(&json).unwrap();
            let expected = WIRE_NAMES
                .iter()
                .find(|(_, wire, _)| *wire == name)
                .map_or(
                    if name == "iot" { DeviceType::IoT } else { DeviceType::Unknown },
                    |(v, _, _)| *v,
                );
            assert_eq!(parsed, expected);
        }

        /// Device JSON roundtrip preserves data
        #[test]
        fn prop_device_json_roundtrip(
            a in 1_u8..=254_u8,
            b in 0_u8..=255_u8,
            c in 0_u8..=255_u8,
            d in 1_u8..=254_u8,
        ) {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            let device = Device::new(ip);
            let json = serde_json::to_string(&device).unwrap();
            let recovered: Device = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered.ip, device.ip);
        }
    }
}
