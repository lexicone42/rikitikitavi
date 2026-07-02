use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::mac::MacAddr;

/// Stable identity of a device across scan runs.
///
/// Uses MAC address when available (stable across DHCP), falls back to IP.
/// The MAC variant holds a canonical [`MacAddr`], so the same physical address
/// fingerprints identically no matter how a scanner formatted it.
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
    /// Open ports discovered.
    pub open_ports: Vec<OpenPort>,
    /// When first seen on the network.
    pub first_seen: DateTime<Utc>,
    /// When last seen on the network.
    pub last_seen: DateTime<Utc>,
    /// Operating system guess.
    pub os_guess: Option<String>,
}

/// Classified device type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DeviceType {
    Router,
    Switch,
    AccessPoint,
    Desktop,
    Laptop,
    Phone,
    Tablet,
    Server,
    Nas,
    Printer,
    Camera,
    SmartTv,
    IoT,
    GameConsole,
    MediaPlayer,
    #[default]
    Unknown,
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
            open_ports: Vec::new(),
            first_seen: now,
            last_seen: now,
            os_guess: None,
        }
    }

    /// Builder-style setter for MAC address.
    ///
    /// Accepts any common textual form (colon/hyphen/dotted/bare hex, any case)
    /// and stores it canonically. An unparseable value is dropped (leaving the
    /// device to fingerprint by IP) rather than stored in a form that would not
    /// match the same address seen elsewhere.
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

    /// Compute a fingerprint that identifies this device across scan runs.
    /// Prefers MAC (stable across DHCP) over IP.
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

/// Hint about a device's identity, attached to findings by scanners that
/// discover device metadata. The runner merges hints into `Device` objects
/// using a priority-based strategy.
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
        let variants = [
            DeviceType::Router,
            DeviceType::Switch,
            DeviceType::AccessPoint,
            DeviceType::Desktop,
            DeviceType::Laptop,
            DeviceType::Phone,
            DeviceType::Tablet,
            DeviceType::Server,
            DeviceType::Nas,
            DeviceType::Printer,
            DeviceType::Camera,
            DeviceType::SmartTv,
            DeviceType::IoT,
            DeviceType::GameConsole,
            DeviceType::MediaPlayer,
            DeviceType::Unknown,
        ];

        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let recovered: DeviceType = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, *variant);
        }
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
        // The core bug this newtype fixes: the SAME physical MAC reported in
        // different formats/casing by different scanners must fingerprint equally.
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
        // Same MAC → same fingerprint even with different IPs (DHCP scenario)
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
