use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Stable identity of a device across scan runs.
///
/// Uses MAC address when available (stable across DHCP), falls back to IP.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeviceFingerprint {
    Mac(String),
    Ip(IpAddr),
}

/// A discovered network device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// IP address.
    pub ip: IpAddr,
    /// MAC address (colon-separated hex).
    pub mac: Option<String>,
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
    #[must_use]
    pub fn with_mac(mut self, mac: impl Into<String>) -> Self {
        self.mac = Some(mac.into());
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
        self.mac.as_ref().map_or_else(
            || DeviceFingerprint::Ip(self.ip),
            |mac| DeviceFingerprint::Mac(mac.clone()),
        )
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
        assert_eq!(device.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
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
            DeviceFingerprint::Mac("aa:bb:cc:dd:ee:ff".to_owned())
        );
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
            assert_eq!(device.mac.as_deref(), Some(mac.as_str()));
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
