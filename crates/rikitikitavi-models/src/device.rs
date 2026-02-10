use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
