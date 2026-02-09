use serde::{Deserialize, Serialize};

/// `UniFi` device type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UniFiDevice {
    DreamMachine,
    DreamMachinePro,
    DreamMachineProMax,
    DreamMachineSE,
    DreamRouter,
    DreamWall,
    CloudGatewayUltra,
    CloudGatewayMax,
    CloudKeyGen2Plus,
    SecurityGateway,
    SecurityGatewayPro4,
    AccessPoint,
    Switch,
    Unknown,
}

/// Information about a `UniFi` site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: String,
    pub name: String,
    pub desc: Option<String>,
}

/// `UniFi` adopted device information (from controller).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdoptedDevice {
    pub mac: String,
    pub name: Option<String>,
    pub model: String,
    pub firmware_version: String,
    pub device_type: UniFiDevice,
    pub adopted: bool,
    pub state: DeviceState,
    pub ip: Option<String>,
}

/// Device adoption/connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceState {
    Connected,
    Disconnected,
    Provisioning,
    Upgrading,
    Adopting,
    Unknown,
}

/// `UniFi` client (endpoint connected to the network).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniFiClientInfo {
    pub mac: String,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub network: Option<String>,
    pub is_wired: bool,
    pub is_guest: bool,
}

/// `UniFi` WLAN configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WlanConfig {
    pub id: String,
    pub name: String,
    pub security: String,
    pub wpa_mode: Option<String>,
    pub pmf_mode: Option<String>,
    pub is_guest: bool,
    pub enabled: bool,
}

/// `UniFi` firewall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub name: Option<String>,
    pub action: String,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub enabled: bool,
}

/// `UniFi` network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub id: String,
    pub name: String,
    pub purpose: String,
    pub vlan_id: Option<u16>,
    pub subnet: Option<String>,
    pub dhcp_enabled: bool,
}

/// `UniFi` IDS/IPS event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsEvent {
    pub timestamp: i64,
    pub signature: String,
    pub category: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub action: String,
}
