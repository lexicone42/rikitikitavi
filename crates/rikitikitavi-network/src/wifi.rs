use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Information about a `WiFi` network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: String,
    pub channel: u32,
    pub frequency_mhz: u32,
    pub signal_strength_dbm: i32,
    pub encryption: WifiEncryption,
    pub wps_enabled: bool,
    pub hidden: bool,
}

/// `WiFi` encryption type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WifiEncryption {
    Open,
    Wep,
    WpaPsk,
    Wpa2Psk,
    Wpa2Enterprise,
    Wpa3Sae,
    Wpa3Enterprise,
    Unknown,
}

/// Scan for visible `WiFi` networks.
pub async fn scan_wifi_networks() -> Result<Vec<WifiNetwork>> {
    // TODO: Implement using platform-specific WiFi APIs
    // Linux: nl80211, macOS: CoreWLAN, Windows: WLAN API
    tracing::debug!("scanning WiFi networks");
    Ok(Vec::new())
}

/// Get information about the currently connected `WiFi` network.
pub async fn current_wifi() -> Result<Option<WifiNetwork>> {
    // TODO: Implement
    tracing::debug!("getting current WiFi info");
    Ok(None)
}
