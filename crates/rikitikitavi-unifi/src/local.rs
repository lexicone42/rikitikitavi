use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::models::UniFiDevice;

/// Detected `UniFi` environment when running on-device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniFiEnvironment {
    pub device_type: UniFiDevice,
    pub unifi_os_version: Option<String>,
    pub network_app_version: Option<String>,
    pub is_on_device: bool,
    pub has_local_db_access: bool,
    pub has_controller_access: bool,
}

impl UniFiEnvironment {
    /// Attempt to detect if we're running on a `UniFi` device.
    ///
    /// Checks for `UniFi` OS markers: `/etc/unifi-os/`, `/data/unifi-core/`, etc.
    pub fn detect() -> Option<Self> {
        tracing::info!("attempting UniFi environment detection");

        // Check for UniFi OS markers
        if !Path::new("/etc/unifi-os").exists() && !Path::new("/data/unifi-core").exists() {
            tracing::debug!("no UniFi OS markers found");
            return None;
        }

        let device_type = detect_device_type();
        let unifi_os_version = read_unifi_os_version();
        let network_app_version = read_network_app_version();

        Some(Self {
            device_type,
            unifi_os_version,
            network_app_version,
            is_on_device: true,
            has_local_db_access: Path::new("/run/mongodb-27117.sock").exists(),
            has_controller_access: true,
        })
    }
}

fn detect_device_type() -> UniFiDevice {
    // TODO: Read /etc/board.info or similar to determine exact model
    // Check model strings like "UDM-Pro", "UCG-Ultra", etc.
    tracing::debug!("detecting UniFi device type");
    UniFiDevice::Unknown
}

fn read_unifi_os_version() -> Option<String> {
    // TODO: Read from /etc/unifi-os/unifi_version or similar
    std::fs::read_to_string("/etc/unifi-os/unifi_version")
        .ok()
        .map(|s| s.trim().to_owned())
}

const fn read_network_app_version() -> Option<String> {
    // TODO: Read from /data/unifi-core/config/version or query local API
    None
}
