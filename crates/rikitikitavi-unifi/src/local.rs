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
    /// Only performs detection on Linux, since `UniFi` devices run Linux.
    #[cfg(target_os = "linux")]
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

    /// On non-Linux platforms, `UniFi` on-device detection is not applicable.
    #[cfg(not(target_os = "linux"))]
    pub fn detect() -> Option<Self> {
        tracing::debug!("UniFi on-device detection is only supported on Linux");
        None
    }
}

/// Board name → `UniFiDevice` mapping.
fn classify_board(board_name: &str) -> UniFiDevice {
    let name = board_name.trim().to_lowercase();
    match name.as_str() {
        "udm" | "unifi-dream-machine" => UniFiDevice::DreamMachine,
        "udmpro" | "udm-pro" | "unifi-dream-machine-pro" => UniFiDevice::DreamMachinePro,
        "udmpromax" | "udm-pro-max" => UniFiDevice::DreamMachineProMax,
        "udmse" | "udm-se" => UniFiDevice::DreamMachineSE,
        "udr" | "unifi-dream-router" => UniFiDevice::DreamRouter,
        "udw" | "unifi-dream-wall" => UniFiDevice::DreamWall,
        "ucg-ultra" | "ucgultra" => UniFiDevice::CloudGatewayUltra,
        "ucg-max" | "ucgmax" => UniFiDevice::CloudGatewayMax,
        "uck-g2-plus" | "uckg2plus" | "cloudkey-g2-plus" => UniFiDevice::CloudKeyGen2Plus,
        "usg" | "unifi-security-gateway" => UniFiDevice::SecurityGateway,
        "usgp4" | "usg-pro-4" => UniFiDevice::SecurityGatewayPro4,
        _ => {
            // Fallback: check for partial matches
            if name.contains("ap") || name.contains("u6") || name.contains("u7") {
                UniFiDevice::AccessPoint
            } else if name.contains("usw") || name.contains("switch") {
                UniFiDevice::Switch
            } else {
                UniFiDevice::Unknown
            }
        }
    }
}

/// Parse board.info file content to extract the board name.
fn parse_board_info(contents: &str) -> Option<String> {
    for line in contents.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("board.name=") {
            return Some(value.trim().to_owned());
        }
        // Some files use board.shortname
        if let Some(value) = line.strip_prefix("board.shortname=") {
            return Some(value.trim().to_owned());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn detect_device_type() -> UniFiDevice {
    tracing::debug!("detecting UniFi device type");

    // Try /etc/board.info first (most common location)
    if let Ok(contents) = std::fs::read_to_string("/etc/board.info") {
        if let Some(board_name) = parse_board_info(&contents) {
            tracing::debug!(%board_name, "found board name");
            return classify_board(&board_name);
        }
    }

    // Try /data/unifi-core/config/hardware
    if let Ok(contents) = std::fs::read_to_string("/data/unifi-core/config/hardware") {
        return classify_board(contents.trim());
    }

    // Try hostname as last resort (some devices set hostname to model)
    if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
        let hostname = hostname.trim().to_lowercase();
        if hostname.starts_with("udm") || hostname.starts_with("ucg") || hostname.starts_with("udr") {
            return classify_board(&hostname);
        }
    }

    UniFiDevice::Unknown
}

#[cfg(target_os = "linux")]
fn read_unifi_os_version() -> Option<String> {
    // Primary location
    if let Ok(version) = std::fs::read_to_string("/etc/unifi-os/unifi_version") {
        let v = version.trim().to_owned();
        if !v.is_empty() {
            return Some(v);
        }
    }

    // Alternative: /data/unifi-core/version
    std::fs::read_to_string("/data/unifi-core/version")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn read_network_app_version() -> Option<String> {
    // Check the UniFi Network app version
    let paths = [
        "/data/unifi-core/config/version",
        "/usr/lib/unifi/data/system.properties",
    ];

    for path in &paths {
        if let Ok(contents) = std::fs::read_to_string(path) {
            // system.properties uses key=value format
            if path.ends_with("system.properties") {
                for line in contents.lines() {
                    if let Some(version) = line.strip_prefix("unifi.version=") {
                        return Some(version.trim().to_owned());
                    }
                }
            } else {
                let v = contents.trim().to_owned();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_board_udm_pro() {
        assert_eq!(classify_board("UDMPRO"), UniFiDevice::DreamMachinePro);
        assert_eq!(classify_board("udm-pro"), UniFiDevice::DreamMachinePro);
    }

    #[test]
    fn test_classify_board_dream_router() {
        assert_eq!(classify_board("UDR"), UniFiDevice::DreamRouter);
    }

    #[test]
    fn test_classify_board_cloud_gateway_ultra() {
        assert_eq!(classify_board("UCG-Ultra"), UniFiDevice::CloudGatewayUltra);
    }

    #[test]
    fn test_classify_board_access_point() {
        assert_eq!(classify_board("U6-Pro"), UniFiDevice::AccessPoint);
        assert_eq!(classify_board("U7-Pro"), UniFiDevice::AccessPoint);
    }

    #[test]
    fn test_classify_board_switch() {
        assert_eq!(classify_board("USW-24-PoE"), UniFiDevice::Switch);
    }

    #[test]
    fn test_classify_board_unknown() {
        assert_eq!(classify_board("something-random"), UniFiDevice::Unknown);
    }

    #[test]
    fn test_parse_board_info() {
        let content = "\
board.name=UDMPRO
board.shortname=UDM-Pro
board.sysid=0x789a
";
        let name = parse_board_info(content);
        assert_eq!(name, Some("UDMPRO".to_owned()));
    }

    #[test]
    fn test_parse_board_info_shortname_fallback() {
        let content = "board.shortname=UCG-Ultra\n";
        let name = parse_board_info(content);
        assert_eq!(name, Some("UCG-Ultra".to_owned()));
    }

    #[test]
    fn test_parse_board_info_empty() {
        let content = "some.other.key=value\n";
        let name = parse_board_info(content);
        assert_eq!(name, None);
    }
}
