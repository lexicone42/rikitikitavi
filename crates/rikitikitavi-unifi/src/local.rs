use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", test))]
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
    /// Detect a `UniFi` OS host via `/etc/unifi-os` or `/data/unifi-core`.
    #[cfg(target_os = "linux")]
    pub fn detect() -> Option<Self> {
        tracing::info!("attempting UniFi environment detection");

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

    /// Always `None` off Linux.
    #[cfg(not(target_os = "linux"))]
    pub fn detect() -> Option<Self> {
        tracing::debug!("UniFi on-device detection is only supported on Linux");
        None
    }
}

#[cfg(any(target_os = "linux", test))]
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

#[cfg(any(target_os = "linux", test))]
/// `board.name` or `board.shortname` value from `board.info` content.
fn parse_board_info(contents: &str) -> Option<String> {
    for line in contents.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("board.name=") {
            return Some(value.trim().to_owned());
        }
        if let Some(value) = line.strip_prefix("board.shortname=") {
            return Some(value.trim().to_owned());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn detect_device_type() -> UniFiDevice {
    tracing::debug!("detecting UniFi device type");

    if let Ok(contents) = std::fs::read_to_string("/etc/board.info")
        && let Some(board_name) = parse_board_info(&contents)
    {
        tracing::debug!(%board_name, "found board name");
        return classify_board(&board_name);
    }

    if let Ok(contents) = std::fs::read_to_string("/data/unifi-core/config/hardware") {
        return classify_board(contents.trim());
    }

    // Some devices set the hostname to the model name.
    if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
        let hostname = hostname.trim().to_lowercase();
        if hostname.starts_with("udm") || hostname.starts_with("ucg") || hostname.starts_with("udr")
        {
            return classify_board(&hostname);
        }
    }

    UniFiDevice::Unknown
}

#[cfg(target_os = "linux")]
fn read_unifi_os_version() -> Option<String> {
    if let Ok(version) = std::fs::read_to_string("/etc/unifi-os/unifi_version") {
        let v = version.trim().to_owned();
        if !v.is_empty() {
            return Some(v);
        }
    }

    std::fs::read_to_string("/data/unifi-core/version")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn read_network_app_version() -> Option<String> {
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

    use proptest::prelude::*;

    /// Exact-match keys of `classify_board`.
    const BOARD_KEYS: &[&str] = &[
        "udm",
        "unifi-dream-machine",
        "udmpro",
        "udm-pro",
        "unifi-dream-machine-pro",
        "udmpromax",
        "udm-pro-max",
        "udmse",
        "udm-se",
        "udr",
        "unifi-dream-router",
        "udw",
        "unifi-dream-wall",
        "ucg-ultra",
        "ucgultra",
        "ucg-max",
        "ucgmax",
        "uck-g2-plus",
        "uckg2plus",
        "cloudkey-g2-plus",
        "usg",
        "unifi-security-gateway",
        "usgp4",
        "usg-pro-4",
    ];

    /// Per-char ASCII case flip driven by `mask` (missing entries lowercase).
    fn mixed_case(s: &str, mask: &[bool]) -> String {
        s.chars()
            .zip(mask.iter().copied().chain(std::iter::repeat(false)))
            .map(|(c, upper)| {
                if upper {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect()
    }

    fn arb_board_info() -> impl Strategy<Value = String> {
        prop_oneof![
            proptest::collection::vec(any::<char>(), 0..200)
                .prop_map(|chars| chars.into_iter().collect::<String>()),
            (
                ".{0,20}",
                "[ \t]{0,2}",
                "board\\.(name|shortname)=",
                "[ \t]{0,2}",
                ".{0,20}",
                "[ \t]{0,2}",
                ".{0,20}",
            )
                .prop_map(|(pre, pad_key, key, pad_left, value, pad_right, post)| {
                    format!("{pre}\n{pad_key}{key}{pad_left}{value}{pad_right}\n{post}")
                }),
        ]
    }

    proptest! {
        /// Surrounding whitespace and ASCII case do not change the classification.
        #[test]
        fn prop_classify_board_case_whitespace_invariant(
            name in "[ -~]{0,24}",
            mask in proptest::collection::vec(any::<bool>(), 0..24),
            lead in "[ \t\r\n]{0,3}",
            trail in "[ \t\r\n]{0,3}",
        ) {
            let mixed = mixed_case(&name, &mask);
            let variant = format!("{lead}{mixed}{trail}");
            prop_assert_eq!(classify_board(&variant), classify_board(&name));
        }

        /// Every exact-match key classifies to a known device under any case/whitespace variation.
        #[test]
        fn prop_classify_board_table_keys(
            idx in 0..BOARD_KEYS.len(),
            mask in proptest::collection::vec(any::<bool>(), 0..24),
            lead in "[ \t\r\n]{0,3}",
            trail in "[ \t\r\n]{0,3}",
        ) {
            let key = BOARD_KEYS[idx];
            let mixed = mixed_case(key, &mask);
            let variant = format!("{lead}{mixed}{trail}");
            let got = classify_board(&variant);
            prop_assert_ne!(got, UniFiDevice::Unknown);
            prop_assert_eq!(got, classify_board(key));
        }

        /// `None` iff no trimmed line starts with a board key; `Some(v)` iff `v` is the trimmed value of such a line.
        #[test]
        fn prop_parse_board_info_spec(contents in arb_board_info()) {
            let key_value = |line: &str| {
                let line = line.trim();
                line.strip_prefix("board.name=")
                    .or_else(|| line.strip_prefix("board.shortname="))
                    .map(str::trim)
                    .map(str::to_owned)
            };
            match parse_board_info(&contents) {
                None => prop_assert!(!contents.lines().any(|l| key_value(l).is_some())),
                Some(v) => {
                    prop_assert_eq!(v.trim(), v.as_str());
                    prop_assert!(contents.lines().any(|l| key_value(l).as_deref() == Some(v.as_str())));
                }
            }
        }
    }
}
