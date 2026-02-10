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
    tracing::debug!("scanning WiFi networks");
    scan_wifi_platform()
}

#[cfg(target_os = "macos")]
fn scan_wifi_platform() -> Result<Vec<WifiNetwork>> {
    // macOS: use airport utility
    let airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
    let output = std::process::Command::new(airport).arg("-s").output();
    match output {
        Ok(out) if out.status.success() => {
            let contents = String::from_utf8_lossy(&out.stdout);
            Ok(parse_airport_output(&contents))
        }
        Ok(out) => {
            tracing::warn!("airport scan failed: {}", String::from_utf8_lossy(&out.stderr));
            Ok(Vec::new())
        }
        Err(e) => {
            tracing::warn!("failed to run airport command: {e}");
            Ok(Vec::new())
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
fn scan_wifi_platform() -> Result<Vec<WifiNetwork>> {
    // Linux: parse iwconfig for connected network, iwlist for scanning
    let output = std::process::Command::new("iwconfig").output();
    match output {
        Ok(out) if out.status.success() => {
            let contents = String::from_utf8_lossy(&out.stdout);
            let mut networks = parse_iwconfig_output(&contents);

            // Also try iwlist scan (requires sudo but may already be cached)
            if let Ok(scan_out) = std::process::Command::new("iwlist").args(["scan"]).output() {
                if scan_out.status.success() {
                    let scan_contents = String::from_utf8_lossy(&scan_out.stdout);
                    let scanned = parse_iwlist_output(&scan_contents);
                    // Merge, avoiding duplicates by BSSID
                    for net in scanned {
                        if !networks.iter().any(|n| n.bssid == net.bssid) {
                            networks.push(net);
                        }
                    }
                }
            }

            Ok(networks)
        }
        _ => {
            tracing::debug!("iwconfig not available");
            Ok(Vec::new())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn scan_wifi_platform() -> Result<Vec<WifiNetwork>> {
    tracing::warn!("WiFi scanning not supported on this platform");
    Ok(Vec::new())
}

/// Get information about the currently connected `WiFi` network.
#[allow(clippy::unused_async)]
pub async fn current_wifi() -> Result<Option<WifiNetwork>> {
    tracing::debug!("getting current WiFi info");
    current_wifi_platform()
}

#[cfg(target_os = "macos")]
fn current_wifi_platform() -> Result<Option<WifiNetwork>> {
    let airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
    let output = std::process::Command::new(airport).arg("-I").output();
    match output {
        Ok(out) if out.status.success() => {
            let contents = String::from_utf8_lossy(&out.stdout);
            Ok(parse_airport_info(&contents))
        }
        _ => Ok(None),
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
fn current_wifi_platform() -> Result<Option<WifiNetwork>> {
    let output = std::process::Command::new("iwconfig").output();
    match output {
        Ok(out) if out.status.success() => {
            let contents = String::from_utf8_lossy(&out.stdout);
            let networks = parse_iwconfig_output(&contents);
            Ok(networks.into_iter().next())
        }
        _ => Ok(None),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn current_wifi_platform() -> Result<Option<WifiNetwork>> {
    Ok(None)
}

// ─── macOS parsers ──────────────────────────────────────────────────────────

/// Parse macOS `airport -s` tabular output.
///
/// Header:  `SSID  BSSID  RSSI  CHANNEL  HT  CC  SECURITY`
/// The SSID column has variable width, so we parse by the fixed-width BSSID column.
#[cfg(any(target_os = "macos", test))]
fn parse_airport_output(contents: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    let mut lines = contents.lines();

    // Find the header line to determine column positions
    let header = match lines.next() {
        Some(h) if h.contains("SSID") && h.contains("BSSID") => h,
        _ => return networks,
    };

    // Use BSSID column position as anchor
    let Some(bssid_col) = header.find("BSSID") else {
        return networks;
    };
    let rssi_col = header.find("RSSI").unwrap_or(bssid_col + 18);
    let channel_col = header.find("CHANNEL").unwrap_or(rssi_col + 5);
    let security_col = header.find("SECURITY").unwrap_or(channel_col + 10);

    for line in lines {
        if line.len() < security_col {
            continue;
        }

        let ssid = line[..bssid_col].trim().to_owned();
        let bssid = line.get(bssid_col..rssi_col)
            .unwrap_or("")
            .trim()
            .to_owned();
        let rssi: i32 = line.get(rssi_col..channel_col)
            .unwrap_or("")
            .trim()
            .parse()
            .unwrap_or(0);
        let channel_str = line.get(channel_col..channel_col + 8)
            .unwrap_or("")
            .trim();
        let channel: u32 = channel_str
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        let security = line.get(security_col..)
            .unwrap_or("")
            .trim();

        let encryption = classify_airport_security(security);
        let wps_enabled = security.contains("WPS");
        let hidden = ssid.is_empty();

        networks.push(WifiNetwork {
            ssid: if hidden { "<hidden>".to_owned() } else { ssid },
            bssid,
            channel,
            frequency_mhz: channel_to_frequency(channel),
            signal_strength_dbm: rssi,
            encryption,
            wps_enabled,
            hidden,
        });
    }

    networks
}

/// Parse macOS `airport -I` info output for current connection.
#[cfg(target_os = "macos")]
fn parse_airport_info(contents: &str) -> Option<WifiNetwork> {
    let mut ssid = None;
    let mut bssid = None;
    let mut channel = 0u32;
    let mut rssi = 0i32;
    let mut security = String::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("SSID:") {
            ssid = Some(val.trim().to_owned());
        } else if let Some(val) = trimmed.strip_prefix("BSSID:") {
            bssid = Some(val.trim().to_owned());
        } else if let Some(val) = trimmed.strip_prefix("channel:") {
            channel = val.trim()
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
        } else if let Some(val) = trimmed.strip_prefix("agrCtlRSSI:") {
            rssi = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = trimmed.strip_prefix("link auth:") {
            val.trim().clone_into(&mut security);
        }
    }

    ssid.map(|ssid| WifiNetwork {
        ssid,
        bssid: bssid.unwrap_or_default(),
        channel,
        frequency_mhz: channel_to_frequency(channel),
        signal_strength_dbm: rssi,
        encryption: classify_airport_security(&security),
        wps_enabled: false,
        hidden: false,
    })
}

/// Classify macOS airport SECURITY string into encryption type.
#[cfg(any(target_os = "macos", test))]
fn classify_airport_security(security: &str) -> WifiEncryption {
    let upper = security.to_uppercase();
    if upper.contains("WPA3") && upper.contains("ENTERPRISE") {
        WifiEncryption::Wpa3Enterprise
    } else if upper.contains("WPA3") || upper.contains("SAE") {
        WifiEncryption::Wpa3Sae
    } else if upper.contains("WPA2") && upper.contains("ENTERPRISE") {
        WifiEncryption::Wpa2Enterprise
    } else if upper.contains("WPA2") {
        WifiEncryption::Wpa2Psk
    } else if upper.contains("WPA") {
        WifiEncryption::WpaPsk
    } else if upper.contains("WEP") {
        WifiEncryption::Wep
    } else if upper.contains("NONE") || upper.is_empty() {
        WifiEncryption::Open
    } else {
        WifiEncryption::Unknown
    }
}

// ─── Linux parsers ──────────────────────────────────────────────────────────

/// Parse `iwconfig` output for the currently connected `WiFi` network.
#[allow(clippy::similar_names)]
fn parse_iwconfig_output(contents: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    let mut current_ssid: Option<String> = None;
    let mut current_bssid = String::new();
    let mut current_freq = 0u32;
    let mut current_signal = 0i32;

    for line in contents.lines() {
        // New interface block: "wlan0  IEEE 802.11  ESSID:"NetworkName""
        if line.contains("ESSID:") {
            // Save previous if exists
            if let Some(ssid) = current_ssid.take() {
                networks.push(WifiNetwork {
                    ssid,
                    bssid: std::mem::take(&mut current_bssid),
                    channel: frequency_to_channel(current_freq),
                    frequency_mhz: current_freq,
                    signal_strength_dbm: current_signal,
                    encryption: WifiEncryption::Unknown, // iwconfig doesn't report this
                    wps_enabled: false,
                    hidden: false,
                });
            }

            if let Some(start) = line.find("ESSID:\"") {
                let rest = &line[start + 7..];
                if let Some(end) = rest.find('"') {
                    let ssid = rest[..end].to_owned();
                    if !ssid.is_empty() {
                        current_ssid = Some(ssid);
                    }
                }
            }
            current_freq = 0;
            current_signal = 0;
        }

        // Access Point line: "Access Point: AA:BB:CC:DD:EE:FF"
        if let Some(idx) = line.find("Access Point:") {
            let rest = line[idx + 13..].trim();
            if rest != "Not-Associated" {
                rest.clone_into(&mut current_bssid);
            }
        }

        // Frequency: "Frequency:2.437 GHz"
        if let Some(idx) = line.find("Frequency:") {
            let rest = &line[idx + 10..];
            if let Some(ghz) = rest.strip_suffix(" GHz").or_else(|| {
                rest.find(" GHz").map(|i| &rest[..i])
            }) {
                if let Ok(freq_ghz) = ghz.trim().parse::<f64>() {
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    {
                        current_freq = (freq_ghz * 1000.0) as u32;
                    }
                }
            }
        }

        // Signal level: "Signal level=-50 dBm"
        if let Some(idx) = line.find("Signal level=") {
            let rest = &line[idx + 13..];
            let num_str: String = rest.chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-')
                .collect();
            current_signal = num_str.parse().unwrap_or(0);
        }
    }

    // Don't forget the last one
    if let Some(ssid) = current_ssid {
        networks.push(WifiNetwork {
            ssid,
            bssid: current_bssid,
            channel: frequency_to_channel(current_freq),
            frequency_mhz: current_freq,
            signal_strength_dbm: current_signal,
            encryption: WifiEncryption::Unknown,
            wps_enabled: false,
            hidden: false,
        });
    }

    networks
}

/// Parse `iwlist scan` output for nearby `WiFi` networks.
fn parse_iwlist_output(contents: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    let mut ssid = String::new();
    let mut bssid = String::new();
    let mut channel = 0u32;
    let mut freq = 0u32;
    let mut signal = 0i32;
    let mut encryption = WifiEncryption::Open;
    let mut in_cell = false;

    for line in contents.lines() {
        let trimmed = line.trim();

        // New cell: "Cell 01 - Address: AA:BB:CC:DD:EE:FF"
        if trimmed.contains("Cell ") && trimmed.contains("Address:") {
            if in_cell && !bssid.is_empty() {
                networks.push(WifiNetwork {
                    ssid: std::mem::take(&mut ssid),
                    bssid: std::mem::take(&mut bssid),
                    channel,
                    frequency_mhz: freq,
                    signal_strength_dbm: signal,
                    encryption,
                    wps_enabled: false,
                    hidden: ssid.is_empty(),
                });
            }
            in_cell = true;
            encryption = WifiEncryption::Open;
            channel = 0;
            freq = 0;
            signal = 0;

            if let Some(addr_idx) = trimmed.find("Address:") {
                trimmed[addr_idx + 8..].trim().clone_into(&mut bssid);
            }
        }

        if let Some(rest) = trimmed.strip_prefix("ESSID:\"") {
            rest.strip_suffix('"').unwrap_or(rest).clone_into(&mut ssid);
        }

        if let Some(rest) = trimmed.strip_prefix("Channel:") {
            channel = rest.parse().unwrap_or(0);
        }

        if trimmed.contains("Encryption key:on") {
            // At minimum WEP
            if encryption == WifiEncryption::Open {
                encryption = WifiEncryption::Wep;
            }
        }

        if trimmed.contains("WPA2") {
            encryption = WifiEncryption::Wpa2Psk;
        } else if trimmed.contains("WPA") && encryption != WifiEncryption::Wpa2Psk {
            encryption = WifiEncryption::WpaPsk;
        }

        if let Some(idx) = trimmed.find("Signal level=") {
            let rest = &trimmed[idx + 13..];
            let num_str: String = rest.chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-')
                .collect();
            signal = num_str.parse().unwrap_or(0);
        }
    }

    // Last cell
    if in_cell && !bssid.is_empty() {
        networks.push(WifiNetwork {
            ssid,
            bssid,
            channel,
            frequency_mhz: freq,
            signal_strength_dbm: signal,
            encryption,
            wps_enabled: false,
            hidden: false,
        });
    }

    networks
}

// ─── Utility ────────────────────────────────────────────────────────────────

/// Convert a `WiFi` channel number to frequency in MHz.
#[cfg(any(target_os = "macos", test))]
const fn channel_to_frequency(channel: u32) -> u32 {
    match channel {
        1..=13 => 2407 + channel * 5,
        14 => 2484,
        36..=177 => 5000 + channel * 5,
        _ => 0,
    }
}

/// Convert frequency in MHz to channel number.
const fn frequency_to_channel(freq_mhz: u32) -> u32 {
    match freq_mhz {
        2412..=2472 => (freq_mhz - 2407) / 5,
        2484 => 14,
        5180..=5885 => (freq_mhz - 5000) / 5,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_to_frequency() {
        assert_eq!(channel_to_frequency(1), 2412);
        assert_eq!(channel_to_frequency(6), 2437);
        assert_eq!(channel_to_frequency(11), 2462);
        assert_eq!(channel_to_frequency(14), 2484);
        assert_eq!(channel_to_frequency(36), 5180);
        assert_eq!(channel_to_frequency(149), 5745);
    }

    #[test]
    fn test_frequency_to_channel() {
        assert_eq!(frequency_to_channel(2412), 1);
        assert_eq!(frequency_to_channel(2437), 6);
        assert_eq!(frequency_to_channel(5180), 36);
    }

    #[test]
    fn test_classify_airport_security() {
        assert_eq!(classify_airport_security("WPA2(PSK/AES/AES)"), WifiEncryption::Wpa2Psk);
        assert_eq!(classify_airport_security("WPA(PSK/TKIP/TKIP)"), WifiEncryption::WpaPsk);
        assert_eq!(classify_airport_security("WPA3(SAE/AES/AES)"), WifiEncryption::Wpa3Sae);
        assert_eq!(classify_airport_security("WPA2 Enterprise"), WifiEncryption::Wpa2Enterprise);
        assert_eq!(classify_airport_security("WEP"), WifiEncryption::Wep);
        assert_eq!(classify_airport_security("NONE"), WifiEncryption::Open);
        assert_eq!(classify_airport_security(""), WifiEncryption::Open);
    }

    const SAMPLE_AIRPORT_OUTPUT: &str = "                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group, 802.1X/EAP)\n                        HomeWiFi aa:bb:cc:dd:ee:ff  -45 6       Y  -- WPA2(PSK/AES/AES)\n                     GuestNet-5G 11:22:33:44:55:66  -72 149     Y  -- WPA2(PSK/AES/AES)\n                          OpenAP de:ad:be:ef:00:01  -80 1       Y  -- NONE\n";

    #[test]
    fn test_parse_airport_output() {
        let networks = parse_airport_output(SAMPLE_AIRPORT_OUTPUT);
        assert_eq!(networks.len(), 3);

        assert_eq!(networks[0].ssid, "HomeWiFi");
        assert_eq!(networks[0].bssid, "aa:bb:cc:dd:ee:ff");
        assert_eq!(networks[0].signal_strength_dbm, -45);
        assert_eq!(networks[0].channel, 6);
        assert_eq!(networks[0].encryption, WifiEncryption::Wpa2Psk);

        assert_eq!(networks[1].ssid, "GuestNet-5G");
        assert_eq!(networks[1].channel, 149);

        assert_eq!(networks[2].ssid, "OpenAP");
        assert_eq!(networks[2].encryption, WifiEncryption::Open);
    }

    const SAMPLE_IWCONFIG: &str = "\
wlan0     IEEE 802.11  ESSID:\"MyNetwork\"
          Mode:Managed  Frequency:2.437 GHz  Access Point: AA:BB:CC:DD:EE:FF
          Bit Rate=72.2 Mb/s   Tx-Power=20 dBm
          Signal level=-42 dBm

eth0      no wireless extensions.

lo        no wireless extensions.
";

    #[test]
    fn test_parse_iwconfig_output() {
        let networks = parse_iwconfig_output(SAMPLE_IWCONFIG);
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].ssid, "MyNetwork");
        assert_eq!(networks[0].bssid, "AA:BB:CC:DD:EE:FF");
        assert_eq!(networks[0].signal_strength_dbm, -42);
        assert_eq!(networks[0].frequency_mhz, 2437);
        assert_eq!(networks[0].channel, 6);
    }
}
