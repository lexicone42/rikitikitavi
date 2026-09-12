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
#[allow(clippy::unnecessary_wraps)]
fn scan_wifi_platform() -> Result<Vec<WifiNetwork>> {
    if let Some(networks) = try_system_profiler_scan() {
        if !networks.is_empty() {
            return Ok(networks);
        }
    }

    // Fallback: deprecated `airport` utility (pre-Sequoia macOS).
    tracing::debug!("system_profiler returned no networks, trying airport fallback");
    Ok(try_airport_scan().unwrap_or_default())
}

/// Try scanning with `system_profiler SPAirPortDataType`.
#[cfg(target_os = "macos")]
fn try_system_profiler_scan() -> Option<Vec<WifiNetwork>> {
    let output = std::process::Command::new("system_profiler")
        .arg("SPAirPortDataType")
        .output()
        .ok()?;
    if !output.status.success() {
        tracing::warn!("system_profiler failed");
        return None;
    }
    let contents = String::from_utf8_lossy(&output.stdout);
    Some(parse_system_profiler_wifi(&contents))
}

/// Try scanning with the deprecated `airport -s` utility.
#[cfg(target_os = "macos")]
fn try_airport_scan() -> Option<Vec<WifiNetwork>> {
    let airport =
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
    let output = std::process::Command::new(airport)
        .arg("-s")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let contents = String::from_utf8_lossy(&output.stdout);
    Some(parse_airport_output(&contents))
}

#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
fn scan_wifi_platform() -> Result<Vec<WifiNetwork>> {
    let output = std::process::Command::new("iwconfig").output();
    match output {
        Ok(out) if out.status.success() => {
            let contents = String::from_utf8_lossy(&out.stdout);
            let mut networks = parse_iwconfig_output(&contents);

            // `iwlist scan` needs root but may return cached results.
            if let Ok(scan_out) = std::process::Command::new("iwlist").args(["scan"]).output()
                && scan_out.status.success()
            {
                let scan_contents = String::from_utf8_lossy(&scan_out.stdout);
                let scanned = parse_iwlist_output(&scan_contents);
                for net in scanned {
                    if !networks.iter().any(|n| n.bssid == net.bssid) {
                        networks.push(net);
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
#[allow(clippy::unnecessary_wraps)]
fn current_wifi_platform() -> Result<Option<WifiNetwork>> {
    if let Ok(output) = std::process::Command::new("system_profiler")
        .arg("SPAirPortDataType")
        .output()
    {
        if output.status.success() {
            let contents = String::from_utf8_lossy(&output.stdout);
            let current = parse_system_profiler_current(&contents);
            if current.is_some() {
                return Ok(current);
            }
        }
    }

    // Fallback: deprecated `airport -I`.
    let airport =
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
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

/// Parse `system_profiler SPAirPortDataType` output; covers both the
/// "Current Network Information:" and "Other Local Wi-Fi Networks:" sections.
///
/// ```text
///   Current Network Information:
///     MyNetwork:
///       PHY Mode: 802.11ax
///       Channel: 6 (2GHz, 20MHz)
///       Security: WPA2 Personal
///       Signal / Noise: -45 dBm / -90 dBm
///   Other Local Wi-Fi Networks:
///     NeighborNet:
///       PHY Mode: 802.11n
///       Channel: 1 (2GHz, 20MHz)
///       Security: WPA/WPA2 Personal
///       Signal / Noise: -72 dBm / -95 dBm
/// ```
#[cfg(any(target_os = "macos", test))]
fn parse_system_profiler_wifi(contents: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();

    if let Some(section) = extract_section(contents, "Current Network Information:") {
        networks.extend(parse_profiler_network_entries(&section, false));
    }
    if let Some(section) = extract_section(contents, "Other Local Wi-Fi Networks:") {
        networks.extend(parse_profiler_network_entries(&section, false));
    }

    networks
}

/// Parse only the "Current Network Information:" section.
#[cfg(any(target_os = "macos", test))]
fn parse_system_profiler_current(contents: &str) -> Option<WifiNetwork> {
    let section = extract_section(contents, "Current Network Information:")?;
    parse_profiler_network_entries(&section, false)
        .into_iter()
        .next()
}

/// Lines under `heading` in `system_profiler` output, up to the next line at the
/// heading's indentation or less.
#[cfg(any(target_os = "macos", test))]
fn extract_section(contents: &str, heading: &str) -> Option<String> {
    let mut lines = contents.lines();
    let mut section_indent = 0;
    let mut found = false;

    for line in &mut lines {
        if line.trim_start().starts_with(heading) {
            section_indent = line.len() - line.trim_start().len();
            found = true;
            break;
        }
    }

    if !found {
        return None;
    }

    let mut section = String::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent <= section_indent && !line.trim().is_empty() {
            break;
        }
        section.push_str(line);
        section.push('\n');
    }

    if section.is_empty() {
        None
    } else {
        Some(section)
    }
}

/// Parse network entries from a `system_profiler` section: a `NetworkName:` line
/// followed by more-indented `Key: value` lines.
#[cfg(any(target_os = "macos", test))]
#[allow(clippy::too_many_lines)]
fn parse_profiler_network_entries(section: &str, _is_current: bool) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    let mut current_name: Option<String> = None;
    let mut channel = 0u32;
    let mut signal = 0i32;
    let mut noise = 0i32;
    let mut security = String::new();
    let mut bssid = String::new();
    let mut name_indent = 0usize;

    let flush = |name: &mut Option<String>,
                 channel: &mut u32,
                 signal: &mut i32,
                 noise: &mut i32,
                 security: &mut String,
                 bssid: &mut String,
                 nets: &mut Vec<WifiNetwork>| {
        if let Some(ssid) = name.take() {
            let encryption = classify_profiler_security(security);
            let hidden = ssid.is_empty();
            nets.push(WifiNetwork {
                ssid: if hidden { "<hidden>".to_owned() } else { ssid },
                bssid: std::mem::take(bssid),
                channel: *channel,
                frequency_mhz: channel_to_frequency(*channel),
                signal_strength_dbm: *signal,
                encryption,
                wps_enabled: false,
                hidden,
            });
            let _ = noise; // parsed, unused
            *channel = 0;
            *signal = 0;
            *noise = 0;
            security.clear();
        }
    };

    for line in section.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();

        // Name lines end with ':' and contain no ": "; key-value lines contain ": ".
        if trimmed.ends_with(':') && !trimmed.contains(": ") {
            flush(
                &mut current_name,
                &mut channel,
                &mut signal,
                &mut noise,
                &mut security,
                &mut bssid,
                &mut networks,
            );
            let name = trimmed[..trimmed.len() - 1].to_owned();
            current_name = Some(name);
            name_indent = indent;
            continue;
        }

        if current_name.is_some() && indent > name_indent {
            if let Some(val) = trimmed.strip_prefix("Channel: ") {
                // "6 (2GHz, 20MHz)"
                channel = val
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
            } else if let Some(val) = trimmed.strip_prefix("Security: ") {
                val.clone_into(&mut security);
            } else if let Some(val) = trimmed.strip_prefix("Signal / Noise: ") {
                // "-45 dBm / -90 dBm"
                let parts: Vec<&str> = val.split('/').collect();
                if let Some(sig_str) = parts.first() {
                    signal = sig_str
                        .trim()
                        .trim_end_matches(" dBm")
                        .trim()
                        .parse()
                        .unwrap_or(0);
                }
                if let Some(noise_str) = parts.get(1) {
                    noise = noise_str
                        .trim()
                        .trim_end_matches(" dBm")
                        .trim()
                        .parse()
                        .unwrap_or(0);
                }
            } else if let Some(val) = trimmed.strip_prefix("BSSID: ") {
                val.clone_into(&mut bssid);
            }
        }
    }

    flush(
        &mut current_name,
        &mut channel,
        &mut signal,
        &mut noise,
        &mut security,
        &mut bssid,
        &mut networks,
    );

    networks
}

/// Classify a `system_profiler` Security string, e.g. "WPA2 Personal",
/// "WPA/WPA2 Personal", "WPA3 Personal", "WPA2 Enterprise", "WEP", "None".
#[cfg(any(target_os = "macos", test))]
fn classify_profiler_security(security: &str) -> WifiEncryption {
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
    } else if upper.contains("NONE") || upper.contains("OPEN") || upper.is_empty() {
        WifiEncryption::Open
    } else {
        WifiEncryption::Unknown
    }
}

/// Parse macOS `airport -s` output. Header: `SSID  BSSID  RSSI  CHANNEL  HT  CC  SECURITY`.
/// Rows are split at the BSSID token (see [`split_airport_row`]); the SSID may contain
/// spaces and non-ASCII characters.
#[cfg(any(target_os = "macos", test))]
fn parse_airport_output(contents: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    let mut lines = contents.lines();

    match lines.next() {
        Some(h) if h.contains("SSID") && h.contains("BSSID") => {}
        _ => return networks,
    }

    for line in lines {
        let Some((ssid, columns)) = split_airport_row(line) else {
            continue;
        };
        let mut fields = columns.split_whitespace();
        let bssid = fields.next().unwrap_or("").to_owned();
        let rssi: i32 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let channel: u32 = fields
            .next()
            .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        // Remaining: HT, CC, SECURITY...
        let security_text = fields.skip(2).collect::<Vec<_>>().join(" ");

        let encryption = classify_airport_security(&security_text);
        let wps_enabled = security_text.contains("WPS");
        let hidden = ssid.is_empty();

        networks.push(WifiNetwork {
            ssid: if hidden {
                "<hidden>".to_owned()
            } else {
                ssid.to_owned()
            },
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

/// Split an `airport -s` row into `(ssid, columns)` at the BSSID: the first
/// MAC-formatted token followed by an integer RSSI. `None` if no such token.
#[cfg(any(target_os = "macos", test))]
fn split_airport_row(line: &str) -> Option<(&str, &str)> {
    let mut pos = 0;
    let mut tokens = line.split_whitespace().peekable();
    while let Some(tok) = tokens.next() {
        let start = pos + line[pos..].find(tok)?;
        pos = start + tok.len();
        let is_bssid = crate::wifi_frames::parse_mac(tok).is_some()
            && tokens
                .peek()
                .is_some_and(|next| next.parse::<i32>().is_ok());
        if is_bssid {
            return Some((line[..start].trim(), &line[start..]));
        }
    }
    None
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
            channel = val
                .trim()
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

/// Parse `iwconfig` output for the currently connected `WiFi` network.
#[allow(clippy::similar_names)]
fn parse_iwconfig_output(contents: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    let mut current_ssid: Option<String> = None;
    let mut current_bssid = String::new();
    let mut current_freq = 0u32;
    let mut current_signal = 0i32;

    for line in contents.lines() {
        // Interface line: `wlan0  IEEE 802.11  ESSID:"NetworkName"`
        if line.contains("ESSID:") {
            if let Some(ssid) = current_ssid.take() {
                networks.push(WifiNetwork {
                    ssid,
                    bssid: std::mem::take(&mut current_bssid),
                    channel: frequency_to_channel(current_freq),
                    frequency_mhz: current_freq,
                    signal_strength_dbm: current_signal,
                    encryption: WifiEncryption::Unknown, // not reported by iwconfig
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

        // "Access Point: AA:BB:CC:DD:EE:FF"
        if let Some(idx) = line.find("Access Point:") {
            let rest = line[idx + 13..].trim();
            if rest != "Not-Associated" {
                rest.clone_into(&mut current_bssid);
            }
        }

        // "Frequency:2.437 GHz"
        if let Some(idx) = line.find("Frequency:") {
            let rest = &line[idx + 10..];
            if let Some(ghz) = rest
                .strip_suffix(" GHz")
                .or_else(|| rest.find(" GHz").map(|i| &rest[..i]))
                && let Ok(freq_ghz) = ghz.trim().parse::<f64>()
            {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                {
                    current_freq = (freq_ghz * 1000.0) as u32;
                }
            }
        }

        // "Signal level=-50 dBm"
        if let Some(idx) = line.find("Signal level=") {
            let rest = &line[idx + 13..];
            let num_str: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-')
                .collect();
            current_signal = num_str.parse().unwrap_or(0);
        }
    }

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

/// One `iwlist scan` cell under construction.
struct IwlistCell {
    ssid: String,
    bssid: String,
    channel: u32,
    signal: i32,
    encryption: WifiEncryption,
}

impl IwlistCell {
    const fn new(bssid: String) -> Self {
        Self {
            ssid: String::new(),
            bssid,
            channel: 0,
            signal: 0,
            encryption: WifiEncryption::Open,
        }
    }

    /// `None` when no BSSID was parsed.
    fn into_network(self) -> Option<WifiNetwork> {
        if self.bssid.is_empty() {
            return None;
        }
        let hidden = self.ssid.is_empty();
        Some(WifiNetwork {
            ssid: if hidden {
                "<hidden>".to_owned()
            } else {
                self.ssid
            },
            bssid: self.bssid,
            channel: self.channel,
            frequency_mhz: 0,
            signal_strength_dbm: self.signal,
            encryption: self.encryption,
            wps_enabled: false,
            hidden,
        })
    }
}

/// Parse `iwlist scan` output for nearby `WiFi` networks.
fn parse_iwlist_output(contents: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    let mut cell: Option<IwlistCell> = None;

    for line in contents.lines() {
        let trimmed = line.trim();

        // "Cell 01 - Address: AA:BB:CC:DD:EE:FF"
        if trimmed.contains("Cell ") && trimmed.contains("Address:") {
            networks.extend(cell.take().and_then(IwlistCell::into_network));
            let bssid = trimmed
                .find("Address:")
                .map(|idx| trimmed[idx + 8..].trim().to_owned())
                .unwrap_or_default();
            cell = Some(IwlistCell::new(bssid));
            continue;
        }

        let Some(cur) = cell.as_mut() else {
            continue;
        };

        if let Some(rest) = trimmed.strip_prefix("ESSID:\"") {
            rest.strip_suffix('"')
                .unwrap_or(rest)
                .clone_into(&mut cur.ssid);
        }

        if let Some(rest) = trimmed.strip_prefix("Channel:") {
            cur.channel = rest.parse().unwrap_or(0);
        }

        // WEP unless a WPA line follows.
        if trimmed.contains("Encryption key:on") && cur.encryption == WifiEncryption::Open {
            cur.encryption = WifiEncryption::Wep;
        }

        if trimmed.contains("WPA2") {
            cur.encryption = WifiEncryption::Wpa2Psk;
        } else if trimmed.contains("WPA") && cur.encryption != WifiEncryption::Wpa2Psk {
            cur.encryption = WifiEncryption::WpaPsk;
        }

        if let Some(idx) = trimmed.find("Signal level=") {
            let rest = &trimmed[idx + 13..];
            let num_str: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-')
                .collect();
            cur.signal = num_str.parse().unwrap_or(0);
        }
    }

    networks.extend(cell.and_then(IwlistCell::into_network));
    networks
}

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

    // ─── system_profiler tests ──────────────────────────────────────────

    const SAMPLE_SYSTEM_PROFILER: &str = "\
Wi-Fi:

      Software Versions:
          CoreWLAN: 16.0 (1657)
          CoreWLANKit: 16.0 (1657)
      Interfaces:
        en0:
          Card Type: Wi-Fi  (0x14E4, 0x4387)
          Firmware Version: wl0: Oct 21 2024 05:12:34
          MAC Address: aa:bb:cc:dd:ee:f0
          Locale: ETSI
          Country Code: US
          Supported PHY Modes: 802.11 a/b/g/n/ac/ax
          Supported Channels: 1-13,36-64,100-144,149-165
          Wake On Wireless: Supported
          AirDrop: Supported
          AirDrop Channel: 44
          Auto Unlock: Supported
          Current Network Information:
            HomeNetwork:
              PHY Mode: 802.11ax
              BSSID: aa:bb:cc:dd:ee:ff
              Channel: 6 (2GHz, 20MHz)
              Country Code: US
              Network Type: Infrastructure
              Security: WPA2 Personal
              Signal / Noise: -45 dBm / -90 dBm
              Transmit Rate: 1201
              MCS Index: 11
          Other Local Wi-Fi Networks:
            NeighborWiFi-5G:
              PHY Mode: 802.11ac
              Channel: 149 (5GHz, 80MHz)
              Country Code: US
              Network Type: Infrastructure
              Security: WPA/WPA2 Personal
              Signal / Noise: -72 dBm / -95 dBm
            CoffeeShop:
              PHY Mode: 802.11n
              Channel: 1 (2GHz, 20MHz)
              Network Type: Infrastructure
              Security: None
              Signal / Noise: -80 dBm / -92 dBm
            CorpNet:
              PHY Mode: 802.11ax
              Channel: 36 (5GHz, 80MHz)
              Network Type: Infrastructure
              Security: WPA2 Enterprise
              Signal / Noise: -65 dBm / -88 dBm
";

    #[test]
    fn test_parse_system_profiler_all_networks() {
        let networks = parse_system_profiler_wifi(SAMPLE_SYSTEM_PROFILER);
        assert_eq!(networks.len(), 4);
    }

    #[test]
    fn test_parse_system_profiler_current_network() {
        let networks = parse_system_profiler_wifi(SAMPLE_SYSTEM_PROFILER);
        let home = &networks[0];
        assert_eq!(home.ssid, "HomeNetwork");
        assert_eq!(home.bssid, "aa:bb:cc:dd:ee:ff");
        assert_eq!(home.channel, 6);
        assert_eq!(home.frequency_mhz, 2437);
        assert_eq!(home.signal_strength_dbm, -45);
        assert_eq!(home.encryption, WifiEncryption::Wpa2Psk);
    }

    #[test]
    fn test_parse_system_profiler_neighbor_5g() {
        let networks = parse_system_profiler_wifi(SAMPLE_SYSTEM_PROFILER);
        let neighbor = &networks[1];
        assert_eq!(neighbor.ssid, "NeighborWiFi-5G");
        assert_eq!(neighbor.channel, 149);
        assert_eq!(neighbor.frequency_mhz, 5745);
        assert_eq!(neighbor.signal_strength_dbm, -72);
        assert_eq!(neighbor.encryption, WifiEncryption::Wpa2Psk);
    }

    #[test]
    fn test_parse_system_profiler_open_network() {
        let networks = parse_system_profiler_wifi(SAMPLE_SYSTEM_PROFILER);
        let coffee = &networks[2];
        assert_eq!(coffee.ssid, "CoffeeShop");
        assert_eq!(coffee.channel, 1);
        assert_eq!(coffee.encryption, WifiEncryption::Open);
    }

    #[test]
    fn test_parse_system_profiler_enterprise() {
        let networks = parse_system_profiler_wifi(SAMPLE_SYSTEM_PROFILER);
        let corp = &networks[3];
        assert_eq!(corp.ssid, "CorpNet");
        assert_eq!(corp.channel, 36);
        assert_eq!(corp.encryption, WifiEncryption::Wpa2Enterprise);
    }

    #[test]
    fn test_parse_system_profiler_current_only() {
        let current = parse_system_profiler_current(SAMPLE_SYSTEM_PROFILER);
        assert!(current.is_some());
        let net = current.unwrap();
        assert_eq!(net.ssid, "HomeNetwork");
        assert_eq!(net.signal_strength_dbm, -45);
    }

    #[test]
    fn test_parse_system_profiler_empty() {
        let networks = parse_system_profiler_wifi("Wi-Fi:\n  No wireless interfaces found.\n");
        assert!(networks.is_empty());
    }

    #[test]
    fn test_classify_profiler_security() {
        assert_eq!(
            classify_profiler_security("WPA2 Personal"),
            WifiEncryption::Wpa2Psk
        );
        assert_eq!(
            classify_profiler_security("WPA/WPA2 Personal"),
            WifiEncryption::Wpa2Psk
        );
        assert_eq!(
            classify_profiler_security("WPA3 Personal"),
            WifiEncryption::Wpa3Sae
        );
        assert_eq!(
            classify_profiler_security("WPA2 Enterprise"),
            WifiEncryption::Wpa2Enterprise
        );
        assert_eq!(
            classify_profiler_security("WPA3 Enterprise"),
            WifiEncryption::Wpa3Enterprise
        );
        assert_eq!(classify_profiler_security("WEP"), WifiEncryption::Wep);
        assert_eq!(classify_profiler_security("None"), WifiEncryption::Open);
        assert_eq!(classify_profiler_security("Open"), WifiEncryption::Open);
        assert_eq!(classify_profiler_security(""), WifiEncryption::Open);
    }

    // ─── airport tests (fallback parser) ────────────────────────────────

    #[test]
    fn test_classify_airport_security() {
        assert_eq!(
            classify_airport_security("WPA2(PSK/AES/AES)"),
            WifiEncryption::Wpa2Psk
        );
        assert_eq!(
            classify_airport_security("WPA(PSK/TKIP/TKIP)"),
            WifiEncryption::WpaPsk
        );
        assert_eq!(
            classify_airport_security("WPA3(SAE/AES/AES)"),
            WifiEncryption::Wpa3Sae
        );
        assert_eq!(
            classify_airport_security("WPA2 Enterprise"),
            WifiEncryption::Wpa2Enterprise
        );
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

    #[test]
    fn test_parse_airport_output_multibyte_ssid() {
        // Rows aligned by character count, so byte columns differ from the header.
        let output = concat!(
            "                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group, 802.1X/EAP)\n",
            "                          日本語ネット aa:bb:cc:dd:ee:01  -55 36,+1   Y  JP WPA2(PSK/AES/AES)\n",
            "                            Café 0:1e:52:aa:bb:cc  -61 11      N  -- WPA(PSK/TKIP/TKIP) WPS\n",
            "                                 de:ad:be:ef:00:02  -70 1       Y  -- NONE\n",
            "  not a network row\n",
        );
        let networks = parse_airport_output(output);
        assert_eq!(networks.len(), 3);

        assert_eq!(networks[0].ssid, "日本語ネット");
        assert_eq!(networks[0].bssid, "aa:bb:cc:dd:ee:01");
        assert_eq!(networks[0].signal_strength_dbm, -55);
        assert_eq!(networks[0].channel, 36);
        assert_eq!(networks[0].encryption, WifiEncryption::Wpa2Psk);
        assert!(!networks[0].hidden);

        assert_eq!(networks[1].ssid, "Café");
        assert_eq!(networks[1].bssid, "0:1e:52:aa:bb:cc");
        assert_eq!(networks[1].channel, 11);
        assert_eq!(networks[1].encryption, WifiEncryption::WpaPsk);
        assert!(networks[1].wps_enabled);

        assert!(networks[2].hidden);
        assert_eq!(networks[2].ssid, "<hidden>");
        assert_eq!(networks[2].bssid, "de:ad:be:ef:00:02");
        assert_eq!(networks[2].encryption, WifiEncryption::Open);
    }

    #[test]
    fn test_split_airport_row() {
        assert_eq!(
            split_airport_row("  My Net  aa:bb:cc:dd:ee:ff  -45 6 Y -- NONE"),
            Some(("My Net", "aa:bb:cc:dd:ee:ff  -45 6 Y -- NONE"))
        );
        assert_eq!(split_airport_row("no bssid here"), None);
        assert_eq!(split_airport_row(""), None);
    }

    // ─── channel/frequency conversion tests ─────────────────────────────

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

    // ─── Linux tests ────────────────────────────────────────────────────

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

    const SAMPLE_IWLIST: &str = "\
wlan0     Scan completed :
          Cell 01 - Address: AA:BB:CC:DD:EE:01
                    Channel:6
                    Frequency:2.437 GHz (Channel 6)
                    Quality=70/70  Signal level=-40 dBm
                    Encryption key:on
                    ESSID:\"FirstNet\"
                    IE: IEEE 802.11i/WPA2 Version 1
          Cell 02 - Address: AA:BB:CC:DD:EE:02
                    Channel:11
                    Quality=40/70  Signal level=-70 dBm
                    Encryption key:on
                    ESSID:\"\"
                    IE: WPA Version 1
          Cell 03 - Address: AA:BB:CC:DD:EE:03
                    Channel:1
                    Quality=30/70  Signal level=-80 dBm
                    Encryption key:off
                    ESSID:\"LastNet\"
";

    #[test]
    fn test_parse_iwlist_hidden_computed_per_cell() {
        let networks = parse_iwlist_output(SAMPLE_IWLIST);
        assert_eq!(networks.len(), 3);

        assert_eq!(networks[0].ssid, "FirstNet");
        assert!(!networks[0].hidden);
        assert_eq!(networks[0].bssid, "AA:BB:CC:DD:EE:01");
        assert_eq!(networks[0].channel, 6);
        assert_eq!(networks[0].signal_strength_dbm, -40);
        assert_eq!(networks[0].encryption, WifiEncryption::Wpa2Psk);

        assert_eq!(networks[1].ssid, "<hidden>");
        assert!(networks[1].hidden);
        assert_eq!(networks[1].encryption, WifiEncryption::WpaPsk);

        assert_eq!(networks[2].ssid, "LastNet");
        assert!(!networks[2].hidden);
        assert_eq!(networks[2].signal_strength_dbm, -80);
        assert_eq!(networks[2].encryption, WifiEncryption::Open);
    }

    #[test]
    fn test_parse_iwlist_last_cell_hidden() {
        let output =
            "          Cell 01 - Address: AA:BB:CC:DD:EE:09\n                    ESSID:\"\"\n";
        let networks = parse_iwlist_output(output);
        assert_eq!(networks.len(), 1);
        assert!(networks[0].hidden);
        assert_eq!(networks[0].ssid, "<hidden>");
    }

    #[test]
    fn test_parse_iwlist_no_cells() {
        assert!(parse_iwlist_output("wlan0     No scan results\n").is_empty());
    }
}
