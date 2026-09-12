//! `WiFi` monitor mode setup and teardown.
//! Linux: virtual monitor interface via `iw` (existing connection preserved).
//! macOS: pcap rfmon on the real interface (disconnects `WiFi`).

use anyhow::{Context, Result, bail};
use std::process::Command;

/// Describes whether monitor mode is available.
#[derive(Debug)]
pub enum MonitorCapability {
    /// Monitor mode is supported on this interface.
    Supported { interface: String, phy: String },
    /// Monitor mode unavailable, with reason.
    NotSupported(String),
}

/// A live monitor mode session with RAII cleanup.
pub struct MonitorSession {
    /// The interface to capture on (the monitor interface).
    pub monitor_interface: String,
    /// The original `WiFi` interface.
    pub original_interface: String,
    /// How the session was created (determines cleanup).
    platform: MonitorPlatform,
}

#[allow(dead_code)]
enum MonitorPlatform {
    /// Virtual monitor interface created via `iw` (Linux).
    LinuxVirtual,
    /// rfmon enabled on existing interface (macOS).
    MacOsRfmon,
}

impl Drop for MonitorSession {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            tracing::warn!(
                "failed to clean up monitor interface {}: {e}",
                self.monitor_interface
            );
        }
    }
}

impl MonitorSession {
    fn cleanup(&self) -> Result<()> {
        match self.platform {
            MonitorPlatform::LinuxVirtual => {
                teardown_linux_monitor(&self.monitor_interface)?;
            }
            MonitorPlatform::MacOsRfmon => {
                // rfmon is released when the pcap capture closes.
            }
        }
        Ok(())
    }
}

/// Find the primary `WiFi` interface on this system.
pub fn find_wifi_interface() -> Result<String> {
    find_wifi_interface_platform()
}

/// Check whether the system supports monitor mode.
pub fn detect_capability() -> MonitorCapability {
    detect_capability_platform()
}

/// Set up a monitor session. Linux creates a virtual interface (`rikmon0`);
/// macOS returns the existing interface, with rfmon set at capture time.
pub fn setup_monitor(interface: &str) -> Result<MonitorSession> {
    setup_monitor_platform(interface)
}

#[cfg(target_os = "linux")]
fn find_wifi_interface_platform() -> Result<String> {
    // Interfaces with a `/sys/class/net/<if>/wireless` directory are wireless.
    let entries = std::fs::read_dir("/sys/class/net").context("failed to read /sys/class/net")?;

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let wireless_path = entry.path().join("wireless");
        if wireless_path.exists() {
            return Ok(name_str.to_string());
        }
    }

    parse_iw_dev_interface(&run_command("iw", &["dev"])?)
        .ok_or_else(|| anyhow::anyhow!("no WiFi interface found"))
}

#[cfg(target_os = "linux")]
fn detect_capability_platform() -> MonitorCapability {
    let interface = match find_wifi_interface() {
        Ok(iface) => iface,
        Err(e) => return MonitorCapability::NotSupported(format!("no WiFi interface: {e}")),
    };

    let Some(phy) = get_phy_for_interface(&interface) else {
        return MonitorCapability::NotSupported(format!("could not determine phy for {interface}"));
    };

    let Ok(output) = run_command("iw", &["phy", &phy, "info"]) else {
        return MonitorCapability::NotSupported(
            "iw command not found or failed — install iw".to_owned(),
        );
    };

    if parse_iw_phy_supports_monitor(&output) {
        MonitorCapability::Supported { interface, phy }
    } else {
        MonitorCapability::NotSupported(format!("{phy} does not support monitor mode"))
    }
}

#[cfg(target_os = "linux")]
fn setup_monitor_platform(interface: &str) -> Result<MonitorSession> {
    let mon_name = "rikmon0";

    // Remove a stale interface from a previous run.
    let _ = run_command("ip", &["link", "set", mon_name, "down"]);
    let _ = run_command("iw", &["dev", mon_name, "del"]);

    run_command(
        "iw",
        &[
            "dev",
            interface,
            "interface",
            "add",
            mon_name,
            "type",
            "monitor",
        ],
    )
    .with_context(|| format!("failed to create monitor interface from {interface}"))?;

    run_command("ip", &["link", "set", mon_name, "up"])
        .with_context(|| format!("failed to bring up {mon_name}"))?;

    tracing::info!(
        monitor = mon_name,
        original = interface,
        "monitor mode active"
    );

    Ok(MonitorSession {
        monitor_interface: mon_name.to_owned(),
        original_interface: interface.to_owned(),
        platform: MonitorPlatform::LinuxVirtual,
    })
}

#[cfg(target_os = "linux")]
fn teardown_linux_monitor(mon_interface: &str) -> Result<()> {
    let _ = run_command("ip", &["link", "set", mon_interface, "down"]);
    run_command("iw", &["dev", mon_interface, "del"])
        .with_context(|| format!("failed to delete monitor interface {mon_interface}"))?;
    tracing::info!(interface = mon_interface, "monitor interface removed");
    Ok(())
}

#[cfg(target_os = "macos")]
fn find_wifi_interface_platform() -> Result<String> {
    let output = run_command("networksetup", &["-listallhardwareports"])?;
    parse_networksetup_wifi_interface(&output)
        .ok_or_else(|| anyhow::anyhow!("no WiFi interface found in networksetup output"))
}

#[cfg(target_os = "macos")]
fn detect_capability_platform() -> MonitorCapability {
    let interface = match find_wifi_interface() {
        Ok(iface) => iface,
        Err(e) => return MonitorCapability::NotSupported(format!("no WiFi interface: {e}")),
    };

    // rfmon support is only verified when pcap opens the capture.
    MonitorCapability::Supported {
        phy: "unknown".to_owned(),
        interface,
    }
}

#[cfg(target_os = "macos")]
fn setup_monitor_platform(interface: &str) -> Result<MonitorSession> {
    tracing::warn!(
        "macOS: enabling monitor mode on {interface} will disconnect your WiFi connection"
    );

    Ok(MonitorSession {
        monitor_interface: interface.to_owned(),
        original_interface: interface.to_owned(),
        platform: MonitorPlatform::MacOsRfmon,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn find_wifi_interface_platform() -> Result<String> {
    bail!("WiFi monitor mode is not supported on this platform");
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn detect_capability_platform() -> MonitorCapability {
    MonitorCapability::NotSupported("unsupported platform".to_owned())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn setup_monitor_platform(_interface: &str) -> Result<MonitorSession> {
    bail!("WiFi monitor mode is not supported on this platform");
}

fn run_command(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {cmd}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{cmd} failed: {stderr}");
    }
}

/// Get the physical device name (phy) for a wireless interface on Linux.
#[cfg(target_os = "linux")]
fn get_phy_for_interface(interface: &str) -> Option<String> {
    let path = format!("/sys/class/net/{interface}/phy80211/name");
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

/// First `Interface <name>` entry in `iw dev` output.
fn parse_iw_dev_interface(output: &str) -> Option<String> {
    // Format:
    //   phy#0
    //     Interface wlan0
    //       type managed
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Interface ") {
            let iface = rest.trim();
            if !iface.is_empty() {
                return Some(iface.to_owned());
            }
        }
    }
    None
}

/// Whether `iw phy <phy> info` lists `monitor` under "Supported interface modes:".
fn parse_iw_phy_supports_monitor(output: &str) -> bool {
    let mut in_modes = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Supported interface modes:") {
            in_modes = true;
            continue;
        }
        if in_modes {
            if trimmed.starts_with('*') {
                if trimmed.contains("monitor") {
                    return true;
                }
            } else if !trimmed.is_empty() {
                in_modes = false;
            }
        }
    }
    false
}

/// Parse `networksetup -listallhardwareports` to find the `WiFi` interface name.
#[cfg(any(target_os = "macos", test))]
fn parse_networksetup_wifi_interface(output: &str) -> Option<String> {
    // Format:
    //   Hardware Port: Wi-Fi
    //   Device: en0
    //   Ethernet Address: ...
    let mut found_wifi = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed == "Hardware Port: Wi-Fi" {
            found_wifi = true;
            continue;
        }
        if found_wifi {
            if let Some(device) = trimmed.strip_prefix("Device: ") {
                return Some(device.trim().to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iw_dev_interface() {
        let output = "\
phy#0
\tInterface wlan0
\t\tifindex 3
\t\twdev 0x1
\t\taddr 00:11:22:33:44:55
\t\ttype managed
\t\tchannel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
\t\ttxpower 20.00 dBm
";
        assert_eq!(parse_iw_dev_interface(output), Some("wlan0".to_owned()));
    }

    #[test]
    fn test_parse_iw_dev_no_interface() {
        assert_eq!(parse_iw_dev_interface(""), None);
        assert_eq!(parse_iw_dev_interface("phy#0\n"), None);
    }

    #[test]
    fn test_parse_iw_phy_supports_monitor() {
        let output = "\
Wiphy phy0
\tmax # scan SSIDs: 20
\tSupported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * AP
\t\t * monitor
\t\t * P2P-client
\tBand 1:
";
        assert!(parse_iw_phy_supports_monitor(output));
    }

    #[test]
    fn test_parse_iw_phy_no_monitor() {
        let output = "\
Wiphy phy0
\tSupported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * AP
\tBand 1:
";
        assert!(!parse_iw_phy_supports_monitor(output));
    }

    #[test]
    fn test_parse_networksetup_wifi() {
        let output = "\
Hardware Port: Ethernet
Device: en6
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 11:22:33:44:55:66

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 11:22:33:44:55:67
";
        assert_eq!(
            parse_networksetup_wifi_interface(output),
            Some("en0".to_owned())
        );
    }

    #[test]
    fn test_parse_networksetup_no_wifi() {
        let output = "\
Hardware Port: Ethernet
Device: en6
Ethernet Address: aa:bb:cc:dd:ee:ff
";
        assert_eq!(parse_networksetup_wifi_interface(output), None);
    }
}
