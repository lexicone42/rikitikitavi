use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// Represents a network interface on the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: Option<IpAddr>,
    pub netmask: Option<IpAddr>,
    pub mac: Option<String>,
    pub is_up: bool,
    pub is_loopback: bool,
}

// ─── Linux implementation ───────────────────────────────────────────────────

/// A parsed route entry from `/proc/net/route`.
#[derive(Debug, Clone)]
struct RouteEntry {
    interface: String,
    destination: Ipv4Addr,
    gateway: Ipv4Addr,
    mask: Ipv4Addr,
}

/// Parse a little-endian hex IP from `/proc/net/route` into an `Ipv4Addr`.
fn parse_hex_ip(hex: &str) -> Result<Ipv4Addr> {
    let val =
        u32::from_str_radix(hex.trim(), 16).with_context(|| format!("invalid hex IP: {hex}"))?;
    // /proc/net/route stores IPs in native (little-endian on x86) byte order
    Ok(Ipv4Addr::from(val.to_be()))
}

/// Parse the contents of `/proc/net/route` into route entries.
fn parse_proc_route(contents: &str) -> Vec<RouteEntry> {
    contents
        .lines()
        .skip(1) // skip header
        .filter_map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() < 8 {
                return None;
            }
            let destination = parse_hex_ip(fields[1]).ok()?;
            let gateway = parse_hex_ip(fields[2]).ok()?;
            let mask = parse_hex_ip(fields[7]).ok()?;
            Some(RouteEntry {
                interface: fields[0].to_owned(),
                destination,
                gateway,
                mask,
            })
        })
        .collect()
}

/// Internal: parse gateway from Linux route table text.
fn detect_gateway_from_proc(contents: &str) -> Option<IpAddr> {
    let routes = parse_proc_route(contents);
    routes
        .iter()
        .find(|r| r.destination == Ipv4Addr::UNSPECIFIED)
        .map(|r| IpAddr::V4(r.gateway))
}

/// Internal: parse network CIDR from Linux route table text.
fn detect_network_from_proc(contents: &str) -> Option<IpNetwork> {
    let routes = parse_proc_route(contents);
    let default_iface = routes
        .iter()
        .find(|r| r.destination == Ipv4Addr::UNSPECIFIED)
        .map(|r| r.interface.clone())?;

    routes
        .iter()
        .find(|r| {
            r.interface == default_iface
                && r.destination != Ipv4Addr::UNSPECIFIED
                && r.mask != Ipv4Addr::UNSPECIFIED
        })
        .and_then(|r| {
            let prefix = mask_to_prefix(r.mask);
            IpNetwork::new(IpAddr::V4(r.destination), prefix).ok()
        })
}

/// Internal: parse default interface from Linux route table text.
fn detect_default_interface_from_proc(contents: &str) -> Option<String> {
    let routes = parse_proc_route(contents);
    routes
        .iter()
        .find(|r| r.destination == Ipv4Addr::UNSPECIFIED)
        .map(|r| r.interface.clone())
}

/// Convert a subnet mask to a CIDR prefix length.
fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    // count_ones() on a u32 returns at most 32, which always fits in u8
    #[allow(clippy::cast_possible_truncation)]
    let prefix = bits.count_ones() as u8;
    prefix
}

// ─── macOS implementation ───────────────────────────────────────────────────

/// Parse gateway from macOS `route -n get default` output.
#[cfg(any(target_os = "macos", test))]
fn detect_gateway_from_macos_route(contents: &str) -> Option<IpAddr> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("gateway:") {
            let ip_str = rest.trim();
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}

/// Parse default interface from macOS `route -n get default` output.
#[cfg(any(target_os = "macos", test))]
fn detect_default_interface_from_macos_route(contents: &str) -> Option<String> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("interface:") {
            let iface = rest.trim();
            if !iface.is_empty() {
                return Some(iface.to_owned());
            }
        }
    }
    None
}

/// Parse network info from macOS `ifconfig <iface>` output.
/// Returns (ip, netmask) if found.
#[cfg(any(target_os = "macos", test))]
fn parse_macos_ifconfig_iface(contents: &str) -> Option<(IpAddr, IpAddr)> {
    for line in contents.lines() {
        let trimmed = line.trim();
        // inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "netmask" {
                let ip: IpAddr = parts[0].parse().ok()?;
                let mask = parse_macos_hex_netmask(parts[2])?;
                return Some((ip, mask));
            }
        }
    }
    None
}

/// Parse a macOS hex netmask like "0xffffff00" into an `IpAddr`.
#[cfg(any(target_os = "macos", test))]
fn parse_macos_hex_netmask(hex: &str) -> Option<IpAddr> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let val = u32::from_str_radix(hex, 16).ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(val)))
}

/// Parse macOS `ifconfig -a` output into network interfaces.
#[cfg(any(target_os = "macos", test))]
#[allow(clippy::similar_names)]
fn parse_macos_ifconfig_all(contents: &str) -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_ip: Option<IpAddr> = None;
    let mut current_netmask: Option<IpAddr> = None;
    let mut current_mac: Option<String> = None;
    let mut current_up = false;
    let mut current_loopback = false;

    for line in contents.lines() {
        // New interface block starts with "en0: flags=..."
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(": flags=") {
            // Save previous interface
            if let Some(name) = current_name.take() {
                interfaces.push(NetworkInterface {
                    name,
                    ip: current_ip.take(),
                    netmask: current_netmask.take(),
                    mac: current_mac.take(),
                    is_up: current_up,
                    is_loopback: current_loopback,
                });
            }

            let Some(colon_pos) = line.find(':') else {
                continue;
            };
            current_name = Some(line[..colon_pos].to_owned());
            current_up = line.contains("UP");
            current_loopback = line.contains("LOOPBACK");
            current_ip = None;
            current_netmask = None;
            current_mac = None;
        } else {
            let trimmed = line.trim();
            // ether aa:bb:cc:dd:ee:ff
            if let Some(rest) = trimmed.strip_prefix("ether ") {
                let mac = rest.split_whitespace().next().unwrap_or(rest);
                if mac != "00:00:00:00:00:00" {
                    current_mac = Some(mac.to_owned());
                }
            }
            // inet 192.168.1.100 netmask 0xffffff00
            if let Some(rest) = trimmed.strip_prefix("inet ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if !parts.is_empty() {
                    current_ip = parts[0].parse().ok();
                }
                if parts.len() >= 3 && parts[1] == "netmask" {
                    current_netmask = parse_macos_hex_netmask(parts[2]);
                }
            }
        }
    }

    // Don't forget the last interface
    if let Some(name) = current_name {
        interfaces.push(NetworkInterface {
            name,
            ip: current_ip,
            netmask: current_netmask,
            mac: current_mac,
            is_up: current_up,
            is_loopback: current_loopback,
        });
    }

    interfaces
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Detect the default gateway IP address.
pub fn detect_gateway() -> Result<Option<IpAddr>> {
    tracing::debug!("detecting default gateway");
    detect_gateway_platform()
}

#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
fn detect_gateway_platform() -> Result<Option<IpAddr>> {
    let contents = match std::fs::read_to_string("/proc/net/route") {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("cannot read /proc/net/route: {e}");
            return Ok(None);
        }
    };
    Ok(detect_gateway_from_proc(&contents))
}

#[cfg(target_os = "macos")]
fn detect_gateway_platform() -> Result<Option<IpAddr>> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let contents = String::from_utf8_lossy(&out.stdout);
            Ok(detect_gateway_from_macos_route(&contents))
        }
        Ok(out) => {
            tracing::warn!(
                "route command failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            Ok(None)
        }
        Err(e) => {
            tracing::warn!("failed to run route command: {e}");
            Ok(None)
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn detect_gateway_platform() -> Result<Option<IpAddr>> {
    tracing::warn!("gateway detection not supported on this platform");
    Ok(None)
}

/// Detect the LAN network CIDR.
pub fn detect_network() -> Result<Option<IpNetwork>> {
    tracing::debug!("detecting current network");
    detect_network_platform()
}

#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
fn detect_network_platform() -> Result<Option<IpNetwork>> {
    let contents = match std::fs::read_to_string("/proc/net/route") {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("cannot read /proc/net/route: {e}");
            return Ok(None);
        }
    };
    Ok(detect_network_from_proc(&contents))
}

#[cfg(target_os = "macos")]
fn detect_network_platform() -> Result<Option<IpNetwork>> {
    // First get the default interface
    let iface = match detect_default_interface()? {
        Some(iface) => iface,
        None => return Ok(None),
    };

    // Then get IP/netmask from ifconfig for that interface
    let output = std::process::Command::new("ifconfig").arg(&iface).output();
    match output {
        Ok(out) if out.status.success() => {
            let contents = String::from_utf8_lossy(&out.stdout);
            if let Some((ip, mask)) = parse_macos_ifconfig_iface(&contents) {
                if let IpAddr::V4(mask_v4) = mask {
                    let prefix = mask_to_prefix(mask_v4);
                    // Compute network address by masking the IP
                    if let IpAddr::V4(ip_v4) = ip {
                        let net_bits = u32::from(ip_v4) & u32::from(mask_v4);
                        let net_addr = IpAddr::V4(Ipv4Addr::from(net_bits));
                        return Ok(IpNetwork::new(net_addr, prefix).ok());
                    }
                }
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn detect_network_platform() -> Result<Option<IpNetwork>> {
    tracing::warn!("network detection not supported on this platform");
    Ok(None)
}

/// Detect the default interface name.
pub fn detect_default_interface() -> Result<Option<String>> {
    detect_default_interface_platform()
}

#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
fn detect_default_interface_platform() -> Result<Option<String>> {
    let contents = match std::fs::read_to_string("/proc/net/route") {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("cannot read /proc/net/route: {e}");
            return Ok(None);
        }
    };
    Ok(detect_default_interface_from_proc(&contents))
}

#[cfg(target_os = "macos")]
fn detect_default_interface_platform() -> Result<Option<String>> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let contents = String::from_utf8_lossy(&out.stdout);
            Ok(detect_default_interface_from_macos_route(&contents))
        }
        _ => Ok(None),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn detect_default_interface_platform() -> Result<Option<String>> {
    tracing::warn!("interface detection not supported on this platform");
    Ok(None)
}

/// List all network interfaces.
pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
    tracing::debug!("listing network interfaces");
    list_interfaces_platform()
}

#[cfg(target_os = "linux")]
fn list_interfaces_platform() -> Result<Vec<NetworkInterface>> {
    let net_dir = std::path::Path::new("/sys/class/net");
    if !net_dir.exists() {
        tracing::warn!("/sys/class/net not found");
        return Ok(Vec::new());
    }

    let mut interfaces = Vec::new();
    let entries = std::fs::read_dir(net_dir).context("failed to read /sys/class/net")?;

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();

        let mac = read_sysfs_file(&entry.path().join("address"))
            .map(|s| s.trim().to_owned())
            .filter(|m| m != "00:00:00:00:00:00");

        let is_up =
            read_sysfs_file(&entry.path().join("operstate")).is_some_and(|s| s.trim() == "up");

        // Type 772 = loopback in Linux
        let if_type = read_sysfs_file(&entry.path().join("type"))
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0);
        let is_loopback = if_type == 772;

        interfaces.push(NetworkInterface {
            name,
            ip: None,
            netmask: None,
            mac,
            is_up,
            is_loopback,
        });
    }

    Ok(interfaces)
}

#[cfg(target_os = "macos")]
fn list_interfaces_platform() -> Result<Vec<NetworkInterface>> {
    let output = std::process::Command::new("ifconfig").arg("-a").output();
    match output {
        Ok(out) if out.status.success() => {
            let contents = String::from_utf8_lossy(&out.stdout);
            Ok(parse_macos_ifconfig_all(&contents))
        }
        Ok(out) => {
            tracing::warn!("ifconfig failed: {}", String::from_utf8_lossy(&out.stderr));
            Ok(Vec::new())
        }
        Err(e) => {
            tracing::warn!("failed to run ifconfig: {e}");
            Ok(Vec::new())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn list_interfaces_platform() -> Result<Vec<NetworkInterface>> {
    tracing::warn!("interface listing not supported on this platform");
    Ok(Vec::new())
}

/// Read a sysfs file, returning its content as a string.
#[cfg(target_os = "linux")]
fn read_sysfs_file(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Linux parsing tests ────────────────────────────────────────────

    const SAMPLE_PROC_ROUTE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    #[test]
    fn test_parse_hex_ip() {
        assert_eq!(
            parse_hex_ip("0101A8C0").unwrap(),
            Ipv4Addr::new(192, 168, 1, 1)
        );
        assert_eq!(parse_hex_ip("00000000").unwrap(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_detect_gateway_linux() {
        let gw = detect_gateway_from_proc(SAMPLE_PROC_ROUTE);
        assert_eq!(gw, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_detect_network_linux() {
        let net = detect_network_from_proc(SAMPLE_PROC_ROUTE);
        assert!(net.is_some());
        let net = net.unwrap();
        assert_eq!(net.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(net.prefix(), 24);
    }

    #[test]
    fn test_detect_default_interface_linux() {
        let iface = detect_default_interface_from_proc(SAMPLE_PROC_ROUTE);
        assert_eq!(iface, Some("eth0".to_owned()));
    }

    #[test]
    fn test_no_default_route() {
        let contents = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";
        assert_eq!(detect_gateway_from_proc(contents), None);
        assert_eq!(detect_network_from_proc(contents), None);
    }

    #[test]
    fn test_mask_to_prefix() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 128)), 25);
        assert_eq!(mask_to_prefix(Ipv4Addr::UNSPECIFIED), 0);
    }

    // ─── macOS parsing tests ────────────────────────────────────────────

    const SAMPLE_MACOS_ROUTE: &str = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,AUTOCONF>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";

    #[test]
    fn test_detect_gateway_macos() {
        let gw = detect_gateway_from_macos_route(SAMPLE_MACOS_ROUTE);
        assert_eq!(gw, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_detect_default_interface_macos() {
        let iface = detect_default_interface_from_macos_route(SAMPLE_MACOS_ROUTE);
        assert_eq!(iface, Some("en0".to_owned()));
    }

    const SAMPLE_MACOS_IFCONFIG: &str = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether a4:83:e7:1a:2b:3c
\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
en1: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\tether 00:11:22:33:44:55
";

    #[test]
    fn test_parse_macos_ifconfig_iface() {
        let ifconfig_en0 = "\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether a4:83:e7:1a:2b:3c
\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
";
        let result = parse_macos_ifconfig_iface(ifconfig_en0);
        assert!(result.is_some());
        let (ip, mask) = result.unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(mask, IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)));
    }

    #[test]
    fn test_parse_macos_ifconfig_all() {
        let ifaces = parse_macos_ifconfig_all(SAMPLE_MACOS_IFCONFIG);
        assert_eq!(ifaces.len(), 3);

        assert_eq!(ifaces[0].name, "lo0");
        assert!(ifaces[0].is_loopback);
        assert!(ifaces[0].is_up);

        assert_eq!(ifaces[1].name, "en0");
        assert!(ifaces[1].is_up);
        assert!(!ifaces[1].is_loopback);
        assert_eq!(ifaces[1].mac.as_deref(), Some("a4:83:e7:1a:2b:3c"));
        assert_eq!(
            ifaces[1].ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
        );

        assert_eq!(ifaces[2].name, "en1");
        assert!(!ifaces[2].is_up); // no RUNNING flag
    }

    #[test]
    fn test_parse_macos_hex_netmask() {
        assert_eq!(
            parse_macos_hex_netmask("0xffffff00"),
            Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)))
        );
        assert_eq!(
            parse_macos_hex_netmask("0xffff0000"),
            Some(IpAddr::V4(Ipv4Addr::new(255, 255, 0, 0)))
        );
    }

    // ─── Property-based tests ─────────────────────────────────────────

    proptest::proptest! {
        /// /proc/net/route parser never panics on arbitrary input.
        #[test]
        fn prop_parse_proc_route_no_panic(input in proptest::prelude::any::<String>()) {
            let _ = parse_proc_route(&input);
        }

        /// hex IP parser never panics (may return Err on invalid input).
        #[test]
        fn prop_parse_hex_ip_no_panic(input in "[0-9a-fA-F]{0,16}") {
            let _ = parse_hex_ip(&input);
        }

        /// macOS ifconfig parser never panics on arbitrary input.
        #[test]
        fn prop_parse_macos_ifconfig_no_panic(input in proptest::prelude::any::<String>()) {
            let _ = parse_macos_ifconfig_all(&input);
        }

        /// macOS hex netmask parser never panics.
        #[test]
        fn prop_parse_macos_hex_netmask_no_panic(input in proptest::prelude::any::<String>()) {
            let _ = parse_macos_hex_netmask(&input);
        }

        /// mask_to_prefix always returns a value in [0, 32].
        #[test]
        fn prop_mask_to_prefix_bounded(octets in proptest::array::uniform4(0_u8..=255)) {
            let mask = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
            let prefix = mask_to_prefix(mask);
            assert!(prefix <= 32, "prefix {prefix} > 32 for mask {mask}");
        }

        /// Interfaces parsed from macOS ifconfig always have non-empty names.
        #[test]
        fn prop_macos_ifconfig_names_nonempty(input in proptest::prelude::any::<String>()) {
            let ifaces = parse_macos_ifconfig_all(&input);
            for iface in &ifaces {
                assert!(!iface.name.is_empty(), "interface with empty name");
            }
        }
    }
}
