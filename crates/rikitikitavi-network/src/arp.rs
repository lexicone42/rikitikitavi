use anyhow::Result;
use std::net::IpAddr;

/// Result of an ARP scan for a single host.
#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: IpAddr,
    pub mac: String,
    pub interface: String,
}

/// ARP cache entries within `network`. No active probing; on Linux
/// `rikitikitavi-nethelper.sh` can populate the cache beforehand.
#[allow(clippy::unused_async)]
pub async fn arp_scan(network: &ipnetwork::IpNetwork) -> Result<Vec<ArpEntry>> {
    tracing::debug!(%network, "performing ARP scan (reading cache)");
    let entries = read_arp_cache()?;
    Ok(entries
        .into_iter()
        .filter(|e| network.contains(e.ip))
        .collect())
}

/// Read the system ARP cache.
pub fn read_arp_cache() -> Result<Vec<ArpEntry>> {
    tracing::debug!("reading ARP cache");
    read_arp_cache_platform()
}

#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
fn read_arp_cache_platform() -> Result<Vec<ArpEntry>> {
    let contents = match std::fs::read_to_string("/proc/net/arp") {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("cannot read /proc/net/arp: {e}");
            return Ok(Vec::new());
        }
    };
    Ok(parse_linux_arp_cache(&contents))
}

#[cfg(target_os = "macos")]
fn read_arp_cache_platform() -> Result<Vec<ArpEntry>> {
    let output = std::process::Command::new("arp").arg("-a").output();
    match output {
        Ok(out) if out.status.success() => {
            let contents = String::from_utf8_lossy(&out.stdout);
            Ok(parse_macos_arp(&contents))
        }
        Ok(out) => {
            tracing::warn!(
                "arp command failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            Ok(Vec::new())
        }
        Err(e) => {
            tracing::warn!("failed to run arp command: {e}");
            Ok(Vec::new())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_arp_cache_platform() -> Result<Vec<ArpEntry>> {
    tracing::warn!("ARP cache reading not supported on this platform");
    Ok(Vec::new())
}

#[cfg(any(target_os = "linux", test))]
/// Parse Linux `/proc/net/arp`: `IP address  HW type  Flags  HW address  Mask  Device`.
/// Incomplete entries (flags `0x0` or MAC `00:00:00:00:00:00`) are dropped.
fn parse_linux_arp_cache(contents: &str) -> Vec<ArpEntry> {
    contents
        .lines()
        .skip(1) // skip header
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }
            let ip: IpAddr = fields[0].parse().ok()?;
            let flags = fields[2];
            let mac = fields[3];
            let interface = fields[5];

            if flags == "0x0" || mac == "00:00:00:00:00:00" {
                return None;
            }

            Some(ArpEntry {
                ip,
                mac: mac.to_owned(),
                interface: interface.to_owned(),
            })
        })
        .collect()
}

/// Parse macOS `arp -a`: `hostname (IP) at MAC on interface [ifscope ...]`.
/// `(incomplete)` lines and the broadcast MAC are dropped.
#[cfg(any(target_os = "macos", test))]
fn parse_macos_arp(contents: &str) -> Vec<ArpEntry> {
    contents
        .lines()
        .filter_map(|line| {
            if line.contains("(incomplete)") {
                return None;
            }

            let open = line.find('(')?;
            let close = line.find(')')?;
            if close <= open + 1 {
                return None;
            }
            let ip_str = &line[open + 1..close];
            let ip: IpAddr = ip_str.parse().ok()?;

            let after_close = &line[close + 1..];
            let at_idx = after_close.find(" at ")?;
            let rest = &after_close[at_idx + 4..];
            let parts: Vec<&str> = rest.split_whitespace().collect();

            // parts[0] = MAC, parts[1] = "on", parts[2] = interface
            if parts.len() < 3 || parts[1] != "on" {
                return None;
            }

            let mac = parts[0];
            if mac == "(incomplete)" || mac == "ff:ff:ff:ff:ff:ff" {
                return None;
            }

            let interface = parts[2];

            Some(ArpEntry {
                ip,
                mac: pad_mac_octets(mac),
                interface: interface.to_owned(),
            })
        })
        .collect()
}

/// BSD `arp -a` prints octets unpadded (`0:1c:42:0:0:8`).
#[cfg(any(target_os = "macos", test))]
fn pad_mac_octets(raw: &str) -> String {
    raw.split(':')
        .map(|o| format!("{o:0>2}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ─── Linux tests ────────────────────────────────────────────────────

    const SAMPLE_LINUX_ARP: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.100    0x1         0x2         11:22:33:44:55:66     *        eth0
192.168.1.200    0x1         0x0         00:00:00:00:00:00     *        eth0
10.0.0.1         0x1         0x2         de:ad:be:ef:00:01     *        wlan0
";

    #[test]
    fn test_parse_linux_arp_basic() {
        let entries = parse_linux_arp_cache(SAMPLE_LINUX_ARP);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_parse_linux_arp_fields() {
        let entries = parse_linux_arp_cache(SAMPLE_LINUX_ARP);
        let first = &entries[0];
        assert_eq!(first.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(first.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(first.interface, "eth0");
    }

    #[test]
    fn test_parse_linux_arp_filters_incomplete() {
        let entries = parse_linux_arp_cache(SAMPLE_LINUX_ARP);
        assert!(
            !entries
                .iter()
                .any(|e| { e.ip == IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)) })
        );
    }

    #[test]
    fn test_parse_linux_arp_multiple_interfaces() {
        let entries = parse_linux_arp_cache(SAMPLE_LINUX_ARP);
        let wlan_entry = entries.iter().find(|e| e.interface == "wlan0");
        assert!(wlan_entry.is_some());
        assert_eq!(
            wlan_entry.unwrap().ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn test_parse_linux_arp_empty() {
        let contents =
            "IP address       HW type     Flags       HW address            Mask     Device\n";
        let entries = parse_linux_arp_cache(contents);
        assert!(entries.is_empty());
    }

    // ─── macOS tests ────────────────────────────────────────────────────

    const SAMPLE_MACOS_ARP: &str = "\
? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
? (192.168.1.100) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
? (192.168.1.200) at (incomplete) on en0 ifscope [ethernet]
myhost.local (10.0.0.50) at de:ad:be:ef:00:02 on en1 [ethernet]
? (224.0.0.251) at ff:ff:ff:ff:ff:ff on en0 ifscope permanent [ethernet]
";

    #[test]
    fn test_parse_macos_arp_basic() {
        let entries = parse_macos_arp(SAMPLE_MACOS_ARP);
        // Should have 3: .1, .100, and 10.0.0.50
        // .200 incomplete, 224.x broadcast filtered
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_parse_macos_arp_fields() {
        let entries = parse_macos_arp(SAMPLE_MACOS_ARP);
        let first = &entries[0];
        assert_eq!(first.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(first.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(first.interface, "en0");
    }

    #[test]
    fn test_parse_macos_arp_filters_incomplete() {
        let entries = parse_macos_arp(SAMPLE_MACOS_ARP);
        assert!(
            !entries
                .iter()
                .any(|e| { e.ip == IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)) })
        );
    }

    #[test]
    fn test_parse_macos_arp_filters_broadcast() {
        let entries = parse_macos_arp(SAMPLE_MACOS_ARP);
        assert!(
            !entries
                .iter()
                .any(|e| { e.ip == IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)) })
        );
    }

    #[test]
    fn test_parse_macos_arp_with_hostname() {
        let entries = parse_macos_arp(SAMPLE_MACOS_ARP);
        let host_entry = entries
            .iter()
            .find(|e| e.ip == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)));
        assert!(host_entry.is_some());
        assert_eq!(host_entry.unwrap().mac, "de:ad:be:ef:00:02");
        assert_eq!(host_entry.unwrap().interface, "en1");
    }

    // ─── Property-based tests ─────────────────────────────────────────

    proptest::proptest! {
        /// Linux ARP parser never panics on arbitrary input.
        #[test]
        fn prop_linux_arp_no_panic(input in proptest::prelude::any::<String>()) {
            let _ = parse_linux_arp_cache(&input);
        }

        /// macOS ARP parser never panics on arbitrary input.
        #[test]
        fn prop_macos_arp_no_panic(input in proptest::prelude::any::<String>()) {
            let _ = parse_macos_arp(&input);
        }

        /// All entries returned by the Linux parser have valid IPs and non-empty MACs.
        #[test]
        fn prop_linux_arp_valid_entries(input in proptest::prelude::any::<String>()) {
            let entries = parse_linux_arp_cache(&input);
            for entry in &entries {
                assert!(!entry.mac.is_empty());
                assert_ne!(entry.mac, "00:00:00:00:00:00");
                assert!(!entry.interface.is_empty());
            }
        }

        /// All entries returned by the macOS parser have non-empty MACs.
        #[test]
        fn prop_macos_arp_valid_entries(input in proptest::prelude::any::<String>()) {
            let entries = parse_macos_arp(&input);
            for entry in &entries {
                assert!(!entry.mac.is_empty());
                assert!(!entry.interface.is_empty());
            }
        }
    }
    #[test]
    fn macos_arp_pads_unpadded_octets() {
        let out = "? (192.168.1.5) at 0:1c:42:0:0:8 on en0 ifscope [ethernet]\n";
        let entries = parse_macos_arp(out);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].mac, "00:1c:42:00:00:08");
        assert_eq!(pad_mac_octets("aa:bb:cc:dd:ee:ff"), "aa:bb:cc:dd:ee:ff");
    }
}
