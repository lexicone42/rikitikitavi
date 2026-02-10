use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::Scanner;

/// ARP security scanner — detects ARP cache anomalies that indicate spoofing.
///
/// Analyzes the ARP cache for:
/// - Duplicate MACs (multiple IPs sharing one MAC — potential ARP spoofing)
/// - Duplicate IPs (multiple MACs for one IP — ARP spoofing in progress)
/// - Broadcast MAC in ARP entries (clearly malicious)
/// - Gateway MAC anomalies
pub struct ArpScanner;

/// Analyze ARP entries for spoofing indicators.
///
/// Returns a list of anomaly descriptions. Pure function for testability.
fn detect_arp_anomalies(entries: &[ArpEntryData], gateway: Option<IpAddr>) -> Vec<ArpAnomaly> {
    let mut anomalies = Vec::new();

    // ── Check for duplicate IPs (multiple MACs for same IP) ─────────
    // Deduplicate MACs per IP first — on macOS, arp -a often shows the
    // same IP+MAC pair on multiple interfaces (en0, en1, awdl0).
    let mut ip_to_macs: HashMap<IpAddr, HashSet<&str>> = HashMap::new();
    for entry in entries {
        ip_to_macs
            .entry(entry.ip)
            .or_default()
            .insert(&entry.mac);
    }

    for (ip, macs) in &ip_to_macs {
        if macs.len() > 1 {
            let is_gateway = gateway == Some(*ip);
            anomalies.push(ArpAnomaly::DuplicateIp {
                ip: *ip,
                macs: macs.iter().map(|m| (*m).to_owned()).collect(),
                is_gateway,
            });
        }
    }

    // ── Check for duplicate MACs (one MAC claiming multiple IPs) ────
    // Deduplicate IPs per MAC — same reasoning as above.
    let mut mac_to_ips: HashMap<&str, HashSet<IpAddr>> = HashMap::new();
    for entry in entries {
        // Skip broadcast and multicast MACs
        if is_broadcast_mac(&entry.mac) || is_multicast_mac(&entry.mac) {
            continue;
        }
        mac_to_ips.entry(&entry.mac).or_default().insert(entry.ip);
    }

    for (mac, ips) in &mac_to_ips {
        if ips.len() > 3 {
            // A single MAC with many IPs is suspicious (normal for router: 1-3 IPs)
            anomalies.push(ArpAnomaly::DuplicateMac {
                mac: (*mac).to_owned(),
                ips: ips.iter().copied().collect(),
            });
        }
    }

    // ── Check for broadcast/multicast MACs in ARP entries ───────────
    for entry in entries {
        if is_broadcast_mac(&entry.mac) {
            anomalies.push(ArpAnomaly::BroadcastMac {
                ip: entry.ip,
                mac: entry.mac.clone(),
            });
        }
    }

    // ── Check for incomplete/zero MAC entries ───────────────────────
    for entry in entries {
        if is_zero_mac(&entry.mac) {
            anomalies.push(ArpAnomaly::IncompleteMac { ip: entry.ip });
        }
    }

    anomalies
}

/// Simplified ARP entry for analysis (matches network crate's `ArpEntry`).
#[derive(Debug, Clone)]
struct ArpEntryData {
    ip: IpAddr,
    mac: String,
}

/// Types of ARP anomalies.
#[derive(Debug, Clone)]
enum ArpAnomaly {
    /// Multiple MACs claim the same IP (likely ARP spoofing).
    DuplicateIp {
        ip: IpAddr,
        macs: Vec<String>,
        is_gateway: bool,
    },
    /// One MAC claims many IPs (suspicious, possible mitm).
    DuplicateMac { mac: String, ips: Vec<IpAddr> },
    /// Broadcast MAC in ARP entry (clearly anomalous).
    BroadcastMac { ip: IpAddr, mac: String },
    /// Incomplete/zero MAC (ARP resolution failed).
    IncompleteMac { ip: IpAddr },
}

/// Check if a MAC address is the broadcast address.
fn is_broadcast_mac(mac: &str) -> bool {
    let normalized = mac.to_lowercase().replace('-', ":");
    normalized == "ff:ff:ff:ff:ff:ff"
}

/// Check if a MAC address is multicast (first octet LSB is 1).
fn is_multicast_mac(mac: &str) -> bool {
    let normalized = mac.to_lowercase().replace('-', ":");
    let Some(first_octet) = normalized.split(':').next() else {
        return false;
    };
    u8::from_str_radix(first_octet, 16)
        .map(|b| b & 1 == 1)
        .unwrap_or(false)
}

/// Check if a MAC address is all zeros.
fn is_zero_mac(mac: &str) -> bool {
    let normalized = mac.to_lowercase().replace('-', ":");
    normalized == "00:00:00:00:00:00"
}

/// Convert an anomaly into a Finding.
fn anomaly_to_finding(anomaly: &ArpAnomaly) -> Finding {
    match anomaly {
        ArpAnomaly::DuplicateIp {
            ip,
            macs,
            is_gateway,
        } => {
            let severity = if *is_gateway {
                Severity::Critical
            } else {
                Severity::High
            };
            let mac_list = macs.join(", ");
            let target = if *is_gateway { "GATEWAY " } else { "" };

            Finding::new(
                "arp",
                &format!("ARP spoofing detected: {target}{ip} has multiple MACs"),
                &format!(
                    "The {target}IP address {ip} has multiple MAC addresses in the ARP \
                     cache: [{mac_list}]. This is a strong indicator of ARP spoofing, \
                     where an attacker is intercepting network traffic by claiming \
                     to be {ip}."
                ),
                severity,
            )
            .with_ip(*ip)
            .with_cwe("CWE-290")
            .with_opt_remediation(crate::remediation::get(
                "rikitikitavi.arp.spoofing-detected",
                &[],
            ))
        }
        ArpAnomaly::DuplicateMac { mac, ips } => {
            let ip_list: Vec<String> = ips.iter().map(ToString::to_string).collect();
            let ip_str = ip_list.join(", ");

            Finding::new(
                "arp",
                &format!("MAC {mac} claims {} IP addresses", ips.len()),
                &format!(
                    "MAC address {mac} appears in the ARP cache for {count} different \
                     IP addresses: [{ip_str}]. While routers may legitimately have \
                     multiple IPs, {count} is unusual and may indicate ARP spoofing \
                     or a misconfigured device.",
                    count = ips.len()
                ),
                Severity::Medium,
            )
            .with_cwe("CWE-290")
        }
        ArpAnomaly::BroadcastMac { ip, mac } => Finding::new(
            "arp",
            &format!("Broadcast MAC for IP {ip}"),
            &format!(
                "IP address {ip} has broadcast MAC address {mac} in the ARP cache. \
                 This is anomalous and could indicate an ARP spoofing attempt or \
                 a severely misconfigured device."
            ),
            Severity::High,
        )
        .with_ip(*ip)
        .with_cwe("CWE-290"),

        ArpAnomaly::IncompleteMac { ip } => Finding::new(
            "arp",
            &format!("Incomplete ARP entry for {ip}"),
            &format!(
                "ARP cache has an incomplete (zero MAC) entry for {ip}. \
                 This usually means the host is unreachable or the ARP \
                 request timed out."
            ),
            Severity::Info,
        )
        .with_ip(*ip),
    }
}

#[async_trait]
impl Scanner for ArpScanner {
    fn id(&self) -> &'static str {
        "arp"
    }

    fn name(&self) -> &'static str {
        "ARP Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    #[allow(clippy::unused_async)]
    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running ARP security scan");

        let arp_entries = rikitikitavi_network::read_arp_cache().map_err(|e| {
            ScanError::ScannerFailed {
                scanner: "arp".to_owned(),
                message: format!("failed to read ARP cache: {e}"),
            }
        })?;

        let entries: Vec<ArpEntryData> = arp_entries
            .iter()
            .map(|e| ArpEntryData {
                ip: e.ip,
                mac: e.mac.clone(),
            })
            .collect();

        let anomalies = detect_arp_anomalies(&entries, ctx.gateway);
        let findings: Vec<Finding> = anomalies.iter().map(anomaly_to_finding).collect();

        tracing::info!(
            entries_checked = entries.len(),
            anomalies = anomalies.len(),
            "ARP security scan complete"
        );

        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        5
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn entry(ip: &str, mac: &str) -> ArpEntryData {
        ArpEntryData {
            ip: ip.parse().unwrap(),
            mac: mac.to_owned(),
        }
    }

    // ── MAC classification tests ────────────────────────────────────

    #[test]
    fn test_is_broadcast_mac() {
        assert!(is_broadcast_mac("ff:ff:ff:ff:ff:ff"));
        assert!(is_broadcast_mac("FF:FF:FF:FF:FF:FF"));
        assert!(is_broadcast_mac("FF-FF-FF-FF-FF-FF"));
        assert!(!is_broadcast_mac("00:11:22:33:44:55"));
    }

    #[test]
    fn test_is_multicast_mac() {
        assert!(is_multicast_mac("01:00:5e:00:00:01")); // IPv4 multicast
        assert!(is_multicast_mac("33:33:00:00:00:01")); // IPv6 multicast
        assert!(!is_multicast_mac("00:11:22:33:44:55")); // Unicast
        assert!(!is_multicast_mac("02:00:00:00:00:00")); // Locally administered but unicast
    }

    #[test]
    fn test_is_zero_mac() {
        assert!(is_zero_mac("00:00:00:00:00:00"));
        assert!(is_zero_mac("00-00-00-00-00-00"));
        assert!(!is_zero_mac("00:11:22:33:44:55"));
    }

    // ── Anomaly detection tests ─────────────────────────────────────

    #[test]
    fn test_no_anomalies_normal_network() {
        let entries = vec![
            entry("192.168.1.1", "aa:bb:cc:dd:ee:01"),
            entry("192.168.1.2", "aa:bb:cc:dd:ee:02"),
            entry("192.168.1.3", "aa:bb:cc:dd:ee:03"),
        ];
        let anomalies = detect_arp_anomalies(&entries, Some("192.168.1.1".parse().unwrap()));
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_duplicate_ip_detected() {
        let entries = vec![
            entry("192.168.1.1", "aa:bb:cc:dd:ee:01"),
            entry("192.168.1.1", "ff:ee:dd:cc:bb:aa"), // Same IP, different MAC
            entry("192.168.1.2", "aa:bb:cc:dd:ee:02"),
        ];
        let anomalies = detect_arp_anomalies(&entries, None);
        let dup_ip_count = anomalies
            .iter()
            .filter(|a| matches!(a, ArpAnomaly::DuplicateIp { .. }))
            .count();
        assert_eq!(dup_ip_count, 1);
    }

    #[test]
    fn test_duplicate_ip_gateway_is_critical() {
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        let entries = vec![
            entry("192.168.1.1", "aa:bb:cc:dd:ee:01"),
            entry("192.168.1.1", "ff:ee:dd:cc:bb:aa"),
        ];
        let anomalies = detect_arp_anomalies(&entries, Some(gw));
        let finding = anomaly_to_finding(&anomalies[0]);
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn test_duplicate_ip_non_gateway_is_high() {
        let entries = vec![
            entry("192.168.1.50", "aa:bb:cc:dd:ee:01"),
            entry("192.168.1.50", "ff:ee:dd:cc:bb:aa"),
        ];
        let anomalies = detect_arp_anomalies(&entries, Some("192.168.1.1".parse().unwrap()));
        let finding = anomaly_to_finding(&anomalies[0]);
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn test_same_ip_same_mac_multi_interface_not_spoofing() {
        // macOS arp -a shows the same IP+MAC on multiple interfaces (en0, en1).
        // This must NOT trigger a DuplicateIp anomaly.
        let entries = vec![
            entry("192.168.1.1", "aa:bb:cc:dd:ee:01"), // en0
            entry("192.168.1.1", "aa:bb:cc:dd:ee:01"), // en1 (same MAC!)
        ];
        let anomalies = detect_arp_anomalies(&entries, None);
        let dup_ip_count = anomalies
            .iter()
            .filter(|a| matches!(a, ArpAnomaly::DuplicateIp { .. }))
            .count();
        assert_eq!(dup_ip_count, 0, "identical MACs should not trigger spoofing");
    }

    #[test]
    fn test_same_mac_same_ip_multi_interface_not_suspicious() {
        // Same IP appearing multiple times with same MAC should not inflate
        // the mac_to_ips count.
        let entries = vec![
            entry("192.168.1.10", "aa:bb:cc:dd:ee:01"),
            entry("192.168.1.10", "aa:bb:cc:dd:ee:01"), // duplicate
            entry("192.168.1.11", "aa:bb:cc:dd:ee:01"),
            entry("192.168.1.11", "aa:bb:cc:dd:ee:01"), // duplicate
        ];
        let anomalies = detect_arp_anomalies(&entries, None);
        let dup_mac_count = anomalies
            .iter()
            .filter(|a| matches!(a, ArpAnomaly::DuplicateMac { .. }))
            .count();
        assert_eq!(dup_mac_count, 0, "2 unique IPs should not trigger DuplicateMac");
    }

    #[test]
    fn test_duplicate_mac_many_ips() {
        let entries = vec![
            entry("192.168.1.10", "aa:bb:cc:dd:ee:01"),
            entry("192.168.1.11", "aa:bb:cc:dd:ee:01"),
            entry("192.168.1.12", "aa:bb:cc:dd:ee:01"),
            entry("192.168.1.13", "aa:bb:cc:dd:ee:01"),
        ];
        let anomalies = detect_arp_anomalies(&entries, None);
        let dup_mac_count = anomalies
            .iter()
            .filter(|a| matches!(a, ArpAnomaly::DuplicateMac { .. }))
            .count();
        assert_eq!(dup_mac_count, 1);
    }

    #[test]
    fn test_duplicate_mac_few_ips_ok() {
        // Router legitimately has 2-3 IPs
        let entries = vec![
            entry("192.168.1.1", "aa:bb:cc:dd:ee:01"),
            entry("192.168.1.2", "aa:bb:cc:dd:ee:01"),
            entry("192.168.1.3", "aa:bb:cc:dd:ee:01"),
        ];
        let anomalies = detect_arp_anomalies(&entries, None);
        let dup_mac_count = anomalies
            .iter()
            .filter(|a| matches!(a, ArpAnomaly::DuplicateMac { .. }))
            .count();
        assert_eq!(dup_mac_count, 0);
    }

    #[test]
    fn test_broadcast_mac_detected() {
        let entries = vec![entry("192.168.1.50", "ff:ff:ff:ff:ff:ff")];
        let anomalies = detect_arp_anomalies(&entries, None);
        let broadcast_count = anomalies
            .iter()
            .filter(|a| matches!(a, ArpAnomaly::BroadcastMac { .. }))
            .count();
        assert_eq!(broadcast_count, 1);
    }

    #[test]
    fn test_zero_mac_detected() {
        let entries = vec![entry("192.168.1.50", "00:00:00:00:00:00")];
        let anomalies = detect_arp_anomalies(&entries, None);
        let incomplete_count = anomalies
            .iter()
            .filter(|a| matches!(a, ArpAnomaly::IncompleteMac { .. }))
            .count();
        assert_eq!(incomplete_count, 1);
    }

    #[test]
    fn test_empty_entries_no_anomalies() {
        let anomalies = detect_arp_anomalies(&[], None);
        assert!(anomalies.is_empty());
    }

    // ── Finding generation tests ────────────────────────────────────

    #[test]
    fn test_anomaly_to_finding_has_cwe() {
        let anomaly = ArpAnomaly::DuplicateIp {
            ip: "192.168.1.1".parse().unwrap(),
            macs: vec!["aa:bb:cc:dd:ee:01".to_owned(), "ff:ee:dd:cc:bb:aa".to_owned()],
            is_gateway: false,
        };
        let finding = anomaly_to_finding(&anomaly);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-290"));
        assert_eq!(finding.scanner, "arp");
    }

    // ── Proptests ───────────────────────────────────────────────────

    proptest! {
        #[test]
        fn prop_is_broadcast_mac_no_panic(mac in "[0-9a-fA-F:-]{0,20}") {
            let _ = is_broadcast_mac(&mac);
        }

        #[test]
        fn prop_is_multicast_mac_no_panic(mac in "[0-9a-fA-F:-]{0,20}") {
            let _ = is_multicast_mac(&mac);
        }

        #[test]
        fn prop_is_zero_mac_no_panic(mac in "[0-9a-fA-F:-]{0,20}") {
            let _ = is_zero_mac(&mac);
        }

        #[test]
        fn prop_detect_anomalies_no_panic(
            count in 0_usize..10,
            last_octet in proptest::collection::vec(1_u8..=254_u8, 0..10),
        ) {
            let entries: Vec<ArpEntryData> = last_octet.iter().take(count).map(|&o| {
                ArpEntryData {
                    ip: format!("192.168.1.{o}").parse().unwrap(),
                    mac: format!("aa:bb:cc:dd:ee:{o:02x}"),
                }
            }).collect();
            let _ = detect_arp_anomalies(&entries, None);
        }
    }
}
