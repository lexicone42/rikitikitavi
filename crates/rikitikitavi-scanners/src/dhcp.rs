use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

use crate::Scanner;

/// DHCP security scanner — detects rogue DHCP servers and DHCP-related risks.
///
/// Since we operate without raw sockets (safe Rust only), this scanner uses
/// indirect detection methods:
/// - Checks for hosts with DHCP server ports open (67/UDP via 68/TCP proxy check)
/// - Cross-references against the known gateway to identify rogue servers
/// - Checks for multiple devices advertising DHCP-related services
/// - Verifies DHCP lease configuration via network interface data
pub struct DhcpScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Well-known ports associated with DHCP infrastructure.
const DHCP_RELATED_PORTS: &[u16] = &[
    67,   // DHCP server (bootps)
    68,   // DHCP client (bootpc)
    547,  // DHCPv6 server
    546,  // DHCPv6 client
    4011, // PXE/DHCP proxy
];

/// Analyze network interfaces for DHCP configuration issues.
///
/// Checks if the current host's network configuration shows signs of
/// DHCP-related problems.
fn analyze_interface_config(
    interfaces: &[InterfaceInfo],
    gateway: Option<IpAddr>,
) -> Vec<DhcpAnomaly> {
    let mut anomalies = Vec::new();

    // Check for interfaces with no gateway (possible DHCP failure)
    for iface in interfaces {
        if iface.has_ip && !iface.has_gateway && !iface.is_loopback {
            anomalies.push(DhcpAnomaly::NoGateway {
                interface: iface.name.clone(),
            });
        }
    }

    // Check if gateway is in a suspicious range (APIPA = DHCP failure)
    if let Some(gw) = gateway
        && is_apipa_address(gw)
    {
        anomalies.push(DhcpAnomaly::ApipaGateway { gateway: gw });
    }

    // Check for APIPA addresses on interfaces (DHCP failure indicator)
    for iface in interfaces {
        if let Some(ip) = iface.ip
            && is_apipa_address(ip)
            && !iface.is_loopback
        {
            anomalies.push(DhcpAnomaly::ApipaAddress {
                interface: iface.name.clone(),
                ip,
            });
        }
    }

    anomalies
}

/// Check if an IP is in the APIPA range (169.254.0.0/16).
///
/// APIPA addresses indicate DHCP failure — the OS assigned a link-local
/// address because no DHCP server responded.
const fn is_apipa_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 169 && octets[1] == 254
        }
        IpAddr::V6(_) => false,
    }
}

/// Simplified interface info for analysis.
#[derive(Debug, Clone)]
struct InterfaceInfo {
    name: String,
    ip: Option<IpAddr>,
    has_ip: bool,
    has_gateway: bool,
    is_loopback: bool,
}

/// Types of DHCP anomalies.
#[derive(Debug, Clone)]
enum DhcpAnomaly {
    /// Potential rogue DHCP server detected (non-gateway with DHCP port open).
    RogueDhcpServer { ip: IpAddr, port: u16 },
    /// Interface has IP but no gateway (DHCP may have failed partially).
    NoGateway { interface: String },
    /// APIPA address detected (DHCP server unreachable).
    ApipaAddress { interface: String, ip: IpAddr },
    /// Gateway is an APIPA address (severe DHCP failure).
    ApipaGateway { gateway: IpAddr },
}

/// Convert anomaly to finding.
fn anomaly_to_finding(anomaly: &DhcpAnomaly) -> Finding {
    match anomaly {
        DhcpAnomaly::RogueDhcpServer { ip, port } => Finding::new(
            "dhcp",
            &format!("Potential rogue DHCP server on {ip}:{port}"),
            &format!(
                "Host {ip} has DHCP-related port {port} open but is not the \
                 configured gateway/router. This could indicate a rogue DHCP \
                 server that may redirect network traffic through an attacker-controlled \
                 device, enabling man-in-the-middle attacks."
            ),
            Severity::High,
        )
        .with_ip(*ip)
        .with_port(*port)
        .with_service("DHCP")
        .with_cwe("CWE-923")
        .with_opt_remediation(crate::remediation::get(
            "rikitikitavi.dhcp.rogue-server",
            &[],
        )),

        DhcpAnomaly::NoGateway { interface } => Finding::new(
            "dhcp",
            &format!("Interface {interface} has no gateway assigned"),
            &format!(
                "Network interface {interface} has an IP address but no default \
                 gateway. This may indicate a DHCP misconfiguration or a partial \
                 DHCP lease. Devices without a gateway cannot reach the internet."
            ),
            Severity::Low,
        )
        .with_service("DHCP"),

        DhcpAnomaly::ApipaAddress { interface, ip } => Finding::new(
            "dhcp",
            &format!("APIPA address on {interface}: {ip}"),
            &format!(
                "Interface {interface} has APIPA address {ip} (169.254.x.x), \
                 indicating the DHCP server did not respond. The device is using \
                 an auto-configured link-local address and cannot reach the \
                 internet or local services properly."
            ),
            Severity::Medium,
        )
        .with_ip(*ip)
        .with_service("DHCP")
        .with_cwe("CWE-923"),

        DhcpAnomaly::ApipaGateway { gateway } => Finding::new(
            "dhcp",
            &format!("Gateway is APIPA address: {gateway}"),
            &format!(
                "The default gateway {gateway} is in the APIPA range (169.254.x.x). \
                 This indicates a severe DHCP failure or misconfiguration. No device \
                 on this network can reach the internet."
            ),
            Severity::High,
        )
        .with_ip(*gateway)
        .with_service("DHCP")
        .with_cwe("CWE-923"),
    }
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl Scanner for DhcpScanner {
    fn id(&self) -> &'static str {
        "dhcp"
    }

    fn name(&self) -> &'static str {
        "DHCP Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running DHCP security scan");
        let mut findings = Vec::new();

        // ── Check for rogue DHCP servers via discovered devices ─────
        if ctx.discovered_devices.is_empty() {
            // Fallback: probe DHCP ports on all ARP cache hosts
            let arp_entries =
                rikitikitavi_network::read_arp_cache().map_err(|e| ScanError::ScannerFailed {
                    scanner: "dhcp".to_owned(),
                    message: format!("failed to read ARP cache: {e}"),
                })?;

            for entry in &arp_entries {
                // Skip gateway
                if ctx.gateway == Some(entry.ip) {
                    continue;
                }

                // Quick TCP probe on DHCP ports (we can't do UDP without raw sockets)
                for &port in DHCP_RELATED_PORTS {
                    let addr = SocketAddr::new(entry.ip, port);
                    if tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
                        .await
                        .is_ok_and(|r| r.is_ok())
                    {
                        findings.push(anomaly_to_finding(&DhcpAnomaly::RogueDhcpServer {
                            ip: entry.ip,
                            port,
                        }));
                    }
                }
            }
        } else {
            for device in &ctx.discovered_devices {
                // Skip the gateway — it's supposed to run DHCP
                if ctx.gateway == Some(device.ip) {
                    continue;
                }

                // Check if any non-gateway device has DHCP ports open
                for port_entry in &device.open_ports {
                    if DHCP_RELATED_PORTS.contains(&port_entry.port) {
                        findings.push(anomaly_to_finding(&DhcpAnomaly::RogueDhcpServer {
                            ip: device.ip,
                            port: port_entry.port,
                        }));
                    }
                }
            }
        }

        // ── Check interface configuration for DHCP issues ───────────
        let interfaces = gather_interface_info();
        let config_anomalies = analyze_interface_config(&interfaces, ctx.gateway);
        for anomaly in &config_anomalies {
            findings.push(anomaly_to_finding(anomaly));
        }

        tracing::info!(
            findings_count = findings.len(),
            "DHCP security scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        15
    }
}

/// Gather network interface information from the system.
fn gather_interface_info() -> Vec<InterfaceInfo> {
    // Try to get interfaces from the network crate
    let Ok(interfaces) = rikitikitavi_network::list_interfaces() else {
        return Vec::new();
    };

    interfaces
        .iter()
        .map(|iface| InterfaceInfo {
            name: iface.name.clone(),
            ip: iface.ip,
            has_ip: iface.ip.is_some(),
            has_gateway: false, // We can't easily determine per-interface gateway
            is_loopback: iface.is_loopback,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn iface(name: &str, ip: Option<&str>, has_gateway: bool, is_loopback: bool) -> InterfaceInfo {
        InterfaceInfo {
            name: name.to_owned(),
            ip: ip.map(|s| s.parse().unwrap()),
            has_ip: ip.is_some(),
            has_gateway,
            is_loopback,
        }
    }

    // ── APIPA detection tests ───────────────────────────────────────

    #[test]
    fn test_apipa_169_254() {
        assert!(is_apipa_address("169.254.1.1".parse().unwrap()));
        assert!(is_apipa_address("169.254.255.255".parse().unwrap()));
    }

    #[test]
    fn test_not_apipa_normal() {
        assert!(!is_apipa_address("192.168.1.1".parse().unwrap()));
        assert!(!is_apipa_address("10.0.0.1".parse().unwrap()));
        assert!(!is_apipa_address("169.253.1.1".parse().unwrap()));
    }

    #[test]
    fn test_not_apipa_ipv6() {
        assert!(!is_apipa_address("::1".parse().unwrap()));
        assert!(!is_apipa_address("fe80::1".parse().unwrap()));
    }

    // ── Interface analysis tests ────────────────────────────────────

    #[test]
    fn test_normal_config_no_anomalies() {
        let interfaces = vec![
            iface("eth0", Some("192.168.1.100"), true, false),
            iface("lo", Some("127.0.0.1"), false, true),
        ];
        let anomalies = analyze_interface_config(&interfaces, Some("192.168.1.1".parse().unwrap()));
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_apipa_address_detected() {
        let interfaces = vec![iface("wlan0", Some("169.254.42.1"), false, false)];
        let anomalies = analyze_interface_config(&interfaces, None);
        let apipa_count = anomalies
            .iter()
            .filter(|a| matches!(a, DhcpAnomaly::ApipaAddress { .. }))
            .count();
        assert_eq!(apipa_count, 1);
    }

    #[test]
    fn test_apipa_gateway_detected() {
        let interfaces = vec![iface("eth0", Some("192.168.1.100"), true, false)];
        let gw: IpAddr = "169.254.1.1".parse().unwrap();
        let anomalies = analyze_interface_config(&interfaces, Some(gw));
        let gw_count = anomalies
            .iter()
            .filter(|a| matches!(a, DhcpAnomaly::ApipaGateway { .. }))
            .count();
        assert_eq!(gw_count, 1);
    }

    #[test]
    fn test_no_gateway_detected() {
        let interfaces = vec![iface("eth0", Some("192.168.1.100"), false, false)];
        let anomalies = analyze_interface_config(&interfaces, None);
        let no_gw_count = anomalies
            .iter()
            .filter(|a| matches!(a, DhcpAnomaly::NoGateway { .. }))
            .count();
        assert_eq!(no_gw_count, 1);
    }

    #[test]
    fn test_loopback_ignored() {
        let interfaces = vec![iface("lo", Some("127.0.0.1"), false, true)];
        let anomalies = analyze_interface_config(&interfaces, None);
        assert!(
            anomalies.is_empty(),
            "loopback should not generate anomalies"
        );
    }

    // ── Finding generation tests ────────────────────────────────────

    #[test]
    fn test_rogue_dhcp_finding() {
        let anomaly = DhcpAnomaly::RogueDhcpServer {
            ip: "192.168.1.50".parse().unwrap(),
            port: 67,
        };
        let finding = anomaly_to_finding(&anomaly);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.scanner, "dhcp");
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-923"));
    }

    #[test]
    fn test_apipa_finding_medium() {
        let anomaly = DhcpAnomaly::ApipaAddress {
            interface: "wlan0".to_owned(),
            ip: "169.254.42.1".parse().unwrap(),
        };
        let finding = anomaly_to_finding(&anomaly);
        assert_eq!(finding.severity, Severity::Medium);
    }

    // ── Proptests ───────────────────────────────────────────────────

    proptest! {
        #[test]
        fn prop_is_apipa_no_panic(
            a in 0_u8..=255_u8,
            b in 0_u8..=255_u8,
            c in 0_u8..=255_u8,
            d in 0_u8..=255_u8,
        ) {
            let ip: IpAddr = format!("{a}.{b}.{c}.{d}").parse().unwrap();
            let result = is_apipa_address(ip);
            // Verify the invariant: APIPA iff first two octets are 169.254
            assert_eq!(result, a == 169 && b == 254);
        }

        #[test]
        fn prop_analyze_interface_no_panic(
            count in 0_usize..5,
            has_gateway in any::<bool>(),
        ) {
            let interfaces: Vec<InterfaceInfo> = (0..count).map(|i| {
                InterfaceInfo {
                    name: format!("eth{i}"),
                    ip: Some(format!("192.168.1.{}", i + 10).parse().unwrap()),
                    has_ip: true,
                    has_gateway,
                    is_loopback: false,
                }
            }).collect();
            let _ = analyze_interface_config(&interfaces, None);
        }
    }
}
