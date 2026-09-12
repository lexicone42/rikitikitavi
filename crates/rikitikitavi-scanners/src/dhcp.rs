use async_trait::async_trait;
use ipnetwork::IpNetwork;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use rikitikitavi_network::NetworkInterface;
use std::net::IpAddr;

use crate::Scanner;

/// DHCP scanner: APIPA addresses and interfaces without a gateway. Sends no DHCP traffic.
pub struct DhcpScanner;

/// Flag interfaces without a gateway and APIPA addresses.
fn analyze_interface_config(
    interfaces: &[InterfaceInfo],
    gateway: Option<IpAddr>,
) -> Vec<DhcpAnomaly> {
    let mut anomalies = Vec::new();

    for iface in interfaces {
        if iface.has_ip && !iface.has_gateway && !iface.is_loopback {
            anomalies.push(DhcpAnomaly::NoGateway {
                interface: iface.name.clone(),
            });
        }
    }

    if let Some(gw) = gateway
        && is_apipa_address(gw)
    {
        anomalies.push(DhcpAnomaly::ApipaGateway { gateway: gw });
    }

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

/// True for 169.254.0.0/16 (APIPA, self-assigned when DHCP fails).
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

    #[allow(clippy::unused_async)]
    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running DHCP security scan");

        let interfaces = gather_interface_info(ctx.gateway);
        let findings: Vec<Finding> = analyze_interface_config(&interfaces, ctx.gateway)
            .iter()
            .map(anomaly_to_finding)
            .collect();

        tracing::info!(
            findings_count = findings.len(),
            "DHCP security scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        1
    }
}

/// True when `iface` carries the default route or `gateway` lies within its subnet.
fn carries_gateway(
    iface: &NetworkInterface,
    default_iface: Option<&str>,
    gateway: Option<IpAddr>,
) -> bool {
    if default_iface == Some(iface.name.as_str()) {
        return true;
    }
    let (Some(ip), Some(mask), Some(gw)) = (iface.ip, iface.netmask, gateway) else {
        return false;
    };
    IpNetwork::with_netmask(ip, mask).is_ok_and(|net| net.contains(gw))
}

/// Build analysis records from system interfaces.
fn interface_info(
    interfaces: &[NetworkInterface],
    default_iface: Option<&str>,
    gateway: Option<IpAddr>,
) -> Vec<InterfaceInfo> {
    interfaces
        .iter()
        .map(|iface| InterfaceInfo {
            name: iface.name.clone(),
            ip: iface.ip,
            has_ip: iface.ip.is_some(),
            has_gateway: carries_gateway(iface, default_iface, gateway),
            is_loopback: iface.is_loopback,
        })
        .collect()
}

/// Gather network interface information from the system.
fn gather_interface_info(gateway: Option<IpAddr>) -> Vec<InterfaceInfo> {
    let Ok(interfaces) = rikitikitavi_network::list_interfaces() else {
        return Vec::new();
    };
    let default_iface = rikitikitavi_network::interfaces::detect_default_interface()
        .ok()
        .flatten();
    interface_info(&interfaces, default_iface.as_deref(), gateway)
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

    fn sys_iface(name: &str, ip: Option<&str>, netmask: Option<&str>) -> NetworkInterface {
        NetworkInterface {
            name: name.to_owned(),
            ip: ip.map(|s| s.parse().unwrap()),
            netmask: netmask.map(|s| s.parse().unwrap()),
            mac: None,
            is_up: true,
            is_loopback: false,
        }
    }

    fn no_gateway_count(anomalies: &[DhcpAnomaly]) -> usize {
        anomalies
            .iter()
            .filter(|a| matches!(a, DhcpAnomaly::NoGateway { .. }))
            .count()
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
        assert_eq!(no_gateway_count(&anomalies), 1);
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

    // ── Gateway derivation tests ────────────────────────────────────

    #[test]
    fn test_default_route_interface_has_gateway() {
        let sys = vec![sys_iface("eth0", Some("192.168.1.100"), None)];
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        let info = interface_info(&sys, Some("eth0"), Some(gw));
        assert!(info[0].has_gateway);
        assert_eq!(
            no_gateway_count(&analyze_interface_config(&info, Some(gw))),
            0
        );
    }

    #[test]
    fn test_on_link_gateway_without_default_interface() {
        let sys = vec![sys_iface(
            "en0",
            Some("192.168.1.100"),
            Some("255.255.255.0"),
        )];
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        let info = interface_info(&sys, None, Some(gw));
        assert!(info[0].has_gateway);
    }

    #[test]
    fn test_off_link_non_default_interface_flagged() {
        let sys = vec![
            sys_iface("eth0", Some("192.168.1.100"), Some("255.255.255.0")),
            sys_iface("docker0", Some("172.17.0.1"), Some("255.255.0.0")),
        ];
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        let info = interface_info(&sys, Some("eth0"), Some(gw));
        assert!(info[0].has_gateway);
        assert!(!info[1].has_gateway);
        let anomalies = analyze_interface_config(&info, Some(gw));
        assert_eq!(no_gateway_count(&anomalies), 1);
        assert!(matches!(
            &anomalies[0],
            DhcpAnomaly::NoGateway { interface } if interface == "docker0"
        ));
    }

    #[test]
    fn test_unknown_gateway_and_default_interface() {
        let sys = vec![sys_iface(
            "eth0",
            Some("192.168.1.100"),
            Some("255.255.255.0"),
        )];
        let info = interface_info(&sys, None, None);
        assert!(!info[0].has_gateway);
        assert_eq!(no_gateway_count(&analyze_interface_config(&info, None)), 1);
    }

    #[test]
    fn test_interface_without_ip_not_flagged() {
        let sys = vec![sys_iface("eth1", None, None)];
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        let info = interface_info(&sys, Some("eth0"), Some(gw));
        assert!(!info[0].has_gateway);
        assert!(analyze_interface_config(&info, Some(gw)).is_empty());
    }

    // ── Finding generation tests ────────────────────────────────────

    #[test]
    fn test_apipa_finding_medium() {
        let anomaly = DhcpAnomaly::ApipaAddress {
            interface: "wlan0".to_owned(),
            ip: "169.254.42.1".parse().unwrap(),
        };
        let finding = anomaly_to_finding(&anomaly);
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.scanner, "dhcp");
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-923"));
    }

    #[test]
    fn test_no_gateway_finding_low() {
        let anomaly = DhcpAnomaly::NoGateway {
            interface: "eth0".to_owned(),
        };
        let finding = anomaly_to_finding(&anomaly);
        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.title.contains("eth0"));
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
