use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, Remediation, ScanContext};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

use crate::Scanner;

/// Network isolation scanner — detects flat networks, multiple subnets,
/// and potential inter-VLAN routing.
pub struct IsolationScanner;

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Common alternate gateway IPs to probe for inter-VLAN routing.
const ALTERNATE_GATEWAYS: &[Ipv4Addr] = &[
    Ipv4Addr::new(192, 168, 0, 1),
    Ipv4Addr::new(192, 168, 1, 1),
    Ipv4Addr::new(192, 168, 2, 1),
    Ipv4Addr::new(10, 0, 0, 1),
    Ipv4Addr::new(10, 0, 1, 1),
    Ipv4Addr::new(10, 1, 0, 1),
    Ipv4Addr::new(172, 16, 0, 1),
    Ipv4Addr::new(172, 16, 1, 1),
];

/// Extract the /24 subnet from an IP address.
const fn subnet_24(ip: &IpAddr) -> Option<[u8; 3]> {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some([octets[0], octets[1], octets[2]])
        }
        IpAddr::V6(_) => None,
    }
}

/// Check if an IP is reachable on a common gateway port (80 or 443).
async fn probe_gateway(ip: Ipv4Addr) -> bool {
    for &port in &[80, 443] {
        let addr = SocketAddr::new(IpAddr::V4(ip), port);
        if tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr))
            .await
            .is_ok_and(|r| r.is_ok())
        {
            return true;
        }
    }
    false
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl Scanner for IsolationScanner {
    fn id(&self) -> &'static str {
        "isolation"
    }

    fn name(&self) -> &'static str {
        "Network Isolation"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[Perspective::Authenticated, Perspective::Privileged]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running network isolation scan");
        let mut findings = Vec::new();

        let arp_entries = rikitikitavi_network::read_arp_cache().map_err(|e| {
            ScanError::ScannerFailed {
                scanner: "isolation".to_owned(),
                message: format!("failed to read ARP cache: {e}"),
            }
        })?;

        // Detect unique /24 subnets in ARP cache
        let subnets: HashSet<[u8; 3]> = arp_entries
            .iter()
            .filter_map(|e| subnet_24(&e.ip))
            .collect();

        tracing::info!(subnet_count = subnets.len(), "unique /24 subnets detected");

        if subnets.len() > 1 {
            let subnet_list: Vec<String> = subnets
                .iter()
                .map(|s| format!("{}.{}.{}.0/24", s[0], s[1], s[2]))
                .collect();

            findings.push(Finding::new(
                "isolation",
                &format!("Multiple subnets detected ({})", subnets.len()),
                &format!(
                    "ARP cache contains devices from {} different /24 subnets: {}. \
                     Multiple subnets visible from a single host may indicate a flat \
                     network without proper VLAN segmentation, or that inter-VLAN \
                     routing is enabled without restrictions.",
                    subnets.len(),
                    subnet_list.join(", ")
                ),
                Severity::Low,
            ).with_cwe("CWE-653"));
        } else if subnets.len() == 1 {
            findings.push(Finding::new(
                "isolation",
                "All devices on a single /24 subnet",
                "All ARP cache entries are on the same /24 subnet. This is typical \
                 for simple home networks but means there is no VLAN segmentation.",
                Severity::Info,
            ));
        }

        // Probe alternate gateways for inter-VLAN routing
        let current_gateway = ctx.gateway.and_then(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        });

        let mut reachable_gateways = Vec::new();
        for &gw in ALTERNATE_GATEWAYS {
            // Skip our own gateway
            if current_gateway == Some(gw) {
                continue;
            }

            if probe_gateway(gw).await {
                reachable_gateways.push(gw);
            }
        }

        if !reachable_gateways.is_empty() {
            let gw_list: Vec<String> = reachable_gateways.iter().map(ToString::to_string).collect();
            findings.push(
                Finding::new(
                    "isolation",
                    &format!(
                        "{} alternate gateway(s) reachable",
                        reachable_gateways.len()
                    ),
                    &format!(
                        "The following gateway IPs on other subnets are reachable from this \
                         host: {}. This indicates inter-VLAN routing is enabled, which means \
                         devices on different network segments can communicate. Consider \
                         implementing firewall rules between VLANs to restrict traffic.",
                        gw_list.join(", ")
                    ),
                    Severity::Medium,
                )
                .with_cwe("CWE-653")
                .with_remediation(Remediation {
                    description: "Implement firewall rules between VLANs.".to_owned(),
                    steps: vec![
                        "Review your router/firewall's inter-VLAN routing rules.".to_owned(),
                        "Create ACLs to restrict traffic between network segments.".to_owned(),
                        "Only allow necessary traffic (e.g. DNS, DHCP) between VLANs.".to_owned(),
                    ],
                    effort: Some("30 minutes".to_owned()),
                }),
            );
        }

        // Large flat network warning
        if arp_entries.len() > 50 && subnets.len() <= 1 {
            findings.push(
                Finding::new(
                    "isolation",
                    "Large flat network — consider segmentation",
                    &format!(
                        "{} devices share a single network segment. Networks with many \
                         devices benefit from VLAN segmentation to isolate IoT devices, \
                         guest access, and servers from personal devices.",
                        arp_entries.len()
                    ),
                    Severity::Medium,
                )
                .with_cwe("CWE-653")
                .with_remediation(Remediation {
                    description: "Segment the network using VLANs.".to_owned(),
                    steps: vec![
                        "Create separate VLANs for IoT devices, guests, and trusted devices.".to_owned(),
                        "Configure your managed switch and router to support VLANs (802.1Q).".to_owned(),
                        "Apply firewall rules between VLANs to limit lateral movement.".to_owned(),
                    ],
                    effort: Some("1 hour".to_owned()),
                }),
            );
        }

        tracing::info!(findings_count = findings.len(), "isolation scan complete");
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        20
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_24_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(subnet_24(&ip), Some([192, 168, 1]));
    }

    #[test]
    fn test_subnet_24_different() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50));
        assert_ne!(subnet_24(&ip1), subnet_24(&ip2));
    }

    #[test]
    fn test_subnet_24_same() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        assert_eq!(subnet_24(&ip1), subnet_24(&ip2));
    }

    #[test]
    fn test_subnet_detection_from_entries() {
        let ips: Vec<IpAddr> = vec![
            "192.168.1.1".parse().unwrap(),
            "192.168.1.100".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.50".parse().unwrap(),
        ];
        let subnets: HashSet<[u8; 3]> = ips.iter().filter_map(subnet_24).collect();
        assert_eq!(subnets.len(), 2); // Two distinct /24s
    }
}
