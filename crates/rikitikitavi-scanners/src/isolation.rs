use async_trait::async_trait;
use ipnetwork::IpNetwork;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

use crate::Scanner;

/// Network isolation scanner: ARP-cache devices outside the target network and
/// reachability of common alternate gateway IPs.
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

/// Network devices are judged against: `target`, else the /24 of an IPv4 `gateway`.
fn home_network(target: Option<IpNetwork>, gateway: Option<IpAddr>) -> Option<IpNetwork> {
    let raw = target.or_else(|| match gateway {
        Some(gw @ IpAddr::V4(_)) => IpNetwork::new(gw, 24).ok(),
        _ => None,
    })?;
    IpNetwork::new(raw.network(), raw.prefix()).ok()
}

/// /24 groups of IPv4 entries outside `home`.
fn foreign_subnets<'a>(
    ips: impl IntoIterator<Item = &'a IpAddr>,
    home: &IpNetwork,
) -> BTreeSet<[u8; 3]> {
    ips.into_iter()
        .filter(|ip| !home.contains(**ip))
        .filter_map(subnet_24)
        .collect()
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

        let arp_entries =
            rikitikitavi_network::read_arp_cache().map_err(|e| ScanError::ScannerFailed {
                scanner: "isolation".to_owned(),
                message: format!("failed to read ARP cache: {e}"),
            })?;

        let mut single_segment = false;
        if let Some(home) = home_network(ctx.target_network, ctx.gateway) {
            let foreign = foreign_subnets(arp_entries.iter().map(|e| &e.ip), &home);
            tracing::info!(%home, foreign_count = foreign.len(), "subnet analysis");
            single_segment = foreign.is_empty();

            if !foreign.is_empty() {
                let subnet_list: Vec<String> = foreign
                    .iter()
                    .map(|s| format!("{}.{}.{}.0/24", s[0], s[1], s[2]))
                    .collect();

                findings.push(
                    Finding::new(
                        "isolation",
                        &format!(
                            "Devices outside {home} detected ({} other subnet(s))",
                            foreign.len()
                        ),
                        &format!(
                            "ARP cache contains devices outside the target network {home}, \
                             from {} other /24 subnet(s): {}. Multiple subnets visible from \
                             a single host may indicate a flat network without proper VLAN \
                             segmentation, or that inter-VLAN routing is enabled without \
                             restrictions.",
                            foreign.len(),
                            subnet_list.join(", ")
                        ),
                        Severity::Low,
                    )
                    .with_cwe("CWE-653"),
                );
            } else if !arp_entries.is_empty() {
                findings.push(Finding::new(
                    "isolation",
                    &format!("All devices within {home}"),
                    &format!(
                        "All ARP cache entries are within {home}. This is typical for \
                         simple home networks but means there is no VLAN segmentation."
                    ),
                    Severity::Info,
                ));
            }
        } else {
            tracing::warn!("no target network or IPv4 gateway; skipping subnet analysis");
        }

        let current_gateway = ctx.gateway.and_then(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        });

        let mut reachable_gateways = Vec::new();
        for &gw in ALTERNATE_GATEWAYS {
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
                .with_opt_remediation(crate::remediation::get(
                    "rikitikitavi.isolation.inter-vlan-routing",
                    &[],
                )),
            );
        }

        if arp_entries.len() > 50 && single_segment {
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
                .with_opt_remediation(crate::remediation::get(
                    "rikitikitavi.isolation.large-flat-network",
                    &[],
                )),
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

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn net(cidr: &str) -> IpNetwork {
        cidr.parse().unwrap()
    }

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
    fn test_slash22_hosts_are_all_local() {
        let home = net("192.168.0.0/22");
        let entries = ips(&[
            "192.168.0.1",
            "192.168.1.50",
            "192.168.2.200",
            "192.168.3.254",
        ]);
        assert!(foreign_subnets(&entries, &home).is_empty());
    }

    #[test]
    fn test_slash22_outside_hosts_grouped_by_24() {
        let home = net("192.168.0.0/22");
        let entries = ips(&[
            "192.168.1.50",
            "192.168.3.254",
            "192.168.4.1",
            "10.0.0.5",
            "10.0.0.9",
        ]);
        let foreign = foreign_subnets(&entries, &home);
        assert_eq!(foreign.len(), 2);
        assert!(foreign.contains(&[192, 168, 4]));
        assert!(foreign.contains(&[10, 0, 0]));
    }

    #[test]
    fn test_slash24_neighbor_is_foreign() {
        let home = net("192.168.1.0/24");
        let entries = ips(&["192.168.1.10", "192.168.2.1"]);
        let foreign = foreign_subnets(&entries, &home);
        assert_eq!(foreign.len(), 1);
        assert!(foreign.contains(&[192, 168, 2]));
    }

    #[test]
    fn test_ipv6_entries_ignored() {
        let home = net("192.168.1.0/24");
        let entries = ips(&["192.168.1.10", "fe80::1"]);
        assert!(foreign_subnets(&entries, &home).is_empty());
    }

    #[test]
    fn test_home_network_prefers_target() {
        let home = home_network(
            Some(net("10.0.0.0/16")),
            Some("192.168.1.1".parse().unwrap()),
        );
        assert_eq!(home, Some(net("10.0.0.0/16")));
    }

    #[test]
    fn test_home_network_falls_back_to_gateway_slash24() {
        let home = home_network(None, Some("192.168.1.1".parse().unwrap())).unwrap();
        assert_eq!(home, net("192.168.1.0/24"));
        assert!(home.contains("192.168.1.77".parse().unwrap()));
        assert!(!home.contains("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn test_home_network_normalizes_host_bits() {
        let home = home_network(Some(net("192.168.1.37/22")), None).unwrap();
        assert_eq!(home.to_string(), "192.168.0.0/22");
    }

    #[test]
    fn test_home_network_none_without_target_or_v4_gateway() {
        assert!(home_network(None, None).is_none());
        assert!(home_network(None, Some("fe80::1".parse().unwrap())).is_none());
    }
}
