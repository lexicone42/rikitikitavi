//! Host discovery via bounded TCP-connect probing (no root required).
//! Complements the ARP cache, which only lists hosts recently talked to.
//!
//! Callers filter exclusions out of the target list before probing; a MAC exclusion
//! can only be mapped to an IP for hosts already in the ARP cache.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ipnetwork::IpNetwork;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// Liveness probe ports; a connect that succeeds or is refused marks the host alive.
const PROBE_PORTS: &[u16] = &[80, 443, 22, 445, 8080, 53];

/// Maximum host addresses probed per sweep.
pub const MAX_SWEEP_HOSTS: usize = 4096;

/// Usable IPv4 host addresses of `network` (network/broadcast excluded except for
/// /31 and /32), capped at [`MAX_SWEEP_HOSTS`]. IPv6 networks return empty.
#[must_use]
pub fn sweep_targets(network: &IpNetwork) -> Vec<IpAddr> {
    let IpNetwork::V4(v4) = network else {
        return Vec::new();
    };

    let net_addr = IpAddr::V4(v4.network());
    let bcast_addr = IpAddr::V4(v4.broadcast());

    v4.iter()
        .map(IpAddr::V4)
        .filter(|ip| v4.prefix() >= 31 || (*ip != net_addr && *ip != bcast_addr))
        .take(MAX_SWEEP_HOSTS)
        .collect()
}

/// Probe a single host: alive if any probe port connects or is refused.
async fn host_alive(ip: IpAddr, timeout: Duration) -> bool {
    for &port in PROBE_PORTS {
        let addr = SocketAddr::new(ip, port);
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => return true,
            // Refused: host reachable, port closed.
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => return true,
            _ => {}
        }
    }
    false
}

/// Live hosts in `network`, sorted. `timeout` bounds each connect; `concurrency`
/// caps parallel hosts. Addresses beyond [`MAX_SWEEP_HOSTS`] are silently not probed.
pub async fn tcp_sweep(network: &IpNetwork, timeout: Duration, concurrency: usize) -> Vec<IpAddr> {
    tcp_sweep_hosts(sweep_targets(network), timeout, concurrency).await
}

/// Live hosts among `targets`, sorted. Only listed addresses are probed.
pub async fn tcp_sweep_hosts(
    targets: Vec<IpAddr>,
    timeout: Duration,
    concurrency: usize,
) -> Vec<IpAddr> {
    if targets.is_empty() {
        return Vec::new();
    }

    tracing::debug!(
        host_count = targets.len(),
        "starting TCP-connect host sweep"
    );

    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(targets.len());

    for ip in targets {
        let sem = Arc::clone(&semaphore);
        handles.push(tokio::spawn(async move {
            // Closed semaphore: host not probed.
            let _permit = sem.acquire_owned().await.ok()?;
            if host_alive(ip, timeout).await {
                Some(ip)
            } else {
                None
            }
        }));
    }

    let mut alive = Vec::new();
    for handle in handles {
        if let Ok(Some(ip)) = handle.await {
            alive.push(ip);
        }
    }
    alive.sort_unstable();
    alive
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_targets_excludes_network_and_broadcast() {
        let net: IpNetwork = "192.168.1.0/24".parse().unwrap();
        let targets = sweep_targets(&net);
        // /24 has 256 addresses; usable hosts = 254 (minus .0 network and .255 broadcast).
        assert_eq!(targets.len(), 254);
        assert!(!targets.contains(&"192.168.1.0".parse().unwrap()));
        assert!(!targets.contains(&"192.168.1.255".parse().unwrap()));
        assert!(targets.contains(&"192.168.1.1".parse().unwrap()));
        assert!(targets.contains(&"192.168.1.254".parse().unwrap()));
    }

    #[test]
    fn sweep_targets_caps_large_ranges() {
        // A /8 has 16M addresses; the sweep must cap at MAX_SWEEP_HOSTS.
        let net: IpNetwork = "10.0.0.0/8".parse().unwrap();
        assert_eq!(sweep_targets(&net).len(), MAX_SWEEP_HOSTS);
    }

    #[test]
    fn sweep_targets_ipv6_is_empty() {
        let net: IpNetwork = "fd00::/64".parse().unwrap();
        assert!(sweep_targets(&net).is_empty());
    }

    #[test]
    fn sweep_targets_slash31_keeps_both() {
        // A /31 (RFC 3021 point-to-point) has no network/broadcast to exclude.
        let net: IpNetwork = "192.168.1.0/31".parse().unwrap();
        assert_eq!(sweep_targets(&net).len(), 2);
    }

    #[tokio::test]
    async fn host_alive_detects_loopback_via_refused() {
        // Loopback refuses connections to closed ports immediately (rather than
        // dropping them), so a probe should classify 127.0.0.1 as alive even with
        // nothing listening. This exercises the real connect/refused code path.
        let alive = host_alive("127.0.0.1".parse().unwrap(), Duration::from_millis(500)).await;
        assert!(alive, "loopback should be detected as alive");
    }

    #[tokio::test]
    async fn tcp_sweep_hosts_probes_only_listed_targets() {
        assert!(
            tcp_sweep_hosts(Vec::new(), Duration::from_millis(200), 4)
                .await
                .is_empty()
        );
        // Loopback is alive via refused connects; an unlisted address can never appear.
        let alive = tcp_sweep_hosts(
            vec!["127.0.0.1".parse().unwrap()],
            Duration::from_millis(500),
            4,
        )
        .await;
        assert_eq!(alive, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn host_alive_times_out_on_unroutable() {
        // TEST-NET-1 (192.0.2.0/24, RFC 5737) is reserved and unroutable, so
        // probes should time out and the host should be classified not-alive.
        let alive = host_alive("192.0.2.1".parse().unwrap(), Duration::from_millis(200)).await;
        assert!(
            !alive,
            "unroutable documentation address should not be alive"
        );
    }

    use std::net::Ipv4Addr;

    use ipnetwork::Ipv4Network;
    use proptest::prelude::*;

    proptest! {
        /// Targets are capped, strictly ascending, inside the network; endpoints absent for /0–/30, present for /31–/32.
        #[test]
        fn prop_sweep_targets_invariants(addr in any::<u32>(), prefix in 0_u8..=32) {
            let v4 = Ipv4Network::new(Ipv4Addr::from(addr), prefix).unwrap();
            let net = IpNetwork::V4(v4);
            let targets = sweep_targets(&net);

            prop_assert!(targets.len() <= MAX_SWEEP_HOSTS);
            prop_assert!(targets.windows(2).all(|w| w[0] < w[1]));
            prop_assert!(targets.iter().all(|ip| net.contains(*ip)));

            let net_addr = IpAddr::V4(v4.network());
            let bcast_addr = IpAddr::V4(v4.broadcast());
            let hosts = 1_u64 << (32 - u32::from(prefix));
            let cap = u64::try_from(MAX_SWEEP_HOSTS).unwrap();
            let got = u64::try_from(targets.len()).unwrap();
            if prefix <= 30 {
                prop_assert!(!targets.contains(&net_addr));
                prop_assert!(!targets.contains(&bcast_addr));
                prop_assert_eq!(got, (hosts - 2).min(cap));
            } else {
                prop_assert!(targets.contains(&net_addr));
                prop_assert!(targets.contains(&bcast_addr));
                prop_assert_eq!(got, hosts);
            }
        }
    }
}
