//! Active host discovery via bounded TCP-connect probing.
//!
//! Reading the OS ARP cache (see [`crate::read_arp_cache`]) only finds hosts the
//! machine has recently exchanged traffic with. On a freshly booted machine that
//! table is nearly empty, so a scan can report ~0 devices and look "clean" when it
//! simply has not looked. A TCP-connect sweep actively probes the range and is
//! **unprivileged** — unlike raw ARP/ICMP sweeps it needs no root.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ipnetwork::IpNetwork;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// Ports probed to decide whether a host is alive. A host counts as alive if a
/// connect to any of these either succeeds (port open) or is actively refused
/// (host reachable, port closed). The set favours ports common on home/SOHO
/// devices — routers, NAS, cameras, printers, PCs.
const PROBE_PORTS: &[u16] = &[80, 443, 22, 445, 8080, 53];

/// Upper bound on how many host addresses a single sweep will probe.
///
/// Guards against enormous ranges (a /16 is 65k hosts) turning a scan into an
/// hours-long operation. A `/22` (1022 usable hosts) fits comfortably under this.
pub const MAX_SWEEP_HOSTS: usize = 4096;

/// Enumerate the usable host addresses of an IPv4 network, excluding the network
/// and broadcast addresses. Returns at most [`MAX_SWEEP_HOSTS`] addresses.
///
/// IPv6 ranges are not swept (a /64 has 2^64 hosts); returns empty for them.
/// IPv6 discovery is tracked separately via the neighbor cache.
#[must_use]
pub fn sweep_targets(network: &IpNetwork) -> Vec<IpAddr> {
    let IpNetwork::V4(v4) = network else {
        return Vec::new();
    };

    let net_addr = IpAddr::V4(v4.network());
    let bcast_addr = IpAddr::V4(v4.broadcast());

    v4.iter()
        .map(IpAddr::V4)
        // Exclude the network and broadcast addresses (not real hosts). For a
        // /31 or /32 there is no broadcast/network to exclude and both usable
        // addresses are kept.
        .filter(|ip| v4.prefix() >= 31 || (*ip != net_addr && *ip != bcast_addr))
        .take(MAX_SWEEP_HOSTS)
        .collect()
}

/// Probe a single host: alive if any probe port connects or is refused.
async fn host_alive(ip: IpAddr, timeout: Duration) -> bool {
    for &port in PROBE_PORTS {
        let addr = SocketAddr::new(ip, port);
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            // Connected — port is open, host is definitely alive.
            Ok(Ok(_stream)) => return true,
            // Actively refused — nothing listening, but the host is reachable.
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => return true,
            // Timeout, unreachable, or other error — try the next port.
            _ => {}
        }
    }
    false
}

/// Actively discover live hosts in `network` via bounded concurrent TCP probes.
///
/// `timeout` bounds each individual connect attempt; `concurrency` caps how many
/// hosts are probed at once. Returns the sorted list of responding host IPs.
/// Returns empty for IPv6 networks or ranges larger than [`MAX_SWEEP_HOSTS`]
/// worth of probing (the excess is silently not probed — callers that care
/// should check the network size first).
pub async fn tcp_sweep(network: &IpNetwork, timeout: Duration, concurrency: usize) -> Vec<IpAddr> {
    let targets = sweep_targets(network);
    if targets.is_empty() {
        return Vec::new();
    }

    tracing::debug!(
        %network,
        host_count = targets.len(),
        "starting TCP-connect host sweep"
    );

    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(targets.len());

    for ip in targets {
        let sem = Arc::clone(&semaphore);
        handles.push(tokio::spawn(async move {
            // If the semaphore is somehow closed, treat the host as not probed.
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
    async fn host_alive_times_out_on_unroutable() {
        // TEST-NET-1 (192.0.2.0/24, RFC 5737) is reserved and unroutable, so
        // probes should time out and the host should be classified not-alive.
        let alive = host_alive("192.0.2.1".parse().unwrap(), Duration::from_millis(200)).await;
        assert!(
            !alive,
            "unroutable documentation address should not be alive"
        );
    }
}
