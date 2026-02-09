use anyhow::Result;
use std::net::IpAddr;

/// Result of an ARP scan for a single host.
#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: IpAddr,
    pub mac: String,
}

/// Perform an ARP scan of the given network range.
pub async fn arp_scan(network: &ipnetwork::IpNetwork) -> Result<Vec<ArpEntry>> {
    // TODO: Implement using raw sockets or pnet
    tracing::debug!(%network, "performing ARP scan");
    Ok(Vec::new())
}

/// Read the system ARP cache.
pub fn read_arp_cache() -> Result<Vec<ArpEntry>> {
    // TODO: Parse /proc/net/arp on Linux, arp -a on other platforms
    tracing::debug!("reading ARP cache");
    Ok(Vec::new())
}
