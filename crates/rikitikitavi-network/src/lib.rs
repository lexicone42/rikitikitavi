pub mod arp;
pub mod epss;
pub mod external;
pub mod interfaces;
pub mod mdns;
pub mod nbns;
pub mod rdns;
pub mod sweep;
pub mod wifi;
pub mod wifi_frames;
#[cfg(feature = "monitor")]
pub mod wifi_monitor;

pub use arp::{ArpEntry, read_arp_cache};
pub use epss::fetch_epss_scores;
pub use external::get_public_ip;
pub use interfaces::{NetworkInterface, detect_gateway, detect_network, list_interfaces};
pub use mdns::{
    DnsHeader, DnsPacket, DnsRecord, MdnsService, build_mdns_query, discover_services,
    parse_dns_header, parse_dns_name, parse_dns_packet, parse_resource_record,
};
pub use sweep::{MAX_SWEEP_HOSTS, tcp_sweep};
pub use wifi::{WifiEncryption, WifiNetwork, scan_wifi_networks};

/// Read at most `max_bytes` of a response body. A read error ends the body early.
pub(crate) async fn read_capped(mut resp: reqwest::Response, max_bytes: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    while buf.len() < max_bytes {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let take = chunk.len().min(max_bytes - buf.len());
                buf.extend_from_slice(&chunk[..take]);
            }
            Ok(None) | Err(_) => break,
        }
    }
    buf
}
