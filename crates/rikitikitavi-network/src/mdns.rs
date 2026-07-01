//! mDNS service discovery with proper DNS packet parsing.
//!
//! Hand-rolled DNS parser covering the record types needed for mDNS service
//! discovery: A, AAAA, PTR, SRV, TXT. Follows the same pattern as
//! [`wifi_frames`](crate::wifi_frames) — pure `&[u8]` → structured types,
//! bounds-checked, no unsafe, proptest-fuzzed.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

// ── DNS constants ──────────────────────────────────────────────────────

/// DNS record type: A (IPv4 address).
const TYPE_A: u16 = 1;
/// DNS record type: PTR (domain name pointer).
const TYPE_PTR: u16 = 12;
/// DNS record type: TXT (text strings).
const TYPE_TXT: u16 = 16;
/// DNS record type: AAAA (IPv6 address).
const TYPE_AAAA: u16 = 28;
/// DNS record type: SRV (service locator).
const TYPE_SRV: u16 = 33;

/// DNS class: Internet.
const CLASS_IN: u16 = 1;
/// Bit set in mDNS to indicate cache-flush.
const MDNS_CACHE_FLUSH: u16 = 0x8000;

/// mDNS multicast address.
const MDNS_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// mDNS port.
const MDNS_PORT: u16 = 5353;

/// Maximum pointer-hop depth for DNS name decompression (cycle protection).
const MAX_NAME_HOPS: usize = 32;

/// DNS header length in bytes.
const DNS_HEADER_LEN: usize = 12;

// ── Public types ───────────────────────────────────────────────────────

/// An mDNS/Bonjour service discovered on the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsService {
    pub name: String,
    pub service_type: String,
    pub hostname: String,
    pub ip: IpAddr,
    pub port: u16,
    pub txt_records: Vec<String>,
}

/// Parsed DNS packet header (12 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answers: u16,
    pub authority: u16,
    pub additional: u16,
}

impl DnsHeader {
    /// Whether this is a response (QR bit set).
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
}

/// A parsed DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecord {
    A {
        name: String,
        ip: Ipv4Addr,
    },
    Aaaa {
        name: String,
        ip: Ipv6Addr,
    },
    Ptr {
        name: String,
        target: String,
    },
    Srv {
        name: String,
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Txt {
        name: String,
        entries: Vec<String>,
    },
}

impl DnsRecord {
    /// The owner name of this record.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::A { name, .. }
            | Self::Aaaa { name, .. }
            | Self::Ptr { name, .. }
            | Self::Srv { name, .. }
            | Self::Txt { name, .. } => name,
        }
    }
}

/// A parsed DNS packet containing header and resource records.
#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub records: Vec<DnsRecord>,
}

// ── DNS name parsing ───────────────────────────────────────────────────

/// Parse a DNS name starting at `offset` in the packet `data`.
///
/// Returns `(name, bytes_consumed)` where `bytes_consumed` is how far past
/// `offset` the caller should advance (compression pointers are only 2 bytes
/// regardless of the pointed-to name length).
///
/// Handles both label sequences and compression pointers (0xC0 prefix).
/// Uses a depth limit to prevent infinite loops from malicious packets.
pub fn parse_dns_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut parts: Vec<String> = Vec::new();
    let mut pos = offset;
    let mut hops = 0;
    // Track how many bytes the name occupies at the *original* position.
    // Once we follow a pointer, `consumed` is frozen (pointer is 2 bytes).
    let mut consumed: Option<usize> = None;

    loop {
        if pos >= data.len() || hops > MAX_NAME_HOPS {
            return None;
        }

        let len_byte = data[pos];

        // Compression pointer: top two bits are 11
        if len_byte & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            // Freeze consumed at the first pointer we encounter
            if consumed.is_none() {
                consumed = Some(pos - offset + 2);
            }
            let ptr = u16::from_be_bytes([len_byte & 0x3F, data[pos + 1]]) as usize;
            if ptr >= data.len() {
                return None;
            }
            pos = ptr;
            hops += 1;
            continue;
        }

        // Zero-length label = root, name is complete
        if len_byte == 0 {
            let consumed = consumed.unwrap_or_else(|| pos - offset + 1);
            let name = parts.join(".");
            return Some((name, consumed));
        }

        let label_len = len_byte as usize;
        let label_start = pos + 1;
        let label_end = label_start + label_len;
        if label_end > data.len() {
            return None;
        }

        // Labels should be ASCII, but be lenient with lossy conversion
        let label = String::from_utf8_lossy(&data[label_start..label_end]).into_owned();
        parts.push(label);
        pos = label_end;
    }
}

// ── DNS header parsing ─────────────────────────────────────────────────

/// Parse a 12-byte DNS header from the start of `data`.
pub fn parse_dns_header(data: &[u8]) -> Option<DnsHeader> {
    if data.len() < DNS_HEADER_LEN {
        return None;
    }
    Some(DnsHeader {
        id: u16::from_be_bytes([data[0], data[1]]),
        flags: u16::from_be_bytes([data[2], data[3]]),
        questions: u16::from_be_bytes([data[4], data[5]]),
        answers: u16::from_be_bytes([data[6], data[7]]),
        authority: u16::from_be_bytes([data[8], data[9]]),
        additional: u16::from_be_bytes([data[10], data[11]]),
    })
}

// ── Resource record parsing ────────────────────────────────────────────

/// Parse a single DNS resource record at `offset`.
///
/// Returns `(record, bytes_consumed)` so the caller can advance past it.
pub fn parse_resource_record(data: &[u8], offset: usize) -> Option<(DnsRecord, usize)> {
    let (name, name_consumed) = parse_dns_name(data, offset)?;
    let rr_start = offset + name_consumed;

    // Need at least: type(2) + class(2) + TTL(4) + rdlength(2) = 10 bytes
    if rr_start + 10 > data.len() {
        return None;
    }

    let rtype = u16::from_be_bytes([data[rr_start], data[rr_start + 1]]);
    let rclass = u16::from_be_bytes([data[rr_start + 2], data[rr_start + 3]]);
    // TTL at rr_start+4..rr_start+8 (not needed for our purposes)
    let rdlength = u16::from_be_bytes([data[rr_start + 8], data[rr_start + 9]]) as usize;
    let rdata_start = rr_start + 10;
    let rdata_end = rdata_start + rdlength;

    if rdata_end > data.len() {
        return None;
    }

    // Strip the mDNS cache-flush bit from the class for comparison
    let class_masked = rclass & !MDNS_CACHE_FLUSH;
    if class_masked != CLASS_IN {
        // Skip non-IN class records but still advance past them
        return Some((
            DnsRecord::Txt {
                name,
                entries: Vec::new(),
            },
            rdata_end - offset,
        ));
    }

    let total_consumed = rdata_end - offset;

    let record = match rtype {
        TYPE_A => {
            if rdlength != 4 {
                return None;
            }
            DnsRecord::A {
                name,
                ip: Ipv4Addr::new(
                    data[rdata_start],
                    data[rdata_start + 1],
                    data[rdata_start + 2],
                    data[rdata_start + 3],
                ),
            }
        }
        TYPE_AAAA => {
            if rdlength != 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[rdata_start..rdata_end]);
            DnsRecord::Aaaa {
                name,
                ip: Ipv6Addr::from(octets),
            }
        }
        TYPE_PTR => {
            let (target, _) = parse_dns_name(data, rdata_start)?;
            DnsRecord::Ptr { name, target }
        }
        TYPE_SRV => {
            if rdlength < 6 {
                return None;
            }
            let priority = u16::from_be_bytes([data[rdata_start], data[rdata_start + 1]]);
            let weight = u16::from_be_bytes([data[rdata_start + 2], data[rdata_start + 3]]);
            let port = u16::from_be_bytes([data[rdata_start + 4], data[rdata_start + 5]]);
            let (target, _) = parse_dns_name(data, rdata_start + 6)?;
            DnsRecord::Srv {
                name,
                priority,
                weight,
                port,
                target,
            }
        }
        TYPE_TXT => {
            let entries = parse_txt_rdata(&data[rdata_start..rdata_end]);
            DnsRecord::Txt { name, entries }
        }
        _ => {
            // Unknown record type — skip it
            DnsRecord::Txt {
                name,
                entries: Vec::new(),
            }
        }
    };

    Some((record, total_consumed))
}

/// Parse TXT record rdata: sequence of length-prefixed strings.
fn parse_txt_rdata(data: &[u8]) -> Vec<String> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let len = data[pos] as usize;
        pos += 1;
        if pos + len > data.len() {
            break;
        }
        let entry = String::from_utf8_lossy(&data[pos..pos + len]).into_owned();
        if !entry.is_empty() {
            entries.push(entry);
        }
        pos += len;
    }
    entries
}

// ── Full packet parsing ────────────────────────────────────────────────

/// Parse a complete DNS packet into header + resource records.
///
/// Skips questions and collects all answer, authority, and additional records.
pub fn parse_dns_packet(data: &[u8]) -> Option<DnsPacket> {
    let header = parse_dns_header(data)?;

    let mut offset = DNS_HEADER_LEN;

    // Skip question section
    for _ in 0..header.questions {
        let (_, name_consumed) = parse_dns_name(data, offset)?;
        // Each question has: name + QTYPE(2) + QCLASS(2)
        offset += name_consumed + 4;
        if offset > data.len() {
            return None;
        }
    }

    // Parse answer + authority + additional sections
    let total_records = header
        .answers
        .saturating_add(header.authority)
        .saturating_add(header.additional);

    let mut records = Vec::new();
    for _ in 0..total_records {
        if offset >= data.len() {
            break;
        }
        let Some((record, consumed)) = parse_resource_record(data, offset) else {
            break;
        };
        records.push(record);
        offset += consumed;
    }

    Some(DnsPacket { header, records })
}

// ── Query builder ──────────────────────────────────────────────────────

/// Build a minimal DNS query packet for the given name and record type.
///
/// The query has a single question with class IN. Transaction ID is 0
/// (standard for mDNS).
#[must_use]
pub fn build_mdns_query(name: &str, record_type: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);

    // Header: ID=0, flags=0, qdcount=1, ancount=0, nscount=0, arcount=0
    packet.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

    // Encode the name as DNS labels
    encode_dns_name(&mut packet, name);

    // QTYPE and QCLASS
    packet.extend_from_slice(&record_type.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());

    packet
}

/// Encode a dotted name into DNS label format and append to `buf`.
fn encode_dns_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        let len = label.len();
        if len > 63 {
            // DNS labels are limited to 63 bytes — truncate
            buf.push(63);
            buf.extend_from_slice(&label.as_bytes()[..63]);
        } else {
            #[allow(clippy::cast_possible_truncation)]
            buf.push(len as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0); // Root label
}

// ── Service discovery ──────────────────────────────────────────────────

/// Common mDNS service types to query for.
const SERVICE_QUERIES: &[&str] = &[
    "_services._dns-sd._udp.local",
    "_http._tcp.local",
    "_ssh._tcp.local",
    "_ipp._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_smb._tcp.local",
    "_googlecast._tcp.local",
    "_hap._tcp.local",
];

/// Discover services via mDNS on the local network.
///
/// Sends PTR queries for common service types and collects responses for
/// `timeout_secs`. Returns structured `MdnsService` objects with names,
/// types, hostnames, IPs, ports, and TXT metadata.
pub async fn discover_services(timeout_secs: u64) -> Result<Vec<MdnsService>> {
    // Run the blocking UDP I/O on a separate thread to avoid blocking the
    // tokio runtime.
    let services = tokio::task::spawn_blocking(move || discover_services_blocking(timeout_secs))
        .await
        .map_err(|e| anyhow::anyhow!("mDNS discovery task failed: {e}"))?;
    Ok(services)
}

/// Blocking mDNS discovery — called from `spawn_blocking`.
fn discover_services_blocking(timeout_secs: u64) -> Vec<MdnsService> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("could not bind mDNS socket: {e}");
            return Vec::new();
        }
    };

    let timeout = Duration::from_secs(timeout_secs);
    let _ = socket.set_read_timeout(Some(timeout));

    let dest = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST), MDNS_PORT);

    // Send PTR queries for each service type
    for &svc_name in SERVICE_QUERIES {
        let query = build_mdns_query(svc_name, TYPE_PTR);
        if socket.send_to(&query, dest).is_err() {
            tracing::debug!(service = svc_name, "could not send mDNS query");
        }
    }

    // Collect and parse responses
    let mut all_records: Vec<(IpAddr, DnsRecord)> = Vec::new();
    let mut buf = [0u8; 4096];

    while let Ok((n, addr)) = socket.recv_from(&mut buf) {
        if let Some(packet) = parse_dns_packet(&buf[..n]) {
            for record in packet.records {
                all_records.push((addr.ip(), record));
            }
        }
    }

    correlate_mdns_records(&all_records)
}

/// Correlate mDNS records into structured service descriptions.
///
/// Follows the chain: PTR → SRV → A/TXT to build complete `MdnsService`
/// objects. Services without a resolved IP are included with the responder's
/// IP as a fallback.
fn correlate_mdns_records(records: &[(IpAddr, DnsRecord)]) -> Vec<MdnsService> {
    use std::collections::HashMap;

    // Index records by name for quick lookup
    let mut a_records: HashMap<&str, Ipv4Addr> = HashMap::new();
    let mut aaaa_records: HashMap<&str, Ipv6Addr> = HashMap::new();
    let mut srv_records: HashMap<&str, (&str, u16)> = HashMap::new();
    let mut txt_records: HashMap<&str, &[String]> = HashMap::new();
    let mut ptr_records: Vec<(&str, &str)> = Vec::new();

    for (_, record) in records {
        match record {
            DnsRecord::A { name, ip } => {
                a_records.insert(name.as_str(), *ip);
            }
            DnsRecord::Aaaa { name, ip } => {
                aaaa_records.insert(name.as_str(), *ip);
            }
            DnsRecord::Srv {
                name, target, port, ..
            } => {
                srv_records.insert(name.as_str(), (target.as_str(), *port));
            }
            DnsRecord::Txt { name, entries } if !entries.is_empty() => {
                txt_records.insert(name.as_str(), entries.as_slice());
            }
            DnsRecord::Ptr { .. } | DnsRecord::Txt { .. } => {}
        }
    }

    // Collect PTR records (service type → instance name)
    for (_, record) in records {
        if let DnsRecord::Ptr { name, target } = record {
            ptr_records.push((name.as_str(), target.as_str()));
        }
    }

    // Also collect SRV records that weren't pointed to by a PTR — these are
    // direct service announcements
    let ptr_targets: std::collections::HashSet<&str> =
        ptr_records.iter().map(|(_, t)| *t).collect();

    let mut services = Vec::new();
    let mut seen: std::collections::HashSet<(String, u16, String)> =
        std::collections::HashSet::new();

    // Build services from PTR → SRV → A/TXT chain
    for (service_type, instance_name) in &ptr_records {
        if let Some(&(target, port)) = srv_records.get(instance_name) {
            let ip = resolve_ip(&a_records, &aaaa_records, target, records);
            let txt = txt_records
                .get(instance_name)
                .map_or_else(Vec::new, |e| e.to_vec());

            let key = (ip.to_string(), port, (*service_type).to_owned());
            if seen.insert(key) {
                // Extract the instance name (part before the service type)
                let friendly_name = instance_name
                    .strip_suffix(service_type)
                    .and_then(|s| s.strip_suffix('.'))
                    .unwrap_or(instance_name);

                services.push(MdnsService {
                    name: friendly_name.to_owned(),
                    service_type: (*service_type).to_owned(),
                    hostname: target.to_owned(),
                    ip,
                    port,
                    txt_records: txt,
                });
            }
        }
    }

    // Build services from direct SRV records (not referenced by any PTR)
    for (_, record) in records {
        if let DnsRecord::Srv {
            name, target, port, ..
        } = record
            && !ptr_targets.contains(name.as_str())
        {
            let ip = resolve_ip(&a_records, &aaaa_records, target.as_str(), records);
            let txt = txt_records
                .get(name.as_str())
                .map_or_else(Vec::new, |e| e.to_vec());

            let service_type = extract_service_type(name);
            let key = (ip.to_string(), *port, service_type.clone());
            if seen.insert(key) {
                let friendly_name = name
                    .strip_suffix(&service_type)
                    .and_then(|s| s.strip_suffix('.'))
                    .unwrap_or(name);

                services.push(MdnsService {
                    name: friendly_name.to_owned(),
                    service_type,
                    hostname: target.to_owned(),
                    ip,
                    port: *port,
                    txt_records: txt,
                });
            }
        }
    }

    services
}

/// Resolve a hostname to an IP address using collected A/AAAA records.
/// Falls back to the responder's IP if no address record exists.
fn resolve_ip(
    a_records: &std::collections::HashMap<&str, Ipv4Addr>,
    aaaa_records: &std::collections::HashMap<&str, Ipv6Addr>,
    target: &str,
    records: &[(IpAddr, DnsRecord)],
) -> IpAddr {
    if let Some(&ipv4) = a_records.get(target) {
        return IpAddr::V4(ipv4);
    }
    if let Some(&ipv6) = aaaa_records.get(target) {
        return IpAddr::V6(ipv6);
    }
    // Fallback: use the IP of the first responder
    records
        .first()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |(ip, _)| *ip)
}

/// Extract the service type from an instance name.
///
/// E.g. `"My Printer._ipp._tcp.local"` → `"_ipp._tcp.local"`.
fn extract_service_type(name: &str) -> String {
    // If the name starts with '_', it's already a bare service type
    // (e.g. "_ipp._tcp.local"). Otherwise, strip the instance prefix
    // before the first "._" (e.g. "My Printer._ipp._tcp.local").
    if name.starts_with('_') {
        name.to_owned()
    } else {
        name.find("._")
            .map_or_else(|| name.to_owned(), |idx| name[idx + 1..].to_owned())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── Test helpers: packet builders ───────────────────────────────

    /// Build a DNS header with the given counts.
    fn build_test_header(
        id: u16,
        flags: u16,
        questions: u16,
        answers: u16,
        authority: u16,
        additional: u16,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&questions.to_be_bytes());
        buf.extend_from_slice(&answers.to_be_bytes());
        buf.extend_from_slice(&authority.to_be_bytes());
        buf.extend_from_slice(&additional.to_be_bytes());
        buf
    }

    /// Encode a dotted name into DNS label format.
    fn encode_name(name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_dns_name(&mut buf, name);
        buf
    }

    /// Build a PTR resource record.
    fn build_ptr_record(name: &str, target: &str, ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        let name_bytes = encode_name(name);
        let target_bytes = encode_name(target);
        buf.extend_from_slice(&name_bytes);
        buf.extend_from_slice(&TYPE_PTR.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());
        #[allow(clippy::cast_possible_truncation)]
        let rdlength = target_bytes.len() as u16;
        buf.extend_from_slice(&rdlength.to_be_bytes());
        buf.extend_from_slice(&target_bytes);
        buf
    }

    /// Build an A resource record.
    fn build_a_record(name: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_name(name));
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        buf.extend_from_slice(&ip.octets());
        buf
    }

    /// Build an SRV resource record.
    fn build_srv_record(
        name: &str,
        priority: u16,
        weight: u16,
        port: u16,
        target: &str,
        ttl: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        let target_bytes = encode_name(target);
        buf.extend_from_slice(&encode_name(name));
        buf.extend_from_slice(&TYPE_SRV.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());
        #[allow(clippy::cast_possible_truncation)]
        let rdlength = (6 + target_bytes.len()) as u16;
        buf.extend_from_slice(&rdlength.to_be_bytes());
        buf.extend_from_slice(&priority.to_be_bytes());
        buf.extend_from_slice(&weight.to_be_bytes());
        buf.extend_from_slice(&port.to_be_bytes());
        buf.extend_from_slice(&target_bytes);
        buf
    }

    /// Build a TXT resource record with the given key=value entries.
    fn build_txt_record(name: &str, entries: &[&str], ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_name(name));
        buf.extend_from_slice(&TYPE_TXT.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());

        // Build rdata
        let mut rdata = Vec::new();
        for entry in entries {
            #[allow(clippy::cast_possible_truncation)]
            rdata.push(entry.len() as u8);
            rdata.extend_from_slice(entry.as_bytes());
        }
        #[allow(clippy::cast_possible_truncation)]
        let rdlength = rdata.len() as u16;
        buf.extend_from_slice(&rdlength.to_be_bytes());
        buf.extend_from_slice(&rdata);
        buf
    }

    /// Build an AAAA resource record.
    fn build_aaaa_record(name: &str, ip: Ipv6Addr, ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_name(name));
        buf.extend_from_slice(&TYPE_AAAA.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&16u16.to_be_bytes()); // rdlength
        buf.extend_from_slice(&ip.octets());
        buf
    }

    // ── DNS name parsing tests ─────────────────────────────────────

    #[test]
    fn test_parse_dns_name_simple() {
        let data = encode_name("example.local");
        let (name, consumed) = parse_dns_name(&data, 0).unwrap();
        assert_eq!(name, "example.local");
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_dns_name_single_label() {
        let data = encode_name("localhost");
        let (name, consumed) = parse_dns_name(&data, 0).unwrap();
        assert_eq!(name, "localhost");
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_dns_name_service_type() {
        let data = encode_name("_http._tcp.local");
        let (name, _) = parse_dns_name(&data, 0).unwrap();
        assert_eq!(name, "_http._tcp.local");
    }

    #[test]
    fn test_parse_dns_name_compressed() {
        // Build a packet where the second name uses a pointer to the first
        let mut data = Vec::new();
        // Name at offset 0: "local" → \x05local\x00
        data.extend_from_slice(&[0x05, b'l', b'o', b'c', b'a', b'l', 0x00]);
        // Name at offset 7: "test" + pointer to offset 0 → \x04test\xC0\x00
        data.extend_from_slice(&[0x04, b't', b'e', b's', b't', 0xC0, 0x00]);

        let (name, _) = parse_dns_name(&data, 7).unwrap();
        assert_eq!(name, "test.local");
    }

    #[test]
    fn test_parse_dns_name_deep_compression() {
        // "example.local" at offset 0
        let mut data = Vec::new();
        data.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x05, b'l', b'o', b'c', b'a', b'l', // "local"
            0x00, // root
        ]);
        // offset 15: "sub" + pointer to offset 0 ("example.local")
        data.extend_from_slice(&[0x03, b's', b'u', b'b', 0xC0, 0x00]);

        let (name, _) = parse_dns_name(&data, 15).unwrap();
        assert_eq!(name, "sub.example.local");
    }

    #[test]
    fn test_parse_dns_name_cycle_protection() {
        // Two pointers forming a cycle: offset 0 → offset 2 → offset 0
        let data = [0xC0, 0x02, 0xC0, 0x00];
        assert!(parse_dns_name(&data, 0).is_none());
    }

    #[test]
    fn test_parse_dns_name_self_pointer() {
        // Self-referencing pointer at offset 0
        let data = [0xC0, 0x00];
        assert!(parse_dns_name(&data, 0).is_none());
    }

    #[test]
    fn test_parse_dns_name_truncated() {
        // Label claims length 10 but only 3 bytes follow
        let data = [0x0A, b'a', b'b', b'c'];
        assert!(parse_dns_name(&data, 0).is_none());
    }

    #[test]
    fn test_parse_dns_name_empty() {
        // Root label only
        let data = [0x00];
        let (name, consumed) = parse_dns_name(&data, 0).unwrap();
        assert_eq!(name, "");
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_parse_dns_name_pointer_out_of_bounds() {
        // Pointer to offset 255 in a 4-byte packet
        let data = [0xC0, 0xFF];
        assert!(parse_dns_name(&data, 0).is_none());
    }

    // ── DNS header tests ───────────────────────────────────────────

    #[test]
    fn test_parse_dns_header() {
        let data = build_test_header(0x1234, 0x8400, 0, 3, 0, 2);
        let header = parse_dns_header(&data).unwrap();
        assert_eq!(header.id, 0x1234);
        assert!(header.is_response());
        assert_eq!(header.answers, 3);
        assert_eq!(header.additional, 2);
    }

    #[test]
    fn test_parse_dns_header_query() {
        let data = build_test_header(0, 0, 1, 0, 0, 0);
        let header = parse_dns_header(&data).unwrap();
        assert!(!header.is_response());
        assert_eq!(header.questions, 1);
    }

    #[test]
    fn test_parse_dns_header_too_short() {
        let data = [0u8; 11];
        assert!(parse_dns_header(&data).is_none());
    }

    // ── Resource record tests ──────────────────────────────────────

    #[test]
    fn test_parse_a_record() {
        let data = build_a_record("printer.local", Ipv4Addr::new(192, 168, 1, 100), 120);
        let (record, _) = parse_resource_record(&data, 0).unwrap();
        assert_eq!(
            record,
            DnsRecord::A {
                name: "printer.local".to_owned(),
                ip: Ipv4Addr::new(192, 168, 1, 100),
            }
        );
    }

    #[test]
    fn test_parse_aaaa_record() {
        let ip = "fe80::1".parse::<Ipv6Addr>().unwrap();
        let data = build_aaaa_record("host.local", ip, 120);
        let (record, _) = parse_resource_record(&data, 0).unwrap();
        assert_eq!(
            record,
            DnsRecord::Aaaa {
                name: "host.local".to_owned(),
                ip,
            }
        );
    }

    #[test]
    fn test_parse_ptr_record() {
        let data = build_ptr_record("_ipp._tcp.local", "My Printer._ipp._tcp.local", 4500);
        let (record, _) = parse_resource_record(&data, 0).unwrap();
        assert_eq!(
            record,
            DnsRecord::Ptr {
                name: "_ipp._tcp.local".to_owned(),
                target: "My Printer._ipp._tcp.local".to_owned(),
            }
        );
    }

    #[test]
    fn test_parse_srv_record() {
        let data = build_srv_record(
            "My Printer._ipp._tcp.local",
            0,
            0,
            631,
            "printer.local",
            120,
        );
        let (record, _) = parse_resource_record(&data, 0).unwrap();
        assert_eq!(
            record,
            DnsRecord::Srv {
                name: "My Printer._ipp._tcp.local".to_owned(),
                priority: 0,
                weight: 0,
                port: 631,
                target: "printer.local".to_owned(),
            }
        );
    }

    #[test]
    fn test_parse_txt_record() {
        let data = build_txt_record(
            "My Printer._ipp._tcp.local",
            &["rp=ipp/print", "ty=EPSON XP-440"],
            4500,
        );
        let (record, _) = parse_resource_record(&data, 0).unwrap();
        match record {
            DnsRecord::Txt { name, entries } => {
                assert_eq!(name, "My Printer._ipp._tcp.local");
                assert_eq!(entries, vec!["rp=ipp/print", "ty=EPSON XP-440"]);
            }
            other => panic!("expected Txt, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_txt_record_empty_entries() {
        // TXT record with a zero-length string (should be skipped)
        let data = build_txt_record("svc.local", &[], 120);
        let (record, _) = parse_resource_record(&data, 0).unwrap();
        match record {
            DnsRecord::Txt { entries, .. } => assert!(entries.is_empty()),
            other => panic!("expected Txt, got {other:?}"),
        }
    }

    // ── Full packet parsing tests ──────────────────────────────────

    #[test]
    fn test_parse_full_mdns_response() {
        // Build a realistic mDNS response with PTR + SRV + TXT + A
        let mut packet = build_test_header(
            0,      // id
            0x8400, // flags: response, authoritative
            0,      // questions
            4,      // answers: PTR + SRV + TXT + A
            0,      // authority
            0,      // additional
        );
        packet.extend_from_slice(&build_ptr_record(
            "_ipp._tcp.local",
            "My Printer._ipp._tcp.local",
            4500,
        ));
        packet.extend_from_slice(&build_srv_record(
            "My Printer._ipp._tcp.local",
            0,
            0,
            631,
            "printer.local",
            120,
        ));
        packet.extend_from_slice(&build_txt_record(
            "My Printer._ipp._tcp.local",
            &["rp=ipp/print", "ty=EPSON XP-440"],
            4500,
        ));
        packet.extend_from_slice(&build_a_record(
            "printer.local",
            Ipv4Addr::new(192, 168, 1, 100),
            120,
        ));

        let parsed = parse_dns_packet(&packet).unwrap();
        assert!(parsed.header.is_response());
        assert_eq!(parsed.records.len(), 4);

        // Verify we got one of each type
        assert!(
            parsed
                .records
                .iter()
                .any(|r| matches!(r, DnsRecord::Ptr { .. }))
        );
        assert!(
            parsed
                .records
                .iter()
                .any(|r| matches!(r, DnsRecord::Srv { .. }))
        );
        assert!(
            parsed
                .records
                .iter()
                .any(|r| matches!(r, DnsRecord::Txt { .. }))
        );
        assert!(
            parsed
                .records
                .iter()
                .any(|r| matches!(r, DnsRecord::A { .. }))
        );
    }

    #[test]
    fn test_parse_packet_with_questions() {
        // A response that echoes the question back
        let mut packet = build_test_header(0, 0x8400, 1, 1, 0, 0);
        // Question: _ipp._tcp.local PTR IN
        packet.extend_from_slice(&encode_name("_ipp._tcp.local"));
        packet.extend_from_slice(&TYPE_PTR.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        // Answer
        packet.extend_from_slice(&build_ptr_record(
            "_ipp._tcp.local",
            "printer._ipp._tcp.local",
            4500,
        ));

        let parsed = parse_dns_packet(&packet).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert!(
            matches!(&parsed.records[0], DnsRecord::Ptr { target, .. } if target == "printer._ipp._tcp.local")
        );
    }

    #[test]
    fn test_parse_packet_additional_section() {
        // Response with answers in the additional section
        let mut packet = build_test_header(0, 0x8400, 0, 0, 0, 1);
        packet.extend_from_slice(&build_a_record(
            "host.local",
            Ipv4Addr::new(10, 0, 0, 1),
            120,
        ));

        let parsed = parse_dns_packet(&packet).unwrap();
        assert_eq!(parsed.records.len(), 1);
    }

    // ── Query builder tests ────────────────────────────────────────

    #[test]
    fn test_build_mdns_query() {
        let query = build_mdns_query("_http._tcp.local", TYPE_PTR);

        // Should parse as a valid DNS packet
        let parsed = parse_dns_packet(&query).unwrap();
        assert!(!parsed.header.is_response());
        assert_eq!(parsed.header.questions, 1);
        assert_eq!(parsed.header.answers, 0);
    }

    #[test]
    fn test_build_mdns_query_round_trip() {
        let query = build_mdns_query("_services._dns-sd._udp.local", TYPE_PTR);
        let header = parse_dns_header(&query).unwrap();
        assert_eq!(header.id, 0);
        assert_eq!(header.questions, 1);

        // Parse the question name
        let (name, _) = parse_dns_name(&query, DNS_HEADER_LEN).unwrap();
        assert_eq!(name, "_services._dns-sd._udp.local");
    }

    // ── Correlation tests ──────────────────────────────────────────

    #[test]
    fn test_correlate_ptr_srv_a_txt() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
        let records = vec![
            (
                ip,
                DnsRecord::Ptr {
                    name: "_http._tcp.local".to_owned(),
                    target: "Web Server._http._tcp.local".to_owned(),
                },
            ),
            (
                ip,
                DnsRecord::Srv {
                    name: "Web Server._http._tcp.local".to_owned(),
                    priority: 0,
                    weight: 0,
                    port: 80,
                    target: "server.local".to_owned(),
                },
            ),
            (
                ip,
                DnsRecord::A {
                    name: "server.local".to_owned(),
                    ip: Ipv4Addr::new(192, 168, 1, 42),
                },
            ),
            (
                ip,
                DnsRecord::Txt {
                    name: "Web Server._http._tcp.local".to_owned(),
                    entries: vec!["path=/admin".to_owned()],
                },
            ),
        ];

        let services = correlate_mdns_records(&records);
        assert_eq!(services.len(), 1);
        let svc = &services[0];
        assert_eq!(svc.name, "Web Server");
        assert_eq!(svc.service_type, "_http._tcp.local");
        assert_eq!(svc.hostname, "server.local");
        assert_eq!(svc.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)));
        assert_eq!(svc.port, 80);
        assert_eq!(svc.txt_records, vec!["path=/admin"]);
    }

    #[test]
    fn test_correlate_dedup() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let records = vec![
            (
                ip,
                DnsRecord::Ptr {
                    name: "_ssh._tcp.local".to_owned(),
                    target: "NAS._ssh._tcp.local".to_owned(),
                },
            ),
            // Duplicate PTR
            (
                ip,
                DnsRecord::Ptr {
                    name: "_ssh._tcp.local".to_owned(),
                    target: "NAS._ssh._tcp.local".to_owned(),
                },
            ),
            (
                ip,
                DnsRecord::Srv {
                    name: "NAS._ssh._tcp.local".to_owned(),
                    priority: 0,
                    weight: 0,
                    port: 22,
                    target: "nas.local".to_owned(),
                },
            ),
            (
                ip,
                DnsRecord::A {
                    name: "nas.local".to_owned(),
                    ip: Ipv4Addr::new(192, 168, 1, 10),
                },
            ),
        ];

        let services = correlate_mdns_records(&records);
        assert_eq!(services.len(), 1);
    }

    #[test]
    fn test_correlate_direct_srv() {
        // SRV record not pointed to by any PTR
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let records = vec![
            (
                ip,
                DnsRecord::Srv {
                    name: "printer._ipp._tcp.local".to_owned(),
                    priority: 0,
                    weight: 0,
                    port: 631,
                    target: "printer.local".to_owned(),
                },
            ),
            (
                ip,
                DnsRecord::A {
                    name: "printer.local".to_owned(),
                    ip: Ipv4Addr::new(10, 0, 0, 5),
                },
            ),
        ];

        let services = correlate_mdns_records(&records);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].port, 631);
        assert_eq!(services[0].service_type, "_ipp._tcp.local");
    }

    // ── extract_service_type tests ─────────────────────────────────

    #[test]
    fn test_extract_service_type_normal() {
        assert_eq!(
            extract_service_type("My Printer._ipp._tcp.local"),
            "_ipp._tcp.local"
        );
    }

    #[test]
    fn test_extract_service_type_no_instance() {
        assert_eq!(extract_service_type("_ipp._tcp.local"), "_ipp._tcp.local");
    }

    #[test]
    fn test_extract_service_type_plain() {
        assert_eq!(extract_service_type("something"), "something");
    }

    // ── DnsRecord::name() tests ────────────────────────────────────

    #[test]
    fn test_record_name() {
        let record = DnsRecord::A {
            name: "host.local".to_owned(),
            ip: Ipv4Addr::LOCALHOST,
        };
        assert_eq!(record.name(), "host.local");
    }

    // ── Proptest: never panic on arbitrary input ───────────────────

    proptest! {
        #[test]
        fn prop_parse_dns_packet_no_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = parse_dns_packet(&data);
        }

        #[test]
        fn prop_parse_dns_name_no_panic(
            data in proptest::collection::vec(any::<u8>(), 0..512),
            offset in 0..512usize,
        ) {
            let _ = parse_dns_name(&data, offset);
        }

        #[test]
        fn prop_parse_resource_record_no_panic(
            data in proptest::collection::vec(any::<u8>(), 0..1024),
            offset in 0..1024usize,
        ) {
            let _ = parse_resource_record(&data, offset);
        }

        #[test]
        fn prop_parse_dns_header_no_panic(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = parse_dns_header(&data);
        }
    }
}
