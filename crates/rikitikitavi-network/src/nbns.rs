//! `NetBIOS` node status (NBSTAT, RFC 1002 4.2.17/4.2.18) over unicast UDP 137.
//!
//! Only RFC 1918 and link-local IPv4 targets are queried. Responses are untrusted
//! and pass through [`parse_node_status`].

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

/// NBNS port.
pub const NBNS_PORT: u16 = 137;

/// Most targets queried in one pass.
pub const MAX_TARGETS: usize = 1024;

/// Longest `NetBIOS` name, in bytes, excluding the suffix byte.
pub const MAX_NAME_LEN: usize = 15;

const HEADER_LEN: usize = 12;
const NODE_NAME_LEN: usize = 18;
const UNIT_ID_LEN: usize = 6;
const TYPE_NBSTAT: u16 = 0x0021;
const CLASS_IN: u16 = 0x0001;
const FLAG_RESPONSE: u16 = 0x8000;
const OPCODE_MASK: u16 = 0x7800;
const RCODE_MASK: u16 = 0x000f;
const NAME_FLAG_GROUP: u16 = 0x8000;
const MAX_POINTER_HOPS: usize = 8;
const MAX_ENCODED_NAME: usize = 255;
const RECV_BUF: usize = 1500;

/// Timing and concurrency for a query pass.
#[derive(Debug, Clone)]
pub struct NbnsConfig {
    /// Timeout for one query.
    pub per_query: Duration,
    /// Bound on the whole pass; unfinished queries are dropped.
    pub total: Duration,
    /// Queries in flight.
    pub concurrency: usize,
}

impl Default for NbnsConfig {
    fn default() -> Self {
        Self {
            per_query: Duration::from_millis(800),
            total: Duration::from_secs(6),
            concurrency: 16,
        }
    }
}

/// Fields taken from one node status response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeStatus {
    /// First unique `<00>` name.
    pub hostname: Option<String>,
    /// First group `<00>` name.
    pub workgroup: Option<String>,
    /// `UNIT_ID`; `None` when absent or all-zero.
    pub unit_id: Option<[u8; 6]>,
}

impl NodeStatus {
    /// `UNIT_ID` has the locally administered bit set.
    #[must_use]
    pub fn unit_id_is_local(&self) -> bool {
        self.unit_id.is_some_and(|m| m[0] & 0x02 != 0)
    }

    const fn is_empty(&self) -> bool {
        self.hostname.is_none() && self.workgroup.is_none() && self.unit_id.is_none()
    }
}

/// Result of a query pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NbnsOutcome {
    /// Parsed responses by address.
    pub nodes: HashMap<Ipv4Addr, NodeStatus>,
    /// Targets queried.
    pub queried: usize,
}

impl NbnsOutcome {
    /// Responses carrying a hostname.
    #[must_use]
    pub fn resolved(&self) -> usize {
        self.nodes.values().filter(|n| n.hostname.is_some()).count()
    }
}

/// RFC 1918 or link-local.
#[must_use]
pub const fn is_queryable(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

/// Node status of each target on UDP 137. Other targets are dropped before any
/// packet is sent.
pub async fn node_status(targets: &[Ipv4Addr], cfg: &NbnsConfig) -> NbnsOutcome {
    let addrs: Vec<SocketAddr> = targets
        .iter()
        .copied()
        .filter(|ip| is_queryable(*ip))
        .map(|ip| SocketAddr::new(IpAddr::V4(ip), NBNS_PORT))
        .collect();
    let (queried, found) = status_with(&addrs, cfg).await;
    let nodes = found
        .into_iter()
        .filter_map(|(addr, node)| match addr.ip() {
            IpAddr::V4(ip) => Some((ip, node)),
            IpAddr::V6(_) => None,
        })
        .collect();
    NbnsOutcome { nodes, queried }
}

async fn status_with(
    targets: &[SocketAddr],
    cfg: &NbnsConfig,
) -> (usize, HashMap<SocketAddr, NodeStatus>) {
    let mut seen = HashSet::new();
    let targets: Vec<SocketAddr> = targets
        .iter()
        .copied()
        .filter(|a| seen.insert(*a))
        .take(MAX_TARGETS)
        .collect();
    let queried = targets.len();
    let mut found = HashMap::new();
    if targets.is_empty() {
        return (queried, found);
    }

    let semaphore = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
    let per_query = cfg.per_query;
    let deadline = Instant::now() + cfg.total;

    let mut set = JoinSet::new();
    for (i, target) in targets.into_iter().enumerate() {
        let semaphore = Arc::clone(&semaphore);
        let id = transaction_id(i);
        set.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok()?;
            query_one(target, id, per_query)
                .await
                .map(|node| (target, node))
        });
    }

    while let Ok(Some(joined)) = tokio::time::timeout_at(deadline, set.join_next()).await {
        if let Ok(Some((addr, node))) = joined {
            found.insert(addr, node);
        }
    }
    (queried, found)
}

fn transaction_id(index: usize) -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let mixed = nanos
        ^ u32::try_from(index)
            .unwrap_or(u32::MAX)
            .wrapping_mul(0x9e37_79b9);
    let bytes = mixed.to_le_bytes();
    u16::from_le_bytes([bytes[0] ^ bytes[2], bytes[1] ^ bytes[3]])
}

async fn query_one(target: SocketAddr, id: u16, timeout: Duration) -> Option<NodeStatus> {
    let bind: SocketAddr = if target.ip().is_loopback() {
        (Ipv4Addr::LOCALHOST, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let packet = build_query(id);
    let exchange = async {
        let socket = UdpSocket::bind(bind).await.ok()?;
        socket.connect(target).await.ok()?;
        socket.send(&packet).await.ok()?;
        let mut buf = [0u8; RECV_BUF];
        loop {
            let (n, from) = socket.recv_from(&mut buf).await.ok()?;
            if from != target {
                continue;
            }
            if let Some(node) = parse_node_status(&buf[..n], id) {
                return Some(node);
            }
        }
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .ok()
        .flatten()
        .filter(|n| !n.is_empty())
}

/// NBSTAT request for the wildcard name `*`.
#[must_use]
pub fn build_query(id: u16) -> [u8; 50] {
    let mut p = [0u8; 50];
    p[0..2].copy_from_slice(&id.to_be_bytes());
    p[4..6].copy_from_slice(&1u16.to_be_bytes());
    p[12] = 0x20;
    let mut raw = [0u8; 16];
    raw[0] = b'*';
    for (i, b) in raw.iter().enumerate() {
        p[13 + 2 * i] = b'A' + (b >> 4);
        p[14 + 2 * i] = b'A' + (b & 0x0f);
    }
    p[45] = 0;
    p[46..48].copy_from_slice(&TYPE_NBSTAT.to_be_bytes());
    p[48..50].copy_from_slice(&CLASS_IN.to_be_bytes());
    p
}

fn be16(buf: &[u8], at: usize) -> Option<u16> {
    let b = buf.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

/// Offset just past the name at `start`. Pointers must target an earlier offset;
/// at most [`MAX_POINTER_HOPS`] are followed and [`MAX_ENCODED_NAME`] label bytes read.
fn skip_name(buf: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    let mut end = None;
    let mut hops = 0;
    let mut total = 0usize;
    loop {
        let len = *buf.get(pos)?;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    return end.or(Some(pos + 1));
                }
                let next = pos + 1 + usize::from(len);
                total += usize::from(len) + 1;
                if next > buf.len() || total > MAX_ENCODED_NAME {
                    return None;
                }
                pos = next;
            }
            0xc0 => {
                let target = usize::from(be16(buf, pos)? & 0x3fff);
                hops += 1;
                if target >= pos || hops > MAX_POINTER_HOPS {
                    return None;
                }
                end.get_or_insert(pos + 2);
                pos = target;
            }
            _ => return None,
        }
    }
}

/// Node status from a response datagram, or `None` if it is not a well-formed
/// positive NBSTAT response with transaction id `id`.
#[must_use]
pub fn parse_node_status(buf: &[u8], id: u16) -> Option<NodeStatus> {
    if buf.len() < HEADER_LEN || be16(buf, 0)? != id {
        return None;
    }
    let flags = be16(buf, 2)?;
    if flags & FLAG_RESPONSE == 0 || flags & OPCODE_MASK != 0 || flags & RCODE_MASK != 0 {
        return None;
    }
    let qdcount = be16(buf, 4)?;
    let ancount = be16(buf, 6)?;
    if qdcount > 1 || ancount == 0 {
        return None;
    }
    let mut pos = HEADER_LEN;
    if qdcount == 1 {
        pos = skip_name(buf, pos)?.checked_add(4)?;
    }
    pos = skip_name(buf, pos)?;
    if be16(buf, pos)? != TYPE_NBSTAT || be16(buf, pos + 2)? != CLASS_IN {
        return None;
    }
    let rdlength = usize::from(be16(buf, pos + 8)?);
    let rdata_start = pos + 10;
    let rdata = buf.get(rdata_start..rdata_start.checked_add(rdlength)?)?;
    let (&num_names, rest) = rdata.split_first()?;
    let names_len = usize::from(num_names) * NODE_NAME_LEN;
    let names = rest.get(..names_len)?;

    let mut node = NodeStatus::default();
    for entry in names.as_chunks::<NODE_NAME_LEN>().0 {
        let suffix = entry[15];
        let group = u16::from_be_bytes([entry[16], entry[17]]) & NAME_FLAG_GROUP != 0;
        if suffix != 0x00 {
            continue;
        }
        let slot = if group {
            &mut node.workgroup
        } else {
            &mut node.hostname
        };
        if slot.is_none() {
            *slot = clean_netbios_name(&entry[..15]);
        }
    }
    node.unit_id = rest
        .get(names_len..names_len + UNIT_ID_LEN)
        .and_then(|b| <[u8; 6]>::try_from(b).ok())
        .filter(|m| m.iter().any(|b| *b != 0));
    Some(node)
}

/// Name with trailing space/NUL padding removed. `None` when empty, longer than
/// [`MAX_NAME_LEN`], or containing bytes outside printable ASCII (space excluded).
#[must_use]
pub fn clean_netbios_name(raw: &[u8]) -> Option<String> {
    let end = raw
        .iter()
        .rposition(|b| *b != b' ' && *b != 0)
        .map_or(0, |i| i + 1);
    let name = &raw[..end];
    if name.is_empty() || name.len() > MAX_NAME_LEN || !name.iter().all(u8::is_ascii_graphic) {
        return None;
    }
    String::from_utf8(name.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ID: u16 = 0x1234;

    fn entry(name: &str, suffix: u8, group: bool) -> Vec<u8> {
        let mut e = format!("{name:<15}").into_bytes();
        e.truncate(15);
        e.push(suffix);
        e.extend_from_slice(&if group { [0x84, 0x00] } else { [0x04, 0x00] });
        e
    }

    /// Response with a full RR name, `names`, and the given statistics bytes.
    fn response(id: u16, names: &[Vec<u8>], stats: &[u8]) -> Vec<u8> {
        let query = build_query(id);
        let mut p = Vec::new();
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&0x8400u16.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
        p.extend_from_slice(&query[12..48]);
        p.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
        let rdlen = 1 + names.len() * NODE_NAME_LEN + stats.len();
        p.extend_from_slice(&u16::try_from(rdlen).unwrap().to_be_bytes());
        p.push(u8::try_from(names.len()).unwrap());
        for n in names {
            p.extend_from_slice(n);
        }
        p.extend_from_slice(stats);
        p
    }

    fn stats(mac: [u8; 6]) -> Vec<u8> {
        let mut s = mac.to_vec();
        s.resize(46, 0);
        s
    }

    fn synology() -> Vec<u8> {
        response(
            ID,
            &[
                entry("RUDIGER", 0x00, false),
                entry("RUDIGER", 0x03, false),
                entry("RUDIGER", 0x20, false),
                entry("\u{1}\u{2}__MSBROWSE__\u{2}", 0x01, true),
                entry("WORKGROUP", 0x00, true),
                entry("WORKGROUP", 0x1d, false),
            ],
            &stats([0x00, 0x11, 0x32, 0xaa, 0xbb, 0xcc]),
        )
    }

    #[test]
    fn query_encodes_wildcard() {
        let q = build_query(0xbeef);
        assert_eq!(&q[0..2], &[0xbe, 0xef]);
        assert_eq!(&q[2..12], &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(q[12], 32);
        assert_eq!(&q[13..15], b"CK");
        assert!(q[15..45].iter().all(|b| *b == b'A'));
        assert_eq!(&q[45..50], &[0, 0, 0x21, 0, 1]);
    }

    #[test]
    fn parses_unique_name_workgroup_and_unit_id() {
        let node = parse_node_status(&synology(), ID).unwrap();
        assert_eq!(node.hostname.as_deref(), Some("RUDIGER"));
        assert_eq!(node.workgroup.as_deref(), Some("WORKGROUP"));
        assert_eq!(node.unit_id, Some([0x00, 0x11, 0x32, 0xaa, 0xbb, 0xcc]));
        assert!(!node.unit_id_is_local());
    }

    #[test]
    fn rejects_wrong_id_and_non_responses() {
        let mut buf = synology();
        assert_eq!(parse_node_status(&buf, ID ^ 1), None);
        buf[2] = 0x04;
        assert_eq!(parse_node_status(&buf, ID), None);
        let mut buf = synology();
        buf[3] |= 0x03;
        assert_eq!(parse_node_status(&buf, ID), None);
        let mut buf = synology();
        buf[2] |= 0x28;
        assert_eq!(parse_node_status(&buf, ID), None);
    }

    #[test]
    fn truncation_at_every_boundary_never_panics() {
        let full = synology();
        for cut in 0..full.len() {
            assert_eq!(parse_node_status(&full[..cut], ID), None, "cut {cut}");
        }
        assert!(parse_node_status(&full, ID).is_some());
    }

    #[test]
    fn short_statistics_drop_unit_id_only() {
        let buf = response(ID, &[entry("HP7BA8A8", 0, false)], &[0x00, 0x11]);
        let node = parse_node_status(&buf, ID).unwrap();
        assert_eq!(node.hostname.as_deref(), Some("HP7BA8A8"));
        assert_eq!(node.unit_id, None);
    }

    #[test]
    fn zero_unit_id_skipped_and_local_flagged() {
        let buf = response(ID, &[entry("MAC-04B06C", 0, false)], &stats([0; 6]));
        assert_eq!(parse_node_status(&buf, ID).unwrap().unit_id, None);
        let buf = response(
            ID,
            &[entry("BRYANS-MBP", 0, false)],
            &stats([0x02, 0, 0, 0, 0, 1]),
        );
        assert!(parse_node_status(&buf, ID).unwrap().unit_id_is_local());
    }

    #[test]
    fn num_names_overflowing_rdlength_rejected() {
        let mut buf = response(ID, &[entry("A", 0, false)], &[]);
        let num_at = HEADER_LEN + 34 + 10;
        buf[num_at] = 2;
        assert_eq!(parse_node_status(&buf, ID), None);
        buf[num_at] = 255;
        buf.resize(buf.len() + 4000, b'A');
        assert_eq!(parse_node_status(&buf, ID), None);
    }

    #[test]
    fn rdlength_past_datagram_rejected() {
        let mut buf = synology();
        let at = HEADER_LEN + 34 + 8;
        buf[at..at + 2].copy_from_slice(&0xffffu16.to_be_bytes());
        assert_eq!(parse_node_status(&buf, ID), None);
    }

    #[test]
    fn wrong_type_or_class_rejected() {
        let mut buf = synology();
        buf[HEADER_LEN + 35] = 0x20;
        assert_eq!(parse_node_status(&buf, ID), None);
        let mut buf = synology();
        buf[HEADER_LEN + 37] = 0x03;
        assert_eq!(parse_node_status(&buf, ID), None);
    }

    #[test]
    fn group_only_names_give_no_hostname() {
        let buf = response(
            ID,
            &[entry("WORKGROUP", 0, true), entry("PRINTER", 0x20, false)],
            &[],
        );
        let node = parse_node_status(&buf, ID).unwrap();
        assert_eq!(node.hostname, None);
        assert_eq!(node.workgroup.as_deref(), Some("WORKGROUP"));
    }

    #[test]
    fn hostile_names_rejected() {
        let buf = response(
            ID,
            &[
                entry("", 0, false),
                entry("ES\u{1b}[31m", 0, false),
                entry("TAB\tX", 0, false),
                entry("REAL", 0, false),
            ],
            &[],
        );
        assert_eq!(
            parse_node_status(&buf, ID).unwrap().hostname.as_deref(),
            Some("REAL")
        );
        assert_eq!(clean_netbios_name(&[0xe9; 15]), None);
        assert_eq!(clean_netbios_name(b"A B            "), None);
        assert_eq!(
            clean_netbios_name(b"NAS\0\0\0\0\0\0\0\0\0\0\0\0").as_deref(),
            Some("NAS")
        );
        assert_eq!(clean_netbios_name(&[b'A'; 16]), None);
    }

    /// RR name replaced by `name_bytes`, followed by the original RR tail.
    fn with_rr_name(name_bytes: &[u8], prefix_question: bool) -> Vec<u8> {
        let full = synology();
        let mut p = full[..HEADER_LEN].to_vec();
        if prefix_question {
            p[5] = 1;
            p.extend_from_slice(&build_query(ID)[12..50]);
        }
        p.extend_from_slice(name_bytes);
        p.extend_from_slice(&full[HEADER_LEN + 34..]);
        p
    }

    #[test]
    fn compression_pointer_to_question_accepted() {
        let buf = with_rr_name(&[0xc0, 0x0c], true);
        assert_eq!(
            parse_node_status(&buf, ID).unwrap().hostname.as_deref(),
            Some("RUDIGER")
        );
    }

    #[test]
    fn bad_pointers_rejected() {
        assert_eq!(
            parse_node_status(&with_rr_name(&[0xc0, 0x0c], false), ID),
            None
        );
        assert_eq!(
            parse_node_status(&with_rr_name(&[0xc0, 0x0d], true), ID),
            None
        );
        assert_eq!(
            parse_node_status(&with_rr_name(&[0xc0, 0xff], true), ID),
            None
        );
        assert_eq!(
            parse_node_status(&with_rr_name(&[0x80, 0x0c], true), ID),
            None
        );
        let mut lp = synology()[..HEADER_LEN].to_vec();
        lp.extend_from_slice(&[0xc0, 0x0e, 0xc0, 0x0c]);
        assert_eq!(skip_name(&lp, 12), None);
        assert_eq!(skip_name(&lp, 14), None);
        let chain = |len: u16| {
            let mut c = vec![0u8; HEADER_LEN + 1];
            let mut prev = 12u16;
            for _ in 0..len {
                let here = u16::try_from(c.len()).unwrap();
                c.extend_from_slice(&(0xc000 | prev).to_be_bytes());
                prev = here;
            }
            c
        };
        let short = chain(u16::try_from(MAX_POINTER_HOPS).unwrap());
        assert_eq!(skip_name(&short, short.len() - 2), Some(short.len()));
        let long = chain(20);
        assert_eq!(skip_name(&long, long.len() - 2), None);
    }

    #[test]
    fn oversized_label_chain_rejected() {
        let mut name = Vec::new();
        for _ in 0..5 {
            name.push(63);
            name.extend_from_slice(&[b'A'; 63]);
        }
        name.push(0);
        assert_eq!(parse_node_status(&with_rr_name(&name, false), ID), None);
    }

    #[tokio::test]
    async fn public_and_loopback_targets_are_never_queried() {
        let out = node_status(
            &[Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::LOCALHOST],
            &NbnsConfig::default(),
        )
        .await;
        assert_eq!(out.queried, 0);
        assert!(is_queryable(Ipv4Addr::new(169, 254, 1, 2)));
        assert!(is_queryable(Ipv4Addr::new(172, 20, 0, 1)));
    }

    /// Fake responder on 127.0.0.1. `mode` 0: forged reply from another socket,
    /// then a wrong-id reply, then the real one. 1: silent. 2: group-only names.
    async fn fake_responder(mode: u8) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                if n != 50 || buf[12..50] != build_query(0)[12..50] {
                    continue;
                }
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                match mode {
                    0 => {
                        let forged = response(id, &[entry("FORGED", 0, false)], &[]);
                        let _ = other.send_to(&forged, peer).await;
                        let wrong = response(id ^ 1, &[entry("WRONG", 0, false)], &[]);
                        let _ = socket.send_to(&wrong, peer).await;
                        let real = response(
                            id,
                            &[entry("RUDIGER", 0, false)],
                            &stats([2, 0, 0, 0, 0, 9]),
                        );
                        let _ = socket.send_to(&real, peer).await;
                    }
                    2 => {
                        let resp = response(id, &[entry("WORKGROUP", 0, true)], &[]);
                        let _ = socket.send_to(&resp, peer).await;
                    }
                    _ => {}
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn fake_responder_lookup() {
        let good = fake_responder(0).await;
        let silent = fake_responder(1).await;
        let group = fake_responder(2).await;
        let cfg = NbnsConfig {
            per_query: Duration::from_millis(300),
            ..NbnsConfig::default()
        };
        let (queried, found) = status_with(&[good, silent, group, good], &cfg).await;
        assert_eq!(queried, 3);
        assert_eq!(found.len(), 2, "{found:?}");
        let node = &found[&good];
        assert_eq!(node.hostname.as_deref(), Some("RUDIGER"));
        assert!(node.unit_id_is_local());
        assert_eq!(found[&group].hostname, None);
    }

    #[tokio::test]
    async fn whole_pass_is_bounded() {
        let mut targets = Vec::new();
        for _ in 0..12 {
            targets.push(fake_responder(1).await);
        }
        let cfg = NbnsConfig {
            per_query: Duration::from_secs(1),
            total: Duration::from_millis(300),
            concurrency: 2,
        };
        let start = std::time::Instant::now();
        let (queried, found) = status_with(&targets, &cfg).await;
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(queried, 12);
        assert!(found.is_empty());
    }

    proptest! {
        #[test]
        fn parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1500), id in any::<u16>()) {
            if let Some(node) = parse_node_status(&bytes, id) {
                for name in node.hostname.iter().chain(node.workgroup.iter()) {
                    prop_assert!(!name.is_empty() && name.len() <= MAX_NAME_LEN);
                    prop_assert!(name.bytes().all(|b| b.is_ascii_graphic()));
                }
            }
        }

        #[test]
        fn parser_never_panics_on_mutated_response(
            idx in 0usize..400, val in any::<u8>(), cut in 0usize..400,
        ) {
            let mut buf = synology();
            if idx < buf.len() {
                buf[idx] = val;
            }
            buf.truncate(cut.max(1));
            let _ = parse_node_status(&buf, ID);
        }
    }
}
