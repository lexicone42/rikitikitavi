//! Reverse DNS (PTR) lookups of LAN addresses against local nameservers only.
//!
//! Queries go to RFC 1918 nameservers only: the default gateway and private
//! `nameserver` entries from the resolver config. Each lookup tries RD=0, then
//! RD=1 only when no server gave a definite answer. Response names are untrusted
//! and pass through [`clean_ptr_name`].

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

/// Longest accepted name, in bytes (one DNS label).
pub const MAX_NAME_LEN: usize = 63;

/// Most targets looked up in one pass.
pub const MAX_TARGETS: usize = 4096;

/// Most nameservers queried per target.
pub const MAX_NAMESERVERS: usize = 3;

/// Suffixes stripped from every PTR name.
const LOCAL_SUFFIXES: &[&str] = &[".localdomain", ".home.arpa", ".local", ".home", ".lan"];

/// Name tokens that carry no identity when paired with IP octets.
const GENERIC_WORDS: &[&str] = &[
    "addr", "address", "adsl", "client", "cpe", "device", "dhcp", "dsl", "dyn", "dynamic", "h",
    "host", "ip", "lease", "node", "pool", "ppp", "static", "unknown", "user", "x",
];

/// Whole names rejected outright.
const REJECTED_NAMES: &[&str] = &[
    "localhost",
    "localdomain",
    "unknown",
    "none",
    "null",
    "local",
    "lan",
    "home",
    "arpa",
];

/// Timing and concurrency for a lookup pass.
#[derive(Debug, Clone)]
pub struct RdnsConfig {
    /// Timeout for one query to one server.
    pub per_query: Duration,
    /// Bound on the whole pass; unfinished lookups are dropped.
    pub total: Duration,
    /// Lookups in flight.
    pub concurrency: usize,
    /// Extra domain suffixes to strip (resolver `search`/`domain`).
    pub strip_suffixes: Vec<String>,
}

impl Default for RdnsConfig {
    fn default() -> Self {
        Self {
            per_query: Duration::from_secs(1),
            total: Duration::from_secs(6),
            concurrency: 16,
            strip_suffixes: Vec::new(),
        }
    }
}

/// Result of a lookup pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RdnsOutcome {
    /// Cleaned names by address.
    pub names: HashMap<Ipv4Addr, String>,
    /// Targets looked up.
    pub queried: usize,
    /// Names obtained with RD=0.
    pub via_rd0: usize,
    /// Names obtained only after the RD=1 fallback.
    pub via_rd1: usize,
}

/// Default gateway followed by private `nameserver` entries of `resolv_conf`,
/// deduplicated, RFC 1918 only, at most [`MAX_NAMESERVERS`].
#[must_use]
pub fn local_nameservers(gateway: Option<Ipv4Addr>, resolv_conf: &str) -> Vec<Ipv4Addr> {
    let from_conf =
        resolv_conf_entries(resolv_conf, "nameserver").filter_map(|v| v.parse::<Ipv4Addr>().ok());
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for ip in gateway.into_iter().chain(from_conf) {
        if ip.is_private() && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out.truncate(MAX_NAMESERVERS);
    out
}

/// Domains from `domain` and `search` lines of `resolv_conf`, lowercased.
#[must_use]
pub fn search_domains(resolv_conf: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in
        resolv_conf_entries(resolv_conf, "domain").chain(resolv_conf_entries(resolv_conf, "search"))
    {
        let d = d.trim_matches('.').to_ascii_lowercase();
        if !d.is_empty() && d.len() <= 253 && !out.contains(&d) {
            out.push(d);
        }
    }
    out
}

/// Contents of `/etc/resolv.conf`; empty when unreadable.
#[must_use]
pub fn system_resolv_conf() -> String {
    std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default()
}

fn resolv_conf_entries<'a>(text: &'a str, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    text.lines().flat_map(move |line| {
        let line = line.split(['#', ';']).next().unwrap_or("");
        let mut words = line.split_whitespace();
        let values: Vec<&str> = if words.next() == Some(key) {
            words.collect()
        } else {
            Vec::new()
        };
        values
    })
}

/// PTR names for `targets` from `nameservers` on port 53. Non-RFC 1918
/// nameservers and targets are dropped before any packet is sent.
pub async fn reverse_lookup(
    nameservers: &[Ipv4Addr],
    targets: &[Ipv4Addr],
    cfg: &RdnsConfig,
) -> RdnsOutcome {
    let servers: Vec<SocketAddr> = nameservers
        .iter()
        .filter(|ip| ip.is_private())
        .take(MAX_NAMESERVERS)
        .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 53))
        .collect();
    let targets: Vec<Ipv4Addr> = targets
        .iter()
        .copied()
        .filter(Ipv4Addr::is_private)
        .collect();
    lookup_with(&servers, &targets, cfg).await
}

async fn lookup_with(
    servers: &[SocketAddr],
    targets: &[Ipv4Addr],
    cfg: &RdnsConfig,
) -> RdnsOutcome {
    let mut seen = HashSet::new();
    let targets: Vec<Ipv4Addr> = targets
        .iter()
        .copied()
        .filter(|ip| seen.insert(*ip))
        .take(MAX_TARGETS)
        .collect();
    let mut outcome = RdnsOutcome {
        queried: targets.len(),
        ..RdnsOutcome::default()
    };
    if servers.is_empty() || targets.is_empty() {
        return outcome;
    }

    let servers: Arc<[SocketAddr]> = servers.into();
    let suffixes: Arc<[String]> = cfg.strip_suffixes.clone().into();
    let semaphore = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
    let per_query = cfg.per_query;
    let deadline = Instant::now() + cfg.total;

    let mut set = JoinSet::new();
    for ip in targets {
        let servers = Arc::clone(&servers);
        let suffixes = Arc::clone(&suffixes);
        let semaphore = Arc::clone(&semaphore);
        set.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok()?;
            lookup_one(&servers, ip, per_query, &suffixes)
                .await
                .map(|(name, rd1)| (ip, name, rd1))
        });
    }

    while let Ok(Some(joined)) = tokio::time::timeout_at(deadline, set.join_next()).await {
        if let Ok(Some((ip, name, rd1))) = joined {
            if rd1 {
                outcome.via_rd1 += 1;
            } else {
                outcome.via_rd0 += 1;
            }
            outcome.names.insert(ip, name);
        }
    }
    outcome
}

/// Cleaned name and whether it came from the RD=1 fallback.
async fn lookup_one(
    servers: &[SocketAddr],
    ip: Ipv4Addr,
    per_query: Duration,
    suffixes: &[String],
) -> Option<(String, bool)> {
    let mut retry = false;
    for &server in servers {
        match query_once(server, ip, false, per_query).await {
            Reply::Name(raw) => {
                if let Some(name) = clean_ptr_name(&raw, ip, suffixes) {
                    return Some((name, false));
                }
            }
            Reply::NxDomain => {}
            Reply::NoAnswer => retry = true,
        }
    }
    if !retry {
        return None;
    }
    for &server in servers {
        if let Reply::Name(raw) = query_once(server, ip, true, per_query).await
            && let Some(name) = clean_ptr_name(&raw, ip, suffixes)
        {
            return Some((name, true));
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Reply {
    /// PTR target, labels joined with `.`.
    Name(String),
    NxDomain,
    /// Timeout, I/O error, error rcode, or no matching PTR record.
    NoAnswer,
}

async fn query_once(server: SocketAddr, ip: Ipv4Addr, rd: bool, timeout: Duration) -> Reply {
    let qname = Name::from(ip);
    let mut msg = Message::query();
    msg.metadata.recursion_desired = rd;
    msg.add_query(Query::query(qname.clone(), RecordType::PTR));
    let id = msg.metadata.id;
    let Ok(packet) = msg.to_vec() else {
        return Reply::NoAnswer;
    };

    let bind: SocketAddr = if server.ip().is_loopback() {
        (Ipv4Addr::LOCALHOST, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let exchange = async {
        let socket = UdpSocket::bind(bind).await.ok()?;
        socket.connect(server).await.ok()?;
        socket.send(&packet).await.ok()?;
        let mut buf = [0u8; 4096];
        loop {
            let n = socket.recv(&mut buf).await.ok()?;
            if let Some(reply) = parse_reply(&buf[..n], id, &qname) {
                return Some(reply);
            }
        }
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .ok()
        .flatten()
        .unwrap_or(Reply::NoAnswer)
}

/// `None` when `buf` is not a response to query `id` for `qname`.
fn parse_reply(buf: &[u8], id: u16, qname: &Name) -> Option<Reply> {
    let msg = Message::from_vec(buf).ok()?;
    let meta = &msg.metadata;
    if meta.id != id || meta.message_type != MessageType::Response || meta.op_code != OpCode::Query
    {
        return None;
    }
    let [query] = msg.queries.as_slice() else {
        return None;
    };
    if query.name() != qname || query.query_type() != RecordType::PTR {
        return None;
    }
    match meta.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => return Some(Reply::NxDomain),
        _ => return Some(Reply::NoAnswer),
    }
    let target = msg.answers.iter().find_map(|r| match &r.data {
        RData::PTR(ptr) if r.name == *qname => Some(&ptr.0),
        _ => None,
    });
    Some(
        target
            .and_then(name_text)
            .map_or(Reply::NoAnswer, Reply::Name),
    )
}

/// Labels joined with `.`; `None` if any label byte is not printable ASCII or is a `.`.
fn name_text(name: &Name) -> Option<String> {
    let mut out = String::new();
    for label in name {
        if label.is_empty() || !label.iter().all(|b| b.is_ascii_graphic() && *b != b'.') {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(std::str::from_utf8(label).ok()?);
        if out.len() > 253 {
            return None;
        }
    }
    Some(out)
}

/// Hostname from a raw PTR name, or `None` if it carries no identity.
///
/// Strips a trailing dot, [`LOCAL_SUFFIXES`] and `extra_suffixes`, then keeps the
/// first label. Rejects empty names, names over [`MAX_NAME_LEN`], characters
/// outside `[A-Za-z0-9_-]`, names without a letter, bare IPs, bare 12-hex MACs,
/// and names that encode `ip` (`192-168-1-5`, `ip-192-168-1-5`, `host-5`).
#[must_use]
pub fn clean_ptr_name(raw: &str, ip: Ipv4Addr, extra_suffixes: &[String]) -> Option<String> {
    if raw.len() > 253 {
        return None;
    }
    let mut name = raw.trim().trim_end_matches('.');
    if name.parse::<Ipv4Addr>().is_ok() {
        return None;
    }
    let extras: Vec<String> = extra_suffixes
        .iter()
        .map(|s| s.trim_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .map(|s| format!(".{s}"))
        .collect();
    let suffixes = LOCAL_SUFFIXES
        .iter()
        .copied()
        .chain(extras.iter().map(String::as_str));
    loop {
        let lower = name.to_ascii_lowercase();
        let Some(cut) = suffixes
            .clone()
            .filter(|s| lower.len() > s.len() && lower.ends_with(s))
            .map(str::len)
            .max()
        else {
            break;
        };
        name = &name[..name.len() - cut];
    }
    let full = name.to_ascii_lowercase();
    let label = name.split('.').next().unwrap_or("");

    if label.is_empty() || label.len() > MAX_NAME_LEN {
        return None;
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    if !label.bytes().any(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let lower = label.to_ascii_lowercase();
    if REJECTED_NAMES.contains(&lower.as_str())
        || is_bare_mac(&lower)
        || encodes_ip(&lower, ip)
        || encodes_ip(&full, ip)
    {
        return None;
    }
    Some(label.to_owned())
}

/// Exactly 12 hex digits once `-` and `_` are removed.
fn is_bare_mac(label: &str) -> bool {
    let hex: Vec<u8> = label.bytes().filter(|b| *b != b'-' && *b != b'_').collect();
    hex.len() == 12 && hex.iter().all(u8::is_ascii_hexdigit)
}

/// Numeric tokens spell `ip` (in order, reversed, a trailing run of octets, or
/// concatenated) and every other token is in [`GENERIC_WORDS`].
fn encodes_ip(label: &str, ip: Ipv4Addr) -> bool {
    let tokens = tokenize(label);
    let (numbers, words): (Vec<&str>, Vec<&str>) = tokens
        .iter()
        .partition(|t| t.bytes().all(|b| b.is_ascii_digit()));
    if numbers.is_empty() || !words.iter().all(|w| GENERIC_WORDS.contains(w)) {
        return false;
    }
    let octets: Vec<String> = ip.octets().iter().map(u8::to_string).collect();
    let numbers: Vec<String> = numbers
        .iter()
        .map(|n| n.trim_start_matches('0'))
        .map(|n| {
            if n.is_empty() {
                "0".to_owned()
            } else {
                n.to_owned()
            }
        })
        .collect();
    let reversed: Vec<String> = octets.iter().rev().cloned().collect();
    if numbers == reversed || octets.ends_with(&numbers) {
        return true;
    }
    if let [joined] = tokens
        .iter()
        .filter(|t| t.bytes().all(|b| b.is_ascii_digit()))
        .copied()
        .collect::<Vec<_>>()
        .as_slice()
    {
        let [a, b, c, d] = ip.octets();
        return *joined == format!("{a}{b}{c}{d}")
            || *joined == format!("{a:03}{b:03}{c:03}{d:03}");
    }
    false
}

/// Splits on non-alphanumerics and on letter/digit boundaries.
fn tokenize(label: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for part in label.split(|c: char| !c.is_ascii_alphanumeric()) {
        let mut start = 0;
        let bytes = part.as_bytes();
        for i in 1..bytes.len() {
            if bytes[i].is_ascii_digit() != bytes[i - 1].is_ascii_digit() {
                out.push(&part[start..i]);
                start = i;
            }
        }
        if start < part.len() {
            out.push(&part[start..]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::Record;
    use hickory_resolver::proto::rr::rdata::PTR;
    use proptest::prelude::*;

    const IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 5);

    fn clean(raw: &str) -> Option<String> {
        clean_ptr_name(raw, IP, &[])
    }

    #[test]
    fn strips_trailing_dot_and_local_suffixes() {
        assert_eq!(clean("Schlage.localdomain.").as_deref(), Some("Schlage"));
        assert_eq!(clean("U7Pro.lan").as_deref(), Some("U7Pro"));
        assert_eq!(clean("printer.local").as_deref(), Some("printer"));
        assert_eq!(clean("nas.home.arpa.").as_deref(), Some("nas"));
        assert_eq!(clean("tv.home").as_deref(), Some("tv"));
        assert_eq!(clean("MyQ-6C7.LOCALDOMAIN").as_deref(), Some("MyQ-6C7"));
        assert_eq!(clean("a.lan.localdomain").as_deref(), Some("a"));
    }

    #[test]
    fn strips_search_domain_and_keeps_first_label() {
        let extra = vec!["attlocal.net.".to_owned()];
        assert_eq!(
            clean_ptr_name("cam.attlocal.net.", IP, &extra).as_deref(),
            Some("cam")
        );
        assert_eq!(clean("host1.corp.example.com").as_deref(), Some("host1"));
    }

    #[test]
    fn rejects_synthetic_names() {
        for raw in [
            "192-168-1-5",
            "ip-192-168-1-5.localdomain.",
            "host-5",
            "dhcp-1-5.lan",
            "5-1-168-192",
            "ip192-168-1-5",
            "192168001005",
            "client-192.168.1.5",
            "x192-168-001-005",
        ] {
            assert_eq!(clean(raw), None, "{raw}");
        }
    }

    #[test]
    fn keeps_names_with_numbers_that_are_not_the_ip() {
        assert_eq!(clean("host-6").as_deref(), Some("host-6"));
        assert_eq!(clean("HS105").as_deref(), Some("HS105"));
        assert_eq!(clean("printer-5").as_deref(), Some("printer-5"));
        assert_eq!(
            clean("USW-Pro-Max-16-PoE").as_deref(),
            Some("USW-Pro-Max-16-PoE")
        );
    }

    #[test]
    fn rejects_bare_ip_mac_and_empty() {
        for raw in [
            "",
            ".",
            "192.168.1.5",
            "10.0.0.1.",
            "00178826d932.localdomain.",
            "00-17-88-26-d9-32",
            "12345",
            "localdomain",
            "localhost.localdomain",
            ".localdomain",
        ] {
            assert_eq!(clean(raw), None, "{raw:?}");
        }
        assert!(clean("LC02032824WF-04A16F104AD4").is_some());
    }

    #[test]
    fn rejects_bad_characters_and_long_names() {
        assert_eq!(clean("bad name"), None);
        assert_eq!(clean("tab\there"), None);
        assert_eq!(clean("es\u{1b}[31m"), None);
        assert_eq!(clean("caf\u{e9}"), None);
        assert_eq!(clean(&"a".repeat(MAX_NAME_LEN + 1)), None);
        assert!(clean(&"a".repeat(MAX_NAME_LEN)).is_some());
    }

    #[test]
    fn nameservers_are_private_only() {
        let conf = "# x\nnameserver 8.8.8.8\nnameserver 192.168.1.1\nnameserver 10.0.0.53 ; c\n\
                    nameserver 127.0.0.53\nnameserver fe80::1%eth0\nnameserver 172.16.0.2\n";
        assert_eq!(
            local_nameservers(Some(Ipv4Addr::new(192, 168, 1, 1)), conf),
            vec![
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(10, 0, 0, 53),
                Ipv4Addr::new(172, 16, 0, 2),
            ]
        );
        assert!(
            local_nameservers(Some(Ipv4Addr::new(1, 1, 1, 1)), "nameserver 9.9.9.9").is_empty()
        );
    }

    #[test]
    fn search_domains_from_domain_and_search() {
        let conf = "domain LocalDomain\nsearch lan. example.com\n#search no\n";
        assert_eq!(
            search_domains(conf),
            vec!["localdomain", "lan", "example.com"]
        );
    }

    #[tokio::test]
    async fn public_nameservers_and_targets_are_never_queried() {
        let out = reverse_lookup(&[Ipv4Addr::new(8, 8, 8, 8)], &[IP], &RdnsConfig::default()).await;
        assert!(out.names.is_empty());
        let out = reverse_lookup(
            &[Ipv4Addr::new(192, 168, 1, 1)],
            &[Ipv4Addr::new(8, 8, 8, 8)],
            &RdnsConfig::default(),
        )
        .await;
        assert_eq!(out.queried, 0);
    }

    fn ptr_response(req: &Message, target: &str) -> Message {
        let mut resp = Message::response(req.metadata.id, OpCode::Query);
        resp.metadata.recursion_desired = req.metadata.recursion_desired;
        resp.add_queries(req.queries.iter().cloned());
        let qname = req.queries[0].name().clone();
        resp.add_answer(Record::from_rdata(
            qname,
            60,
            RData::PTR(PTR(Name::from_ascii(target).unwrap())),
        ));
        resp
    }

    /// Fake resolver on 127.0.0.1: `.5` answers only with RD=1 (REFUSED otherwise),
    /// `.6` answers RD=0 after a forged reply, `.7` is NXDOMAIN, `.8` is silent,
    /// `.9` returns a synthetic name.
    async fn fake_server() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(req) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let first = req.queries[0].name().iter().next().unwrap().to_vec();
                let rd = req.metadata.recursion_desired;
                let resp = match first.as_slice() {
                    b"5" if rd => ptr_response(&req, "rd1-only.localdomain."),
                    b"5" => {
                        Message::error_msg(req.metadata.id, OpCode::Query, ResponseCode::Refused)
                            .add_queries(req.queries.iter().cloned())
                            .clone()
                    }
                    b"6" => {
                        let mut forged = ptr_response(&req, "forged.lan.");
                        forged.metadata.id = req.metadata.id.wrapping_add(1);
                        let _ = socket.send_to(&forged.to_vec().unwrap(), peer).await;
                        ptr_response(&req, "MyQ-6C7.localdomain.")
                    }
                    b"7" => {
                        Message::error_msg(req.metadata.id, OpCode::Query, ResponseCode::NXDomain)
                            .add_queries(req.queries.iter().cloned())
                            .clone()
                    }
                    b"9" => ptr_response(&req, "ip-192-168-1-9.localdomain."),
                    _ => continue,
                };
                let _ = socket.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn fake_server_lookup() {
        let server = fake_server().await;
        let targets: Vec<Ipv4Addr> = (5..=9).map(|d| Ipv4Addr::new(192, 168, 1, d)).collect();
        let cfg = RdnsConfig {
            per_query: Duration::from_millis(300),
            total: Duration::from_secs(5),
            ..RdnsConfig::default()
        };
        let out = lookup_with(&[server], &targets, &cfg).await;
        assert_eq!(out.queried, 5);
        assert_eq!(out.names.len(), 2, "{:?}", out.names);
        assert_eq!(out.names[&Ipv4Addr::new(192, 168, 1, 5)], "rd1-only");
        assert_eq!(out.names[&Ipv4Addr::new(192, 168, 1, 6)], "MyQ-6C7");
        assert_eq!((out.via_rd0, out.via_rd1), (1, 1));
    }

    #[tokio::test]
    async fn whole_pass_is_bounded() {
        let server = fake_server().await;
        let targets: Vec<Ipv4Addr> = (10..74).map(|d| Ipv4Addr::new(10, 8, 0, d)).collect();
        let cfg = RdnsConfig {
            per_query: Duration::from_secs(1),
            total: Duration::from_millis(400),
            concurrency: 4,
            strip_suffixes: Vec::new(),
        };
        let start = std::time::Instant::now();
        let out = lookup_with(&[server], &targets, &cfg).await;
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(out.names.is_empty());
    }

    #[test]
    fn parse_reply_rejects_mismatched_question() {
        let mut req = Message::query();
        req.add_query(Query::query(Name::from(IP), RecordType::PTR));
        let resp = ptr_response(&req, "x.lan.");
        let bytes = resp.to_vec().unwrap();
        let other = Name::from(Ipv4Addr::new(192, 168, 1, 6));
        assert_eq!(parse_reply(&bytes, req.metadata.id, &other), None);
        assert_eq!(
            parse_reply(&bytes, req.metadata.id, &Name::from(IP)),
            Some(Reply::Name("x.lan".to_owned()))
        );
        assert_eq!(parse_reply(&[0u8; 3], 0, &other), None);
    }

    proptest! {
        #[test]
        fn clean_never_panics_or_emits_control_chars(
            raw in "\\PC{0,80}|[ -~]{0,300}|[\\x00-\\x1f]{0,10}",
            octets in any::<[u8; 4]>(),
            extra in proptest::collection::vec("[a-z.]{0,12}", 0..3),
        ) {
            if let Some(name) = clean_ptr_name(&raw, Ipv4Addr::from(octets), &extra) {
                prop_assert!(!name.is_empty() && name.len() <= MAX_NAME_LEN);
                prop_assert!(!name.chars().any(char::is_control));
                prop_assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
            }
        }

        #[test]
        fn parse_reply_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = parse_reply(&bytes, 0, &Name::from(IP));
        }
    }
}
