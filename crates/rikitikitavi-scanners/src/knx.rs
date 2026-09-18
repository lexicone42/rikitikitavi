//! KNXnet/IP building-automation discovery, UDP/3671.
//!
//! Sends `SEARCH_REQUEST` (0x0201) and `SEARCH_REQUEST_EXTENDED` (0x020B) — the
//! two read-only discovery verbs of the KNXnet/IP Core specification — to the
//! KNX discovery multicast group and to each discovered host, then parses the
//! `SEARCH_RESPONSE` DIBs. `CONNECT_REQUEST`, `DEVICE_CONFIGURATION_REQUEST` and
//! every other management verb are deliberately not implemented.
//!
//! CVE-2023-4346 (CWE-645, KEV 2026-07-15) lets an attacker on the installation
//! purge devices and set a BCU key, permanently locking any device that has
//! none. That precondition — Connection Authorization Option 1 with no BCU key
//! set — is a bus-level property and is carried in **no** KNXnet/IP datagram, so
//! this scanner reports attack surface, not a vulnerability verdict, and does not
//! attach the CVE id to any finding.

use async_trait::async_trait;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::config::ExclusionSet;
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, Remediation, ScanContext};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::Scanner;

/// KNXnet/IP discovery scanner.
pub struct KnxScanner;

/// IANA `knxnet` / KNXnet/IP.
const KNX_PORT: u16 = 3671;

/// KNX discovery multicast group (System Setup Multicast Address).
const KNX_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);

/// KNXnet/IP header: length 6, protocol version 1.0.
const HEADER: [u8; 2] = [0x06, 0x10];

const SEARCH_REQUEST: u16 = 0x0201;
const SEARCH_RESPONSE: u16 = 0x0202;
const SEARCH_REQUEST_EXTENDED: u16 = 0x020B;
const SEARCH_RESPONSE_EXTENDED: u16 = 0x020C;

/// HPAI host protocol code for IPv4 over UDP.
const HPAI_IPV4_UDP: u8 = 0x01;

/// DIB type codes used here.
const DIB_DEVICE_INFO: u8 = 0x01;
const DIB_SUPP_SVC_FAMILIES: u8 = 0x02;
const DIB_SECURED_SERVICE_FAMILIES: u8 = 0x06;
const DIB_TUNNELLING_INFO: u8 = 0x07;

/// Service family ids.
const FAMILY_DEVICE_MANAGEMENT: u8 = 0x03;
const FAMILY_TUNNELLING: u8 = 0x04;
const FAMILY_ROUTING: u8 = 0x05;
const FAMILY_SECURITY: u8 = 0x09;

/// Window for collecting replies after the searches are sent.
const COLLECT_WINDOW: Duration = Duration::from_secs(4);

/// Cap on replies processed per scan.
const MAX_REPLIES: usize = 128;

/// Receive buffer; a `SEARCH_RESPONSE` is ~70 bytes, the extended form larger.
const RECV_BUF: usize = 2048;

/// Friendly-name field width in the Device Info DIB.
const FRIENDLY_NAME_LEN: usize = 30;

// ── Request construction ────────────────────────────────────────────────────

/// Encode an HPAI (Host Protocol Address Information) structure.
const fn hpai(endpoint: SocketAddrV4) -> [u8; 8] {
    let ip = endpoint.ip().octets();
    let port = endpoint.port().to_be_bytes();
    [
        0x08,
        HPAI_IPV4_UDP,
        ip[0],
        ip[1],
        ip[2],
        ip[3],
        port[0],
        port[1],
    ]
}

/// The only two verbs this scanner may emit.
///
/// `build_search` takes this rather than a raw `u16`, so a frame carrying
/// `CONNECT_REQUEST`, a device-configuration verb or anything else assembled at
/// runtime is unrepresentable rather than merely absent from the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchVerb {
    Plain,
    Extended,
}

impl SearchVerb {
    const fn service(self) -> u16 {
        match self {
            Self::Plain => SEARCH_REQUEST,
            Self::Extended => SEARCH_REQUEST_EXTENDED,
        }
    }

    /// Both verbs, in the order they are sent.
    const ALL: [Self; 2] = [Self::Plain, Self::Extended];
}

/// Build a `SEARCH_REQUEST` / `SEARCH_REQUEST_EXTENDED` frame.
///
/// Both carry one HPAI naming the endpoint the response is sent to; the extended
/// form carries no search-request parameter blocks here, which asks for every
/// DIB the server has, including Secured Service Families.
fn build_search(verb: SearchVerb, discovery_endpoint: SocketAddrV4) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14);
    frame.extend_from_slice(&HEADER);
    frame.extend_from_slice(&verb.service().to_be_bytes());
    frame.extend_from_slice(&14u16.to_be_bytes());
    frame.extend_from_slice(&hpai(discovery_endpoint));
    frame
}

// ── Response parsing ────────────────────────────────────────────────────────

/// KNX medium codes (KNXnet/IP Core, Device Info DIB).
const fn medium_name(code: u8) -> &'static str {
    match code {
        0x02 => "TP1",
        0x04 => "PL110",
        0x10 => "RF",
        0x20 => "KNX IP",
        _ => "unknown medium",
    }
}

/// Service family labels.
const fn family_name(id: u8) -> &'static str {
    match id {
        0x02 => "Core",
        FAMILY_DEVICE_MANAGEMENT => "Device Management",
        FAMILY_TUNNELLING => "Tunnelling",
        FAMILY_ROUTING => "Routing",
        0x06 => "Remote Logging",
        0x07 => "Remote Configuration and Diagnosis",
        0x08 => "Object Server",
        FAMILY_SECURITY => "Security",
        _ => "unknown family",
    }
}

/// A KNXnet/IP server as it describes itself in a `SEARCH_RESPONSE`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct KnxServer {
    /// Control endpoint HPAI from the response.
    control_endpoint: Option<SocketAddrV4>,
    /// KNX medium code.
    medium: Option<u8>,
    /// Device status octet; bit 0 is programming mode.
    status: Option<u8>,
    /// Individual address, e.g. `1.1.0`.
    individual_address: Option<String>,
    /// Project installation identifier.
    project_id: Option<u16>,
    /// KNX serial number, hex.
    serial: Option<String>,
    /// Routing multicast address the server uses (0.0.0.0 when it does not route).
    routing_multicast: Option<Ipv4Addr>,
    /// MAC address from the DIB, lowercase colon form.
    mac: Option<String>,
    /// Friendly name, Latin-1 decoded and trimmed.
    friendly_name: Option<String>,
    /// Supported service families as `(id, version)`.
    families: Vec<(u8, u8)>,
    /// Secured service families as `(id, version)`; only the extended response
    /// carries this DIB.
    secured_families: Vec<(u8, u8)>,
    /// Tunnelling-info DIB present.
    tunnelling_dib: bool,
}

impl KnxServer {
    /// Whether the response identified the server at all.
    const fn identified(&self) -> bool {
        self.individual_address.is_some() || self.serial.is_some() || !self.families.is_empty()
    }

    /// Programming mode: bit 0 of the device status octet.
    fn programming_mode(&self) -> bool {
        self.status.is_some_and(|s| s & 0x01 != 0)
    }

    fn has_family(&self, id: u8) -> bool {
        self.families.iter().any(|(fid, _)| *fid == id)
    }

    /// Families that expose the installation to a peer: tunnelling, device
    /// management and routing.
    fn management_families(&self) -> Vec<u8> {
        [FAMILY_DEVICE_MANAGEMENT, FAMILY_TUNNELLING, FAMILY_ROUTING]
            .into_iter()
            .filter(|id| self.has_family(*id))
            .collect()
    }

    /// Whether anything in the response indicates KNX Secure.
    fn advertises_secure(&self) -> bool {
        !self.secured_families.is_empty() || self.has_family(FAMILY_SECURITY)
    }
}

/// Decode the 30-byte friendly name: Latin-1, NUL-terminated, controls dropped.
fn decode_friendly_name(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let name: String = bytes[..end]
        .iter()
        .map(|b| char::from(*b))
        .filter(|c| !c.is_control())
        .collect();
    let name = name.trim().to_owned();
    (!name.is_empty()).then_some(name)
}

/// Format a KNX individual address: 4-bit area, 4-bit line, 8-bit device.
fn format_individual_address(raw: [u8; 2]) -> String {
    format!("{}.{}.{}", raw[0] >> 4, raw[0] & 0x0F, raw[1])
}

/// Parse the Device Info DIB payload (everything after its length/type octets).
///
/// Layout: medium(1) status(1) individual address(2) project id(2) serial(6)
/// routing multicast(4) MAC(6) friendly name(30) = 52 octets.
fn parse_device_info(payload: &[u8], server: &mut KnxServer) {
    if payload.len() < 52 {
        return;
    }
    server.medium = Some(payload[0]);
    server.status = Some(payload[1]);
    server.individual_address = Some(format_individual_address([payload[2], payload[3]]));
    server.project_id = Some(u16::from_be_bytes([payload[4], payload[5]]));
    server.serial = Some(payload[6..12].iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    }));
    server.routing_multicast = Some(Ipv4Addr::new(
        payload[12],
        payload[13],
        payload[14],
        payload[15],
    ));
    server.mac = Some(
        payload[16..22]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    );
    server.friendly_name = decode_friendly_name(&payload[22..22 + FRIENDLY_NAME_LEN]);
}

/// Parse a service-families DIB payload into `(id, version)` pairs.
fn parse_service_families(payload: &[u8]) -> Vec<(u8, u8)> {
    let (pairs, _) = payload.as_chunks::<2>();
    pairs.iter().map(|p| (p[0], p[1])).collect()
}

/// Parse a `SEARCH_RESPONSE` or `SEARCH_RESPONSE_EXTENDED` frame.
///
/// Returns `None` for anything that is not a well-formed KNXnet/IP search
/// response, which also rejects our own looped-back `SEARCH_REQUEST`.
fn parse_search_response(frame: &[u8]) -> Option<KnxServer> {
    if frame.len() < 6 || frame[0] != HEADER[0] || frame[1] != HEADER[1] {
        return None;
    }
    let service = u16::from_be_bytes([frame[2], frame[3]]);
    if service != SEARCH_RESPONSE && service != SEARCH_RESPONSE_EXTENDED {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([frame[4], frame[5]]));
    // The declared length is authoritative; trailing bytes are ignored and a
    // truncated datagram is rejected.
    if total < 14 || total > frame.len() {
        return None;
    }
    let body = frame.get(6..total)?;

    let mut server = KnxServer::default();
    if body[0] == 0x08 && body[1] == HPAI_IPV4_UDP {
        let ip = Ipv4Addr::new(body[2], body[3], body[4], body[5]);
        let port = u16::from_be_bytes([body[6], body[7]]);
        server.control_endpoint = Some(SocketAddrV4::new(ip, port));
    }

    let mut pos = 8;
    while pos + 2 <= body.len() {
        let len = usize::from(body[pos]);
        let dib_type = body[pos + 1];
        // A zero or over-long structure length would not advance: stop.
        if len < 2 || pos + len > body.len() {
            break;
        }
        let payload = &body[pos + 2..pos + len];
        match dib_type {
            DIB_DEVICE_INFO => parse_device_info(payload, &mut server),
            DIB_SUPP_SVC_FAMILIES => server.families = parse_service_families(payload),
            DIB_SECURED_SERVICE_FAMILIES => {
                server.secured_families = parse_service_families(payload);
            }
            DIB_TUNNELLING_INFO => server.tunnelling_dib = true,
            _ => {}
        }
        pos += len;
    }

    server.identified().then_some(server)
}

// ── Findings ────────────────────────────────────────────────────────────────

/// Human label for the server, for finding text.
fn server_label(server: &KnxServer) -> String {
    server
        .friendly_name
        .clone()
        .unwrap_or_else(|| "an unnamed KNXnet/IP server".to_owned())
}

/// Evidence line: what the response actually carried.
fn evidence(server: &KnxServer) -> String {
    let mut parts = vec![format!(
        "SEARCH_RESPONSE from {}",
        server.control_endpoint.map_or_else(
            || "an undeclared control endpoint".to_owned(),
            |e| e.to_string()
        )
    )];
    if let Some(name) = &server.friendly_name {
        parts.push(format!("name={name}"));
    }
    if let Some(addr) = &server.individual_address {
        parts.push(format!("individual address={addr}"));
    }
    if let Some(medium) = server.medium {
        parts.push(format!("medium={}", medium_name(medium)));
    }
    if let Some(serial) = &server.serial {
        parts.push(format!("serial={serial}"));
    }
    if !server.families.is_empty() {
        let families: Vec<String> = server
            .families
            .iter()
            .map(|(id, version)| format!("{} v{version}", family_name(*id)))
            .collect();
        parts.push(format!("service families: {}", families.join(", ")));
    }
    if !server.secured_families.is_empty() {
        let secured: Vec<String> = server
            .secured_families
            .iter()
            .map(|(id, _)| family_name(*id).to_owned())
            .collect();
        parts.push(format!("secured families: {}", secured.join(", ")));
    }
    parts.join("; ")
}

fn knx_references() -> Vec<String> {
    refs![
        "https://www.cisa.gov/news-events/ics-advisories/icsa-23-236-01",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-4346",
        "https://www.knx.org/knx-en/for-professionals/get-started/knx-secure/",
        "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt",
    ]
}

fn segmentation_remediation() -> Remediation {
    Remediation {
        description: "KNXnet/IP discovery and tunnelling are reachable by any host on \
                      this network. Plain KNXnet/IP has no authentication, so reachability \
                      is the control."
            .to_owned(),
        steps: vec![
            "Never port-forward UDP 3671 and confirm the router has no UPnP mapping for it."
                .to_owned(),
            "Put the KNX IP interface or router on its own VLAN and allow UDP 3671 only \
             from the visualisation or automation hosts that need it."
                .to_owned(),
            "Set the BCU Key in the ETS project for every device, as ICSA-23-236-01 \
             requires; a device with no BCU key set can be locked permanently by anyone \
             who reaches the installation."
                .to_owned(),
            "Where the hardware supports it, enable KNX Data Secure and IP Secure so \
             tunnelling and routing require authentication."
                .to_owned(),
        ],
        effort: Some("1-2 hours (ETS project change)".to_owned()),
    }
}

/// Presence: a KNXnet/IP server answered discovery.
fn presence_finding(ip: IpAddr, server: &KnxServer) -> Finding {
    let mut hint = DeviceHint::new()
        .with_device_type(DeviceType::Hub)
        .with_device_subtype("knx_gateway");
    if let Some(name) = &server.friendly_name {
        hint = hint.with_model(name.clone());
    }

    Finding::new(
        "knx",
        &format!("KNXnet/IP building-automation gateway on {ip}:{KNX_PORT}"),
        &format!(
            "The host at {ip}:{KNX_PORT} answered a KNXnet/IP SEARCH_REQUEST and \
             identified itself as {} on medium {}, individual address {}. A KNXnet/IP \
             server bridges this IP network to the KNX bus that operates lighting, \
             blinds, heating and often door hardware. Discovery itself is unauthenticated \
             by design and leaks the installation's topology, serial number and MAC. \
             Treat the gateway as a control plane for the building and restrict who can \
             reach it.",
            server_label(server),
            server.medium.map_or("an unreported medium", medium_name),
            server
                .individual_address
                .as_deref()
                .unwrap_or("not reported"),
        ),
        Severity::Info,
    )
    .with_confidence(Confidence::Confirmed)
    .with_ip(ip)
    .with_port(KNX_PORT)
    .with_service("KNXnet/IP")
    .with_evidence(evidence(server))
    .with_remediation(segmentation_remediation())
    .with_references(knx_references())
    .with_device_hint(hint)
}

/// Management services offered without any KNX Secure indication.
///
/// Attack surface, not a verdict: whether Connection Authorization Option 1 is in
/// use with no BCU key set (the CVE-2023-4346 precondition) is a bus-level
/// property that no KNXnet/IP datagram carries.
fn unsecured_services_finding(ip: IpAddr, server: &KnxServer) -> Option<Finding> {
    let families = server.management_families();
    if families.is_empty() || server.advertises_secure() {
        return None;
    }
    let names: Vec<&str> = families.iter().map(|id| family_name(*id)).collect();

    Some(
        Finding::new(
            "knx",
            &format!("KNXnet/IP gateway offers unsecured management services on {ip}"),
            &format!(
                "The KNXnet/IP server at {ip}:{KNX_PORT} advertises the {} service \
                 {} and advertised no secured service families, so tunnelling and \
                 management connections to the KNX bus are available to any host that \
                 can reach UDP {KNX_PORT}. Plain KNXnet/IP carries no authentication: a \
                 peer that opens a tunnel can read and write group addresses, which on a \
                 typical installation means lighting, blinds, HVAC and any door hardware \
                 on the bus. Note what this scan cannot see: CVE-2023-4346 (CISA KEV) \
                 additionally requires devices using Connection Authorization Option 1 \
                 with no BCU key set, which is a bus-level property carried in no \
                 KNXnet/IP datagram — so this finding reports reachable attack surface, \
                 not that the installation is vulnerable. Confirm BCU keys in the ETS \
                 project.",
                names.join(" and "),
                if names.len() == 1 {
                    "family"
                } else {
                    "families"
                },
            ),
            Severity::Low,
        )
        .with_confidence(Confidence::Inferred)
        .with_ip(ip)
        .with_port(KNX_PORT)
        .with_service("KNXnet/IP")
        .with_cwe("CWE-306")
        .with_evidence(evidence(server))
        .with_remediation(segmentation_remediation())
        .with_references(knx_references()),
    )
}

/// Programming mode left on: bit 0 of the device status octet.
fn programming_mode_finding(ip: IpAddr, server: &KnxServer) -> Option<Finding> {
    if !server.programming_mode() {
        return None;
    }
    Some(
        Finding::new(
            "knx",
            &format!("KNX device left in programming mode on {ip}"),
            &format!(
                "The KNXnet/IP server at {ip}:{KNX_PORT} reports programming mode active \
                 in its device status. Programming mode is the commissioning state ETS \
                 uses to assign an individual address and download an application; it is \
                 meant to be switched on at the device for the few minutes a download \
                 takes. While it is on, any commissioning tool that can reach the \
                 installation can readdress or reprogram this device. Press the \
                 programming button to clear it.",
            ),
            Severity::Medium,
        )
        .with_confidence(Confidence::Confirmed)
        .with_ip(ip)
        .with_port(KNX_PORT)
        .with_service("KNXnet/IP")
        .with_cwe("CWE-284")
        .with_evidence(evidence(server))
        .with_remediation(Remediation {
            description: "Clear programming mode on the device and restrict who can reach \
                          the KNX installation."
                .to_owned(),
            steps: vec![
                "Press the programming button on the device so the programming LED goes out."
                    .to_owned(),
                "Confirm in ETS that no commissioning session is in progress.".to_owned(),
                "Keep UDP 3671 off general-purpose network segments.".to_owned(),
            ],
            effort: Some("5 minutes".to_owned()),
        })
        .with_references(knx_references()),
    )
}

/// All findings for one answering server.
fn findings_for(ip: IpAddr, server: &KnxServer) -> Vec<Finding> {
    let mut findings = vec![presence_finding(ip, server)];
    findings.extend(unsecured_services_finding(ip, server));
    findings.extend(programming_mode_finding(ip, server));
    findings
}

// ── Probe ───────────────────────────────────────────────────────────────────

/// Local IPv4 endpoint a KNX server should send its response to.
///
/// The `SEARCH_RESPONSE` goes to the HPAI in the request, so it has to carry a
/// real address. A connected throwaway socket names the interface the kernel
/// would use for the group; the probe socket is then bound to that address.
fn local_endpoint(group: Ipv4Addr) -> Option<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    probe.connect(SocketAddr::from((group, KNX_PORT))).ok()?;
    match probe.local_addr().ok()? {
        SocketAddr::V4(addr) => Some(*addr.ip()),
        SocketAddr::V6(_) => None,
    }
}

/// Bind the probe socket and return it with its own route-back endpoint.
async fn bind_probe_socket() -> Option<(UdpSocket, SocketAddrV4)> {
    let local_ip = local_endpoint(KNX_GROUP)?;
    let socket = UdpSocket::bind((local_ip, 0)).await.ok()?;
    if let Err(e) = socket.join_multicast_v4(KNX_GROUP, local_ip) {
        tracing::debug!("could not join the KNX discovery group: {e}");
    }
    let SocketAddr::V4(local) = socket.local_addr().ok()? else {
        return None;
    };
    Some((socket, local))
}

/// Send both search verbs to the group and to each target, then collect replies.
async fn discover(targets: &[IpAddr], exclusions: &ExclusionSet) -> Vec<(IpAddr, KnxServer)> {
    let mut results: Vec<(IpAddr, KnxServer)> = Vec::new();
    let Some((socket, local)) = bind_probe_socket().await else {
        tracing::warn!("could not bind a KNXnet/IP probe socket");
        return results;
    };

    let frames = SearchVerb::ALL.map(|verb| build_search(verb, local));
    let group = SocketAddr::from((KNX_GROUP, KNX_PORT));
    for frame in &frames {
        if let Err(e) = socket.send_to(frame, group).await {
            tracing::debug!("could not send the KNX multicast search: {e}");
        }
        for &ip in targets {
            // Defence in depth: `scan` pre-filters, and no excluded host is
            // probed even if a caller passes one.
            if exclusions.excludes_ip(ip) {
                continue;
            }
            if let Err(e) = socket.send_to(frame, SocketAddr::new(ip, KNX_PORT)).await {
                tracing::debug!(%ip, "could not send the KNX search: {e}");
            }
        }
    }

    let deadline = Instant::now() + COLLECT_WINDOW;
    let mut best: Vec<(IpAddr, KnxServer)> = Vec::new();
    let mut seen: HashSet<IpAddr> = HashSet::new();
    let mut buf = vec![0u8; RECV_BUF];
    while best.len() < MAX_REPLIES {
        let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
        else {
            break;
        };
        let ip = from.ip();
        if exclusions.excludes_ip(ip) {
            continue;
        }
        let Some(chunk) = buf.get(..n) else { continue };
        let Some(server) = parse_search_response(chunk) else {
            continue;
        };
        // Two searches per host: keep the richer answer, which is the extended
        // one when the server implements it.
        if seen.insert(ip) {
            best.push((ip, server));
        } else if let Some(slot) = best.iter_mut().find(|(seen_ip, _)| *seen_ip == ip)
            && server.secured_families.len() > slot.1.secured_families.len()
        {
            slot.1 = server;
        }
    }

    results.extend(best);
    results
}

#[async_trait]
impl Scanner for KnxScanner {
    fn id(&self) -> &'static str {
        "knx"
    }

    fn name(&self) -> &'static str {
        "KNXnet/IP Building Automation"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running KNXnet/IP discovery scan");
        let mut findings = Vec::new();

        // Application-layer datagrams: Active intensity and above only.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping KNXnet/IP scan in quick scan mode");
            return Ok(findings);
        }

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "knx".to_owned(),
                message: e.to_string(),
            })?;

        // UDP/3671 is invisible to the TCP sweep, so every discovered host is
        // searched directly alongside the multicast search.
        let targets: Vec<IpAddr> = ctx
            .discovered_devices
            .iter()
            .filter(|d| !exclusions.excludes_device(d))
            .map(|d| d.ip)
            .collect();

        let replies = discover(&targets, &exclusions).await;
        tracing::info!(reply_count = replies.len(), "KNXnet/IP replies received");

        for (ip, server) in &replies {
            findings.extend(findings_for(*ip, server));
        }

        tracing::info!(
            findings_count = findings.len(),
            "KNXnet/IP discovery scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        10
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn local() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 50123)
    }

    /// Build a `SEARCH_RESPONSE` around the given DIB bytes.
    fn response_frame(service: u16, dibs: &[u8]) -> Vec<u8> {
        let total = 6 + 8 + dibs.len();
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&HEADER);
        frame.extend_from_slice(&service.to_be_bytes());
        frame.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        frame.extend_from_slice(&hpai(SocketAddrV4::new(
            Ipv4Addr::new(192, 168, 1, 30),
            KNX_PORT,
        )));
        frame.extend_from_slice(dibs);
        frame
    }

    /// Device Info DIB shaped after a real KNX IP interface.
    fn device_info_dib(status: u8) -> Vec<u8> {
        let mut dib = vec![0x36, DIB_DEVICE_INFO, 0x02, status, 0x11, 0x00, 0x00, 0x01];
        dib.extend_from_slice(&[0x00, 0xC5, 0x01, 0x02, 0x03, 0x04]); // serial
        dib.extend_from_slice(&[224, 0, 23, 12]); // routing multicast
        dib.extend_from_slice(&[0x00, 0x0E, 0x8C, 0x11, 0x22, 0x33]); // MAC
        let mut name = b"KNX IP Interface 730".to_vec();
        name.resize(FRIENDLY_NAME_LEN, 0);
        dib.extend_from_slice(&name);
        assert_eq!(dib.len(), 0x36);
        dib
    }

    fn families_dib(kind: u8, families: &[(u8, u8)]) -> Vec<u8> {
        let mut dib = vec![u8::try_from(2 + families.len() * 2).unwrap(), kind];
        for (id, version) in families {
            dib.push(*id);
            dib.push(*version);
        }
        dib
    }

    fn full_response(status: u8) -> Vec<u8> {
        let mut dibs = device_info_dib(status);
        dibs.extend(families_dib(
            DIB_SUPP_SVC_FAMILIES,
            &[
                (0x02, 2),
                (FAMILY_DEVICE_MANAGEMENT, 2),
                (FAMILY_TUNNELLING, 2),
            ],
        ));
        response_frame(SEARCH_RESPONSE, &dibs)
    }

    fn ip() -> IpAddr {
        IpAddr::from([192, 168, 1, 30])
    }

    // ── Request construction ────────────────────────────────────────

    #[test]
    fn search_request_matches_the_wire_format() {
        assert_eq!(
            build_search(SearchVerb::Plain, local()),
            vec![
                0x06, 0x10, 0x02, 0x01, 0x00, 0x0E, 0x08, 0x01, 192, 168, 1, 10, 0xC3, 0xCB
            ]
        );
    }

    #[test]
    fn extended_search_differs_only_in_the_service_type() {
        let plain = build_search(SearchVerb::Plain, local());
        let extended = build_search(SearchVerb::Extended, local());
        assert_eq!(&extended[2..4], &[0x02, 0x0B]);
        assert_eq!(plain[4..], extended[4..]);
    }

    #[test]
    fn only_search_verbs_are_ever_built() {
        // `build_search` takes a SearchVerb, so no other service type can be
        // assembled at runtime — the grep below only guards the constants.
        for verb in SearchVerb::ALL {
            let frame = build_search(verb, local());
            let service = u16::from_be_bytes([frame[2], frame[3]]);
            assert!(service == SEARCH_REQUEST || service == SEARCH_REQUEST_EXTENDED);
            assert_eq!(service, verb.service());
        }
        assert_eq!(SearchVerb::ALL.len(), 2);
        // Needles are split so this file contains each spelling only once.
        let src = include_str!("knx.rs");
        let connect = concat!("0x02", "05");
        let device_config = concat!("0x03", "10");
        assert!(!src.contains(connect), "a CONNECT_REQUEST constant exists");
        assert!(
            !src.contains(device_config),
            "a DEVICE_CONFIGURATION_REQUEST constant exists"
        );
    }

    // ── Response parsing ────────────────────────────────────────────

    #[test]
    fn parses_a_full_search_response() {
        let server = parse_search_response(&full_response(0x00)).unwrap();
        assert_eq!(
            server.control_endpoint,
            Some(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 30), KNX_PORT))
        );
        assert_eq!(server.medium, Some(0x02));
        assert_eq!(server.individual_address.as_deref(), Some("1.1.0"));
        assert_eq!(server.project_id, Some(1));
        assert_eq!(server.serial.as_deref(), Some("00c501020304"));
        assert_eq!(server.mac.as_deref(), Some("00:0e:8c:11:22:33"));
        assert_eq!(
            server.friendly_name.as_deref(),
            Some("KNX IP Interface 730")
        );
        assert_eq!(
            server.families,
            vec![
                (0x02, 2),
                (FAMILY_DEVICE_MANAGEMENT, 2),
                (FAMILY_TUNNELLING, 2)
            ]
        );
        assert!(!server.programming_mode());
    }

    #[test]
    fn programming_mode_reads_bit_zero() {
        let server = parse_search_response(&full_response(0x01)).unwrap();
        assert!(server.programming_mode());
        let server = parse_search_response(&full_response(0x02)).unwrap();
        assert!(!server.programming_mode());
    }

    #[test]
    fn parses_secured_service_families_from_the_extended_response() {
        let mut dibs = device_info_dib(0x00);
        dibs.extend(families_dib(
            DIB_SUPP_SVC_FAMILIES,
            &[(0x02, 2), (FAMILY_TUNNELLING, 2), (FAMILY_SECURITY, 1)],
        ));
        dibs.extend(families_dib(
            DIB_SECURED_SERVICE_FAMILIES,
            &[(FAMILY_TUNNELLING, 1)],
        ));
        let server = parse_search_response(&response_frame(SEARCH_RESPONSE_EXTENDED, &dibs))
            .expect("extended response parses");
        assert_eq!(server.secured_families, vec![(FAMILY_TUNNELLING, 1)]);
        assert!(server.advertises_secure());
    }

    #[test]
    fn rejects_non_knx_and_non_search_frames() {
        assert!(parse_search_response(b"").is_none());
        assert!(parse_search_response(b"HTTP/1.1 200 OK\r\n\r\n").is_none());
        // Right header, wrong service type (CONNECT_RESPONSE).
        let mut frame = full_response(0x00);
        frame[2] = 0x02;
        frame[3] = 0x06;
        assert!(parse_search_response(&frame).is_none());
    }

    #[test]
    fn rejects_our_own_search_request() {
        assert!(parse_search_response(&build_search(SearchVerb::Plain, local())).is_none());
    }

    #[test]
    fn rejects_a_truncated_frame() {
        let frame = full_response(0x00);
        assert!(parse_search_response(&frame[..frame.len() - 10]).is_none());
    }

    #[test]
    fn ignores_trailing_bytes_past_the_declared_length() {
        let mut frame = full_response(0x00);
        frame.extend_from_slice(&[0xFF; 32]);
        let server = parse_search_response(&frame).unwrap();
        assert_eq!(server.families.len(), 3);
    }

    #[test]
    fn stops_on_a_zero_length_dib() {
        let mut dibs = device_info_dib(0x00);
        dibs.extend_from_slice(&[0x00, DIB_SUPP_SVC_FAMILIES, 0x02, 0x02]);
        let server = parse_search_response(&response_frame(SEARCH_RESPONSE, &dibs)).unwrap();
        assert!(server.families.is_empty());
        assert_eq!(server.individual_address.as_deref(), Some("1.1.0"));
    }

    #[test]
    fn unknown_dib_types_are_skipped() {
        let mut dibs = device_info_dib(0x00);
        dibs.extend_from_slice(&[0x04, 0x55, 0xAA, 0xBB]);
        dibs.extend(families_dib(DIB_SUPP_SVC_FAMILIES, &[(FAMILY_ROUTING, 1)]));
        let server = parse_search_response(&response_frame(SEARCH_RESPONSE, &dibs)).unwrap();
        assert_eq!(server.families, vec![(FAMILY_ROUTING, 1)]);
    }

    #[test]
    fn short_device_info_leaves_fields_unset() {
        let mut dibs = vec![0x08, DIB_DEVICE_INFO, 0x02, 0x00, 0x11, 0x00, 0x00, 0x01];
        dibs.extend(families_dib(DIB_SUPP_SVC_FAMILIES, &[(0x02, 2)]));
        let server = parse_search_response(&response_frame(SEARCH_RESPONSE, &dibs)).unwrap();
        assert!(server.individual_address.is_none());
        assert_eq!(server.families, vec![(0x02, 2)]);
    }

    #[test]
    fn odd_family_payload_drops_the_trailing_octet() {
        assert_eq!(parse_service_families(&[0x02, 0x02, 0x04]), vec![(2, 2)]);
    }

    // ── Field decoding ──────────────────────────────────────────────

    #[test]
    fn individual_address_splits_area_line_device() {
        assert_eq!(format_individual_address([0x11, 0x00]), "1.1.0");
        assert_eq!(format_individual_address([0xFF, 0xFF]), "15.15.255");
        assert_eq!(format_individual_address([0x00, 0x00]), "0.0.0");
    }

    #[test]
    fn friendly_name_stops_at_nul_and_drops_controls() {
        let mut bytes = b"Gira KNX IP\x00junk".to_vec();
        bytes.resize(FRIENDLY_NAME_LEN, 0);
        assert_eq!(decode_friendly_name(&bytes).as_deref(), Some("Gira KNX IP"));
        assert!(decode_friendly_name(&[0u8; FRIENDLY_NAME_LEN]).is_none());
        assert_eq!(
            decode_friendly_name(b"a\x07b").as_deref(),
            Some("ab"),
            "control characters are dropped"
        );
    }

    #[test]
    fn friendly_name_decodes_latin1() {
        // 0xE4 is "a umlaut" in Latin-1, which is what the DIB encodes.
        assert_eq!(
            decode_friendly_name(&[b'B', 0xFC, b'r', b'o']).unwrap(),
            "Büro"
        );
    }

    // ── Findings ────────────────────────────────────────────────────

    #[test]
    fn presence_finding_is_info_and_confirmed() {
        let server = parse_search_response(&full_response(0x00)).unwrap();
        let finding = presence_finding(ip(), &server);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.affected_port, Some(KNX_PORT));
        assert!(
            finding
                .title
                .contains("KNXnet/IP building-automation gateway")
        );
        let hint = finding.device_hint.expect("device hint");
        assert_eq!(hint.device_type, Some(DeviceType::Hub));
    }

    #[test]
    fn unsecured_services_finding_fires_without_secure_families() {
        let server = parse_search_response(&full_response(0x00)).unwrap();
        let finding = unsecured_services_finding(ip(), &server).expect("finding");
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.confidence, Confidence::Inferred);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-306"));
    }

    #[test]
    fn no_cve_is_attached_to_any_knx_finding() {
        // The CVE-2023-4346 precondition is a bus-level property; attaching the
        // id would let KEV scoring assert a vulnerability this scan cannot see.
        let server = parse_search_response(&full_response(0x01)).unwrap();
        for finding in findings_for(ip(), &server) {
            assert!(finding.cve_ids.is_empty(), "{} carries CVEs", finding.title);
        }
    }

    #[test]
    fn secure_gateway_gets_no_unsecured_finding() {
        let mut dibs = device_info_dib(0x00);
        dibs.extend(families_dib(
            DIB_SUPP_SVC_FAMILIES,
            &[(FAMILY_TUNNELLING, 2), (FAMILY_SECURITY, 1)],
        ));
        let server = parse_search_response(&response_frame(SEARCH_RESPONSE, &dibs)).unwrap();
        assert!(unsecured_services_finding(ip(), &server).is_none());
    }

    #[test]
    fn core_only_gateway_gets_no_unsecured_finding() {
        let mut dibs = device_info_dib(0x00);
        dibs.extend(families_dib(DIB_SUPP_SVC_FAMILIES, &[(0x02, 2)]));
        let server = parse_search_response(&response_frame(SEARCH_RESPONSE, &dibs)).unwrap();
        assert!(unsecured_services_finding(ip(), &server).is_none());
    }

    #[test]
    fn programming_mode_finding_only_when_bit_set() {
        let idle = parse_search_response(&full_response(0x00)).unwrap();
        assert!(programming_mode_finding(ip(), &idle).is_none());
        let active = parse_search_response(&full_response(0x01)).unwrap();
        let finding = programming_mode_finding(ip(), &active).expect("finding");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.confidence, Confidence::Confirmed);
    }

    #[test]
    fn titles_are_stable_across_response_details() {
        let a = parse_search_response(&full_response(0x00)).unwrap();
        let mut dibs = device_info_dib(0x00);
        dibs.extend(families_dib(
            DIB_SUPP_SVC_FAMILIES,
            &[(FAMILY_DEVICE_MANAGEMENT, 2)],
        ));
        let b = parse_search_response(&response_frame(SEARCH_RESPONSE, &dibs)).unwrap();
        assert_eq!(
            presence_finding(ip(), &a).title,
            presence_finding(ip(), &b).title
        );
    }

    #[test]
    fn evidence_names_the_service_families() {
        let server = parse_search_response(&full_response(0x00)).unwrap();
        let text = evidence(&server);
        assert!(text.contains("Tunnelling"));
        assert!(text.contains("KNX IP Interface 730"));
    }

    #[test]
    fn family_and_medium_labels_cover_the_assigned_codes() {
        assert_eq!(family_name(FAMILY_TUNNELLING), "Tunnelling");
        assert_eq!(family_name(0xF0), "unknown family");
        assert_eq!(medium_name(0x20), "KNX IP");
        assert_eq!(medium_name(0x00), "unknown medium");
    }

    proptest! {
        /// No datagram from the network can panic the parser.
        #[test]
        fn parse_search_response_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = parse_search_response(&bytes);
        }

        /// Neither can a frame that keeps the KNXnet/IP header and service type.
        #[test]
        fn parse_shaped_response_never_panics(
            len in any::<u16>(),
            body in proptest::collection::vec(any::<u8>(), 0..400),
        ) {
            let mut frame = Vec::with_capacity(body.len() + 6);
            frame.extend_from_slice(&HEADER);
            frame.extend_from_slice(&SEARCH_RESPONSE.to_be_bytes());
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(&body);
            if let Some(server) = parse_search_response(&frame) {
                let _ = findings_for(ip(), &server);
            }
        }
    }
}
