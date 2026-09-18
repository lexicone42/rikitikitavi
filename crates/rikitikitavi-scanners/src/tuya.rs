//! Tuya local-protocol discovery.
//!
//! Binds UDP 6666 and 6667 and decodes the `0x000055AA` (plaintext or
//! AES-128-ECB) and `0x00006699` (protocol 3.5, AES-128-GCM) broadcast frames
//! under the published broadcast key. Sends nothing on UDP. At Active intensity
//! it also makes a bare TCP connect to 6668 and closes it; no bytes are written.

use async_trait::async_trait;
use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::cipher::{AES_128, DecryptingKey, DecryptionContext, UnboundCipherKey};
use futures::stream::StreamExt as _;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::config::{ExclusionSet, ScanIntensity};
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, MacAddr, Remediation, ScanContext};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;

use crate::Scanner;

/// Tuya local-protocol scanner: passive UDP 6666/6667 listener plus TCP 6668
/// presence.
pub struct TuyaScanner;

/// Discovery broadcast port used by protocol 3.1 (payload usually plaintext).
const UDP_PORT_PLAIN: u16 = 6666;

/// Discovery broadcast port used by protocol 3.3 and later (payload encrypted).
const UDP_PORT_ENCRYPTED: u16 = 6667;

/// Tuya local control port.
const TCP_PORT: u16 = 6668;

/// Port recorded on discovery findings. Fixed, because `affected_port` feeds the
/// finding fingerprint and the set of broadcast ports a device is heard on varies
/// between scans. The ports actually heard go in the evidence.
const DISCOVERY_PORT: u16 = UDP_PORT_ENCRYPTED;

/// Fixed broadcast key, `md5("yGAdlopoPVldABfn")`; identical on all devices.
const UDP_KEY: [u8; 16] = [
    0x6c, 0x1e, 0xc8, 0xe2, 0xbb, 0x9b, 0xb5, 0x9a, 0xb5, 0x0b, 0x0d, 0xaf, 0x64, 0x9b, 0x41, 0x0a,
];

/// Frame magic for protocol 3.1–3.4.
const PREFIX_55AA: [u8; 4] = [0x00, 0x00, 0x55, 0xaa];

/// Frame terminator for protocol 3.1–3.4.
const SUFFIX_55AA: [u8; 4] = [0x00, 0x00, 0xaa, 0x55];

/// Frame magic for protocol 3.5.
const PREFIX_6699: [u8; 4] = [0x00, 0x00, 0x66, 0x99];

/// Frame terminator for protocol 3.5.
const SUFFIX_6699: [u8; 4] = [0x00, 0x00, 0x99, 0x66];

/// Bytes before the payload in a 55AA frame: prefix, sequence, command, length.
const HEADER_55AA: usize = 16;

/// Trailer inside the declared 55AA length: CRC32 and suffix.
const TRAILER_55AA: usize = 8;

/// Bytes before the nonce in a 6699 frame: prefix, flags, sequence, command, length.
const HEADER_6699: usize = 18;

/// GCM nonce plus tag, both counted inside the declared 6699 length.
const OVERHEAD_6699: usize = 28;

/// GCM authentication tag length.
const TAG_LEN: usize = 16;

/// Listen window at Quick intensity. Tuya broadcasts every ~5 s, so a shorter
/// window misses devices outright.
const WINDOW_QUICK: Duration = Duration::from_secs(6);

/// Listen window at Active intensity and above.
const WINDOW_ACTIVE: Duration = Duration::from_secs(8);

/// Datagrams accepted per port before the listener stops.
const MAX_DATAGRAMS: usize = 512;

/// Largest datagram read.
const MAX_DATAGRAM_LEN: usize = 4096;

/// Connect timeout for the TCP 6668 presence check.
const TCP_TIMEOUT: Duration = Duration::from_secs(2);

/// Hosts checked for an open 6668.
const MAX_TCP_TARGETS: usize = 256;

/// Upper bound on concurrent 6668 connects.
const MAX_TCP_PARALLELISM: usize = 64;

/// Wall-clock ceiling for the whole TCP phase. Hitting it drops the control-port
/// results only; the passive findings already in hand are still returned.
const TCP_PHASE_BUDGET: Duration = Duration::from_secs(30);

// ── frame decoding ──────────────────────────────────────────────────────────

/// Which Tuya framing a datagram used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Magic {
    /// `0x000055AA` — protocol 3.1 through 3.4.
    V55Aa,
    /// `0x00006699` — protocol 3.5.
    V6699,
}

impl Magic {
    /// Stable label for evidence strings.
    const fn label(self) -> &'static str {
        match self {
            Self::V55Aa => "0x000055AA",
            Self::V6699 => "0x00006699",
        }
    }
}

/// Outcome of decoding one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decoded {
    /// Payload recovered as a JSON object, with the framing it arrived in.
    /// `None` when the datagram carried no Tuya magic.
    Json(Option<Magic>, String),
    /// Framing recognised, payload not recoverable with the broadcast key.
    Opaque(Magic),
    /// Not a Tuya datagram.
    Unknown,
}

/// Read a big-endian `u32` from the first four bytes of `bytes`.
fn be_u32(bytes: &[u8]) -> Option<u32> {
    let head: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_be_bytes(head))
}

/// Decode a discovery datagram.
///
/// Framed input is parsed by magic. Unframed input is tried as plain JSON and
/// then as a bare AES-ECB blob, which some 3.1 firmwares emit.
fn decode_datagram(data: &[u8]) -> Decoded {
    if data.starts_with(&PREFIX_55AA) {
        return decode_55aa(data).map_or(Decoded::Opaque(Magic::V55Aa), |json| {
            Decoded::Json(Some(Magic::V55Aa), json)
        });
    }
    if data.starts_with(&PREFIX_6699) {
        return decode_6699(data).map_or(Decoded::Opaque(Magic::V6699), |json| {
            Decoded::Json(Some(Magic::V6699), json)
        });
    }
    recover_payload(data).map_or(Decoded::Unknown, |json| Decoded::Json(None, json))
}

/// Decode a `0x000055AA` frame: bounds-check the declared length, verify the
/// suffix, then recover the payload.
fn decode_55aa(data: &[u8]) -> Option<String> {
    let length = usize::try_from(be_u32(data.get(12..HEADER_55AA)?)?).ok()?;
    if length < TRAILER_55AA {
        return None;
    }
    let end = HEADER_55AA.checked_add(length)?;
    if end > data.len() || data.get(end - 4..end)? != SUFFIX_55AA {
        return None;
    }
    recover_payload(data.get(HEADER_55AA..end - TRAILER_55AA)?)
}

/// Decode a `0x00006699` frame. The AAD is the 14 header bytes after the magic;
/// the nonce is the 12 bytes after the header and the tag the last 16 inside the
/// declared length.
fn decode_6699(data: &[u8]) -> Option<String> {
    let length = usize::try_from(be_u32(data.get(14..HEADER_6699)?)?).ok()?;
    if length < OVERHEAD_6699 {
        return None;
    }
    let end = HEADER_6699.checked_add(length)?;
    if end.checked_add(4)? > data.len() || data.get(end..end + 4)? != SUFFIX_6699 {
        return None;
    }
    let plain = aes_gcm_open(
        data.get(HEADER_6699..HEADER_6699 + 12)?,
        data.get(4..HEADER_6699)?,
        data.get(end - TAG_LEN..end)?,
        data.get(HEADER_6699 + 12..end - TAG_LEN)?,
    )?;
    extract_json(&plain).or_else(|| extract_json(plain.get(4..)?))
}

/// Recover the JSON body of a payload: plaintext or AES-ECB under the broadcast
/// key, with an optional four-byte return code in front of either.
fn recover_payload(payload: &[u8]) -> Option<String> {
    for body in [payload, payload.get(4..).unwrap_or(&[])] {
        if let Some(text) = extract_json(body) {
            return Some(text);
        }
        if let Some(plain) = aes_ecb_decrypt(body)
            && let Some(text) = extract_json(&plain)
        {
            return Some(text);
        }
    }
    None
}

/// Trim to the outermost `{`…`}` and return it if the span is valid UTF-8.
fn extract_json(data: &[u8]) -> Option<String> {
    let start = data.iter().position(|&b| b == b'{')?;
    let end = data.iter().rposition(|&b| b == b'}')?;
    if end <= start {
        return None;
    }
    Some(std::str::from_utf8(data.get(start..=end)?).ok()?.to_owned())
}

/// AES-128-ECB decrypt under the broadcast key, with PKCS#7 padding removed.
///
/// ECB is the mode Tuya chose; this only reads what the device already
/// broadcasts to the whole segment.
fn aes_ecb_decrypt(ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return None;
    }
    let key = DecryptingKey::ecb(UnboundCipherKey::new(&AES_128, &UDP_KEY).ok()?).ok()?;
    let mut buf = ciphertext.to_vec();
    let len = key.decrypt(&mut buf, DecryptionContext::None).ok()?.len();
    buf.truncate(len);
    strip_pkcs7(&mut buf);
    Some(buf)
}

/// AES-128-GCM open under the broadcast key. A bad tag returns `None`.
fn aes_gcm_open(nonce: &[u8], aad: &[u8], tag: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &UDP_KEY).ok()?);
    let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
    let mut buf = ciphertext.to_vec();
    let len = key
        .open_in_place_separate_tag(nonce, Aad::from(aad), tag, &mut buf)
        .ok()?
        .len();
    buf.truncate(len);
    Some(buf)
}

/// Remove PKCS#7 padding when it is well formed; leave the buffer alone otherwise.
fn strip_pkcs7(buf: &mut Vec<u8>) {
    let Some(&last) = buf.last() else {
        return;
    };
    let pad = usize::from(last);
    if pad == 0 || pad > 16 || pad > buf.len() {
        return;
    }
    let cut = buf.len() - pad;
    if buf[cut..].iter().all(|&b| usize::from(b) == pad) {
        buf.truncate(cut);
    }
}

// ── broadcast payload ───────────────────────────────────────────────────────

/// Fields of interest from a decoded discovery broadcast.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TuyaBroadcast {
    /// Device / gateway identifier.
    gw_id: Option<String>,
    /// Address the device claims for itself.
    claimed_ip: Option<String>,
    /// Tuya product key (the model's cloud product identifier).
    product_key: Option<String>,
    /// Local protocol version, e.g. `3.3`.
    version: Option<String>,
    /// Whether the device says its session payloads are encrypted.
    encrypted: Option<bool>,
}

/// Parse a decoded broadcast. Returns `None` unless at least `gwId` or `ip` is
/// present, which keeps a coincidental `{`…`}` in garbage from being reported.
fn parse_broadcast(json: &str) -> Option<TuyaBroadcast> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let obj = value.as_object()?;
    let text = |key: &str| {
        obj.get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let parsed = TuyaBroadcast {
        gw_id: text("gwId"),
        claimed_ip: text("ip"),
        product_key: text("productKey"),
        version: text("version"),
        encrypted: obj.get("encrypt").and_then(serde_json::Value::as_bool),
    };
    (parsed.gw_id.is_some() || parsed.claimed_ip.is_some()).then_some(parsed)
}

/// True for protocol 3.1, the only version where a LAN host can read device
/// status without the per-device local key — and there only below firmware
/// 1.0.5, which the broadcast does not report, so this is a candidate test.
fn unauthenticated_readout(version: Option<&str>) -> bool {
    version.is_some_and(|v| v.starts_with("3.1"))
}

/// What was heard from one address during the listen window.
#[derive(Debug, Clone, Default)]
struct Observation {
    /// UDP ports the device was heard on.
    ports: Vec<u16>,
    /// Datagrams attributed to this address.
    frames: usize,
    /// Best decoded broadcast, if any.
    broadcast: Option<TuyaBroadcast>,
    /// Framing seen; the magic of the frame that decoded, when one did.
    framing: Option<Magic>,
}

impl Observation {
    /// Ports heard on, for evidence: `UDP/6666, UDP/6667`.
    fn ports_label(&self) -> String {
        if self.ports.is_empty() {
            return format!("UDP/{DISCOVERY_PORT}");
        }
        let mut ports = self.ports.clone();
        ports.sort_unstable();
        ports
            .iter()
            .map(|port| format!("UDP/{port}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Fold one datagram into the observation.
    ///
    /// An unframed datagram must carry `gwId` to be believed: without a magic
    /// there is no protocol evidence, and any JSON object with an `ip` field
    /// would otherwise be reported as a confirmed Tuya device.
    fn record(&mut self, port: u16, data: &[u8]) {
        self.frames += 1;
        if !self.ports.contains(&port) {
            self.ports.push(port);
        }
        match decode_datagram(data) {
            Decoded::Json(magic, json) => {
                if let Some(magic) = magic {
                    self.framing.get_or_insert(magic);
                }
                if self.broadcast.is_none()
                    && let Some(parsed) = parse_broadcast(&json)
                    && (magic.is_some() || parsed.gw_id.is_some())
                {
                    self.broadcast = Some(parsed);
                    self.framing = magic.or(self.framing);
                }
            }
            Decoded::Opaque(magic) => {
                self.framing.get_or_insert(magic);
            }
            Decoded::Unknown => {}
        }
    }
}

/// Group datagrams by source address.
fn observe(datagrams: &[(IpAddr, u16, Vec<u8>)]) -> BTreeMap<IpAddr, Observation> {
    let mut seen: BTreeMap<IpAddr, Observation> = BTreeMap::new();
    for (ip, port, data) in datagrams {
        seen.entry(*ip).or_default().record(*port, data);
    }
    seen
}

// ── findings ────────────────────────────────────────────────────────────────

/// References for a finding. The CWE page matches the id the finding sets, if any.
fn tuya_references(cwe: Option<&str>) -> Vec<String> {
    let mut references = refs!["https://github.com/jasonacox/tinytuya"];
    if let Some(id) = cwe.and_then(|cwe| cwe.strip_prefix("CWE-")) {
        references.push(format!("https://cwe.mitre.org/data/definitions/{id}.html"));
    }
    references
}

/// Remediation shared by the identity and control-port findings.
fn segment_remediation() -> Remediation {
    Remediation {
        description: "Tuya firmware cannot be told to stop broadcasting; contain it by \
                      segmenting instead."
            .to_owned(),
        steps: vec![
            "Move Tuya / Smart Life devices onto an IoT VLAN or a separate SSID.".to_owned(),
            "Enable client isolation on that SSID so devices cannot reach each other.".to_owned(),
            "Allow only the hub or automation controller to reach TCP 6668; block the rest \
             of the LAN."
                .to_owned(),
            "Block outbound traffic from the IoT segment except what the vendor cloud needs."
                .to_owned(),
        ],
        effort: Some("30 minutes".to_owned()),
    }
}

/// Finding for a device whose broadcast was decoded.
fn identity_finding(ip: IpAddr, observation: &Observation, broadcast: &TuyaBroadcast) -> Finding {
    let version = broadcast.version.as_deref();
    let readable = unauthenticated_readout(version);
    let severity = if readable {
        Severity::Medium
    } else {
        Severity::Low
    };
    let cwe = if readable { "CWE-306" } else { "CWE-200" };
    let description = format!(
        "The device at {ip} broadcasts a Tuya local-protocol discovery frame on \
         {ports}. The payload is readable by any host on the segment: the \
         broadcast key is the fixed constant md5(\"yGAdlopoPVldABfn\"), identical \
         across all Tuya devices and published in every local client library. It \
         reveals the device id (gwId), the product key and the protocol version, \
         which is enough to inventory and fingerprint the device and to target it \
         with version-specific attacks. {extra}",
        ports = observation.ports_label(),
        extra = if readable {
            "Protocol 3.1 devices running firmware below 1.0.5 additionally allow \
             a LAN host to read device status without the per-device local key; \
             the broadcast does not carry the firmware version, so whether this \
             device is affected cannot be settled from discovery alone."
        } else {
            "Reading or changing device state still requires the per-device local \
             key, which is not in the broadcast."
        }
    );

    let mut evidence = format!(
        "{} frame on {}",
        observation.framing.map_or("Tuya", Magic::label),
        observation.ports_label()
    );
    if let Some(gw_id) = &broadcast.gw_id {
        let _ = write!(evidence, " gwId={gw_id}");
    }
    if let Some(product_key) = &broadcast.product_key {
        let _ = write!(evidence, " productKey={product_key}");
    }
    if let Some(version) = version {
        let _ = write!(evidence, " version={version}");
    }
    if broadcast.encrypted == Some(false) {
        evidence.push_str(" encrypt=false");
    }

    let mut hint = DeviceHint::new()
        .with_vendor("Tuya")
        .with_device_type(DeviceType::IoT);
    if let Some(product_key) = &broadcast.product_key {
        hint = hint.with_model(product_key);
    }
    if let Some(version) = version {
        hint = hint.with_os_guess(format!("Tuya local protocol {version}"));
    }

    Finding::new(
        "tuya",
        &format!("Tuya device identity broadcast readable on {ip}"),
        &description,
        severity,
    )
    .with_confidence(Confidence::Confirmed)
    .with_ip(ip)
    .with_port(DISCOVERY_PORT)
    .with_service("Tuya")
    .with_cwe(cwe)
    .with_evidence(evidence)
    .with_device_hint(hint)
    .with_references(tuya_references(Some(cwe)))
    .with_remediation(segment_remediation())
}

/// Finding for a Tuya-framed datagram whose payload did not decode.
fn opaque_finding(ip: IpAddr, observation: &Observation, magic: Magic) -> Finding {
    Finding::new(
        "tuya",
        &format!("Tuya-framed broadcast from {ip} could not be decoded"),
        &format!(
            "The device at {ip} emits datagrams on {ports} carrying the Tuya \
             local-protocol magic {magic}, but the payload did not decode under \
             the published broadcast key. This is still a Tuya-family device; it \
             may run a vendor build with a substituted key or a protocol revision \
             this scanner does not parse. Treat it as unmanaged IoT.",
            ports = observation.ports_label(),
            magic = magic.label()
        ),
        Severity::Low,
    )
    .with_confidence(Confidence::Probable)
    .with_ip(ip)
    .with_port(DISCOVERY_PORT)
    .with_service("Tuya")
    .with_evidence(format!(
        "{} magic on {}, payload not recoverable with the published broadcast key",
        magic.label(),
        observation.ports_label()
    ))
    .with_device_hint(
        DeviceHint::new()
            .with_vendor("Tuya")
            .with_device_type(DeviceType::IoT),
    )
    .with_references(tuya_references(None))
}

/// Finding for an open TCP 6668. `corroborated` is true when the same address
/// also produced a decodable broadcast; without one the probe is a bare connect,
/// so the title states the port, not the vendor (6668 is also an IRC alternate).
fn control_port_finding(ip: IpAddr, corroborated: bool) -> Finding {
    let (title, description) = if corroborated {
        (
            format!("Tuya local control port open on {ip}"),
            format!(
                "TCP/{TCP_PORT} is accepting connections on {ip}. This is the Tuya \
                 local control channel: any host on the segment can open a session \
                 and, with the device's local key, read status and issue commands. \
                 The key is not obtainable from the LAN, so this is an exposure of \
                 attack surface rather than direct unauthenticated control — but the \
                 port should not be reachable from general-purpose LAN clients."
            ),
        )
    } else {
        (
            format!("TCP/{TCP_PORT} open on {ip}, Tuya protocol unconfirmed"),
            format!(
                "TCP/{TCP_PORT} is accepting connections on {ip}. Tuya devices use \
                 this port for local control, but nothing on this host confirmed the \
                 protocol: no Tuya broadcast was heard from this address and no bytes \
                 were exchanged. TCP/{TCP_PORT} is also a long-standing IRC alternate \
                 port. If this is a Tuya device, the port should not be reachable from \
                 general-purpose LAN clients."
            ),
        )
    };

    let finding = Finding::new("tuya", &title, &description, Severity::Low)
        .with_confidence(if corroborated {
            Confidence::Probable
        } else {
            Confidence::Inferred
        })
        .with_ip(ip)
        .with_port(TCP_PORT)
        .with_evidence(format!("TCP connect to {ip}:{TCP_PORT} accepted"))
        .with_references(tuya_references(None))
        .with_remediation(segment_remediation());
    if corroborated {
        finding.with_service("Tuya").with_device_hint(
            DeviceHint::new()
                .with_vendor("Tuya")
                .with_device_type(DeviceType::IoT),
        )
    } else {
        finding
    }
}

/// Build all findings for one listen window plus the set of addresses whose
/// TCP 6668 answered.
fn build_findings(
    observations: &BTreeMap<IpAddr, Observation>,
    control_ports: &[IpAddr],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (ip, observation) in observations {
        if let Some(broadcast) = &observation.broadcast {
            findings.push(identity_finding(*ip, observation, broadcast));
        } else if let Some(magic) = observation.framing {
            findings.push(opaque_finding(*ip, observation, magic));
        }
    }
    for ip in control_ports {
        let corroborated = observations
            .get(ip)
            .is_some_and(|o| o.broadcast.is_some() || o.framing.is_some());
        findings.push(control_port_finding(*ip, corroborated));
    }
    findings
}

// ── network I/O ─────────────────────────────────────────────────────────────

/// Bind `port` and collect datagrams until `deadline` or `max` frames. Sends
/// nothing.
async fn listen(port: u16, deadline: Instant, max: usize) -> Vec<(IpAddr, u16, Vec<u8>)> {
    let socket = match UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port))).await {
        Ok(socket) => socket,
        Err(e) => {
            tracing::warn!("could not bind UDP/{port} for Tuya discovery: {e}");
            return Vec::new();
        }
    };

    let mut collected = Vec::new();
    let mut buf = vec![0u8; MAX_DATAGRAM_LEN];
    while collected.len() < max {
        let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
        else {
            break;
        };
        if let Some(data) = buf.get(..n) {
            collected.push((from.ip(), port, data.to_vec()));
        }
    }
    collected
}

/// True when a TCP connect to `ip:6668` is accepted. Writes no bytes.
async fn control_port_open(ip: IpAddr) -> bool {
    let addr = SocketAddr::new(ip, TCP_PORT);
    matches!(
        tokio::time::timeout(TCP_TIMEOUT, TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// MAC for each address we know one for: discovered devices plus the ARP cache.
///
/// Passively heard addresses never went through the runner's device-level
/// exclusion pass, so the MAC has to be resolved here before anything connects.
fn known_macs(ctx: &ScanContext) -> BTreeMap<IpAddr, MacAddr> {
    let mut macs: BTreeMap<IpAddr, MacAddr> = ctx
        .discovered_devices
        .iter()
        .filter_map(|device| Some((device.ip, device.mac?)))
        .collect();
    match rikitikitavi_network::read_arp_cache() {
        Ok(entries) => {
            for entry in entries {
                if let Ok(mac) = entry.mac.parse::<MacAddr>() {
                    macs.insert(entry.ip, mac);
                }
            }
        }
        Err(e) => tracing::warn!("could not read ARP cache for Tuya exclusion check: {e}"),
    }
    macs
}

/// True when `ip` is excluded by address or by the MAC resolved for it.
fn excluded(ip: IpAddr, exclusions: &ExclusionSet, macs: &BTreeMap<IpAddr, MacAddr>) -> bool {
    exclusions.excludes_ip(ip)
        || macs
            .get(&ip)
            .is_some_and(|mac| exclusions.excludes_mac(*mac))
}

/// Addresses to check for an open 6668: devices from discovery plus the senders
/// heard passively, filtered and capped.
///
/// Passively heard senders take the same filter as discovered devices; the
/// runner's device-level exclusion pass never saw them.
fn select_tcp_targets(
    devices: &[IpAddr],
    heard: &[IpAddr],
    in_scope: impl Fn(IpAddr) -> bool,
) -> Vec<IpAddr> {
    let mut targets: Vec<IpAddr> = devices
        .iter()
        .chain(heard)
        .copied()
        .filter(|ip| in_scope(*ip))
        .collect();
    targets.sort_unstable();
    targets.dedup();
    targets.truncate(MAX_TCP_TARGETS);
    targets
}

/// Addresses eligible for probing: in the target network and not excluded.
fn in_scope(
    ip: IpAddr,
    ctx: &ScanContext,
    exclusions: &ExclusionSet,
    macs: &BTreeMap<IpAddr, MacAddr>,
) -> bool {
    ctx.target_network.as_ref().is_none_or(|n| n.contains(ip)) && !excluded(ip, exclusions, macs)
}

#[async_trait]
impl Scanner for TuyaScanner {
    fn id(&self) -> &'static str {
        "tuya"
    }

    fn name(&self) -> &'static str {
        "Tuya Local Protocol"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running Tuya local-protocol scan");

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "tuya".to_owned(),
                message: format!("invalid exclusion entry: {e}"),
            })?;

        // Resolving MACs costs a file read, so only when an exclusion can use one.
        let macs = if exclusions.is_empty() {
            BTreeMap::new()
        } else {
            known_macs(ctx)
        };

        let active = ctx.config.intensity.at_least(ScanIntensity::Active);
        let window = if active { WINDOW_ACTIVE } else { WINDOW_QUICK };
        let deadline = Instant::now() + window;

        // Passive half: listen only. No datagram is sent on either port.
        let (plain, encrypted) = tokio::join!(
            listen(UDP_PORT_PLAIN, deadline, MAX_DATAGRAMS),
            listen(UDP_PORT_ENCRYPTED, deadline, MAX_DATAGRAMS),
        );

        let datagrams: Vec<(IpAddr, u16, Vec<u8>)> = plain
            .into_iter()
            .chain(encrypted)
            .filter(|(ip, _, _)| in_scope(*ip, ctx, &exclusions, &macs))
            .collect();

        let observations = observe(&datagrams);
        tracing::info!(
            datagrams = datagrams.len(),
            senders = observations.len(),
            "Tuya passive listen complete"
        );

        // Active half: bare TCP connect to the local control port.
        let mut control_ports = Vec::new();
        if active {
            let devices: Vec<IpAddr> = ctx.discovered_devices.iter().map(|d| d.ip).collect();
            let heard: Vec<IpAddr> = observations.keys().copied().collect();
            let targets =
                select_tcp_targets(&devices, &heard, |ip| in_scope(ip, ctx, &exclusions, &macs));
            tracing::debug!(targets = targets.len(), "Tuya control-port sweep");

            // Bounded concurrency; the sweep has its own deadline.
            let parallelism = ctx.config.parallelism.clamp(1, MAX_TCP_PARALLELISM);
            let sweep = futures::stream::iter(targets)
                .map(|ip| async move { (ip, control_port_open(ip).await) })
                .buffer_unordered(parallelism)
                .filter_map(|(ip, open)| async move { open.then_some(ip) })
                .collect::<Vec<IpAddr>>();

            control_ports = tokio::time::timeout(TCP_PHASE_BUDGET, sweep)
                .await
                .unwrap_or_else(|_| {
                    tracing::warn!(
                        budget_secs = TCP_PHASE_BUDGET.as_secs(),
                        "Tuya TCP/{TCP_PORT} sweep timed out; keeping passive findings"
                    );
                    Vec::new()
                });
            control_ports.sort_unstable();
        } else {
            tracing::info!("skipping Tuya TCP/{TCP_PORT} check in quick scan mode");
        }

        let findings = build_findings(&observations, &control_ports);
        tracing::info!(
            findings_count = findings.len(),
            "Tuya local-protocol scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        20
    }
}

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Fixtures generated from the published frame layout with an independent
    // AES implementation (Python `cryptography`), then pasted as literals.

    /// 55AA frame, plaintext JSON payload, protocol 3.1.
    const FRAME_55AA_PLAIN: [u8; 163] = [
        0x00, 0x00, 0x55, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00,
        0x93, 0x7b, 0x22, 0x69, 0x70, 0x22, 0x3a, 0x22, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38,
        0x2e, 0x31, 0x2e, 0x34, 0x34, 0x22, 0x2c, 0x22, 0x67, 0x77, 0x49, 0x64, 0x22, 0x3a, 0x22,
        0x65, 0x62, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63,
        0x64, 0x65, 0x66, 0x30, 0x31, 0x32, 0x33, 0x22, 0x2c, 0x22, 0x61, 0x63, 0x74, 0x69, 0x76,
        0x65, 0x22, 0x3a, 0x32, 0x2c, 0x22, 0x61, 0x62, 0x6c, 0x69, 0x6c, 0x74, 0x79, 0x22, 0x3a,
        0x30, 0x2c, 0x22, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x22, 0x3a, 0x74, 0x72, 0x75,
        0x65, 0x2c, 0x22, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x4b, 0x65, 0x79, 0x22, 0x3a,
        0x22, 0x6b, 0x65, 0x79, 0x64, 0x48, 0x71, 0x6f, 0x55, 0x4b, 0x68, 0x79, 0x30, 0x4a, 0x6b,
        0x67, 0x68, 0x22, 0x2c, 0x22, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x22,
        0x33, 0x2e, 0x31, 0x22, 0x7d, 0xe6, 0x61, 0xdc, 0x74, 0x00, 0x00, 0xaa, 0x55,
    ];

    /// 55AA frame, AES-128-ECB payload under the broadcast key, protocol 3.3.
    const FRAME_55AA_ECB: [u8; 168] = [
        0x00, 0x00, 0x55, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00,
        0x98, 0xd0, 0x97, 0x66, 0x67, 0x6f, 0x33, 0x69, 0xeb, 0x10, 0xb5, 0xe9, 0xf1, 0x32, 0xfd,
        0x80, 0x2a, 0xfb, 0xb0, 0x3f, 0x11, 0x56, 0xa5, 0x58, 0x01, 0xd4, 0xb7, 0x48, 0x98, 0x3d,
        0xd2, 0xc9, 0x38, 0xee, 0x60, 0x3e, 0x9c, 0xd6, 0x13, 0xe3, 0xec, 0xa9, 0xfa, 0x72, 0xbd,
        0x9e, 0x22, 0x6f, 0x29, 0x02, 0x8c, 0xa3, 0x60, 0x83, 0x5c, 0x0b, 0x9b, 0xee, 0x48, 0xf8,
        0x9e, 0x03, 0x7e, 0x8f, 0x80, 0xc2, 0xfb, 0x84, 0x59, 0xb1, 0x15, 0x5f, 0xc7, 0x5d, 0x4b,
        0xf6, 0x69, 0x9f, 0x92, 0xcb, 0xa4, 0xc0, 0xba, 0x52, 0x01, 0x48, 0x04, 0x5e, 0x76, 0x05,
        0xfa, 0x04, 0x98, 0xdf, 0xea, 0x5a, 0xab, 0xc1, 0xc0, 0x12, 0x27, 0x67, 0xa2, 0x12, 0x53,
        0x35, 0x54, 0x64, 0x20, 0x1a, 0x13, 0xa7, 0xc3, 0x44, 0xae, 0xc8, 0xd6, 0x6b, 0xeb, 0x0c,
        0x2e, 0xbb, 0x92, 0x94, 0x2d, 0x3a, 0xe0, 0x3a, 0x5f, 0x6e, 0xda, 0x8e, 0xea, 0x40, 0xe9,
        0x3b, 0x1e, 0x3f, 0xc1, 0x4a, 0x25, 0x70, 0xe1, 0x82, 0x79, 0x93, 0xfd, 0x70, 0x89, 0x00,
        0x00, 0xaa, 0x55,
    ];

    /// 6699 frame, AES-128-GCM payload under the broadcast key, protocol 3.5.
    const FRAME_6699_GCM: [u8; 189] = [
        0x00, 0x00, 0x66, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00,
        0x00, 0x00, 0xa7, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0xc7, 0x3d, 0x7f, 0x42, 0xf5, 0xa2, 0xdb, 0xe0, 0xb0, 0x21, 0x2e, 0xd1, 0xe0, 0xcd, 0x0f,
        0xc6, 0xff, 0x4f, 0x10, 0xaa, 0xa5, 0x41, 0x9a, 0xd5, 0x50, 0x9f, 0xd4, 0x41, 0x08, 0x25,
        0x7e, 0x75, 0x5d, 0xad, 0x3f, 0x9c, 0xf5, 0x00, 0xbb, 0x85, 0x55, 0x45, 0x5a, 0x82, 0xd3,
        0x7a, 0x79, 0x42, 0x04, 0x8e, 0x3b, 0x82, 0xc7, 0xbe, 0x3e, 0x97, 0xcd, 0x08, 0x1e, 0x38,
        0x0f, 0x79, 0x67, 0x0f, 0xd0, 0x92, 0x82, 0x3e, 0xb3, 0x6c, 0x85, 0x84, 0x27, 0x97, 0xf1,
        0xc6, 0x14, 0x73, 0x7b, 0xe8, 0x72, 0xa6, 0x33, 0x7b, 0xbb, 0x30, 0xf4, 0x37, 0x9c, 0x6c,
        0x57, 0xcb, 0xc7, 0x65, 0x6b, 0xb8, 0x50, 0x97, 0x7a, 0xa8, 0x46, 0x0f, 0x96, 0x53, 0xfb,
        0x9b, 0xb3, 0x4f, 0x29, 0xa2, 0xd2, 0x98, 0x0e, 0x95, 0x6f, 0xdf, 0xc5, 0x5e, 0x13, 0x49,
        0xce, 0x14, 0x0f, 0x30, 0x0c, 0xa9, 0x93, 0x45, 0xec, 0x20, 0x33, 0x91, 0x0e, 0xda, 0xbe,
        0xa0, 0x56, 0x7d, 0xab, 0xaa, 0x02, 0xb8, 0xc7, 0x9e, 0x46, 0x40, 0xd6, 0x91, 0x0d, 0xb3,
        0x92, 0x38, 0x10, 0x84, 0x07, 0x00, 0x00, 0x99, 0x66,
    ];

    /// Bare AES-128-ECB blob with no framing, as some 3.1 firmwares emit.
    const BARE_ECB: [u8; 144] = [
        0xd0, 0x97, 0x66, 0x67, 0x6f, 0x33, 0x69, 0xeb, 0x10, 0xb5, 0xe9, 0xf1, 0x32, 0xfd, 0x80,
        0x2a, 0x0e, 0x39, 0x52, 0x68, 0x4f, 0x37, 0xc3, 0x73, 0x79, 0x75, 0xa8, 0x20, 0x05, 0x54,
        0x9b, 0x63, 0x45, 0xc0, 0x47, 0x96, 0x8a, 0x6d, 0xeb, 0x6d, 0x8f, 0x7b, 0xe4, 0xce, 0xbf,
        0xc1, 0x13, 0xff, 0xc4, 0x36, 0x51, 0xf6, 0x0b, 0xcf, 0x4a, 0xd0, 0xd3, 0x6b, 0x25, 0xc3,
        0x16, 0x57, 0x08, 0x8d, 0xc2, 0xfb, 0x84, 0x59, 0xb1, 0x15, 0x5f, 0xc7, 0x5d, 0x4b, 0xf6,
        0x69, 0x9f, 0x92, 0xcb, 0xa4, 0xc0, 0xba, 0x52, 0x01, 0x48, 0x04, 0x5e, 0x76, 0x05, 0xfa,
        0x04, 0x98, 0xdf, 0xea, 0x5a, 0xab, 0x13, 0x02, 0x1e, 0x3c, 0x32, 0xa3, 0xfb, 0xf4, 0xf2,
        0x09, 0xd8, 0xaa, 0x11, 0xa2, 0x17, 0x6e, 0xfa, 0x21, 0x36, 0xe8, 0xc5, 0x17, 0x6b, 0x99,
        0xdc, 0xc1, 0xfa, 0x6e, 0x74, 0x4e, 0xb4, 0xaf, 0xcd, 0xc8, 0x71, 0xb3, 0xb6, 0x3f, 0x06,
        0x2c, 0xdb, 0x3f, 0x00, 0xe5, 0xce, 0x1e, 0x74, 0x61,
    ];

    fn json_of(decoded: &Decoded) -> &str {
        match decoded {
            Decoded::Json(_, text) => text,
            other => panic!("expected JSON, got {other:?}"),
        }
    }

    fn magic_of(decoded: &Decoded) -> Option<Magic> {
        match decoded {
            Decoded::Json(magic, _) => *magic,
            other => panic!("expected JSON, got {other:?}"),
        }
    }

    // ── frame decoding ──────────────────────────────────────────────────────

    #[test]
    fn decodes_plaintext_55aa_frame() {
        let decoded = decode_datagram(&FRAME_55AA_PLAIN);
        let broadcast = parse_broadcast(json_of(&decoded)).unwrap();
        assert_eq!(broadcast.gw_id.as_deref(), Some("eb0123456789abcdef0123"));
        assert_eq!(broadcast.claimed_ip.as_deref(), Some("192.168.1.44"));
        assert_eq!(broadcast.product_key.as_deref(), Some("keydHqoUKhy0Jkgh"));
        assert_eq!(broadcast.version.as_deref(), Some("3.1"));
        assert_eq!(broadcast.encrypted, Some(true));
    }

    #[test]
    fn decodes_ecb_encrypted_55aa_frame() {
        let decoded = decode_datagram(&FRAME_55AA_ECB);
        let broadcast = parse_broadcast(json_of(&decoded)).unwrap();
        assert_eq!(broadcast.gw_id.as_deref(), Some("eb9876543210fedcba9876"));
        assert_eq!(broadcast.version.as_deref(), Some("3.3"));
    }

    #[test]
    fn decoded_frames_carry_the_magic_they_arrived_in() {
        assert_eq!(
            magic_of(&decode_datagram(&FRAME_55AA_PLAIN)),
            Some(Magic::V55Aa)
        );
        assert_eq!(
            magic_of(&decode_datagram(&FRAME_6699_GCM)),
            Some(Magic::V6699)
        );
        assert_eq!(magic_of(&decode_datagram(&BARE_ECB)), None, "unframed");
    }

    #[test]
    fn decodes_gcm_encrypted_6699_frame() {
        let decoded = decode_datagram(&FRAME_6699_GCM);
        let broadcast = parse_broadcast(json_of(&decoded)).unwrap();
        assert_eq!(broadcast.gw_id.as_deref(), Some("ebfeedfacecafe01234567"));
        assert_eq!(broadcast.product_key.as_deref(), Some("key5544332211aab"));
        assert_eq!(broadcast.version.as_deref(), Some("3.5"));
    }

    #[test]
    fn decodes_unframed_ecb_blob() {
        let decoded = decode_datagram(&BARE_ECB);
        let broadcast = parse_broadcast(json_of(&decoded)).unwrap();
        assert_eq!(broadcast.version.as_deref(), Some("3.1"));
    }

    #[test]
    fn gcm_tag_is_verified() {
        let mut tampered = FRAME_6699_GCM;
        let tag_start = tampered.len() - 4 - TAG_LEN;
        tampered[tag_start] ^= 0x01;
        assert_eq!(
            decode_datagram(&tampered),
            Decoded::Opaque(Magic::V6699),
            "a flipped tag bit must not yield plaintext"
        );
    }

    #[test]
    fn gcm_aad_is_bound_to_the_header() {
        let mut tampered = FRAME_6699_GCM;
        tampered[6] ^= 0x01; // sequence number, inside the AAD
        assert_eq!(decode_datagram(&tampered), Decoded::Opaque(Magic::V6699));
    }

    #[test]
    fn rejects_frame_with_wrong_suffix() {
        let mut broken = FRAME_55AA_PLAIN;
        let last = broken.len() - 1;
        broken[last] = 0x00;
        assert_eq!(decode_datagram(&broken), Decoded::Opaque(Magic::V55Aa));
    }

    #[test]
    fn rejects_frame_with_length_past_the_buffer() {
        let mut broken = FRAME_55AA_PLAIN;
        broken[12..16].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        assert_eq!(decode_datagram(&broken), Decoded::Opaque(Magic::V55Aa));
    }

    #[test]
    fn rejects_truncated_frames_without_panicking() {
        for len in 0..FRAME_55AA_PLAIN.len() {
            let _ = decode_datagram(&FRAME_55AA_PLAIN[..len]);
        }
        for len in 0..FRAME_6699_GCM.len() {
            let _ = decode_datagram(&FRAME_6699_GCM[..len]);
        }
    }

    #[test]
    fn unrelated_traffic_is_unknown() {
        assert_eq!(decode_datagram(b"hello world"), Decoded::Unknown);
        assert_eq!(decode_datagram(&[]), Decoded::Unknown);
        assert_eq!(decode_datagram(&[0xff; 64]), Decoded::Unknown);
    }

    #[test]
    fn strips_leading_return_code_before_json() {
        let mut payload = vec![0x00, 0x00, 0x00, 0x00];
        payload.extend_from_slice(br#"{"gwId":"abc","version":"3.3"}"#);
        let text = recover_payload(&payload).unwrap();
        assert_eq!(
            parse_broadcast(&text).unwrap().gw_id.as_deref(),
            Some("abc")
        );
    }

    // ── payload parsing ─────────────────────────────────────────────────────

    #[test]
    fn parse_broadcast_requires_an_identifying_field() {
        assert!(parse_broadcast(r#"{"active":2}"#).is_none());
        assert!(parse_broadcast("{}").is_none());
        assert!(parse_broadcast("not json").is_none());
        assert!(parse_broadcast("[1,2,3]").is_none());
        assert!(parse_broadcast(r#"{"ip":"10.0.0.1"}"#).is_some());
    }

    #[test]
    fn parse_broadcast_tolerates_unexpected_field_types() {
        // Firmware builds disagree on whether these are ints, bools or strings.
        let json = r#"{"gwId":"x","active":true,"encrypt":"yes","ablilty":"0"}"#;
        let broadcast = parse_broadcast(json).unwrap();
        assert_eq!(broadcast.gw_id.as_deref(), Some("x"));
        assert_eq!(broadcast.encrypted, None);
    }

    #[test]
    fn unauthenticated_readout_only_for_31() {
        assert!(unauthenticated_readout(Some("3.1")));
        assert!(!unauthenticated_readout(Some("3.3")));
        assert!(!unauthenticated_readout(Some("3.5")));
        assert!(!unauthenticated_readout(None));
    }

    #[test]
    fn extract_json_needs_a_balanced_span() {
        assert!(extract_json(b"}{").is_none());
        assert!(extract_json(b"no braces").is_none());
        assert_eq!(extract_json(b"xx{\"a\":1}yy").unwrap(), r#"{"a":1}"#);
    }

    #[test]
    fn strip_pkcs7_leaves_malformed_padding_alone() {
        let mut buf = vec![1, 2, 3, 0x05];
        strip_pkcs7(&mut buf);
        assert_eq!(buf, vec![1, 2, 3, 0x05], "pad longer than buffer");

        let mut buf = vec![1, 2, 0x02, 0x02];
        strip_pkcs7(&mut buf);
        assert_eq!(buf, vec![1, 2]);

        let mut buf = vec![1, 2, 0x01, 0x02];
        strip_pkcs7(&mut buf);
        assert_eq!(buf, vec![1, 2, 0x01, 0x02], "inconsistent pad bytes");

        let mut buf = vec![0x00];
        strip_pkcs7(&mut buf);
        assert_eq!(buf, vec![0x00], "zero pad length");
    }

    // ── observation grouping ────────────────────────────────────────────────

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn observations_group_by_source_and_list_every_port() {
        let datagrams = vec![
            (ip("192.168.1.44"), 6667, FRAME_55AA_ECB.to_vec()),
            (ip("192.168.1.44"), 6666, FRAME_55AA_PLAIN.to_vec()),
            (ip("192.168.1.46"), 6667, FRAME_6699_GCM.to_vec()),
        ];
        let observations = observe(&datagrams);
        assert_eq!(observations.len(), 2);
        let first = &observations[&ip("192.168.1.44")];
        assert_eq!(first.frames, 2);
        assert_eq!(first.ports_label(), "UDP/6666, UDP/6667");
        assert!(first.broadcast.is_some());
        assert!(observations[&ip("192.168.1.46")].broadcast.is_some());
    }

    #[test]
    fn unframed_json_without_gwid_is_not_believed() {
        // Any JSON object with an `ip` field would otherwise pass as Tuya.
        let observation = observation_from(br#"{"ip":"10.0.0.11","version":"3.1"}"#, 6666);
        assert!(observation.broadcast.is_none());
        assert!(observation.framing.is_none());
        assert!(
            build_findings(
                &observe(&[(ip("10.0.0.11"), 6666, br#"{"ip":"10.0.0.11"}"#.to_vec())]),
                &[]
            )
            .is_empty()
        );
    }

    #[test]
    fn unframed_json_with_gwid_is_believed() {
        let observation = observation_from(br#"{"gwId":"eb01","ip":"10.0.0.12"}"#, 6666);
        assert_eq!(
            observation.broadcast.as_ref().unwrap().gw_id.as_deref(),
            Some("eb01")
        );
        assert!(observation.framing.is_none(), "no magic to report");
    }

    #[test]
    fn undecodable_framing_is_still_recorded() {
        let mut tampered = FRAME_6699_GCM;
        tampered[40] ^= 0xff;
        let observations = observe(&[(ip("10.0.0.5"), 6667, tampered.to_vec())]);
        let observation = &observations[&ip("10.0.0.5")];
        assert!(observation.broadcast.is_none());
        assert_eq!(observation.framing, Some(Magic::V6699));
    }

    #[test]
    fn unrelated_traffic_produces_no_observation_state() {
        let observations = observe(&[(ip("10.0.0.6"), 6666, b"random".to_vec())]);
        let observation = &observations[&ip("10.0.0.6")];
        assert!(observation.broadcast.is_none());
        assert!(observation.framing.is_none());
    }

    // ── findings ────────────────────────────────────────────────────────────

    fn observation_from(data: &[u8], port: u16) -> Observation {
        let mut observation = Observation::default();
        observation.record(port, data);
        observation
    }

    #[test]
    fn identity_finding_for_31_is_medium_and_confirmed() {
        let observation = observation_from(&FRAME_55AA_PLAIN, 6666);
        let broadcast = observation.broadcast.clone().unwrap();
        let finding = identity_finding(ip("192.168.1.44"), &observation, &broadcast);
        assert_eq!(
            finding.title,
            "Tuya device identity broadcast readable on 192.168.1.44"
        );
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-306"));
        assert_eq!(finding.affected_port, Some(DISCOVERY_PORT));
        assert!(finding.cve_ids.is_empty(), "no CVE should be fabricated");
        assert!(
            finding.description.contains("firmware below 1.0.5"),
            "the readout claim must stay conditional: {}",
            finding.description
        );
        assert!(
            finding.references.iter().any(|r| r.ends_with("/306.html")),
            "{:?}",
            finding.references
        );
        let evidence = finding.evidence.as_deref().unwrap();
        assert!(
            evidence.contains("gwId=eb0123456789abcdef0123"),
            "{evidence}"
        );
        assert!(evidence.contains("version=3.1"), "{evidence}");
        assert!(
            evidence.contains("0x000055AA frame on UDP/6666"),
            "{evidence}"
        );
        let hint = finding.device_hint.unwrap();
        assert_eq!(hint.vendor.as_deref(), Some("Tuya"));
        assert_eq!(hint.device_type, Some(DeviceType::IoT));
        assert_eq!(hint.model.as_deref(), Some("keydHqoUKhy0Jkgh"));
    }

    #[test]
    fn identity_finding_for_33_is_low_and_cwe_200() {
        let observation = observation_from(&FRAME_55AA_ECB, 6667);
        let broadcast = observation.broadcast.clone().unwrap();
        let finding = identity_finding(ip("192.168.1.45"), &observation, &broadcast);
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-200"));
        assert_eq!(finding.affected_port, Some(DISCOVERY_PORT));
        assert!(finding.references.iter().any(|r| r.ends_with("/200.html")));
        assert!(
            !finding.references.iter().any(|r| r.ends_with("/306.html")),
            "the linked CWE page must match the id the finding sets"
        );
    }

    #[test]
    fn v35_identity_evidence_reports_the_6699_magic() {
        let observation = observation_from(&FRAME_6699_GCM, 6667);
        let broadcast = observation.broadcast.clone().unwrap();
        let finding = identity_finding(ip("192.168.1.46"), &observation, &broadcast);
        let evidence = finding.evidence.as_deref().unwrap();
        assert!(evidence.starts_with("0x00006699 frame"), "{evidence}");
    }

    #[test]
    fn a_decodable_frame_sets_the_framing_even_after_an_opaque_one() {
        let mut tampered = FRAME_55AA_PLAIN;
        tampered[16] ^= 0xff; // breaks the payload, keeps the 55AA magic
        let mut observation = Observation::default();
        observation.record(6667, &tampered);
        assert_eq!(observation.framing, Some(Magic::V55Aa));
        observation.record(6667, &FRAME_6699_GCM);
        assert_eq!(
            observation.framing,
            Some(Magic::V6699),
            "the frame that decoded names the framing"
        );
    }

    #[test]
    fn findings_without_a_cwe_carry_no_cwe_page() {
        let observation = observation_from(b"\x00\x00\x66\x99short", 6667);
        for finding in [
            opaque_finding(ip("10.0.0.7"), &observation, Magic::V6699),
            control_port_finding(ip("10.0.0.8"), true),
        ] {
            assert!(finding.cwe_id.is_none());
            assert!(
                !finding
                    .references
                    .iter()
                    .any(|r| r.contains("cwe.mitre.org")),
                "{:?}",
                finding.references
            );
        }
    }

    #[test]
    fn opaque_finding_is_probable_not_confirmed() {
        let observation = observation_from(b"\x00\x00\x66\x99short", 6667);
        let finding = opaque_finding(ip("10.0.0.7"), &observation, Magic::V6699);
        assert_eq!(finding.confidence, Confidence::Probable);
        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.cwe_id.is_none());
        assert!(finding.evidence.as_deref().unwrap().contains("0x00006699"));
    }

    #[test]
    fn control_port_finding_confidence_tracks_corroboration() {
        assert_eq!(
            control_port_finding(ip("10.0.0.8"), true).confidence,
            Confidence::Probable
        );
        let bare = control_port_finding(ip("10.0.0.8"), false);
        assert_eq!(bare.confidence, Confidence::Inferred);
        assert_eq!(bare.affected_port, Some(TCP_PORT));
    }

    #[test]
    fn uncorroborated_control_port_title_does_not_claim_tuya() {
        let bare = control_port_finding(ip("10.0.0.8"), false);
        assert_eq!(
            bare.title,
            "TCP/6668 open on 10.0.0.8, Tuya protocol unconfirmed"
        );
        assert_eq!(bare.affected_service, None);
        assert_eq!(
            control_port_finding(ip("10.0.0.8"), true).title,
            "Tuya local control port open on 10.0.0.8"
        );
    }

    #[test]
    fn build_findings_prefers_identity_over_opaque_and_adds_control_port() {
        let datagrams = vec![
            (ip("192.168.1.44"), 6666, FRAME_55AA_PLAIN.to_vec()),
            (ip("10.0.0.7"), 6667, b"\x00\x00\x66\x99short".to_vec()),
            (ip("10.0.0.9"), 6666, b"noise".to_vec()),
        ];
        let observations = observe(&datagrams);
        let findings = build_findings(&observations, &[ip("192.168.1.44")]);
        assert_eq!(findings.len(), 3, "identity + opaque + control port");
        assert_eq!(
            findings.iter().filter(|f| f.scanner == "tuya").count(),
            3,
            "all findings carry the scanner id"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.affected_ip != Some(ip("10.0.0.9"))),
            "unrelated traffic must not produce a finding"
        );
    }

    #[test]
    fn titles_are_stable_across_repeated_observation() {
        let one = observation_from(&FRAME_55AA_ECB, 6667);
        let mut two = one.clone();
        two.record(6667, &FRAME_55AA_ECB);
        let broadcast = one.broadcast.clone().unwrap();
        assert_eq!(
            identity_finding(ip("192.168.1.45"), &one, &broadcast).fingerprint(),
            identity_finding(ip("192.168.1.45"), &two, &broadcast).fingerprint()
        );
    }

    #[test]
    fn fingerprint_survives_a_changed_set_of_broadcast_ports() {
        // One scan hears the device on 6667 only, the next on both ports.
        let one = observation_from(&FRAME_55AA_ECB, 6667);
        let mut two = one.clone();
        two.record(6666, &FRAME_55AA_PLAIN);
        let broadcast = one.broadcast.clone().unwrap();
        assert_eq!(
            identity_finding(ip("192.168.1.45"), &one, &broadcast).fingerprint(),
            identity_finding(ip("192.168.1.45"), &two, &broadcast).fingerprint(),
            "a device heard on an extra port must not read as resolved + new"
        );
    }

    // ── exclusions ──────────────────────────────────────────────────────────

    fn mac(text: &str) -> MacAddr {
        text.parse().unwrap()
    }

    #[test]
    fn mac_exclusions_apply_to_passively_heard_addresses() {
        let exclusions = ExclusionSet::parse(&[], &["aa:bb:cc:dd:ee:ff".to_owned()]).unwrap();
        let macs = BTreeMap::from([
            (ip("192.168.1.44"), mac("aa:bb:cc:dd:ee:ff")),
            (ip("192.168.1.45"), mac("aa:bb:cc:dd:ee:01")),
        ]);
        assert!(
            excluded(ip("192.168.1.44"), &exclusions, &macs),
            "a MAC-excluded device must not be connected to, however it was found"
        );
        assert!(!excluded(ip("192.168.1.45"), &exclusions, &macs));
        assert!(
            !excluded(ip("192.168.1.46"), &exclusions, &macs),
            "unknown MAC"
        );
    }

    #[test]
    fn passively_heard_senders_go_through_the_mac_filter() {
        let exclusions = ExclusionSet::parse(&[], &["aa:bb:cc:dd:ee:ff".to_owned()]).unwrap();
        let macs = BTreeMap::from([(ip("192.168.1.44"), mac("aa:bb:cc:dd:ee:ff"))]);
        // .44 was only heard passively, so discovery's exclusion pass never saw it.
        let targets = select_tcp_targets(&[ip("192.168.1.45")], &[ip("192.168.1.44")], |ip| {
            !excluded(ip, &exclusions, &macs)
        });
        assert_eq!(
            targets,
            vec![ip("192.168.1.45")],
            "an excluded MAC must not be connected to on 6668"
        );
    }

    #[test]
    fn tcp_targets_are_sorted_deduped_and_capped() {
        let devices: Vec<IpAddr> = (0..300)
            .map(|n| ip(&format!("10.0.{}.{}", n / 256, n % 256)))
            .collect();
        let targets = select_tcp_targets(&devices, &devices, |_| true);
        assert_eq!(targets.len(), MAX_TCP_TARGETS);
        assert!(
            targets.windows(2).all(|w| w[0] < w[1]),
            "sorted and deduped"
        );
    }

    #[test]
    fn ip_and_cidr_exclusions_still_apply() {
        let exclusions =
            ExclusionSet::parse(&["10.0.0.0/24".to_owned()], &["192.168.1.7".to_owned()]).unwrap();
        let macs = BTreeMap::new();
        assert!(excluded(ip("10.0.0.5"), &exclusions, &macs));
        assert!(excluded(ip("192.168.1.7"), &exclusions, &macs));
        assert!(!excluded(ip("192.168.1.8"), &exclusions, &macs));
    }

    // ── proptests ───────────────────────────────────────────────────────────

    /// Datagrams prefixed with a real Tuya magic, then arbitrary bytes.
    fn framed_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..1024),
            proptest::collection::vec(any::<u8>(), 0..512).prop_map(|tail| {
                let mut data = PREFIX_55AA.to_vec();
                data.extend_from_slice(&tail);
                data
            }),
            proptest::collection::vec(any::<u8>(), 0..512).prop_map(|tail| {
                let mut data = PREFIX_6699.to_vec();
                data.extend_from_slice(&tail);
                data
            }),
            (0u32..8192, proptest::collection::vec(any::<u8>(), 0..512)).prop_map(
                |(length, tail)| {
                    // Declared length that rarely matches the real body.
                    let mut data = PREFIX_55AA.to_vec();
                    data.extend_from_slice(&[0; 8]);
                    data.extend_from_slice(&length.to_be_bytes());
                    data.extend_from_slice(&tail);
                    data.extend_from_slice(&SUFFIX_55AA);
                    data
                }
            ),
            (0u32..8192, proptest::collection::vec(any::<u8>(), 0..512)).prop_map(
                |(length, tail)| {
                    let mut data = PREFIX_6699.to_vec();
                    data.extend_from_slice(&[0; 10]);
                    data.extend_from_slice(&length.to_be_bytes());
                    data.extend_from_slice(&tail);
                    data.extend_from_slice(&SUFFIX_6699);
                    data
                }
            ),
        ]
    }

    proptest! {
        /// The datagram decoder never panics on arbitrary or part-framed bytes.
        #[test]
        fn prop_decode_datagram_no_panic(data in framed_strategy()) {
            let _ = decode_datagram(&data);
        }

        /// Truncating a real frame at any offset never panics.
        #[test]
        fn prop_truncated_frames_no_panic(cut in 0usize..FRAME_6699_GCM.len()) {
            let _ = decode_datagram(&FRAME_6699_GCM[..cut]);
            let _ = decode_datagram(&FRAME_55AA_ECB[..cut.min(FRAME_55AA_ECB.len())]);
        }

        /// Flipping any single byte of a real frame never panics and never
        /// yields a decode that claims a different device id.
        #[test]
        fn prop_bitflip_never_forges_identity(
            index in 0usize..FRAME_6699_GCM.len(),
            mask in 1u8..=255,
        ) {
            let mut data = FRAME_6699_GCM;
            data[index] ^= mask;
            if let Decoded::Json(_, text) = decode_datagram(&data)
                && let Some(broadcast) = parse_broadcast(&text)
            {
                prop_assert_eq!(broadcast.gw_id.as_deref(), Some("ebfeedfacecafe01234567"));
            }
        }

        /// The payload parser never panics on arbitrary text.
        #[test]
        fn prop_parse_broadcast_no_panic(text in ".*") {
            let _ = parse_broadcast(&text);
        }

        /// Padding removal never grows the buffer and never removes more than a block.
        #[test]
        fn prop_strip_pkcs7_bounded(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let mut buf = data.clone();
            strip_pkcs7(&mut buf);
            prop_assert!(buf.len() <= data.len());
            prop_assert!(data.len() - buf.len() <= 16);
            prop_assert_eq!(&buf[..], &data[..buf.len()]);
        }

        /// ECB decryption only accepts whole blocks and never panics.
        #[test]
        fn prop_aes_ecb_decrypt_no_panic(data in proptest::collection::vec(any::<u8>(), 0..96)) {
            let out = aes_ecb_decrypt(&data);
            if data.is_empty() || !data.len().is_multiple_of(16) {
                prop_assert!(out.is_none());
            } else {
                prop_assert!(out.is_some_and(|plain| plain.len() <= data.len()));
            }
        }

        /// GCM open never panics on arbitrary nonce/aad/tag/ciphertext lengths.
        #[test]
        fn prop_aes_gcm_open_no_panic(
            nonce in proptest::collection::vec(any::<u8>(), 0..20),
            aad in proptest::collection::vec(any::<u8>(), 0..32),
            tag in proptest::collection::vec(any::<u8>(), 0..20),
            ct in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            prop_assert!(aes_gcm_open(&nonce, &aad, &tag, &ct).is_none());
        }

        /// Observations stay consistent however many datagrams arrive.
        #[test]
        fn prop_observe_counts_every_datagram(
            count in 1usize..16,
            data in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let datagrams: Vec<_> = (0..count)
                .map(|_| (ip("10.1.2.3"), 6667u16, data.clone()))
                .collect();
            let observations = observe(&datagrams);
            prop_assert_eq!(observations[&ip("10.1.2.3")].frames, count);
            prop_assert_eq!(observations[&ip("10.1.2.3")].ports.len(), 1);
        }
    }
    #[test]
    fn control_port_finding_hint_only_when_corroborated() {
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        assert!(control_port_finding(ip, true).device_hint.is_some());
        assert!(control_port_finding(ip, false).device_hint.is_none());
    }
}

/// Parser entry points for the fuzz harness.
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    pub fn datagram(data: &[u8]) {
        let _ = super::decode_datagram(data);
    }
    #[must_use]
    pub fn json(data: &[u8]) -> bool {
        super::extract_json(data).is_some()
    }
    #[must_use]
    pub fn broadcast(json: &str) -> bool {
        super::parse_broadcast(json).is_some()
    }
}
