//! mDNS service discovery with a hand-rolled DNS parser (A, AAAA, PTR, SRV, TXT).
//! Pure `&[u8]` parsing, bounds-checked, proptest-fuzzed.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

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

/// Upper bound on records collected per discovery run.
const MAX_MDNS_RECORDS: usize = 4096;

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

/// Parse a DNS name at `offset`, following compression pointers (max [`MAX_NAME_HOPS`]).
/// Returns `(name, bytes_consumed)`; a compression pointer consumes 2 bytes regardless of target length.
pub fn parse_dns_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut parts: Vec<String> = Vec::new();
    let mut pos = offset;
    let mut hops = 0;
    // Frozen at the first compression pointer.
    let mut consumed: Option<usize> = None;

    loop {
        if pos >= data.len() || hops > MAX_NAME_HOPS {
            return None;
        }

        let len_byte = data[pos];

        // Compression pointer: top two bits set.
        if len_byte & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
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

        // Root label terminates the name.
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

        let label = String::from_utf8_lossy(&data[label_start..label_end]).into_owned();
        parts.push(label);
        pos = label_end;
    }
}

/// Parse a 12-byte DNS header from the start of `data`.
pub const fn parse_dns_header(data: &[u8]) -> Option<DnsHeader> {
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

/// Parse one resource record at `offset`. Returns `(record, bytes_consumed)`.
pub fn parse_resource_record(data: &[u8], offset: usize) -> Option<(DnsRecord, usize)> {
    let (name, name_consumed) = parse_dns_name(data, offset)?;
    let rr_start = offset + name_consumed;

    // Fixed part: type(2) + class(2) + TTL(4) + rdlength(2) = 10 bytes
    if rr_start + 10 > data.len() {
        return None;
    }

    let rtype = u16::from_be_bytes([data[rr_start], data[rr_start + 1]]);
    let rclass = u16::from_be_bytes([data[rr_start + 2], data[rr_start + 3]]);
    // TTL at rr_start+4..rr_start+8 is skipped.
    let rdlength = u16::from_be_bytes([data[rr_start + 8], data[rr_start + 9]]) as usize;
    let rdata_start = rr_start + 10;
    let rdata_end = rdata_start + rdlength;

    if rdata_end > data.len() {
        return None;
    }

    let class_masked = rclass & !MDNS_CACHE_FLUSH;
    if class_masked != CLASS_IN {
        // Non-IN class: returned as an empty TXT so the caller still advances.
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
            // Unknown type: returned as an empty TXT.
            DnsRecord::Txt {
                name,
                entries: Vec::new(),
            }
        }
    };

    Some((record, total_consumed))
}

/// Parse TXT record rdata: sequence of length-prefixed strings.
///
/// RFC 6763 §6.5 allows arbitrary binary values; Thread's `_meshcop._udp` uses
/// them for `sb`, `xp` and `omr`. A value that is not printable UTF-8 is rendered
/// as [`HEX_VALUE_PREFIX`] plus lowercase hex rather than lossily replaced.
fn parse_txt_rdata(data: &[u8]) -> Vec<String> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let len = data[pos] as usize;
        pos += 1;
        if pos + len > data.len() {
            break;
        }
        let entry = render_txt_entry(&data[pos..pos + len]);
        if !entry.is_empty() {
            entries.push(entry);
        }
        pos += len;
    }
    entries
}

/// Marker prefixing a hex-rendered binary TXT value.
pub const HEX_VALUE_PREFIX: &str = "0x";

/// Whether `bytes` is UTF-8 with no control characters.
fn is_printable(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|s| !s.chars().any(char::is_control))
}

/// Render one TXT entry, hex-encoding a binary value.
fn render_txt_entry(raw: &[u8]) -> String {
    let Some(eq) = raw.iter().position(|&b| b == b'=') else {
        return String::from_utf8_lossy(raw).into_owned();
    };
    let (key, value) = (&raw[..eq], &raw[eq + 1..]);
    if !is_printable(key) {
        return String::from_utf8_lossy(raw).into_owned();
    }
    let key = String::from_utf8_lossy(key);
    if is_printable(value) {
        format!("{key}={}", String::from_utf8_lossy(value))
    } else {
        let mut out = format!("{key}={HEX_VALUE_PREFIX}");
        for b in value {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}

/// Value of TXT key `key`, or `None`.
///
/// Keys are case-insensitive (RFC 6763 §6.4). A boolean attribute — a key with
/// no `=` — yields `Some("")`.
#[must_use]
pub fn txt_get<'a>(txt: &'a [String], key: &str) -> Option<&'a str> {
    txt.iter().find_map(|entry| match entry.split_once('=') {
        Some((k, v)) => k.eq_ignore_ascii_case(key).then_some(v),
        None => entry.eq_ignore_ascii_case(key).then_some(""),
    })
}

/// Well-known mDNS TXT keys, interpreted.
///
/// Sources for the key meanings: RFC 6763 §6, Apple's `_device-info._tcp` and
/// `_raop._tcp` conventions, the Matter specification's commissionable-node
/// records, and `ot-br-posix`'s `_meshcop._udp` border-agent record.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MdnsTxt {
    /// Hardware model, from the key that means "model" for this service type.
    pub model: Option<String>,
    /// `fn` / `n`: friendly name chosen by the owner.
    pub friendly_name: Option<String>,
    /// `gen`: protocol/hardware generation (Shelly, Google Cast).
    pub generation: Option<String>,
    /// Manufacturer, from the key that means "vendor" for this service type.
    pub manufacturer: Option<String>,
    /// `VP`: Matter vendor and product id, `vid+pid`.
    pub vendor_product: Option<String>,
    /// `CM`: Matter commissioning mode. Non-zero means a window is open.
    pub commissioning_mode: Option<u8>,
    /// `D`: Matter discriminator.
    pub discriminator: Option<String>,
    /// `DT`: Matter device type id.
    pub device_type_id: Option<String>,
    /// `DN`: Matter device name.
    pub device_name: Option<String>,
    /// `nn`: Thread network name.
    pub thread_network_name: Option<String>,
    /// `xp`: Thread extended PAN id.
    pub thread_extended_pan_id: Option<String>,
    /// `omr`: Thread off-mesh-routable IPv6 prefix.
    pub thread_omr_prefix: Option<String>,
    /// `sb`: Thread border-agent state bitmap.
    pub thread_state_bitmap: Option<String>,
    /// `tv`: Thread stack version.
    pub thread_version: Option<String>,
}

/// TXT keys holding the hardware model, for `service_type`. `md` is the model
/// only for `_hap`, `_googlecast`, Shelly and `_device-info`; in `_raop`/`_airplay`
/// it lists metadata types and the model is `am` or `model`. `mn` is the model in
/// `_meshcop._udp`.
fn model_keys(service_type: &str) -> &'static [&'static str] {
    if service_type.contains("_raop.") || service_type.contains("_airplay.") {
        &["am", "model"]
    } else if service_type.contains("_meshcop") {
        &["mn"]
    } else if service_type.contains("_hap.")
        || service_type.contains("_googlecast.")
        || service_type.contains("_shelly")
        || service_type.contains("_device-info.")
    {
        &["md", "model", "mdl"]
    } else {
        &["model", "mdl"]
    }
}

/// TXT keys holding the manufacturer, for `service_type`. `vn` is the vendor
/// name only in `_meshcop._udp`; in `_raop` it is the protocol version.
fn manufacturer_keys(service_type: &str) -> &'static [&'static str] {
    if service_type.contains("_meshcop") {
        &["vn", "manufacturer", "vendor"]
    } else {
        &["manufacturer", "vendor"]
    }
}

impl MdnsTxt {
    /// Interpret the well-known keys of a TXT record set; `service_type` selects
    /// the model and manufacturer keys.
    #[must_use]
    pub fn parse(service_type: &str, txt: &[String]) -> Self {
        let first = |keys: &[&str]| -> Option<String> {
            keys.iter()
                .find_map(|k| txt_get(txt, k))
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned)
        };
        Self {
            model: first(model_keys(service_type)),
            friendly_name: first(&["fn", "n"]),
            generation: first(&["gen"]),
            manufacturer: first(manufacturer_keys(service_type)),
            vendor_product: first(&["vp"]),
            commissioning_mode: first(&["cm"]).and_then(|v| v.parse().ok()),
            discriminator: first(&["d"]),
            device_type_id: first(&["dt"]),
            device_name: first(&["dn"]),
            thread_network_name: first(&["nn"]),
            thread_extended_pan_id: first(&["xp"]),
            thread_omr_prefix: first(&["omr"]),
            thread_state_bitmap: first(&["sb"]),
            thread_version: first(&["tv"]),
        }
    }
}

/// Decoded Thread border-agent state bitmap (the `sb` TXT key).
///
/// Field layout from `ot-br-posix`'s border agent (BSD-3-Clause; the layout is
/// read from the Thread specification, no code was copied): connection mode in
/// bits 0-2, Thread interface status 3-4, availability 5-6, backbone router
/// active 7, backbone router primary 8, Thread role 9-10, ePSKc supported 11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadStateBitmap {
    /// The undecoded 32-bit value.
    pub raw: u32,
    /// How a commissioner may connect: 0 none, 1 `PSKc`, 2 `PSKd`, 3 vendor, 4 X.509.
    pub connection_mode: u8,
    /// 0 not initialised, 1 initialised but not attached, 2 active.
    pub interface_status: u8,
    /// 0 infrequent, 1 high.
    pub availability: u8,
    /// Backbone router function is running.
    pub bbr_active: bool,
    /// This border router is the primary backbone router.
    pub bbr_primary: bool,
    /// Thread role: 0 disabled or detached, 1 child, 2 router, 3 leader.
    pub thread_role: u8,
    /// Ephemeral-key commissioning (`_meshcop-e._udp`) is supported.
    pub epskc_supported: bool,
}

impl ThreadStateBitmap {
    /// Decode the bit fields of a raw `sb` value.
    #[must_use]
    pub const fn from_bits(raw: u32) -> Self {
        Self {
            raw,
            connection_mode: (raw & 0b111) as u8,
            interface_status: ((raw >> 3) & 0b11) as u8,
            availability: ((raw >> 5) & 0b11) as u8,
            bbr_active: (raw >> 7) & 1 == 1,
            bbr_primary: (raw >> 8) & 1 == 1,
            thread_role: ((raw >> 9) & 0b11) as u8,
            epskc_supported: (raw >> 11) & 1 == 1,
        }
    }

    /// Parse an `sb` TXT value: `0x`-prefixed hex (how a binary TXT value is
    /// rendered here) or decimal.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let raw = match value.strip_prefix(HEX_VALUE_PREFIX) {
            Some(hex) if hex.chars().all(|c| c.is_ascii_hexdigit()) && !hex.is_empty() => {
                u32::from_str_radix(hex, 16).ok()?
            }
            Some(_) => return None,
            None => value.parse::<u32>().ok()?,
        };
        Some(Self::from_bits(raw))
    }

    /// How a commissioner may connect to the border agent.
    #[must_use]
    pub const fn connection_mode_name(self) -> &'static str {
        match self.connection_mode {
            0 => "no commissioner connection allowed",
            1 => "PSKc, the key derived from the network passphrase",
            2 => "PSKd, a device-specific join passcode",
            3 => "a vendor-specific credential",
            4 => "an X.509 certificate",
            _ => "a connection mode this build does not recognise",
        }
    }

    /// State of the border router's own Thread interface.
    #[must_use]
    pub const fn interface_status_name(self) -> &'static str {
        match self.interface_status {
            0 => "not initialised",
            1 => "initialised but not attached to a mesh",
            2 => "active on a mesh",
            _ => "in an unrecognised state",
        }
    }

    /// A commissioner could start a session now: the interface is active and the
    /// agent accepts some credential.
    #[must_use]
    pub const fn commissioning_path_open(self) -> bool {
        self.connection_mode != 0 && self.interface_status == 2
    }
}

/// Parse a DNS packet: header plus answer, authority, and additional records.
/// Questions are skipped.
pub fn parse_dns_packet(data: &[u8]) -> Option<DnsPacket> {
    let header = parse_dns_header(data)?;

    let mut offset = DNS_HEADER_LEN;

    for _ in 0..header.questions {
        let (_, name_consumed) = parse_dns_name(data, offset)?;
        // Question: name + QTYPE(2) + QCLASS(2)
        offset += name_consumed + 4;
        if offset > data.len() {
            return None;
        }
    }

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

/// Build a DNS query with one IN-class question. Transaction ID is 0 (mDNS).
#[must_use]
pub fn build_mdns_query(name: &str, record_type: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);

    // Header: ID=0, flags=0, qdcount=1, ancount=0, nscount=0, arcount=0
    packet.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

    encode_dns_name(&mut packet, name);

    // QTYPE, QCLASS
    packet.extend_from_slice(&record_type.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());

    packet
}

/// Encode a dotted name into DNS label format and append to `buf`.
fn encode_dns_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        let len = label.len();
        if len > 63 {
            // Labels are capped at 63 bytes; longer ones are truncated.
            buf.push(63);
            buf.extend_from_slice(&label.as_bytes()[..63]);
        } else {
            #[allow(clippy::cast_possible_truncation)]
            buf.push(len as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0); // root label
}

/// Service types queried by [`discover_services`].
///
/// The consumer set: the 113 types Home Assistant's `generated/zeroconf.py`
/// enumerates (Apache-2.0 — see `THIRD-PARTY-NOTICES.md`), plus the general
/// host/file-sharing types and the Matter and Thread types from the Matter
/// specification and `ot-br-posix`, which HA does not list in full.
///
/// Sent in batches of [`QUERY_BATCH`]; see [`discover_services_blocking`].
pub const SERVICE_QUERIES: &[&str] = &[
    // DNS-SD meta-query: best-effort, many embedded responders ignore it.
    "_services._dns-sd._udp.local",
    // General host, file sharing and management.
    "_http._tcp.local",
    "_https._tcp.local",
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_nfs._tcp.local",
    "_workstation._tcp.local",
    "_device-info._tcp.local",
    "_system-bridge._tcp.local",
    "_rfb._tcp.local",
    // Printers and 3D printers.
    "_ipp._tcp.local",
    "_ipps._tcp.local",
    "_printer._tcp.local",
    "_pdl-datastream._tcp.local",
    "_scanner._tcp.local",
    "_uscan._tcp.local",
    "_octoprint._tcp.local",
    // Apple ecosystem.
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_airport._tcp.local",
    "_appletv-v2._tcp.local",
    "_companion-link._tcp.local",
    "_hscp._tcp.local",
    "_mediaremotetv._tcp.local",
    "_sleep-proxy._udp.local",
    "_touch-able._tcp.local",
    "_daap._tcp.local",
    // Casting, televisions and media.
    "_googlecast._tcp.local",
    "_androidtvremote2._tcp.local",
    "_philipstv_rpc._tcp.local",
    "_philipstv_s_rpc._tcp.local",
    "_viziocast._tcp.local",
    "_plexmediasvr._tcp.local",
    "_xbmc-jsonrpc-h._tcp.local",
    "_Volumio._tcp.local",
    "_mass._tcp.local",
    "_kiosker._tcp.local",
    "_tvm._tcp.local",
    // Speakers and audio.
    "_sonos._tcp.local",
    "_heos-audio._tcp.local",
    "_musc._tcp.local",
    "_bangolufsen._tcp.local",
    "_linkplay._tcp.local",
    "_soundtouch._tcp.local",
    "_devialet-http._tcp.local",
    "_smoip._tcp.local",
    "_stream-magic._tcp.local",
    "_rio._tcp.local",
    // Home automation hubs, bridges and coordinators.
    "_hap._tcp.local",
    "_hap._udp.local",
    "_homekit._tcp.local",
    "_hue._tcp.local",
    "_lutron._tcp.local",
    "_bond._tcp.local",
    "_deako._tcp.local",
    "_kizbox._tcp.local",
    "_kizboxdev._tcp.local",
    "_czc._tcp.local",
    "_slzb-06._tcp.local",
    "_uzg-01._tcp.local",
    "_xzg._tcp.local",
    "_zigate-zigbee-gateway._tcp.local",
    "_zigbee-coordinator._tcp.local",
    "_zigstar_gw._tcp.local",
    "_zwave-js-server._tcp.local",
    "_esphomelib._tcp.local",
    "_wyoming._tcp.local",
    "_lookin._tcp.local",
    "_bbxsrv._tcp.local",
    "_dvl-deviceapi._tcp.local",
    "_powerhub._udp.local",
    "_systemnexa2._tcp.local",
    // Matter and Thread. Matter mandates IPv6 and this socket is IPv4-only, so
    // Thread-attached nodes answer only through their border router.
    "_matter._tcp.local",
    "_matterc._udp.local",
    "_matterd._udp.local",
    "_meshcop._udp.local",
    "_meshcop-e._udp.local",
    // Lighting, blinds and small IoT.
    "_nanoleafapi._tcp.local",
    "_nanoleafms._tcp.local",
    "_wled._tcp.local",
    "_elg._tcp.local",
    "_shelly._tcp.local",
    "_powerview._tcp.local",
    "_PowerView-G3._tcp.local",
    "_miio._udp.local",
    "_aicu-http._tcp.local",
    "_amzn-alexa._tcp.local",
    "_vege._tcp.local",
    // Solar, battery, energy metering and EV charging.
    "_enphase-envoy._tcp.local",
    "_solaredge-modbus._tcp.local",
    "_solarman._tcp.local",
    "_mypv._tcp.local",
    "_iometer._tcp.local",
    "_homewizard._tcp.local",
    "_hwenergy._tcp.local",
    "_openevse._tcp.local",
    "_nrgkick._tcp.local",
    "_technove-stations._tcp.local",
    "_gasleser._tcp.local",
    "_gaspulse._tcp.local",
    "_stromleser._tcp.local",
    "_waermeleser._tcp.local",
    "_wasserleser._tcp.local",
    "_wattwaechter._tcp.local",
    // Climate, appliances and sensors.
    "_ecobee._tcp.local",
    "_sideplay._tcp.local",
    "_dkapi._tcp.local",
    "_plugwise._tcp.local",
    "_homeconnect._tcp.local",
    "_mieleathome._tcp.local",
    "_prana._tcp.local",
    "_rabbitair._udp.local",
    "_airgradient._tcp.local",
    "_altruist._tcp.local",
    "_owserver._tcp.local",
    "_nut._tcp.local",
    "_droplet._tcp.local",
    "_ws._tcp.local",
    "_tbk_vmc._tcp.local",
    // Cameras, doorbells, security and network appliances.
    "_axis-video._tcp.local",
    "_elmax-ssl._tcp.local",
    "_fbx-api._tcp.local",
    "_easylink._tcp.local",
    "_api._tcp.local",
    "_api._udp.local",
];

/// PTR queries sent back-to-back before pausing to read responses.
const QUERY_BATCH: usize = 12;

/// Send PTR queries for [`SERVICE_QUERIES`] and collect responses until
/// `timeout_secs` (minimum 1) elapses or [`MAX_MDNS_RECORDS`] are collected.
pub async fn discover_services(timeout_secs: u64) -> Result<Vec<MdnsService>> {
    let services = tokio::task::spawn_blocking(move || discover_services_blocking(timeout_secs))
        .await
        .map_err(|e| anyhow::anyhow!("mDNS discovery task failed: {e}"))?;
    Ok(services)
}

/// Blocking half of [`discover_services`].
///
/// Queries go out in batches of [`QUERY_BATCH`] rather than one burst, with a
/// slice of the remaining budget spent reading after each batch; the tail of the
/// budget is left for the last batch's answers.
fn discover_services_blocking(timeout_secs: u64) -> Vec<MdnsService> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("could not bind mDNS socket: {e}");
            return Vec::new();
        }
    };

    let deadline = Instant::now() + discovery_timeout(timeout_secs);
    let dest = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST), MDNS_PORT);

    let batches = SERVICE_QUERIES.len().div_ceil(QUERY_BATCH);
    let mut all_records: Vec<(IpAddr, DnsRecord)> = Vec::new();

    for (i, batch) in SERVICE_QUERIES.chunks(QUERY_BATCH).enumerate() {
        for &svc_name in batch {
            let query = build_mdns_query(svc_name, TYPE_PTR);
            if socket.send_to(&query, dest).is_err() {
                tracing::debug!(service = svc_name, "could not send mDNS query");
            }
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        // One share per remaining batch plus one for the tail; always >= 2.
        let shares = u32::try_from(batches - i + 1).unwrap_or(u32::MAX);
        let slice = Instant::now() + remaining / shares;
        collect_mdns_records(&socket, slice, MAX_MDNS_RECORDS, &mut all_records);
        if all_records.len() >= MAX_MDNS_RECORDS {
            break;
        }
    }

    collect_mdns_records(&socket, deadline, MAX_MDNS_RECORDS, &mut all_records);
    correlate_mdns_records(&all_records)
}

/// `timeout_secs` as a `Duration`, clamped to at least 1s.
const fn discovery_timeout(timeout_secs: u64) -> Duration {
    Duration::from_secs(if timeout_secs == 0 { 1 } else { timeout_secs })
}

/// Read packets from `socket` until `deadline` passes, `max_records` are
/// collected, or a read fails. The read timeout is re-armed to the time remaining.
fn collect_mdns_records(
    socket: &UdpSocket,
    deadline: Instant,
    max_records: usize,
    all_records: &mut Vec<(IpAddr, DnsRecord)>,
) {
    let mut buf = [0u8; 4096];

    while all_records.len() < max_records {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if let Err(e) = socket.set_read_timeout(Some(remaining)) {
            tracing::warn!("could not set mDNS read timeout: {e}");
            break;
        }
        let Ok((n, addr)) = socket.recv_from(&mut buf) else {
            break;
        };
        if let Some(packet) = parse_dns_packet(&buf[..n]) {
            for record in packet.records {
                if all_records.len() >= max_records {
                    break;
                }
                all_records.push((addr.ip(), record));
            }
        }
    }
}

/// Build services by following PTR → SRV → A/AAAA/TXT. Unresolved targets fall
/// back to the IP of the responder that sent the SRV record (see [`resolve_ip`]).
fn correlate_mdns_records(records: &[(IpAddr, DnsRecord)]) -> Vec<MdnsService> {
    use std::collections::HashMap;

    let mut a_records: HashMap<&str, Ipv4Addr> = HashMap::new();
    let mut aaaa_records: HashMap<&str, Ipv6Addr> = HashMap::new();
    let mut srv_records: HashMap<&str, (&str, u16, IpAddr)> = HashMap::new();
    let mut txt_records: HashMap<&str, &[String]> = HashMap::new();
    let mut ptr_records: Vec<(&str, &str)> = Vec::new();

    for (responder, record) in records {
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
                srv_records.insert(name.as_str(), (target.as_str(), *port, *responder));
            }
            DnsRecord::Txt { name, entries } if !entries.is_empty() => {
                txt_records.insert(name.as_str(), entries.as_slice());
            }
            DnsRecord::Ptr { .. } | DnsRecord::Txt { .. } => {}
        }
    }

    // PTR: service type → instance name
    for (_, record) in records {
        if let DnsRecord::Ptr { name, target } = record {
            ptr_records.push((name.as_str(), target.as_str()));
        }
    }

    let ptr_targets: std::collections::HashSet<&str> =
        ptr_records.iter().map(|(_, t)| *t).collect();

    let mut services = Vec::new();
    let mut seen: std::collections::HashSet<(String, u16, String)> =
        std::collections::HashSet::new();

    for (service_type, instance_name) in &ptr_records {
        if let Some(&(target, port, responder)) = srv_records.get(instance_name) {
            let ip = resolve_ip(&a_records, &aaaa_records, target, responder);
            let txt = txt_records
                .get(instance_name)
                .map_or_else(Vec::new, |e| e.to_vec());

            let key = (ip.to_string(), port, (*service_type).to_owned());
            if seen.insert(key) {
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

    // SRV records not referenced by any PTR are direct announcements.
    for (responder, record) in records {
        if let DnsRecord::Srv {
            name, target, port, ..
        } = record
            && !ptr_targets.contains(name.as_str())
        {
            let ip = resolve_ip(&a_records, &aaaa_records, target.as_str(), *responder);
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

/// IP for `target` from A/AAAA records, else `responder` (source of the SRV record).
fn resolve_ip(
    a_records: &std::collections::HashMap<&str, Ipv4Addr>,
    aaaa_records: &std::collections::HashMap<&str, Ipv6Addr>,
    target: &str,
    responder: IpAddr,
) -> IpAddr {
    if let Some(&ipv4) = a_records.get(target) {
        return IpAddr::V4(ipv4);
    }
    if let Some(&ipv6) = aaaa_records.get(target) {
        return IpAddr::V6(ipv6);
    }
    responder
}

/// Extract the service type from an instance name.
///
/// E.g. `"My Printer._ipp._tcp.local"` → `"_ipp._tcp.local"`.
fn extract_service_type(name: &str) -> String {
    // A leading '_' means the name is already a bare service type.
    if name.starts_with('_') {
        name.to_owned()
    } else {
        name.find("._")
            .map_or_else(|| name.to_owned(), |idx| name[idx + 1..].to_owned())
    }
}

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

    #[test]
    fn test_correlate_unresolved_target_uses_srv_responder() {
        let other = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let cam = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        let records = vec![
            (
                other,
                DnsRecord::A {
                    name: "other.local".to_owned(),
                    ip: Ipv4Addr::new(192, 168, 1, 10),
                },
            ),
            (
                cam,
                DnsRecord::Ptr {
                    name: "_rtsp._tcp.local".to_owned(),
                    target: "Cam._rtsp._tcp.local".to_owned(),
                },
            ),
            (
                cam,
                DnsRecord::Srv {
                    name: "Cam._rtsp._tcp.local".to_owned(),
                    priority: 0,
                    weight: 0,
                    port: 554,
                    target: "cam.local".to_owned(),
                },
            ),
        ];

        let services = correlate_mdns_records(&records);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].ip, cam);
    }

    #[test]
    fn test_correlate_direct_srv_unresolved_target_uses_responder() {
        let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let printer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let records = vec![
            (
                other,
                DnsRecord::Aaaa {
                    name: "other.local".to_owned(),
                    ip: Ipv6Addr::LOCALHOST,
                },
            ),
            (
                printer,
                DnsRecord::Srv {
                    name: "printer._ipp._tcp.local".to_owned(),
                    priority: 0,
                    weight: 0,
                    port: 631,
                    target: "printer.local".to_owned(),
                },
            ),
        ];

        let services = correlate_mdns_records(&records);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].ip, printer);
    }

    // ── Receive loop tests ─────────────────────────────────────────

    #[test]
    fn test_discovery_timeout_clamps_zero() {
        assert_eq!(discovery_timeout(0), Duration::from_secs(1));
        assert_eq!(discovery_timeout(3), Duration::from_secs(3));
    }

    #[test]
    fn test_collect_records_past_deadline_does_not_block() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let start = Instant::now();
        let mut records = Vec::new();
        collect_mdns_records(&socket, start, 10, &mut records);
        assert!(records.is_empty());
        assert!(start.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn test_collect_records_returns_at_deadline() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let start = Instant::now();
        let mut records = Vec::new();
        collect_mdns_records(
            &socket,
            start + Duration::from_millis(200),
            10,
            &mut records,
        );
        assert!(records.is_empty());
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(100), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }

    #[test]
    fn test_collect_records_caps_record_count() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest = receiver.local_addr().unwrap();

        // 4 packets x 3 A records = 12 records offered.
        let mut packet = build_test_header(0, 0x8400, 0, 3, 0, 0);
        for i in 1..=3u8 {
            packet.extend_from_slice(&build_a_record(
                &format!("host{i}.local"),
                Ipv4Addr::new(10, 0, 0, i),
                120,
            ));
        }
        for _ in 0..4 {
            sender.send_to(&packet, dest).unwrap();
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut records = Vec::new();
        collect_mdns_records(&receiver, deadline, 5, &mut records);
        assert_eq!(records.len(), 5);
        assert!(
            records
                .iter()
                .all(|(ip, _)| *ip == IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
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

    // ── TXT interpretation ─────────────────────────────────────────

    fn txt(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn test_txt_get_is_case_insensitive_on_keys() {
        let records = txt(&["MD=Shelly", "fn=Kitchen"]);
        assert_eq!(txt_get(&records, "md"), Some("Shelly"));
        assert_eq!(txt_get(&records, "FN"), Some("Kitchen"));
        assert_eq!(txt_get(&records, "gen"), None);
    }

    #[test]
    fn test_txt_get_boolean_attribute() {
        let records = txt(&["sf", "ci=2"]);
        assert_eq!(txt_get(&records, "sf"), Some(""));
    }

    #[test]
    fn test_txt_get_empty_value() {
        let records = txt(&["md="]);
        assert_eq!(txt_get(&records, "md"), Some(""));
    }

    #[test]
    fn test_render_txt_entry_keeps_printable_utf8() {
        assert_eq!(
            render_txt_entry(b"nn=OpenThread-a1b2"),
            "nn=OpenThread-a1b2"
        );
    }

    #[test]
    fn test_render_txt_entry_hex_encodes_binary_value() {
        // Thread `xp` is an 8-byte extended PAN id, not text.
        let mut raw = b"xp=".to_vec();
        raw.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03]);
        assert_eq!(render_txt_entry(&raw), "xp=0xdeadbeef00010203");
    }

    #[test]
    fn test_render_txt_entry_without_equals() {
        assert_eq!(render_txt_entry(b"flag"), "flag");
    }

    #[test]
    fn test_mdns_txt_parses_homekit_and_shelly_keys() {
        let records = txt(&["md=Shelly Plus 1", "fn=Porch", "gen=2"]);
        let parsed = MdnsTxt::parse("_shelly._tcp.local", &records);
        assert_eq!(parsed.model.as_deref(), Some("Shelly Plus 1"));
        assert_eq!(parsed.friendly_name.as_deref(), Some("Porch"));
        assert_eq!(parsed.generation.as_deref(), Some("2"));
    }

    #[test]
    fn mdns_txt_ignores_raop_md_and_vn() {
        let records = txt(&["md=0,1,2", "vn=65537", "am=AppleTV14,1"]);
        let parsed = MdnsTxt::parse("_raop._tcp.local", &records);
        assert_eq!(parsed.model.as_deref(), Some("AppleTV14,1"));
        assert_eq!(parsed.manufacturer, None);

        // `_airplay._tcp` spells the same model `model=`.
        let airplay = MdnsTxt::parse(
            "_airplay._tcp.local",
            &txt(&["md=0,1,2", "model=AppleTV14,1"]),
        );
        assert_eq!(airplay.model.as_deref(), Some("AppleTV14,1"));

        // The same keys still read as model and vendor where they mean that.
        let hap = MdnsTxt::parse("_hap._tcp.local", &txt(&["md=Eve Door 20EBP"]));
        assert_eq!(hap.model.as_deref(), Some("Eve Door 20EBP"));
        let thread = MdnsTxt::parse("_meshcop._udp.local", &txt(&["mn=BorderRouter", "vn=Nest"]));
        assert_eq!(thread.model.as_deref(), Some("BorderRouter"));
        assert_eq!(thread.manufacturer.as_deref(), Some("Nest"));

        // An unknown service type gets neither ambiguous key.
        let generic = MdnsTxt::parse("_http._tcp.local", &txt(&["md=0,1,2", "vn=65537"]));
        assert_eq!(generic.model, None);
        assert_eq!(generic.manufacturer, None);
    }

    #[test]
    fn test_mdns_txt_parses_matter_commissioning_keys() {
        let records = txt(&["VP=65521+32769", "CM=2", "D=3840", "DT=21", "DN=Front Lamp"]);
        let parsed = MdnsTxt::parse("_matterc._udp.local", &records);
        assert_eq!(parsed.vendor_product.as_deref(), Some("65521+32769"));
        assert_eq!(parsed.commissioning_mode, Some(2));
        assert_eq!(parsed.discriminator.as_deref(), Some("3840"));
        assert_eq!(parsed.device_type_id.as_deref(), Some("21"));
        assert_eq!(parsed.device_name.as_deref(), Some("Front Lamp"));
    }

    #[test]
    fn test_mdns_txt_parses_thread_border_agent_keys() {
        let records = txt(&[
            "rv=1",
            "tv=1.3.0",
            "nn=HomeThread",
            "xp=0xdead00beef00cafe",
            "sb=0x00000131",
            "omr=0xfd11223300000000",
        ]);
        let parsed = MdnsTxt::parse("_meshcop._udp.local", &records);
        assert_eq!(parsed.thread_network_name.as_deref(), Some("HomeThread"));
        assert_eq!(parsed.thread_version.as_deref(), Some("1.3.0"));
        assert_eq!(
            parsed.thread_extended_pan_id.as_deref(),
            Some("0xdead00beef00cafe")
        );
        assert_eq!(parsed.thread_state_bitmap.as_deref(), Some("0x00000131"));
        assert_eq!(
            parsed.thread_omr_prefix.as_deref(),
            Some("0xfd11223300000000")
        );
    }

    #[test]
    fn test_mdns_txt_ignores_unparseable_commissioning_mode() {
        assert_eq!(
            MdnsTxt::parse("_matterc._udp.local", &txt(&["CM=open"])).commissioning_mode,
            None
        );
    }

    // ── Service query list ─────────────────────────────────────────

    #[test]
    fn test_service_queries_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for &query in SERVICE_QUERIES {
            assert!(seen.insert(query), "duplicate service query {query}");
            assert!(query.starts_with('_'), "{query}");
            assert!(
                query
                    .rsplit_once('.')
                    .is_some_and(|(_, tld)| tld == "local"),
                "{query}"
            );
            assert!(!query.ends_with('.'), "{query}");
        }
    }

    /// The query list must actually be spread over several batches: one burst of
    /// 127 PTR packets is what the batching exists to avoid.
    #[test]
    fn test_service_queries_are_spread_over_several_batches() {
        const { assert!(QUERY_BATCH > 0) };
        let batches: Vec<_> = SERVICE_QUERIES.chunks(QUERY_BATCH).collect();
        assert!(batches.len() >= 8, "{} batches", batches.len());
        assert_eq!(
            batches.iter().map(|b| b.len()).sum::<usize>(),
            SERVICE_QUERIES.len()
        );
        // `discover_services_blocking` divides the remaining budget by
        // `batches - i + 1`; even at the 1s floor every share must stay non-zero.
        let budget = discovery_timeout(0);
        for i in 0..batches.len() {
            let shares = u32::try_from(batches.len() - i + 1).expect("batch count fits u32");
            assert!(!(budget / shares).is_zero(), "batch {i}");
        }
    }

    // ── Thread border-agent state bitmap ───────────────────────────

    /// Live value from a Thread border router on the author's LAN.
    #[test]
    fn test_thread_state_bitmap_decodes_a_live_value() {
        let s = ThreadStateBitmap::parse("0x00000fb1").expect("parses");
        assert_eq!(s.raw, 0x0000_0fb1);
        assert_eq!(s.connection_mode, 1);
        assert_eq!(s.interface_status, 2);
        assert_eq!(s.availability, 1);
        assert!(s.bbr_active);
        assert!(s.bbr_primary);
        assert_eq!(s.thread_role, 3);
        assert!(s.epskc_supported);
        assert!(s.commissioning_path_open());
    }

    #[test]
    fn test_thread_state_bitmap_closed_agent() {
        // Interface active, connection mode 0: nothing can connect.
        let s = ThreadStateBitmap::from_bits(0b1_0000);
        assert_eq!(s.connection_mode, 0);
        assert_eq!(s.interface_status, 2);
        assert!(!s.commissioning_path_open());
        // Connection mode offered but the interface is not up.
        let s = ThreadStateBitmap::from_bits(0b1);
        assert!(!s.commissioning_path_open());
    }

    #[test]
    fn test_thread_state_bitmap_accepts_decimal_and_rejects_junk() {
        assert_eq!(
            ThreadStateBitmap::parse("4017"),
            ThreadStateBitmap::parse("0x00000fb1")
        );
        assert!(ThreadStateBitmap::parse("").is_none());
        assert!(ThreadStateBitmap::parse("0x").is_none());
        assert!(ThreadStateBitmap::parse("0xzz").is_none());
        assert!(ThreadStateBitmap::parse("0x1ffffffff").is_none());
        assert!(ThreadStateBitmap::parse("nope").is_none());
    }

    #[test]
    fn test_thread_state_bitmap_names_unknown_values() {
        let s = ThreadStateBitmap::from_bits(0b111 | (0b11 << 3));
        assert!(s.connection_mode_name().contains("does not recognise"));
        assert!(s.interface_status_name().contains("unrecognised"));
    }

    // ── Proptest: never panic on arbitrary input ───────────────────

    proptest! {
        #[test]
        fn prop_render_txt_entry_no_panic(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = render_txt_entry(&data);
        }

        #[test]
        fn prop_parse_txt_rdata_no_panic(data in proptest::collection::vec(any::<u8>(), 0..600)) {
            let entries = parse_txt_rdata(&data);
            let _ = MdnsTxt::parse("_http._tcp.local", &entries);
            let _ = txt_get(&entries, "md");
        }

        #[test]
        fn prop_parse_dns_packet_no_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = parse_dns_packet(&data);
        }

        #[test]
        fn prop_thread_state_bitmap_no_panic(raw in ".*") {
            if let Some(s) = ThreadStateBitmap::parse(&raw) {
                let _ = s.connection_mode_name();
                let _ = s.interface_status_name();
                let _ = s.commissioning_path_open();
            }
        }

        #[test]
        fn prop_thread_state_bitmap_roundtrips(raw in any::<u32>()) {
            let s = ThreadStateBitmap::from_bits(raw);
            prop_assert_eq!(s.raw, raw);
            prop_assert_eq!(ThreadStateBitmap::parse(&format!("{raw}")), Some(s));
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
