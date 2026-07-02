use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{DeviceHint, Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::Scanner;
use crate::ports::udp_probe;

/// SNMP default community-string scanner.
///
/// SNMP (Simple Network Management Protocol) speaks UDP/161, which the TCP
/// connect port scan cannot see. A device that answers a v2c `GetRequest` for
/// the community string `public` leaks its entire inventory MIB (hostname, OS,
/// interfaces, ARP/routing tables, running processes) to anyone on the LAN; a
/// device that answers to `private` typically also grants **write** access,
/// letting an attacker reconfigure interfaces, reboot the device, or repoint
/// routes. Default and guessable community strings on printers, switches,
/// cameras, and consumer routers are a perennial, actively-exploited weakness.
///
/// Unlike the TCP-gated scanners (e.g. [`crate::database::DatabaseScanner`]),
/// this one probes every discovered device directly on UDP/161 rather than
/// gating on an open TCP port — the port scan simply never reports it. The
/// probe is pure detection: a single read-only `GET` of `sysDescr.0`. It never
/// writes, never brute-forces beyond the two canonical default communities, and
/// never alters device state.
pub struct SnmpScanner;

/// SNMP agent port.
const SNMP_PORT: u16 = 161;

/// Per-datagram timeout. SNMP is UDP, so a lost packet just looks like silence;
/// a couple of seconds is plenty on a LAN without dragging the scan out.
const SNMP_TIMEOUT: Duration = Duration::from_secs(2);

/// The community strings we test — the two canonical defaults only. Kept
/// deliberately tiny: this is default-credential *detection*, not brute force.
/// Order matters: `public` (read-only) is tried before `private` (read-write),
/// and we stop at the first that answers.
const DEFAULT_COMMUNITIES: &[&str] = &["public", "private"];

/// BER object identifier for `sysDescr.0` (`1.3.6.1.2.1.1.1.0`).
///
/// The first two sub-identifiers `1.3` pack into a single byte `40*1 + 3 = 0x2b`;
/// the remainder encode one byte each.
const OID_SYSDESCR_0: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

// ── BER/DER encoding helpers ────────────────────────────────────────────────

/// Append a BER definite length to `out` (short form `< 128`, else long form).
fn encode_ber_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0x7f));
        return;
    }
    // Long form: 0x80 | number-of-length-bytes, then big-endian length.
    let bytes = len.to_be_bytes();
    let first_significant = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first_significant..];
    out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0));
    out.extend_from_slice(significant);
}

/// Build a complete BER TLV: `tag`, definite length, then `content`.
fn ber_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    encode_ber_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

/// Encode the *content* octets of a non-negative BER INTEGER (minimal form).
///
/// Leading zero bytes are stripped; a `0x00` pad is prepended when the top bit
/// of the first octet is set, so the value never reads as negative.
fn ber_integer_content(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first_significant = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = bytes[first_significant..].to_vec();
    if content[0] & 0x80 != 0 {
        content.insert(0, 0x00);
    }
    content
}

/// Build a full SNMP v2c `GetRequest` for `sysDescr.0` with the given community.
///
/// Wire structure (all BER/DER):
/// ```text
/// SEQUENCE {
///   INTEGER version = 1            -- 1 == SNMPv2c
///   OCTET STRING community
///   GetRequest-PDU [0xA0] {
///     INTEGER request-id
///     INTEGER error-status = 0
///     INTEGER error-index  = 0
///     SEQUENCE {                   -- variable-bindings
///       SEQUENCE {                 -- one binding
///         OID  1.3.6.1.2.1.1.1.0   -- sysDescr.0
///         NULL
///       }
///     }
///   }
/// }
/// ```
fn build_get_request(community: &str, request_id: u32) -> Vec<u8> {
    // Innermost: the single variable binding { OID sysDescr.0, NULL }.
    let mut varbind = ber_tlv(0x06, OID_SYSDESCR_0);
    varbind.extend_from_slice(&ber_tlv(0x05, &[])); // NULL value
    let varbind = ber_tlv(0x30, &varbind);
    let varbind_list = ber_tlv(0x30, &varbind);

    // GetRequest-PDU body.
    let mut pdu = ber_tlv(0x02, &ber_integer_content(request_id)); // request-id
    pdu.extend_from_slice(&ber_tlv(0x02, &[0x00])); // error-status = 0
    pdu.extend_from_slice(&ber_tlv(0x02, &[0x00])); // error-index  = 0
    pdu.extend_from_slice(&varbind_list);
    let pdu = ber_tlv(0xA0, &pdu); // context tag [0] == GetRequest

    // Outer message.
    let mut msg = ber_tlv(0x02, &[0x01]); // version = 1 (v2c)
    msg.extend_from_slice(&ber_tlv(0x04, community.as_bytes())); // community
    msg.extend_from_slice(&pdu);
    ber_tlv(0x30, &msg)
}

// ── BER/DER decoding helpers ────────────────────────────────────────────────

/// A parsed BER TLV header: `(tag, content_offset, content_len)`, where
/// `content_offset` is the byte index (within the input slice) at which the
/// value begins. `content_offset + content_len` is the total consumed length.
type Tlv = (u8, usize, usize);

/// Read one BER TLV header from the front of `data`.
///
/// Supports short-form and long-form (up to 4 length bytes) definite lengths.
/// Returns `None` on truncated input, indefinite length, or a length that
/// overruns the buffer — so callers can never index out of bounds.
fn read_ber_tlv(data: &[u8]) -> Option<Tlv> {
    if data.len() < 2 {
        return None;
    }
    let tag = data[0];
    let first = data[1];
    let (content_offset, content_len) = if first & 0x80 == 0 {
        (2, usize::from(first))
    } else {
        let num = usize::from(first & 0x7f);
        if num == 0 || num > 4 || data.len() < 2 + num {
            return None; // indefinite form or too long / truncated
        }
        let mut len = 0usize;
        for &b in &data[2..2 + num] {
            len = (len << 8) | usize::from(b);
        }
        (2 + num, len)
    };
    if data.len() < content_offset + content_len {
        return None;
    }
    Some((tag, content_offset, content_len))
}

/// Classification of an SNMP datagram received in reply to our `GetRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SnmpResponse {
    /// `true` when the PDU tag is `0xA2` (`GetResponse`) — proof the agent
    /// accepted the community string.
    is_get_response: bool,
    /// Best-effort `sysDescr.0` string extracted from the first variable
    /// binding, if present and non-empty.
    sys_descr: Option<String>,
}

/// Parse an SNMP v1/v2c message, returning the PDU classification and any
/// `sysDescr` payload. Returns `None` if the bytes are not a well-formed SNMP
/// message (outer `SEQUENCE` → `INTEGER` version → `OCTET STRING` community →
/// PDU).
fn parse_snmp_response(data: &[u8]) -> Option<SnmpResponse> {
    let (tag, off, len) = read_ber_tlv(data)?;
    if tag != 0x30 {
        return None;
    }
    let body = &data[off..off + len];

    // version (INTEGER)
    let (vtag, voff, vlen) = read_ber_tlv(body)?;
    if vtag != 0x02 {
        return None;
    }
    let rest = &body[voff + vlen..];

    // community (OCTET STRING)
    let (ctag, coff, clen) = read_ber_tlv(rest)?;
    if ctag != 0x04 {
        return None;
    }
    let rest = &rest[coff + clen..];

    // PDU (context tag: 0xA2 for GetResponse)
    let (ptag, poff, plen) = read_ber_tlv(rest)?;
    let is_get_response = ptag == 0xA2;
    let pdu_body = &rest[poff..poff + plen];

    Some(SnmpResponse {
        is_get_response,
        sys_descr: extract_sys_descr(pdu_body),
    })
}

/// Extract the first variable-binding value from a response PDU body, when it is
/// an `OCTET STRING` (as `sysDescr.0` is). Best-effort: any structural surprise
/// yields `None` rather than an error.
///
/// PDU body layout: `INTEGER request-id`, `INTEGER error-status`,
/// `INTEGER error-index`, then the variable-bindings `SEQUENCE`.
fn extract_sys_descr(pdu_body: &[u8]) -> Option<String> {
    // Skip request-id, error-status, error-index.
    let mut cursor = pdu_body;
    for _ in 0..3 {
        let (_, off, len) = read_ber_tlv(cursor)?;
        cursor = &cursor[off + len..];
    }

    // variable-bindings SEQUENCE
    let (tag, off, len) = read_ber_tlv(cursor)?;
    if tag != 0x30 {
        return None;
    }
    let varbind_list = &cursor[off..off + len];

    // first binding SEQUENCE { OID, value }
    let (btag, boff, blen) = read_ber_tlv(varbind_list)?;
    if btag != 0x30 {
        return None;
    }
    let binding = &varbind_list[boff..boff + blen];

    // OID
    let (oid_tag, oid_off, oid_len) = read_ber_tlv(binding)?;
    if oid_tag != 0x06 {
        return None;
    }
    let value = &binding[oid_off + oid_len..];

    // value must be an OCTET STRING to be a printable sysDescr.
    let (vtag, voff, vlen) = read_ber_tlv(value)?;
    if vtag != 0x04 {
        return None;
    }
    let text = String::from_utf8_lossy(&value[voff..voff + vlen])
        .trim()
        .to_owned();
    if text.is_empty() { None } else { Some(text) }
}

/// Guess a vendor/OS keyword from a `sysDescr` string, for device enrichment.
///
/// `sysDescr` values are free-form but conventionally begin with the vendor or
/// OS name (e.g. `"Linux router 5.4.0 ... x86_64"`, `"Cisco IOS Software ..."`,
/// `"RouterOS RB750"`). We match a small set of well-known keywords; a miss
/// simply means no vendor hint.
fn guess_vendor(sys_descr: &str) -> Option<&'static str> {
    let lower = sys_descr.to_ascii_lowercase();
    VENDOR_KEYWORDS
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map(|&(_, vendor)| vendor)
}

/// `(lowercase needle, canonical vendor)` pairs for [`guess_vendor`].
const VENDOR_KEYWORDS: &[(&str, &str)] = &[
    ("cisco", "Cisco"),
    ("mikrotik", "MikroTik"),
    ("routeros", "MikroTik"),
    ("ubiquiti", "Ubiquiti"),
    ("edgeos", "Ubiquiti"),
    ("juniper", "Juniper"),
    ("arista", "Arista"),
    ("netgear", "Netgear"),
    ("tp-link", "TP-Link"),
    ("d-link", "D-Link"),
    ("hp ", "HP"),
    ("hewlett", "HP"),
    ("brother", "Brother"),
    ("canon", "Canon"),
    ("epson", "Epson"),
    ("xerox", "Xerox"),
    ("lexmark", "Lexmark"),
    ("synology", "Synology"),
    ("qnap", "QNAP"),
    ("windows", "Microsoft"),
    ("linux", "Linux"),
    ("vyos", "VyOS"),
    ("fortinet", "Fortinet"),
    ("aruba", "Aruba"),
];

/// The community that an agent accepted, plus the parsed response.
struct SnmpHit {
    community: &'static str,
    response: SnmpResponse,
}

/// Probe one host on UDP/161 with each default community in order, returning the
/// first that yields a `GetResponse` (accepted). `None` means no community was
/// accepted (silence, filtered, or malformed replies) — inconclusive, not proof
/// of safety.
async fn probe_snmp(ip: IpAddr) -> Option<SnmpHit> {
    let addr = SocketAddr::new(ip, SNMP_PORT);
    for (idx, &community) in DEFAULT_COMMUNITIES.iter().enumerate() {
        // A distinct, benign request-id per attempt aids correlation in logs.
        let request_id = 0x7269_0000 | u32::try_from(idx).unwrap_or(0);
        let packet = build_get_request(community, request_id);
        let Some(reply) = udp_probe(addr, &packet, SNMP_TIMEOUT).await else {
            continue;
        };
        if let Some(response) = parse_snmp_response(&reply)
            && response.is_get_response
        {
            return Some(SnmpHit {
                community,
                response,
            });
        }
    }
    None
}

/// Build a `DeviceHint` from a `sysDescr` string (OS guess + best-effort vendor).
fn hint_from_sys_descr(sys_descr: &str) -> DeviceHint {
    let mut hint = DeviceHint::new().with_os_guess(sys_descr);
    if let Some(vendor) = guess_vendor(sys_descr) {
        hint = hint.with_vendor(vendor);
    }
    hint
}

/// Turn an accepted-community hit into a finding.
fn finding_for_hit(ip: IpAddr, hit: &SnmpHit) -> Finding {
    let community = hit.community;
    let sys_descr = hit.response.sys_descr.as_deref();

    // sysDescr snippet for the human-readable description, if we got one.
    let descr_sentence = sys_descr.map_or_else(String::new, |d| {
        format!(" The agent reported sysDescr: \"{d}\".")
    });

    let (severity, cwe, access, title, remediation) = if community == "private" {
        (
            Severity::High,
            "CWE-284",
            "read-write",
            format!("SNMP read-write default community \"private\" accepted on {ip}:{SNMP_PORT}"),
            "This grants write access: an attacker can reconfigure interfaces, \
             alter routing, or reboot the device. Remove the default community, \
             disable SNMPv1/v2c entirely, and switch to SNMPv3 with authentication \
             and privacy (authPriv). If SNMP is not needed, disable the agent.",
        )
    } else {
        (
            Severity::Medium,
            "CWE-306",
            "read-only",
            format!("SNMP default community \"public\" accepted on {ip}:{SNMP_PORT}"),
            "This exposes the device's full inventory MIB (hostname, OS, interfaces, \
             ARP and routing tables, sometimes running processes) to any host on the \
             LAN. Set a strong, non-default community and restrict SNMP to trusted \
             management hosts, or better, disable SNMPv1/v2c and use SNMPv3 (authPriv). \
             If SNMP is not needed, disable the agent.",
        )
    };

    let description = format!(
        "The SNMP agent at {ip}:{SNMP_PORT} answered a v2c GetRequest that used the \
         well-known default community string \"{community}\", returning a valid \
         GetResponse ({access} access).{descr_sentence} Default community strings are \
         trivially guessed and are routinely abused for network reconnaissance and \
         device takeover. {remediation}"
    );

    // Evidence: exactly what proves the finding.
    let evidence = sys_descr.map_or_else(
        || format!("GetResponse (0xA2) to community \"{community}\""),
        |d| format!("GetResponse (0xA2) to community \"{community}\"; sysDescr=\"{d}\""),
    );

    let mut finding = Finding::new("snmp", &title, &description, severity)
        // A valid GetResponse to our unauthenticated GET is direct proof.
        .with_confidence(rikitikitavi_core::Confidence::Confirmed)
        .with_ip(ip)
        .with_port(SNMP_PORT)
        .with_service("SNMP")
        .with_cwe(cwe)
        .with_evidence(evidence)
        .with_references(refs![
            "https://www.rfc-editor.org/rfc/rfc3416",
            "https://cwe.mitre.org/data/definitions/284.html",
            "https://owasp.org/www-project-top-ten/",
        ]);

    if let Some(descr) = sys_descr {
        finding = finding.with_device_hint(hint_from_sys_descr(descr));
    }
    finding
}

#[async_trait]
impl Scanner for SnmpScanner {
    fn id(&self) -> &'static str {
        "snmp"
    }

    fn name(&self) -> &'static str {
        "SNMP Default Community"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running SNMP default-community scan");
        let mut findings = Vec::new();

        // Skip in Passive/quick mode — this sends application-layer probes.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping SNMP scan in quick scan mode");
            return Ok(findings);
        }

        // SNMP is UDP/161, which the TCP port scan never reports, so we cannot
        // gate on an open TCP port. Probe every discovered device directly;
        // fall back to the ARP cache if Phase 1 discovery has not run.
        let targets: Vec<IpAddr> = if ctx.discovered_devices.is_empty() {
            let arp_entries =
                rikitikitavi_network::read_arp_cache().map_err(|e| ScanError::ScannerFailed {
                    scanner: "snmp".to_owned(),
                    message: format!("failed to read ARP cache: {e}"),
                })?;
            arp_entries.iter().map(|e| e.ip).collect()
        } else {
            ctx.discovered_devices.iter().map(|d| d.ip).collect()
        };

        if targets.is_empty() {
            tracing::info!("no SNMP targets found");
            return Ok(findings);
        }

        tracing::info!(target_count = targets.len(), "probing SNMP agents");

        for ip in targets {
            if let Some(hit) = probe_snmp(ip).await {
                tracing::debug!(ip = %ip, community = hit.community, "SNMP community accepted");
                findings.push(finding_for_hit(ip, &hit));
            }
        }

        tracing::info!(
            findings_count = findings.len(),
            "SNMP default-community scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        20
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── GetRequest builder: exact-bytes tests ───────────────────────────────

    #[test]
    fn test_build_get_request_public_exact_bytes() {
        // Full, hand-verified SNMP v2c GetRequest for sysDescr.0, community
        // "public", request-id 1.
        let packet = build_get_request("public", 1);
        let expected: Vec<u8> = vec![
            0x30, 0x26, // SEQUENCE, len 38
            0x02, 0x01, 0x01, // INTEGER version = 1 (v2c)
            0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // OCTET STRING "public"
            0xA0, 0x19, // GetRequest-PDU [0], len 25
            0x02, 0x01, 0x01, // request-id = 1
            0x02, 0x01, 0x00, // error-status = 0
            0x02, 0x01, 0x00, // error-index = 0
            0x30, 0x0E, // varbind-list SEQUENCE, len 14
            0x30, 0x0C, // varbind SEQUENCE, len 12
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID sysDescr.0
            0x05, 0x00, // NULL
        ];
        assert_eq!(packet, expected);
    }

    #[test]
    fn test_build_get_request_private_community_only_differs_in_string() {
        let public = build_get_request("public", 1);
        let private = build_get_request("private", 1);
        // "private" is one byte longer than "public"; that propagates into the
        // three enclosing length octets (outer SEQUENCE, and nothing after the
        // community since the PDU is unchanged in size).
        assert_eq!(private.len(), public.len() + 1);
        assert_eq!(private[0], 0x30);
        assert_eq!(private[5], 0x04); // OCTET STRING tag
        assert_eq!(private[6], 0x07); // length of "private"
        assert_eq!(&private[7..14], b"private");
    }

    #[test]
    fn test_build_get_request_request_id_encoding() {
        // request-id 0 encodes as a single 0x00 content byte.
        let p0 = build_get_request("public", 0);
        // Locate the PDU: after outer header (2) + version (3) + community (8).
        // request-id TLV starts right after the 0xA0 PDU header (2 bytes).
        let pdu_start = 2 + 3 + 8;
        assert_eq!(p0[pdu_start], 0xA0);
        let reqid = pdu_start + 2;
        assert_eq!(&p0[reqid..reqid + 3], &[0x02, 0x01, 0x00]);
    }

    // ── BER integer content encoding ────────────────────────────────────────

    #[test]
    fn test_ber_integer_content_small() {
        assert_eq!(ber_integer_content(0), vec![0x00]);
        assert_eq!(ber_integer_content(1), vec![0x01]);
        assert_eq!(ber_integer_content(127), vec![0x7f]);
    }

    #[test]
    fn test_ber_integer_content_high_bit_padded() {
        // 0x80 would read as negative, so a leading 0x00 pad is inserted.
        assert_eq!(ber_integer_content(0x80), vec![0x00, 0x80]);
        assert_eq!(ber_integer_content(0xFF), vec![0x00, 0xFF]);
    }

    #[test]
    fn test_ber_integer_content_multibyte() {
        assert_eq!(ber_integer_content(0x0102), vec![0x01, 0x02]);
        assert_eq!(ber_integer_content(0x0001_0000), vec![0x01, 0x00, 0x00]);
        assert_eq!(
            ber_integer_content(0xFFFF_FFFF),
            vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    // ── BER length encoding ─────────────────────────────────────────────────

    #[test]
    fn test_encode_ber_length_short_form() {
        let mut out = Vec::new();
        encode_ber_length(0, &mut out);
        assert_eq!(out, vec![0x00]);
        out.clear();
        encode_ber_length(127, &mut out);
        assert_eq!(out, vec![0x7f]);
    }

    #[test]
    fn test_encode_ber_length_long_form() {
        let mut out = Vec::new();
        encode_ber_length(128, &mut out);
        assert_eq!(out, vec![0x81, 0x80]);
        out.clear();
        encode_ber_length(255, &mut out);
        assert_eq!(out, vec![0x81, 0xFF]);
        out.clear();
        encode_ber_length(256, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x00]);
        out.clear();
        encode_ber_length(300, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x2C]);
    }

    #[test]
    fn test_ber_tlv_wraps_content() {
        assert_eq!(ber_tlv(0x04, b"hi"), vec![0x04, 0x02, b'h', b'i']);
        assert_eq!(ber_tlv(0x05, &[]), vec![0x05, 0x00]);
    }

    // ── read_ber_tlv ────────────────────────────────────────────────────────

    #[test]
    fn test_read_ber_tlv_short_form() {
        let (tag, off, len) = read_ber_tlv(&[0x02, 0x01, 0x2a]).unwrap();
        assert_eq!(tag, 0x02);
        assert_eq!(off, 2);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_read_ber_tlv_long_form() {
        // 0x82 0x01 0x00 => length 256; supply enough bytes.
        let mut data = vec![0x30, 0x82, 0x01, 0x00];
        data.extend(std::iter::repeat_n(0u8, 256));
        let (tag, off, len) = read_ber_tlv(&data).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(off, 4);
        assert_eq!(len, 256);
    }

    #[test]
    fn test_read_ber_tlv_truncated_content() {
        // Claims 5 content bytes but only 2 present.
        assert!(read_ber_tlv(&[0x04, 0x05, 0x01, 0x02]).is_none());
    }

    #[test]
    fn test_read_ber_tlv_too_short() {
        assert!(read_ber_tlv(&[]).is_none());
        assert!(read_ber_tlv(&[0x30]).is_none());
    }

    #[test]
    fn test_read_ber_tlv_indefinite_rejected() {
        // 0x80 == indefinite length; unsupported.
        assert!(read_ber_tlv(&[0x30, 0x80, 0x00, 0x00]).is_none());
    }

    // ── Response classification ─────────────────────────────────────────────

    /// Build a minimal SNMP `GetResponse` carrying one octet-string varbind value.
    fn build_get_response(community: &str, sys_descr: &[u8]) -> Vec<u8> {
        let mut varbind = ber_tlv(0x06, OID_SYSDESCR_0);
        varbind.extend_from_slice(&ber_tlv(0x04, sys_descr)); // value = OCTET STRING
        let varbind = ber_tlv(0x30, &varbind);
        let varbind_list = ber_tlv(0x30, &varbind);

        let mut pdu = ber_tlv(0x02, &ber_integer_content(1)); // request-id
        pdu.extend_from_slice(&ber_tlv(0x02, &[0x00])); // error-status
        pdu.extend_from_slice(&ber_tlv(0x02, &[0x00])); // error-index
        pdu.extend_from_slice(&varbind_list);
        let pdu = ber_tlv(0xA2, &pdu); // GetResponse-PDU [2]

        let mut msg = ber_tlv(0x02, &[0x01]); // version v2c
        msg.extend_from_slice(&ber_tlv(0x04, community.as_bytes()));
        msg.extend_from_slice(&pdu);
        ber_tlv(0x30, &msg)
    }

    #[test]
    fn test_parse_get_response_accepted_with_sysdescr() {
        let data = build_get_response("public", b"Linux router 5.4.0 x86_64");
        let resp = parse_snmp_response(&data).unwrap();
        assert!(resp.is_get_response);
        assert_eq!(resp.sys_descr.as_deref(), Some("Linux router 5.4.0 x86_64"));
    }

    #[test]
    fn test_parse_get_response_trims_and_empties_to_none() {
        let data = build_get_response("public", b"   ");
        let resp = parse_snmp_response(&data).unwrap();
        assert!(resp.is_get_response);
        assert!(resp.sys_descr.is_none());
    }

    #[test]
    fn test_parse_non_getresponse_pdu() {
        // Same message but with a GetRequest PDU tag (0xA0), not a response.
        let data = build_get_request("public", 1);
        let resp = parse_snmp_response(&data).unwrap();
        assert!(!resp.is_get_response);
    }

    #[test]
    fn test_parse_wrong_outer_tag() {
        // Leading byte not a SEQUENCE.
        assert!(parse_snmp_response(&[0x02, 0x01, 0x00]).is_none());
    }

    #[test]
    fn test_parse_missing_community() {
        // SEQUENCE { INTEGER version } then truncated — no community.
        let msg = ber_tlv(0x30, &ber_tlv(0x02, &[0x01]));
        assert!(parse_snmp_response(&msg).is_none());
    }

    #[test]
    fn test_parse_empty_input() {
        assert!(parse_snmp_response(&[]).is_none());
    }

    // ── sysDescr extraction edge cases ──────────────────────────────────────

    #[test]
    fn test_extract_sys_descr_non_octet_value() {
        // Build a response whose varbind value is an INTEGER, not an OCTET STRING.
        let mut varbind = ber_tlv(0x06, OID_SYSDESCR_0);
        varbind.extend_from_slice(&ber_tlv(0x02, &[0x2a])); // INTEGER value
        let varbind = ber_tlv(0x30, &varbind);
        let varbind_list = ber_tlv(0x30, &varbind);
        let mut pdu = ber_tlv(0x02, &[0x01]);
        pdu.extend_from_slice(&ber_tlv(0x02, &[0x00]));
        pdu.extend_from_slice(&ber_tlv(0x02, &[0x00]));
        pdu.extend_from_slice(&varbind_list);
        assert!(extract_sys_descr(&pdu).is_none());
    }

    // ── vendor guessing ─────────────────────────────────────────────────────

    #[test]
    fn test_guess_vendor_known() {
        assert_eq!(guess_vendor("Cisco IOS Software, C2960"), Some("Cisco"));
        assert_eq!(guess_vendor("RouterOS RB750Gr3"), Some("MikroTik"));
        assert_eq!(guess_vendor("Linux nas 6.1.0 x86_64"), Some("Linux"));
        assert_eq!(guess_vendor("Brother HL-L2350DW series"), Some("Brother"));
    }

    #[test]
    fn test_guess_vendor_unknown() {
        assert_eq!(guess_vendor("some unlabeled device"), None);
        assert_eq!(guess_vendor(""), None);
    }

    // ── finding construction ────────────────────────────────────────────────

    #[test]
    fn test_finding_public_is_medium_confirmed() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let hit = SnmpHit {
            community: "public",
            response: SnmpResponse {
                is_get_response: true,
                sys_descr: Some("Linux gw 5.15".to_owned()),
            },
        };
        let f = finding_for_hit(ip, &hit);
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.confidence, rikitikitavi_core::Confidence::Confirmed);
        assert_eq!(f.affected_port, Some(161));
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-306"));
        assert!(f.cve_ids.is_empty(), "no CVE should be fabricated");
        assert!(f.device_hint.is_some());
        assert!(f.evidence.as_deref().unwrap().contains("0xA2"));
    }

    #[test]
    fn test_finding_private_is_high() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let hit = SnmpHit {
            community: "private",
            response: SnmpResponse {
                is_get_response: true,
                sys_descr: None,
            },
        };
        let f = finding_for_hit(ip, &hit);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, rikitikitavi_core::Confidence::Confirmed);
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-284"));
        assert!(f.device_hint.is_none());
    }

    // ── Proptests ───────────────────────────────────────────────────────────

    proptest! {
        /// Parser never panics on arbitrary bytes.
        #[test]
        fn prop_parse_snmp_no_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_snmp_response(&data);
        }

        /// read_ber_tlv never panics and never reports a range past the buffer.
        #[test]
        fn prop_read_ber_tlv_in_bounds(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            if let Some((_, off, len)) = read_ber_tlv(&data) {
                prop_assert!(off + len <= data.len());
            }
        }

        /// The builder always produces a parseable message whose PDU is a
        /// `GetRequest` (not a response) for any community and request-id.
        #[test]
        fn prop_build_get_request_roundtrips(
            community in "[ -~]{0,40}",
            request_id in any::<u32>(),
        ) {
            let packet = build_get_request(&community, request_id);
            prop_assert_eq!(packet[0], 0x30);
            let resp = parse_snmp_response(&packet).unwrap();
            prop_assert!(!resp.is_get_response);
        }

        /// A crafted `GetResponse` always classifies as accepted; a non-empty
        /// sysDescr round-trips (trimmed), an all-whitespace one becomes `None`.
        #[test]
        fn prop_get_response_accepted(descr in "[ -~]{1,60}") {
            let data = build_get_response("public", descr.as_bytes());
            let resp = parse_snmp_response(&data).unwrap();
            prop_assert!(resp.is_get_response);
            let trimmed = descr.trim();
            if trimmed.is_empty() {
                prop_assert!(resp.sys_descr.is_none());
            } else {
                prop_assert_eq!(resp.sys_descr.as_deref(), Some(trimmed));
            }
        }
    }
}
