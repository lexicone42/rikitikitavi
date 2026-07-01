//! Pure-Rust 802.11 management frame parsing.
//!
//! Parses raw captured packets (radiotap header + 802.11 frame) into structured
//! types for analysis. No platform-specific code — just bytes in, data out.

use std::fmt;

// ── Types ───────────────────────────────────────────────────────────────

/// Six-byte MAC address.
pub type MacAddress = [u8; 6];

/// Parsed radiotap header metadata.
#[derive(Debug, Clone)]
pub struct RadiotapHeader {
    /// Total radiotap header length in bytes.
    pub length: usize,
    /// Signal strength in dBm (if present in radiotap fields).
    pub signal_dbm: Option<i8>,
    /// Channel frequency in MHz (if present).
    pub channel_freq: Option<u16>,
}

/// A parsed 802.11 management frame.
#[derive(Debug, Clone)]
pub enum FrameType {
    Beacon(BeaconFrame),
    ProbeRequest(ProbeRequestFrame),
    ProbeResponse(ProbeResponseFrame),
    Deauth(DeauthFrame),
    Disassoc(DisassocFrame),
    Other,
}

/// Beacon frame — broadcast by access points to announce their presence.
#[derive(Debug, Clone)]
pub struct BeaconFrame {
    pub bssid: MacAddress,
    pub ssid: Option<String>,
    pub channel: Option<u8>,
    pub encryption: EncryptionType,
    pub signal_dbm: Option<i8>,
}

/// Probe request — sent by devices searching for networks.
#[derive(Debug, Clone)]
pub struct ProbeRequestFrame {
    pub source_mac: MacAddress,
    /// `None` means broadcast probe (any network).
    pub ssid: Option<String>,
    pub signal_dbm: Option<i8>,
}

/// Probe response — AP reply to a probe request.
#[derive(Debug, Clone)]
pub struct ProbeResponseFrame {
    pub bssid: MacAddress,
    pub ssid: Option<String>,
    pub channel: Option<u8>,
    pub encryption: EncryptionType,
    pub signal_dbm: Option<i8>,
}

/// Deauthentication frame.
#[derive(Debug, Clone)]
pub struct DeauthFrame {
    pub source: MacAddress,
    pub destination: MacAddress,
    pub bssid: MacAddress,
    pub reason_code: u16,
}

/// Disassociation frame.
#[derive(Debug, Clone)]
pub struct DisassocFrame {
    pub source: MacAddress,
    pub destination: MacAddress,
    pub bssid: MacAddress,
    pub reason_code: u16,
}

/// Detected encryption type from beacon/probe-response tagged parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionType {
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
    Unknown,
}

impl fmt::Display for EncryptionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "Open"),
            Self::Wep => write!(f, "WEP"),
            Self::Wpa => write!(f, "WPA"),
            Self::Wpa2 => write!(f, "WPA2"),
            Self::Wpa3 => write!(f, "WPA3"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ── Radiotap present-field bit positions ────────────────────────────────

const RADIOTAP_FLAGS: u32 = 1 << 1;
const RADIOTAP_RATE: u32 = 1 << 2;
const RADIOTAP_CHANNEL: u32 = 1 << 3;
const RADIOTAP_FHSS: u32 = 1 << 4;
const RADIOTAP_DBM_SIGNAL: u32 = 1 << 5;
const RADIOTAP_DBM_NOISE: u32 = 1 << 6;

// ── 802.11 frame control subtypes (first byte of frame control) ─────────

/// Beacon (management, subtype 8): type=0b00, subtype=0b1000 → byte = 0x80.
const FC_BEACON: u8 = 0x80;
/// Probe request (management, subtype 4): 0x40.
const FC_PROBE_REQUEST: u8 = 0x40;
/// Probe response (management, subtype 5): 0x50.
const FC_PROBE_RESPONSE: u8 = 0x50;
/// Deauthentication (management, subtype 12): 0xC0.
const FC_DEAUTH: u8 = 0xC0;
/// Disassociation (management, subtype 10): 0xA0.
const FC_DISASSOC: u8 = 0xA0;

// ── Tagged parameter IDs ────────────────────────────────────────────────

const TAG_SSID: u8 = 0;
const TAG_DS_PARAMETER: u8 = 3;
const TAG_RSN: u8 = 48;
const TAG_VENDOR: u8 = 221;

/// Microsoft WPA OUI prefix in vendor-specific IE.
const WPA_OUI: [u8; 4] = [0x00, 0x50, 0xF2, 0x01];

/// IEEE 802.11i RSN AKM suite OUI for SAE (`WPA3`).
const RSN_AKM_SAE: [u8; 4] = [0x00, 0x0F, 0xAC, 0x08];

// ── Public API ──────────────────────────────────────────────────────────

/// Parse a radiotap header from the front of a captured packet.
///
/// Returns `None` if the data is too short or the header is malformed.
pub fn parse_radiotap(data: &[u8]) -> Option<RadiotapHeader> {
    // Minimum radiotap header: version(1) + pad(1) + length(2) + present(4) = 8 bytes
    if data.len() < 8 {
        return None;
    }

    let version = data[0];
    if version != 0 {
        return None;
    }

    let length = u16::from_le_bytes([data[2], data[3]]) as usize;
    if length < 8 || length > data.len() {
        return None;
    }

    let present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    // Walk through present fields to extract signal and channel.
    // Radiotap fields appear in order of their bit position.
    let mut offset = 8;
    let mut signal_dbm = None;
    let mut channel_freq = None;

    // Skip extended present bitmasks (bit 31 set = another u32 follows)
    let mut cur_present = present;
    while cur_present & (1 << 31) != 0 {
        offset += 4;
        if offset + 4 > length {
            return Some(RadiotapHeader {
                length,
                signal_dbm: None,
                channel_freq: None,
            });
        }
        cur_present = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
        // We only parse the first bitmask's fields
    }
    // Reset offset to after all present bitmasks
    // (we already advanced past them)

    // Bit 0: TSFT (u64, 8-byte aligned)
    if present & 1 != 0 {
        offset = align_to(offset, 8);
        offset += 8;
    }

    // Bit 1: Flags (u8)
    if present & RADIOTAP_FLAGS != 0 {
        offset += 1;
    }

    // Bit 2: Rate (u8)
    if present & RADIOTAP_RATE != 0 {
        offset += 1;
    }

    // Bit 3: Channel (u16 freq + u16 flags, 2-byte aligned)
    if present & RADIOTAP_CHANNEL != 0 {
        offset = align_to(offset, 2);
        if offset + 4 <= length {
            channel_freq = Some(u16::from_le_bytes([data[offset], data[offset + 1]]));
        }
        offset += 4;
    }

    // Bit 4: FHSS (u8 + u8)
    if present & RADIOTAP_FHSS != 0 {
        offset += 2;
    }

    // Bit 5: Antenna signal dBm (i8)
    if present & RADIOTAP_DBM_SIGNAL != 0 {
        if offset < length {
            #[allow(clippy::cast_possible_wrap)]
            {
                signal_dbm = Some(data[offset] as i8);
            }
        }
        offset += 1;
    }

    // Bit 6: Antenna noise dBm — we skip it but need to account for the byte
    if present & RADIOTAP_DBM_NOISE != 0 {
        let _ = offset; // suppress unused warning in the last branch
    }

    Some(RadiotapHeader {
        length,
        signal_dbm,
        channel_freq,
    })
}

/// Parse an 802.11 frame from raw captured data (including radiotap header).
///
/// Returns `None` if the packet is too short or unparseable.
pub fn parse_frame(data: &[u8]) -> Option<FrameType> {
    let header = parse_radiotap(data)?;
    let frame_data = data.get(header.length..)?;

    // Need at least frame control (2) + duration (2) = 4 bytes
    if frame_data.len() < 4 {
        return None;
    }

    let fc0 = frame_data[0];
    // Mask out protocol version bits (bits 0-1) and check only type+subtype
    let subtype_byte = fc0 & 0xFC;

    match subtype_byte {
        FC_BEACON => parse_beacon(frame_data, header.signal_dbm),
        FC_PROBE_REQUEST => parse_probe_request(frame_data, header.signal_dbm),
        FC_PROBE_RESPONSE => parse_probe_response(frame_data, header.signal_dbm),
        FC_DEAUTH => parse_deauth(frame_data),
        FC_DISASSOC => parse_disassoc(frame_data),
        _ => Some(FrameType::Other),
    }
}

/// Format a MAC address as "aa:bb:cc:dd:ee:ff".
pub fn format_mac(mac: &MacAddress) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse a MAC address from a "aa:bb:cc:dd:ee:ff" string.
pub fn parse_mac(s: &str) -> Option<MacAddress> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

/// Check if a MAC address is a broadcast/multicast address.
pub const fn is_broadcast(mac: &MacAddress) -> bool {
    mac[0] == 0xFF
        && mac[1] == 0xFF
        && mac[2] == 0xFF
        && mac[3] == 0xFF
        && mac[4] == 0xFF
        && mac[5] == 0xFF
}

/// Check if a MAC address uses a locally-administered (randomized) bit.
/// Bit 1 of the first octet is the U/L bit: 1 = locally administered.
pub const fn is_locally_administered(mac: &MacAddress) -> bool {
    mac[0] & 0x02 != 0
}

// ── Internal parsing ────────────────────────────────────────────────────

/// Extract 6-byte MAC address starting at `offset`.
fn read_mac(data: &[u8], offset: usize) -> Option<MacAddress> {
    if offset + 6 > data.len() {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&data[offset..offset + 6]);
    Some(mac)
}

/// Align `offset` up to the next multiple of `alignment`.
const fn align_to(offset: usize, alignment: usize) -> usize {
    let rem = offset % alignment;
    if rem == 0 {
        offset
    } else {
        offset + (alignment - rem)
    }
}

/// Parse a beacon frame body.
/// Layout: FC(2) + Dur(2) + DA(6) + SA(6) + BSSID(6) + SeqCtl(2) = 24 bytes header
/// Then: Timestamp(8) + Interval(2) + Capability(2) + Tagged Parameters
fn parse_beacon(frame: &[u8], signal_dbm: Option<i8>) -> Option<FrameType> {
    if frame.len() < 36 {
        return None;
    }

    let bssid = read_mac(frame, 16)?;

    // Fixed fields start at offset 24: timestamp(8) + interval(2) + capability(2) = 12
    let capability = u16::from_le_bytes([frame[34], frame[35]]);
    let tagged_start = 36;
    let (ssid, channel, encryption) = parse_tagged_parameters(&frame[tagged_start..], capability);

    Some(FrameType::Beacon(BeaconFrame {
        bssid,
        ssid,
        channel,
        encryption,
        signal_dbm,
    }))
}

/// Parse a probe request frame.
/// Layout: FC(2) + Dur(2) + DA(6) + SA(6) + BSSID(6) + SeqCtl(2) = 24 bytes
/// Then: Tagged Parameters (no fixed fields for probe request)
fn parse_probe_request(frame: &[u8], signal_dbm: Option<i8>) -> Option<FrameType> {
    if frame.len() < 24 {
        return None;
    }

    let source_mac = read_mac(frame, 10)?; // SA at offset 10

    let (ssid, _, _) = parse_tagged_parameters(&frame[24..], 0);

    Some(FrameType::ProbeRequest(ProbeRequestFrame {
        source_mac,
        ssid,
        signal_dbm,
    }))
}

/// Parse a probe response frame (same layout as beacon).
fn parse_probe_response(frame: &[u8], signal_dbm: Option<i8>) -> Option<FrameType> {
    if frame.len() < 36 {
        return None;
    }

    let bssid = read_mac(frame, 16)?;
    let capability = u16::from_le_bytes([frame[34], frame[35]]);
    let (ssid, channel, encryption) = parse_tagged_parameters(&frame[36..], capability);

    Some(FrameType::ProbeResponse(ProbeResponseFrame {
        bssid,
        ssid,
        channel,
        encryption,
        signal_dbm,
    }))
}

/// Parse a deauthentication frame.
/// Layout: FC(2) + Dur(2) + DA(6) + SA(6) + BSSID(6) + SeqCtl(2) = 24 bytes
/// Then: Reason code (2 bytes)
fn parse_deauth(frame: &[u8]) -> Option<FrameType> {
    if frame.len() < 26 {
        return None;
    }

    let destination = read_mac(frame, 4)?;
    let source = read_mac(frame, 10)?;
    let bssid = read_mac(frame, 16)?;
    let reason_code = u16::from_le_bytes([frame[24], frame[25]]);

    Some(FrameType::Deauth(DeauthFrame {
        source,
        destination,
        bssid,
        reason_code,
    }))
}

/// Parse a disassociation frame (same layout as deauth).
fn parse_disassoc(frame: &[u8]) -> Option<FrameType> {
    if frame.len() < 26 {
        return None;
    }

    let destination = read_mac(frame, 4)?;
    let source = read_mac(frame, 10)?;
    let bssid = read_mac(frame, 16)?;
    let reason_code = u16::from_le_bytes([frame[24], frame[25]]);

    Some(FrameType::Disassoc(DisassocFrame {
        source,
        destination,
        bssid,
        reason_code,
    }))
}

/// Parse 802.11 tagged parameters to extract SSID, channel, and encryption type.
///
/// `capability` is the 2-byte capability info from beacons/probe responses.
/// Bit 4 (0x0010) = Privacy — indicates WEP if no RSN/WPA IE is present.
fn parse_tagged_parameters(
    data: &[u8],
    capability: u16,
) -> (Option<String>, Option<u8>, EncryptionType) {
    let mut ssid = None;
    let mut channel = None;
    let mut has_rsn = false;
    let mut has_wpa = false;
    let mut has_sae = false;

    let mut offset = 0;
    while offset + 2 <= data.len() {
        let tag_id = data[offset];
        let tag_len = data[offset + 1] as usize;
        offset += 2;

        if offset + tag_len > data.len() {
            break;
        }

        let tag_data = &data[offset..offset + tag_len];

        match tag_id {
            TAG_SSID => {
                if tag_len > 0 {
                    // SSID may contain non-UTF8 bytes
                    let s = String::from_utf8_lossy(tag_data).to_string();
                    if !s.is_empty() && !s.chars().all(|c| c == '\0') {
                        ssid = Some(s);
                    }
                }
                // tag_len == 0 means broadcast/wildcard SSID
            }
            TAG_DS_PARAMETER => {
                if tag_len == 1 {
                    channel = Some(tag_data[0]);
                }
            }
            TAG_RSN => {
                has_rsn = true;
                // Check AKM suites for SAE (WPA3)
                if tag_len >= 8 {
                    has_sae = check_rsn_for_sae(tag_data);
                }
            }
            TAG_VENDOR if tag_len >= 4 && tag_data[..4] == WPA_OUI => {
                has_wpa = true;
            }
            _ => {}
        }

        offset += tag_len;
    }

    let privacy = capability & 0x0010 != 0;

    let encryption = if has_sae {
        EncryptionType::Wpa3
    } else if has_rsn {
        EncryptionType::Wpa2
    } else if has_wpa {
        EncryptionType::Wpa
    } else if privacy {
        EncryptionType::Wep
    } else {
        EncryptionType::Open
    };

    (ssid, channel, encryption)
}

/// Check an RSN information element for SAE AKM suite (`WPA3`).
fn check_rsn_for_sae(rsn_data: &[u8]) -> bool {
    // RSN IE layout:
    // Version(2) + Group cipher(4) + Pairwise count(2) + Pairwise suites(4*n) + AKM count(2) + AKM suites(4*n)
    if rsn_data.len() < 2 {
        return false;
    }

    let mut offset = 2; // skip version

    // Group cipher suite
    if offset + 4 > rsn_data.len() {
        return false;
    }
    offset += 4;

    // Pairwise cipher suite count + suites
    if offset + 2 > rsn_data.len() {
        return false;
    }
    let pairwise_count = u16::from_le_bytes([rsn_data[offset], rsn_data[offset + 1]]) as usize;
    offset += 2 + pairwise_count * 4;

    // AKM suite count + suites
    if offset + 2 > rsn_data.len() {
        return false;
    }
    let akm_count = u16::from_le_bytes([rsn_data[offset], rsn_data[offset + 1]]) as usize;
    offset += 2;

    for _ in 0..akm_count {
        if offset + 4 > rsn_data.len() {
            return false;
        }
        if rsn_data[offset..offset + 4] == RSN_AKM_SAE {
            return true;
        }
        offset += 4;
    }

    false
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal radiotap header with specific present flags.
    fn build_radiotap(present: u32, fields: &[u8]) -> Vec<u8> {
        #[allow(clippy::cast_possible_truncation)] // test helper, lengths are always small
        let length = (8 + fields.len()) as u16;
        let mut data = vec![
            0x00,                         // version
            0x00,                         // pad
            (length & 0xFF) as u8,        // length lo
            ((length >> 8) & 0xFF) as u8, // length hi
        ];
        data.extend_from_slice(&present.to_le_bytes());
        data.extend_from_slice(fields);
        data
    }

    /// Build a minimal 802.11 management frame header (24 bytes).
    fn build_mgmt_header(fc0: u8, dest: MacAddress, src: MacAddress, bssid: MacAddress) -> Vec<u8> {
        let mut frame = vec![fc0, 0x00]; // frame control
        frame.extend_from_slice(&[0x00, 0x00]); // duration
        frame.extend_from_slice(&dest);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&[0x00, 0x00]); // sequence control
        frame
    }

    /// Build a tagged parameter.
    fn build_tag(id: u8, data: &[u8]) -> Vec<u8> {
        #[allow(clippy::cast_possible_truncation)] // test helper, tag data always < 256
        let mut tag = vec![id, data.len() as u8];
        tag.extend_from_slice(data);
        tag
    }

    /// Build beacon fixed fields: timestamp(8) + interval(2) + capability(2).
    fn build_beacon_fixed(capability: u16) -> Vec<u8> {
        let mut fixed = vec![0u8; 10]; // timestamp(8) + interval(2)
        fixed.extend_from_slice(&capability.to_le_bytes());
        fixed
    }

    #[test]
    fn test_parse_radiotap_minimal() {
        let data = build_radiotap(0, &[]);
        let header = parse_radiotap(&data).unwrap();
        assert_eq!(header.length, 8);
        assert!(header.signal_dbm.is_none());
        assert!(header.channel_freq.is_none());
    }

    #[test]
    fn test_parse_radiotap_with_signal() {
        // Present: TSFT(0) + Flags(1) + Rate(2) + Channel(3) + DBM_SIGNAL(5)
        let present = 1 | RADIOTAP_FLAGS | RADIOTAP_RATE | RADIOTAP_CHANNEL | RADIOTAP_DBM_SIGNAL;
        let mut fields = vec![];
        // TSFT: 8 bytes (needs 8-byte alignment from offset 8, which is already aligned)
        fields.extend_from_slice(&[0u8; 8]);
        // Flags: 1 byte
        fields.push(0x00);
        // Rate: 1 byte
        fields.push(0x0C);
        // Channel: u16 freq + u16 flags (2-byte aligned — after flags+rate=2 bytes, offset is 8+8+2=18, already aligned)
        fields.extend_from_slice(&2437u16.to_le_bytes()); // 2437 MHz = channel 6
        fields.extend_from_slice(&[0x00, 0x00]); // channel flags
        // Signal: i8
        fields.push((-50_i8).to_ne_bytes()[0]);

        let data = build_radiotap(present, &fields);
        let header = parse_radiotap(&data).unwrap();
        assert_eq!(header.signal_dbm, Some(-50));
        assert_eq!(header.channel_freq, Some(2437));
    }

    #[test]
    fn test_parse_radiotap_too_short() {
        assert!(parse_radiotap(&[0x00, 0x00, 0x04]).is_none());
    }

    #[test]
    fn test_parse_radiotap_bad_version() {
        let mut data = build_radiotap(0, &[]);
        data[0] = 1; // bad version
        assert!(parse_radiotap(&data).is_none());
    }

    #[test]
    fn test_parse_beacon_frame() {
        let radiotap = build_radiotap(RADIOTAP_DBM_SIGNAL, &[(-60_i8).to_ne_bytes()[0]]);

        let bssid: MacAddress = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let dest: MacAddress = [0xFF; 6]; // broadcast
        let src = bssid;
        let mut frame = build_mgmt_header(FC_BEACON, dest, src, bssid);
        frame.extend_from_slice(&build_beacon_fixed(0x0010)); // privacy bit set
        frame.extend_from_slice(&build_tag(TAG_SSID, b"TestNetwork"));
        frame.extend_from_slice(&build_tag(TAG_DS_PARAMETER, &[6]));
        // Add RSN IE (WPA2): version(2) + group cipher(4) + pairwise count(2) + pairwise(4) + AKM count(2) + AKM(4)
        let rsn_ie = {
            let mut ie = vec![];
            ie.extend_from_slice(&1u16.to_le_bytes()); // version 1
            ie.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // group: CCMP
            ie.extend_from_slice(&1u16.to_le_bytes()); // 1 pairwise suite
            ie.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // pairwise: CCMP
            ie.extend_from_slice(&1u16.to_le_bytes()); // 1 AKM suite
            ie.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x02]); // AKM: PSK
            ie
        };
        frame.extend_from_slice(&build_tag(TAG_RSN, &rsn_ie));

        let mut packet = radiotap;
        packet.extend_from_slice(&frame);

        let result = parse_frame(&packet).unwrap();
        match result {
            FrameType::Beacon(b) => {
                assert_eq!(b.bssid, bssid);
                assert_eq!(b.ssid.as_deref(), Some("TestNetwork"));
                assert_eq!(b.channel, Some(6));
                assert_eq!(b.encryption, EncryptionType::Wpa2);
                assert_eq!(b.signal_dbm, Some(-60));
            }
            other => panic!("expected Beacon, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_beacon_wpa3() {
        let radiotap = build_radiotap(0, &[]);

        let bssid: MacAddress = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mut frame = build_mgmt_header(FC_BEACON, [0xFF; 6], bssid, bssid);
        frame.extend_from_slice(&build_beacon_fixed(0x0010));
        frame.extend_from_slice(&build_tag(TAG_SSID, b"WPA3Net"));

        // RSN IE with SAE AKM
        let rsn_ie = {
            let mut ie = vec![];
            ie.extend_from_slice(&1u16.to_le_bytes());
            ie.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // group: CCMP
            ie.extend_from_slice(&1u16.to_le_bytes());
            ie.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // pairwise: CCMP
            ie.extend_from_slice(&1u16.to_le_bytes());
            ie.extend_from_slice(&RSN_AKM_SAE); // AKM: SAE (WPA3)
            ie
        };
        frame.extend_from_slice(&build_tag(TAG_RSN, &rsn_ie));

        let mut packet = radiotap;
        packet.extend_from_slice(&frame);

        match parse_frame(&packet).unwrap() {
            FrameType::Beacon(b) => {
                assert_eq!(b.encryption, EncryptionType::Wpa3);
                assert_eq!(b.ssid.as_deref(), Some("WPA3Net"));
            }
            other => panic!("expected Beacon, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_beacon_open() {
        let radiotap = build_radiotap(0, &[]);
        let bssid: MacAddress = [0xAA; 6];
        let mut frame = build_mgmt_header(FC_BEACON, [0xFF; 6], bssid, bssid);
        frame.extend_from_slice(&build_beacon_fixed(0x0000)); // no privacy bit
        frame.extend_from_slice(&build_tag(TAG_SSID, b"OpenNet"));

        let mut packet = radiotap;
        packet.extend_from_slice(&frame);

        match parse_frame(&packet).unwrap() {
            FrameType::Beacon(b) => {
                assert_eq!(b.encryption, EncryptionType::Open);
                assert_eq!(b.ssid.as_deref(), Some("OpenNet"));
            }
            other => panic!("expected Beacon, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_beacon_wep() {
        let radiotap = build_radiotap(0, &[]);
        let bssid: MacAddress = [0xBB; 6];
        let mut frame = build_mgmt_header(FC_BEACON, [0xFF; 6], bssid, bssid);
        frame.extend_from_slice(&build_beacon_fixed(0x0010)); // privacy but no RSN/WPA
        frame.extend_from_slice(&build_tag(TAG_SSID, b"WepNet"));

        let mut packet = radiotap;
        packet.extend_from_slice(&frame);

        match parse_frame(&packet).unwrap() {
            FrameType::Beacon(b) => {
                assert_eq!(b.encryption, EncryptionType::Wep);
            }
            other => panic!("expected Beacon, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_beacon_wpa1() {
        let radiotap = build_radiotap(0, &[]);
        let bssid: MacAddress = [0xCC; 6];
        let mut frame = build_mgmt_header(FC_BEACON, [0xFF; 6], bssid, bssid);
        frame.extend_from_slice(&build_beacon_fixed(0x0010));
        frame.extend_from_slice(&build_tag(TAG_SSID, b"WpaNet"));

        // Vendor-specific WPA IE
        let mut wpa_ie = WPA_OUI.to_vec();
        wpa_ie.extend_from_slice(&[0x01, 0x00]); // version
        frame.extend_from_slice(&build_tag(TAG_VENDOR, &wpa_ie));

        let mut packet = radiotap;
        packet.extend_from_slice(&frame);

        match parse_frame(&packet).unwrap() {
            FrameType::Beacon(b) => {
                assert_eq!(b.encryption, EncryptionType::Wpa);
            }
            other => panic!("expected Beacon, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_probe_request_directed() {
        let radiotap = build_radiotap(RADIOTAP_DBM_SIGNAL, &[(-70_i8).to_ne_bytes()[0]]);
        let src: MacAddress = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let dest: MacAddress = [0xFF; 6];
        let bssid: MacAddress = [0xFF; 6];
        let mut frame = build_mgmt_header(FC_PROBE_REQUEST, dest, src, bssid);
        frame.extend_from_slice(&build_tag(TAG_SSID, b"MyHomeWifi"));

        let mut packet = radiotap;
        packet.extend_from_slice(&frame);

        match parse_frame(&packet).unwrap() {
            FrameType::ProbeRequest(pr) => {
                assert_eq!(pr.source_mac, src);
                assert_eq!(pr.ssid.as_deref(), Some("MyHomeWifi"));
                assert_eq!(pr.signal_dbm, Some(-70));
            }
            other => panic!("expected ProbeRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_probe_request_broadcast() {
        let radiotap = build_radiotap(0, &[]);
        let src: MacAddress = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        let mut frame = build_mgmt_header(FC_PROBE_REQUEST, [0xFF; 6], src, [0xFF; 6]);
        frame.extend_from_slice(&build_tag(TAG_SSID, &[])); // empty SSID = broadcast

        let mut packet = radiotap;
        packet.extend_from_slice(&frame);

        match parse_frame(&packet).unwrap() {
            FrameType::ProbeRequest(pr) => {
                assert!(pr.ssid.is_none());
            }
            other => panic!("expected ProbeRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_deauth_frame() {
        let radiotap = build_radiotap(0, &[]);
        let src: MacAddress = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let dest: MacAddress = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let bssid = src;
        let mut frame = build_mgmt_header(FC_DEAUTH, dest, src, bssid);
        frame.extend_from_slice(&7u16.to_le_bytes()); // reason code 7: Class 3 frame from non-associated station

        let mut packet = radiotap;
        packet.extend_from_slice(&frame);

        match parse_frame(&packet).unwrap() {
            FrameType::Deauth(d) => {
                assert_eq!(d.source, src);
                assert_eq!(d.destination, dest);
                assert_eq!(d.bssid, bssid);
                assert_eq!(d.reason_code, 7);
            }
            other => panic!("expected Deauth, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_disassoc_frame() {
        let radiotap = build_radiotap(0, &[]);
        let src: MacAddress = [0xAA; 6];
        let dest: MacAddress = [0xBB; 6];
        let bssid = src;
        let mut frame = build_mgmt_header(FC_DISASSOC, dest, src, bssid);
        frame.extend_from_slice(&3u16.to_le_bytes()); // reason code

        let mut packet = radiotap;
        packet.extend_from_slice(&frame);

        match parse_frame(&packet).unwrap() {
            FrameType::Disassoc(d) => {
                assert_eq!(d.source, src);
                assert_eq!(d.destination, dest);
                assert_eq!(d.reason_code, 3);
            }
            other => panic!("expected Disassoc, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_frame_truncated() {
        let radiotap = build_radiotap(0, &[]);
        // Only radiotap + 2 bytes (too short for a management frame)
        let mut packet = radiotap;
        packet.extend_from_slice(&[0x80, 0x00]);
        // Should still parse but beacon will fail due to insufficient length
        assert!(parse_frame(&packet).is_none());
    }

    #[test]
    fn test_parse_frame_other_subtype() {
        let radiotap = build_radiotap(0, &[]);
        // Authentication frame (subtype 11): 0xB0
        let mut frame = vec![0xB0, 0x00];
        frame.extend_from_slice(&[0u8; 22]); // fill rest of header
        let mut packet = radiotap;
        packet.extend_from_slice(&frame);

        assert!(matches!(parse_frame(&packet), Some(FrameType::Other)));
    }

    #[test]
    fn test_format_mac() {
        let mac: MacAddress = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac("aa:bb:cc").is_none());
        assert!(parse_mac("not:a:mac:address:at:all").is_none());
        assert!(parse_mac("").is_none());
    }

    #[test]
    fn test_is_broadcast() {
        assert!(is_broadcast(&[0xFF; 6]));
        assert!(!is_broadcast(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]));
    }

    #[test]
    fn test_is_locally_administered() {
        // Bit 1 of first octet set = locally administered (randomized MAC)
        assert!(is_locally_administered(&[
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00
        ]));
        assert!(is_locally_administered(&[
            0xFE, 0x00, 0x00, 0x00, 0x00, 0x00
        ]));
        // Bit 1 clear = globally unique (real MAC)
        assert!(!is_locally_administered(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]));
        assert!(!is_locally_administered(&[
            0xAC, 0x00, 0x00, 0x00, 0x00, 0x00
        ]));
    }

    #[test]
    fn test_tagged_params_hidden_ssid() {
        // Hidden SSID: tag present but all null bytes
        let data = build_tag(TAG_SSID, &[0x00, 0x00, 0x00]);
        let (ssid, _, _) = parse_tagged_parameters(&data, 0);
        assert!(ssid.is_none());
    }

    #[test]
    fn test_tagged_params_malformed() {
        // Tag claims length 100 but data is only 5 bytes
        let data = vec![TAG_SSID, 100, 0x41, 0x42, 0x43];
        let (ssid, _, _) = parse_tagged_parameters(&data, 0);
        // Should not panic, just stop parsing
        assert!(ssid.is_none());
    }

    #[test]
    fn test_probe_response_parsing() {
        let radiotap = build_radiotap(0, &[]);
        let bssid: MacAddress = [0x11; 6];
        let mut frame = build_mgmt_header(FC_PROBE_RESPONSE, [0xFF; 6], bssid, bssid);
        frame.extend_from_slice(&build_beacon_fixed(0x0010));
        let rsn_ie = {
            let mut ie = vec![];
            ie.extend_from_slice(&1u16.to_le_bytes());
            ie.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]);
            ie.extend_from_slice(&1u16.to_le_bytes());
            ie.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]);
            ie.extend_from_slice(&1u16.to_le_bytes());
            ie.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x02]);
            ie
        };
        frame.extend_from_slice(&build_tag(TAG_SSID, b"ProbeResp"));
        frame.extend_from_slice(&build_tag(TAG_DS_PARAMETER, &[11]));
        frame.extend_from_slice(&build_tag(TAG_RSN, &rsn_ie));

        let mut packet = radiotap;
        packet.extend_from_slice(&frame);

        match parse_frame(&packet).unwrap() {
            FrameType::ProbeResponse(pr) => {
                assert_eq!(pr.bssid, bssid);
                assert_eq!(pr.ssid.as_deref(), Some("ProbeResp"));
                assert_eq!(pr.channel, Some(11));
                assert_eq!(pr.encryption, EncryptionType::Wpa2);
            }
            other => panic!("expected ProbeResponse, got {other:?}"),
        }
    }

    #[test]
    fn test_encryption_display() {
        assert_eq!(format!("{}", EncryptionType::Open), "Open");
        assert_eq!(format!("{}", EncryptionType::Wep), "WEP");
        assert_eq!(format!("{}", EncryptionType::Wpa), "WPA");
        assert_eq!(format!("{}", EncryptionType::Wpa2), "WPA2");
        assert_eq!(format!("{}", EncryptionType::Wpa3), "WPA3");
        assert_eq!(format!("{}", EncryptionType::Unknown), "Unknown");
    }
}
