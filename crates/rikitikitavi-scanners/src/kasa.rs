//! TP-Link Kasa local control plane (TCP/9999).
//!
//! The Kasa LAN protocol is a 4-byte big-endian length prefix followed by an XOR
//! autokey stream with initial key 171. It carries no authentication: any host on
//! the LAN can read `get_sysinfo` and issue control commands. This probe sends one
//! request from a hard allowlist (`get_sysinfo` only) and never writes device state.
//!
//! Protocol description: <https://github.com/softScheck/tplink-smartplug>

use async_trait::async_trait;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, Remediation, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Scanner;

/// TP-Link Kasa local control scanner.
///
/// Probes hosts Phase 1 found with TCP/9999 open, decodes `system.get_sysinfo`,
/// and reports the device identity plus the absence of any authentication.
pub struct KasaScanner;

/// Kasa local control port.
const KASA_PORT: u16 = 9999;

/// Initial key of the XOR autokey stream.
const INITIAL_KEY: u8 = 171;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on a response body; devices with many schedule rules are large.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// The only command this scanner is permitted to send.
const GET_SYSINFO: &str = r#"{"system":{"get_sysinfo":{}}}"#;

/// Hard allowlist. The same socket accepts `reset`, `reboot` and `set_stainfo`,
/// so the read-only property is enforced here rather than by convention.
const ALLOWED_COMMANDS: &[&str] = &[GET_SYSINFO];

// ── XOR autokey cipher ──────────────────────────────────────────────────────

/// Encrypt with the XOR autokey stream: `key ^= plaintext_byte`, emit `key`.
fn encrypt(plain: &[u8]) -> Vec<u8> {
    let mut key = INITIAL_KEY;
    plain
        .iter()
        .map(|&byte| {
            key ^= byte;
            key
        })
        .collect()
}

/// Decrypt the XOR autokey stream: each ciphertext byte becomes the next key.
fn decrypt(cipher: &[u8]) -> Vec<u8> {
    let mut key = INITIAL_KEY;
    cipher
        .iter()
        .map(|&byte| {
            let plain = byte ^ key;
            key = byte;
            plain
        })
        .collect()
}

/// Frame a command as `u32` big-endian length + ciphertext.
///
/// Returns `None` for any command outside [`ALLOWED_COMMANDS`].
fn build_request(command: &str) -> Option<Vec<u8>> {
    if !ALLOWED_COMMANDS.contains(&command) {
        tracing::error!(command, "refusing to send a command outside the allowlist");
        return None;
    }
    let body = encrypt(command.as_bytes());
    let len = u32::try_from(body.len()).ok()?;
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Some(out)
}

// ── Minimal JSON reader ─────────────────────────────────────────────────────

/// JSON value. Numbers keep their source text, so no float round-trip happens
/// for values that are only ever compared or rendered.
#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Self>),
    Obj(Vec<(String, Self)>),
}

impl Json {
    /// Field of an object, or `None` for any other value / missing key.
    fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Obj(fields) => fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(text) => Some(text),
            _ => None,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Num(text) => text.parse().ok(),
            _ => None,
        }
    }
}

/// Maximum nesting accepted; bounds recursion on hostile input.
const MAX_DEPTH: u32 = 32;

struct JsonReader<'a> {
    bytes: &'a [u8],
    src: &'a str,
    pos: usize,
    depth: u32,
}

impl<'a> JsonReader<'a> {
    const fn new(src: &'a str) -> Self {
        Self {
            bytes: src.as_bytes(),
            src,
            pos: 0,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> Option<()> {
        (self.peek() == Some(byte)).then(|| self.pos += 1)
    }

    fn literal(&mut self, word: &str, value: Json) -> Option<Json> {
        if self.src[self.pos..].starts_with(word) {
            self.pos += word.len();
            return Some(value);
        }
        None
    }

    fn value(&mut self) -> Option<Json> {
        if self.depth >= MAX_DEPTH {
            return None;
        }
        self.skip_ws();
        match self.peek()? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => self.string().map(Json::Str),
            b't' => self.literal("true", Json::Bool(true)),
            b'f' => self.literal("false", Json::Bool(false)),
            b'n' => self.literal("null", Json::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn object(&mut self) -> Option<Json> {
        self.eat(b'{')?;
        self.depth += 1;
        let mut fields = Vec::new();
        self.skip_ws();
        if self.eat(b'}').is_some() {
            self.depth -= 1;
            return Some(Json::Obj(fields));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.eat(b':')?;
            let value = self.value()?;
            fields.push((key, value));
            self.skip_ws();
            if self.eat(b',').is_some() {
                continue;
            }
            self.eat(b'}')?;
            self.depth -= 1;
            return Some(Json::Obj(fields));
        }
    }

    fn array(&mut self) -> Option<Json> {
        self.eat(b'[')?;
        self.depth += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.eat(b']').is_some() {
            self.depth -= 1;
            return Some(Json::Arr(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            if self.eat(b',').is_some() {
                continue;
            }
            self.eat(b']')?;
            self.depth -= 1;
            return Some(Json::Arr(items));
        }
    }

    /// Parse a string literal. `"` and `\` are ASCII, so every slice taken here
    /// lands on a char boundary.
    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out = String::new();
        let mut chunk_start = self.pos;
        loop {
            match self.peek()? {
                b'"' => {
                    out.push_str(self.src.get(chunk_start..self.pos)?);
                    self.pos += 1;
                    return Some(out);
                }
                b'\\' => {
                    out.push_str(self.src.get(chunk_start..self.pos)?);
                    self.pos += 1;
                    self.escape(&mut out)?;
                    chunk_start = self.pos;
                }
                byte if byte < 0x20 => return None,
                _ => self.pos += 1,
            }
        }
    }

    /// Decode one escape sequence, already past the backslash.
    fn escape(&mut self, out: &mut String) -> Option<()> {
        let byte = self.peek()?;
        self.pos += 1;
        let simple = match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode_escape(out),
            _ => return None,
        };
        out.push(simple);
        Some(())
    }

    /// Decode `\uXXXX`, joining a surrogate pair when a low surrogate follows.
    fn unicode_escape(&mut self, out: &mut String) -> Option<()> {
        let high = self.hex4()?;
        // Not a surrogate: a lone code point.
        if !(0xD800..0xE000).contains(&high) {
            out.push(char::from_u32(high)?);
            return Some(());
        }
        // Low surrogate without a preceding high one is invalid.
        if high >= 0xDC00 {
            return None;
        }
        if self.eat(b'\\').is_none() || self.eat(b'u').is_none() {
            return None;
        }
        let low = self.hex4()?;
        if !(0xDC00..0xE000).contains(&low) {
            return None;
        }
        let combined = 0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00);
        out.push(char::from_u32(combined)?);
        Some(())
    }

    fn hex4(&mut self) -> Option<u32> {
        let digits = self.src.get(self.pos..self.pos + 4)?;
        let value = u32::from_str_radix(digits, 16).ok()?;
        self.pos += 4;
        Some(value)
    }

    fn number(&mut self) -> Option<Json> {
        let start = self.pos;
        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.pos += 1;
        }
        let text = self.src.get(start..self.pos)?;
        // Reject anything Rust would not read back as a finite number.
        if !text.parse::<f64>().is_ok_and(f64::is_finite) {
            return None;
        }
        Some(Json::Num(text.to_owned()))
    }
}

/// Parse a complete JSON document. Trailing content (other than whitespace)
/// makes the document invalid.
fn parse_json(text: &str) -> Option<Json> {
    let mut reader = JsonReader::new(text);
    let value = reader.value()?;
    reader.skip_ws();
    (reader.pos == reader.bytes.len()).then_some(value)
}

// ── get_sysinfo interpretation ──────────────────────────────────────────────

/// Fields of interest from `system.get_sysinfo`.
#[derive(Debug, Clone, Default, PartialEq)]
struct Sysinfo {
    model: Option<String>,
    sw_ver: Option<String>,
    hw_ver: Option<String>,
    device_id: Option<String>,
    alias: Option<String>,
    dev_name: Option<String>,
    mac: Option<String>,
    dev_type: Option<String>,
    /// Device switches mains power (plug or wall switch).
    switches_mains: bool,
    /// Configured latitude/longitude, when set to something other than 0,0.
    location: Option<(f64, f64)>,
}

impl Sysinfo {
    /// Best available label for the device.
    fn label(&self) -> String {
        self.model
            .clone()
            .or_else(|| self.dev_name.clone())
            .unwrap_or_else(|| "TP-Link Kasa device".to_owned())
    }
}

fn string_field(info: &Json, key: &str) -> Option<String> {
    let text = info.get(key)?.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Read the geolocation: degrees first, then the `_i` form scaled by 1e4.
/// `(0, 0)` means unset, not the Gulf of Guinea.
fn read_location(info: &Json) -> Option<(f64, f64)> {
    let degrees = info
        .get("latitude")
        .and_then(Json::as_f64)
        .zip(info.get("longitude").and_then(Json::as_f64));
    let scaled = info
        .get("latitude_i")
        .and_then(Json::as_f64)
        .zip(info.get("longitude_i").and_then(Json::as_f64))
        .map(|(lat, lon)| (lat / 10_000.0, lon / 10_000.0));

    let (lat, lon) = degrees.or(scaled)?;
    if lat == 0.0 && lon == 0.0 {
        return None;
    }
    (lat.abs() <= 90.0 && lon.abs() <= 180.0).then_some((lat, lon))
}

/// Interpret a decoded response. Returns `None` unless it is a well-formed
/// `system.get_sysinfo` reply with a zero (or absent) `err_code`.
fn parse_sysinfo(text: &str) -> Option<Sysinfo> {
    let info = parse_json(text)?.get("system")?.get("get_sysinfo")?.clone();
    if !matches!(&info, Json::Obj(fields) if !fields.is_empty()) {
        return None;
    }
    if info.get("err_code").and_then(Json::as_f64).unwrap_or(0.0) != 0.0 {
        return None;
    }

    // Bulbs use `mic_type`/`mic_mac` where plugs use `type`/`mac`.
    let dev_type = string_field(&info, "type").or_else(|| string_field(&info, "mic_type"));
    let switches_mains = info.get("relay_state").is_some()
        || dev_type
            .as_deref()
            .is_some_and(|t| t.contains("SMARTPLUGSWITCH"));

    Some(Sysinfo {
        model: string_field(&info, "model"),
        sw_ver: string_field(&info, "sw_ver"),
        hw_ver: string_field(&info, "hw_ver"),
        device_id: string_field(&info, "deviceId"),
        alias: string_field(&info, "alias"),
        dev_name: string_field(&info, "dev_name"),
        mac: string_field(&info, "mac").or_else(|| string_field(&info, "mic_mac")),
        dev_type,
        switches_mains,
        location: read_location(&info),
    })
}

// ── Probe ───────────────────────────────────────────────────────────────────

/// Send one `get_sysinfo` and return the decrypted response body.
///
/// The length header is honoured: a single fixed-size read truncates on devices
/// with many schedule rules.
async fn probe_sysinfo(ip: IpAddr, port: u16) -> Option<String> {
    let request = build_request(GET_SYSINFO)?;
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    tokio::time::timeout(IO_TIMEOUT, stream.write_all(&request))
        .await
        .ok()?
        .ok()?;

    let mut header = [0u8; 4];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut header))
        .await
        .ok()?
        .ok()?;

    let len = usize::try_from(u32::from_be_bytes(header)).ok()?;
    if len == 0 || len > MAX_RESPONSE_BYTES {
        tracing::debug!(%ip, port, len, "implausible Kasa response length");
        return None;
    }

    let mut body = vec![0u8; len];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut body))
        .await
        .ok()?
        .ok()?;

    String::from_utf8(decrypt(&body)).ok()
}

// ── Findings ────────────────────────────────────────────────────────────────

fn segmentation_remediation(switches_mains: bool) -> Remediation {
    let mut steps = vec![
        "Move Kasa devices onto an IoT VLAN / guest SSID that cannot reach \
         workstations, servers or management interfaces."
            .to_owned(),
        "Block inbound TCP/9999 from every host that is not the controller you \
         intend to allow (a firewall rule on the IoT VLAN, not on the device)."
            .to_owned(),
        "Never port-forward 9999; confirm the router's UPnP/NAT-PMP table has no \
         mapping for it."
            .to_owned(),
        "Treat the device alias and configured geolocation as published data — \
         they are readable by anything on the same L2 segment."
            .to_owned(),
    ];
    if switches_mains {
        steps.push(
            "For anything switching a load you care about (heater, pump, network \
             gear), prefer a device generation that authenticates, or place it \
             behind a physically separate network."
                .to_owned(),
        );
    }
    Remediation {
        description: "This hardware generation has no authentication to enable; a \
                      firmware update does not add one. Contain it with network \
                      segmentation."
            .to_owned(),
        steps,
        effort: Some("30 minutes (network change)".to_owned()),
    }
}

fn control_finding(ip: IpAddr, port: u16, info: &Sysinfo) -> Finding {
    let severity = if info.switches_mains {
        Severity::High
    } else {
        Severity::Medium
    };
    let label = info.label();
    let alias = info.alias.as_deref().unwrap_or("(no alias)");
    let firmware = info.sw_ver.as_deref().unwrap_or("unknown");
    let hardware = info.hw_ver.as_deref().unwrap_or("unknown");

    let mut hint = DeviceHint::new()
        .with_vendor("TP-Link")
        .with_device_type(DeviceType::IoT);
    if let Some(model) = &info.model {
        hint = hint.with_model(model.clone());
    }
    if let Some(alias) = &info.alias {
        hint = hint.with_hostname(alias.clone());
    }

    let finding = Finding::new(
        "kasa",
        &format!("TP-Link Kasa device accepts unauthenticated local control on {ip}:{port}"),
        &format!(
            "{label} at {ip}:{port} answered a `system.get_sysinfo` request sent with no \
             credentials. The Kasa LAN protocol wraps JSON in an XOR autokey stream with a \
             fixed initial key (171) — obfuscation, not encryption — and the device accepts \
             commands independent of state: the same socket also takes relay control, \
             reboot, factory reset and Wi-Fi reconfiguration. Any host on this L2 segment, \
             including a compromised IoT device or a guest, can read the device inventory \
             (alias \"{alias}\", firmware {firmware}, hardware {hardware}) and operate it. \
             Note that `get_sysinfo` does not return stored Wi-Fi credentials; the \
             companion read-only leak is the nearby-AP list via `netif.get_scaninfo`."
        ),
        severity,
    )
    .with_confidence(Confidence::Confirmed)
    .with_ip(ip)
    .with_port(port)
    .with_service("kasa")
    .with_cwe("CWE-306")
    .with_remediation(segmentation_remediation(info.switches_mains))
    .with_device_hint(hint)
    .with_evidence(format!(
        "get_sysinfo decoded: model={} sw_ver={} hw_ver={} type={} alias={}",
        info.model.as_deref().unwrap_or("?"),
        firmware,
        hardware,
        info.dev_type.as_deref().unwrap_or("?"),
        alias,
    ))
    .with_references(refs![
        "https://github.com/softScheck/tplink-smartplug",
        "https://cwe.mitre.org/data/definitions/306.html",
    ]);

    match &info.mac {
        Some(mac) => finding.with_mac(mac.as_str()),
        None => finding,
    }
}

fn geolocation_finding(ip: IpAddr, port: u16, lat: f64, lon: f64) -> Finding {
    Finding::new(
        "kasa",
        &format!("TP-Link Kasa device discloses its configured geolocation on {ip}:{port}"),
        &format!(
            "The unauthenticated `get_sysinfo` response from {ip}:{port} includes the \
             coordinates configured during setup, which for a mains-powered smart plug is \
             the installation address. Anything on the same network can read it without \
             credentials. The coordinates are cleared by removing the location in the Kasa \
             app; segmenting the device (see the related finding) is the durable fix."
        ),
        Severity::Low,
    )
    .with_confidence(Confidence::Confirmed)
    .with_ip(ip)
    .with_port(port)
    .with_service("kasa")
    .with_cwe("CWE-200")
    .with_evidence(format!("latitude={lat:.4} longitude={lon:.4}"))
    .with_references(refs!["https://github.com/softScheck/tplink-smartplug"])
}

// ── Scanner ─────────────────────────────────────────────────────────────────

#[async_trait]
impl Scanner for KasaScanner {
    fn id(&self) -> &'static str {
        "kasa"
    }

    fn name(&self) -> &'static str {
        "TP-Link Kasa Local Control"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running TP-Link Kasa scan");
        let mut findings = Vec::new();

        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping Kasa scan in quick scan mode");
            return Ok(findings);
        }

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "kasa".to_owned(),
                message: e.to_string(),
            })?;

        let targets: Vec<IpAddr> = ctx
            .discovered_devices
            .iter()
            .filter(|d| d.open_ports.iter().any(|p| p.port == KASA_PORT))
            .filter(|d| !exclusions.excludes_device(d))
            .map(|d| d.ip)
            .collect();

        if targets.is_empty() {
            tracing::info!("no Kasa targets found");
            return Ok(findings);
        }

        tracing::info!(target_count = targets.len(), "probing Kasa devices");

        for ip in targets {
            let Some(response) = probe_sysinfo(ip, KASA_PORT).await else {
                continue;
            };
            let Some(info) = parse_sysinfo(&response) else {
                // Port 9999 is not Kasa-exclusive; a non-decoding peer is not a finding.
                tracing::debug!(%ip, "response did not decode as system.get_sysinfo");
                continue;
            };
            if let Some((lat, lon)) = info.location {
                findings.push(geolocation_finding(ip, KASA_PORT, lat, lon));
            }
            findings.push(control_finding(ip, KASA_PORT, &info));
        }

        tracing::info!(findings_count = findings.len(), "Kasa scan complete");
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        10
    }

    fn relevant_ports(&self) -> &[u16] {
        &[KASA_PORT]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Published `get_sysinfo` ciphertext (softScheck tplink-smartplug), no length prefix.
    const GET_SYSINFO_CIPHERTEXT: &str =
        "d0f281f88bff9af7d5ef94b6d1b4c09fec95e68fe187e8caf08bf68bf6";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    /// HS110 smart plug with energy monitoring; degrees-form geolocation.
    const HS110_SYSINFO: &str = r#"{"system":{"get_sysinfo":{"err_code":0,
        "sw_ver":"1.2.5 Build 171213 Rel.101659","hw_ver":"1.0",
        "type":"IOT.SMARTPLUGSWITCH","model":"HS110(EU)","mac":"50:C7:BF:11:22:33",
        "deviceId":"8006AB1234567890ABCDEF1234567890ABCDEF12","hwId":"45E29DA8",
        "oemId":"3D341ECE","alias":"Living Room Lamp",
        "dev_name":"Wi-Fi Smart Plug With Energy Monitoring","icon_hash":"",
        "relay_state":1,"on_time":34712,"active_mode":"schedule","feature":"TIM:ENE",
        "updating":0,"rssi":-53,"led_off":0,"latitude":51.5074,"longitude":-0.1278}}}"#;

    /// KL130 bulb: `mic_type`/`mic_mac`, `_i`-scaled geolocation, no `relay_state`.
    const KL130_SYSINFO: &str = r#"{"system":{"get_sysinfo":{
        "sw_ver":"1.8.11 Build 191113 Rel.105336","hw_ver":"2.0","model":"KL130B(US)",
        "deviceId":"801E1234567890ABCDEF1234567890ABCDEF1234","oemId":"E45F4D1A",
        "mic_type":"IOT.SMARTBULB","mic_mac":"B0BE76445566","dev_state":"normal",
        "is_factory":false,"alias":"Bedroom","latitude_i":377749,"longitude_i":-1224194,
        "err_code":0,
        "light_state":{"on_off":1,"mode":"normal","hue":0,"saturation":0,
            "color_temp":2700,"brightness":75},
        "preferred_state":[{"index":0,"hue":0,"saturation":0,"color_temp":2700,
            "brightness":100}]}}}"#;

    // ── Cipher ──────────────────────────────────────────────────────

    #[test]
    fn encrypt_matches_published_get_sysinfo_vector() {
        assert_eq!(
            encrypt(GET_SYSINFO.as_bytes()),
            hex_to_bytes(GET_SYSINFO_CIPHERTEXT)
        );
    }

    #[test]
    fn decrypt_reverses_the_published_vector() {
        let plain = decrypt(&hex_to_bytes(GET_SYSINFO_CIPHERTEXT));
        assert_eq!(String::from_utf8(plain).unwrap(), GET_SYSINFO);
    }

    #[test]
    fn encrypt_first_byte_uses_initial_key() {
        // '{' == 0x7b, 0x7b ^ 171 == 0xd0.
        assert_eq!(encrypt(b"{")[0], 0xd0);
    }

    #[test]
    fn cipher_handles_empty_input() {
        assert!(encrypt(&[]).is_empty());
        assert!(decrypt(&[]).is_empty());
    }

    // ── Request framing / allowlist ─────────────────────────────────

    #[test]
    fn build_request_frames_length_then_ciphertext() {
        let request = build_request(GET_SYSINFO).unwrap();
        let expected_len = u32::try_from(GET_SYSINFO.len()).unwrap();
        assert_eq!(request[..4], expected_len.to_be_bytes());
        assert_eq!(&request[4..], hex_to_bytes(GET_SYSINFO_CIPHERTEXT));
    }

    #[test]
    fn build_request_refuses_commands_outside_the_allowlist() {
        for command in [
            r#"{"system":{"set_relay_state":{"state":1}}}"#,
            r#"{"system":{"reboot":{"delay":1}}}"#,
            r#"{"system":{"reset":{"delay":1}}}"#,
            r#"{"netif":{"set_stainfo":{"ssid":"x","password":"y","key_type":3}}}"#,
            r#"{"netif":{"get_scaninfo":{"refresh":0}}}"#,
            "",
        ] {
            assert!(
                build_request(command).is_none(),
                "must refuse to send {command}"
            );
        }
    }

    #[test]
    fn allowlist_holds_only_get_sysinfo() {
        assert_eq!(ALLOWED_COMMANDS, &[GET_SYSINFO]);
    }

    // ── JSON reader ─────────────────────────────────────────────────

    #[test]
    fn parse_json_reads_scalars_and_containers() {
        assert_eq!(parse_json("null"), Some(Json::Null));
        assert_eq!(parse_json(" true "), Some(Json::Bool(true)));
        assert_eq!(parse_json("false"), Some(Json::Bool(false)));
        assert_eq!(parse_json("-12.5e3"), Some(Json::Num("-12.5e3".to_owned())));
        assert_eq!(parse_json(r#""hi""#), Some(Json::Str("hi".to_owned())));
        assert_eq!(parse_json("[]"), Some(Json::Arr(vec![])));
        assert_eq!(parse_json("{}"), Some(Json::Obj(vec![])));
        assert_eq!(
            parse_json(r#"{"a":[1,{"b":null}]}"#).and_then(|v| v.get("a").cloned()),
            Some(Json::Arr(vec![
                Json::Num("1".to_owned()),
                Json::Obj(vec![("b".to_owned(), Json::Null)]),
            ]))
        );
    }

    #[test]
    fn parse_json_decodes_escapes() {
        let value = parse_json(r#""a\"b\\c\/d\n\té😀""#).unwrap();
        assert_eq!(value.as_str(), Some("a\"b\\c/d\n\té😀"));
    }

    #[test]
    fn parse_json_rejects_malformed_documents() {
        for bad in [
            "",
            "{",
            "[1,]",
            r#"{"a"}"#,
            r#"{"a":1,}"#,
            r#""unterminated"#,
            "{} trailing",
            "tru",
            "01x",
            "1e999",            // overflows to infinity
            r#""\ud800""#,      // lone high surrogate
            r#""\udc00""#,      // lone low surrogate
            r#""\q""#,          // unknown escape
            "\"raw\nnewline\"", // control character in a string
        ] {
            assert!(parse_json(bad).is_none(), "must reject {bad:?}");
        }
    }

    #[test]
    fn parse_json_rejects_documents_deeper_than_the_limit() {
        let deep = "[".repeat(64) + &"]".repeat(64);
        assert!(parse_json(&deep).is_none());
        let shallow = "[".repeat(8) + &"]".repeat(8);
        assert!(parse_json(&shallow).is_some());
    }

    #[test]
    fn json_accessors_are_type_checked() {
        let value = parse_json(r#"{"s":"x","n":4}"#).unwrap();
        assert_eq!(value.get("s").and_then(Json::as_str), Some("x"));
        assert_eq!(value.get("n").and_then(Json::as_f64), Some(4.0));
        assert_eq!(value.get("n").and_then(Json::as_str), None);
        assert_eq!(value.get("s").and_then(Json::as_f64), None);
        assert_eq!(value.get("missing"), None);
        assert_eq!(Json::Null.get("any"), None);
    }

    // ── get_sysinfo interpretation ──────────────────────────────────

    #[test]
    fn parse_sysinfo_reads_a_plug() {
        let info = parse_sysinfo(HS110_SYSINFO).unwrap();
        assert_eq!(info.model.as_deref(), Some("HS110(EU)"));
        assert_eq!(
            info.sw_ver.as_deref(),
            Some("1.2.5 Build 171213 Rel.101659")
        );
        assert_eq!(info.hw_ver.as_deref(), Some("1.0"));
        assert_eq!(info.alias.as_deref(), Some("Living Room Lamp"));
        assert_eq!(info.mac.as_deref(), Some("50:C7:BF:11:22:33"));
        assert_eq!(
            info.device_id.as_deref(),
            Some("8006AB1234567890ABCDEF1234567890ABCDEF12")
        );
        assert_eq!(info.dev_type.as_deref(), Some("IOT.SMARTPLUGSWITCH"));
        assert!(info.switches_mains);
        let (lat, lon) = info.location.unwrap();
        assert!((lat - 51.5074).abs() < 1e-9);
        assert!((lon - -0.1278).abs() < 1e-9);
    }

    #[test]
    fn parse_sysinfo_reads_a_bulb_with_scaled_coordinates() {
        let info = parse_sysinfo(KL130_SYSINFO).unwrap();
        assert_eq!(info.model.as_deref(), Some("KL130B(US)"));
        assert_eq!(info.mac.as_deref(), Some("B0BE76445566"));
        assert_eq!(info.dev_type.as_deref(), Some("IOT.SMARTBULB"));
        assert!(!info.switches_mains, "a bulb does not switch mains");
        let (lat, lon) = info.location.unwrap();
        assert!((lat - 37.7749).abs() < 1e-9);
        assert!((lon - -122.4194).abs() < 1e-9);
    }

    #[test]
    fn parse_sysinfo_rejects_non_kasa_and_error_responses() {
        for bad in [
            "",
            "not json",
            "{}",
            r#"{"system":{}}"#,
            r#"{"system":{"get_sysinfo":{}}}"#, // empty object: no device data
            r#"{"system":{"get_sysinfo":[]}}"#,
            r#"{"emeter":{"get_realtime":{"power":12}}}"#,
            r#"{"system":{"get_sysinfo":{"err_code":-1,"err_msg":"module not support"}}}"#,
        ] {
            assert!(parse_sysinfo(bad).is_none(), "must reject {bad:?}");
        }
    }

    #[test]
    fn parse_sysinfo_survives_missing_optional_fields() {
        let info = parse_sysinfo(r#"{"system":{"get_sysinfo":{"model":"HS100(UK)"}}}"#).unwrap();
        assert_eq!(info.model.as_deref(), Some("HS100(UK)"));
        assert_eq!(info.alias, None);
        assert_eq!(info.location, None);
        assert!(!info.switches_mains);
    }

    #[test]
    fn relay_state_zero_still_means_switched_mains() {
        let info = parse_sysinfo(r#"{"system":{"get_sysinfo":{"relay_state":0,"model":"HS200"}}}"#)
            .unwrap();
        assert!(info.switches_mains);
    }

    #[test]
    fn unset_or_implausible_coordinates_are_dropped() {
        let cases = [
            r#"{"system":{"get_sysinfo":{"latitude":0,"longitude":0,"model":"HS100"}}}"#,
            r#"{"system":{"get_sysinfo":{"latitude_i":0,"longitude_i":0,"model":"HS100"}}}"#,
            r#"{"system":{"get_sysinfo":{"latitude":91.5,"longitude":10,"model":"HS100"}}}"#,
            r#"{"system":{"get_sysinfo":{"latitude":10,"model":"HS100"}}}"#,
            r#"{"system":{"get_sysinfo":{"latitude":"n/a","longitude":"n/a","model":"HS1"}}}"#,
        ];
        for case in cases {
            assert_eq!(parse_sysinfo(case).unwrap().location, None, "{case}");
        }
    }

    #[test]
    fn blank_string_fields_become_none() {
        let info =
            parse_sysinfo(r#"{"system":{"get_sysinfo":{"model":"  ","alias":"  x  "}}}"#).unwrap();
        assert_eq!(info.model, None);
        assert_eq!(info.alias.as_deref(), Some("x"));
    }

    #[test]
    fn label_falls_back_through_model_then_dev_name() {
        let plug = parse_sysinfo(HS110_SYSINFO).unwrap();
        assert_eq!(plug.label(), "HS110(EU)");
        let named =
            parse_sysinfo(r#"{"system":{"get_sysinfo":{"dev_name":"Smart Wi-Fi Plug"}}}"#).unwrap();
        assert_eq!(named.label(), "Smart Wi-Fi Plug");
        let bare = parse_sysinfo(r#"{"system":{"get_sysinfo":{"rssi":-40}}}"#).unwrap();
        assert_eq!(bare.label(), "TP-Link Kasa device");
    }

    // ── Findings ────────────────────────────────────────────────────

    fn ip() -> IpAddr {
        "192.168.1.55".parse().unwrap()
    }

    #[test]
    fn plug_finding_is_high_and_confirmed() {
        let info = parse_sysinfo(HS110_SYSINFO).unwrap();
        let finding = control_finding(ip(), KASA_PORT, &info);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.affected_port, Some(9999));
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-306"));
        assert!(finding.affected_mac.is_some());
        assert!(finding.remediation.is_some());
        let hint = finding.device_hint.unwrap();
        assert_eq!(hint.vendor.as_deref(), Some("TP-Link"));
        assert_eq!(hint.model.as_deref(), Some("HS110(EU)"));
        assert_eq!(hint.hostname.as_deref(), Some("Living Room Lamp"));
    }

    #[test]
    fn bulb_finding_is_medium() {
        let info = parse_sysinfo(KL130_SYSINFO).unwrap();
        assert_eq!(
            control_finding(ip(), KASA_PORT, &info).severity,
            Severity::Medium
        );
    }

    #[test]
    fn finding_titles_are_stable_across_devices() {
        let plug = control_finding(ip(), KASA_PORT, &parse_sysinfo(HS110_SYSINFO).unwrap());
        let bulb = control_finding(ip(), KASA_PORT, &parse_sysinfo(KL130_SYSINFO).unwrap());
        assert_eq!(
            plug.title, bulb.title,
            "the title must not carry per-device data; it feeds the fingerprint"
        );
        assert_eq!(plug.fingerprint(), bulb.fingerprint());
    }

    #[test]
    fn geolocation_finding_reports_rounded_coordinates() {
        let finding = geolocation_finding(ip(), KASA_PORT, 51.507_4, -0.127_8);
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-200"));
        assert_eq!(
            finding.evidence.as_deref(),
            Some("latitude=51.5074 longitude=-0.1278")
        );
    }

    // ── Proptests ───────────────────────────────────────────────────

    proptest! {
        /// The JSON reader never panics on arbitrary text.
        #[test]
        fn prop_parse_json_no_panic(text in ".{0,512}") {
            let _ = parse_json(&text);
        }

        /// Neither does the sysinfo interpreter, on arbitrary text...
        #[test]
        fn prop_parse_sysinfo_no_panic(text in ".{0,512}") {
            let _ = parse_sysinfo(&text);
        }

        /// ...nor on arbitrary bytes run through the real decrypt path.
        #[test]
        fn prop_decrypt_then_parse_no_panic(
            body in proptest::collection::vec(any::<u8>(), 0..1024)
        ) {
            if let Ok(text) = String::from_utf8(decrypt(&body)) {
                let _ = parse_sysinfo(&text);
            }
        }

        /// ...nor on structurally valid JSON wrapped in the Kasa envelope.
        #[test]
        fn prop_parse_sysinfo_envelope_no_panic(
            alias in ".{0,64}",
            lat in -1e9f64..1e9,
            relay in 0i32..2,
        ) {
            let alias = alias.replace(['"', '\\'], "");
            let text = format!(
                r#"{{"system":{{"get_sysinfo":{{"alias":"{alias}","latitude":{lat},
                   "longitude":{lat},"relay_state":{relay}}}}}}}"#
            );
            if let Some(info) = parse_sysinfo(&text) {
                prop_assert!(info.switches_mains);
                let _ = control_finding("10.0.0.1".parse().unwrap(), KASA_PORT, &info);
            }
        }

        /// Decrypting an encryption round-trips for any payload.
        #[test]
        fn prop_cipher_roundtrips(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            prop_assert_eq!(decrypt(&encrypt(&data)), data);
        }

        /// Only the allowlisted command is ever framed for sending.
        #[test]
        fn prop_build_request_only_allowlisted(command in ".{0,128}") {
            if command != GET_SYSINFO {
                prop_assert!(build_request(&command).is_none());
            }
        }
    }
}

/// Parser entry points for the fuzz harness.
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    #[must_use]
    pub fn decrypt(cipher: &[u8]) -> usize {
        super::decrypt(cipher).len()
    }
    #[must_use]
    pub fn json(text: &str) -> bool {
        super::parse_json(text).is_some()
    }
    #[must_use]
    pub fn sysinfo(text: &str) -> bool {
        super::parse_sysinfo(text).is_some()
    }
}
