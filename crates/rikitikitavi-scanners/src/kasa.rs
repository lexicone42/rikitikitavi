//! TP-Link Kasa local control plane (TCP/9999).
//!
//! The Kasa LAN protocol is a 4-byte big-endian length prefix followed by an XOR
//! autokey stream with initial key 171. It carries no authentication: any host on
//! the LAN can read `get_sysinfo` and issue control commands. This probe sends one
//! request from a hard allowlist (`get_sysinfo` only) and never writes device state.
//!
//! Protocol description and the test vector: softScheck/tplink-smartplug
//! (Apache-2.0); see THIRD-PARTY-NOTICES.md.

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

// ── JSON ────────────────────────────────────────────────────────────────────

type Json = serde_json::Value;

/// Parse a complete JSON document.
fn parse_json(text: &str) -> Option<Json> {
    serde_json::from_str(text).ok()
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
    if info.as_object().is_none_or(serde_json::Map::is_empty) {
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

// ── Fixed-firmware table ────────────────────────────────────────────────────

/// Improper authentication and account-information exposure (FAQ 5342).
const CVE_AUTH: &str = "CVE-2026-108473";
/// Insufficient cryptographic protection of local control messages (FAQ 5267).
const CVE_CRYPTO: &str = "CVE-2026-76784";

const FAQ_5342: &str = "https://www.omadanetworks.com/us/support/faq/5342/";
const FAQ_5267: &str = "https://www.omadanetworks.com/us/support/faq/5267/";
const FAQ_4416: &str = "https://www.tp-link.com/support/faq/4416";
/// GPL-3.0; linked only.
const PYTHON_KASA_SUPPORTED: &str =
    "https://github.com/python-kasa/python-kasa/blob/master/SUPPORTED.md";

/// `(major, minor, patch, build)`.
type FwVersion = (u32, u32, u32, u32);

/// One advisory row. `hw_ver` is in `get_sysinfo` form (FAQ `V5` is `5.0`);
/// `None` when the advisory names the model without a hardware version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FixedFirmware {
    model: &'static str,
    hw_ver: Option<&'static str>,
    fixed: &'static str,
    cve: &'static str,
}

const fn auth(model: &'static str, hw_ver: &'static str, fixed: &'static str) -> FixedFirmware {
    FixedFirmware {
        model,
        hw_ver: Some(hw_ver),
        fixed,
        cve: CVE_AUTH,
    }
}

const fn crypto(
    model: &'static str,
    hw_ver: Option<&'static str>,
    fixed: &'static str,
) -> FixedFirmware {
    FixedFirmware {
        model,
        hw_ver,
        fixed,
        cve: CVE_CRYPTO,
    }
}

/// FAQ 5342 (updated 2026-10-14) and FAQ 5267 (updated 2026-08-26). Model names
/// are normalised: `KS230 KIT` is `KS230`, `ES20M & KS220M` is two rows,
/// `HS103P3/HS103P4` is `HS103`, `KP125MP2/KP125MP4` is `KP125M`, and
/// `HS220-LA(US) / HS220-BL(US)` is `HS220`.
const FIXED_FIRMWARE: &[FixedFirmware] = &[
    auth("HS103", "5.0", "1.1.3 Build 250908 Rel.112508"),
    auth("EP10", "1.0", "1.1.1 Build 250908 Rel.112508"),
    auth("EP40", "1.0", "1.1.0 Build 250225 Rel.171723"),
    auth("HS200", "5.0", "1.1.2 Build 241220 Rel.165559"),
    auth("KP401", "1.0", "1.1.2 Build 241223 Rel.094434"),
    auth("KS230", "2.0", "1.1.4 Build 241223 Rel.105830"),
    auth("KP405", "1.0", "1.1.0 Build 250225 Rel.174632"),
    auth("HS220", "3.0", "1.1.4 Build 241220 Rel.171050"),
    auth("KP115", "1.0", "1.1.1 Build 250908 Rel.112945"),
    auth("HS210", "3.0", "1.1.0 Build 250225 Rel.163425"),
    auth("HS300", "2.0", "1.1.2 Build 241220 Rel.171333"),
    auth("KP200", "3.0", "1.1.0 Build 250225 Rel.171724"),
    auth("KP303", "2.0", "1.1.2 Build 241220 Rel.173321"),
    auth("KS200", "1.0", "1.1.2 Build 241223 Rel.103857"),
    auth("EP40A", "1.0", "1.1.1 Build 250908 Rel.112526"),
    auth("KS220", "1.0", "1.1.3 Build 241223 Rel.105515"),
    auth("KS200M", "1.0", "1.1.4 Build 241223 Rel.104700"),
    auth("ES20M", "1.0", "1.1.6 Build 250522 Rel.210254"),
    auth("KS220M", "1.0", "1.1.6 Build 250522 Rel.210254"),
    auth("KP400", "3.0", "1.1.0 Build 250225 Rel.171723"),
    auth("KL125", "4.0", "1.1.1 Build 260710 Rel.082646"),
    auth("KL135", "2.0", "1.1.1 Build 260710 Rel.082646"),
    auth("KL110", "4.0", "1.1.1 Build 260710 Rel.082646"),
    auth("KL420L5", "1.0", "1.4.2 Build 260605 Rel.035033"),
    crypto("HS103", None, "1.1.3 Build 250908 Rel.112508"),
    crypto("EP10", None, "1.1.1 Build 250908 Rel.112508"),
    crypto("EP25", Some("2.0"), "1.0.3 Build 240529 Rel.145252"),
    crypto("HS300", Some("2.0"), "1.1.2 Build 241220 Rel.171333"),
    crypto("KP303", Some("2.0"), "1.1.2 Build 241220 Rel.173321"),
    crypto("EP40A", None, "1.1.1 Build 250908 Rel.112526"),
    crypto("KP125M", None, "1.2.5 Build 241213 Rel.172504"),
    crypto("KP115", None, "1.1.1 Build 250908 Rel.112945"),
    crypto("KS225", None, "1.1.1 Build 240626 Rel.175125"),
    crypto("EP40M", None, "1.1.0 Build 240415 Rel.171219"),
    crypto("KS205", None, "1.1.1 Build 240724 Rel.105920"),
    crypto("KS240", None, "1.0.6 Build 240122 Rel.160100"),
    crypto("ES20M", None, "1.1.6 Build 250522 Rel.210254"),
    crypto("KS220M", None, "1.1.6 Build 250522 Rel.210254"),
    crypto("KP200", Some("3.0"), "1.1.0 Build 250225 Rel.171724"),
    crypto("HS200", Some("5.26"), "1.0.3 Build 240723 Rel.192622"),
    crypto("HS220", Some("6.6"), "1.0.3 Build 240723 Rel.192630"),
    crypto("HS220", Some("3.26"), "1.1.1 Build 240802 Rel.094131"),
    crypto("HS220", Some("4.6"), "1.1.1 Build 240802 Rel.094142"),
    crypto("KL125", None, "1.1.1 Build 260710 Rel.082646"),
];

/// Multi-pack SKUs in the advisories and the model the device reports.
const PACK_ALIASES: &[(&str, &str)] = &[
    ("HS103P3", "HS103"),
    ("HS103P4", "HS103"),
    ("KP125MP2", "KP125M"),
    ("KP125MP4", "KP125M"),
];

/// Upper-case base model: region (`(US)`), colour (`-LA`) and `KIT` suffixes
/// dropped, pack SKUs mapped to the single unit.
fn normalise_model(raw: &str) -> String {
    let upper = raw.trim().to_ascii_uppercase();
    let base = upper.split(['(', ' ', '-']).next().unwrap_or_default();
    PACK_ALIASES
        .iter()
        .find(|(pack, _)| *pack == base)
        .map_or(base, |(_, model)| model)
        .to_owned()
}

/// `get_sysinfo` form: `V5` and `5` become `5.0`; `5.26` is unchanged.
fn normalise_hw(raw: &str) -> String {
    let trimmed = raw.trim();
    let bare = trimmed.strip_prefix(['V', 'v']).unwrap_or(trimmed);
    if bare.contains('.') {
        bare.to_owned()
    } else {
        format!("{bare}.0")
    }
}

/// Parse `1.0.8 Build 230804 Rel.172306`. `Rel.` is ignored.
fn parse_sw_ver(raw: &str) -> Option<FwVersion> {
    let mut tokens = raw.split_whitespace();
    let mut parts = tokens.next()?.split('.').map(|p| p.parse::<u32>().ok());
    let major = parts.next()??;
    let minor = parts.next()??;
    let patch = parts.next()??;
    if parts.next().is_some() || !tokens.next()?.eq_ignore_ascii_case("build") {
        return None;
    }
    let build = tokens.next()?.parse().ok()?;
    Some((major, minor, patch, build))
}

/// `Some(true)` for a hardware-version match, `Some(false)` for a model-only
/// match, `None` when the row does not apply.
///
/// A model-only row applies to the hardware versions of keyed rows for the same
/// model; with no keyed row it applies to every hardware version.
fn row_match(row: &FixedFirmware, model: &str, hw: Option<&str>) -> Option<bool> {
    if row.model != model {
        return None;
    }
    if let Some(row_hw) = row.hw_ver {
        return (Some(row_hw) == hw).then_some(true);
    }
    let mut keyed = FIXED_FIRMWARE
        .iter()
        .filter(|r| r.model == model)
        .filter_map(|r| r.hw_ver)
        .peekable();
    if keyed.peek().is_none() {
        return Some(false);
    }
    keyed.any(|h| Some(h) == hw).then_some(true)
}

/// Firmware status against [`FIXED_FIRMWARE`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum FirmwareVerdict {
    /// No row applies, or `sw_ver` did not parse.
    Unknown,
    /// At or above the fix of every applicable row.
    Fixed,
    /// Below the fix of at least one applicable row.
    Vulnerable {
        cves: Vec<&'static str>,
        /// Highest fixed release among the rows that flagged the device.
        fixed: &'static str,
        /// At least one flagging row matched the hardware version.
        hw_matched: bool,
    },
}

fn classify_firmware(
    model: Option<&str>,
    hw_ver: Option<&str>,
    sw_ver: Option<&str>,
) -> FirmwareVerdict {
    let Some(model) = model.map(normalise_model) else {
        return FirmwareVerdict::Unknown;
    };
    let hw = hw_ver.map(normalise_hw);
    let rows: Vec<(&FixedFirmware, bool)> = FIXED_FIRMWARE
        .iter()
        .filter_map(|row| row_match(row, &model, hw.as_deref()).map(|exact| (row, exact)))
        .collect();
    let Some(installed) = sw_ver.and_then(parse_sw_ver) else {
        return FirmwareVerdict::Unknown;
    };
    if rows.is_empty() {
        return FirmwareVerdict::Unknown;
    }

    let mut cves = Vec::new();
    let mut highest: Option<(FwVersion, &'static str)> = None;
    let mut hw_matched = false;
    for (row, exact) in rows {
        let Some(target) = parse_sw_ver(row.fixed) else {
            continue;
        };
        if installed >= target {
            continue;
        }
        if !cves.contains(&row.cve) {
            cves.push(row.cve);
        }
        hw_matched |= exact;
        if highest.is_none_or(|(v, _)| target > v) {
            highest = Some((target, row.fixed));
        }
    }
    match highest {
        None => FirmwareVerdict::Fixed,
        Some((_, fixed)) => FirmwareVerdict::Vulnerable {
            cves,
            fixed,
            hw_matched,
        },
    }
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

/// Update, verify, then segment. `fixed` names the release to install when known.
fn segmentation_remediation(switches_mains: bool, fixed: Option<&str>) -> Remediation {
    let update = fixed.map_or_else(
        || "Update the firmware from the Kasa app.".to_owned(),
        |release| format!("Update the firmware from the Kasa app to {release} or later."),
    );
    let mut steps = vec![
        update,
        "Re-scan to verify. Some updates add authentication to the local protocol \
         (HS100 (UK) hardware 4.1 on firmware 1.1.0); others leave TCP 9999 open."
            .to_owned(),
        "If TCP 9999 still answers, move the device onto an IoT VLAN / guest SSID \
         that cannot reach workstations, servers or management interfaces, and allow \
         TCP 9999 only from the controller that needs it (a firewall rule on the \
         VLAN, not on the device)."
            .to_owned(),
        "Leave Me > Settings > Third-Party Compatibility off unless a local \
         controller such as Home Assistant needs it; TP-Link states it may reduce \
         the security protections (FAQ 4416)."
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
        description: "Update the firmware, re-scan to check whether TCP 9999 still \
                      answers without credentials, and segment the device if it does."
            .to_owned(),
        steps,
        effort: Some("30 minutes (firmware update, network change)".to_owned()),
    }
}

fn device_hint(info: &Sysinfo) -> DeviceHint {
    let mut hint = DeviceHint::new()
        .with_vendor("TP-Link")
        .with_device_type(DeviceType::IoT);
    if let Some(model) = &info.model {
        hint = hint.with_model(model.clone());
    }
    if let Some(alias) = &info.alias {
        hint = hint.with_hostname(alias.clone());
    }
    hint
}

fn sysinfo_evidence(info: &Sysinfo) -> String {
    format!(
        "get_sysinfo decoded: model={} sw_ver={} hw_ver={} type={} alias={}",
        info.model.as_deref().unwrap_or("?"),
        info.sw_ver.as_deref().unwrap_or("unknown"),
        info.hw_ver.as_deref().unwrap_or("unknown"),
        info.dev_type.as_deref().unwrap_or("?"),
        info.alias.as_deref().unwrap_or("(no alias)"),
    )
}

/// CVE finding when the firmware is below an advisory fix, otherwise the
/// generic unauthenticated-control finding.
fn device_finding(ip: IpAddr, port: u16, info: &Sysinfo) -> Finding {
    match classify_firmware(
        info.model.as_deref(),
        info.hw_ver.as_deref(),
        info.sw_ver.as_deref(),
    ) {
        FirmwareVerdict::Vulnerable {
            cves,
            fixed,
            hw_matched,
        } => cve_finding(ip, port, info, &cves, fixed, hw_matched),
        FirmwareVerdict::Fixed | FirmwareVerdict::Unknown => control_finding(ip, port, info),
    }
}

const CVE_SUMMARIES: &[(&str, &str)] = &[
    (
        CVE_AUTH,
        "CVE-2026-108473 (TP-Link FAQ 5342): improper authentication in the local \
         device-management protocol lets an unauthenticated adjacent attacker change \
         device state or management settings, and account information can be exposed.",
    ),
    (
        CVE_CRYPTO,
        "CVE-2026-76784 (TP-Link FAQ 5267): insufficient cryptographic protection of \
         the local protocol lets an adjacent attacker intercept, replay or forge \
         control messages.",
    ),
];

fn cve_summary(cve: &str) -> &'static str {
    CVE_SUMMARIES
        .iter()
        .find(|(id, _)| *id == cve)
        .map_or("", |(_, text)| text)
}

fn cve_finding(
    ip: IpAddr,
    port: u16,
    info: &Sysinfo,
    cves: &[&'static str],
    fixed: &str,
    hw_matched: bool,
) -> Finding {
    let label = info.label();
    let firmware = info.sw_ver.as_deref().unwrap_or("unknown");
    let hardware = info.hw_ver.as_deref().unwrap_or("unknown");
    let summaries: Vec<&str> = cves.iter().map(|cve| cve_summary(cve)).collect();
    let match_note = if hw_matched {
        "TP-Link lists this model and hardware version with that fixed release."
    } else {
        "TP-Link lists this model without a hardware version, so the match is on the \
         model only."
    };
    let has_auth = cves.contains(&CVE_AUTH);

    let mut references = Vec::new();
    if has_auth {
        references.push(FAQ_5342.to_owned());
    }
    if cves.contains(&CVE_CRYPTO) {
        references.push(FAQ_5267.to_owned());
    }
    references.extend(refs![
        FAQ_4416,
        "https://github.com/softScheck/tplink-smartplug",
    ]);

    let finding = Finding::new(
        "kasa",
        &format!("TP-Link Kasa firmware below the vendor-listed fixed release on {ip}:{port}"),
        &format!(
            "{label} at {ip}:{port} answered `system.get_sysinfo` with no credentials and \
             reports hardware {hardware}, firmware {firmware}, which is below {fixed}. \
             {match_note} {}",
            summaries.join(" ")
        ),
        Severity::High,
    )
    .with_confidence(if hw_matched {
        Confidence::Confirmed
    } else {
        Confidence::Probable
    })
    .with_ip(ip)
    .with_port(port)
    .with_service("kasa")
    .with_cwe(if has_auth { "CWE-287" } else { "CWE-327" })
    .with_cve_ids(cves.iter().map(|&cve| cve.to_owned()).collect())
    .with_remediation(segmentation_remediation(info.switches_mains, Some(fixed)))
    .with_device_hint(device_hint(info))
    .with_evidence(format!("{}; fixed={fixed}", sysinfo_evidence(info)))
    .with_references(references);

    match &info.mac {
        Some(mac) => finding.with_mac(mac.as_str()),
        None => finding,
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
    .with_remediation(segmentation_remediation(info.switches_mains, None))
    .with_device_hint(device_hint(info))
    .with_evidence(sysinfo_evidence(info))
    .with_references(refs![
        "https://github.com/softScheck/tplink-smartplug",
        "https://cwe.mitre.org/data/definitions/306.html",
        FAQ_4416,
        PYTHON_KASA_SUPPORTED,
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
    .with_remediation(geolocation_remediation())
}

fn geolocation_remediation() -> Remediation {
    Remediation {
        description: "Remove the stored location, then keep the device off networks \
                      that untrusted clients can reach."
            .to_owned(),
        steps: vec![
            "In the Kasa app open the device's settings and clear its location.".to_owned(),
            "Re-scan and confirm the coordinates are gone from the finding.".to_owned(),
            "Segment the device as described in its local-control finding.".to_owned(),
        ],
        effort: Some("5 minutes".to_owned()),
    }
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
            findings.push(device_finding(ip, KASA_PORT, &info));
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

    /// Published `get_sysinfo` ciphertext (softScheck/tplink-smartplug, Apache-2.0),
    /// no length prefix.
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
            "3.",               // digits required after the point
            "-.5",              // digits required before the point
            "01",               // leading zero
            r#""\u+123""#,      // sign inside a \u escape
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
        let deep = "[".repeat(200) + &"]".repeat(200);
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
        // A repeated key reads as its last value.
        let dup = parse_json(r#"{"k":1,"k":2}"#).unwrap();
        assert_eq!(dup.get("k").and_then(Json::as_f64), Some(2.0));
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

    // ── Fixed-firmware table ────────────────────────────────────────

    fn sysinfo_for(model: &str, hw: &str, sw: &str) -> Sysinfo {
        parse_sysinfo(&format!(
            r#"{{"system":{{"get_sysinfo":{{"model":"{model}","hw_ver":"{hw}",
               "sw_ver":"{sw}","relay_state":1,"mac":"50:C7:BF:11:22:33"}}}}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn parse_sw_ver_reads_the_kasa_shape() {
        assert_eq!(
            parse_sw_ver("1.0.8 Build 230804 Rel.172306"),
            Some((1, 0, 8, 230_804))
        );
        assert_eq!(parse_sw_ver("1.1.3 build 250908"), Some((1, 1, 3, 250_908)));
        assert_eq!(
            parse_sw_ver("  1.2.5   Build 171213  "),
            Some((1, 2, 5, 171_213))
        );
    }

    #[test]
    fn parse_sw_ver_rejects_other_shapes() {
        for bad in [
            "",
            "1.0.8",
            "1.0 Build 230804",
            "1.0.8.1 Build 230804",
            "1.0.8 Rel 230804",
            "1.0.8 Build",
            "1.0.x Build 230804",
            "1.0.8 Build 2308x4",
            "99999999999.0.0 Build 1",
        ] {
            assert_eq!(parse_sw_ver(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn every_table_row_parses_and_is_normalised() {
        for row in FIXED_FIRMWARE {
            assert!(parse_sw_ver(row.fixed).is_some(), "{row:?}");
            assert_eq!(normalise_model(row.model), row.model, "{row:?}");
            if let Some(hw) = row.hw_ver {
                assert_eq!(normalise_hw(hw), hw, "{row:?}");
            }
            assert!(row.cve == CVE_AUTH || row.cve == CVE_CRYPTO);
            assert!(!cve_summary(row.cve).is_empty());
        }
    }

    #[test]
    fn table_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for row in FIXED_FIRMWARE {
            assert!(seen.insert((row.model, row.hw_ver, row.cve)), "{row:?}");
        }
    }

    #[test]
    fn table_row_counts_match_the_advisories() {
        let count = |cve| FIXED_FIRMWARE.iter().filter(|r| r.cve == cve).count();
        // FAQ 5342: 23 rows, `ES20M & KS220M` split in two.
        assert_eq!(count(CVE_AUTH), 24);
        // FAQ 5267: 20 rows.
        assert_eq!(count(CVE_CRYPTO), 20);
        assert!(
            FIXED_FIRMWARE
                .iter()
                .filter(|r| r.cve == CVE_AUTH)
                .all(|r| r.hw_ver.is_some())
        );
    }

    #[test]
    fn model_names_are_normalised() {
        assert_eq!(normalise_model("HS103(US)"), "HS103");
        assert_eq!(normalise_model("hs200(us)"), "HS200");
        assert_eq!(normalise_model("KS230 KIT"), "KS230");
        assert_eq!(normalise_model("HS103P3"), "HS103");
        assert_eq!(normalise_model("HS103P4"), "HS103");
        assert_eq!(normalise_model("KP125MP2"), "KP125M");
        assert_eq!(normalise_model("KP125MP4(US)"), "KP125M");
        assert_eq!(normalise_model("HS220-LA(US)"), "HS220");
        assert_eq!(normalise_model(" KL420L5(US) "), "KL420L5");
        assert_eq!(normalise_model(""), "");
    }

    #[test]
    fn hardware_versions_are_normalised() {
        assert_eq!(normalise_hw("V5"), "5.0");
        assert_eq!(normalise_hw("5"), "5.0");
        assert_eq!(normalise_hw("5.0"), "5.0");
        assert_eq!(normalise_hw("V5.26"), "5.26");
        assert_eq!(normalise_hw(" v3.0 "), "3.0");
    }

    #[test]
    fn hs200_v5_and_v5_26_are_separate_firmware_lines() {
        // V5 fixed in 1.1.2 B241220; V5.26 fixed in 1.0.3 B240723.
        assert_eq!(
            classify_firmware(Some("HS200(US)"), Some("5.26"), Some("1.0.3 Build 240723")),
            FirmwareVerdict::Fixed
        );
        assert_eq!(
            classify_firmware(Some("HS200(US)"), Some("5.0"), Some("1.0.3 Build 240723")),
            FirmwareVerdict::Vulnerable {
                cves: vec![CVE_AUTH],
                fixed: "1.1.2 Build 241220 Rel.165559",
                hw_matched: true,
            }
        );
        assert_eq!(
            classify_firmware(Some("HS200(US)"), Some("5.26"), Some("1.0.2 Build 240101")),
            FirmwareVerdict::Vulnerable {
                cves: vec![CVE_CRYPTO],
                fixed: "1.0.3 Build 240723 Rel.192622",
                hw_matched: true,
            }
        );
    }

    #[test]
    fn a_model_in_both_advisories_lists_both_cves() {
        assert_eq!(
            classify_firmware(
                Some("HS300(US)"),
                Some("2.0"),
                Some("1.0.12 Build 220121 Rel.175814")
            ),
            FirmwareVerdict::Vulnerable {
                cves: vec![CVE_AUTH, CVE_CRYPTO],
                fixed: "1.1.2 Build 241220 Rel.171333",
                hw_matched: true,
            }
        );
    }

    #[test]
    fn a_model_only_row_follows_its_faq_5342_counterpart() {
        // HS103: FAQ 5342 keys V5; FAQ 5267 names the model only.
        assert_eq!(
            classify_firmware(Some("HS103(US)"), Some("5.0"), Some("1.0.8 Build 230804")),
            FirmwareVerdict::Vulnerable {
                cves: vec![CVE_AUTH, CVE_CRYPTO],
                fixed: "1.1.3 Build 250908 Rel.112508",
                hw_matched: true,
            }
        );
        // Another hardware version is outside both rows.
        assert_eq!(
            classify_firmware(Some("HS103(US)"), Some("4.0"), Some("1.0.8 Build 230804")),
            FirmwareVerdict::Unknown
        );
    }

    #[test]
    fn a_model_only_row_without_a_counterpart_is_a_model_match() {
        assert_eq!(
            classify_firmware(Some("KP125M(US)"), Some("1.0"), Some("1.2.3 Build 240624")),
            FirmwareVerdict::Vulnerable {
                cves: vec![CVE_CRYPTO],
                fixed: "1.2.5 Build 241213 Rel.172504",
                hw_matched: false,
            }
        );
        assert_eq!(
            classify_firmware(Some("KS240(US)"), None, Some("1.0.6 Build 240122")),
            FirmwareVerdict::Fixed
        );
    }

    #[test]
    fn at_or_above_the_fixed_build_is_fixed() {
        for sw in [
            "1.1.3 Build 250908 Rel.112508",
            "1.1.3 Build 250908 Rel.000000",
            "1.1.4 Build 250101",
            "2.0.0 Build 100101",
        ] {
            assert_eq!(
                classify_firmware(Some("HS103(US)"), Some("5.0"), Some(sw)),
                FirmwareVerdict::Fixed,
                "{sw}"
            );
        }
    }

    #[test]
    fn unknown_model_or_unreadable_firmware_is_unknown() {
        assert_eq!(
            classify_firmware(Some("HS110(EU)"), Some("1.0"), Some("1.2.5 Build 171213")),
            FirmwareVerdict::Unknown
        );
        assert_eq!(
            classify_firmware(None, Some("5.0"), Some("1.0.8 Build 230804")),
            FirmwareVerdict::Unknown
        );
        assert_eq!(
            classify_firmware(Some("HS103"), Some("5.0"), None),
            FirmwareVerdict::Unknown
        );
        assert_eq!(
            classify_firmware(Some("HS103"), Some("5.0"), Some("garbage")),
            FirmwareVerdict::Unknown
        );
        // A keyed row needs a hardware version.
        assert_eq!(
            classify_firmware(Some("EP40"), None, Some("1.0.0 Build 200101")),
            FirmwareVerdict::Unknown
        );
    }

    #[test]
    fn hw_matched_cve_finding_is_high_confirmed_with_cwe_287() {
        let info = sysinfo_for("HS200(US)", "5.0", "1.0.8 Build 230804 Rel.172306");
        let finding = device_finding(ip(), KASA_PORT, &info);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-287"));
        assert_eq!(finding.cve_ids, vec![CVE_AUTH.to_owned()]);
        assert!(finding.references.iter().any(|r| r == FAQ_5342));
        assert!(finding.references.iter().all(|r| r != FAQ_5267));
        assert!(finding.affected_mac.is_some());
        let remediation = finding.remediation.unwrap();
        assert!(remediation.steps[0].contains("1.1.2 Build 241220 Rel.165559"));
        assert!(
            finding
                .evidence
                .unwrap()
                .contains("fixed=1.1.2 Build 241220 Rel.165559")
        );
    }

    #[test]
    fn model_only_cve_finding_is_probable_with_cwe_327() {
        let info = sysinfo_for("KS225(US)", "1.0", "1.0.2 Build 231108 Rel.165511");
        let finding = device_finding(ip(), KASA_PORT, &info);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Probable);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-327"));
        assert_eq!(finding.cve_ids, vec![CVE_CRYPTO.to_owned()]);
        assert!(finding.references.iter().any(|r| r == FAQ_5267));
        assert!(finding.description.contains("model only"));
    }

    #[test]
    fn a_bulb_below_the_fix_is_still_high() {
        let info = parse_sysinfo(
            r#"{"system":{"get_sysinfo":{"model":"KL125(US)","hw_ver":"4.0",
               "sw_ver":"1.0.7 Build 220715 Rel.111111","mic_type":"IOT.SMARTBULB"}}}"#,
        )
        .unwrap();
        let finding = device_finding(ip(), KASA_PORT, &info);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.cve_ids.len(), 2);
    }

    #[test]
    fn fixed_or_unknown_devices_get_the_generic_finding() {
        let fixed = sysinfo_for("HS103(US)", "5.0", "1.1.3 Build 250908 Rel.112508");
        let unknown = parse_sysinfo(HS110_SYSINFO).unwrap();
        for info in [fixed, unknown] {
            let finding = device_finding(ip(), KASA_PORT, &info);
            let generic = control_finding(ip(), KASA_PORT, &info);
            assert_eq!(finding.title, generic.title);
            assert_eq!(finding.description, generic.description);
            assert_eq!(finding.severity, generic.severity);
            assert!(finding.cve_ids.is_empty());
            assert_eq!(finding.cwe_id.as_deref(), Some("CWE-306"));
        }
    }

    #[test]
    fn cve_finding_titles_are_stable_across_devices() {
        let a = device_finding(
            ip(),
            KASA_PORT,
            &sysinfo_for("HS200", "5.0", "1.0.1 Build 200101"),
        );
        let b = device_finding(
            ip(),
            KASA_PORT,
            &sysinfo_for("KS225", "1.0", "1.0.1 Build 200101"),
        );
        assert_eq!(a.title, b.title);
    }

    #[test]
    fn remediation_is_update_verify_segment() {
        let remediation = segmentation_remediation(false, None);
        assert!(remediation.steps[0].starts_with("Update the firmware"));
        assert!(remediation.steps[1].starts_with("Re-scan"));
        assert!(remediation.steps[2].contains("only from the controller"));
        assert!(remediation.steps.iter().any(|s| s.contains("FAQ 4416")));
        let all = format!(
            "{} {}",
            remediation.description,
            remediation.steps.join(" ")
        );
        assert!(!all.contains("does not add one"));
        assert_eq!(remediation.steps.len(), 6);
        assert_eq!(segmentation_remediation(true, None).steps.len(), 7);
    }

    #[test]
    fn generic_finding_links_python_kasa_and_faq_4416() {
        let finding = control_finding(ip(), KASA_PORT, &parse_sysinfo(HS110_SYSINFO).unwrap());
        assert!(
            finding
                .references
                .iter()
                .any(|r| r == PYTHON_KASA_SUPPORTED)
        );
        assert!(finding.references.iter().any(|r| r == FAQ_4416));
    }

    #[test]
    fn cve_summary_of_an_unlisted_id_is_empty() {
        assert_eq!(cve_summary("CVE-2000-0001"), "");
    }

    // ── Proptests ───────────────────────────────────────────────────

    proptest! {
        /// Firmware parsing and classification never panic.
        #[test]
        fn prop_firmware_classification_no_panic(
            model in ".{0,24}",
            hw in ".{0,8}",
            sw in ".{0,40}",
        ) {
            let _ = parse_sw_ver(&sw);
            let _ = classify_firmware(Some(&model), Some(&hw), Some(&sw));
        }

        /// A parsed version round-trips through its canonical text.
        #[test]
        fn prop_sw_ver_roundtrips(a in 0u32..100, b in 0u32..100, c in 0u32..100, d in 0u32..999_999) {
            prop_assert_eq!(parse_sw_ver(&format!("{a}.{b}.{c} Build {d} Rel.1")), Some((a, b, c, d)));
        }

        /// Vulnerability is downward-closed in the installed version.
        #[test]
        fn prop_older_firmware_is_never_less_vulnerable(
            row in 0..FIXED_FIRMWARE.len(),
            lo in (0u32..3, 0u32..5, 0u32..15, 200_000u32..270_000),
            hi in (0u32..3, 0u32..5, 0u32..15, 200_000u32..270_000),
        ) {
            let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
            let row = FIXED_FIRMWARE[row];
            let hw = row.hw_ver.unwrap_or("1.0");
            let sw = |v: FwVersion| format!("{}.{}.{} Build {}", v.0, v.1, v.2, v.3);
            let vulnerable = |v| matches!(
                classify_firmware(Some(row.model), Some(hw), Some(&sw(v))),
                FirmwareVerdict::Vulnerable { .. }
            );
            if vulnerable(hi) {
                prop_assert!(vulnerable(lo));
            }
        }

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
