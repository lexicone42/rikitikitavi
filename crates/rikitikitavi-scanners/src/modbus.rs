use async_trait::async_trait;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::config::ExclusionSet;
use rikitikitavi_models::{Device, DeviceHint, DeviceType, Finding, Remediation, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Scanner;

/// Modbus/TCP `SunSpec` discovery scanner.
///
/// Modbus/TCP has no authentication, encryption or authorisation. This scanner
/// issues **read-only** function codes: FC 0x03 (Read Holding Registers) at the
/// `SunSpec` base addresses, and FC 0x2B/0x0E (Read Device Identification)
/// opportunistically. It never sends a write, reset or control function code.
pub struct ModbusScanner;

/// IANA `mbap`.
const MODBUS_PORT: u16 = 502;

/// Ports gating this scanner in Phase 2.
const MODBUS_PORTS: &[u16] = &[MODBUS_PORT];

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// `SunSpec` base addresses, in the order the specification recommends probing.
const SUNSPEC_BASES: &[u16] = &[40000, 0, 50000];

/// Unit (slave) ids tried, in order. Most residential gear answers on 1; 0xFF is
/// the Modbus/TCP "no relevant slave" id used by native TCP servers.
const UNIT_IDS: &[u8] = &[1, 0xFF];

/// `"SunS"` as two big-endian holding registers.
const SUNSPEC_MAGIC: [u16; 2] = [0x5375, 0x6E53];

/// Registers in the `SunSpec` common model block, including its ID/L header.
const COMMON_MODEL_REGS: u16 = 68;

/// Largest Modbus/TCP ADU: 7-byte MBAP header plus a 253-byte PDU.
const MAX_ADU: usize = 260;

/// Largest legal MBAP length field: unit id plus a 253-byte PDU.
const MAX_MBAP_LEN: usize = 254;

// ── Request builders ────────────────────────────────────────────────────────

/// Wrap a PDU in an MBAP header.
///
/// ```text
/// [2] transaction id
/// [2] protocol id = 0x0000
/// [2] length = 1 (unit id) + PDU length
/// [1] unit id
/// [n] PDU
/// ```
fn mbap_frame(tid: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let len = u16::try_from(pdu.len() + 1).unwrap_or(u16::MAX);
    let mut frame = Vec::with_capacity(pdu.len() + 7);
    frame.extend_from_slice(&tid.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.push(unit);
    frame.extend_from_slice(pdu);
    frame
}

/// FC 0x03 Read Holding Registers. Read-only.
fn build_read_holding(tid: u16, unit: u8, addr: u16, qty: u16) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(5);
    pdu.push(0x03);
    pdu.extend_from_slice(&addr.to_be_bytes());
    pdu.extend_from_slice(&qty.to_be_bytes());
    mbap_frame(tid, unit, &pdu)
}

/// FC 0x2B / MEI type 0x0E Read Device Identification, basic stream from object 0.
/// Read-only, and optional in the specification.
fn build_device_id(tid: u16, unit: u8) -> Vec<u8> {
    mbap_frame(tid, unit, &[0x2B, 0x0E, 0x01, 0x00])
}

// ── Response parsing ────────────────────────────────────────────────────────

/// A parsed Modbus/TCP response frame.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ModbusReply {
    /// Normal response: function code plus the PDU bytes after it.
    Data {
        tid: u16,
        unit: u8,
        function: u8,
        data: Vec<u8>,
    },
    /// Exception response (`function | 0x80`); `function` is the original code.
    Exception {
        tid: u16,
        unit: u8,
        function: u8,
        code: u8,
    },
    /// Not a well-formed Modbus/TCP response.
    Malformed,
}

/// Parse one Modbus/TCP response frame.
///
/// Requires protocol id 0, a length field within `2..=254` that the buffer
/// actually carries, and a function code. Anything else is
/// [`ModbusReply::Malformed`] — the port is then not treated as Modbus.
fn parse_response(buf: &[u8]) -> ModbusReply {
    if buf.len() < 8 {
        return ModbusReply::Malformed;
    }
    if buf[2] != 0x00 || buf[3] != 0x00 {
        return ModbusReply::Malformed;
    }
    let tid = u16::from_be_bytes([buf[0], buf[1]]);
    let len = usize::from(u16::from_be_bytes([buf[4], buf[5]]));
    if !(2..=MAX_MBAP_LEN).contains(&len) || buf.len() < 6 + len {
        return ModbusReply::Malformed;
    }
    let unit = buf[6];
    let function = buf[7];
    let body = &buf[8..6 + len];

    if function & 0x80 == 0 {
        return ModbusReply::Data {
            tid,
            unit,
            function,
            data: body.to_vec(),
        };
    }
    let Some(&code) = body.first() else {
        return ModbusReply::Malformed;
    };
    ModbusReply::Exception {
        tid,
        unit,
        function: function & 0x7F,
        code,
    }
}

/// Registers from an FC 0x03 response body: a byte count, then big-endian words.
fn parse_registers(data: &[u8]) -> Option<Vec<u16>> {
    let count = usize::from(*data.first()?);
    if count == 0 || count % 2 != 0 || data.len() < 1 + count {
        return None;
    }
    let (pairs, _) = data[1..=count].as_chunks::<2>();
    Some(pairs.iter().map(|&w| u16::from_be_bytes(w)).collect())
}

/// Modbus exception code labels (MODBUS Application Protocol V1.1b3, §7).
const fn exception_name(code: u8) -> &'static str {
    match code {
        0x01 => "illegal function",
        0x02 => "illegal data address",
        0x03 => "illegal data value",
        0x04 => "server device failure",
        0x05 => "acknowledge",
        0x06 => "server device busy",
        0x08 => "memory parity error",
        0x0A => "gateway path unavailable",
        0x0B => "gateway target device failed to respond",
        _ => "unknown exception",
    }
}

// ── SunSpec decoding ────────────────────────────────────────────────────────

/// Whether the first two registers carry the `SunSpec` `"SunS"` magic.
const fn has_sunspec_magic(regs: &[u16]) -> bool {
    regs.len() >= 2 && regs[0] == SUNSPEC_MAGIC[0] && regs[1] == SUNSPEC_MAGIC[1]
}

/// `SunSpec` common model (model id 1) string fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SunSpecCommon {
    manufacturer: String,
    model: String,
    options: String,
    version: String,
    serial: String,
}

/// Decode a `SunSpec` `String` field: two big-endian bytes per register, NUL
/// terminated, non-printable bytes dropped.
fn register_string(regs: &[u16]) -> String {
    let mut out = String::with_capacity(regs.len() * 2);
    for &reg in regs {
        for byte in reg.to_be_bytes() {
            if byte == 0 {
                return out.trim().to_owned();
            }
            if byte.is_ascii_graphic() || byte == b' ' {
                out.push(char::from(byte));
            }
        }
    }
    out.trim().to_owned()
}

/// Parse the `SunSpec` common model starting at its `ID`/`L` header.
///
/// Layout: `ID`(1) `L`(1) `Mn`(16) `Md`(16) `Opt`(8) `Vr`(8) `SN`(16) — 66
/// registers before the optional `DA`/pad. `ID` must be 1.
fn parse_common_model(regs: &[u16]) -> Option<SunSpecCommon> {
    if regs.len() < 66 || regs[0] != 1 {
        return None;
    }
    Some(SunSpecCommon {
        manufacturer: register_string(&regs[2..18]),
        model: register_string(&regs[18..34]),
        options: register_string(&regs[34..42]),
        version: register_string(&regs[42..50]),
        serial: register_string(&regs[50..66]),
    })
}

// ── Device identification (FC 0x2B / 0x0E) ──────────────────────────────────

/// Object ids defined for the basic and regular device identification streams.
const fn device_id_object_name(id: u8) -> &'static str {
    match id {
        0x00 => "VendorName",
        0x01 => "ProductCode",
        0x02 => "MajorMinorRevision",
        0x03 => "VendorUrl",
        0x04 => "ProductName",
        0x05 => "ModelName",
        0x06 => "UserApplicationName",
        _ => "Object",
    }
}

/// Parse an FC 0x2B/0x0E response body into `(object id, value)` pairs.
///
/// Body: `MEI type` `read code` `conformity` `more follows` `next object id`
/// `object count`, then `id`/`length`/`bytes` triples. A truncated object ends
/// parsing; whatever was decoded before it is kept.
fn parse_device_id(data: &[u8]) -> Vec<(u8, String)> {
    if data.len() < 6 || data[0] != 0x0E {
        return Vec::new();
    }
    let count = usize::from(data[5]);
    let mut objects = Vec::with_capacity(count.min(16));
    let mut pos = 6;
    for _ in 0..count {
        if pos + 2 > data.len() {
            break;
        }
        let id = data[pos];
        let len = usize::from(data[pos + 1]);
        let start = pos + 2;
        let Some(end) = start.checked_add(len).filter(|e| *e <= data.len()) else {
            break;
        };
        let value: String = data[start..end]
            .iter()
            .filter(|b| b.is_ascii_graphic() || **b == b' ')
            .map(|&b| char::from(b))
            .collect();
        let value = value.trim().to_owned();
        if !value.is_empty() {
            objects.push((id, value));
        }
        pos = end;
    }
    objects
}

// ── Equipment classification ────────────────────────────────────────────────

/// Equipment class implied by a `SunSpec` manufacturer or product string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Equipment {
    SolarInverter,
    Battery,
    EvCharger,
    Meter,
    Unknown,
}

impl Equipment {
    /// Noun used in finding text.
    const fn label(self) -> &'static str {
        match self {
            Self::SolarInverter => "solar inverter",
            Self::Battery => "battery storage system",
            Self::EvCharger => "EV charger",
            Self::Meter => "energy meter",
            Self::Unknown => "energy device",
        }
    }
}

/// Lowercase vendor substrings and the class they imply. Vendor names only —
/// a match is a hint, never the basis for a severity.
const VENDOR_CLASSES: &[(&str, Equipment)] = &[
    ("solaredge", Equipment::SolarInverter),
    ("sma", Equipment::SolarInverter),
    ("fronius", Equipment::SolarInverter),
    ("huawei", Equipment::SolarInverter),
    ("growatt", Equipment::SolarInverter),
    ("goodwe", Equipment::SolarInverter),
    ("kostal", Equipment::SolarInverter),
    ("enphase", Equipment::SolarInverter),
    ("sungrow", Equipment::SolarInverter),
    ("solax", Equipment::SolarInverter),
    ("solis", Equipment::SolarInverter),
    ("ginlong", Equipment::SolarInverter),
    ("kaco", Equipment::SolarInverter),
    ("fimer", Equipment::SolarInverter),
    ("my-pv", Equipment::SolarInverter),
    ("victron", Equipment::Battery),
    ("pylontech", Equipment::Battery),
    ("sonnen", Equipment::Battery),
    ("senec", Equipment::Battery),
    ("byd", Equipment::Battery),
    ("wallbox", Equipment::EvCharger),
    ("keba", Equipment::EvCharger),
    ("alfen", Equipment::EvCharger),
    ("easee", Equipment::EvCharger),
    ("evbox", Equipment::EvCharger),
    ("openevse", Equipment::EvCharger),
    ("janitza", Equipment::Meter),
    ("carlo gavazzi", Equipment::Meter),
    ("eastron", Equipment::Meter),
];

/// Classify equipment from the manufacturer string, falling back to the model.
fn classify_equipment(manufacturer: &str, model: &str) -> Equipment {
    let mn = manufacturer.to_ascii_lowercase();
    let md = model.to_ascii_lowercase();
    VENDOR_CLASSES
        .iter()
        .find(|(needle, _)| mn.contains(needle) || md.contains(needle))
        .map_or(Equipment::Unknown, |(_, class)| *class)
}

// ── Probing ─────────────────────────────────────────────────────────────────

/// What one host answered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ModbusProbe {
    /// Unit id that answered.
    unit: u8,
    /// `SunSpec` base address carrying the magic.
    sunspec_base: Option<u16>,
    /// Common model, when it could be read.
    common: Option<SunSpecCommon>,
    /// Device identification objects, when the optional FC is implemented.
    device_id: Vec<(u8, String)>,
    /// Exception seen: `(function, code)`. Proof of a Modbus server.
    exception: Option<(u8, u8)>,
}

/// One request/response exchange. Reads the 6-byte MBAP prefix, then exactly the
/// number of bytes it declares, so a slow peer cannot be mis-parsed as truncated.
async fn transact(stream: &mut TcpStream, frame: &[u8]) -> Option<ModbusReply> {
    tokio::time::timeout(READ_TIMEOUT, stream.write_all(frame))
        .await
        .ok()?
        .ok()?;

    let mut head = [0u8; 6];
    tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut head))
        .await
        .ok()?
        .ok()?;

    let len = usize::from(u16::from_be_bytes([head[4], head[5]]));
    if !(2..=MAX_MBAP_LEN).contains(&len) {
        return Some(ModbusReply::Malformed);
    }
    let mut buf = Vec::with_capacity(MAX_ADU);
    buf.extend_from_slice(&head);
    buf.resize(6 + len, 0);
    tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut buf[6..]))
        .await
        .ok()?
        .ok()?;

    Some(parse_response(&buf))
}

/// Probe one host on one unit id over a single connection.
///
/// At most three FC 0x03 base reads (stopping at the first `SunSpec` magic), then
/// the common model block and one device-identification request. One connection,
/// no retry: several inverters accept only one or two concurrent sessions.
async fn probe_unit(ip: IpAddr, port: u16, unit: u8) -> Option<ModbusProbe> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut probe = ModbusProbe {
        unit,
        ..ModbusProbe::default()
    };
    let mut answered = false;
    let mut tid: u16 = 1;

    for &base in SUNSPEC_BASES {
        let Some(reply) = transact(&mut stream, &build_read_holding(tid, unit, base, 3)).await
        else {
            break;
        };
        tid = tid.wrapping_add(1);
        match reply {
            ModbusReply::Data { data, .. } => {
                answered = true;
                if parse_registers(&data).is_some_and(|regs| has_sunspec_magic(&regs)) {
                    probe.sunspec_base = Some(base);
                    break;
                }
            }
            ModbusReply::Exception { function, code, .. } => {
                answered = true;
                probe.exception = Some((function, code));
            }
            ModbusReply::Malformed => break,
        }
    }

    if let Some(base) = probe.sunspec_base {
        // Common model header sits two registers past the magic.
        let frame = build_read_holding(tid, unit, base.wrapping_add(2), COMMON_MODEL_REGS);
        if let Some(ModbusReply::Data { data, .. }) = transact(&mut stream, &frame).await {
            probe.common = parse_registers(&data)
                .as_deref()
                .and_then(parse_common_model);
        }
        tid = tid.wrapping_add(1);
    }

    if answered {
        // Optional in the specification; most residential gear returns an exception.
        if let Some(ModbusReply::Data { data, .. }) =
            transact(&mut stream, &build_device_id(tid, unit)).await
        {
            probe.device_id = parse_device_id(&data);
        }
    }

    if answered { Some(probe) } else { None }
}

/// Probe a host: unit id 1, then 0xFF if 1 never answered.
async fn probe_modbus(ip: IpAddr, port: u16) -> Option<ModbusProbe> {
    for &unit in UNIT_IDS {
        if let Some(probe) = probe_unit(ip, port, unit).await {
            return Some(probe);
        }
    }
    None
}

// ── Target selection ────────────────────────────────────────────────────────

/// Discovered devices with 502 open, minus configured exclusions.
fn select_targets(devices: &[Device], exclusions: &ExclusionSet) -> Vec<IpAddr> {
    devices
        .iter()
        .filter(|d| d.open_ports.iter().any(|p| p.port == MODBUS_PORT))
        .filter(|d| !exclusions.excludes_ip(d.ip))
        .filter(|d| !d.mac.is_some_and(|m| exclusions.excludes_mac(m)))
        .map(|d| d.ip)
        .collect()
}

// ── Findings ────────────────────────────────────────────────────────────────

/// Guidance shared by both Modbus findings.
fn modbus_remediation() -> Remediation {
    Remediation {
        description: "Modbus/TCP has no authentication, no encryption and no \
                      authorisation: every peer that can reach port 502 is a fully \
                      privileged client. Reachability is the only control, so the \
                      listener must be confined to the hosts that need it."
            .to_owned(),
        steps: vec![
            "Never port-forward 502 or expose it over any VPN-less remote access; \
             confirm the router has no forward or UPnP mapping for it."
                .to_owned(),
            "Put the device on a separate VLAN or IoT network and allow inbound 502 \
             only from the monitoring host (Home Assistant, logger, EMS)."
                .to_owned(),
            "If the vendor offers a read-only or write-disable setting for Modbus/TCP \
             (SMA, SolarEdge and others ship writes off by default), confirm it is on."
                .to_owned(),
            "Prefer the vendor's authenticated API or a Modbus gateway that enforces \
             access control over exposing the register map directly."
                .to_owned(),
        ],
        effort: Some("15-30 minutes".to_owned()),
    }
}

/// References cited by both Modbus findings.
fn modbus_references() -> Vec<String> {
    refs![
        "https://cwe.mitre.org/data/definitions/306.html",
        "https://sunspec.org/sunspec-modbus-specifications/",
        "https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
        "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt",
    ]
}

/// Evidence line: what was read, and from where.
fn probe_evidence(probe: &ModbusProbe) -> String {
    let mut parts = Vec::new();
    if let Some(base) = probe.sunspec_base {
        parts.push(format!(
            "FC 0x03 @ {base} unit {} -> SunS magic",
            probe.unit
        ));
    } else if let Some((function, code)) = probe.exception {
        parts.push(format!(
            "FC 0x{function:02X} unit {} -> exception 0x{code:02X} ({})",
            probe.unit,
            exception_name(code)
        ));
    } else {
        parts.push(format!("FC 0x03 unit {} answered", probe.unit));
    }
    if let Some(common) = &probe.common {
        parts.push(format!(
            "Mn={} Md={} Vr={}",
            common.manufacturer, common.model, common.version
        ));
    }
    for (id, value) in &probe.device_id {
        parts.push(format!("{}={value}", device_id_object_name(*id)));
    }
    parts.join("; ")
}

/// Device hint from whatever identification the probe recovered.
fn probe_hint(probe: &ModbusProbe) -> Option<DeviceHint> {
    let common = probe.common.as_ref();
    let vendor = common
        .map(|c| c.manufacturer.clone())
        .filter(|v| !v.is_empty())
        .or_else(|| device_id_value(probe, 0x00));
    let model = common
        .map(|c| c.model.clone())
        .filter(|v| !v.is_empty())
        .or_else(|| device_id_value(probe, 0x04));
    if vendor.is_none() && model.is_none() {
        return None;
    }
    let mut hint = DeviceHint::new().with_device_type(DeviceType::IoT);
    if let Some(vendor) = vendor {
        hint = hint.with_vendor(vendor);
    }
    if let Some(model) = model {
        hint = hint.with_model(model);
    }
    Some(hint)
}

/// Value of one device-identification object, if present and non-empty.
fn device_id_value(probe: &ModbusProbe, id: u8) -> Option<String> {
    probe
        .device_id
        .iter()
        .find(|(oid, _)| *oid == id)
        .map(|(_, v)| v.clone())
}

/// `SunSpec` confirmed: High, and the equipment class is known.
fn sunspec_finding(ip: IpAddr, port: u16, probe: &ModbusProbe) -> Finding {
    let common = probe.common.clone().unwrap_or_default();
    let equipment = classify_equipment(&common.manufacturer, &common.model);
    let identity = if common.manufacturer.is_empty() && common.model.is_empty() {
        "The common model block did not decode, so the make and model are unknown.".to_owned()
    } else {
        format!(
            "The SunSpec common model identifies it as {} {} (firmware {}).",
            display_or(&common.manufacturer, "an unnamed manufacturer"),
            display_or(&common.model, "an unnamed model"),
            display_or(&common.version, "unknown")
        )
    };

    Finding::new(
        "modbus",
        &format!("Unauthenticated Modbus/TCP SunSpec device on {ip}:{port}"),
        &format!(
            "The host at {ip}:{port} answered an unauthenticated Modbus/TCP read \
             (FC 0x03) and returned the SunSpec `SunS` magic, so it is a SunSpec {} \
             exposing its register map to the whole network. {identity} Modbus/TCP \
             carries no authentication, no encryption and no authorisation: any device \
             that can reach port 502 can read live production, consumption, state of \
             charge and serial numbers. The protocol also accepts write function codes \
             (0x06, 0x10) from any peer — this scan issued reads only and did not test \
             whether this unit honours writes; many vendors ship write access disabled. \
             Restrict who can reach port 502.",
            equipment.label()
        ),
        Severity::High,
    )
    .with_confidence(Confidence::Confirmed)
    .with_ip(ip)
    .with_port(port)
    .with_service("Modbus/TCP")
    .with_cwe("CWE-306")
    .with_evidence(probe_evidence(probe))
    .with_remediation(modbus_remediation())
    .with_references(modbus_references())
}

/// Bare Modbus server, no `SunSpec`: Medium.
fn bare_modbus_finding(ip: IpAddr, port: u16, probe: &ModbusProbe) -> Finding {
    Finding::new(
        "modbus",
        &format!("Unauthenticated Modbus/TCP service on {ip}:{port}"),
        &format!(
            "The host at {ip}:{port} responded to an unauthenticated Modbus/TCP request, \
             so a Modbus server is listening and answering any peer on the network. The \
             SunSpec `SunS` magic was not present at bases 40000, 0 or 50000, so the \
             equipment type could not be identified from the register map. Modbus/TCP \
             carries no authentication, no encryption and no authorisation, and the \
             protocol accepts write function codes (0x06, 0x10) from any peer — this \
             scan issued reads only and did not test whether this unit honours writes. \
             Confirm what the device is and restrict who can reach port 502."
        ),
        Severity::Medium,
    )
    .with_confidence(Confidence::Confirmed)
    .with_ip(ip)
    .with_port(port)
    .with_service("Modbus/TCP")
    .with_cwe("CWE-306")
    .with_evidence(probe_evidence(probe))
    .with_remediation(modbus_remediation())
    .with_references(modbus_references())
}

/// `value` if non-empty, else `fallback`.
const fn display_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

/// Build the finding for one probed host.
fn finding_for_probe(ip: IpAddr, port: u16, probe: &ModbusProbe) -> Finding {
    let mut finding = if probe.sunspec_base.is_some() {
        sunspec_finding(ip, port, probe)
    } else {
        bare_modbus_finding(ip, port, probe)
    };
    if let Some(hint) = probe_hint(probe) {
        finding = finding.with_device_hint(hint);
    }
    finding
}

#[async_trait]
impl Scanner for ModbusScanner {
    fn id(&self) -> &'static str {
        "modbus"
    }

    fn name(&self) -> &'static str {
        "Modbus/TCP SunSpec Discovery"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running Modbus/TCP SunSpec scan");
        let mut findings = Vec::new();

        // Application-layer probes: Active and above only.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping Modbus scan in quick scan mode");
            return Ok(findings);
        }

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "modbus".to_owned(),
                message: e.to_string(),
            })?;

        let targets = select_targets(&ctx.discovered_devices, &exclusions);
        if targets.is_empty() {
            tracing::info!("no Modbus targets found");
            return Ok(findings);
        }

        tracing::info!(target_count = targets.len(), "probing Modbus/TCP servers");

        for ip in targets {
            if let Some(probe) = probe_modbus(ip, MODBUS_PORT).await {
                tracing::debug!(ip = %ip, unit = probe.unit, sunspec = ?probe.sunspec_base, "Modbus server answered");
                findings.push(finding_for_probe(ip, MODBUS_PORT, &probe));
            }
        }

        tracing::info!(
            findings_count = findings.len(),
            "Modbus/TCP SunSpec scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        15
    }

    fn relevant_ports(&self) -> &[u16] {
        MODBUS_PORTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_models::device::{OpenPort, PortProtocol};

    fn open_port(port: u16) -> OpenPort {
        OpenPort {
            port,
            protocol: PortProtocol::Tcp,
            service: None,
            version: None,
            banner: None,
        }
    }

    /// Build a valid response frame around a PDU.
    fn frame(tid: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
        mbap_frame(tid, unit, pdu)
    }

    // ── Request builders ────────────────────────────────────────────

    #[test]
    fn read_holding_frame_matches_wire_format() {
        // tid 1, unit 1, FC 0x03, address 40000 (0x9C40), quantity 3.
        assert_eq!(
            build_read_holding(1, 1, 40000, 3),
            vec![
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x9C, 0x40, 0x00, 0x03
            ]
        );
    }

    #[test]
    fn read_holding_frame_base_zero_and_unit_255() {
        assert_eq!(
            build_read_holding(7, 0xFF, 0, 3),
            vec![
                0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0xFF, 0x03, 0x00, 0x00, 0x00, 0x03
            ]
        );
    }

    #[test]
    fn device_id_frame_declares_length_five() {
        // The documented frame: length is 5, not 6.
        assert_eq!(
            build_device_id(1, 1),
            vec![
                0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2B, 0x0E, 0x01, 0x00
            ]
        );
    }

    #[test]
    fn builders_never_emit_a_write_function_code() {
        // 0x05/0x06/0x0F/0x10/0x16/0x17/0x2B-with-write are the mutating codes;
        // only 0x03 and 0x2B (read device id) may ever appear at PDU offset 0.
        for frame in [build_read_holding(1, 1, 40000, 3), build_device_id(1, 1)] {
            assert!(
                matches!(frame[7], 0x03 | 0x2B),
                "function code {}",
                frame[7]
            );
        }
    }

    // ── Response parsing ────────────────────────────────────────────

    #[test]
    fn parses_read_holding_data_response() {
        // FC 0x03, byte count 6, three registers.
        let buf = frame(1, 1, &[0x03, 0x06, 0x53, 0x75, 0x6E, 0x53, 0x00, 0x01]);
        let reply = parse_response(&buf);
        assert_eq!(
            reply,
            ModbusReply::Data {
                tid: 1,
                unit: 1,
                function: 0x03,
                data: vec![0x06, 0x53, 0x75, 0x6E, 0x53, 0x00, 0x01],
            }
        );
    }

    #[test]
    fn parses_exception_response() {
        // FC 0x03 | 0x80, exception 0x02 (illegal data address).
        let buf = frame(9, 1, &[0x83, 0x02]);
        assert_eq!(
            parse_response(&buf),
            ModbusReply::Exception {
                tid: 9,
                unit: 1,
                function: 0x03,
                code: 0x02,
            }
        );
    }

    #[test]
    fn rejects_non_zero_protocol_id() {
        let mut buf = frame(1, 1, &[0x03, 0x02, 0x00, 0x01]);
        buf[3] = 0x01;
        assert_eq!(parse_response(&buf), ModbusReply::Malformed);
    }

    #[test]
    fn rejects_truncated_and_oversized_length() {
        let mut buf = frame(1, 1, &[0x03, 0x02, 0x00, 0x01]);
        // Declared length longer than the buffer carries.
        buf[5] = 0x20;
        assert_eq!(parse_response(&buf), ModbusReply::Malformed);
        // Length above the 254-byte maximum.
        buf[4] = 0x01;
        buf[5] = 0x00;
        assert_eq!(parse_response(&buf), ModbusReply::Malformed);
    }

    #[test]
    fn rejects_short_frames() {
        assert_eq!(parse_response(&[]), ModbusReply::Malformed);
        assert_eq!(
            parse_response(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01]),
            ModbusReply::Malformed
        );
    }

    #[test]
    fn rejects_exception_without_a_code() {
        // Length 2 covers unit + function but no exception code byte.
        let buf = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x83];
        assert_eq!(parse_response(&buf), ModbusReply::Malformed);
    }

    // ── Register decoding ───────────────────────────────────────────

    #[test]
    fn parses_register_payload() {
        assert_eq!(
            parse_registers(&[0x04, 0x53, 0x75, 0x6E, 0x53]),
            Some(vec![0x5375, 0x6E53])
        );
    }

    #[test]
    fn rejects_bad_register_payloads() {
        assert_eq!(parse_registers(&[]), None);
        assert_eq!(parse_registers(&[0x00]), None, "zero byte count");
        assert_eq!(
            parse_registers(&[0x03, 0x01, 0x02, 0x03]),
            None,
            "odd count"
        );
        assert_eq!(parse_registers(&[0x08, 0x01, 0x02]), None, "short buffer");
    }

    #[test]
    fn extra_trailing_bytes_are_ignored() {
        assert_eq!(
            parse_registers(&[0x02, 0x00, 0x01, 0xFF, 0xFF]),
            Some(vec![0x0001])
        );
    }

    // ── SunSpec ─────────────────────────────────────────────────────

    #[test]
    fn detects_sunspec_magic() {
        assert!(has_sunspec_magic(&[0x5375, 0x6E53, 0x0001]));
        assert!(!has_sunspec_magic(&[0x5375]));
        assert!(!has_sunspec_magic(&[0x0000, 0x0000]));
        assert!(!has_sunspec_magic(&[0x6E53, 0x5375]), "byte order matters");
    }

    /// Pack an ASCII string into `regs` registers, NUL padded.
    fn pack(text: &str, regs: usize) -> Vec<u16> {
        let mut bytes = text.as_bytes().to_vec();
        bytes.resize(regs * 2, 0);
        let (pairs, _) = bytes.as_chunks::<2>();
        pairs.iter().map(|&w| u16::from_be_bytes(w)).collect()
    }

    fn common_block(mn: &str, md: &str, opt: &str, vr: &str, sn: &str) -> Vec<u16> {
        let mut regs = vec![1u16, 66];
        regs.extend(pack(mn, 16));
        regs.extend(pack(md, 16));
        regs.extend(pack(opt, 8));
        regs.extend(pack(vr, 8));
        regs.extend(pack(sn, 16));
        regs.push(0); // DA
        regs.push(0); // pad
        regs
    }

    #[test]
    fn parses_common_model_block() {
        let regs = common_block("SolarEdge", "SE7600A-US", "", "0004.0016.0031", "7E1234AB");
        let common = parse_common_model(&regs).expect("common model parses");
        assert_eq!(common.manufacturer, "SolarEdge");
        assert_eq!(common.model, "SE7600A-US");
        assert_eq!(common.version, "0004.0016.0031");
        assert_eq!(common.serial, "7E1234AB");
        assert_eq!(common.options, "");
    }

    #[test]
    fn rejects_common_model_with_wrong_id_or_length() {
        let mut regs = common_block("SMA", "STP 10.0", "", "3.10.19.R", "3005123456");
        assert!(parse_common_model(&regs).is_some());
        regs[0] = 103; // an inverter model, not the common block
        assert_eq!(parse_common_model(&regs), None);
        assert_eq!(parse_common_model(&[1, 66]), None, "too short");
    }

    #[test]
    fn register_string_stops_at_nul_and_drops_controls() {
        assert_eq!(register_string(&[0x4162, 0x0043]), "Ab");
        assert_eq!(register_string(&[0x4100, 0x4242]), "A");
        assert_eq!(register_string(&[0x2020, 0x4120]), "A", "trimmed");
        assert_eq!(register_string(&[]), "");
    }

    // ── Device identification ───────────────────────────────────────

    #[test]
    fn parses_device_id_objects() {
        // MEI 0x0E, read code 1, conformity 0x01, more 0x00, next 0x00, 3 objects.
        let mut body = vec![0x0E, 0x01, 0x01, 0x00, 0x00, 0x03];
        for (id, value) in [(0x00u8, "Wago"), (0x01, "750-352"), (0x02, "1.2.3")] {
            body.push(id);
            body.push(u8::try_from(value.len()).unwrap());
            body.extend_from_slice(value.as_bytes());
        }
        assert_eq!(
            parse_device_id(&body),
            vec![
                (0x00, "Wago".to_owned()),
                (0x01, "750-352".to_owned()),
                (0x02, "1.2.3".to_owned()),
            ]
        );
    }

    #[test]
    fn device_id_truncated_object_keeps_earlier_ones() {
        let mut body = vec![0x0E, 0x01, 0x01, 0x00, 0x00, 0x02];
        body.extend_from_slice(&[0x00, 0x03, b'S', b'M', b'A']);
        body.extend_from_slice(&[0x01, 0x10, b'S', b'T']); // claims 16 bytes, has 2
        assert_eq!(parse_device_id(&body), vec![(0x00, "SMA".to_owned())]);
    }

    #[test]
    fn device_id_rejects_wrong_mei_type() {
        assert!(parse_device_id(&[0x0D, 0x01, 0x01, 0x00, 0x00, 0x01]).is_empty());
        assert!(parse_device_id(&[0x0E, 0x01]).is_empty());
    }

    #[test]
    fn device_id_object_names_cover_the_basic_stream() {
        assert_eq!(device_id_object_name(0x00), "VendorName");
        assert_eq!(device_id_object_name(0x02), "MajorMinorRevision");
        assert_eq!(device_id_object_name(0x7F), "Object");
    }

    // ── Classification ──────────────────────────────────────────────

    #[test]
    fn classifies_equipment_by_vendor() {
        assert_eq!(
            classify_equipment("SolarEdge", "SE7600A-US"),
            Equipment::SolarInverter
        );
        assert_eq!(
            classify_equipment("Wallbox Chargers", "Pulsar Plus"),
            Equipment::EvCharger
        );
        assert_eq!(
            classify_equipment("Victron Energy", "MultiPlus-II"),
            Equipment::Battery
        );
        assert_eq!(classify_equipment("", "Janitza UMG 604"), Equipment::Meter);
        assert_eq!(classify_equipment("Acme Widgets", ""), Equipment::Unknown);
    }

    #[test]
    fn equipment_labels_are_stable() {
        assert_eq!(Equipment::SolarInverter.label(), "solar inverter");
        assert_eq!(Equipment::Unknown.label(), "energy device");
    }

    #[test]
    fn exception_names_cover_the_spec_codes() {
        assert_eq!(exception_name(0x01), "illegal function");
        assert_eq!(
            exception_name(0x0B),
            "gateway target device failed to respond"
        );
        assert_eq!(exception_name(0x42), "unknown exception");
    }

    // ── Target selection ────────────────────────────────────────────

    #[test]
    fn selects_only_hosts_with_502_open() {
        let mut with = Device::new("192.168.1.10".parse().unwrap());
        with.open_ports = vec![open_port(80), open_port(502)];
        let mut without = Device::new("192.168.1.11".parse().unwrap());
        without.open_ports = vec![open_port(80)];
        let devices = vec![with, without];
        let exclusions = ExclusionSet::parse(&[], &[]).unwrap();
        assert_eq!(
            select_targets(&devices, &exclusions),
            vec!["192.168.1.10".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn honours_ip_cidr_and_mac_exclusions() {
        let mut by_ip = Device::new("192.168.1.10".parse().unwrap());
        by_ip.open_ports = vec![open_port(502)];
        let mut by_cidr = Device::new("192.168.9.10".parse().unwrap());
        by_cidr.open_ports = vec![open_port(502)];
        let mut by_mac = Device::new("192.168.1.12".parse().unwrap()).with_mac("aa:bb:cc:dd:ee:ff");
        by_mac.open_ports = vec![open_port(502)];
        let mut kept = Device::new("192.168.1.13".parse().unwrap());
        kept.open_ports = vec![open_port(502)];

        let exclusions = ExclusionSet::parse(
            &["192.168.9.0/24".to_owned()],
            &["192.168.1.10".to_owned(), "aa:bb:cc:dd:ee:ff".to_owned()],
        )
        .unwrap();
        assert_eq!(
            select_targets(&[by_ip, by_cidr, by_mac, kept], &exclusions),
            vec!["192.168.1.13".parse::<IpAddr>().unwrap()]
        );
    }

    // ── Findings ────────────────────────────────────────────────────

    fn sunspec_probe() -> ModbusProbe {
        ModbusProbe {
            unit: 1,
            sunspec_base: Some(40000),
            common: Some(SunSpecCommon {
                manufacturer: "SolarEdge".to_owned(),
                model: "SE7600A-US".to_owned(),
                options: String::new(),
                version: "0004.0016.0031".to_owned(),
                serial: "7E1234AB".to_owned(),
            }),
            device_id: Vec::new(),
            exception: None,
        }
    }

    #[test]
    fn sunspec_finding_is_high_and_confirmed() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let finding = finding_for_probe(ip, 502, &sunspec_probe());
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.affected_port, Some(502));
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-306"));
        assert!(finding.title.contains("SunSpec"));
        assert!(finding.description.contains("solar inverter"));
        let hint = finding.device_hint.expect("hint from the common model");
        assert_eq!(hint.vendor.as_deref(), Some("SolarEdge"));
        assert_eq!(hint.model.as_deref(), Some("SE7600A-US"));
    }

    #[test]
    fn sunspec_finding_never_claims_registers_are_writable() {
        let finding = finding_for_probe("192.168.1.10".parse().unwrap(), 502, &sunspec_probe());
        assert!(
            finding
                .description
                .contains("did not test whether this unit honours writes")
        );
    }

    #[test]
    fn bare_modbus_finding_is_medium() {
        let probe = ModbusProbe {
            unit: 0xFF,
            sunspec_base: None,
            common: None,
            device_id: vec![(0x00, "Wago".to_owned())],
            exception: Some((0x03, 0x02)),
        };
        let finding = finding_for_probe("192.168.1.20".parse().unwrap(), 502, &probe);
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert!(finding.title.contains("Unauthenticated Modbus/TCP service"));
        let evidence = finding.evidence.expect("exception evidence");
        assert!(evidence.contains("illegal data address"), "{evidence}");
        assert!(evidence.contains("VendorName=Wago"), "{evidence}");
        assert_eq!(
            finding.device_hint.and_then(|h| h.vendor).as_deref(),
            Some("Wago")
        );
    }

    #[test]
    fn titles_are_stable_across_probe_detail() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let mut bare = sunspec_probe();
        bare.common = None;
        assert_eq!(
            finding_for_probe(ip, 502, &sunspec_probe()).title,
            finding_for_probe(ip, 502, &bare).title
        );
        assert_eq!(
            finding_for_probe(ip, 502, &sunspec_probe()).fingerprint(),
            finding_for_probe(ip, 502, &bare).fingerprint()
        );
    }

    #[test]
    fn probe_without_identification_yields_no_hint() {
        let probe = ModbusProbe {
            unit: 1,
            sunspec_base: Some(0),
            common: None,
            device_id: Vec::new(),
            exception: None,
        };
        assert!(probe_hint(&probe).is_none());
    }

    #[test]
    fn scanner_metadata() {
        let scanner = ModbusScanner;
        assert_eq!(scanner.id(), "modbus");
        assert_eq!(scanner.relevant_ports(), &[502]);
        assert!(
            scanner
                .supported_perspectives()
                .contains(&Perspective::Unauthenticated)
        );
    }

    // ── Loopback probe tests ────────────────────────────────────────

    /// Serve one client, answering each request with `respond`'s PDU.
    async fn spawn_server(respond: fn(&[u8]) -> Vec<u8>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            loop {
                let mut head = [0u8; 6];
                if socket.read_exact(&mut head).await.is_err() {
                    return;
                }
                let len = usize::from(u16::from_be_bytes([head[4], head[5]]));
                let mut body = vec![0u8; len];
                if socket.read_exact(&mut body).await.is_err() {
                    return;
                }
                let pdu = respond(&body[1..]);
                let tid = u16::from_be_bytes([head[0], head[1]]);
                if socket
                    .write_all(&mbap_frame(tid, body[0], &pdu))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        addr
    }

    /// FC 0x03 response PDU carrying `regs`.
    fn read_response(regs: &[u16]) -> Vec<u8> {
        let mut pdu = vec![0x03, u8::try_from(regs.len() * 2).unwrap()];
        for reg in regs {
            pdu.extend_from_slice(&reg.to_be_bytes());
        }
        pdu
    }

    /// Inverter with `SunSpec` at 40000 and no device-identification support.
    fn sunspec_at_40000(pdu: &[u8]) -> Vec<u8> {
        if pdu.len() == 5 && pdu[0] == 0x03 {
            let addr = u16::from_be_bytes([pdu[1], pdu[2]]);
            return match addr {
                40000 => read_response(&[SUNSPEC_MAGIC[0], SUNSPEC_MAGIC[1], 1]),
                40002 => read_response(&common_block(
                    "SolarEdge",
                    "SE7600A-US",
                    "",
                    "0004.0016.0031",
                    "7E1234AB",
                )),
                _ => vec![0x83, 0x02],
            };
        }
        vec![pdu[0] | 0x80, 0x01]
    }

    /// Inverter whose `SunSpec` block sits at base 0, with device identification.
    fn sunspec_at_zero(pdu: &[u8]) -> Vec<u8> {
        if pdu.len() == 5 && pdu[0] == 0x03 {
            let addr = u16::from_be_bytes([pdu[1], pdu[2]]);
            return match addr {
                0 => read_response(&[SUNSPEC_MAGIC[0], SUNSPEC_MAGIC[1], 1]),
                2 => read_response(&common_block("SMA", "STP 10.0", "", "3.10.19.R", "3005")),
                _ => vec![0x83, 0x02],
            };
        }
        if pdu.first() == Some(&0x2B) {
            let mut body = vec![0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01];
            body.extend_from_slice(&[0x00, 0x03, b'S', b'M', b'A']);
            return body;
        }
        vec![pdu[0] | 0x80, 0x01]
    }

    /// Modbus server that rejects every address: proof of a server, no `SunSpec`.
    fn always_exception(pdu: &[u8]) -> Vec<u8> {
        vec![pdu[0] | 0x80, 0x02]
    }

    #[tokio::test]
    async fn probe_reads_sunspec_common_model_over_a_socket() {
        let addr = spawn_server(sunspec_at_40000).await;
        let probe = probe_unit(addr.ip(), addr.port(), 1)
            .await
            .expect("inverter answers");
        assert_eq!(probe.sunspec_base, Some(40000));
        let common = probe.common.clone().expect("common model read");
        assert_eq!(common.manufacturer, "SolarEdge");
        assert_eq!(common.model, "SE7600A-US");
        assert_eq!(common.version, "0004.0016.0031");
        assert!(probe.device_id.is_empty(), "device id not implemented");

        let finding = finding_for_probe(addr.ip(), 502, &probe);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Confirmed);
    }

    #[tokio::test]
    async fn probe_falls_through_to_base_zero_and_reads_device_id() {
        let addr = spawn_server(sunspec_at_zero).await;
        let probe = probe_unit(addr.ip(), addr.port(), 1)
            .await
            .expect("inverter answers");
        assert_eq!(probe.sunspec_base, Some(0));
        assert_eq!(probe.common.map(|c| c.manufacturer), Some("SMA".to_owned()));
        assert_eq!(probe.device_id, vec![(0x00, "SMA".to_owned())]);
    }

    #[tokio::test]
    async fn exception_response_identifies_a_bare_modbus_server() {
        let addr = spawn_server(always_exception).await;
        let probe = probe_unit(addr.ip(), addr.port(), 1)
            .await
            .expect("exceptions still identify a server");
        assert_eq!(probe.sunspec_base, None);
        assert_eq!(probe.exception, Some((0x03, 0x02)));

        let finding = finding_for_probe(addr.ip(), 502, &probe);
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[tokio::test]
    async fn non_modbus_listener_yields_nothing() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            }
        });
        assert_eq!(probe_unit(addr.ip(), addr.port(), 1).await, None);
    }

    #[tokio::test]
    async fn closed_port_yields_nothing() {
        // Bind, record the port, drop the listener: nothing is listening there.
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert_eq!(probe_modbus(addr.ip(), addr.port()).await, None);
    }

    // ── Proptests ───────────────────────────────────────────────────

    proptest! {
        /// The frame parser never panics on arbitrary bytes.
        #[test]
        fn prop_parse_response_no_panic(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = parse_response(&data);
        }

        /// The register decoder never panics and never over-reads.
        #[test]
        fn prop_parse_registers_no_panic(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            if let Some(regs) = parse_registers(&data) {
                prop_assert!(regs.len() * 2 < data.len());
            }
        }

        /// The device-identification decoder never panics.
        #[test]
        fn prop_parse_device_id_no_panic(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = parse_device_id(&data);
        }

        /// The `SunSpec` string decoder never panics and emits printable ASCII only.
        #[test]
        fn prop_register_string_printable(regs in proptest::collection::vec(any::<u16>(), 0..64)) {
            let s = register_string(&regs);
            prop_assert!(s.bytes().all(|b| b.is_ascii_graphic() || b == b' '));
        }

        /// The common-model parser never panics on arbitrary register blocks.
        #[test]
        fn prop_parse_common_model_no_panic(regs in proptest::collection::vec(any::<u16>(), 0..200)) {
            let _ = parse_common_model(&regs);
        }

        /// Every built frame is a well-formed MBAP whose length field matches,
        /// and whose function code is one of the two read codes.
        #[test]
        fn prop_built_frames_are_read_only(tid in any::<u16>(), unit in any::<u8>(), addr in any::<u16>(), qty in 1u16..=125) {
            for frame in [build_read_holding(tid, unit, addr, qty), build_device_id(tid, unit)] {
                prop_assert_eq!(&frame[2..4], &[0x00, 0x00]);
                let len = usize::from(u16::from_be_bytes([frame[4], frame[5]]));
                prop_assert_eq!(frame.len(), 6 + len);
                prop_assert!(matches!(frame[7], 0x03 | 0x2B));
            }
        }

        /// A data frame round-trips through the builder-shaped encoder and parser.
        #[test]
        fn prop_data_frame_roundtrip(
            tid in any::<u16>(),
            unit in any::<u8>(),
            body in proptest::collection::vec(any::<u8>(), 0..120),
        ) {
            let mut pdu = vec![0x03];
            pdu.extend_from_slice(&body);
            let buf = mbap_frame(tid, unit, &pdu);
            prop_assert_eq!(
                parse_response(&buf),
                ModbusReply::Data { tid, unit, function: 0x03, data: body }
            );
        }
    }
}

/// Parser entry points for the fuzz harness.
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    pub fn response(data: &[u8]) {
        let _ = super::parse_response(data);
    }
    #[must_use]
    pub fn registers(data: &[u8]) -> bool {
        super::parse_registers(data).is_some()
    }
    #[must_use]
    pub fn device_id(data: &[u8]) -> usize {
        super::parse_device_id(data).len()
    }
    #[must_use]
    pub fn common_model(regs: &[u16]) -> bool {
        super::parse_common_model(regs).is_some()
    }
}
