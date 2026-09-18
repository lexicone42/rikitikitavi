//! Hikvision SADP (Search Active Device Protocol) discovery, UDP/37020.
//!
//! Sends one well-formed `<Types>inquiry</Types>` datagram — the same request
//! the vendor's own SADP tool sends — to the SADP multicast group and to each
//! discovered host, then parses the `ProbeMatch` XML reply. Read-only: no
//! activation, password-reset or configuration request is ever sent (those are
//! separate SADP verbs and are deliberately not implemented here).
//!
//! The reply carries model, firmware build date, serial, MAC and activation
//! state in clear, which yields both device identification and a firmware
//! version floor for CVE-2025-66177 (AV:A, 2025) and CVE-2017-7921 (KEV).
//!
//! The XML-over-UDP flavour is used, not the raw-Ethernet one, which would need
//! `CAP_NET_RAW`.

use async_trait::async_trait;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::config::ExclusionSet;
use rikitikitavi_models::finding::Remediation;
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, MacAddr, ScanContext};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::Scanner;

/// Hikvision SADP discovery scanner.
pub struct SadpScanner;

/// SADP port (both the multicast group port and the per-device listener).
const SADP_PORT: u16 = 37020;

/// SADP multicast group.
const SADP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

/// Window for collecting replies after the inquiries are sent.
const COLLECT_WINDOW: Duration = Duration::from_secs(4);

/// Cap on replies processed per scan.
const MAX_REPLIES: usize = 256;

/// Receive buffer; real `ProbeMatch` replies are ~1 KiB.
const RECV_BUF: usize = 8192;

/// Firmware build floor from the 2025 Hikvision advisory family behind
/// CVE-2025-66177: builds before `250807` (YYMMDD) are affected.
const BUILD_FLOOR: u32 = 250_807;

/// Last affected build for CVE-2017-7921 (fixed in V5.4.5 build 170123).
const CVE_2017_7921_LAST_BUILD: u32 = 170_109;

// ── Probe construction ──────────────────────────────────────────────────────

/// Pseudo-UUID for the `Probe` element, rendered from the wall clock in the
/// canonical 8-4-4-4-12 form. SADP does not validate it; it only echoes it back.
fn probe_uuid() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let hex = format!("{nanos:032X}");
    format!(
        "{{{}-{}-{}-{}-{}}}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Build the SADP inquiry datagram. `inquiry` is the read-only discovery verb.
fn build_inquiry(uuid: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <Probe><Uuid>{uuid}</Uuid><Types>inquiry</Types></Probe>"
    )
}

// ── Reply parsing ───────────────────────────────────────────────────────────

/// Fields of interest from a SADP `ProbeMatch` reply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SadpDevice {
    /// `DeviceType` — in SADP this is the model string, e.g. `DS-2CD2032-I`.
    model: Option<String>,
    /// `DeviceDescription`, e.g. `IPCamera`, `NVR`, `Access Controller`.
    description: Option<String>,
    /// `SoftwareVersion` verbatim, e.g. `V5.3.0build 150513`.
    software_version: Option<String>,
    /// Parsed `(major, minor)` and build date from `software_version`.
    version: Option<FirmwareVersion>,
    /// `IPv4Address` as reported by the device itself.
    ipv4: Option<Ipv4Addr>,
    /// `MAC`, normalised to lowercase colon form.
    mac: Option<String>,
    /// `DeviceSN` (serial number).
    serial: Option<String>,
    /// `HttpPort`.
    http_port: Option<u16>,
    /// `Activated` — `false` means no admin password has been set yet.
    activated: Option<bool>,
}

/// Parsed Hikvision firmware version string.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct FirmwareVersion {
    major: u16,
    minor: u16,
    /// `build NNNNNN` as a YYMMDD integer, when present and plausible.
    build: Option<u32>,
}

/// Decode the five predefined XML entities. SADP payloads are plain ASCII, but
/// `DeviceDescription` can contain `&amp;`.
fn decode_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Text content of the first `<tag>...</tag>`, trimmed and entity-decoded.
/// Returns `None` when absent or empty.
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let rest = xml.get(start..)?;
    let end = rest.find(&close)?;
    let content = rest.get(..end)?.trim();
    if content.is_empty() {
        None
    } else {
        Some(decode_entities(content))
    }
}

/// Parse a SADP boolean (`true`/`false`, some firmware uses `1`/`0`).
fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

/// `true` when `yymmdd` decodes to a plausible calendar date.
const fn plausible_build_date(yymmdd: u32) -> bool {
    let month = (yymmdd / 100) % 100;
    let day = yymmdd % 100;
    month >= 1 && month <= 12 && day >= 1 && day <= 31
}

/// Parse `SoftwareVersion` strings such as `V5.3.0build 150513`,
/// `V5.4.5 build 170123` or `V4.0.2`.
///
/// The build token is a YYMMDD date; anything that is not exactly six digits
/// decoding to a plausible date is treated as absent rather than guessed at.
fn parse_firmware_version(raw: &str) -> Option<FirmwareVersion> {
    let lower = raw.trim().to_ascii_lowercase();
    let numeric = lower.strip_prefix('v').unwrap_or(&lower);

    // major.minor — stop at the first non-digit in each position.
    let major_digits: String = numeric.chars().take_while(char::is_ascii_digit).collect();
    let major: u16 = major_digits.parse().ok()?;
    let after_major = numeric.get(major_digits.len()..)?.strip_prefix('.')?;
    let minor_digits: String = after_major
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    let minor: u16 = minor_digits.parse().ok()?;

    // "build" may be glued to the patch number or separated by whitespace.
    let build = lower.find("build").and_then(|idx| {
        let after = lower.get(idx + "build".len()..)?.trim_start();
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        if digits.len() != 6 {
            return None;
        }
        let value: u32 = digits.parse().ok()?;
        plausible_build_date(value).then_some(value)
    });

    Some(FirmwareVersion {
        major,
        minor,
        build,
    })
}

/// Parse a `ProbeMatch` reply. Returns `None` unless at least one identifying
/// field is present, which also rejects our own looped-back `Probe` datagram.
fn parse_probe_match(xml: &str) -> Option<SadpDevice> {
    let software_version = extract_tag(xml, "SoftwareVersion");
    let device = SadpDevice {
        model: extract_tag(xml, "DeviceType"),
        description: extract_tag(xml, "DeviceDescription"),
        version: software_version.as_deref().and_then(parse_firmware_version),
        software_version,
        ipv4: extract_tag(xml, "IPv4Address").and_then(|v| v.parse().ok()),
        mac: extract_tag(xml, "MAC")
            .and_then(|v| v.parse::<MacAddr>().ok())
            .map(|m| m.to_string()),
        serial: extract_tag(xml, "DeviceSN"),
        http_port: extract_tag(xml, "HttpPort").and_then(|v| v.parse().ok()),
        activated: extract_tag(xml, "Activated").and_then(|v| parse_bool(&v)),
    };

    let identifying = device.model.is_some()
        || device.software_version.is_some()
        || device.serial.is_some()
        || device.mac.is_some();
    identifying.then_some(device)
}

// ── Classification ──────────────────────────────────────────────────────────

/// Vendor label, set only when the model string carries a Hikvision prefix.
/// OEM rebrands (`Annke`, `LaView`, and others) answer SADP with their own model
/// strings, so an unrecognised prefix leaves the vendor unset rather than
/// mislabelling the device.
fn vendor_for(model: Option<&str>) -> Option<&'static str> {
    let model = model?.to_ascii_lowercase();
    (model.starts_with("ds-") || model.starts_with("ids-") || model.starts_with("hwi-"))
        .then_some("Hikvision")
}

/// Map `DeviceDescription` / model prefix to a device type. Video devices
/// dominate SADP; access-control and alarm panels are the known exceptions.
fn classify_device(description: Option<&str>, model: Option<&str>) -> DeviceType {
    let descr = description.unwrap_or_default().to_ascii_lowercase();
    if descr.contains("access") || descr.contains("door") || descr.contains("intercom") {
        return DeviceType::IoT;
    }
    if descr.contains("alarm") || descr.contains("panel") {
        return DeviceType::IoT;
    }
    let model = model.unwrap_or_default().to_ascii_lowercase();
    if model.starts_with("ds-k") {
        return DeviceType::IoT;
    }
    if model.starts_with("ds-pw") || model.starts_with("ds-pm") || model.starts_with("ds-pd") {
        return DeviceType::IoT;
    }
    // Cameras, domes, NVRs, DVRs and CVRs all land here; `DeviceType` has no
    // recorder variant.
    DeviceType::Camera
}

/// Firmware verdict from the parsed build date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildVerdict {
    /// Build at or before the last CVE-2017-7921 build, in the affected 5.2-5.4
    /// range — unauthenticated configuration download (CISA KEV).
    KevAuthBypass,
    /// Build before the 2025 advisory floor.
    BelowFloor,
    /// Build at or after the floor.
    Current,
    /// No usable build date in `SoftwareVersion`.
    Unknown,
}

/// Classify a parsed firmware version against the two known floors.
const fn classify_build(version: Option<FirmwareVersion>) -> BuildVerdict {
    let Some(v) = version else {
        return BuildVerdict::Unknown;
    };
    let Some(build) = v.build else {
        return BuildVerdict::Unknown;
    };
    if build <= CVE_2017_7921_LAST_BUILD && v.major == 5 && v.minor >= 2 && v.minor <= 4 {
        return BuildVerdict::KevAuthBypass;
    }
    if build < BUILD_FLOOR {
        return BuildVerdict::BelowFloor;
    }
    BuildVerdict::Current
}

/// CVEs to attach for a verdict.
fn cves_for(verdict: BuildVerdict) -> Vec<String> {
    match verdict {
        BuildVerdict::KevAuthBypass => {
            vec!["CVE-2017-7921".to_owned(), "CVE-2025-66177".to_owned()]
        }
        BuildVerdict::BelowFloor => vec!["CVE-2025-66177".to_owned()],
        BuildVerdict::Current | BuildVerdict::Unknown => Vec::new(),
    }
}

/// Short `model / firmware / serial` summary for evidence strings.
fn evidence_summary(device: &SadpDevice) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(model) = &device.model {
        parts.push(format!("DeviceType={model}"));
    }
    if let Some(version) = &device.software_version {
        parts.push(format!("SoftwareVersion={version}"));
    }
    if let Some(mac) = &device.mac {
        parts.push(format!("MAC={mac}"));
    }
    if let Some(ipv4) = device.ipv4 {
        parts.push(format!("IPv4Address={ipv4}"));
    }
    if let Some(activated) = device.activated {
        parts.push(format!("Activated={activated}"));
    }
    parts.join(" ")
}

/// Device hint (vendor, model, type) derived from the reply.
fn hint_for(device: &SadpDevice) -> DeviceHint {
    let mut hint = DeviceHint::new().with_device_type(classify_device(
        device.description.as_deref(),
        device.model.as_deref(),
    ));
    if let Some(vendor) = vendor_for(device.model.as_deref()) {
        hint = hint.with_vendor(vendor);
    }
    if let Some(model) = &device.model {
        hint = hint.with_model(model.clone());
    }
    if let Some(version) = &device.software_version {
        hint = hint.with_os_guess(format!("Hikvision firmware {version}"));
    }
    hint
}

/// Attach the fields every SADP finding shares.
fn base_finding(ip: IpAddr, device: &SadpDevice, finding: Finding) -> Finding {
    let finding = finding
        .with_ip(ip)
        .with_port(SADP_PORT)
        .with_service("SADP")
        .with_evidence(evidence_summary(device))
        .with_device_hint(hint_for(device));
    match &device.mac {
        Some(mac) => finding.with_mac(mac.as_str()),
        None => finding,
    }
}

// ── Findings ────────────────────────────────────────────────────────────────

/// Presence finding: the device answered SADP, leaking its inventory record.
fn presence_finding(ip: IpAddr, device: &SadpDevice) -> Finding {
    let model = device.model.as_deref().unwrap_or("unknown model");
    let version = device.software_version.as_deref().unwrap_or("unreported");
    let serial_note = if device.serial.is_some() {
        " The reply includes the device serial number, which vendor password-reset \
         workflows have historically accepted as proof of ownership."
    } else {
        ""
    };

    base_finding(
        ip,
        device,
        Finding::new(
            "sadp",
            &format!("Hikvision SADP discovery service answers on {ip}:{SADP_PORT}"),
            &format!(
                "The host at {ip} answered an unauthenticated SADP inquiry on UDP/{SADP_PORT} \
                 with a ProbeMatch record (model {model}, firmware {version}). SADP is \
                 Hikvision's device-discovery protocol; the reply carries model, firmware \
                 build, serial number, MAC, IP configuration and management ports to any \
                 host on the LAN, with no authentication.{serial_note} SADP is also the \
                 vector for the 2025 adjacent-network advisories against Hikvision \
                 NVR/DVR/CVR and IP camera firmware.",
            ),
            Severity::Info,
        )
        .with_confidence(Confidence::Confirmed)
        .with_cwe("CWE-200")
        .with_references(refs![
            "https://www.hikvision.com/en/support/cybersecurity/security-advisory/",
            "https://cwe.mitre.org/data/definitions/200.html",
        ])
        .with_remediation(Remediation {
            description: "Restrict the SADP discovery service and segment video devices."
                .to_owned(),
            steps: vec![
                "Disable SADP / multicast discovery in the device's network settings if the \
                 firmware offers it (Configuration > Network > Advanced)."
                    .to_owned(),
                "Put cameras and recorders on their own VLAN with no route to general LAN \
                 clients or to the internet."
                    .to_owned(),
                "Block UDP/37020 between client VLANs and the video VLAN.".to_owned(),
            ],
            effort: Some("30 minutes".to_owned()),
        }),
    )
}

/// Firmware-floor finding for a build below one of the two known floors.
fn firmware_finding(ip: IpAddr, device: &SadpDevice, verdict: BuildVerdict) -> Option<Finding> {
    let version = device.software_version.as_deref().unwrap_or("unreported");
    let (severity, title, description, cwe) = match verdict {
        BuildVerdict::KevAuthBypass => (
            Severity::Critical,
            format!(
                "Hikvision firmware vulnerable to the CVE-2017-7921 authentication bypass on {ip}"
            ),
            format!(
                "The device at {ip} reports firmware {version}. Builds in the V5.2.0-V5.4.4 \
                 range dated 170109 or earlier carry CVE-2017-7921, an improper authentication \
                 flaw that lets anyone on the network download the full device configuration \
                 — including the admin password hash — and escalate to full control. CISA added \
                 it to the Known Exploited Vulnerabilities catalog on 2026-03-05; it is used by \
                 IoT botnets and has been exploited in the wild for years. The same build is \
                 also below the 250807 floor of the 2025 advisory family (CVE-2025-66177). \
                 Upgrade the firmware and then change every credential, since existing \
                 passwords must be assumed disclosed."
            ),
            "CWE-287",
        ),
        BuildVerdict::BelowFloor => (
            Severity::High,
            format!("Hikvision firmware predates the 250807 security build floor on {ip}"),
            format!(
                "The device at {ip} reports firmware {version}, whose build date is earlier \
                 than 250807 (2025-08-07). The 2025 Hikvision advisory family behind \
                 CVE-2025-66177 lists that build date as the fix floor across 89 of 104 \
                 affected NVR/DVR/CVR and IP camera families; the flaw is reachable from the \
                 adjacent network (CVSS AV:A), which is exactly the position any other device \
                 on this LAN occupies. Update the firmware from the vendor's support site and \
                 verify the reported build date afterwards."
            ),
            "CWE-1104",
        ),
        BuildVerdict::Current | BuildVerdict::Unknown => return None,
    };

    Some(base_finding(
        ip,
        device,
        Finding::new("sadp", &title, &description, severity)
            // Version-derived, not demonstrated: the build date is self-reported.
            .with_confidence(Confidence::Probable)
            .with_cwe(cwe)
            .with_cve_ids(cves_for(verdict))
            .with_references(refs![
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "https://www.hikvision.com/en/support/cybersecurity/security-advisory/",
            ])
            .with_remediation(Remediation {
                description: "Update the device firmware and rotate its credentials.".to_owned(),
                steps: vec![
                    "Download the current firmware for this exact model from the vendor's \
                     support site and apply it."
                        .to_owned(),
                    "Re-run this scan and confirm the reported build date is 250807 or later."
                        .to_owned(),
                    "Change the admin password and any RTSP/ONVIF service accounts after the \
                     update; older builds must be assumed to have leaked them."
                        .to_owned(),
                    "Keep the device off the internet — do not port-forward 80, 554 or 8000."
                        .to_owned(),
                ],
                effort: Some("1 hour per device".to_owned()),
            }),
    ))
}

/// Finding for a device still in the factory un-activated state.
fn unactivated_finding(ip: IpAddr, device: &SadpDevice) -> Option<Finding> {
    if device.activated != Some(false) {
        return None;
    }
    Some(base_finding(
        ip,
        device,
        Finding::new(
            "sadp",
            &format!("Hikvision device is un-activated — no admin password set on {ip}"),
            &format!(
                "The device at {ip} reports Activated=false in its SADP record: it is still in \
                 the factory state with no administrator password. Any host on this LAN can \
                 complete activation over SADP and take ownership of the device, including its \
                 video streams and its position inside the network. Activate it now from a \
                 trusted host and set a long, unique password."
            ),
            Severity::Critical,
        )
        .with_confidence(Confidence::Confirmed)
        .with_cwe("CWE-1188")
        .with_references(refs![
            "https://cwe.mitre.org/data/definitions/1188.html",
            "https://www.hikvision.com/en/support/cybersecurity/security-advisory/",
        ])
        .with_remediation(Remediation {
            description: "Activate the device and set a strong administrator password.".to_owned(),
            steps: vec![
                "Activate the device immediately from a trusted host on an isolated network \
                 segment, setting a long unique password."
                    .to_owned(),
                "Disconnect it from the LAN until activation is complete if that is possible."
                    .to_owned(),
                "After activation, update the firmware before returning it to service.".to_owned(),
            ],
            effort: Some("15 minutes".to_owned()),
        }),
    ))
}

/// All findings for one answering device.
fn findings_for(ip: IpAddr, device: &SadpDevice) -> Vec<Finding> {
    let mut findings = vec![presence_finding(ip, device)];
    if let Some(finding) = unactivated_finding(ip, device) {
        findings.push(finding);
    }
    if let Some(finding) = firmware_finding(ip, device, classify_build(device.version)) {
        findings.push(finding);
    }
    findings
}

// ── Probe ───────────────────────────────────────────────────────────────────

/// Bind the SADP socket. Binding 37020 and joining the group is what makes
/// devices that answer to the multicast group (rather than to our source port)
/// visible; an ephemeral port is the fallback when 37020 is already in use.
async fn bind_sadp_socket() -> Option<UdpSocket> {
    match UdpSocket::bind(("0.0.0.0", SADP_PORT)).await {
        Ok(socket) => {
            if let Err(e) = socket.join_multicast_v4(SADP_GROUP, Ipv4Addr::UNSPECIFIED) {
                tracing::debug!("could not join SADP multicast group: {e}");
            }
            Some(socket)
        }
        Err(e) => {
            tracing::debug!("could not bind UDP/{SADP_PORT} ({e}); using an ephemeral port");
            UdpSocket::bind("0.0.0.0:0").await.ok()
        }
    }
}

/// Send the inquiry to the multicast group and to each unicast target, then
/// collect replies until the window closes. Replies from excluded hosts are
/// dropped.
async fn discover(targets: &[IpAddr], exclusions: &ExclusionSet) -> Vec<(IpAddr, SadpDevice)> {
    let mut results: Vec<(IpAddr, SadpDevice)> = Vec::new();
    let Some(socket) = bind_sadp_socket().await else {
        tracing::warn!("could not bind a SADP socket");
        return results;
    };

    let inquiry = build_inquiry(&probe_uuid());
    // The multicast inquiry mirrors the existing SSDP/mDNS discovery scanners:
    // one group datagram, results filtered by the exclusion set on receipt.
    let group = SocketAddr::new(IpAddr::V4(SADP_GROUP), SADP_PORT);
    if let Err(e) = socket.send_to(inquiry.as_bytes(), group).await {
        tracing::debug!("could not send the SADP multicast inquiry: {e}");
    }
    for &ip in targets {
        // Defence in depth: `scan` pre-filters, and no excluded host is probed
        // even if a caller passes one.
        if exclusions.excludes_ip(ip) {
            continue;
        }
        let dest = SocketAddr::new(ip, SADP_PORT);
        if let Err(e) = socket.send_to(inquiry.as_bytes(), dest).await {
            tracing::debug!(%ip, "could not send the SADP inquiry: {e}");
        }
    }

    let deadline = Instant::now() + COLLECT_WINDOW;
    let mut seen: HashSet<IpAddr> = HashSet::new();
    let mut buf = vec![0u8; RECV_BUF];
    while results.len() < MAX_REPLIES {
        let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
        else {
            break;
        };
        let ip = from.ip();
        if exclusions.excludes_ip(ip) || !seen.insert(ip) {
            continue;
        }
        let Some(chunk) = buf.get(..n) else { continue };
        if let Some(device) = parse_probe_match(&String::from_utf8_lossy(chunk)) {
            results.push((ip, device));
        }
    }

    results
}

#[async_trait]
impl Scanner for SadpScanner {
    fn id(&self) -> &'static str {
        "sadp"
    }

    fn name(&self) -> &'static str {
        "Hikvision SADP Discovery"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running Hikvision SADP discovery scan");
        let mut findings = Vec::new();

        // Skip below Active intensity — this sends application-layer datagrams.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping SADP scan in quick scan mode");
            return Ok(findings);
        }

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "sadp".to_owned(),
                message: e.to_string(),
            })?;

        // UDP/37020 is invisible to the TCP port scan, so every discovered host
        // is probed directly in addition to the multicast inquiry.
        let targets: Vec<IpAddr> = ctx
            .discovered_devices
            .iter()
            .filter(|d| !exclusions.excludes_device(d))
            .map(|d| d.ip)
            .collect();

        let replies = discover(&targets, &exclusions).await;
        tracing::info!(reply_count = replies.len(), "SADP replies received");

        for (ip, device) in &replies {
            findings.extend(findings_for(*ip, device));
        }

        tracing::info!(
            findings_count = findings.len(),
            "Hikvision SADP discovery scan complete"
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

    /// Reply shaped after a real DS-2CD2032-I `ProbeMatch`.
    const CAMERA_REPLY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ProbeMatch>
<Uuid>{A1B2C3D4-0000-0000-0000-000000000001}</Uuid>
<Types>inquiry</Types>
<DeviceType>DS-2CD2032-I</DeviceType>
<DeviceDescription>IPCamera</DeviceDescription>
<DeviceSN>DS-2CD2032-I20150513CCWR123456789</DeviceSN>
<CommandPort>8000</CommandPort>
<HttpPort>80</HttpPort>
<MAC>44-19-b6-11-22-33</MAC>
<IPv4Address>192.168.1.64</IPv4Address>
<IPv4SubnetMask>255.255.255.0</IPv4SubnetMask>
<IPv4Gateway>192.168.1.1</IPv4Gateway>
<DHCP>false</DHCP>
<SoftwareVersion>V5.3.0build 150513</SoftwareVersion>
<DSPVersion>V5.0build 140714</DSPVersion>
<BootTime>2015-05-13 00:00:00</BootTime>
<ResetAbility>true</ResetAbility>
<DiskNumber>0</DiskNumber>
<Activated>true</Activated>
<PasswordResetAbility>true</PasswordResetAbility>
</ProbeMatch>"#;

    /// Reply from an un-activated NVR on current firmware.
    const NVR_REPLY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ProbeMatch>
<Types>inquiry</Types>
<DeviceType>DS-7608NI-K2</DeviceType>
<DeviceDescription>NVR</DeviceDescription>
<DeviceSN>DS-7608NI-K20260101AAWR987654321</DeviceSN>
<HttpPort>80</HttpPort>
<MAC>c0:56:e3:aa:bb:cc</MAC>
<IPv4Address>192.168.1.70</IPv4Address>
<SoftwareVersion>V4.61.025 build 260115</SoftwareVersion>
<Activated>false</Activated>
</ProbeMatch>"#;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn inquiry_is_the_read_only_discovery_verb() {
        let msg = build_inquiry("{ABCD}");
        assert!(msg.contains("<Types>inquiry</Types>"));
        assert!(msg.contains("<Uuid>{ABCD}</Uuid>"));
        // No write/control verb is ever emitted.
        for verb in ["update", "activate", "reset", "modify"] {
            assert!(!msg.contains(verb), "{verb} in {msg}");
        }
    }

    #[test]
    fn probe_uuid_has_the_canonical_shape() {
        let uuid = probe_uuid();
        assert!(uuid.starts_with('{') && uuid.ends_with('}'));
        let inner = uuid.trim_matches(['{', '}']);
        let groups: Vec<&str> = inner.split('-').collect();
        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(inner.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    }

    #[test]
    fn parses_a_camera_probe_match() {
        let device = parse_probe_match(CAMERA_REPLY).unwrap();
        assert_eq!(device.model.as_deref(), Some("DS-2CD2032-I"));
        assert_eq!(device.description.as_deref(), Some("IPCamera"));
        assert_eq!(
            device.software_version.as_deref(),
            Some("V5.3.0build 150513")
        );
        assert_eq!(device.ipv4, Some(Ipv4Addr::new(192, 168, 1, 64)));
        assert_eq!(device.mac.as_deref(), Some("44:19:b6:11:22:33"));
        assert_eq!(device.http_port, Some(80));
        assert_eq!(device.activated, Some(true));
        assert_eq!(
            device.version,
            Some(FirmwareVersion {
                major: 5,
                minor: 3,
                build: Some(150_513)
            })
        );
    }

    #[test]
    fn parses_an_nvr_probe_match() {
        let device = parse_probe_match(NVR_REPLY).unwrap();
        assert_eq!(device.model.as_deref(), Some("DS-7608NI-K2"));
        assert_eq!(device.activated, Some(false));
        assert_eq!(device.version.and_then(|v| v.build), Some(260_115));
        assert_eq!(device.mac.as_deref(), Some("c0:56:e3:aa:bb:cc"));
    }

    #[test]
    fn rejects_non_probe_match_payloads() {
        assert!(parse_probe_match("").is_none());
        assert!(parse_probe_match("not xml at all").is_none());
        // Our own inquiry, looped back by multicast, is not a device record.
        assert!(parse_probe_match(&build_inquiry("{DEAD}")).is_none());
        assert!(parse_probe_match("<ProbeMatch><Types>inquiry</Types></ProbeMatch>").is_none());
    }

    #[test]
    fn extract_tag_handles_absent_empty_and_entity_content() {
        assert_eq!(extract_tag("<A>x</A>", "A").as_deref(), Some("x"));
        assert_eq!(extract_tag("<A> x </A>", "A").as_deref(), Some("x"));
        assert_eq!(extract_tag("<A></A>", "A"), None);
        assert_eq!(extract_tag("<A>x</A>", "B"), None);
        assert_eq!(extract_tag("<A>x", "A"), None);
        assert_eq!(
            extract_tag("<A>Ann &amp; Co &lt;3</A>", "A").as_deref(),
            Some("Ann & Co <3")
        );
    }

    #[test]
    fn parses_the_firmware_version_forms_seen_in_the_field() {
        let cases = [
            ("V5.3.0build 150513", 5, 3, Some(150_513)),
            ("V5.4.5 build 170123", 5, 4, Some(170_123)),
            ("V5.4.41build 170312", 5, 4, Some(170_312)),
            ("V4.61.025 build 260115", 4, 61, Some(260_115)),
            ("V4.0.2", 4, 0, None),
            ("5.2.0build 140721", 5, 2, Some(140_721)),
        ];
        for (raw, major, minor, build) in cases {
            let parsed = parse_firmware_version(raw).unwrap_or_else(|| panic!("{raw}"));
            assert_eq!(
                (parsed.major, parsed.minor, parsed.build),
                (major, minor, build),
                "{raw}"
            );
        }
    }

    #[test]
    fn rejects_implausible_or_malformed_build_tokens() {
        // Not six digits, or not a plausible YYMMDD: treated as absent.
        assert_eq!(
            parse_firmware_version("V5.3.0build 15051").unwrap().build,
            None
        );
        assert_eq!(
            parse_firmware_version("V5.3.0build 1505133").unwrap().build,
            None
        );
        assert_eq!(
            parse_firmware_version("V5.3.0build 159901").unwrap().build,
            None
        );
        assert_eq!(
            parse_firmware_version("V5.3.0build 150500").unwrap().build,
            None
        );
        assert_eq!(
            parse_firmware_version("V5.3.0build abc").unwrap().build,
            None
        );
        assert!(parse_firmware_version("").is_none());
        assert!(parse_firmware_version("Vx.y.z").is_none());
        assert!(parse_firmware_version("V5").is_none());
    }

    #[test]
    fn classifies_builds_against_both_floors() {
        let v = |major, minor, build| {
            Some(FirmwareVersion {
                major,
                minor,
                build,
            })
        };
        assert_eq!(
            classify_build(v(5, 3, Some(150_513))),
            BuildVerdict::KevAuthBypass
        );
        assert_eq!(
            classify_build(v(5, 4, Some(170_109))),
            BuildVerdict::KevAuthBypass
        );
        // One day past the CVE-2017-7921 window, still below the 2025 floor.
        assert_eq!(
            classify_build(v(5, 4, Some(170_123))),
            BuildVerdict::BelowFloor
        );
        // Old build outside the 5.2-5.4 range: only the 2025 floor applies.
        assert_eq!(
            classify_build(v(5, 1, Some(140_101))),
            BuildVerdict::BelowFloor
        );
        assert_eq!(
            classify_build(v(4, 61, Some(250_806))),
            BuildVerdict::BelowFloor
        );
        assert_eq!(
            classify_build(v(4, 61, Some(250_807))),
            BuildVerdict::Current
        );
        assert_eq!(
            classify_build(v(4, 61, Some(260_115))),
            BuildVerdict::Current
        );
        assert_eq!(classify_build(v(5, 3, None)), BuildVerdict::Unknown);
        assert_eq!(classify_build(None), BuildVerdict::Unknown);
    }

    #[test]
    fn cve_correlation_follows_the_verdict() {
        assert_eq!(
            cves_for(BuildVerdict::KevAuthBypass),
            vec!["CVE-2017-7921", "CVE-2025-66177"]
        );
        assert_eq!(cves_for(BuildVerdict::BelowFloor), vec!["CVE-2025-66177"]);
        assert!(cves_for(BuildVerdict::Current).is_empty());
        assert!(cves_for(BuildVerdict::Unknown).is_empty());
    }

    #[test]
    fn classifies_device_types_and_vendor() {
        assert_eq!(
            classify_device(Some("IPCamera"), Some("DS-2CD2032-I")),
            DeviceType::Camera
        );
        assert_eq!(
            classify_device(Some("NVR"), Some("DS-7608NI-K2")),
            DeviceType::Camera
        );
        assert_eq!(
            classify_device(Some("Access Controller"), Some("DS-K1T341")),
            DeviceType::IoT
        );
        assert_eq!(classify_device(None, Some("DS-K1T341")), DeviceType::IoT);
        assert_eq!(classify_device(None, Some("DS-PWA96")), DeviceType::IoT);
        assert_eq!(classify_device(None, None), DeviceType::Camera);

        assert_eq!(vendor_for(Some("DS-2CD2032-I")), Some("Hikvision"));
        assert_eq!(vendor_for(Some("iDS-2CD7A46G0")), Some("Hikvision"));
        // OEM rebrand: no vendor claimed rather than a wrong one.
        assert_eq!(vendor_for(Some("N48PBW")), None);
        assert_eq!(vendor_for(None), None);
    }

    #[test]
    fn camera_reply_yields_presence_and_kev_findings() {
        let device = parse_probe_match(CAMERA_REPLY).unwrap();
        let findings = findings_for(ip("192.168.1.64"), &device);
        assert_eq!(findings.len(), 2, "{findings:#?}");

        let presence = &findings[0];
        assert_eq!(presence.severity, Severity::Info);
        assert_eq!(presence.affected_port, Some(SADP_PORT));
        assert_eq!(presence.confidence, Confidence::Confirmed);
        assert!(
            presence
                .evidence
                .as_deref()
                .unwrap()
                .contains("DS-2CD2032-I")
        );
        let hint = presence.device_hint.as_ref().unwrap();
        assert_eq!(hint.vendor.as_deref(), Some("Hikvision"));
        assert_eq!(hint.device_type, Some(DeviceType::Camera));

        let firmware = &findings[1];
        assert_eq!(firmware.severity, Severity::Critical);
        assert_eq!(firmware.confidence, Confidence::Probable);
        assert_eq!(firmware.cve_ids, vec!["CVE-2017-7921", "CVE-2025-66177"]);
        assert_eq!(
            firmware.affected_mac.map(|m| m.to_string()).as_deref(),
            Some("44:19:b6:11:22:33")
        );
    }

    #[test]
    fn unactivated_current_firmware_yields_presence_and_activation_findings() {
        let device = parse_probe_match(NVR_REPLY).unwrap();
        let findings = findings_for(ip("192.168.1.70"), &device);
        assert_eq!(findings.len(), 2, "{findings:#?}");
        assert_eq!(findings[1].severity, Severity::Critical);
        assert!(findings[1].title.contains("un-activated"));
        assert!(findings[1].cve_ids.is_empty());
    }

    #[test]
    fn current_activated_firmware_yields_only_the_presence_finding() {
        let mut device = parse_probe_match(NVR_REPLY).unwrap();
        device.activated = Some(true);
        let findings = findings_for(ip("192.168.1.70"), &device);
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn titles_are_stable_across_firmware_and_serial_changes() {
        let mut device = parse_probe_match(CAMERA_REPLY).unwrap();
        let before = findings_for(ip("192.168.1.64"), &device)[0].fingerprint();
        device.software_version = Some("V5.4.5 build 170123".to_owned());
        device.version = parse_firmware_version("V5.4.5 build 170123");
        device.serial = Some("OTHER".to_owned());
        let after = findings_for(ip("192.168.1.64"), &device)[0].fingerprint();
        assert_eq!(before, after);
    }

    #[test]
    fn excluded_replies_are_dropped() {
        let exclusions = ExclusionSet::parse(&["10.0.0.0/24".to_owned()], &[]).unwrap();
        assert!(exclusions.excludes_ip(ip("10.0.0.7")));
        assert!(!exclusions.excludes_ip(ip("192.168.1.64")));
    }

    /// Answer one inquiry on 127.0.0.1:37020 with `CAMERA_REPLY`, asserting the
    /// request is the read-only inquiry verb.
    fn spawn_responder(responder: UdpSocket) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF];
            let Ok((n, from)) = responder.recv_from(&mut buf).await else {
                return;
            };
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(request.contains("<Types>inquiry</Types>"), "{request}");
            let _ = responder.send_to(CAMERA_REPLY.as_bytes(), from).await;
        })
    }

    #[tokio::test]
    async fn discover_round_trips_against_a_local_responder_and_honours_exclusions() {
        // Holding 37020 also exercises the ephemeral-port fallback in
        // `bind_sadp_socket`. If the port is busy on this machine, skip.
        let Ok(responder) = UdpSocket::bind(("127.0.0.1", SADP_PORT)).await else {
            return;
        };
        let server = spawn_responder(responder);
        let found = discover(&[ip("127.0.0.1")], &ExclusionSet::default()).await;
        server.abort();

        let (addr, device) = found
            .iter()
            .find(|(addr, _)| *addr == ip("127.0.0.1"))
            .expect("the responder's ProbeMatch should be parsed");
        assert_eq!(*addr, ip("127.0.0.1"));
        assert_eq!(device.model.as_deref(), Some("DS-2CD2032-I"));

        // Same exchange, but the responder's address is excluded.
        let Ok(responder) = UdpSocket::bind(("127.0.0.1", SADP_PORT)).await else {
            return;
        };
        let server = spawn_responder(responder);
        let excluded = ExclusionSet::parse(&["127.0.0.0/8".to_owned()], &[]).unwrap();
        let found = discover(&[ip("127.0.0.1")], &excluded).await;
        server.abort();
        assert!(found.is_empty(), "{found:?}");
    }

    proptest! {
        #[test]
        fn prop_parse_probe_match_no_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_probe_match(&String::from_utf8_lossy(&bytes));
        }

        #[test]
        fn prop_parse_probe_match_no_panic_on_xmlish(s in "(<[A-Za-z/]{0,12}>|[ -~]){0,200}") {
            let _ = parse_probe_match(&s);
        }

        #[test]
        fn prop_parse_firmware_version_no_panic(s in "[Vv]?[0-9a-zA-Z. ]{0,40}") {
            if let Some(v) = parse_firmware_version(&s)
                && let Some(build) = v.build
            {
                prop_assert!((100_101..=999_931).contains(&build));
                prop_assert!(plausible_build_date(build));
            }
        }

        #[test]
        fn prop_extract_tag_no_panic(s in ".{0,200}", tag in "[A-Za-z]{1,10}") {
            let _ = extract_tag(&s, &tag);
        }

        #[test]
        fn prop_findings_for_no_panic(
            model in proptest::option::of("[ -~]{0,40}"),
            descr in proptest::option::of("[ -~]{0,40}"),
            version in proptest::option::of("[ -~]{0,40}"),
        ) {
            let device = SadpDevice {
                version: version.as_deref().and_then(parse_firmware_version),
                model,
                description: descr,
                software_version: version,
                ..SadpDevice::default()
            };
            let findings = findings_for(ip("192.168.1.9"), &device);
            prop_assert!(!findings.is_empty());
        }
    }
}

/// Parser entry points for the fuzz harness.
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    #[must_use]
    pub fn probe_match(xml: &str) -> bool {
        super::parse_probe_match(xml).is_some()
    }
    #[must_use]
    pub fn firmware(raw: &str) -> bool {
        super::parse_firmware_version(raw).is_some()
    }
}
