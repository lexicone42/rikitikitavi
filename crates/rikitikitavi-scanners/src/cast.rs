//! Google Cast identification (Chromecast, Nest speakers/displays, Cast-built-in TVs)
//! and setup-endpoint exposure.
//!
//! Read-only and unauthenticated: one `GET /setup/eureka_info` (HTTPS/8443 first,
//! HTTP/8008 as fallback) and one TLS `ClientHello` on 8009. The same setup API
//! exposes reboot and Wi-Fi configuration endpoints; those are never touched.
//!
//! 8009 is not an IANA Cast port (IANA assigns `nvme-disc`, nmap names it `ajp13`),
//! so the port number alone never identifies a Cast device — the TLS response does.

use async_trait::async_trait;
use futures::stream::StreamExt as _;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::config::ExclusionSet;
use rikitikitavi_models::device::PortProtocol;
use rikitikitavi_models::{Device, DeviceHint, DeviceType, Finding, Remediation, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::Scanner;
use crate::http_util::{read_body_capped, unauthenticated_probe_client};

/// Google Cast scanner. Only probes hosts Phase 1 found with a Cast port open.
pub struct CastScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(4);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// `eureka_info` bodies are a few KB; cap far below the shared default.
const MAX_EUREKA_BYTES: usize = 64 * 1024;

/// `DIAL`/setup API over TLS.
const CAST_HTTPS_PORT: u16 = 8443;
/// `DIAL`/setup API in the clear (older firmware).
const CAST_HTTP_PORT: u16 = 8008;
/// Cast v2 protocol port (TLS + protobuf).
const CAST_PROTOCOL_PORT: u16 = 8009;

const CAST_PORTS: &[u16] = &[CAST_HTTPS_PORT, CAST_PROTOCOL_PORT, CAST_HTTP_PORT];

/// Deadline for the whole probe phase, below the runner's per-scanner budget.
const PROBE_BUDGET: Duration = Duration::from_secs(40);

/// Cap on concurrent host probes.
const MAX_PARALLELISM: usize = 16;

/// Read-only status selector, as used by `pychromecast`'s `dial.py`.
const EUREKA_PATH: &str =
    "/setup/eureka_info?params=name,build_info,device_info,net,wifi,detail,settings&options=detail";

// ── Pure parsing / classification (unit-tested below) ───────────────────

/// Fields of interest from a `/setup/eureka_info` response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct EurekaInfo {
    /// Owner-assigned friendly name (e.g. `Living Room TV`).
    name: Option<String>,
    manufacturer: Option<String>,
    model_name: Option<String>,
    product_name: Option<String>,
    build_revision: Option<String>,
    mac_address: Option<String>,
    ssid: Option<String>,
    bssid: Option<String>,
    timezone: Option<String>,
    /// Presence only — the hash value is never stored or reported.
    auth_token_hash_present: bool,
    cloud_device_id_present: bool,
}

/// Follow `path` through nested JSON objects and return a trimmed non-empty string.
fn json_str(root: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut cur = root;
    for key in path {
        cur = cur.get(key)?;
    }
    let text = cur.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// First path that yields a string.
fn first_str(root: &serde_json::Value, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|p| json_str(root, p))
}

/// Whether `path` resolves to a value carrying data. Null and empty/whitespace
/// strings are unset fields, not disclosure — Cast firmware emits `""` for those.
fn json_present(root: &serde_json::Value, path: &[&str]) -> bool {
    let mut cur = root;
    for key in path {
        match cur.get(key) {
            Some(next) => cur = next,
            None => return false,
        }
    }
    match cur {
        serde_json::Value::Null => false,
        serde_json::Value::String(s) => !s.trim().is_empty(),
        _ => true,
    }
}

/// Parse an `eureka_info` body. `None` unless the JSON object carries one of the
/// Cast-specific containers, so an unrelated JSON endpoint on 8443 is not claimed.
fn parse_eureka_info(body: &str) -> Option<EurekaInfo> {
    let root: serde_json::Value = serde_json::from_str(body).ok()?;
    if !root.is_object() {
        return None;
    }
    let cast_shaped = ["device_info", "build_info", "ssdp_udn", "opt_in"]
        .iter()
        .any(|k| root.get(k).is_some());
    if !cast_shaped {
        return None;
    }

    Some(EurekaInfo {
        name: first_str(&root, &[&["name"], &["settings", "name"]]),
        manufacturer: json_str(&root, &["device_info", "manufacturer"]),
        model_name: json_str(&root, &["device_info", "model_name"]),
        product_name: json_str(&root, &["device_info", "product_name"]),
        build_revision: first_str(
            &root,
            &[
                &["build_info", "cast_build_revision"],
                &["build_info", "system_build_number"],
            ],
        ),
        mac_address: json_str(&root, &["device_info", "mac_address"]),
        ssid: first_str(&root, &[&["wifi", "ssid"], &["ssid"]]),
        bssid: first_str(&root, &[&["wifi", "bssid"], &["bssid"]]),
        timezone: first_str(&root, &[&["settings", "timezone"], &["timezone"]]),
        auth_token_hash_present: json_present(
            &root,
            &["device_info", "local_authorization_token_hash"],
        ),
        cloud_device_id_present: json_present(&root, &["device_info", "cloud_device_id"]),
    })
}

/// Best available label for the device.
fn device_label(info: &EurekaInfo) -> String {
    info.model_name
        .as_ref()
        .or(info.product_name.as_ref())
        .map_or_else(|| "Google Cast device".to_owned(), Clone::clone)
}

/// Classify from the model/product strings only — the friendly name is
/// owner-assigned and would misclassify a speaker called "TV".
fn classify_cast_device(info: &EurekaInfo) -> DeviceType {
    let haystack = [info.model_name.as_deref(), info.product_name.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    if haystack.contains("tv") || haystack.contains("display") {
        DeviceType::SmartTv
    } else {
        DeviceType::MediaPlayer
    }
}

/// Sensitive `eureka_info` fields the device handed to an unauthenticated peer.
fn exposed_fields(info: &EurekaInfo) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if info.ssid.is_some() {
        fields.push("wifi.ssid");
    }
    if info.bssid.is_some() {
        fields.push("wifi.bssid");
    }
    if info.mac_address.is_some() {
        fields.push("device_info.mac_address");
    }
    if info.auth_token_hash_present {
        fields.push("device_info.local_authorization_token_hash");
    }
    if info.cloud_device_id_present {
        fields.push("device_info.cloud_device_id");
    }
    if info.timezone.is_some() {
        fields.push("settings.timezone");
    }
    fields
}

/// `Medium` when the leak geolocates the network or exposes token material;
/// `Low` for identifiers alone; `None` when nothing sensitive came back.
fn exposure_severity(fields: &[&str]) -> Option<Severity> {
    if fields.is_empty() {
        return None;
    }
    let high_value = fields.iter().any(|f| {
        matches!(
            *f,
            "wifi.bssid" | "device_info.local_authorization_token_hash"
        )
    });
    Some(if high_value {
        Severity::Medium
    } else {
        Severity::Low
    })
}

/// URL for the `eureka_info` probe. Cast answers 403 for a hostname `Host`
/// header, so the authority is always the literal address.
fn eureka_url(scheme: &str, ip: IpAddr, port: u16) -> String {
    format!("{scheme}://{}{EUREKA_PATH}", SocketAddr::new(ip, port))
}

/// What the peer sent back to a `ClientHello`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsResponse {
    /// Handshake record carrying a `ServerHello`.
    ServerHello,
    /// Handshake record of some other type.
    Handshake,
    /// Alert record — still proof of a TLS speaker.
    Alert,
    /// Not a TLS record.
    NotTls,
}

impl TlsResponse {
    const fn is_tls(self) -> bool {
        !matches!(self, Self::NotTls)
    }
}

/// Classify the first bytes of a reply to a `ClientHello`.
///
/// A TLS record is `<content type> 0x03 <minor> <len hi> <len lo>`; for a
/// handshake record byte 5 is the handshake type (`0x02` = `ServerHello`).
fn classify_tls_response(data: &[u8]) -> Option<TlsResponse> {
    if data.len() < 3 {
        return None;
    }
    if data[1] != 0x03 || data[2] > 0x04 {
        return Some(TlsResponse::NotTls);
    }
    Some(match data[0] {
        0x16 if data.get(5) == Some(&0x02) => TlsResponse::ServerHello,
        0x16 => TlsResponse::Handshake,
        0x15 => TlsResponse::Alert,
        _ => TlsResponse::NotTls,
    })
}

/// Fixed client random: the probe never resumes a session, so it need not vary.
const CLIENT_HELLO_RANDOM: [u8; 32] = [0x72; 32];

/// Broad TLS 1.2 suite list, chosen so Cast answers with a `ServerHello`
/// rather than a `handshake_failure` alert.
const CLIENT_HELLO_CIPHERS: &[u16] = &[
    0xC02B, 0xC02C, 0xC02F, 0xC030, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
];

/// Append one `extension_type` / `length` / `data` triple.
fn push_extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(data);
}

/// `supported_groups`, `ec_point_formats`, `signature_algorithms`. No SNI: the
/// probe connects by address and Cast does not require it.
fn build_extensions() -> Vec<u8> {
    let mut out = Vec::new();
    // x25519, secp256r1, secp384r1
    push_extension(
        &mut out,
        0x000A,
        &[0x00, 0x06, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x18],
    );
    // uncompressed point format
    push_extension(&mut out, 0x000B, &[0x01, 0x00]);
    // rsa_pkcs1_sha256, ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha1
    push_extension(
        &mut out,
        0x000D,
        &[0x00, 0x08, 0x04, 0x01, 0x04, 0x03, 0x08, 0x04, 0x02, 0x01],
    );
    out
}

/// Build a minimal TLS 1.2 `ClientHello` record.
///
/// ```text
/// Record:    0x16 0x03 0x01 <len:2>
/// Handshake: 0x01 <len:3>
///   client_version 0x03 0x03, random[32], session_id(0),
///   cipher_suites, compression_methods(null), extensions
/// ```
fn build_client_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&CLIENT_HELLO_RANDOM);
    body.push(0x00);
    let cipher_bytes = u16::try_from(CLIENT_HELLO_CIPHERS.len() * 2).unwrap_or(0);
    body.extend_from_slice(&cipher_bytes.to_be_bytes());
    for suite in CLIENT_HELLO_CIPHERS {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    body.extend_from_slice(&[0x01, 0x00]);
    let extensions = build_extensions();
    body.extend_from_slice(&u16::try_from(extensions.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01);
    let body_len = u32::try_from(body.len()).unwrap_or(0);
    handshake.extend_from_slice(&body_len.to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(0x16);
    // Record-layer version 0x0301 for maximum middlebox compatibility.
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&u16::try_from(handshake.len()).unwrap_or(0).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// A host with at least one Cast-candidate port open.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CastTarget {
    ip: IpAddr,
    ports: Vec<u16>,
}

/// Phase-1 devices with a Cast-candidate TCP port, minus excluded IPs and MACs.
fn select_cast_targets(devices: &[Device], exclusions: &ExclusionSet) -> Vec<CastTarget> {
    devices
        .iter()
        .filter(|d| !exclusions.excludes_ip(d.ip))
        .filter(|d| !d.mac.is_some_and(|m| exclusions.excludes_mac(m)))
        .filter_map(|d| {
            let mut ports: Vec<u16> = d
                .open_ports
                .iter()
                .filter(|p| p.protocol == PortProtocol::Tcp && CAST_PORTS.contains(&p.port))
                .map(|p| p.port)
                .collect();
            ports.sort_unstable();
            ports.dedup();
            (!ports.is_empty()).then_some(CastTarget { ip: d.ip, ports })
        })
        .collect()
}

// ── Finding builders (pure, unit-tested) ────────────────────────────────

/// Identification finding. The endpoint is Cast-specific and answered as
/// expected, so this is [`Confidence::Confirmed`].
fn build_identification_finding(ip: IpAddr, port: u16, info: &EurekaInfo) -> Finding {
    let label = device_label(info);
    let build = info
        .build_revision
        .as_deref()
        .map_or_else(String::new, |b| format!(" build {b}"));
    let friendly = info
        .name
        .as_deref()
        .map_or_else(String::new, |n| format!(" named '{n}'"));

    let mut hint = DeviceHint::new()
        .with_device_type(classify_cast_device(info))
        .with_vendor(
            info.manufacturer
                .clone()
                .unwrap_or_else(|| "Google".to_owned()),
        );
    if let Some(model) = info.model_name.as_ref().or(info.product_name.as_ref()) {
        hint = hint.with_model(model.clone());
    }
    if let Some(name) = info.name.as_deref() {
        hint = hint.with_hostname(name);
    }

    let finding = Finding::new(
        "cast",
        &format!("Google Cast device identified on {ip}:{port}"),
        &format!(
            "The host at {ip}:{port} answered an unauthenticated \
             GET /setup/eureka_info and identifies as {label}{build}{friendly}. \
             Cast devices accept media-playback control from any host on the same \
             network by design; keep them off the segment that carries \
             administrative or personal systems."
        ),
        Severity::Info,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service("Google Cast")
    .with_confidence(Confidence::Confirmed)
    .with_evidence(format!("eureka_info: {label}{build}"))
    .with_device_hint(hint);

    match info.mac_address.as_deref() {
        Some(mac) => finding.with_mac(mac),
        None => finding,
    }
}

/// Setup-endpoint disclosure finding.
fn build_exposure_finding(
    ip: IpAddr,
    port: u16,
    plaintext: bool,
    info: &EurekaInfo,
    fields: &[&str],
    severity: Severity,
) -> Finding {
    let ssid = info
        .ssid
        .as_deref()
        .map_or_else(String::new, |s| format!(" Wi-Fi SSID '{s}'."));
    let transport = if plaintext {
        " The endpoint answered over plaintext HTTP, so the disclosure is also \
         readable by anyone who can observe the traffic."
    } else {
        ""
    };

    Finding::new(
        "cast",
        &format!("Google Cast setup endpoint discloses device and network details on {ip}:{port}"),
        &format!(
            "The Cast setup API at {ip}:{port} returned {} sensitive field(s) to an \
             unauthenticated request: {}.{ssid}{transport} The Wi-Fi BSSID geolocates the \
             network in public wardriving databases, and the MAC address and account \
             identifiers support device tracking. The endpoint cannot be disabled, so \
             the control is network placement.",
            fields.len(),
            fields.join(", "),
        ),
        severity,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service("Google Cast")
    .with_confidence(Confidence::Confirmed)
    .with_cwe("CWE-200")
    .with_evidence(format!("eureka_info disclosed: {}", fields.join(", ")))
    .with_references(refs![
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://github.com/home-assistant-libs/pychromecast",
    ])
    .with_remediation(Remediation {
        description: "Move Cast devices onto an isolated IoT network segment; the \
                      setup API has no authentication and answers every LAN host."
            .to_owned(),
        steps: vec![
            "Put Cast devices on a separate SSID/VLAN and block that segment from \
             reaching management interfaces and personal systems."
                .to_owned(),
            "Keep the device on automatic firmware updates.".to_owned(),
            "Treat the Wi-Fi BSSID as public once a Cast device joins the network; \
             do not rely on the SSID being unknown."
                .to_owned(),
        ],
        effort: Some("30 minutes".to_owned()),
    })
}

/// 8009 TLS-presence finding. `cast_confirmed` says whether `eureka_info` on the
/// same host already identified it; without that, TLS on 8009 is only suggestive.
fn build_protocol_port_finding(
    ip: IpAddr,
    port: u16,
    response: TlsResponse,
    cast_confirmed: bool,
) -> Finding {
    let confidence = if cast_confirmed {
        Confidence::Confirmed
    } else {
        Confidence::Probable
    };
    let qualifier = if cast_confirmed {
        "The same host was identified as a Cast device through its setup endpoint."
    } else {
        "No setup endpoint answered on this host, so the port is attributed to Cast \
         from the TLS response alone; 8009 is registered to other services."
    };

    Finding::new(
        "cast",
        &format!("Google Cast control channel open on {ip}:{port}"),
        &format!(
            "TCP {port} on {ip} answered a TLS ClientHello with a TLS record \
             ({response:?}), the signature of the Cast v2 control channel. That channel \
             accepts unauthenticated application launch and media control from any host \
             on the network. {qualifier}"
        ),
        Severity::Info,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service("Google Cast")
    .with_confidence(confidence)
    .with_evidence(format!(
        "TLS record in response to ClientHello: {response:?}"
    ))
}

// ── Network probes ──────────────────────────────────────────────────────

/// One `GET /setup/eureka_info`; `None` on any transport error, non-2xx status,
/// or a body that is not a Cast response.
async fn fetch_eureka(
    client: &reqwest::Client,
    ip: IpAddr,
    port: u16,
    scheme: &str,
) -> Option<EurekaInfo> {
    let url = eureka_url(scheme, ip, port);
    let resp = tokio::time::timeout(HTTP_TIMEOUT, client.get(&url).send())
        .await
        .ok()?
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = read_body_capped(resp, MAX_EUREKA_BYTES).await;
    parse_eureka_info(&body)
}

/// Send one `ClientHello` and classify the first response record.
async fn probe_cast_tls(ip: IpAddr, port: u16) -> Option<TlsResponse> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let hello = build_client_hello();
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(&hello))
        .await
        .ok()?
        .ok()?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    classify_tls_response(&buf[..n])
}

/// Probe one host: setup endpoint first (HTTPS then HTTP), then 8009.
async fn scan_target(client: &reqwest::Client, target: &CastTarget, findings: &mut Vec<Finding>) {
    let mut eureka: Option<(u16, bool, EurekaInfo)> = None;
    for (port, scheme, plaintext) in [
        (CAST_HTTPS_PORT, "https", false),
        (CAST_HTTP_PORT, "http", true),
    ] {
        if !target.ports.contains(&port) {
            continue;
        }
        if let Some(info) = fetch_eureka(client, target.ip, port, scheme).await {
            eureka = Some((port, plaintext, info));
            break;
        }
    }

    if let Some((port, plaintext, info)) = eureka.as_ref() {
        findings.push(build_identification_finding(target.ip, *port, info));
        let fields = exposed_fields(info);
        if let Some(severity) = exposure_severity(&fields) {
            findings.push(build_exposure_finding(
                target.ip, *port, *plaintext, info, &fields, severity,
            ));
        }
    }

    if target.ports.contains(&CAST_PROTOCOL_PORT) {
        match probe_cast_tls(target.ip, CAST_PROTOCOL_PORT).await {
            Some(response) if response.is_tls() => findings.push(build_protocol_port_finding(
                target.ip,
                CAST_PROTOCOL_PORT,
                response,
                eureka.is_some(),
            )),
            // Open but not TLS: 8009 is registered to other services, so stay silent.
            other => tracing::debug!(
                ip = %target.ip,
                result = ?other,
                "port 8009 open but no TLS response"
            ),
        }
    }
}

#[async_trait]
impl Scanner for CastScanner {
    fn id(&self) -> &'static str {
        "cast"
    }

    fn name(&self) -> &'static str {
        "Google Cast Exposure"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running Google Cast scan");
        let mut findings = Vec::new();

        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping Cast scan in quick scan mode");
            return Ok(findings);
        }

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "cast".to_owned(),
                message: e.to_string(),
            })?;

        let targets = select_cast_targets(&ctx.discovered_devices, &exclusions);
        if targets.is_empty() {
            tracing::info!("no Cast targets found");
            return Ok(findings);
        }

        let Ok(client) =
            unauthenticated_probe_client(HTTP_TIMEOUT, reqwest::redirect::Policy::none())
        else {
            return Err(ScanError::ScannerFailed {
                scanner: "cast".to_owned(),
                message: "failed to build HTTP probe client".to_owned(),
            });
        };

        tracing::info!(target_count = targets.len(), "probing Cast candidates");

        // Bounded concurrency behind a phase deadline; findings collected so
        // far survive an overrun.
        let parallelism = ctx.config.parallelism.clamp(1, MAX_PARALLELISM);
        let deadline = Instant::now() + PROBE_BUDGET;
        let mut probes = futures::stream::iter(targets)
            .map(|target| {
                let client = client.clone();
                async move {
                    let mut found = Vec::new();
                    scan_target(&client, &target, &mut found).await;
                    found
                }
            })
            .buffer_unordered(parallelism);
        loop {
            match tokio::time::timeout_at(deadline, probes.next()).await {
                Ok(Some(found)) => findings.extend(found),
                Ok(None) => break,
                Err(_) => {
                    tracing::warn!(
                        budget_secs = PROBE_BUDGET.as_secs(),
                        "Cast probe phase timed out; keeping the findings collected so far"
                    );
                    break;
                }
            }
        }
        // Stable: keeps each host's findings in the order scan_target built them.
        findings.sort_by_key(|f| f.affected_ip);

        tracing::info!(findings_count = findings.len(), "Google Cast scan complete");
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        15
    }

    fn relevant_ports(&self) -> &[u16] {
        CAST_PORTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_models::device::OpenPort;

    /// Full `eureka_info` response, shaped after a Chromecast (3rd gen).
    const CHROMECAST_FIXTURE: &str = r#"{
      "bssid": "",
      "build_info": {
        "cast_build_revision": "1.56.500000",
        "cast_control_version": 2,
        "release_track": "stable-channel",
        "system_build_number": "PPR1.180610.011"
      },
      "device_info": {
        "capabilities": {"ble_supported": true, "multizone_supported": true},
        "cloud_device_id": "38FA1C9E0F2B4A0E9C1D4E5F6A7B8C9D",
        "factory_country_code": "US",
        "hotspot_bssid": "FA:8F:CA:00:11:22",
        "local_authorization_token_hash": "hZm0d5S1Q0rN2hQ",
        "mac_address": "F4:F5:D8:11:22:33",
        "manufacturer": "Google Inc.",
        "model_name": "Chromecast",
        "product_name": "Chromecast",
        "ssdp_udn": "e4e0a6c6-1c2b-4c44-9d02-2e6c0c1f5a3b",
        "uptime": 154283.6
      },
      "name": "Living Room TV",
      "net": {"ethernet_connected": false, "ip_address": "192.168.1.52", "online": true},
      "opt_in": {"crash": true, "opencast": true, "stats": true},
      "settings": {
        "control_notifications": 1,
        "country_code": "US",
        "locale": "en-US",
        "network_standby": 0,
        "timezone": "America/Los_Angeles"
      },
      "wifi": {
        "bssid": "3C:37:86:AA:BB:CC",
        "noise_level": -92,
        "signal_level": -47,
        "ssid": "Home-2G",
        "wpa_configured": true,
        "wpa_state": 10
      }
    }"#;

    /// Wired/standby speaker: no `wifi` block, no `cast_build_revision`.
    const NEST_MINI_FIXTURE: &str = r#"{
      "build_info": {"system_build_number": "1.56.275975"},
      "device_info": {
        "manufacturer": "Google Inc.",
        "model_name": "Google Nest Mini",
        "product_name": "Google Nest Mini",
        "mac_address": "1C:F2:9A:44:55:66"
      },
      "name": "Kitchen speaker",
      "settings": {"timezone": "Europe/London"}
    }"#;

    /// Unlinked speaker: sensitive fields present but empty.
    const UNLINKED_FIXTURE: &str = r#"{
      "build_info": {"system_build_number": "1.56.275975"},
      "device_info": {
        "cloud_device_id": "",
        "local_authorization_token_hash": "",
        "mac_address": "",
        "manufacturer": "Google Inc.",
        "model_name": "Google Nest Mini"
      },
      "name": "Spare speaker",
      "settings": {"timezone": ""},
      "wifi": {"ssid": "", "bssid": "   "}
    }"#;

    fn tcp_port(port: u16) -> OpenPort {
        OpenPort {
            port,
            protocol: PortProtocol::Tcp,
            service: None,
            version: None,
            banner: None,
        }
    }

    fn device_with(ip: &str, ports: &[u16]) -> Device {
        let mut device = Device::new(ip.parse().expect("test ip"));
        device.open_ports = ports.iter().copied().map(tcp_port).collect();
        device
    }

    // ── eureka_info parsing ─────────────────────────────────────────

    #[test]
    fn parses_full_chromecast_response() {
        let info = parse_eureka_info(CHROMECAST_FIXTURE).expect("cast-shaped body");
        assert_eq!(info.name.as_deref(), Some("Living Room TV"));
        assert_eq!(info.manufacturer.as_deref(), Some("Google Inc."));
        assert_eq!(info.model_name.as_deref(), Some("Chromecast"));
        assert_eq!(info.product_name.as_deref(), Some("Chromecast"));
        assert_eq!(info.build_revision.as_deref(), Some("1.56.500000"));
        assert_eq!(info.mac_address.as_deref(), Some("F4:F5:D8:11:22:33"));
        assert_eq!(info.ssid.as_deref(), Some("Home-2G"));
        assert_eq!(info.bssid.as_deref(), Some("3C:37:86:AA:BB:CC"));
        assert_eq!(info.timezone.as_deref(), Some("America/Los_Angeles"));
        assert!(info.auth_token_hash_present);
        assert!(info.cloud_device_id_present);
    }

    #[test]
    fn parses_speaker_without_wifi_block() {
        let info = parse_eureka_info(NEST_MINI_FIXTURE).expect("cast-shaped body");
        assert_eq!(info.model_name.as_deref(), Some("Google Nest Mini"));
        // Falls back to system_build_number when cast_build_revision is absent.
        assert_eq!(info.build_revision.as_deref(), Some("1.56.275975"));
        assert_eq!(info.ssid, None);
        assert_eq!(info.bssid, None);
        assert!(!info.auth_token_hash_present);
        assert!(!info.cloud_device_id_present);
    }

    #[test]
    fn parses_minimal_ssdp_udn_only_response() {
        let info = parse_eureka_info(r#"{"ssdp_udn":"abc"}"#).expect("cast-shaped body");
        assert_eq!(info, EurekaInfo::default());
    }

    #[test]
    fn rejects_non_cast_json() {
        assert_eq!(parse_eureka_info(r#"{"status":"ok","uptime":12}"#), None);
        assert_eq!(parse_eureka_info("{}"), None);
    }

    #[test]
    fn rejects_non_object_and_invalid_json() {
        assert_eq!(parse_eureka_info("[1,2,3]"), None);
        assert_eq!(parse_eureka_info("null"), None);
        assert_eq!(parse_eureka_info("\"device_info\""), None);
        assert_eq!(parse_eureka_info("<html>403</html>"), None);
        assert_eq!(parse_eureka_info(""), None);
    }

    #[test]
    fn blank_and_wrongly_typed_fields_become_none() {
        let body = r#"{"device_info":{"model_name":"   ","mac_address":12345},"name":""}"#;
        let info = parse_eureka_info(body).expect("cast-shaped body");
        assert_eq!(info.model_name, None);
        assert_eq!(info.mac_address, None);
        assert_eq!(info.name, None);
    }

    #[test]
    fn top_level_fallback_paths_are_used() {
        let body =
            r#"{"build_info":{},"ssid":"Flat-5G","bssid":"AA:BB:CC:DD:EE:FF","timezone":"UTC"}"#;
        let info = parse_eureka_info(body).expect("cast-shaped body");
        assert_eq!(info.ssid.as_deref(), Some("Flat-5G"));
        assert_eq!(info.bssid.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(info.timezone.as_deref(), Some("UTC"));
    }

    #[test]
    fn null_sensitive_fields_are_not_counted_as_present() {
        let body =
            r#"{"device_info":{"local_authorization_token_hash":null,"cloud_device_id":null}}"#;
        let info = parse_eureka_info(body).expect("cast-shaped body");
        assert!(!info.auth_token_hash_present);
        assert!(!info.cloud_device_id_present);
    }

    // ── labelling and classification ────────────────────────────────

    #[test]
    fn device_label_prefers_model_then_product_then_generic() {
        let info = parse_eureka_info(CHROMECAST_FIXTURE).expect("cast-shaped body");
        assert_eq!(device_label(&info), "Chromecast");

        let product_only = EurekaInfo {
            product_name: Some("Chromecast Ultra".to_owned()),
            ..EurekaInfo::default()
        };
        assert_eq!(device_label(&product_only), "Chromecast Ultra");
        assert_eq!(device_label(&EurekaInfo::default()), "Google Cast device");
    }

    #[test]
    fn classifies_media_players_and_televisions() {
        let cases: &[(&str, DeviceType)] = &[
            ("Chromecast", DeviceType::MediaPlayer),
            ("Google Nest Mini", DeviceType::MediaPlayer),
            ("Google Home Max", DeviceType::MediaPlayer),
            ("Chromecast built-in TV", DeviceType::SmartTv),
            ("SONY BRAVIA 4K GB ATV3", DeviceType::SmartTv),
            ("Smart Display", DeviceType::SmartTv),
        ];
        for (model, expected) in cases {
            let info = EurekaInfo {
                model_name: Some((*model).to_owned()),
                ..EurekaInfo::default()
            };
            assert_eq!(classify_cast_device(&info), *expected, "model {model}");
        }
    }

    #[test]
    fn friendly_name_never_drives_classification() {
        // An owner-named speaker must not be classified as a television.
        let info = EurekaInfo {
            name: Some("TV Room Speaker".to_owned()),
            model_name: Some("Google Nest Audio".to_owned()),
            ..EurekaInfo::default()
        };
        assert_eq!(classify_cast_device(&info), DeviceType::MediaPlayer);
    }

    // ── exposure assessment ─────────────────────────────────────────

    #[test]
    fn exposed_fields_lists_every_sensitive_value_returned() {
        let info = parse_eureka_info(CHROMECAST_FIXTURE).expect("cast-shaped body");
        assert_eq!(
            exposed_fields(&info),
            vec![
                "wifi.ssid",
                "wifi.bssid",
                "device_info.mac_address",
                "device_info.local_authorization_token_hash",
                "device_info.cloud_device_id",
                "settings.timezone",
            ]
        );
    }

    #[test]
    fn exposed_fields_empty_for_bare_response() {
        assert!(exposed_fields(&EurekaInfo::default()).is_empty());
    }

    #[test]
    fn empty_string_fields_are_not_disclosure() {
        let info = parse_eureka_info(UNLINKED_FIXTURE).expect("cast-shaped body");
        assert!(!info.auth_token_hash_present);
        assert!(!info.cloud_device_id_present);
        assert!(exposed_fields(&info).is_empty());
        assert_eq!(exposure_severity(&exposed_fields(&info)), None);
    }

    #[test]
    fn exposure_severity_tiers() {
        assert_eq!(exposure_severity(&[]), None);
        assert_eq!(
            exposure_severity(&["wifi.ssid", "settings.timezone"]),
            Some(Severity::Low)
        );
        assert_eq!(
            exposure_severity(&["device_info.mac_address"]),
            Some(Severity::Low)
        );
        assert_eq!(exposure_severity(&["wifi.bssid"]), Some(Severity::Medium));
        assert_eq!(
            exposure_severity(&["device_info.local_authorization_token_hash"]),
            Some(Severity::Medium)
        );
    }

    // ── URL construction ────────────────────────────────────────────

    #[test]
    fn eureka_url_uses_literal_address_authority() {
        let v4 = eureka_url("https", "192.168.1.52".parse().expect("ip"), 8443);
        assert!(v4.starts_with("https://192.168.1.52:8443/setup/eureka_info?params="));
        let v6 = eureka_url("http", "fe80::1".parse().expect("ip"), 8008);
        assert!(v6.starts_with("http://[fe80::1]:8008/setup/eureka_info?"));
    }

    // ── TLS response classification ─────────────────────────────────

    #[test]
    fn classifies_server_hello() {
        // Handshake record, TLS 1.2, ServerHello (type 0x02).
        let bytes = [
            0x16, 0x03, 0x03, 0x00, 0x51, 0x02, 0x00, 0x00, 0x4D, 0x03, 0x03,
        ];
        assert_eq!(
            classify_tls_response(&bytes),
            Some(TlsResponse::ServerHello)
        );
    }

    #[test]
    fn classifies_alert_as_tls() {
        // Alert record: fatal(2) / handshake_failure(40).
        let bytes = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert_eq!(classify_tls_response(&bytes), Some(TlsResponse::Alert));
        assert!(TlsResponse::Alert.is_tls());
    }

    #[test]
    fn classifies_other_handshake_record() {
        // Handshake record whose first message is Certificate (0x0B).
        let bytes = [0x16, 0x03, 0x01, 0x00, 0x04, 0x0B, 0x00, 0x00, 0x00];
        assert_eq!(classify_tls_response(&bytes), Some(TlsResponse::Handshake));
    }

    #[test]
    fn classifies_non_tls_responses() {
        assert_eq!(
            classify_tls_response(b"HTTP/1.1 400 Bad Request"),
            Some(TlsResponse::NotTls)
        );
        // AJP13 response prefix "AB".
        assert_eq!(
            classify_tls_response(&[0x41, 0x42, 0x00, 0x01]),
            Some(TlsResponse::NotTls)
        );
        // Right content type, impossible version.
        assert_eq!(
            classify_tls_response(&[0x16, 0x03, 0x09, 0x00]),
            Some(TlsResponse::NotTls)
        );
        assert_eq!(
            classify_tls_response(&[0x16, 0x02, 0x00, 0x00]),
            Some(TlsResponse::NotTls)
        );
        assert!(!TlsResponse::NotTls.is_tls());
    }

    #[test]
    fn short_response_is_inconclusive() {
        assert_eq!(classify_tls_response(&[]), None);
        assert_eq!(classify_tls_response(&[0x16, 0x03]), None);
    }

    // ── ClientHello construction ────────────────────────────────────

    #[test]
    fn client_hello_record_is_well_formed() {
        let hello = build_client_hello();
        assert_eq!(hello[0], 0x16, "handshake record");
        assert_eq!(&hello[1..3], &[0x03, 0x01], "record-layer version");

        let record_len = usize::from(u16::from_be_bytes([hello[3], hello[4]]));
        assert_eq!(hello.len(), 5 + record_len, "record length matches payload");

        assert_eq!(hello[5], 0x01, "ClientHello");
        let hs_len = usize::from(u16::from_be_bytes([hello[7], hello[8]]))
            + usize::from(hello[6]) * 0x0001_0000;
        assert_eq!(hs_len, record_len - 4, "handshake length matches body");

        assert_eq!(&hello[9..11], &[0x03, 0x03], "client_version TLS 1.2");
        assert_eq!(&hello[11..43], &CLIENT_HELLO_RANDOM);
        assert_eq!(hello[43], 0x00, "empty session id");
        let cipher_bytes = usize::from(u16::from_be_bytes([hello[44], hello[45]]));
        assert_eq!(cipher_bytes, CLIENT_HELLO_CIPHERS.len() * 2);
    }

    #[test]
    fn client_hello_offers_null_compression_and_extensions() {
        let hello = build_client_hello();
        let comp_at = 46 + CLIENT_HELLO_CIPHERS.len() * 2;
        assert_eq!(&hello[comp_at..comp_at + 2], &[0x01, 0x00]);
        let ext_len = usize::from(u16::from_be_bytes([hello[comp_at + 2], hello[comp_at + 3]]));
        assert_eq!(ext_len, build_extensions().len());
        assert_eq!(hello.len(), comp_at + 4 + ext_len);
    }

    #[test]
    fn client_hello_is_deterministic() {
        assert_eq!(build_client_hello(), build_client_hello());
    }

    #[test]
    fn extensions_are_length_prefixed_triples() {
        let ext = build_extensions();
        let mut offset = 0;
        let mut types = Vec::new();
        while offset + 4 <= ext.len() {
            let ext_type = u16::from_be_bytes([ext[offset], ext[offset + 1]]);
            let len = usize::from(u16::from_be_bytes([ext[offset + 2], ext[offset + 3]]));
            types.push(ext_type);
            offset += 4 + len;
        }
        assert_eq!(offset, ext.len(), "extensions consume the buffer exactly");
        assert_eq!(types, vec![0x000A, 0x000B, 0x000D]);
    }

    // ── target selection ────────────────────────────────────────────

    #[test]
    fn selects_only_hosts_with_cast_ports() {
        let devices = [
            device_with("192.168.1.52", &[8008, 8009, 8443]),
            device_with("192.168.1.53", &[80, 443]),
            device_with("192.168.1.54", &[8009]),
        ];
        let exclusions = ExclusionSet::parse(&[], &[]).expect("empty exclusions");
        let targets = select_cast_targets(&devices, &exclusions);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].ports, vec![8008, 8009, 8443]);
        assert_eq!(targets[1].ip.to_string(), "192.168.1.54");
    }

    #[test]
    fn ignores_udp_ports_with_cast_numbers() {
        let mut device = Device::new("192.168.1.55".parse().expect("ip"));
        device.open_ports = vec![OpenPort {
            port: 8009,
            protocol: PortProtocol::Udp,
            service: None,
            version: None,
            banner: None,
        }];
        let exclusions = ExclusionSet::parse(&[], &[]).expect("empty exclusions");
        assert!(select_cast_targets(&[device], &exclusions).is_empty());
    }

    #[test]
    fn honours_ip_cidr_and_mac_exclusions() {
        let mut excluded_mac = device_with("192.168.1.60", &[8443]);
        excluded_mac.mac = "AA:BB:CC:DD:EE:FF".parse().ok();
        let devices = [
            device_with("192.168.1.52", &[8443]),
            device_with("192.168.1.61", &[8443]),
            device_with("10.0.0.2", &[8443]),
            excluded_mac,
        ];
        let exclusions = ExclusionSet::parse(
            &["10.0.0.0/30".to_owned()],
            &["192.168.1.61".to_owned(), "aa:bb:cc:dd:ee:ff".to_owned()],
        )
        .expect("exclusions parse");
        let targets = select_cast_targets(&devices, &exclusions);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].ip.to_string(), "192.168.1.52");
    }

    // ── finding builders ────────────────────────────────────────────

    #[test]
    fn identification_finding_is_confirmed_and_carries_a_device_hint() {
        let ip: IpAddr = "192.168.1.52".parse().expect("ip");
        let info = parse_eureka_info(CHROMECAST_FIXTURE).expect("cast-shaped body");
        let finding = build_identification_finding(ip, 8443, &info);

        assert_eq!(
            finding.title,
            "Google Cast device identified on 192.168.1.52:8443"
        );
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.affected_port, Some(8443));
        assert!(finding.affected_mac.is_some());

        let hint = finding.device_hint.expect("device hint");
        // Model "Chromecast" types as a media player even though the owner named it "TV".
        assert_eq!(hint.device_type, Some(DeviceType::MediaPlayer));
        assert_eq!(hint.vendor.as_deref(), Some("Google Inc."));
        assert_eq!(hint.model.as_deref(), Some("Chromecast"));
        assert_eq!(hint.hostname.as_deref(), Some("Living Room TV"));
    }

    #[test]
    fn identification_finding_defaults_vendor_when_undisclosed() {
        let ip: IpAddr = "192.168.1.52".parse().expect("ip");
        let finding = build_identification_finding(ip, 8008, &EurekaInfo::default());
        let hint = finding.device_hint.expect("device hint");
        assert_eq!(hint.vendor.as_deref(), Some("Google"));
        assert_eq!(hint.model, None);
        assert_eq!(finding.affected_mac, None);
        assert!(finding.description.contains("Google Cast device"));
    }

    #[test]
    fn exposure_finding_names_fields_and_never_prints_token_material() {
        let ip: IpAddr = "192.168.1.52".parse().expect("ip");
        let info = parse_eureka_info(CHROMECAST_FIXTURE).expect("cast-shaped body");
        let fields = exposed_fields(&info);
        let severity = exposure_severity(&fields).expect("sensitive fields present");
        let finding = build_exposure_finding(ip, 8443, false, &info, &fields, severity);

        assert_eq!(
            finding.title,
            "Google Cast setup endpoint discloses device and network details on 192.168.1.52:8443"
        );
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-200"));
        assert!(finding.remediation.is_some());
        assert!(finding.description.contains("wifi.bssid"));
        assert!(finding.description.contains("Home-2G"));
        // The token hash is reported by name only.
        let rendered = format!("{} {:?}", finding.description, finding.evidence);
        assert!(!rendered.contains("hZm0d5S1Q0rN2hQ"));
    }

    #[test]
    fn exposure_finding_flags_plaintext_transport() {
        let ip: IpAddr = "192.168.1.52".parse().expect("ip");
        let info = parse_eureka_info(NEST_MINI_FIXTURE).expect("cast-shaped body");
        let fields = exposed_fields(&info);
        let finding = build_exposure_finding(ip, 8008, true, &info, &fields, Severity::Low);
        assert!(finding.description.contains("plaintext HTTP"));
    }

    #[test]
    fn protocol_port_finding_confidence_depends_on_corroboration() {
        let ip: IpAddr = "192.168.1.52".parse().expect("ip");
        let confirmed = build_protocol_port_finding(ip, 8009, TlsResponse::ServerHello, true);
        assert_eq!(confirmed.confidence, Confidence::Confirmed);
        assert_eq!(
            confirmed.title,
            "Google Cast control channel open on 192.168.1.52:8009"
        );

        let alone = build_protocol_port_finding(ip, 8009, TlsResponse::Alert, false);
        assert_eq!(alone.confidence, Confidence::Probable);
        assert!(alone.description.contains("registered to other services"));
    }

    #[test]
    fn scanner_metadata_is_stable() {
        let scanner = CastScanner;
        assert_eq!(scanner.id(), "cast");
        assert_eq!(scanner.relevant_ports(), &[8443, 8009, 8008]);
        assert!(
            scanner
                .supported_perspectives()
                .contains(&Perspective::Unauthenticated)
        );
        assert!(!scanner.requires_privileges());
    }

    // ── Proptests ───────────────────────────────────────────────────

    proptest! {
        /// The eureka parser never panics on arbitrary text.
        #[test]
        fn prop_parse_eureka_info_no_panic(body in ".{0,512}") {
            let _ = parse_eureka_info(&body);
        }

        /// Nor on arbitrary bytes decoded the way a response body would be.
        #[test]
        fn prop_parse_eureka_info_bytes_no_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..512)
        ) {
            let body = String::from_utf8_lossy(&bytes);
            let _ = parse_eureka_info(&body);
        }

        /// A parsed response either carries a Cast container or is rejected.
        #[test]
        fn prop_parse_requires_cast_container(body in ".{0,256}") {
            if parse_eureka_info(&body).is_some() {
                prop_assert!(
                    ["device_info", "build_info", "ssdp_udn", "opt_in"]
                        .iter()
                        .any(|k| body.contains(k))
                );
            }
        }

        /// The TLS classifier never panics on arbitrary bytes.
        #[test]
        fn prop_classify_tls_response_no_panic(
            data in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            let _ = classify_tls_response(&data);
        }

        /// Only a handshake record whose first message is ServerHello classifies as one.
        #[test]
        fn prop_server_hello_requires_handshake_record(
            data in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            if classify_tls_response(&data) == Some(TlsResponse::ServerHello) {
                prop_assert!(data.len() >= 6);
                prop_assert_eq!(data[0], 0x16);
                prop_assert_eq!(data[1], 0x03);
                prop_assert_eq!(data[5], 0x02);
            }
        }

        /// Any TLS verdict implies a plausible record version.
        #[test]
        fn prop_tls_verdict_implies_version(
            data in proptest::collection::vec(any::<u8>(), 3..256)
        ) {
            if classify_tls_response(&data).is_some_and(TlsResponse::is_tls) {
                prop_assert_eq!(data[1], 0x03);
                prop_assert!(data[2] <= 0x04);
            }
        }

        /// Target selection never yields an excluded address or a non-Cast port.
        #[test]
        fn prop_select_targets_respects_ports(
            ports in proptest::collection::vec(any::<u16>(), 0..8)
        ) {
            let mut device = Device::new("192.168.1.52".parse().expect("ip"));
            device.open_ports = ports.iter().copied().map(tcp_port).collect();
            let exclusions = ExclusionSet::parse(&[], &[]).expect("empty exclusions");
            for target in select_cast_targets(&[device], &exclusions) {
                for port in target.ports {
                    prop_assert!(CAST_PORTS.contains(&port));
                }
            }
        }

        /// Building an identification finding never panics, whatever the device said.
        #[test]
        fn prop_identification_finding_no_panic(
            model in ".{0,64}",
            name in ".{0,64}",
            mac in ".{0,32}",
        ) {
            let info = EurekaInfo {
                model_name: Some(model),
                name: Some(name),
                mac_address: Some(mac),
                ..EurekaInfo::default()
            };
            let ip: IpAddr = "192.168.1.52".parse().expect("ip");
            let finding = build_identification_finding(ip, 8443, &info);
            prop_assert!(!finding.title.is_empty());
        }
    }

    // ── Loopback probe tests ────────────────────────────────────────

    /// Serve `response` to one connection on loopback; return the bytes received.
    async fn one_shot_server(response: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 2048];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            buf.truncate(n);
            let _ = sock.write_all(&response).await;
            let _ = sock.flush().await;
            buf
        });
        (addr, handle)
    }

    fn http_response(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn fetch_eureka_parses_a_loopback_cast_response() {
        let (addr, _server) = one_shot_server(http_response("200 OK", CHROMECAST_FIXTURE)).await;
        let client = unauthenticated_probe_client(HTTP_TIMEOUT, reqwest::redirect::Policy::none())
            .expect("probe client");
        let info = fetch_eureka(&client, addr.ip(), addr.port(), "http")
            .await
            .expect("eureka parsed");
        assert_eq!(info.model_name.as_deref(), Some("Chromecast"));
        assert_eq!(info.ssid.as_deref(), Some("Home-2G"));
    }

    #[tokio::test]
    async fn fetch_eureka_ignores_non_success_status() {
        let (addr, _server) = one_shot_server(http_response("403 Forbidden", "{}")).await;
        let client = unauthenticated_probe_client(HTTP_TIMEOUT, reqwest::redirect::Policy::none())
            .expect("probe client");
        assert_eq!(
            fetch_eureka(&client, addr.ip(), addr.port(), "http").await,
            None
        );
    }

    #[tokio::test]
    async fn probe_cast_tls_sends_a_client_hello_and_reads_a_server_hello() {
        let server_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x51, 0x02, 0x00, 0x00, 0x4D, 0x03, 0x03,
        ];
        let (addr, server) = one_shot_server(server_hello).await;
        let verdict = probe_cast_tls(addr.ip(), addr.port()).await;
        assert_eq!(verdict, Some(TlsResponse::ServerHello));
        let received = server.await.expect("server task");
        assert_eq!(received, build_client_hello(), "probe sent a ClientHello");
    }

    #[tokio::test]
    async fn probe_cast_tls_rejects_a_plain_http_listener() {
        let (addr, _server) = one_shot_server(b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec()).await;
        let verdict = probe_cast_tls(addr.ip(), addr.port()).await;
        assert_eq!(verdict, Some(TlsResponse::NotTls));
        assert!(!verdict.expect("verdict").is_tls());
    }
}

/// Parser entry points for the fuzz harness.
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    #[must_use]
    pub fn eureka(body: &str) -> bool {
        super::parse_eureka_info(body).is_some()
    }
    #[must_use]
    pub fn tls(data: &[u8]) -> bool {
        super::classify_tls_response(data).is_some()
    }
}
