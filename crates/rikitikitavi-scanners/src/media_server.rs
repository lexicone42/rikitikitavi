//! Home media servers: Plex (32400) and Jellyfin (8096 / 8920 / UDP 7359).
//!
//! Read-only and unauthenticated. Plex is identified from `GET /identity`, which
//! returns the machine identifier and version to any peer; `/myplex/account`,
//! the endpoint CVE-2025-34158 abuses, is never requested. Jellyfin is
//! identified from `GET /System/Info/Public`, the only unauthenticated source of
//! its version, optionally located first by the UDP/7359 discovery datagram,
//! which works unicast and needs no broadcast. The `Address` in a discovery reply
//! is attacker-controlled text: it is accepted only when its host is the literal
//! IP that sent the reply, and the URL that is then fetched is rebuilt from that
//! IP, so a reply can never steer a request at a third host or past an exclusion.
//!
//! Version checks: CVE-2020-5741 (Plex Media Server before 1.19.3, CISA KEV) and
//! CVE-2025-34158 (1.41.7.x-1.42.0.x, fixed 1.42.1). Both are reported at
//! Probable — a version string is a banner, not a demonstration.

use async_trait::async_trait;
use reqwest::redirect::Policy;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, Remediation, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::Scanner;

/// Plex / Jellyfin media-server scanner.
pub struct MediaServerScanner;

const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
/// Both responses are small JSON/XML documents.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// Plex Media Server.
const PLEX_PORT: u16 = 32400;
/// Jellyfin HTTP.
const JELLYFIN_PORT: u16 = 8096;
/// Jellyfin HTTPS.
const JELLYFIN_TLS_PORT: u16 = 8920;
/// Jellyfin UDP discovery.
const JELLYFIN_DISCOVERY_PORT: u16 = 7359;

/// HTTP ports probed per device. Not returned from `relevant_ports`: 8096 and
/// 8920 are in neither the common nor the extended sweep list, so gating the
/// whole scanner on them would skip the UDP/7359 discovery, which needs no TCP
/// port at all. Gating happens per device inside `scan` instead.
const MEDIA_PORTS: &[u16] = &[PLEX_PORT, JELLYFIN_PORT, JELLYFIN_TLS_PORT];

/// The only Plex path this scanner requests.
const PLEX_PATH: &str = "/identity";
/// The only Jellyfin path this scanner requests.
const JELLYFIN_PATH: &str = "/System/Info/Public";

/// Jellyfin's UDP discovery question, sent verbatim by its own clients.
const JELLYFIN_DISCOVERY_QUERY: &[u8] = b"who is JellyfinServer?";

/// Window for collecting UDP discovery replies.
const DISCOVERY_WINDOW: Duration = Duration::from_secs(2);

/// Replies accepted from the discovery socket.
const MAX_DISCOVERY_REPLIES: usize = 64;

/// `Plex Media Server` before this release: CVE-2020-5741 (CISA KEV).
const PLEX_KEV_FIXED: [u32; 3] = [1, 19, 3];
/// First release in the CVE-2025-34158 range.
const PLEX_2025_FIRST: [u32; 3] = [1, 41, 7];
/// Release that fixes CVE-2025-34158.
const PLEX_2025_FIXED: [u32; 3] = [1, 42, 1];

// ── Version handling ────────────────────────────────────────────────────────

/// Parse the leading dotted-numeric part of a version string.
///
/// Plex reports `1.41.3.9314-a0bfb8370` and Jellyfin `10.10.7`; both stop at the
/// first component that is not a run of digits.
fn parse_version(raw: &str) -> Option<Vec<u32>> {
    let mut parts = Vec::new();
    for field in raw.trim().split('.') {
        let digits: String = field.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            break;
        }
        parts.push(digits.parse().ok()?);
        if digits.len() != field.len() {
            break;
        }
    }
    (!parts.is_empty()).then_some(parts)
}

/// Compare two version component lists, padding the shorter with zeros.
fn version_cmp(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    let len = a.len().max(b.len());
    for i in 0..len {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        match x.cmp(&y) {
            std::cmp::Ordering::Equal => {}
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Which published Plex issue a version falls under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlexVerdict {
    /// Before 1.19.3 — CVE-2020-5741, in CISA KEV.
    KevRce,
    /// 1.41.7.x-1.42.0.x — CVE-2025-34158.
    CredentialExposure,
    /// Outside both ranges.
    Current,
    /// No version was readable.
    Unknown,
}

/// Classify a parsed Plex version.
fn classify_plex(version: Option<&[u32]>) -> PlexVerdict {
    let Some(version) = version else {
        return PlexVerdict::Unknown;
    };
    if version_cmp(version, &PLEX_KEV_FIXED).is_lt() {
        return PlexVerdict::KevRce;
    }
    if version_cmp(version, &PLEX_2025_FIRST).is_ge()
        && version_cmp(version, &PLEX_2025_FIXED).is_lt()
    {
        return PlexVerdict::CredentialExposure;
    }
    PlexVerdict::Current
}

// ── Plex response parsing ───────────────────────────────────────────────────

/// What `GET /identity` disclosed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PlexIdentity {
    machine_identifier: Option<String>,
    version: Option<String>,
    /// `claimed="1"` means the server is bound to a Plex account.
    claimed: Option<bool>,
}

/// Value of an XML attribute in the first `MediaContainer` element.
fn xml_attr(body: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = body.find(&needle)? + needle.len();
    let rest = body.get(start..)?;
    let end = rest.find('"')?;
    let value = rest.get(..end)?.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// Parse a Plex `/identity` response. `None` unless it looks like Plex.
///
/// Attributes are read from the `MediaContainer` element onwards, so the XML
/// prolog's own `version="1.0"` is not mistaken for the server version.
fn parse_plex_identity(body: &str) -> Option<PlexIdentity> {
    let element = body.get(body.find("<MediaContainer")?..)?;
    let identity = PlexIdentity {
        machine_identifier: xml_attr(element, "machineIdentifier"),
        version: xml_attr(element, "version"),
        claimed: xml_attr(element, "claimed").map(|v| v == "1" || v.eq_ignore_ascii_case("true")),
    };
    // `MediaContainer` alone is also the wrapper for error documents; require a
    // field only a real server emits.
    (identity.machine_identifier.is_some() || identity.version.is_some()).then_some(identity)
}

// ── Jellyfin response parsing ───────────────────────────────────────────────

/// What `GET /System/Info/Public` disclosed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct JellyfinInfo {
    server_name: Option<String>,
    version: Option<String>,
    operating_system: Option<String>,
    id: Option<String>,
    /// `false` means the first-run wizard has not been completed.
    startup_wizard_completed: Option<bool>,
}

/// Parse a Jellyfin public system-info document.
fn parse_jellyfin_info(body: &str) -> Option<JellyfinInfo> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let object = value.as_object()?;
    let string = |key: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
    };
    let info = JellyfinInfo {
        server_name: string("ServerName"),
        version: string("Version"),
        operating_system: string("OperatingSystem"),
        id: string("Id"),
        startup_wizard_completed: object
            .get("StartupWizardCompleted")
            .and_then(serde_json::Value::as_bool),
    };
    // Emby serves the same endpoint on the same port with the same fields —
    // Jellyfin is a fork of it — so a ProductName that names another product is
    // a rejection, not a missing signal. The version+id shape is a fallback only
    // when no ProductName is present at all.
    let looks_like_jellyfin = match string("ProductName") {
        Some(product) => product.to_ascii_lowercase().contains("jellyfin"),
        None => info.version.is_some() && info.id.is_some(),
    };
    looks_like_jellyfin.then_some(info)
}

/// Parse a Jellyfin UDP discovery reply: `{"Address":"http://ip:8096","Id":…}`.
/// Returns the advertised base address, unvalidated — see `discovery_target`.
fn parse_jellyfin_discovery(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let address = value.get("Address")?.as_str()?.trim().trim_end_matches('/');
    if !address.starts_with("http://") && !address.starts_with("https://") {
        return None;
    }
    Some(address.to_owned())
}

/// Split a URL authority into host and port, honouring the `[v6]:port` form.
fn split_authority(authority: &str, default_port: u16) -> Option<(&str, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail {
            "" => default_port,
            _ => tail.strip_prefix(':')?.parse().ok()?,
        };
        return Some((host, port));
    }
    // Unbracketed, an IPv6 literal is ambiguous with host:port, so RFC 3986
    // requires the brackets; more than one colon here is malformed.
    if authority.matches(':').count() > 1 {
        return None;
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, port.parse().ok()?)),
        None => Some((authority, default_port)),
    }
}

/// Port and a base URL rebuilt from `from`, for a discovery `address`.
///
/// The address is whatever the responder chose to send, so it is accepted only
/// when its host is the literal IP the datagram came from. Everything fetched
/// afterwards is built from `from`, never from the responder's string, so no
/// path, query or userinfo in the reply survives and no request can be aimed at
/// a host the caller has not already checked against the exclusions.
fn discovery_target(from: IpAddr, address: &str) -> Option<(u16, String)> {
    let (scheme, rest) = address.split_once("://")?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') {
        return None;
    }
    let (host, port) = split_authority(authority, default_port)?;
    if host.parse::<IpAddr>().ok()? != from {
        tracing::debug!(%from, address, "discovery reply advertises another host; ignored");
        return None;
    }
    let base = match from {
        IpAddr::V4(v4) => format!("{scheme}://{v4}:{port}"),
        IpAddr::V6(v6) => format!("{scheme}://[{v6}]:{port}"),
    };
    Some((port, base))
}

// ── Findings ────────────────────────────────────────────────────────────────

fn plex_references() -> Vec<String> {
    refs![
        "https://cveawg.mitre.org/api/cve/CVE-2025-34158",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-5741",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "https://forums.plex.tv/t/plex-media-server-security-updates/",
    ]
}

fn plex_remediation() -> Remediation {
    Remediation {
        description: "Update Plex Media Server and keep the server port off untrusted \
                      network segments."
            .to_owned(),
        steps: vec![
            "Update Plex Media Server to the current release from Settings > General.".to_owned(),
            "Turn off manual port forwarding and UPnP for TCP 32400 unless remote access \
             is genuinely needed; Plex's own Remote Access relay does not require it."
                .to_owned(),
            "Review Settings > Users for shared accounts that no longer need access — the \
             2025 issue is exploitable by any signed-in user of the server."
                .to_owned(),
            "Enable 'Require authentication on local network' so LAN clients are not \
             granted admin-equivalent access implicitly."
                .to_owned(),
        ],
        effort: Some("15 minutes".to_owned()),
    }
}

fn plex_evidence(identity: &PlexIdentity, url: &str) -> String {
    let mut parts = vec![format!("GET {url}")];
    if let Some(version) = &identity.version {
        parts.push(format!("version={version}"));
    }
    if let Some(id) = &identity.machine_identifier {
        parts.push(format!("machineIdentifier={id}"));
    }
    if let Some(claimed) = identity.claimed {
        parts.push(format!("claimed={claimed}"));
    }
    parts.join("; ")
}

/// Finding for one Plex server.
fn plex_finding(ip: IpAddr, port: u16, identity: &PlexIdentity, url: &str) -> Finding {
    let parsed = identity.version.as_deref().and_then(parse_version);
    let verdict = classify_plex(parsed.as_deref());
    let reported = identity.version.as_deref().unwrap_or("unknown");

    let (title, description, severity, confidence) = match verdict {
        PlexVerdict::KevRce => (
            format!("Plex Media Server below 1.19.3 on {ip}:{port}"),
            format!(
                "The Plex Media Server at {ip}:{port} reports version {reported}, which is \
                 before the 1.19.3 release that fixed CVE-2020-5741. That issue lets someone \
                 who holds the server's own Plex account run code on the host through the \
                 Camera Upload path, and CISA lists it as exploited in the wild. The version \
                 is read from the unauthenticated /identity endpoint, so this is a banner \
                 match rather than a demonstration. Update the server."
            ),
            Severity::High,
            Confidence::Probable,
        ),
        PlexVerdict::CredentialExposure => (
            format!("Plex Media Server exposes owner credentials on {ip}:{port}"),
            format!(
                "The Plex Media Server at {ip}:{port} reports version {reported}, inside the \
                 1.41.7.x-1.42.0.x range affected by CVE-2025-34158 and before the 1.42.1 \
                 fix. In that range an authenticated low-privilege user of the server — any \
                 account it is shared with — can read the owner's account credentials from \
                 the /myplex/account endpoint. This is not unauthenticated LAN takeover: it \
                 needs a signed-in user. This scan read only /identity and never requested \
                 the affected endpoint. Update to 1.42.1 or later."
            ),
            Severity::Medium,
            Confidence::Probable,
        ),
        PlexVerdict::Current | PlexVerdict::Unknown => (
            format!("Plex Media Server reachable on {ip}:{port}"),
            format!(
                "The host at {ip}:{port} runs Plex Media Server (reported version \
                 {reported}). Its /identity endpoint answers unauthenticated requests with \
                 the server version and machine identifier, which is normal for Plex but \
                 means any host on this network can fingerprint the server and track it \
                 across IP changes. No published issue matches the reported version. Keep \
                 the server updated and confirm TCP 32400 is not forwarded from the internet."
            ),
            Severity::Info,
            if verdict == PlexVerdict::Unknown {
                Confidence::Inferred
            } else {
                Confidence::Confirmed
            },
        ),
    };

    let finding = Finding::new("media_server", &title, &description, severity)
        .with_confidence(confidence)
        .with_ip(ip)
        .with_port(port)
        .with_service("Plex Media Server")
        .with_evidence(plex_evidence(identity, url))
        .with_remediation(plex_remediation())
        .with_references(plex_references())
        .with_device_hint(
            DeviceHint::new()
                .with_device_type(DeviceType::Server)
                .with_device_subtype("plex_media_server"),
        );

    match verdict {
        PlexVerdict::KevRce => finding
            .with_cwe("CWE-502")
            .with_cve_ids(vec!["CVE-2020-5741".to_owned()]),
        PlexVerdict::CredentialExposure => finding
            .with_cwe("CWE-669")
            .with_cve_ids(vec!["CVE-2025-34158".to_owned()]),
        PlexVerdict::Current | PlexVerdict::Unknown => finding,
    }
}

fn jellyfin_references() -> Vec<String> {
    refs![
        "https://jellyfin.org/docs/general/post-install/networking/",
        "https://jellyfin.org/docs/general/quick-start/",
        "https://cwe.mitre.org/data/definitions/306.html",
    ]
}

fn jellyfin_evidence(info: &JellyfinInfo, url: &str) -> String {
    let mut parts = vec![format!("GET {url}")];
    if let Some(name) = &info.server_name {
        parts.push(format!("ServerName={name}"));
    }
    if let Some(version) = &info.version {
        parts.push(format!("Version={version}"));
    }
    if let Some(os) = &info.operating_system {
        parts.push(format!("OperatingSystem={os}"));
    }
    if let Some(done) = info.startup_wizard_completed {
        parts.push(format!("StartupWizardCompleted={done}"));
    }
    parts.join("; ")
}

/// Presence finding for one Jellyfin server.
fn jellyfin_finding(ip: IpAddr, port: u16, info: &JellyfinInfo, url: &str) -> Finding {
    let version = info.version.as_deref().unwrap_or("unknown");
    let os = info.operating_system.as_deref().unwrap_or("unreported");

    Finding::new(
        "media_server",
        &format!("Jellyfin media server reachable on {ip}:{port}"),
        &format!(
            "The host at {ip}:{port} runs Jellyfin (version {version}, host OS {os}). \
             /System/Info/Public answers unauthenticated requests with the server version, \
             name, host operating system and a stable server id — by design, since clients \
             need it before login, but it also lets any host on this network fingerprint \
             the server and match its version against published issues. Keep Jellyfin \
             updated and do not forward its port from the internet without a reverse proxy \
             that terminates TLS."
        ),
        Severity::Info,
    )
    .with_confidence(Confidence::Confirmed)
    .with_ip(ip)
    .with_port(port)
    .with_service("Jellyfin")
    .with_cwe("CWE-200")
    .with_evidence(jellyfin_evidence(info, url))
    .with_references(jellyfin_references())
    .with_device_hint(
        DeviceHint::new()
            .with_device_type(DeviceType::Server)
            .with_device_subtype("jellyfin"),
    )
}

/// First-run wizard still open: anyone on the network can claim the server.
fn jellyfin_wizard_finding(
    ip: IpAddr,
    port: u16,
    info: &JellyfinInfo,
    url: &str,
) -> Option<Finding> {
    if info.startup_wizard_completed != Some(false) {
        return None;
    }
    Some(
        Finding::new(
            "media_server",
            &format!("Jellyfin first-run setup is still open on {ip}:{port}"),
            &format!(
                "The Jellyfin server at {ip}:{port} reports StartupWizardCompleted=false, so \
                 it has never completed first-run setup. Until the wizard is finished the \
                 setup endpoints accept unauthenticated requests, and whoever completes it \
                 creates the first administrator account — on this network that is anyone \
                 who can reach the port. Finish the setup wizard now from a trusted host, \
                 or stop the server until you can."
            ),
            Severity::High,
        )
        .with_confidence(Confidence::Confirmed)
        .with_ip(ip)
        .with_port(port)
        .with_service("Jellyfin")
        .with_cwe("CWE-306")
        .with_evidence(jellyfin_evidence(info, url))
        .with_remediation(Remediation {
            description: "Complete the Jellyfin setup wizard from a trusted host so the \
                          server stops accepting unauthenticated setup requests."
                .to_owned(),
            steps: vec![
                "Open the server in a browser from a trusted machine and complete the \
                 wizard, setting a strong administrator password."
                    .to_owned(),
                "If the server was already reachable while unconfigured, check \
                 Dashboard > Users for accounts you did not create."
                    .to_owned(),
                "Keep the server off guest and IoT network segments.".to_owned(),
            ],
            effort: Some("10 minutes".to_owned()),
        })
        .with_references(jellyfin_references()),
    )
}

// ── Probes ──────────────────────────────────────────────────────────────────

/// Fetch one URL, returning `(status, body)`; any failure is `None`.
async fn fetch(client: &reqwest::Client, url: &str) -> Option<(u16, String)> {
    let resp = tokio::time::timeout(HTTP_TIMEOUT, client.get(url).send())
        .await
        .ok()?
        .ok()?;
    let status = resp.status().as_u16();
    let body = crate::http_util::read_body_capped(resp, MAX_BODY_BYTES).await;
    Some((status, body))
}

/// Probe Plex on one port, trying HTTP then HTTPS: the server multiplexes both
/// on 32400 and refuses plaintext when "Secure connections" is set to Required.
async fn probe_plex(
    client: &reqwest::Client,
    ip: IpAddr,
    port: u16,
) -> Option<(PlexIdentity, String)> {
    for scheme in ["http", "https"] {
        let url = format!("{scheme}://{ip}:{port}{PLEX_PATH}");
        let Some((status, body)) = fetch(client, &url).await else {
            continue;
        };
        if status != 200 {
            continue;
        }
        if let Some(identity) = parse_plex_identity(&body) {
            return Some((identity, url));
        }
    }
    None
}

/// Probe Jellyfin at a base URL.
async fn probe_jellyfin_at(client: &reqwest::Client, base: &str) -> Option<(JellyfinInfo, String)> {
    let url = format!("{base}{JELLYFIN_PATH}");
    let (status, body) = fetch(client, &url).await?;
    if status != 200 {
        return None;
    }
    parse_jellyfin_info(&body).map(|info| (info, url))
}

/// Probe Jellyfin on one port, picking the scheme from the port.
async fn probe_jellyfin(
    client: &reqwest::Client,
    ip: IpAddr,
    port: u16,
) -> Option<(JellyfinInfo, String)> {
    let scheme = if port == JELLYFIN_TLS_PORT {
        "https"
    } else {
        "http"
    };
    probe_jellyfin_at(client, &format!("{scheme}://{ip}:{port}")).await
}

/// Ask each target the Jellyfin discovery question on UDP/7359 and return the
/// base addresses that answered. Unicast only: no broadcast is sent.
async fn discover_jellyfin(targets: &[IpAddr]) -> Vec<(IpAddr, String)> {
    let mut found = Vec::new();
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        tracing::debug!("could not bind a Jellyfin discovery socket");
        return found;
    };
    for &ip in targets {
        let dest = SocketAddr::new(ip, JELLYFIN_DISCOVERY_PORT);
        if let Err(e) = socket.send_to(JELLYFIN_DISCOVERY_QUERY, dest).await {
            tracing::debug!(%ip, "could not send the Jellyfin discovery query: {e}");
        }
    }

    let deadline = tokio::time::Instant::now() + DISCOVERY_WINDOW;
    let mut buf = vec![0u8; 4096];
    let mut seen = std::collections::HashSet::new();
    while found.len() < MAX_DISCOVERY_REPLIES {
        let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
        else {
            break;
        };
        let Some(chunk) = buf.get(..n) else { continue };
        // One reply per responder: a host that answers repeatedly must not fill
        // the cap or be probed twice.
        if !seen.insert(from.ip()) {
            continue;
        }
        if let Some(address) = parse_jellyfin_discovery(&String::from_utf8_lossy(chunk)) {
            found.push((from.ip(), address));
        }
    }
    found
}

#[async_trait]
impl Scanner for MediaServerScanner {
    fn id(&self) -> &'static str {
        "media_server"
    }

    fn name(&self) -> &'static str {
        "Plex / Jellyfin Media Servers"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running media-server scan");
        let mut findings = Vec::new();

        // Network probe: Active intensity and above only.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping media-server scan in quick scan mode");
            return Ok(findings);
        }

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "media_server".to_owned(),
                message: e.to_string(),
            })?;

        let Ok(client) =
            crate::http_util::unauthenticated_probe_client(HTTP_TIMEOUT, Policy::none())
        else {
            return Err(ScanError::ScannerFailed {
                scanner: "media_server".to_owned(),
                message: "could not build an HTTP client".to_owned(),
            });
        };

        let targets: Vec<IpAddr> = ctx
            .discovered_devices
            .iter()
            .filter(|d| !exclusions.excludes_device(d))
            .map(|d| d.ip)
            .collect();

        for device in &ctx.discovered_devices {
            if exclusions.excludes_device(device) {
                continue;
            }
            for open in device
                .open_ports
                .iter()
                .filter(|o| MEDIA_PORTS.contains(&o.port))
            {
                match open.port {
                    PLEX_PORT => {
                        if let Some((identity, url)) =
                            probe_plex(&client, device.ip, open.port).await
                        {
                            findings.push(plex_finding(device.ip, open.port, &identity, &url));
                        }
                    }
                    JELLYFIN_PORT | JELLYFIN_TLS_PORT => {
                        if let Some((info, url)) =
                            probe_jellyfin(&client, device.ip, open.port).await
                        {
                            findings
                                .extend(jellyfin_wizard_finding(device.ip, open.port, &info, &url));
                            findings.push(jellyfin_finding(device.ip, open.port, &info, &url));
                        }
                    }
                    _ => {}
                }
            }
        }

        // UDP/7359 is invisible to the TCP sweep and finds Jellyfin on ports the
        // sweep does not cover. Hosts already reported above are skipped, and the
        // advertised address is validated against the responder before any fetch.
        let mut reported: std::collections::HashSet<IpAddr> =
            findings.iter().filter_map(|f| f.affected_ip).collect();
        for (ip, address) in discover_jellyfin(&targets).await {
            if exclusions.excludes_ip(ip) || !reported.insert(ip) {
                continue;
            }
            let Some((port, base)) = discovery_target(ip, &address) else {
                continue;
            };
            if let Some((info, url)) = probe_jellyfin_at(&client, &base).await {
                findings.extend(jellyfin_wizard_finding(ip, port, &info, &url));
                findings.push(jellyfin_finding(ip, port, &info, &url));
            }
        }

        tracing::info!(
            findings_count = findings.len(),
            "media-server scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        15
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const PLEX_IDENTITY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<MediaContainer size="0" claimed="1" machineIdentifier="8f7d2c1b9a0e4f6d" version="1.41.3.9314-a0bfb8370">
</MediaContainer>"#;

    const JELLYFIN_INFO: &str = r#"{"LocalAddress":"http://192.168.1.40:8096","ServerName":"jellyfin",
"Version":"10.10.7","ProductName":"Jellyfin Server","OperatingSystem":"Linux",
"Id":"5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c","StartupWizardCompleted":true}"#;

    /// A real Emby `/System/Info/Public` body: same port, same path, same
    /// Version/Id/StartupWizardCompleted fields, different product.
    const EMBY_INFO: &str = r#"{"LocalAddress":"http://192.168.1.41:8096","ServerName":"emby",
"Version":"4.8.11.0","ProductName":"Emby Server","OperatingSystem":"Linux",
"Id":"a1b2c3d4e5f60718293a4b5c6d7e8f90","StartupWizardCompleted":false}"#;

    fn ip() -> IpAddr {
        IpAddr::from([192, 168, 1, 40])
    }

    fn plex_with(version: &str) -> PlexIdentity {
        PlexIdentity {
            machine_identifier: Some("abc".to_owned()),
            version: Some(version.to_owned()),
            claimed: Some(true),
        }
    }

    // ── Version handling ────────────────────────────────────────────

    #[test]
    fn parses_plex_and_jellyfin_version_shapes() {
        assert_eq!(
            parse_version("1.41.3.9314-a0bfb8370"),
            Some(vec![1, 41, 3, 9314])
        );
        assert_eq!(parse_version("10.10.7"), Some(vec![10, 10, 7]));
        assert_eq!(parse_version("1.42.1"), Some(vec![1, 42, 1]));
        assert_eq!(parse_version(" 1.19.3 "), Some(vec![1, 19, 3]));
    }

    #[test]
    fn rejects_unparseable_versions() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("unknown"), None);
        assert_eq!(parse_version("v1.2"), None);
    }

    #[test]
    fn version_compare_pads_the_shorter_side() {
        assert!(version_cmp(&[1, 41, 7, 9314], &[1, 41, 7]).is_ge());
        assert!(version_cmp(&[1, 42], &[1, 42, 1]).is_lt());
        assert!(version_cmp(&[1, 19, 3], &[1, 19, 3, 0]).is_eq());
    }

    // ── Plex classification ─────────────────────────────────────────

    #[test]
    fn plex_below_the_kev_floor_is_kev_rce() {
        assert_eq!(classify_plex(Some(&[1, 19, 2])), PlexVerdict::KevRce);
        assert_eq!(classify_plex(Some(&[0, 9, 9])), PlexVerdict::KevRce);
    }

    #[test]
    fn plex_at_the_kev_fix_is_not_flagged() {
        assert_eq!(classify_plex(Some(&[1, 19, 3])), PlexVerdict::Current);
    }

    #[test]
    fn plex_2025_range_boundaries() {
        assert_eq!(classify_plex(Some(&[1, 41, 6, 9999])), PlexVerdict::Current);
        assert_eq!(
            classify_plex(Some(&[1, 41, 7, 1])),
            PlexVerdict::CredentialExposure
        );
        assert_eq!(
            classify_plex(Some(&[1, 42, 0, 9999])),
            PlexVerdict::CredentialExposure
        );
        assert_eq!(classify_plex(Some(&[1, 42, 1])), PlexVerdict::Current);
        assert_eq!(classify_plex(Some(&[1, 43, 0])), PlexVerdict::Current);
    }

    #[test]
    fn plex_without_a_version_is_unknown() {
        assert_eq!(classify_plex(None), PlexVerdict::Unknown);
    }

    // ── Plex parsing ────────────────────────────────────────────────

    #[test]
    fn parses_a_plex_identity_document() {
        let identity = parse_plex_identity(PLEX_IDENTITY).expect("identity");
        assert_eq!(identity.version.as_deref(), Some("1.41.3.9314-a0bfb8370"));
        assert_eq!(
            identity.machine_identifier.as_deref(),
            Some("8f7d2c1b9a0e4f6d")
        );
        assert_eq!(identity.claimed, Some(true));
    }

    #[test]
    fn rejects_non_plex_bodies() {
        assert!(parse_plex_identity("").is_none());
        assert!(parse_plex_identity("<html><title>nginx</title></html>").is_none());
        // A MediaContainer with no identifying attribute is not enough.
        assert!(parse_plex_identity("<MediaContainer size=\"0\"/>").is_none());
        // The XML prolog's own version attribute is not the server version.
        assert!(parse_plex_identity("<?xml version=\"1.0\"?><other/>").is_none());
    }

    #[test]
    fn plex_identity_survives_a_multibyte_body() {
        let body = "<!-- café --><MediaContainer version=\"1.42.1.10060\"/>";
        assert_eq!(
            parse_plex_identity(body).unwrap().version.as_deref(),
            Some("1.42.1.10060")
        );
    }

    #[test]
    fn identity_is_the_only_plex_path() {
        assert_eq!(PLEX_PATH, "/identity");
        // The endpoint CVE-2025-34158 abuses is named in the finding text and
        // never fetched: the probe concatenates PLEX_PATH and nothing else.
        let finding = plex_finding(ip(), PLEX_PORT, &plex_with("1.41.9.9961"), "u");
        assert!(finding.description.contains("never requested"));
    }

    // ── Jellyfin parsing ────────────────────────────────────────────

    #[test]
    fn parses_a_jellyfin_public_info_document() {
        let info = parse_jellyfin_info(JELLYFIN_INFO).expect("info");
        assert_eq!(info.server_name.as_deref(), Some("jellyfin"));
        assert_eq!(info.version.as_deref(), Some("10.10.7"));
        assert_eq!(info.operating_system.as_deref(), Some("Linux"));
        assert_eq!(info.startup_wizard_completed, Some(true));
    }

    #[test]
    fn parses_an_unconfigured_jellyfin() {
        let body = r#"{"ServerName":"jellyfin","Version":"10.10.7","ProductName":"Jellyfin Server",
"Id":"abc","StartupWizardCompleted":false}"#;
        let info = parse_jellyfin_info(body).expect("info");
        assert_eq!(info.startup_wizard_completed, Some(false));
    }

    #[test]
    fn rejects_non_jellyfin_json() {
        assert!(parse_jellyfin_info("").is_none());
        assert!(parse_jellyfin_info("{}").is_none());
        assert!(parse_jellyfin_info("[1,2,3]").is_none());
    }

    /// A complete Emby body carries every field the version+id fallback needs,
    /// so only the product name can reject it.
    #[test]
    fn a_full_emby_body_is_not_jellyfin() {
        let value: serde_json::Value = serde_json::from_str(EMBY_INFO).unwrap();
        assert!(value.get("Version").is_some() && value.get("Id").is_some());
        assert!(
            parse_jellyfin_info(EMBY_INFO).is_none(),
            "Emby identified as Jellyfin"
        );
    }

    /// Without a `ProductName` the version+id shape is still enough.
    #[test]
    fn a_body_without_a_product_name_falls_back_to_version_and_id() {
        let body = r#"{"ServerName":"jf","Version":"10.10.7","Id":"abc"}"#;
        assert!(parse_jellyfin_info(body).is_some());
    }

    #[test]
    fn parses_a_discovery_reply() {
        let body = r#"{"Address":"http://192.168.1.40:8096/","Id":"abc","Name":"jellyfin","EndpointAddress":null}"#;
        assert_eq!(
            parse_jellyfin_discovery(body).as_deref(),
            Some("http://192.168.1.40:8096")
        );
    }

    #[test]
    fn rejects_a_discovery_reply_without_an_http_address() {
        assert!(parse_jellyfin_discovery(r#"{"Address":"ftp://x"}"#).is_none());
        assert!(parse_jellyfin_discovery(r#"{"Id":"abc"}"#).is_none());
        assert!(parse_jellyfin_discovery("who is JellyfinServer?").is_none());
    }

    #[test]
    fn discovery_query_is_the_documented_string() {
        assert_eq!(JELLYFIN_DISCOVERY_QUERY, b"who is JellyfinServer?");
    }

    // ── Discovery target validation ─────────────────────────────────

    #[test]
    fn a_discovery_address_naming_its_own_responder_is_accepted() {
        assert_eq!(
            discovery_target(ip(), "http://192.168.1.40:8096"),
            Some((8096, "http://192.168.1.40:8096".to_owned()))
        );
        assert_eq!(
            discovery_target(ip(), "https://192.168.1.40:8920"),
            Some((8920, "https://192.168.1.40:8920".to_owned()))
        );
    }

    #[test]
    fn a_discovery_address_naming_another_host_is_refused() {
        // The exclusion bypass: a responder pointing the next GET at a host the
        // user excluded, or at one that is not on this network at all.
        for address in [
            "http://192.168.1.99:8096",
            "http://10.0.0.5:443",
            "http://jellyfin.example.com:8096",
            "http://192.168.1.40@192.168.1.99:8096",
            "http://192.168.1.99:8096/../192.168.1.40",
            "ftp://192.168.1.40:8096",
            "192.168.1.40:8096",
        ] {
            assert!(
                discovery_target(ip(), address).is_none(),
                "{address} was accepted"
            );
        }
    }

    #[test]
    fn a_discovery_address_path_and_query_never_survive() {
        assert_eq!(
            discovery_target(ip(), "http://192.168.1.40:8096/evil?x=1#f"),
            Some((8096, "http://192.168.1.40:8096".to_owned()))
        );
    }

    #[test]
    fn a_discovery_port_comes_from_the_url_not_a_rsplit() {
        // A bare address takes the scheme default, not JELLYFIN_PORT.
        assert_eq!(
            discovery_target(ip(), "http://192.168.1.40"),
            Some((80, "http://192.168.1.40:80".to_owned()))
        );
        assert_eq!(
            discovery_target(ip(), "https://192.168.1.40"),
            Some((443, "https://192.168.1.40:443".to_owned()))
        );
        assert!(discovery_target(ip(), "http://192.168.1.40:notaport").is_none());
    }

    #[test]
    fn an_ipv6_discovery_address_round_trips_bracketed() {
        let v6: IpAddr = "fd00::40".parse().unwrap();
        assert_eq!(
            discovery_target(v6, "http://[fd00::40]:8096"),
            Some((8096, "http://[fd00::40]:8096".to_owned()))
        );
        // The unbracketed form is not a valid authority and must not be read as
        // host "fd00" port "":40".
        assert!(discovery_target(v6, "http://fd00::40:8096").is_none());
    }

    #[test]
    fn media_ports_do_not_gate_the_scanner() {
        // 8096 and 8920 are in no sweep list, so relevant_ports must stay empty
        // or UDP discovery would never run. The default impl returns &[].
        assert!(MediaServerScanner.relevant_ports().is_empty());
        assert!(MEDIA_PORTS.contains(&JELLYFIN_PORT));
    }

    // ── Findings ────────────────────────────────────────────────────

    #[test]
    fn kev_plex_finding_carries_the_kev_cve() {
        let finding = plex_finding(ip(), PLEX_PORT, &plex_with("1.18.2.2029"), "u");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Probable);
        assert_eq!(finding.cve_ids, vec!["CVE-2020-5741".to_owned()]);
    }

    #[test]
    fn credential_exposure_finding_is_medium_and_names_its_precondition() {
        let finding = plex_finding(ip(), PLEX_PORT, &plex_with("1.41.9.9961"), "u");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.cve_ids, vec!["CVE-2025-34158".to_owned()]);
        assert!(
            finding
                .description
                .contains("authenticated low-privilege user"),
            "the PR:L precondition is not stated"
        );
    }

    #[test]
    fn current_plex_carries_no_cve() {
        let finding = plex_finding(ip(), PLEX_PORT, &plex_with("1.42.1.10060"), "u");
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.cve_ids.is_empty());
        assert_eq!(finding.confidence, Confidence::Confirmed);
    }

    #[test]
    fn plex_without_a_version_is_inferred() {
        let identity = PlexIdentity {
            machine_identifier: Some("abc".to_owned()),
            ..PlexIdentity::default()
        };
        let finding = plex_finding(ip(), PLEX_PORT, &identity, "u");
        assert_eq!(finding.confidence, Confidence::Inferred);
        assert!(finding.cve_ids.is_empty());
    }

    #[test]
    fn plex_titles_are_stable_per_verdict() {
        let a = plex_finding(ip(), PLEX_PORT, &plex_with("1.41.8.1"), "u").title;
        let b = plex_finding(ip(), PLEX_PORT, &plex_with("1.42.0.500"), "u").title;
        assert_eq!(a, b);
    }

    #[test]
    fn plex_hint_is_a_server() {
        let hint = plex_finding(ip(), PLEX_PORT, &plex_with("1.42.1"), "u")
            .device_hint
            .expect("hint");
        assert_eq!(hint.device_type, Some(DeviceType::Server));
        assert_eq!(hint.device_subtype.as_deref(), Some("plex_media_server"));
    }

    #[test]
    fn jellyfin_presence_is_info_and_confirmed() {
        let info = parse_jellyfin_info(JELLYFIN_INFO).unwrap();
        let finding = jellyfin_finding(ip(), JELLYFIN_PORT, &info, "u");
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-200"));
    }

    #[test]
    fn wizard_finding_fires_only_when_setup_is_incomplete() {
        let done = parse_jellyfin_info(JELLYFIN_INFO).unwrap();
        assert!(jellyfin_wizard_finding(ip(), JELLYFIN_PORT, &done, "u").is_none());

        let mut open = done.clone();
        open.startup_wizard_completed = Some(false);
        let finding = jellyfin_wizard_finding(ip(), JELLYFIN_PORT, &open, "u").expect("finding");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-306"));

        let mut absent = done;
        absent.startup_wizard_completed = None;
        assert!(jellyfin_wizard_finding(ip(), JELLYFIN_PORT, &absent, "u").is_none());
    }

    #[test]
    fn evidence_records_what_was_read() {
        let info = parse_jellyfin_info(JELLYFIN_INFO).unwrap();
        let text = jellyfin_evidence(&info, "http://x/System/Info/Public");
        assert!(text.contains("Version=10.10.7"));
        assert!(text.contains("StartupWizardCompleted=true"));
    }

    proptest! {
        /// No response body can panic the Plex parser.
        #[test]
        fn plex_parser_never_panics(body in ".*") {
            let _ = parse_plex_identity(&body);
        }

        /// Nor can arbitrary bytes from the discovery socket.
        #[test]
        fn jellyfin_parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let text = String::from_utf8_lossy(&bytes);
            let _ = parse_jellyfin_info(&text);
            if let Some(address) = parse_jellyfin_discovery(&text) {
                let _ = discovery_target(ip(), &address);
            }
        }

        /// Whatever a responder sends, the URL that is fetched names the
        /// responder and nothing else.
        #[test]
        fn a_discovery_target_always_names_its_responder(address in "[a-z0-9.:/\\[\\]@?#-]{0,48}") {
            if let Some((port, base)) = discovery_target(ip(), &address) {
                prop_assert_eq!(base, format!("http://192.168.1.40:{port}"));
            }
        }

        /// Any version string that parses classifies without panicking, and the
        /// finding it produces keeps one of the stable titles.
        #[test]
        fn plex_findings_are_total(raw in "[0-9a-z.\\-]{0,24}") {
            let identity = PlexIdentity {
                version: Some(raw),
                ..PlexIdentity::default()
            };
            let finding = plex_finding(ip(), PLEX_PORT, &identity, "u");
            prop_assert!(finding.title.starts_with("Plex Media Server"));
        }
    }
}

/// Parser entry points for the fuzz harness.
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    #[must_use]
    pub fn plex(body: &str) -> bool {
        super::parse_plex_identity(body).is_some()
    }
    #[must_use]
    pub fn jellyfin(body: &str) -> bool {
        super::parse_jellyfin_info(body).is_some()
    }
    #[must_use]
    pub fn discovery(body: &str) -> bool {
        super::parse_jellyfin_discovery(body).is_some()
    }
    #[must_use]
    pub fn version(raw: &str) -> bool {
        super::parse_version(raw).is_some()
    }
    #[must_use]
    pub fn authority(a: &str) -> bool {
        super::split_authority(a, 8096).is_some()
    }
}
