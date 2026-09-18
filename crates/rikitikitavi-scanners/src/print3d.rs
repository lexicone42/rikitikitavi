//! Networked 3D printers: Moonraker/Klipper (7125, 7130) and `OctoPrint` (5000).
//!
//! Read-only and unauthenticated. Moonraker's `GET /access/info` is registered
//! with `auth_required=False`, so it answers every caller and reports whether
//! *this* host is a trusted client. `login_required` from the same document is
//! recorded as evidence but is never a verdict: upstream it is true only when
//! `force_logins` is on *and* more than one user exists, and `force_logins`
//! defaults to off, so a correctly locked-down instance that enforces an API key
//! still reports false.
//! `OctoPrint` is identified by the
//! `X-Clacks-Overhead` response header, which it sets on every response
//! including the 403 — `/api/version` alone cannot distinguish the two, because
//! Moonraker's `octoprint_compat` component serves the same path.
//!
//! No G-code, file upload, print control or `machine` endpoint is ever
//! requested; only the two identification paths below.

use async_trait::async_trait;
use reqwest::redirect::Policy;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, Remediation, ScanContext};
use std::net::IpAddr;
use std::time::Duration;

use crate::Scanner;

/// Moonraker / `OctoPrint` scanner.
pub struct Print3dScanner;

const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
/// Both answers are small JSON documents; the `OctoPrint` index page is capped too.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// Moonraker HTTP.
const MOONRAKER_PORT: u16 = 7125;
/// Moonraker HTTPS; usually closed, since it starts only when a certificate and
/// key are configured.
const MOONRAKER_TLS_PORT: u16 = 7130;
/// `OctoPrint` default.
const OCTOPRINT_PORT: u16 = 5000;

/// Ports gating this scanner in Phase 2.
const PRINTER_PORTS: &[u16] = &[OCTOPRINT_PORT, MOONRAKER_PORT, MOONRAKER_TLS_PORT];

/// Moonraker paths: identification, then the authorization posture.
const MOONRAKER_INFO_PATH: &str = "/server/info";
const MOONRAKER_ACCESS_PATH: &str = "/access/info";
/// `OctoPrint` paths.
const OCTOPRINT_INDEX_PATH: &str = "/";
const OCTOPRINT_VERSION_PATH: &str = "/api/version";

/// Every path this scanner may request. `request` refuses anything else, so a
/// path assembled at runtime cannot reach the network.
const ALLOWED_PATHS: &[&str] = &[
    MOONRAKER_INFO_PATH,
    MOONRAKER_ACCESS_PATH,
    OCTOPRINT_INDEX_PATH,
    OCTOPRINT_VERSION_PATH,
];

/// `OctoPrint` sets this on every response, including the 403.
const CLACKS_HEADER: &str = "x-clacks-overhead";
const CLACKS_VALUE: &str = "GNU Terry Pratchett";

// ── Moonraker parsing ───────────────────────────────────────────────────────

/// `GET /access/info`, which Moonraker registers with `auth_required=False`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AccessInfo {
    /// The requesting address is covered by `trusted_clients`.
    trusted: Option<bool>,
    /// A login is required for authenticated endpoints.
    login_required: Option<bool>,
}

/// Parse `/access/info`. Moonraker wraps every answer in `result`.
fn parse_access_info(body: &str) -> Option<AccessInfo> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let result = value.get("result")?.as_object()?;
    let info = AccessInfo {
        trusted: result.get("trusted").and_then(serde_json::Value::as_bool),
        login_required: result
            .get("login_required")
            .and_then(serde_json::Value::as_bool),
    };
    // `default_source` is always present; without it this is not /access/info.
    let identified = result.contains_key("default_source")
        || info.trusted.is_some()
        || info.login_required.is_some();
    identified.then_some(info)
}

/// Identification fields from `GET /server/info`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MoonrakerInfo {
    version: Option<String>,
    klippy_state: Option<String>,
    /// Loaded components; `authorization` present means the auth layer is active.
    components: Vec<String>,
}

impl MoonrakerInfo {
    fn has_authorization_component(&self) -> bool {
        self.components.iter().any(|c| c == "authorization")
    }
}

/// Parse `/server/info`.
fn parse_server_info(body: &str) -> Option<MoonrakerInfo> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let result = value.get("result")?.as_object()?;
    let info = MoonrakerInfo {
        version: result
            .get("moonraker_version")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
        klippy_state: result
            .get("klippy_state")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
        components: result
            .get("components")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|c| c.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    };
    (info.version.is_some() || info.klippy_state.is_some()).then_some(info)
}

/// What one Moonraker host answered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MoonrakerProbe {
    info: Option<MoonrakerInfo>,
    /// `/server/info` answered 200 without credentials.
    info_unauthenticated: bool,
    access: Option<AccessInfo>,
    /// `/access/info` was not served, i.e. the authorization component is absent.
    access_missing: bool,
}

/// Why a Moonraker instance is reported as unauthenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthPosture {
    /// This scanning host is inside `trusted_clients`.
    TrustedClient,
    /// The authorization component is not loaded at all.
    NoAuthComponent,
    /// A privileged endpoint answered an unauthenticated request.
    AnsweredUnauthenticated,
    /// Authentication is enforced for this host.
    Enforced,
}

/// Classify the authentication posture from what the host answered.
///
/// `login_required` is deliberately not a signal: upstream it is true only when
/// `force_logins` is on and more than one user exists, and `force_logins`
/// defaults to off, so an instance that rejects this host with a 401 still
/// reports false. Only three
/// things are evidence of open control: being a trusted client, no authorization
/// component at all, or an `auth_required` endpoint answering 200.
fn classify_posture(probe: &MoonrakerProbe) -> AuthPosture {
    if probe.access.and_then(|a| a.trusted) == Some(true) {
        return AuthPosture::TrustedClient;
    }
    if probe.access_missing
        && probe
            .info
            .as_ref()
            .is_some_and(|i| !i.has_authorization_component())
    {
        return AuthPosture::NoAuthComponent;
    }
    if probe.info_unauthenticated {
        return AuthPosture::AnsweredUnauthenticated;
    }
    AuthPosture::Enforced
}

// ── OctoPrint parsing ───────────────────────────────────────────────────────

/// What one `OctoPrint` host answered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OctoPrintProbe {
    /// `X-Clacks-Overhead` was seen: this is `OctoPrint`, not Moonraker.
    clacks: bool,
    /// Version from `/api/version` when it answered without an API key.
    version: Option<String>,
    /// `/api/version` returned 200 without credentials.
    api_unauthenticated: bool,
}

/// Parse `/api/version`: `{"api":"0.1","server":"1.10.3","text":"OctoPrint 1.10.3"}`.
fn parse_octoprint_version(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let object = value.as_object()?;
    // `text` carries the product name, which distinguishes a real OctoPrint
    // answer from Moonraker's octoprint_compat shim.
    let text = object.get("text").and_then(serde_json::Value::as_str);
    if !text.is_some_and(|t| t.to_ascii_lowercase().contains("octoprint")) {
        return None;
    }
    object
        .get("server")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| text.map(ToOwned::to_owned))
}

// ── Findings ────────────────────────────────────────────────────────────────

fn moonraker_references() -> Vec<String> {
    refs![
        "https://moonraker.readthedocs.io/en/latest/configuration/",
        "https://moonraker.readthedocs.io/en/latest/web_api/",
        "https://cwe.mitre.org/data/definitions/306.html",
    ]
}

fn moonraker_remediation() -> Remediation {
    Remediation {
        description: "Moonraker's API drives the printer: G-code, file upload, firmware \
                      restart and host power control. Require authentication for every \
                      client and keep the printer off general-purpose network segments."
            .to_owned(),
        steps: vec![
            "In moonraker.conf, narrow [authorization] trusted_clients to single \
             addresses you control, or remove the whole trusted_clients list and use \
             API keys or user logins instead of a trusted subnet."
                .to_owned(),
            "Do not combine a trusted LAN range with cors_domains: * — any page a \
             browser on this network visits can then drive the printer. (cors_domains \
             alone is not an authentication bypass; combined with trusted_clients it is \
             the practical risk.)"
                .to_owned(),
            "Put the printer on its own VLAN and reach it through a reverse proxy that \
             authenticates, rather than exposing 7125 directly."
                .to_owned(),
            "Never port-forward 7125 or 80/443 of the printer's web UI to the internet.".to_owned(),
        ],
        effort: Some("30 minutes".to_owned()),
    }
}

fn moonraker_evidence(probe: &MoonrakerProbe, base: &str) -> String {
    let mut parts = Vec::new();
    if let Some(info) = &probe.info {
        let version = info.version.as_deref().unwrap_or("unreported");
        parts.push(format!(
            "GET {base}{MOONRAKER_INFO_PATH} -> version {version}"
        ));
        if let Some(state) = &info.klippy_state {
            parts.push(format!("klippy_state={state}"));
        }
    }
    if let Some(access) = probe.access {
        parts.push(format!(
            "GET {base}{MOONRAKER_ACCESS_PATH} -> trusted={} login_required={}",
            access
                .trusted
                .map_or_else(|| "absent".to_owned(), |v| v.to_string()),
            access
                .login_required
                .map_or_else(|| "absent".to_owned(), |v| v.to_string())
        ));
    } else if probe.access_missing {
        parts.push(format!("{MOONRAKER_ACCESS_PATH} not served"));
    }
    parts.join("; ")
}

/// Device hint for a Klipper/Moonraker host.
fn printer_hint(subtype: &str, model: Option<&str>) -> DeviceHint {
    let mut hint = DeviceHint::new()
        .with_device_type(DeviceType::Printer3d)
        .with_device_subtype(subtype);
    if let Some(model) = model {
        hint = hint.with_model(model);
    }
    hint
}

/// Finding for one Moonraker instance.
fn moonraker_finding(ip: IpAddr, port: u16, probe: &MoonrakerProbe, base: &str) -> Finding {
    let posture = classify_posture(probe);
    let version = probe
        .info
        .as_ref()
        .and_then(|i| i.version.clone())
        .unwrap_or_else(|| "unreported".to_owned());

    let (title, reason, severity, confidence) = match posture {
        AuthPosture::TrustedClient => (
            format!("Moonraker printer API accepts unauthenticated control on {ip}:{port}"),
            "The printer reports that this scanning host is inside its trusted_clients \
             range, so every API endpoint is available to it with no credentials at all."
                .to_owned(),
            Severity::High,
            Confidence::Confirmed,
        ),
        AuthPosture::NoAuthComponent => (
            format!("Moonraker printer API accepts unauthenticated control on {ip}:{port}"),
            "The instance serves no /access/info and lists no authorization component, so \
             Moonraker's authentication layer is not configured and every endpoint is open."
                .to_owned(),
            Severity::High,
            Confidence::Confirmed,
        ),
        AuthPosture::AnsweredUnauthenticated => (
            format!("Moonraker printer API accepts unauthenticated control on {ip}:{port}"),
            "Moonraker registers /server/info with auth_required defaulted to true, and this \
             instance answered it with a 200 to an unauthenticated request, so the API is \
             reachable from this host without credentials."
                .to_owned(),
            Severity::High,
            Confidence::Confirmed,
        ),
        AuthPosture::Enforced => (
            format!("Moonraker printer interface reachable on {ip}:{port}"),
            "The instance did not serve its authenticated endpoints to this host, so the \
             exposure is the reachable service itself rather than open control."
                .to_owned(),
            Severity::Info,
            Confidence::Confirmed,
        ),
    };

    let description = format!(
        "The host at {ip}:{port} runs Moonraker (version {version}), the HTTP API in front \
         of a Klipper 3D printer. {reason} Moonraker's API covers arbitrary G-code \
         execution, file upload and deletion, emergency stop, firmware restart and — where \
         the host power component is configured — rebooting or shutting down the machine. \
         Klipper enforces its own max_temp limits and thermal-runaway protection, and shell \
         execution needs a third-party extension, so this is full control over the machine \
         and its files rather than a thermal hazard. Restrict who can reach the API."
    );

    let finding = Finding::new("print3d", &title, &description, severity)
        .with_confidence(confidence)
        .with_ip(ip)
        .with_port(port)
        .with_service("Moonraker")
        .with_evidence(moonraker_evidence(probe, base))
        .with_remediation(moonraker_remediation())
        .with_references(moonraker_references())
        .with_device_hint(printer_hint("klipper_moonraker", None));

    if posture == AuthPosture::Enforced {
        finding
    } else {
        finding.with_cwe("CWE-306")
    }
}

fn octoprint_references() -> Vec<String> {
    refs![
        "https://docs.octoprint.org/en/master/api/general.html",
        "https://docs.octoprint.org/en/master/bundledplugins/softwareupdate.html",
        "https://cwe.mitre.org/data/definitions/306.html",
    ]
}

fn octoprint_remediation() -> Remediation {
    Remediation {
        description: "OctoPrint's API drives the printer. Keep access control enabled and \
                      the instance off untrusted networks."
            .to_owned(),
        steps: vec![
            "In Settings > Access Control, confirm access control is enabled and that \
             'Allow unauthenticated access to read-only endpoints' is off unless you need it."
                .to_owned(),
            "Issue per-application API keys instead of sharing the global key, and revoke \
             keys you no longer recognise."
                .to_owned(),
            "Keep OctoPrint updated from Settings > Software Update.".to_owned(),
            "Put the printer on its own VLAN; never port-forward it to the internet.".to_owned(),
        ],
        effort: Some("20 minutes".to_owned()),
    }
}

/// Finding for one `OctoPrint` instance.
fn octoprint_finding(ip: IpAddr, port: u16, probe: &OctoPrintProbe) -> Finding {
    let version = probe.version.as_deref().unwrap_or("unreported");

    let (title, description, severity) = if probe.api_unauthenticated {
        (
            format!("OctoPrint API answers unauthenticated requests on {ip}:{port}"),
            format!(
                "The host at {ip}:{port} runs OctoPrint (version {version}) and answered \
                 an unauthenticated request to its version endpoint with a 200. OctoPrint \
                 normally returns 403 there without an API key, so either access control is \
                 disabled or unauthenticated read access is enabled. The same API also \
                 covers job control, file upload and arbitrary G-code, so confirm what is \
                 reachable without a key and turn access control back on."
            ),
            Severity::High,
        )
    } else {
        (
            format!("OctoPrint printer interface reachable on {ip}:{port}"),
            format!(
                "The host at {ip}:{port} runs OctoPrint (version {version}), identified by \
                 the X-Clacks-Overhead response header it sets on every response. Its API \
                 required credentials for the version endpoint, so the exposure is the \
                 reachable service itself. OctoPrint drives a 3D printer: keep access \
                 control enabled and the instance off untrusted network segments."
            ),
            Severity::Info,
        )
    };

    let finding = Finding::new("print3d", &title, &description, severity)
        .with_confidence(Confidence::Confirmed)
        .with_ip(ip)
        .with_port(port)
        .with_service("OctoPrint")
        .with_evidence(format!(
            "{CLACKS_HEADER}: {CLACKS_VALUE}; GET {OCTOPRINT_VERSION_PATH} -> {}",
            if probe.api_unauthenticated {
                format!("200, server {version}")
            } else {
                "not served without credentials".to_owned()
            }
        ))
        .with_remediation(octoprint_remediation())
        .with_references(octoprint_references())
        .with_device_hint(printer_hint("octoprint", None));

    if probe.api_unauthenticated {
        finding.with_cwe("CWE-306")
    } else {
        finding
    }
}

// ── Probes ──────────────────────────────────────────────────────────────────

/// One GET: status, the `X-Clacks-Overhead` header if present, and the body.
async fn fetch(client: &reqwest::Client, url: &str) -> Option<(u16, bool, String)> {
    let resp = tokio::time::timeout(HTTP_TIMEOUT, client.get(url).send())
        .await
        .ok()?
        .ok()?;
    let status = resp.status().as_u16();
    let clacks = resp
        .headers()
        .get(CLACKS_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case(CLACKS_VALUE));
    let body = crate::http_util::read_body_capped(resp, MAX_BODY_BYTES).await;
    Some((status, clacks, body))
}

/// Whether `path` is one of the four identification paths.
fn path_allowed(path: &str) -> bool {
    ALLOWED_PATHS.contains(&path)
}

/// One GET at `path` under `base`. The single place this module reaches the
/// network, and the only place a URL is built: anything outside the allowlist is
/// refused before a connection is opened.
async fn request(client: &reqwest::Client, base: &str, path: &str) -> Option<(u16, bool, String)> {
    if !path_allowed(path) {
        tracing::error!(path, "refusing a request outside the print3d allowlist");
        return None;
    }
    fetch(client, &format!("{base}{path}")).await
}

/// Scheme for a port: only Moonraker's 7130 is TLS.
const fn scheme_for(port: u16) -> &'static str {
    if port == MOONRAKER_TLS_PORT {
        "https"
    } else {
        "http"
    }
}

/// Probe Moonraker at one endpoint. `None` unless something identified it.
async fn probe_moonraker(client: &reqwest::Client, base: &str) -> Option<MoonrakerProbe> {
    let mut probe = MoonrakerProbe::default();

    if let Some((200, _, body)) = request(client, base, MOONRAKER_INFO_PATH).await {
        probe.info = parse_server_info(&body);
        probe.info_unauthenticated = probe.info.is_some();
    }

    match request(client, base, MOONRAKER_ACCESS_PATH).await {
        Some((200, _, body)) => probe.access = parse_access_info(&body),
        Some((_, _, _)) => probe.access_missing = true,
        None => {}
    }

    (probe.info.is_some() || probe.access.is_some()).then_some(probe)
}

/// Probe `OctoPrint` at one endpoint. `None` unless the Clacks header was seen.
async fn probe_octoprint(client: &reqwest::Client, base: &str) -> Option<OctoPrintProbe> {
    let mut probe = OctoPrintProbe::default();

    if let Some((_, clacks, _)) = request(client, base, OCTOPRINT_INDEX_PATH).await {
        probe.clacks = clacks;
    }

    if let Some((status, clacks, body)) = request(client, base, OCTOPRINT_VERSION_PATH).await {
        probe.clacks |= clacks;
        if status == 200 {
            probe.version = parse_octoprint_version(&body);
            probe.api_unauthenticated = probe.version.is_some();
        }
    }

    probe.clacks.then_some(probe)
}

#[async_trait]
impl Scanner for Print3dScanner {
    fn id(&self) -> &'static str {
        "print3d"
    }

    fn name(&self) -> &'static str {
        "3D Printer Control Interfaces"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running 3D printer interface scan");
        let mut findings = Vec::new();

        // Network probe: Active intensity and above only.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping 3D printer scan in quick scan mode");
            return Ok(findings);
        }

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "print3d".to_owned(),
                message: e.to_string(),
            })?;

        let Ok(client) =
            crate::http_util::unauthenticated_probe_client(HTTP_TIMEOUT, Policy::none())
        else {
            return Err(ScanError::ScannerFailed {
                scanner: "print3d".to_owned(),
                message: "could not build an HTTP client".to_owned(),
            });
        };

        for device in &ctx.discovered_devices {
            if exclusions.excludes_device(device) {
                continue;
            }
            for open in &device.open_ports {
                if !PRINTER_PORTS.contains(&open.port) {
                    continue;
                }
                let base = format!("{}://{}:{}", scheme_for(open.port), device.ip, open.port);
                if let Some(probe) = probe_moonraker(&client, &base).await {
                    findings.push(moonraker_finding(device.ip, open.port, &probe, &base));
                    continue;
                }
                if let Some(probe) = probe_octoprint(&client, &base).await {
                    findings.push(octoprint_finding(device.ip, open.port, &probe));
                }
            }
        }

        tracing::info!(
            findings_count = findings.len(),
            "3D printer interface scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        10
    }

    fn relevant_ports(&self) -> &[u16] {
        PRINTER_PORTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ACCESS_TRUSTED: &str = r#"{"result":{"default_source":"moonraker",
"available_sources":["moonraker"],"login_required":false,"trusted":true}}"#;

    const ACCESS_ENFORCED: &str = r#"{"result":{"default_source":"moonraker",
"available_sources":["moonraker","ldap"],"login_required":true,"trusted":false}}"#;

    const SERVER_INFO: &str = r#"{"result":{"klippy_connected":true,"klippy_state":"ready",
"components":["server","file_manager","authorization","klippy_apis"],
"failed_components":[],"registered_directories":["gcodes","config"],
"warnings":[],"websocket_count":2,"moonraker_version":"v0.9.3-4-gf1b2c3d",
"missing_klippy_requirements":[],"api_version":[1,5,0],"api_version_string":"1.5.0"}}"#;

    const OCTOPRINT_VERSION: &str = r#"{"api":"0.1","server":"1.10.3","text":"OctoPrint 1.10.3"}"#;

    fn ip() -> IpAddr {
        IpAddr::from([192, 168, 1, 55])
    }

    fn probe_with(access: Option<AccessInfo>, info: Option<MoonrakerInfo>) -> MoonrakerProbe {
        MoonrakerProbe {
            info_unauthenticated: info.is_some(),
            info,
            access,
            access_missing: access.is_none(),
        }
    }

    // ── Moonraker parsing ───────────────────────────────────────────

    #[test]
    fn parses_a_trusted_access_info() {
        let access = parse_access_info(ACCESS_TRUSTED).expect("access info");
        assert_eq!(access.trusted, Some(true));
        assert_eq!(access.login_required, Some(false));
    }

    #[test]
    fn parses_an_enforcing_access_info() {
        let access = parse_access_info(ACCESS_ENFORCED).expect("access info");
        assert_eq!(access.trusted, Some(false));
        assert_eq!(access.login_required, Some(true));
    }

    #[test]
    fn rejects_bodies_that_are_not_access_info() {
        assert!(parse_access_info("").is_none());
        assert!(parse_access_info("{}").is_none());
        assert!(parse_access_info(r#"{"result":{}}"#).is_none());
        assert!(parse_access_info(r#"{"error":{"code":401}}"#).is_none());
    }

    #[test]
    fn parses_server_info() {
        let info = parse_server_info(SERVER_INFO).expect("server info");
        assert_eq!(info.version.as_deref(), Some("v0.9.3-4-gf1b2c3d"));
        assert_eq!(info.klippy_state.as_deref(), Some("ready"));
        assert!(info.has_authorization_component());
    }

    #[test]
    fn server_info_without_authorization_component() {
        let body = r#"{"result":{"klippy_state":"ready","components":["server","file_manager"]}}"#;
        let info = parse_server_info(body).expect("server info");
        assert!(!info.has_authorization_component());
    }

    #[test]
    fn rejects_bodies_that_are_not_server_info() {
        assert!(parse_server_info("").is_none());
        assert!(parse_server_info(r#"{"result":{"other":1}}"#).is_none());
    }

    // ── Posture classification ──────────────────────────────────────

    #[test]
    fn trusted_client_is_the_first_verdict() {
        let probe = probe_with(parse_access_info(ACCESS_TRUSTED), None);
        assert_eq!(classify_posture(&probe), AuthPosture::TrustedClient);
    }

    /// A stock, correctly locked-down instance answers exactly this: not a
    /// trusted client, and `login_required=false` because `force_logins`
    /// defaults to false. It must not be reported as open.
    #[test]
    fn login_not_required_alone_is_not_open() {
        let access = parse_access_info(
            r#"{"result":{"default_source":"moonraker","login_required":false,"trusted":false}}"#,
        );
        assert_eq!(access.unwrap().login_required, Some(false));
        assert_eq!(
            classify_posture(&probe_with(access, None)),
            AuthPosture::Enforced
        );
    }

    /// The same host with the API key enforced: /server/info 401s, so nothing
    /// was read there either.
    #[test]
    fn enforcing_instance_that_only_served_access_info_is_enforced() {
        let probe = MoonrakerProbe {
            info: None,
            info_unauthenticated: false,
            access: Some(AccessInfo {
                trusted: Some(false),
                login_required: Some(false),
            }),
            access_missing: false,
        };
        assert_eq!(classify_posture(&probe), AuthPosture::Enforced);
    }

    #[test]
    fn missing_access_endpoint_with_no_auth_component_is_open() {
        let body = r#"{"result":{"klippy_state":"ready","components":["server"]}}"#;
        let probe = probe_with(None, parse_server_info(body));
        assert_eq!(classify_posture(&probe), AuthPosture::NoAuthComponent);
    }

    #[test]
    fn server_info_answered_without_credentials_is_reported() {
        let probe = MoonrakerProbe {
            info: parse_server_info(SERVER_INFO),
            info_unauthenticated: true,
            access: None,
            access_missing: false,
        };
        assert_eq!(
            classify_posture(&probe),
            AuthPosture::AnsweredUnauthenticated
        );
    }

    #[test]
    fn enforced_when_the_printer_says_so() {
        let probe = MoonrakerProbe {
            info: None,
            info_unauthenticated: false,
            access: parse_access_info(ACCESS_ENFORCED),
            access_missing: false,
        };
        assert_eq!(classify_posture(&probe), AuthPosture::Enforced);
    }

    // ── OctoPrint parsing ───────────────────────────────────────────

    #[test]
    fn parses_an_octoprint_version() {
        assert_eq!(
            parse_octoprint_version(OCTOPRINT_VERSION).as_deref(),
            Some("1.10.3")
        );
    }

    #[test]
    fn moonraker_octoprint_compat_is_not_octoprint() {
        // Moonraker's shim answers the same path with its own text field.
        let body = r#"{"api":"0.1","server":"1.5.0","text":"OctoPrint (Moonraker v0.9.3)"}"#;
        assert!(
            parse_octoprint_version(body).is_some(),
            "text names OctoPrint"
        );
        let body = r#"{"api":"0.1","server":"1.5.0","text":"Moonraker v0.9.3"}"#;
        assert!(parse_octoprint_version(body).is_none());
    }

    #[test]
    fn rejects_non_octoprint_json() {
        assert!(parse_octoprint_version("").is_none());
        assert!(parse_octoprint_version("{}").is_none());
        assert!(parse_octoprint_version(r#"{"server":"1.10.3"}"#).is_none());
    }

    #[test]
    fn clacks_header_value_is_the_documented_one() {
        assert_eq!(CLACKS_VALUE, "GNU Terry Pratchett");
        assert_eq!(CLACKS_HEADER, "x-clacks-overhead");
    }

    // ── Findings ────────────────────────────────────────────────────

    #[test]
    fn trusted_moonraker_is_high_and_confirmed() {
        let probe = probe_with(
            parse_access_info(ACCESS_TRUSTED),
            parse_server_info(SERVER_INFO),
        );
        let finding = moonraker_finding(ip(), MOONRAKER_PORT, &probe, "http://x");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-306"));
        assert!(finding.description.contains("v0.9.3-4-gf1b2c3d"));
    }

    #[test]
    fn enforcing_moonraker_is_info_without_a_cwe() {
        let probe = MoonrakerProbe {
            info: None,
            info_unauthenticated: false,
            access: parse_access_info(ACCESS_ENFORCED),
            access_missing: false,
        };
        let finding = moonraker_finding(ip(), MOONRAKER_PORT, &probe, "http://x");
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.cwe_id.is_none());
    }

    #[test]
    fn moonraker_titles_are_stable_across_open_postures() {
        let trusted = probe_with(parse_access_info(ACCESS_TRUSTED), None);
        let no_component = probe_with(
            None,
            parse_server_info(r#"{"result":{"klippy_state":"ready","components":["server"]}}"#),
        );
        let answered = MoonrakerProbe {
            info: parse_server_info(SERVER_INFO),
            info_unauthenticated: true,
            access: None,
            access_missing: false,
        };
        let title = moonraker_finding(ip(), MOONRAKER_PORT, &trusted, "http://x").title;
        for probe in [&no_component, &answered] {
            assert_eq!(
                moonraker_finding(ip(), MOONRAKER_PORT, probe, "http://x").title,
                title
            );
        }
    }

    /// `login_required` is still reported, just as evidence rather than a verdict.
    #[test]
    fn login_required_stays_in_the_evidence() {
        let probe = probe_with(parse_access_info(ACCESS_TRUSTED), None);
        let evidence = moonraker_finding(ip(), MOONRAKER_PORT, &probe, "http://x")
            .evidence
            .expect("evidence");
        assert!(evidence.contains("login_required=false"));
    }

    #[test]
    fn moonraker_remediation_corrects_the_cors_claim() {
        let steps = moonraker_remediation().steps.join(" ");
        assert!(steps.contains("not an authentication bypass"));
    }

    #[test]
    fn moonraker_finding_states_klippers_own_protections() {
        let probe = probe_with(parse_access_info(ACCESS_TRUSTED), None);
        let finding = moonraker_finding(ip(), MOONRAKER_PORT, &probe, "http://x");
        assert!(finding.description.contains("thermal-runaway protection"));
        assert!(
            finding
                .description
                .contains("full control over the machine")
        );
    }

    #[test]
    fn moonraker_hint_is_a_3d_printer() {
        let probe = probe_with(parse_access_info(ACCESS_TRUSTED), None);
        let hint = moonraker_finding(ip(), MOONRAKER_PORT, &probe, "http://x")
            .device_hint
            .expect("hint");
        assert_eq!(hint.device_type, Some(DeviceType::Printer3d));
        assert_eq!(hint.device_subtype.as_deref(), Some("klipper_moonraker"));
    }

    #[test]
    fn unauthenticated_octoprint_api_is_high() {
        let probe = OctoPrintProbe {
            clacks: true,
            version: parse_octoprint_version(OCTOPRINT_VERSION),
            api_unauthenticated: true,
        };
        let finding = octoprint_finding(ip(), OCTOPRINT_PORT, &probe);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-306"));
        assert!(finding.evidence.unwrap().contains("1.10.3"));
    }

    #[test]
    fn identified_octoprint_without_api_access_is_info() {
        let probe = OctoPrintProbe {
            clacks: true,
            ..OctoPrintProbe::default()
        };
        let finding = octoprint_finding(ip(), OCTOPRINT_PORT, &probe);
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.cwe_id.is_none());
        assert_eq!(finding.affected_service.as_deref(), Some("OctoPrint"));
    }

    #[test]
    fn scheme_is_https_only_for_the_moonraker_tls_port() {
        assert_eq!(scheme_for(MOONRAKER_TLS_PORT), "https");
        assert_eq!(scheme_for(MOONRAKER_PORT), "http");
        assert_eq!(scheme_for(OCTOPRINT_PORT), "http");
    }

    #[test]
    fn only_identification_paths_are_requested() {
        for path in [
            MOONRAKER_INFO_PATH,
            MOONRAKER_ACCESS_PATH,
            OCTOPRINT_INDEX_PATH,
            OCTOPRINT_VERSION_PATH,
        ] {
            assert!(path.starts_with('/'));
        }
        // Every allowlisted path is one of the four, and nothing else passes.
        assert_eq!(ALLOWED_PATHS.len(), 4);
        for path in ALLOWED_PATHS {
            assert!(path_allowed(path));
        }
        for control in [
            "/printer/gcode/script",
            "/machine/reboot",
            "/server/files/upload",
            "/api/job",
            "/server/info/../../machine/shutdown",
            "",
        ] {
            assert!(!path_allowed(control), "{control} passed the allowlist");
        }
        // Nor is a control path spelled out anywhere in this module.
        let src = include_str!("print3d.rs");
        let non_test = src.split("mod tests").next().expect("module body");
        for verb in [
            concat!("/printer/", "gcode"),
            concat!("/machine/", "reboot"),
            concat!("/server/", "files/upload"),
            concat!("/api/", "job"),
            concat!("emergency", "_stop"),
        ] {
            assert!(
                !non_test.contains(verb),
                "{verb} appears outside the print3d tests"
            );
        }
    }

    proptest! {
        /// No response body can panic the Moonraker parsers.
        #[test]
        fn moonraker_parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let text = String::from_utf8_lossy(&bytes);
            let _ = parse_access_info(&text);
            let _ = parse_server_info(&text);
        }

        /// Nor can any body reach the OctoPrint parser and panic.
        #[test]
        fn octoprint_parser_never_panics(body in ".*") {
            let _ = parse_octoprint_version(&body);
        }

        /// Every posture produces a finding with a stable title prefix, and no
        /// combination of `login_required` alone ever reports open control.
        #[test]
        fn moonraker_findings_are_total(trusted in any::<Option<bool>>(), login in any::<Option<bool>>()) {
            let probe = probe_with(Some(AccessInfo { trusted, login_required: login }), None);
            let posture = classify_posture(&probe);
            if trusted != Some(true) {
                prop_assert_eq!(posture, AuthPosture::Enforced);
            }
            let finding = moonraker_finding(ip(), MOONRAKER_PORT, &probe, "http://x");
            prop_assert!(finding.title.starts_with("Moonraker printer"));
        }
    }
}
