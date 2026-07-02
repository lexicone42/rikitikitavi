//! TR-069 / CWMP management-plane LAN-exposure scanner.
//!
//! TR-069 (CPE WAN Management Protocol, CWMP) is how an ISP's Auto
//! Configuration Server (ACS) remotely provisions customer routers. The CWMP
//! "connection request" listener conventionally runs on TCP 7547 and is meant
//! to face **only** the ISP's WAN side. A 7547 listener answering on the LAN is
//! a real, actionable exposure: it is a repeated mass-compromise vector
//! (the November 2016 Mirai/TR-064 outbreak abused 7547 on millions of CPEs)
//! and continues to yield router RCEs — e.g. `CVE-2025-9961` (TP-Link CWMP
//! stack overflow) and `CVE-2024-51138` (`DrayTek` Vigor).
//!
//! This scanner is pure detection: it performs an unauthenticated HTTP probe of
//! an already-open 7547 port and classifies the response. It never attempts
//! credential brute-forcing or any state-changing CWMP RPC.

use async_trait::async_trait;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::finding::Remediation;
use rikitikitavi_models::{Finding, ScanContext};
use std::net::IpAddr;
use std::time::Duration;

use crate::Scanner;

/// TR-069 / CWMP LAN-exposure scanner.
///
/// Flags hosts whose CWMP connection-request listener (TCP 7547) is reachable
/// from the LAN, which should never be the case on a correctly firewalled
/// customer router.
pub struct Tr069Scanner;

/// Conventional CWMP connection-request port.
const TR069_PORT: u16 = 7547;

/// Bound every HTTP phase of the probe. CWMP responses are tiny; a few seconds
/// is ample and keeps a hostile or dead host from stalling the scan.
const HTTP_TIMEOUT: Duration = Duration::from_secs(4);

/// Body read cap. A CWMP fault/`GetRPCMethods` document or a `401` challenge
/// page is a few hundred bytes; 64 `KiB` is generous while bounding a hostile
/// device that streams forever.
const BODY_CAP: usize = 64 * 1024;

/// Case-insensitive tokens that, when seen in the `WWW-Authenticate`, `Server`,
/// or body of a 7547 response, positively identify a CWMP endpoint (as opposed
/// to some unrelated HTTP service that merely happens to bind 7547).
const CWMP_TOKENS: &[&str] = &[
    "cwmp",
    "tr-069",
    "tr069",
    "dslforum",
    "urn:dslforum-org",
    "connectionrequest",
    "connection request",
    "getrpcmethods",
    "connection_request",
];

/// Relevant fields extracted from a 7547 HTTP response for classification.
///
/// Kept as a plain data struct (no I/O) so the classifier can be unit-tested
/// against synthetic responses without a live device.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tr069Response {
    /// HTTP status code (e.g. `401` for the typical Basic-auth challenge).
    status: u16,
    /// `WWW-Authenticate` header value, if the server issued a challenge.
    www_authenticate: Option<String>,
    /// `Server` header value, if present.
    server: Option<String>,
    /// Response body (already capped by the caller).
    body: String,
}

/// Outcome of classifying a 7547 exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tr069Signal {
    /// A CWMP / connection-request signature was observed in the response —
    /// the endpoint is demonstrably TR-069.
    CwmpConfirmed,
    /// An HTTP server answered on 7547 but exposed no CWMP signature. Still an
    /// exposure worth reporting, but the CWMP nature is only inferred from the
    /// port convention.
    HttpServer,
    /// The port is open (per Phase 1 discovery) but no HTTP response was
    /// obtained during this probe.
    OpenPortOnly,
}

impl Tr069Signal {
    /// Evidence strength this signal justifies.
    const fn confidence(self) -> Confidence {
        match self {
            Self::CwmpConfirmed => Confidence::Confirmed,
            Self::HttpServer => Confidence::Probable,
            Self::OpenPortOnly => Confidence::Inferred,
        }
    }
}

/// Probe an open 7547 port over HTTP and extract the fields we classify on.
///
/// Returns `None` if no HTTP response could be obtained. All network I/O is
/// bounded by [`HTTP_TIMEOUT`]; the body is capped by [`BODY_CAP`].
async fn probe_tr069(ip: IpAddr, port: u16) -> Option<Tr069Response> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;

    let url = format!("http://{ip}:{port}/");
    let resp = tokio::time::timeout(HTTP_TIMEOUT, client.get(&url).send())
        .await
        .ok()?
        .ok()?;

    let status = resp.status().as_u16();
    let www_authenticate = header_string(&resp, "www-authenticate");
    let server = header_string(&resp, "server");

    let body = tokio::time::timeout(
        HTTP_TIMEOUT,
        crate::http_util::read_body_capped(resp, BODY_CAP),
    )
    .await
    .unwrap_or_default();

    Some(Tr069Response {
        status,
        www_authenticate,
        server,
        body,
    })
}

/// Extract a header value as an owned `String`, if present and valid UTF-8.
fn header_string(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
}

/// Classify a 7547 HTTP response into a [`Tr069Signal`].
///
/// A CWMP token in the auth challenge, `Server` header, or a bounded prefix of
/// the body upgrades the result to [`Tr069Signal::CwmpConfirmed`]; otherwise any
/// HTTP response is [`Tr069Signal::HttpServer`].
fn classify_tr069_response(resp: &Tr069Response) -> Tr069Signal {
    // Only scan a bounded prefix of the body: signatures appear early, and this
    // keeps the (lossy already) string cheap to lowercase.
    let body_prefix: String = resp.body.chars().take(8192).collect();
    let haystack = format!(
        "{} {} {}",
        resp.www_authenticate.as_deref().unwrap_or(""),
        resp.server.as_deref().unwrap_or(""),
        body_prefix,
    )
    .to_ascii_lowercase();

    if CWMP_TOKENS.iter().any(|tok| haystack.contains(tok)) {
        Tr069Signal::CwmpConfirmed
    } else {
        Tr069Signal::HttpServer
    }
}

/// Map an identifiable router vendor (from OUI vendor and/or `Server` header)
/// to the known CWMP/7547 CVEs for that vendor.
///
/// Returns an empty vec when the vendor is not recognised — the finding stays
/// general in that case rather than attaching a CVE that may not apply.
fn cve_ids_for_vendor(hay: &str) -> Vec<String> {
    let h = hay.to_ascii_lowercase();
    let mut cves = Vec::new();
    if h.contains("tp-link") || h.contains("tplink") {
        // TP-Link CWMP stack buffer overflow (unauthenticated RCE).
        cves.push("CVE-2025-9961".to_owned());
    }
    if h.contains("draytek") || h.contains("vigor") {
        // DrayTek Vigor CWMP/ACS memory corruption.
        cves.push("CVE-2024-51138".to_owned());
    }
    if h.contains("zyxel") || h.contains("eir") {
        // Eir/Zyxel D1000 — the canonical 7547 TR-064 mass-exploitation CVE.
        cves.push("CVE-2016-10372".to_owned());
    }
    cves
}

/// Build the remediation guidance shared by all TR-069 exposure findings.
fn tr069_remediation() -> Remediation {
    Remediation {
        description: "TR-069/CWMP remote management should not be reachable from \
                      the LAN — it is intended to face only the ISP's WAN side. A \
                      7547 listener on the LAN exposes a well-known remote-compromise \
                      surface."
            .to_owned(),
        steps: vec![
            "Confirm whether your ISP requires TR-069 at all; if not, disable \
             remote/CWMP management in the router configuration."
                .to_owned(),
            "If TR-069 is required, ensure the CWMP connection-request listener is \
             bound to the WAN interface only and firewalled off from the LAN."
                .to_owned(),
            "Update the router firmware — 7547/CWMP stacks have a long history of \
             remotely exploitable bugs (Mirai/TR-064, and vendor CVEs)."
                .to_owned(),
            "Restrict the ACS source to your ISP's documented addresses where the \
             router supports an ACS allow-list."
                .to_owned(),
        ],
        effort: Some("15 minutes (router config); firmware update varies".to_owned()),
    }
}

/// Build the finding for a TR-069/CWMP LAN exposure.
///
/// `vendor_hay` is a free-form haystack (OUI vendor and/or `Server` header) used
/// only to attach vendor-specific CVEs. `evidence` is an optional short `PoC`
/// string (the auth challenge or server banner).
fn build_tr069_finding(
    ip: IpAddr,
    port: u16,
    signal: Tr069Signal,
    vendor_hay: &str,
    evidence: Option<&str>,
) -> Finding {
    let detail = match signal {
        Tr069Signal::CwmpConfirmed => {
            "The endpoint returned a CWMP / connection-request signature, \
             confirming an ISP remote-management (TR-069) service is answering \
             on the LAN."
        }
        Tr069Signal::HttpServer => {
            "An HTTP server answered on the CWMP connection-request port (7547) \
             from the LAN. This port should only be reachable from the ISP's WAN \
             side; a LAN-facing listener is a remote-management exposure."
        }
        Tr069Signal::OpenPortOnly => {
            "TCP 7547 (the CWMP connection-request port) is open on the LAN but \
             did not return an HTTP response to this probe. This port should only \
             be reachable from the ISP's WAN side."
        }
    };

    let cves = cve_ids_for_vendor(vendor_hay);

    let mut finding = Finding::new(
        "tr069",
        "ISP remote-management (TR-069/CWMP) reachable on the LAN",
        &format!(
            "{detail} TR-069/CWMP on TCP 7547 is a repeated mass-compromise vector \
             (Mirai/TR-064) and continues to yield router RCEs. It should not be \
             reachable from the LAN — check the router configuration and firmware."
        ),
        Severity::High,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service("CWMP/TR-069")
    .with_confidence(signal.confidence())
    .with_cwe("CWE-306")
    .with_references(refs![
        "https://en.wikipedia.org/wiki/TR-069",
        "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/",
        "https://attack.mitre.org/techniques/T1190/",
    ])
    .with_remediation(tr069_remediation());

    if !cves.is_empty() {
        finding = finding.with_cve_ids(cves);
    }
    if let Some(ev) = evidence {
        finding = finding.with_evidence(ev);
    }
    finding
}

/// Derive a short `PoC` evidence string from a probe response.
fn build_evidence(resp: &Tr069Response) -> Option<String> {
    resp.www_authenticate.as_ref().map_or_else(
        || {
            resp.server.as_ref().map_or_else(
                || Some(format!("HTTP {} on port {TR069_PORT}", resp.status)),
                |server| Some(format!("HTTP {} — Server: {server}", resp.status)),
            )
        },
        |wa| Some(format!("HTTP {} — WWW-Authenticate: {wa}", resp.status)),
    )
}

#[async_trait]
impl Scanner for Tr069Scanner {
    fn id(&self) -> &'static str {
        "tr069"
    }

    fn name(&self) -> &'static str {
        "TR-069/CWMP Exposure"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running TR-069/CWMP exposure scan");
        let mut findings = Vec::new();

        // Skip in quick/passive mode — this issues an active HTTP probe.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping TR-069 scan in quick scan mode");
            return Ok(findings);
        }

        if ctx.discovered_devices.is_empty() {
            tracing::info!("no discovered devices, skipping TR-069 scan");
            return Ok(findings);
        }

        for device in &ctx.discovered_devices {
            // Only probe hosts where 7547 was actually found open in Phase 1.
            if !device.open_ports.iter().any(|p| p.port == TR069_PORT) {
                continue;
            }

            let (signal, evidence, server) = match probe_tr069(device.ip, TR069_PORT).await {
                Some(resp) => {
                    let signal = classify_tr069_response(&resp);
                    let evidence = build_evidence(&resp);
                    (signal, evidence, resp.server.clone())
                }
                None => (Tr069Signal::OpenPortOnly, None, None),
            };

            let vendor_hay = format!(
                "{} {}",
                device.vendor.as_deref().unwrap_or(""),
                server.as_deref().unwrap_or(""),
            );

            findings.push(build_tr069_finding(
                device.ip,
                TR069_PORT,
                signal,
                &vendor_hay,
                evidence.as_deref(),
            ));
        }

        tracing::info!(
            findings_count = findings.len(),
            "TR-069/CWMP exposure scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        15
    }

    fn relevant_ports(&self) -> &[u16] {
        &[TR069_PORT]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn resp(
        status: u16,
        www_authenticate: Option<&str>,
        server: Option<&str>,
        body: &str,
    ) -> Tr069Response {
        Tr069Response {
            status,
            www_authenticate: www_authenticate.map(ToOwned::to_owned),
            server: server.map(ToOwned::to_owned),
            body: body.to_owned(),
        }
    }

    // ── classifier: CWMP-signature detection ────────────────────────

    #[test]
    fn cwmp_realm_in_www_authenticate_is_confirmed() {
        let r = resp(401, Some("Basic realm=\"cwmp\""), Some("RomPager/4.07"), "");
        assert_eq!(classify_tr069_response(&r), Tr069Signal::CwmpConfirmed);
    }

    #[test]
    fn tr069_connection_request_realm_is_confirmed() {
        let r = resp(
            401,
            Some("Basic realm=\"TR-069 Connection Request\""),
            None,
            "",
        );
        assert_eq!(classify_tr069_response(&r), Tr069Signal::CwmpConfirmed);
    }

    #[test]
    fn dslforum_soap_body_is_confirmed() {
        let body = "<?xml version=\"1.0\"?><soap:Envelope \
                    xmlns:cwmp=\"urn:dslforum-org:cwmp-1-0\"><soap:Body>\
                    <cwmp:GetRPCMethodsResponse/></soap:Body></soap:Envelope>";
        let r = resp(200, None, Some("nginx"), body);
        assert_eq!(classify_tr069_response(&r), Tr069Signal::CwmpConfirmed);
    }

    #[test]
    fn getrpcmethods_body_is_confirmed() {
        let r = resp(200, None, None, "GetRPCMethods");
        assert_eq!(classify_tr069_response(&r), Tr069Signal::CwmpConfirmed);
    }

    #[test]
    fn signature_match_is_case_insensitive() {
        let r = resp(401, Some("Basic realm=\"CWMP\""), None, "");
        assert_eq!(classify_tr069_response(&r), Tr069Signal::CwmpConfirmed);
    }

    // ── classifier: plain HTTP server, no signature ─────────────────

    #[test]
    fn generic_basic_auth_without_signature_is_http_server() {
        // A 401 Basic challenge with a non-CWMP realm — still an exposure, but
        // the CWMP nature is not demonstrated.
        let r = resp(401, Some("Basic realm=\"index\""), Some("lighttpd"), "");
        assert_eq!(classify_tr069_response(&r), Tr069Signal::HttpServer);
    }

    #[test]
    fn plain_200_without_signature_is_http_server() {
        let r = resp(200, None, Some("Apache"), "<html>hello</html>");
        assert_eq!(classify_tr069_response(&r), Tr069Signal::HttpServer);
    }

    #[test]
    fn empty_response_without_signature_is_http_server() {
        let r = resp(404, None, None, "");
        assert_eq!(classify_tr069_response(&r), Tr069Signal::HttpServer);
    }

    // ── confidence mapping ──────────────────────────────────────────

    #[test]
    fn confidence_mapping_is_honest() {
        assert_eq!(
            Tr069Signal::CwmpConfirmed.confidence(),
            Confidence::Confirmed
        );
        assert_eq!(Tr069Signal::HttpServer.confidence(), Confidence::Probable);
        assert_eq!(Tr069Signal::OpenPortOnly.confidence(), Confidence::Inferred);
    }

    // ── vendor → CVE mapping ────────────────────────────────────────

    #[test]
    fn tplink_vendor_maps_to_cwmp_cve() {
        assert_eq!(
            cve_ids_for_vendor("TP-Link Technologies"),
            ["CVE-2025-9961"]
        );
        assert_eq!(cve_ids_for_vendor("tplink"), ["CVE-2025-9961"]);
    }

    #[test]
    fn draytek_vendor_maps_to_cve() {
        assert_eq!(cve_ids_for_vendor("DrayTek Corp"), ["CVE-2024-51138"]);
        assert_eq!(cve_ids_for_vendor("Server: Vigor2760"), ["CVE-2024-51138"]);
    }

    #[test]
    fn zyxel_vendor_maps_to_cve() {
        assert_eq!(
            cve_ids_for_vendor("ZyXEL Communications"),
            ["CVE-2016-10372"]
        );
    }

    #[test]
    fn unknown_vendor_has_no_cve() {
        assert!(cve_ids_for_vendor("Netgear Inc").is_empty());
        assert!(cve_ids_for_vendor("").is_empty());
    }

    // ── finding builder ─────────────────────────────────────────────

    #[test]
    fn confirmed_finding_is_high_confirmed_cwe306() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let f = build_tr069_finding(
            ip,
            TR069_PORT,
            Tr069Signal::CwmpConfirmed,
            "TP-Link",
            Some("HTTP 401 — WWW-Authenticate: Basic realm=\"cwmp\""),
        );
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-306"));
        assert_eq!(f.affected_port, Some(TR069_PORT));
        assert_eq!(f.affected_service.as_deref(), Some("CWMP/TR-069"));
        assert_eq!(f.cve_ids, ["CVE-2025-9961"]);
        assert!(f.evidence.is_some());
        assert!(f.remediation.is_some());
    }

    #[test]
    fn http_server_finding_is_probable_and_general() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let f = build_tr069_finding(ip, TR069_PORT, Tr069Signal::HttpServer, "", None);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Probable);
        assert!(f.cve_ids.is_empty());
        assert!(f.evidence.is_none());
    }

    #[test]
    fn open_port_only_finding_is_inferred() {
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        let f = build_tr069_finding(ip, TR069_PORT, Tr069Signal::OpenPortOnly, "", None);
        assert_eq!(f.confidence, Confidence::Inferred);
    }

    // ── evidence builder ────────────────────────────────────────────

    #[test]
    fn evidence_prefers_www_authenticate() {
        let r = resp(401, Some("Basic realm=\"cwmp\""), Some("RomPager"), "");
        let ev = build_evidence(&r).unwrap();
        assert!(ev.contains("WWW-Authenticate"));
        assert!(ev.contains("cwmp"));
    }

    #[test]
    fn evidence_falls_back_to_server_then_status() {
        let with_server = resp(200, None, Some("nginx"), "");
        assert!(build_evidence(&with_server).unwrap().contains("nginx"));
        let bare = resp(500, None, None, "");
        assert!(build_evidence(&bare).unwrap().contains("500"));
    }

    // ── proptests: classifiers never panic ──────────────────────────

    proptest! {
        #[test]
        fn prop_classify_no_panic(
            status in 0_u16..=599,
            wa in proptest::option::of(".*"),
            server in proptest::option::of(".*"),
            body in ".*",
        ) {
            let r = Tr069Response {
                status,
                www_authenticate: wa,
                server,
                body,
            };
            let _ = classify_tr069_response(&r);
            let _ = build_evidence(&r);
        }

        #[test]
        fn prop_cve_for_vendor_no_panic(hay in ".*") {
            let _ = cve_ids_for_vendor(&hay);
        }
    }
}
