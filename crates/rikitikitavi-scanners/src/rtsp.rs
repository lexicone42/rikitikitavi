use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Scanner;

/// RTSP / ONVIF camera exposure scanner.
///
/// Tests whether a camera's video stream is reachable without authentication:
///  1. `OPTIONS` confirms an RTSP server (reply begins `RTSP/1.0`) and yields
///     its `Server` header for vendor fingerprinting.
///  2. `DESCRIBE` against common stream routes. A `200 OK` with no
///     `WWW-Authenticate` challenge means the stream is served without
///     credentials; a `401`/`403` with `WWW-Authenticate` means auth is enforced.
///
/// Never pulls video frames or sends credentials; only probes hosts Phase 1
/// found with an RTSP port open.
pub struct RtspScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(4);

/// Cap on response bytes read; only the status line and headers are needed.
const MAX_RTSP_RESPONSE: usize = 8 * 1024;

/// RTSP control ports: 554 (standard) and 8554 (common alternate).
const RTSP_PORTS: &[u16] = &[554, 8554];

/// User-Agent sent on every probe.
const RTSP_USER_AGENT: &str = "rikitikitavi-scan";

/// Default stream routes tried with `DESCRIBE` (generic, Dahua, Hikvision,
/// ONVIF, and bare channel numbers).
const RTSP_ROUTES: &[&str] = &[
    "/",
    "/live.sdp",
    "/live",
    "/cam/realmonitor",
    "/Streaming/Channels/101",
    "/onvif1",
    "/11",
    "/12",
];

/// Camera vendor identified from the RTSP `Server` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CameraVendor {
    Hikvision,
    Dahua,
    Xiongmai,
    Axis,
    Unknown,
}

/// Parsed, security-relevant fields of an RTSP response.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RtspResponse {
    /// Numeric status code from the `RTSP/1.0 <code> <reason>` status line.
    status: u16,
    /// Value of the `Server` header, if present (for vendor fingerprinting).
    server: Option<String>,
    /// Whether a `WWW-Authenticate` header was present (an auth challenge).
    www_authenticate: bool,
}

/// Verdict from classifying a `DESCRIBE` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DescribeVerdict {
    /// `200 OK` with no auth challenge — the stream is reachable without creds.
    OpenNoAuth,
    /// `401`/`403` with a `WWW-Authenticate` challenge — auth is enforced.
    AuthRequired,
    /// Any other outcome (not found, server error, ambiguous).
    Other,
}

/// Build an RTSP `OPTIONS` request for `rtsp://ip:port/`.
fn build_options_request(ip: IpAddr, port: u16, cseq: u32) -> String {
    format!(
        "OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n\
         CSeq: {cseq}\r\n\
         User-Agent: {RTSP_USER_AGENT}\r\n\
         \r\n"
    )
}

/// Build an RTSP `DESCRIBE` request (asks for the stream's SDP) for
/// `rtsp://ip:port{route}`.
fn build_describe_request(ip: IpAddr, port: u16, route: &str, cseq: u32) -> String {
    format!(
        "DESCRIBE rtsp://{ip}:{port}{route} RTSP/1.0\r\n\
         CSeq: {cseq}\r\n\
         Accept: application/sdp\r\n\
         User-Agent: {RTSP_USER_AGENT}\r\n\
         \r\n"
    )
}

/// Parse an RTSP response's status line and the two headers we care about.
///
/// Returns `None` if the payload does not begin with `RTSP/1.0` (i.e. it is not
/// an RTSP server) or the status code cannot be parsed. Header matching is
/// case-insensitive, per RFC 2326.
fn parse_rtsp_response(raw: &str) -> Option<RtspResponse> {
    // The status line ends at the first CR or LF. Be tolerant of bare-LF servers.
    let line_end = raw.find(['\r', '\n']).unwrap_or(raw.len());
    let status_line = &raw[..line_end];

    let rest = status_line.strip_prefix("RTSP/1.0")?;
    // A space must separate the version from the status code.
    let rest = rest.strip_prefix(' ')?;
    let code_str = rest.split_whitespace().next()?;
    let status: u16 = code_str.parse().ok()?;

    let mut server = None;
    let mut www_authenticate = false;
    for line in raw.lines().skip(1) {
        let line = line.trim_end();
        if line.is_empty() {
            // Blank line terminates the header block; ignore any body (SDP).
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            if key.eq_ignore_ascii_case("Server") {
                let value = value.trim();
                if !value.is_empty() {
                    server = Some(value.to_owned());
                }
            } else if key.eq_ignore_ascii_case("WWW-Authenticate") {
                www_authenticate = true;
            }
        }
    }

    Some(RtspResponse {
        status,
        server,
        www_authenticate,
    })
}

/// Classify a `DESCRIBE` response into a reachability verdict.
const fn classify_describe(resp: &RtspResponse) -> DescribeVerdict {
    if resp.status == 200 && !resp.www_authenticate {
        DescribeVerdict::OpenNoAuth
    } else if (resp.status == 401 || resp.status == 403) && resp.www_authenticate {
        DescribeVerdict::AuthRequired
    } else {
        DescribeVerdict::Other
    }
}

/// Fingerprint the camera vendor from a `Server` header value.
///
/// Only unambiguous substrings match; otherwise [`CameraVendor::Unknown`].
fn fingerprint_vendor(server: &str) -> CameraVendor {
    let s = server.to_ascii_lowercase();
    if s.contains("hikvision") {
        CameraVendor::Hikvision
    } else if s.contains("dahua") {
        CameraVendor::Dahua
    } else if s.contains("xiongmai") || s.contains("netsurveillance") {
        CameraVendor::Xiongmai
    } else if s.contains("axis") {
        CameraVendor::Axis
    } else {
        CameraVendor::Unknown
    }
}

/// Human-readable vendor label.
const fn vendor_label(vendor: CameraVendor) -> &'static str {
    match vendor {
        CameraVendor::Hikvision => "Hikvision",
        CameraVendor::Dahua => "Dahua",
        CameraVendor::Xiongmai => "Xiongmai",
        CameraVendor::Axis => "Axis",
        CameraVendor::Unknown => "unknown vendor",
    }
}

/// CVEs to attach for an identified vendor (only when the `Server` header names
/// the vendor). Axis is fingerprinted but carries no blanket CVE.
fn vendor_cves(vendor: CameraVendor) -> Vec<String> {
    match vendor {
        // Unauthenticated command injection (CISA KEV).
        CameraVendor::Hikvision => vec!["CVE-2021-36260".to_owned()],
        // Authentication bypass across many Dahua devices.
        CameraVendor::Dahua => vec!["CVE-2021-33044".to_owned(), "CVE-2021-33045".to_owned()],
        // XMeye P2P stack buffer overflow (Xiongmai OEM cameras/DVRs).
        CameraVendor::Xiongmai => vec!["CVE-2018-10088".to_owned()],
        CameraVendor::Axis | CameraVendor::Unknown => Vec::new(),
    }
}

/// Perform one RTSP request over a fresh TCP connection and return the response
/// text (status line + headers, capped). Returns `None` on any timeout/IO error
/// or an empty reply.
async fn rtsp_exchange(ip: IpAddr, port: u16, request: &[u8]) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(request))
        .await
        .ok()?
        .ok()?;

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        if buf.len() >= MAX_RTSP_RESPONSE {
            break;
        }
        // Timeout, or a read error — return what we have so far.
        let Ok(Ok(n)) = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut chunk)).await else {
            break;
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        // Stop as soon as the header block is complete; we never need the body.
        if find_header_end(&buf).is_some() {
            break;
        }
    }

    if buf.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Find the end of the HTTP/RTSP-style header block (the `\r\n\r\n` separator).
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Outcome of probing a single RTSP endpoint.
struct RtspProbe {
    /// The `Server` header from the `OPTIONS` reply, if any.
    server: Option<String>,
    /// First route found reachable without authentication, if any.
    open_route: Option<String>,
    /// Whether at least one route responded with an auth challenge.
    auth_required: bool,
}

/// Probe one RTSP endpoint: confirm it speaks RTSP via `OPTIONS`, then walk the
/// route dictionary with `DESCRIBE`. Returns `None` if the host is not RTSP.
async fn probe_rtsp(ip: IpAddr, port: u16) -> Option<RtspProbe> {
    let options_req = build_options_request(ip, port, 1);
    let raw = rtsp_exchange(ip, port, options_req.as_bytes()).await?;
    let options_resp = parse_rtsp_response(&raw)?;

    let mut open_route = None;
    let mut auth_required = false;

    // CSeq starts at 2 (the OPTIONS probe used 1) and increments per route.
    for (cseq, route) in (2_u32..).zip(RTSP_ROUTES.iter()) {
        let req = build_describe_request(ip, port, route, cseq);
        let Some(raw) = rtsp_exchange(ip, port, req.as_bytes()).await else {
            continue;
        };
        let Some(resp) = parse_rtsp_response(&raw) else {
            continue;
        };
        match classify_describe(&resp) {
            DescribeVerdict::OpenNoAuth => {
                // One open stream is enough; stop probing further routes.
                open_route = Some((*route).to_owned());
                break;
            }
            DescribeVerdict::AuthRequired => auth_required = true,
            DescribeVerdict::Other => {}
        }
    }

    Some(RtspProbe {
        server: options_resp.server,
        open_route,
        auth_required,
    })
}

#[async_trait]
impl Scanner for RtspScanner {
    fn id(&self) -> &'static str {
        "rtsp"
    }

    fn name(&self) -> &'static str {
        "RTSP/ONVIF Camera Exposure"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running RTSP/ONVIF camera exposure scan");
        let mut findings = Vec::new();

        // Skip below Active intensity — this performs a DESCRIBE route walk.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping RTSP scan in quick scan mode");
            return Ok(findings);
        }

        // Only target hosts Phase 1 found with an RTSP port open.
        let targets: Vec<(IpAddr, Vec<u16>)> = ctx
            .discovered_devices
            .iter()
            .map(|d| {
                let rtsp_ports: Vec<u16> = d
                    .open_ports
                    .iter()
                    .filter(|p| RTSP_PORTS.contains(&p.port))
                    .map(|p| p.port)
                    .collect();
                (d.ip, rtsp_ports)
            })
            .filter(|(_, ports)| !ports.is_empty())
            .collect();

        if targets.is_empty() {
            tracing::info!("no RTSP targets found");
            return Ok(findings);
        }

        tracing::info!(
            target_count = targets.len(),
            "checking RTSP camera exposure"
        );

        for (ip, ports) in &targets {
            for &port in ports {
                probe_and_report(ip, port, &mut findings).await;
            }
        }

        tracing::info!(
            findings_count = findings.len(),
            "RTSP/ONVIF camera exposure scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        20
    }

    fn relevant_ports(&self) -> &[u16] {
        RTSP_PORTS
    }
}

/// Probe one endpoint and push any findings.
async fn probe_and_report(ip: &IpAddr, port: u16, findings: &mut Vec<Finding>) {
    let Some(probe) = probe_rtsp(*ip, port).await else {
        return;
    };

    let vendor = probe
        .server
        .as_deref()
        .map_or(CameraVendor::Unknown, fingerprint_vendor);
    let cves = vendor_cves(vendor);
    let server_note = probe.server.as_ref().map_or_else(String::new, |s| {
        format!(
            " The server identifies itself as \"{s}\" ({}).",
            vendor_label(vendor)
        )
    });

    if let Some(route) = probe.open_route {
        let mut finding = Finding::new(
            "rtsp",
            &format!("RTSP stream reachable without authentication on {ip}:{port}{route}"),
            &format!(
                "The RTSP server at {ip}:{port} returned a 200 OK to a DESCRIBE for \
                 rtsp://{ip}:{port}{route} with no WWW-Authenticate challenge. The video \
                 stream's media description — and, in practice, the live stream itself — \
                 is reachable by anyone on the network (and by anyone on the internet if \
                 this port is forwarded). Set a strong camera password, enable RTSP \
                 authentication, and never port-forward 554/8554 to the internet.{server_note}"
            ),
            Severity::High,
        )
        .with_confidence(rikitikitavi_core::Confidence::Confirmed)
        .with_ip(*ip)
        .with_port(port)
        .with_service("RTSP")
        .with_cwe("CWE-306")
        .with_evidence(format!(
            "DESCRIBE {route} -> 200 OK, no WWW-Authenticate challenge"
        ))
        .with_references(refs![
            "https://cwe.mitre.org/data/definitions/306.html",
            "https://owasp.org/www-project-internet-of-things/",
        ]);
        if !cves.is_empty() {
            finding = finding.with_cve_ids(cves);
        }
        findings.push(finding);
    } else if probe.auth_required {
        // Server challenged for credentials; none are tried. Presence note only.
        let mut finding = Finding::new(
            "rtsp",
            &format!("RTSP server requires authentication on {ip}:{port}"),
            &format!(
                "An RTSP server at {ip}:{port} responded to DESCRIBE with an \
                 authentication challenge (401/403 with WWW-Authenticate). This is the \
                 correct posture. Ensure the camera uses a strong, unique password rather \
                 than a factory default.{server_note}"
            ),
            Severity::Info,
        )
        .with_confidence(rikitikitavi_core::Confidence::Probable)
        .with_ip(*ip)
        .with_port(port)
        .with_service("RTSP");
        if !cves.is_empty() {
            finding = finding.with_cve_ids(cves);
        }
        findings.push(finding);
    } else {
        // RTSP confirmed by OPTIONS, but no route open or challenged. Presence note.
        let mut finding = Finding::new(
            "rtsp",
            &format!("RTSP server present on {ip}:{port}"),
            &format!(
                "An RTSP server is listening on {ip}:{port} (confirmed via OPTIONS). No \
                 default stream route was reachable without authentication in the routes \
                 checked. Verify the camera enforces authentication and is not exposed to \
                 the internet.{server_note}"
            ),
            Severity::Info,
        )
        .with_confidence(rikitikitavi_core::Confidence::Probable)
        .with_ip(*ip)
        .with_port(port)
        .with_service("RTSP");
        if !cves.is_empty() {
            finding = finding.with_cve_ids(cves);
        }
        findings.push(finding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ip() -> IpAddr {
        "192.0.2.10".parse().unwrap()
    }

    // ── OPTIONS request builder ─────────────────────────────────────

    #[test]
    fn test_build_options_request_exact() {
        let req = build_options_request(ip(), 554, 1);
        assert_eq!(
            req,
            "OPTIONS rtsp://192.0.2.10:554/ RTSP/1.0\r\n\
             CSeq: 1\r\n\
             User-Agent: rikitikitavi-scan\r\n\
             \r\n"
        );
    }

    #[test]
    fn test_build_options_request_ends_with_blank_line() {
        let req = build_options_request(ip(), 8554, 7);
        assert!(req.ends_with("\r\n\r\n"));
        assert!(req.starts_with("OPTIONS rtsp://192.0.2.10:8554/ RTSP/1.0\r\n"));
        assert!(req.contains("CSeq: 7\r\n"));
    }

    // ── DESCRIBE request builder ────────────────────────────────────

    #[test]
    fn test_build_describe_request_exact() {
        let req = build_describe_request(ip(), 554, "/live.sdp", 2);
        assert_eq!(
            req,
            "DESCRIBE rtsp://192.0.2.10:554/live.sdp RTSP/1.0\r\n\
             CSeq: 2\r\n\
             Accept: application/sdp\r\n\
             User-Agent: rikitikitavi-scan\r\n\
             \r\n"
        );
    }

    #[test]
    fn test_build_describe_request_root_route() {
        let req = build_describe_request(ip(), 8554, "/", 3);
        assert!(req.starts_with("DESCRIBE rtsp://192.0.2.10:8554/ RTSP/1.0\r\n"));
        assert!(req.contains("Accept: application/sdp\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_describe_request_per_route_cseq_and_path() {
        for (i, route) in RTSP_ROUTES.iter().enumerate() {
            let cseq = u32::try_from(i).unwrap() + 2;
            let req = build_describe_request(ip(), 554, route, cseq);
            assert!(req.contains(&format!("rtsp://192.0.2.10:554{route} RTSP/1.0")));
            assert!(req.contains(&format!("CSeq: {cseq}\r\n")));
        }
    }

    // ── Response parser ─────────────────────────────────────────────

    #[test]
    fn test_parse_rtsp_response_options_ok() {
        let raw = "RTSP/1.0 200 OK\r\n\
                   CSeq: 1\r\n\
                   Server: Hikvision-Webs\r\n\
                   Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n";
        let resp = parse_rtsp_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.server.as_deref(), Some("Hikvision-Webs"));
        assert!(!resp.www_authenticate);
    }

    #[test]
    fn test_parse_rtsp_response_describe_200_no_auth() {
        let raw = "RTSP/1.0 200 OK\r\n\
                   CSeq: 2\r\n\
                   Content-Type: application/sdp\r\n\
                   Content-Length: 42\r\n\r\n\
                   v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n";
        let resp = parse_rtsp_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(!resp.www_authenticate);
    }

    #[test]
    fn test_parse_rtsp_response_401_with_challenge() {
        let raw = "RTSP/1.0 401 Unauthorized\r\n\
                   CSeq: 2\r\n\
                   WWW-Authenticate: Digest realm=\"IP Camera\", nonce=\"abc\"\r\n\
                   Server: Dahua Rtsp Server\r\n\r\n";
        let resp = parse_rtsp_response(raw).unwrap();
        assert_eq!(resp.status, 401);
        assert!(resp.www_authenticate);
        assert_eq!(resp.server.as_deref(), Some("Dahua Rtsp Server"));
    }

    #[test]
    fn test_parse_rtsp_response_header_case_insensitive() {
        let raw = "RTSP/1.0 401 Unauthorized\r\n\
                   www-authenticate: Basic realm=\"cam\"\r\n\
                   SERVER: AXIS-Video\r\n\r\n";
        let resp = parse_rtsp_response(raw).unwrap();
        assert!(resp.www_authenticate);
        assert_eq!(resp.server.as_deref(), Some("AXIS-Video"));
    }

    #[test]
    fn test_parse_rtsp_response_bare_lf() {
        // Some cheap firmwares use bare LF line endings.
        let raw = "RTSP/1.0 200 OK\nCSeq: 1\nServer: XM\n\n";
        let resp = parse_rtsp_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.server.as_deref(), Some("XM"));
    }

    #[test]
    fn test_parse_rtsp_response_not_rtsp() {
        assert!(parse_rtsp_response("HTTP/1.1 200 OK\r\n\r\n").is_none());
        assert!(parse_rtsp_response("garbage").is_none());
        assert!(parse_rtsp_response("").is_none());
    }

    #[test]
    fn test_parse_rtsp_response_malformed_status() {
        // Correct prefix but no numeric status code.
        assert!(parse_rtsp_response("RTSP/1.0 OK\r\n\r\n").is_none());
        assert!(parse_rtsp_response("RTSP/1.0\r\n\r\n").is_none());
    }

    #[test]
    fn test_parse_rtsp_response_no_server_header() {
        let raw = "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n";
        let resp = parse_rtsp_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.server.is_none());
        assert!(!resp.www_authenticate);
    }

    // ── DESCRIBE classifier ─────────────────────────────────────────

    #[test]
    fn test_classify_describe_open() {
        let resp = RtspResponse {
            status: 200,
            server: None,
            www_authenticate: false,
        };
        assert_eq!(classify_describe(&resp), DescribeVerdict::OpenNoAuth);
    }

    #[test]
    fn test_classify_describe_200_with_challenge_is_not_open() {
        // A 200 that somehow also carries a challenge is not "open".
        let resp = RtspResponse {
            status: 200,
            server: None,
            www_authenticate: true,
        };
        assert_eq!(classify_describe(&resp), DescribeVerdict::Other);
    }

    #[test]
    fn test_classify_describe_401_auth_required() {
        let resp = RtspResponse {
            status: 401,
            server: None,
            www_authenticate: true,
        };
        assert_eq!(classify_describe(&resp), DescribeVerdict::AuthRequired);
    }

    #[test]
    fn test_classify_describe_403_auth_required() {
        let resp = RtspResponse {
            status: 403,
            server: None,
            www_authenticate: true,
        };
        assert_eq!(classify_describe(&resp), DescribeVerdict::AuthRequired);
    }

    #[test]
    fn test_classify_describe_401_without_header_is_other() {
        let resp = RtspResponse {
            status: 401,
            server: None,
            www_authenticate: false,
        };
        assert_eq!(classify_describe(&resp), DescribeVerdict::Other);
    }

    #[test]
    fn test_classify_describe_404_other() {
        let resp = RtspResponse {
            status: 404,
            server: None,
            www_authenticate: false,
        };
        assert_eq!(classify_describe(&resp), DescribeVerdict::Other);
    }

    // ── Vendor fingerprinting ───────────────────────────────────────

    #[test]
    fn test_fingerprint_vendor_hikvision() {
        assert_eq!(
            fingerprint_vendor("Hikvision-Webs"),
            CameraVendor::Hikvision
        );
        assert_eq!(
            fingerprint_vendor("HIKVISION RTSP Server/1.0"),
            CameraVendor::Hikvision
        );
    }

    #[test]
    fn test_fingerprint_vendor_dahua() {
        assert_eq!(fingerprint_vendor("Dahua Rtsp Server"), CameraVendor::Dahua);
    }

    #[test]
    fn test_fingerprint_vendor_xiongmai() {
        assert_eq!(
            fingerprint_vendor("NetSurveillance"),
            CameraVendor::Xiongmai
        );
        assert_eq!(fingerprint_vendor("Xiongmai"), CameraVendor::Xiongmai);
    }

    #[test]
    fn test_fingerprint_vendor_axis() {
        assert_eq!(fingerprint_vendor("AXIS-Video"), CameraVendor::Axis);
    }

    #[test]
    fn test_fingerprint_vendor_unknown() {
        assert_eq!(fingerprint_vendor("Rtsp Server"), CameraVendor::Unknown);
        assert_eq!(fingerprint_vendor(""), CameraVendor::Unknown);
    }

    // ── Vendor CVEs ─────────────────────────────────────────────────

    #[test]
    fn test_vendor_cves_hikvision() {
        assert_eq!(vendor_cves(CameraVendor::Hikvision), vec!["CVE-2021-36260"]);
    }

    #[test]
    fn test_vendor_cves_dahua() {
        assert_eq!(
            vendor_cves(CameraVendor::Dahua),
            vec!["CVE-2021-33044", "CVE-2021-33045"]
        );
    }

    #[test]
    fn test_vendor_cves_xiongmai() {
        assert_eq!(vendor_cves(CameraVendor::Xiongmai), vec!["CVE-2018-10088"]);
    }

    #[test]
    fn test_vendor_cves_axis_and_unknown_empty() {
        assert!(vendor_cves(CameraVendor::Axis).is_empty());
        assert!(vendor_cves(CameraVendor::Unknown).is_empty());
    }

    // ── Header-end detection ────────────────────────────────────────

    #[test]
    fn test_find_header_end() {
        assert_eq!(find_header_end(b"RTSP/1.0 200 OK\r\n\r\nBODY"), Some(15));
        assert!(find_header_end(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n").is_none());
        assert!(find_header_end(b"").is_none());
    }

    // ── Proptests ───────────────────────────────────────────────────

    proptest! {
        /// The parser never panics on arbitrary input.
        #[test]
        fn prop_parse_rtsp_response_no_panic(raw in ".*") {
            let _ = parse_rtsp_response(&raw);
        }

        /// A parsed "open" verdict is only ever reached from a 200 without a
        /// challenge.
        #[test]
        fn prop_classify_describe_open_requires_200_no_auth(
            status in 0u16..=600,
            www in any::<bool>(),
        ) {
            let resp = RtspResponse { status, server: None, www_authenticate: www };
            if classify_describe(&resp) == DescribeVerdict::OpenNoAuth {
                prop_assert_eq!(status, 200);
                prop_assert!(!www);
            }
        }

        /// Fingerprinting never panics and never invents CVEs for an
        /// unidentified vendor.
        #[test]
        fn prop_fingerprint_unknown_has_no_cves(server in ".*") {
            let v = fingerprint_vendor(&server);
            if v == CameraVendor::Unknown {
                prop_assert!(vendor_cves(v).is_empty());
            }
        }

        /// The DESCRIBE builder always yields a well-formed request line ending
        /// in a blank line.
        #[test]
        fn prop_build_describe_wellformed(cseq in 0u32..100_000, idx in 0usize..8) {
            let route = RTSP_ROUTES[idx];
            let req = build_describe_request(ip(), 554, route, cseq);
            let cseq_line = format!("CSeq: {cseq}\r\n");
            prop_assert!(req.starts_with("DESCRIBE rtsp://192.0.2.10:554"));
            prop_assert!(req.ends_with("\r\n\r\n"));
            prop_assert!(req.contains(&cseq_line));
        }
    }
}
