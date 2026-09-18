use async_trait::async_trait;
use reqwest::redirect::Policy;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, Remediation, ScanContext};
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use crate::Scanner;

/// `PaperCut` NG/MF print-management server scanner.
///
/// Read-only and unauthenticated: `GET /`, `GET /app` and `GET /api/health` on
/// the admin ports. The login page references its own assets with a cache-buster
/// query string (`/css/style.css?76602papercut-mf`) carrying the **build id** and
/// the **edition**; the page footer carries edition and licensee only. The
/// August 2026 advisory (CVE-2026-81578 chained with CVE-2026-82078, CISA KEV
/// 2026-08-31) applies to all NG and MF versions, so a build that is not a known
/// fixed build is reported rather than assumed safe.
pub struct PaperCutScanner;

const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
/// Login pages are small; cap well below the shared 2 MiB default.
const MAX_BODY_BYTES: usize = 512 * 1024;

/// `PaperCut` admin interface (HTTP).
const ADMIN_PORT: u16 = 9191;
/// `PaperCut` admin interface (HTTPS, usually a self-signed certificate).
const ADMIN_TLS_PORT: u16 = 9192;
const PAPERCUT_PORTS: &[u16] = &[ADMIN_PORT, ADMIN_TLS_PORT];

/// Paths probed, in order. All are GETs of unauthenticated endpoints.
const ASSET_PATHS: &[&str] = &["/", "/app"];
/// Secondary fingerprint: answers 401 to an unauthenticated request.
const HEALTH_PATH: &str = "/api/health";

/// The August 2026 chain: missing authentication into unsafe dynamic class
/// loading = unauthenticated remote code execution.
const PAPERCUT_CVES: &[&str] = &["CVE-2026-81578", "CVE-2026-82078"];

/// Published fixed builds, as `(build id, edition, release)`.
///
/// Build ids are **not** monotonic across branches (76610 > 76604 > 76602) and
/// Emergency Patches 1-3 carry earlier build ids while being fixed, so a build
/// outside this table is "not confirmed patched", never "confirmed vulnerable".
const KNOWN_FIXED_BUILDS: &[(u32, Edition, &str)] = &[
    (76602, Edition::Mf, "26.0.5"),
    (76603, Edition::Ng, "26.0.5"),
    (76604, Edition::Mf, "25.0.13"),
    (76605, Edition::Ng, "25.0.13"),
    (76610, Edition::Mf, "24.1.10"),
    (76611, Edition::Ng, "24.1.10"),
];

// ── Pure parsing / classification (unit-tested below) ───────────────────

/// `PaperCut` edition, from the asset cache-buster suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edition {
    /// `PaperCut` MF.
    Mf,
    /// `PaperCut` NG.
    Ng,
}

impl fmt::Display for Edition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Mf => "MF",
            Self::Ng => "NG",
        })
    }
}

/// Build id and edition recovered from an asset cache-buster query string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PaperCutAsset {
    build: u32,
    edition: Edition,
}

/// Patch state derived from the observed build id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildVerdict {
    /// Build id matches a published fixed build of that edition.
    Fixed(&'static str),
    /// Build id parsed but is not a known fixed build.
    NotFixed,
    /// `PaperCut` identified but no build id recoverable.
    Unknown,
}

/// Extract build id and edition from an asset path cache-buster.
///
/// Equivalent to `\?(\d{4,6})papercut-(mf|ng)`, case-insensitive; returns the
/// first match in document order.
fn parse_papercut_asset(body: &str) -> Option<PaperCutAsset> {
    const TOKEN: &str = "papercut-";

    let lower = body.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut cursor = 0usize;

    while let Some(offset) = lower[cursor..].find(TOKEN) {
        let token_start = cursor + offset;
        let suffix_start = token_start + TOKEN.len();
        cursor = suffix_start;

        let edition = match lower.get(suffix_start..suffix_start + 2) {
            Some("mf") => Edition::Mf,
            Some("ng") => Edition::Ng,
            _ => continue,
        };

        let mut digits_start = token_start;
        while digits_start > 0 && bytes[digits_start - 1].is_ascii_digit() {
            digits_start -= 1;
        }
        let digit_len = token_start - digits_start;
        if !(4..=6).contains(&digit_len) {
            continue;
        }
        if digits_start == 0 || bytes[digits_start - 1] != b'?' {
            continue;
        }

        if let Ok(build) = lower[digits_start..token_start].parse::<u32>() {
            return Some(PaperCutAsset { build, edition });
        }
    }

    None
}

/// Look up a published fixed release for this build id and edition.
fn fixed_release(build: u32, edition: Edition) -> Option<&'static str> {
    KNOWN_FIXED_BUILDS
        .iter()
        .find(|(b, e, _)| *b == build && *e == edition)
        .map(|(_, _, release)| *release)
}

/// Classify the observed build against the published fixed builds.
fn classify_build(asset: Option<PaperCutAsset>) -> BuildVerdict {
    asset.map_or(BuildVerdict::Unknown, |a| {
        fixed_release(a.build, a.edition).map_or(BuildVerdict::NotFixed, BuildVerdict::Fixed)
    })
}

/// Case-insensitive `PaperCut` mention (page title, footer, health JSON).
fn mentions_papercut(text: &str) -> bool {
    text.to_ascii_lowercase().contains("papercut")
}

// ── Finding builders (pure, unit-tested) ────────────────────────────────

/// What the probe learned about one endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PaperCutProbe {
    asset: Option<PaperCutAsset>,
    /// A `PaperCut` string appeared in a page body.
    page_marker: bool,
    /// `/api/health` answered 401 and mentioned `PaperCut`.
    health_401: bool,
}

impl PaperCutProbe {
    /// Whether anything identified the host as `PaperCut`.
    const fn identified(&self) -> bool {
        self.asset.is_some() || self.page_marker || self.health_401
    }
}

/// Evidence line: what was observed, not what it implies.
fn probe_evidence(probe: &PaperCutProbe) -> String {
    let mut parts = Vec::new();
    if let Some(asset) = probe.asset {
        parts.push(format!(
            "asset cache-buster ?{build}papercut-{suffix} (build {build}, edition {edition})",
            build = asset.build,
            suffix = asset.edition.to_string().to_ascii_lowercase(),
            edition = asset.edition
        ));
    }
    if probe.page_marker {
        parts.push("PaperCut string in login page".to_owned());
    }
    if probe.health_401 {
        parts.push(format!("{HEALTH_PATH} answered 401 with a PaperCut body"));
    }
    parts.join("; ")
}

fn papercut_remediation() -> Remediation {
    Remediation {
        description: "Upgrade PaperCut NG/MF to a fixed build and keep the admin \
                      interface off untrusted networks."
            .to_owned(),
        steps: vec![
            "Upgrade to PaperCut MF/NG 26.0.5, 25.0.13 or 24.1.10 (or later); \
             Emergency Patches 1-3 also carry the fix."
                .to_owned(),
            "Confirm the running build in About > Version, or from the login page \
             asset query string, against the vendor bulletin."
                .to_owned(),
            "Restrict TCP 9191/9192 to the print-management VLAN; never expose the \
             admin interface to the internet."
                .to_owned(),
            "Review application and web-access logs for unauthenticated requests \
             to administrative endpoints."
                .to_owned(),
        ],
        effort: Some("1 hour".to_owned()),
    }
}

fn papercut_references() -> Vec<String> {
    refs![
        "https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-81578",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-82078",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ]
}

/// Build the finding for one identified endpoint.
///
/// Three stable titles, one per [`BuildVerdict`]. A build matching a published
/// fixed build yields an exposure note with no CVEs attached, so risk scoring
/// does not charge a patched server for a KEV entry.
fn build_papercut_finding(ip: IpAddr, port: u16, probe: &PaperCutProbe) -> Finding {
    let verdict = classify_build(probe.asset);
    let edition = probe
        .asset
        .map_or_else(|| "NG/MF".to_owned(), |a| a.edition.to_string());

    let (title, description, severity, confidence) = match verdict {
        BuildVerdict::Fixed(release) => (
            format!("PaperCut NG/MF admin interface reachable on {ip}:{port}"),
            format!(
                "The host at {ip}:{port} runs PaperCut {edition}. Its build id \
                 matches the published fixed release {release}, so the August 2026 \
                 unauthenticated remote-code-execution chain (CVE-2026-81578 with \
                 CVE-2026-82078) appears patched. The admin interface is still \
                 reachable from this network segment; restrict it to the hosts \
                 that need it."
            ),
            Severity::Low,
            Confidence::Confirmed,
        ),
        BuildVerdict::NotFixed => (
            format!("PaperCut NG/MF build not confirmed patched on {ip}:{port}"),
            format!(
                "The host at {ip}:{port} runs PaperCut {edition} with a build id \
                 that is not one of the published fixed builds. The August 2026 \
                 advisory applies to all NG and MF versions: missing authentication \
                 (CVE-2026-81578) chained with unsafe dynamic class loading \
                 (CVE-2026-82078) yields unauthenticated remote code execution, and \
                 the chain is in CISA KEV. Build ids are not ordered across release \
                 branches, and Emergency Patches 1-3 carry earlier build ids while \
                 being fixed, so confirm the installed version against the vendor \
                 bulletin before concluding this server is vulnerable."
            ),
            Severity::High,
            Confidence::Probable,
        ),
        BuildVerdict::Unknown => (
            format!("PaperCut NG/MF exposed with unverified build on {ip}:{port}"),
            format!(
                "The host at {ip}:{port} identifies as PaperCut {edition}, but no \
                 build id could be read from the login page assets. The August 2026 \
                 advisory (CVE-2026-81578 chained with CVE-2026-82078, CISA KEV) \
                 applies to all NG and MF versions, so treat this server as \
                 unpatched until the build is verified in About > Version."
            ),
            Severity::Medium,
            Confidence::Inferred,
        ),
    };

    let finding = Finding::new("papercut", &title, &description, severity)
        .with_ip(ip)
        .with_port(port)
        .with_service("PaperCut")
        .with_confidence(confidence)
        .with_evidence(probe_evidence(probe))
        .with_references(papercut_references())
        .with_remediation(papercut_remediation());

    match verdict {
        BuildVerdict::Fixed(_) => finding,
        BuildVerdict::NotFixed | BuildVerdict::Unknown => finding
            .with_cwe("CWE-470")
            .with_cve_ids(PAPERCUT_CVES.iter().map(|s| (*s).to_owned()).collect()),
    }
}

// ── Network probe (read-only GETs, all bounded by tokio::time::timeout) ──

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

/// Probe one admin endpoint. `None` unless something identified it as `PaperCut`.
async fn probe_papercut(ip: IpAddr, port: u16) -> Option<PaperCutProbe> {
    let scheme = if port == ADMIN_TLS_PORT {
        "https"
    } else {
        "http"
    };
    let base = format!("{scheme}://{ip}:{port}");
    // Self-signed certificates are the norm on 9192; never send credentials.
    let client =
        crate::http_util::unauthenticated_probe_client(HTTP_TIMEOUT, Policy::none()).ok()?;

    let mut asset = None;
    let mut page_marker = false;
    for path in ASSET_PATHS {
        let Some((_, body)) = fetch(&client, &format!("{base}{path}")).await else {
            continue;
        };
        page_marker |= mentions_papercut(&body);
        if asset.is_none() {
            asset = parse_papercut_asset(&body);
        }
        if asset.is_some() {
            break;
        }
    }

    let health_401 = fetch(&client, &format!("{base}{HEALTH_PATH}"))
        .await
        .is_some_and(|(status, body)| status == 401 && mentions_papercut(&body));

    let probe = PaperCutProbe {
        asset,
        page_marker,
        health_401,
    };
    probe.identified().then_some(probe)
}

#[async_trait]
impl Scanner for PaperCutScanner {
    fn id(&self) -> &'static str {
        "papercut"
    }

    fn name(&self) -> &'static str {
        "PaperCut NG/MF Exposure"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running PaperCut NG/MF exposure scan");
        let mut findings = Vec::new();

        // Network probe: Active intensity and above only.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping PaperCut scan in quick scan mode");
            return Ok(findings);
        }

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "papercut".to_owned(),
                message: e.to_string(),
            })?;

        for device in &ctx.discovered_devices {
            if exclusions.excludes_device(device) {
                continue;
            }
            for open in &device.open_ports {
                if !PAPERCUT_PORTS.contains(&open.port) {
                    continue;
                }
                if let Some(probe) = probe_papercut(device.ip, open.port).await {
                    findings.push(build_papercut_finding(device.ip, open.port, &probe));
                }
            }
        }

        tracing::info!(
            findings_count = findings.len(),
            "PaperCut NG/MF exposure scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        15
    }

    fn relevant_ports(&self) -> &[u16] {
        PAPERCUT_PORTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── parse_papercut_asset ────────────────────────────────────────

    #[test]
    fn test_asset_stylesheet_mf() {
        let body = r#"<link rel="stylesheet" href="/css/style.css?76602papercut-mf">"#;
        assert_eq!(
            parse_papercut_asset(body),
            Some(PaperCutAsset {
                build: 76602,
                edition: Edition::Mf
            })
        );
    }

    #[test]
    fn test_asset_script_ng() {
        let body = r#"<script src="/js/app.js?76611papercut-ng"></script>"#;
        assert_eq!(
            parse_papercut_asset(body),
            Some(PaperCutAsset {
                build: 76611,
                edition: Edition::Ng
            })
        );
    }

    #[test]
    fn test_asset_case_insensitive() {
        let body = "/css/Style.css?76604PaperCut-MF";
        assert_eq!(
            parse_papercut_asset(body),
            Some(PaperCutAsset {
                build: 76604,
                edition: Edition::Mf
            })
        );
    }

    #[test]
    fn test_asset_first_match_wins() {
        let body = "/a.css?76602papercut-mf and /b.js?76610papercut-mf";
        assert_eq!(parse_papercut_asset(body).unwrap().build, 76602);
    }

    #[test]
    fn test_asset_requires_question_mark() {
        assert!(parse_papercut_asset("/css/style.css76602papercut-mf").is_none());
        assert!(parse_papercut_asset("/css/style.css=76602papercut-mf").is_none());
    }

    #[test]
    fn test_asset_digit_length_bounds() {
        // Fewer than four digits, and more than six, are not build ids.
        assert!(parse_papercut_asset("?123papercut-mf").is_none());
        assert!(parse_papercut_asset("?1234567papercut-ng").is_none());
        assert_eq!(
            parse_papercut_asset("?1234papercut-ng").unwrap().build,
            1234
        );
        assert_eq!(
            parse_papercut_asset("?123456papercut-ng").unwrap().build,
            123_456
        );
    }

    #[test]
    fn test_asset_unknown_edition() {
        assert!(parse_papercut_asset("?76602papercut-xx").is_none());
        assert!(parse_papercut_asset("?76602papercut-").is_none());
    }

    #[test]
    fn test_asset_skips_bad_candidate_and_keeps_scanning() {
        let body = "?12papercut-mf then /x.css?76605papercut-ng";
        assert_eq!(
            parse_papercut_asset(body),
            Some(PaperCutAsset {
                build: 76605,
                edition: Edition::Ng
            })
        );
    }

    #[test]
    fn test_asset_absent() {
        assert!(parse_papercut_asset("").is_none());
        assert!(parse_papercut_asset("<html><title>nginx</title></html>").is_none());
        assert!(parse_papercut_asset("PaperCut MF login").is_none());
    }

    #[test]
    fn test_asset_multibyte_body() {
        let body = "<title>PaperCut — Café</title>/css/s.css?76603papercut-ng";
        assert_eq!(parse_papercut_asset(body).unwrap().build, 76603);
    }

    // ── classify_build / fixed_release ──────────────────────────────

    #[test]
    fn test_classify_known_fixed_builds() {
        for (build, edition, release) in KNOWN_FIXED_BUILDS {
            let asset = PaperCutAsset {
                build: *build,
                edition: *edition,
            };
            assert_eq!(classify_build(Some(asset)), BuildVerdict::Fixed(release));
        }
    }

    #[test]
    fn test_classify_edition_mismatch_is_not_fixed() {
        // 76602 is the MF build; the same id claimed by NG is not a fixed build.
        let asset = PaperCutAsset {
            build: 76602,
            edition: Edition::Ng,
        };
        assert_eq!(classify_build(Some(asset)), BuildVerdict::NotFixed);
    }

    #[test]
    fn test_classify_older_build_not_fixed() {
        let asset = PaperCutAsset {
            build: 75_000,
            edition: Edition::Mf,
        };
        assert_eq!(classify_build(Some(asset)), BuildVerdict::NotFixed);
    }

    #[test]
    fn test_classify_no_asset_is_unknown() {
        assert_eq!(classify_build(None), BuildVerdict::Unknown);
    }

    #[test]
    fn test_fixed_release_lookup() {
        assert_eq!(fixed_release(76611, Edition::Ng), Some("24.1.10"));
        assert_eq!(fixed_release(76611, Edition::Mf), None);
        assert_eq!(fixed_release(1, Edition::Mf), None);
    }

    // ── probe_papercut against a local stub server ──────────────────

    const LOGIN_PAGE: &str = "<html><head><title>PaperCut MF : Login</title>\
        <link rel=\"stylesheet\" href=\"/css/style.css?76602papercut-mf\"></head></html>";

    /// Serve canned responses until the listener is dropped.
    async fn serve(listener: tokio::net::TcpListener, page: &'static str) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 1024];
            let Ok(n) = sock.read(&mut buf).await else {
                continue;
            };
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let (status, body) = match (req.starts_with("GET /api/health"), mentions_papercut(page))
            {
                (true, true) => ("401 Unauthorized", r#"{"product":"PaperCut MF"}"#),
                (true, false) => ("404 Not Found", "{}"),
                (false, _) => ("200 OK", page),
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    }

    #[tokio::test]
    async fn test_probe_identifies_local_stub() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, LOGIN_PAGE));

        let probe = probe_papercut(addr.ip(), addr.port())
            .await
            .expect("stub must be identified");
        assert_eq!(
            probe.asset,
            Some(PaperCutAsset {
                build: 76602,
                edition: Edition::Mf
            })
        );
        assert!(probe.page_marker);
        assert!(probe.health_401);

        let f = build_papercut_finding(addr.ip(), 9191, &probe);
        assert_eq!(f.severity, Severity::Low);
    }

    #[tokio::test]
    async fn test_probe_ignores_non_papercut_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, "<html><title>nginx</title></html>"));

        assert!(probe_papercut(addr.ip(), addr.port()).await.is_none());
    }

    #[tokio::test]
    async fn test_probe_closed_port_is_none() {
        // Bind then drop, so the port is almost certainly refused.
        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        assert!(probe_papercut(addr.ip(), addr.port()).await.is_none());
    }

    // ── mentions_papercut ───────────────────────────────────────────

    #[test]
    fn test_mentions_papercut() {
        assert!(mentions_papercut("<title>PaperCut Login</title>"));
        assert!(mentions_papercut("PAPERCUT MF"));
        assert!(!mentions_papercut("<title>Jetty</title>"));
        assert!(!mentions_papercut(""));
    }

    // ── Finding builders ────────────────────────────────────────────

    fn probe_with(asset: Option<PaperCutAsset>) -> PaperCutProbe {
        PaperCutProbe {
            asset,
            page_marker: true,
            health_401: false,
        }
    }

    #[test]
    fn test_finding_fixed_build_is_low_without_cves() {
        let ip: IpAddr = "192.168.1.20".parse().unwrap();
        let probe = probe_with(Some(PaperCutAsset {
            build: 76602,
            edition: Edition::Mf,
        }));
        let f = build_papercut_finding(ip, 9191, &probe);
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert!(f.cve_ids.is_empty());
        assert!(f.cwe_id.is_none());
        assert_eq!(f.affected_port, Some(9191));
        assert!(f.title.contains("admin interface reachable"));
    }

    #[test]
    fn test_finding_unfixed_build_is_high_with_cves() {
        let ip: IpAddr = "192.168.1.21".parse().unwrap();
        let probe = probe_with(Some(PaperCutAsset {
            build: 70_000,
            edition: Edition::Ng,
        }));
        let f = build_papercut_finding(ip, 9191, &probe);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Probable);
        assert_eq!(f.cve_ids.len(), 2);
        assert!(f.cve_ids.contains(&"CVE-2026-81578".to_owned()));
        assert!(f.cve_ids.contains(&"CVE-2026-82078".to_owned()));
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-470"));
        assert!(f.remediation.is_some());
        assert!(
            f.evidence
                .as_deref()
                .is_some_and(|e| e.contains("build 70000"))
        );
    }

    #[test]
    fn test_finding_unknown_build_is_medium_inferred() {
        let ip: IpAddr = "192.168.1.22".parse().unwrap();
        let probe = PaperCutProbe {
            asset: None,
            page_marker: false,
            health_401: true,
        };
        let f = build_papercut_finding(ip, 9192, &probe);
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.confidence, Confidence::Inferred);
        assert_eq!(f.cve_ids.len(), 2);
        assert_eq!(f.affected_port, Some(9192));
        assert!(f.evidence.as_deref().is_some_and(|e| e.contains("401")));
    }

    #[test]
    fn test_probe_identified() {
        assert!(
            !PaperCutProbe {
                asset: None,
                page_marker: false,
                health_401: false
            }
            .identified()
        );
        assert!(probe_with(None).identified());
    }

    #[test]
    fn test_titles_are_stable_per_verdict() {
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let a = build_papercut_finding(ip, 9191, &probe_with(None));
        let b = build_papercut_finding(
            ip,
            9191,
            &PaperCutProbe {
                asset: None,
                page_marker: false,
                health_401: true,
            },
        );
        assert_eq!(a.title, b.title);
    }

    // ── Proptests: parsers never panic ──────────────────────────────

    proptest! {
        #[test]
        fn prop_parse_asset_no_panic(body in ".*") {
            let _ = parse_papercut_asset(&body);
        }

        #[test]
        fn prop_mentions_papercut_no_panic(text in ".*") {
            let _ = mentions_papercut(&text);
        }

        #[test]
        fn prop_parse_asset_roundtrip(
            build in 1000u32..=999_999,
            ng in any::<bool>(),
            prefix in "[a-z /.]*",
            suffix in "[a-z /.]*",
        ) {
            let edition = if ng { "ng" } else { "mf" };
            let body = format!("{prefix}/css/s.css?{build}papercut-{edition}\"{suffix}");
            let parsed = parse_papercut_asset(&body).expect("marker must parse");
            prop_assert_eq!(parsed.build, build);
            prop_assert_eq!(parsed.edition == Edition::Ng, ng);
        }

        #[test]
        fn prop_classify_build_total(build in any::<u32>(), ng in any::<bool>()) {
            let edition = if ng { Edition::Ng } else { Edition::Mf };
            let _ = classify_build(Some(PaperCutAsset { build, edition }));
        }
    }
}
