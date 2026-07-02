use async_trait::async_trait;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, Remediation, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Scanner;

/// Printer exposure scanner — detects unauthenticated printer control surfaces.
///
/// Two exposure classes are checked, both purely by observation (no credential
/// brute-forcing, no print jobs, no destructive commands):
///
/// * `CUPS`/`IPP` on TCP 631 — an HTTP `GET /` reveals the `Server` header. A
///   `CUPS x.y` banner is correlated with the September 2024 unauthenticated
///   `RCE` chain (`cups-browsed`/`foomatic`), which is `CVSS ~9.9`.
/// * Raw `JetDirect`/`PDL` on TCP 9100 — an open port is itself an
///   unauthenticated raw print/control channel (`PJL`/`PostScript`). We
///   optionally send a bounded, non-destructive `@PJL INFO ID` to fingerprint
///   the model.
///
/// Like [`crate::database::DatabaseScanner`] it only targets hosts whose Phase 1
/// port scan actually found the relevant port open.
pub struct PrinterScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(4);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// `CUPS`/`IPP` administrative HTTP port.
const IPP_PORT: u16 = 631;
/// Raw `JetDirect`/`PDL` printing port.
const RAW_PRINT_PORT: u16 = 9100;

/// The four September-2024 `OpenPrinting` `CUPS` unauthenticated-RCE CVEs.
///
/// Chained, an attacker on the LAN reaches remote command execution when a
/// print job is dispatched to an attacker-controlled `IPP` printer. Kept as a
/// set so the `KEV`/`EPSS` enrichment layer can flag whichever are actively
/// exploited.
const CUPS_RCE_CVES: &[&str] = &[
    "CVE-2024-47076",
    "CVE-2024-47175",
    "CVE-2024-47176",
    "CVE-2024-47177",
];

/// Brother default-admin-password CVEs (password derivable from the serial
/// number → authentication bypass).
const BROTHER_DEFAULT_PW_CVES: &[&str] = &["CVE-2024-51977", "CVE-2024-51978"];

/// Non-destructive `PJL` model query, wrapped in the standard `UEL` (Universal
/// Exit Language) prologue so line-printer daemons parse it. `INFO ID` only
/// reads the model string — it never changes device state.
const PJL_INFO_ID: &[u8] = b"\x1b%-12345X@PJL INFO ID\r\n";

// ── Pure classification / parsing logic (unit-tested below) ─────────────

/// Structured result of identifying a `CUPS` server from its `Server` header.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CupsInfo {
    /// Parsed version string (e.g. `2.4.7`), if the banner exposed one.
    version: Option<String>,
}

/// Classify an HTTP `Server` header as `CUPS`, extracting the version if present.
///
/// `CUPS` advertises itself as `CUPS/2.4.7 IPP/2.1` (and historically as
/// `CUPS 1.x`). Returns `Some` only when the header actually identifies `CUPS`;
/// the inner `version` is `None` when no numeric version follows the token.
fn classify_cups_server(server: &str) -> Option<CupsInfo> {
    let lower = server.to_ascii_lowercase();
    let idx = lower.find("cups")?;
    // Skip the "cups" token and any separator ('/' or spaces) before the version.
    let rest = server[idx + "cups".len()..].trim_start_matches(['/', ' ']);
    let version: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let version = if version.is_empty() {
        None
    } else {
        Some(version)
    };
    Some(CupsInfo { version })
}

/// Parse the model string from a raw `@PJL INFO ID` response.
///
/// A typical reply echoes the command then returns a quoted model, e.g.
/// `@PJL INFO ID\r\n"Brother HL-L2350DW series"\r\n\x0c`. We skip echoed `@PJL`
/// lines and return the first meaningful line with surrounding quotes stripped.
fn parse_pjl_id(banner: &str) -> Option<String> {
    for line in banner.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("@PJL") {
            continue;
        }
        let cleaned = line.trim_matches('"').trim();
        if cleaned.is_empty() {
            continue;
        }
        return Some(cleaned.to_owned());
    }
    None
}

/// Case-insensitive test for a `Brother` printer signature in banner/HTML text.
fn looks_like_brother(text: &str) -> bool {
    text.to_ascii_lowercase().contains("brother")
}

/// Replace non-printable control bytes (except tab/newline/carriage-return) so
/// evidence strings stay log-safe.
fn sanitize_banner(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
                '.'
            } else {
                c
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

// ── Finding builders (pure, unit-tested) ────────────────────────────────

/// Build the informational `CUPS` exposure finding (version-inferred, so
/// [`Confidence::Probable`]) with the unauthenticated-RCE CVE set attached.
fn build_cups_finding(ip: IpAddr, port: u16, info: &CupsInfo) -> Finding {
    let version_label = info
        .version
        .as_deref()
        .map_or_else(|| "(version undisclosed)".to_owned(), ToOwned::to_owned);

    Finding::new(
        "printers",
        &format!("CUPS printing service {version_label} exposed on {ip}:{port}"),
        &format!(
            "The host at {ip}:{port} identifies as CUPS {version_label} via its \
             HTTP Server header. CUPS versions in the affected range are subject \
             to an unauthenticated remote-code-execution chain (cups-browsed / \
             foomatic-rip, CVSS ~9.9): an attacker on the LAN can register a \
             malicious IPP printer and execute commands when a job is printed. \
             The version is inferred from the banner and may be back-patched, so \
             confirm the installed package version.",
        ),
        Severity::High,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service("IPP/CUPS")
    .with_confidence(Confidence::Probable)
    .with_cwe("CWE-78")
    .with_cve_ids(CUPS_RCE_CVES.iter().map(|s| (*s).to_owned()).collect())
    .with_references(refs![
        "https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/",
        "https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8",
    ])
    .with_remediation(Remediation {
        description: "Restrict or disable CUPS network exposure and patch the \
                      cups-filters / cups-browsed stack."
            .to_owned(),
        steps: vec![
            "Stop and disable cups-browsed if not required: \
             `systemctl stop cups-browsed && systemctl disable cups-browsed`."
                .to_owned(),
            "Block UDP/631 and restrict TCP/631 to trusted hosts at the firewall.".to_owned(),
            "Update cups, cups-filters, libcupsfilters and libppd to patched versions.".to_owned(),
        ],
        effort: Some("15 minutes".to_owned()),
    })
}

/// Build the raw-printing (port 9100) exposure finding. The open port *is* the
/// unauthenticated channel, so this is [`Confidence::Confirmed`]. A parsed model
/// string is attached as evidence when available.
fn build_raw_printing_finding(ip: IpAddr, port: u16, model: Option<&str>) -> Finding {
    let finding = Finding::new(
        "printers",
        &format!(
            "Raw printing (JetDirect/PJL) port open — unauthenticated \
             print/control channel on {ip}:{port}"
        ),
        &format!(
            "TCP {port} on {ip} is an open raw printing port (JetDirect/PDL). It \
             is an unauthenticated channel: anyone on the network can submit \
             print jobs and issue PJL/PostScript control commands (read the \
             display, change settings, exhaust consumables, and on some models \
             access the filesystem). Raw printing has no authentication by design.",
        ),
        Severity::Medium,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service("RAW-Printing")
    .with_confidence(Confidence::Confirmed)
    .with_cwe("CWE-306")
    .with_references(refs![
        "http://hacking-printers.net/wiki/index.php/Port_9100_printing",
        "https://github.com/RUB-NDS/PRET",
    ])
    .with_remediation(Remediation {
        description: "Restrict access to the raw printing (JetDirect) port.".to_owned(),
        steps: vec![
            "Disable the raw/PDL (port 9100) service on the printer if it is unused.".to_owned(),
            "Restrict TCP/9100 to trusted print servers with firewall/VLAN rules.".to_owned(),
            "Prefer authenticated, encrypted printing (IPPS) over raw port 9100.".to_owned(),
        ],
        effort: Some("15 minutes".to_owned()),
    });

    match model {
        Some(m) if !m.is_empty() => finding.with_evidence(format!("PJL INFO ID: {m}")),
        _ => finding,
    }
}

/// Build the `Brother` default-admin-password advisory. Inferred from a model
/// signature we cannot fully verify, so [`Confidence::Probable`].
fn build_brother_finding(ip: IpAddr, port: u16, service: &str) -> Finding {
    Finding::new(
        "printers",
        &format!("Brother printer default admin password risk on {ip}:{port}"),
        &format!(
            "The device at {ip}:{port} appears to be a Brother printer. A range \
             of Brother (and rebadged) printers ship with a default administrator \
             password that is derivable from the device serial number, allowing \
             authentication bypass. The model is inferred from a banner/HTML \
             signature and cannot be confirmed remotely; verify the model and \
             change the default administrator password.",
        ),
        Severity::High,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service(service)
    .with_confidence(Confidence::Probable)
    .with_cwe("CWE-1392")
    .with_cve_ids(
        BROTHER_DEFAULT_PW_CVES
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    )
    .with_references(refs![
        "https://nvd.nist.gov/vuln/detail/CVE-2024-51978",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-51977",
    ])
    .with_remediation(Remediation {
        description: "Change the printer's default administrator password.".to_owned(),
        steps: vec![
            "Log in to the printer's Web Based Management console.".to_owned(),
            "Set a unique, strong administrator password; do not rely on the \
             factory default derived from the serial number."
                .to_owned(),
            "Update the printer firmware to the latest available version.".to_owned(),
        ],
        effort: Some("10 minutes".to_owned()),
    })
}

// ── Network probes (all I/O bounded by tokio::time::timeout) ────────────

/// Data gathered from an HTTP probe of the `CUPS`/`IPP` port.
struct IppHttpProbe {
    server: Option<String>,
    /// Whether a `Brother` signature was seen in the `Server` header or body.
    brother: bool,
}

/// Probe the `CUPS`/`IPP` HTTP port: `GET /`, read the `Server` header, and scan
/// a bounded body for a `Brother` signature. Read errors yield `None`.
async fn probe_ipp_http(ip: IpAddr, port: u16) -> Option<IppHttpProbe> {
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;

    let url = format!("http://{ip}:{port}/");
    let resp = tokio::time::timeout(HTTP_TIMEOUT, client.get(&url).send())
        .await
        .ok()?
        .ok()?;

    let server = resp
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let brother_header = server.as_deref().is_some_and(looks_like_brother);

    // Bounded body read — the device is untrusted and could stream endlessly.
    let body = crate::http_util::read_body_capped(resp, crate::http_util::MAX_BODY_BYTES).await;
    let brother = brother_header || looks_like_brother(&body);

    Some(IppHttpProbe { server, brother })
}

/// Send a bounded, non-destructive `@PJL INFO ID` to the raw printing port and
/// return the sanitized banner. Any failure (no PJL support, timeout) is `None`;
/// the caller still reports the open-port exposure regardless.
async fn grab_pjl_banner(ip: IpAddr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(PJL_INFO_ID))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    let banner = sanitize_banner(&String::from_utf8_lossy(&buf[..n]));
    if banner.is_empty() {
        None
    } else {
        Some(banner)
    }
}

// ── Per-port orchestration ──────────────────────────────────────────────

async fn check_cups(ip: IpAddr, port: u16, findings: &mut Vec<Finding>) {
    let Some(probe) = probe_ipp_http(ip, port).await else {
        return;
    };

    if let Some(ref server) = probe.server
        && let Some(info) = classify_cups_server(server)
    {
        findings.push(build_cups_finding(ip, port, &info));
    }

    if probe.brother {
        findings.push(build_brother_finding(ip, port, "IPP/CUPS"));
    }
}

async fn check_raw_printing(ip: IpAddr, port: u16, findings: &mut Vec<Finding>) {
    // The open port itself is the exposure — reported unconditionally.
    let banner = grab_pjl_banner(ip, port).await;
    let model = banner.as_deref().and_then(parse_pjl_id);

    findings.push(build_raw_printing_finding(ip, port, model.as_deref()));

    // Fingerprint enrichment: flag Brother default-password risk if seen.
    let brother = model.as_deref().is_some_and(looks_like_brother)
        || banner.as_deref().is_some_and(looks_like_brother);
    if brother {
        findings.push(build_brother_finding(ip, port, "RAW-Printing"));
    }
}

#[async_trait]
impl Scanner for PrinterScanner {
    fn id(&self) -> &'static str {
        "printers"
    }

    fn name(&self) -> &'static str {
        "Printer Exposure"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running printer exposure scan");
        let mut findings = Vec::new();

        // Skip in Passive/quick mode — active probes are unnecessary there.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping printer scan in quick scan mode");
            return Ok(findings);
        }

        if ctx.discovered_devices.is_empty() {
            tracing::info!("no discovered devices, skipping printer scan");
            return Ok(findings);
        }

        for device in &ctx.discovered_devices {
            for open in &device.open_ports {
                match open.port {
                    IPP_PORT => check_cups(device.ip, open.port, &mut findings).await,
                    RAW_PRINT_PORT => {
                        check_raw_printing(device.ip, open.port, &mut findings).await;
                    }
                    _ => {}
                }
            }
        }

        tracing::info!(
            findings_count = findings.len(),
            "printer exposure scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        20
    }

    fn relevant_ports(&self) -> &[u16] {
        &[IPP_PORT, RAW_PRINT_PORT]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── classify_cups_server ────────────────────────────────────────

    #[test]
    fn test_cups_server_with_version() {
        let info = classify_cups_server("CUPS/2.4.7 IPP/2.1").unwrap();
        assert_eq!(info.version.as_deref(), Some("2.4.7"));
    }

    #[test]
    fn test_cups_server_space_form() {
        let info = classify_cups_server("CUPS 1.7.5").unwrap();
        assert_eq!(info.version.as_deref(), Some("1.7.5"));
    }

    #[test]
    fn test_cups_server_case_insensitive() {
        let info = classify_cups_server("cups/2.3.3op2").unwrap();
        // Version stops at the first non [0-9.] char.
        assert_eq!(info.version.as_deref(), Some("2.3.3"));
    }

    #[test]
    fn test_cups_server_no_version() {
        let info = classify_cups_server("CUPS").unwrap();
        assert!(info.version.is_none());
    }

    #[test]
    fn test_cups_server_not_cups() {
        assert!(classify_cups_server("Apache/2.4.57 (Debian)").is_none());
        assert!(classify_cups_server("").is_none());
        assert!(classify_cups_server("nginx").is_none());
    }

    #[test]
    fn test_cups_server_embedded() {
        // Some builds prepend an OS token before the CUPS token.
        let info = classify_cups_server("Linux CUPS/2.4.2").unwrap();
        assert_eq!(info.version.as_deref(), Some("2.4.2"));
    }

    // ── parse_pjl_id ────────────────────────────────────────────────

    #[test]
    fn test_pjl_id_quoted_with_echo() {
        let banner = "@PJL INFO ID\r\n\"Brother HL-L2350DW series\"\r\n";
        assert_eq!(
            parse_pjl_id(banner).as_deref(),
            Some("Brother HL-L2350DW series")
        );
    }

    #[test]
    fn test_pjl_id_unquoted() {
        let banner = "HP LaserJet 4250\n";
        assert_eq!(parse_pjl_id(banner).as_deref(), Some("HP LaserJet 4250"));
    }

    #[test]
    fn test_pjl_id_only_echo() {
        assert!(parse_pjl_id("@PJL INFO ID\r\n").is_none());
    }

    #[test]
    fn test_pjl_id_empty() {
        assert!(parse_pjl_id("").is_none());
        assert!(parse_pjl_id("\r\n\r\n").is_none());
    }

    #[test]
    fn test_pjl_id_form_feed_stripped() {
        // Trailing form-feed (0x0c) is whitespace and must be trimmed away.
        let banner = "@PJL INFO ID\r\n\"KONICA MINOLTA C258\"\r\n\x0c";
        assert_eq!(parse_pjl_id(banner).as_deref(), Some("KONICA MINOLTA C258"));
    }

    // ── looks_like_brother ──────────────────────────────────────────

    #[test]
    fn test_brother_detection() {
        assert!(looks_like_brother("Brother HL-L2350DW"));
        assert!(looks_like_brother("brother mfc-j4335dw"));
        assert!(looks_like_brother("<title>BROTHER MFC</title>"));
        assert!(!looks_like_brother("HP LaserJet"));
        assert!(!looks_like_brother(""));
    }

    // ── sanitize_banner ─────────────────────────────────────────────

    #[test]
    fn test_sanitize_banner_replaces_control() {
        let raw = "model\x00\x07name";
        assert_eq!(sanitize_banner(raw), "model..name");
    }

    #[test]
    fn test_sanitize_banner_keeps_newlines() {
        assert_eq!(sanitize_banner("a\nb\t"), "a\nb");
    }

    // ── Finding builders ────────────────────────────────────────────

    #[test]
    fn test_build_cups_finding_probable_high_with_cves() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let f = build_cups_finding(
            ip,
            631,
            &CupsInfo {
                version: Some("2.4.7".to_owned()),
            },
        );
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Probable);
        assert_eq!(f.affected_port, Some(631));
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-78"));
        assert_eq!(f.cve_ids.len(), 4);
        assert!(f.cve_ids.contains(&"CVE-2024-47176".to_owned()));
        assert!(f.remediation.is_some());
    }

    #[test]
    fn test_build_raw_printing_finding_confirmed_medium() {
        let ip: IpAddr = "192.168.1.60".parse().unwrap();
        let f = build_raw_printing_finding(ip, 9100, None);
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert_eq!(f.affected_port, Some(9100));
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-306"));
        assert!(f.cve_ids.is_empty());
        assert!(f.evidence.is_none());
    }

    #[test]
    fn test_build_raw_printing_finding_with_model_evidence() {
        let ip: IpAddr = "192.168.1.60".parse().unwrap();
        let f = build_raw_printing_finding(ip, 9100, Some("HP LaserJet 4250"));
        assert!(
            f.evidence
                .as_deref()
                .is_some_and(|e| e.contains("HP LaserJet 4250"))
        );
    }

    #[test]
    fn test_build_brother_finding_probable_with_cves() {
        let ip: IpAddr = "192.168.1.70".parse().unwrap();
        let f = build_brother_finding(ip, 9100, "RAW-Printing");
        assert_eq!(f.confidence, Confidence::Probable);
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-1392"));
        assert_eq!(f.cve_ids.len(), 2);
        assert!(f.cve_ids.contains(&"CVE-2024-51978".to_owned()));
        assert!(f.remediation.is_some());
    }

    // ── Proptests: parsers never panic ──────────────────────────────

    proptest! {
        #[test]
        fn prop_classify_cups_no_panic(server in ".*") {
            let _ = classify_cups_server(&server);
        }

        #[test]
        fn prop_parse_pjl_no_panic(banner in ".*") {
            let _ = parse_pjl_id(&banner);
        }

        #[test]
        fn prop_sanitize_banner_no_panic(raw in ".*") {
            let _ = sanitize_banner(&raw);
        }

        #[test]
        fn prop_looks_like_brother_no_panic(text in ".*") {
            let _ = looks_like_brother(&text);
        }
    }
}
