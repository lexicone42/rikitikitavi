//! `DD-WRT` `UPnP` daemon exposure, UDP/1900 (CVE-2021-27137, CISA KEV 2026-07-21).
//!
//! The vulnerable daemon is the Broadcom-derived `upnpd` `DD-WRT` ships, not
//! `MiniUPnPd`: `router/upnp/src/ssdp.c` has an unbounded `strcpy` on the M-SEARCH
//! path and emits `Server: DD-WRT/<os_version> UPnP/1.0 upnpd/0.9.0`, with
//! `os_name` hardcoded to `DD-WRT` even on OEM builds. A `MiniUPnPd` banner is a
//! negative indicator.
//!
//! Detection is a banner match on the `SERVER` header of an ordinary
//! `ssdp:discover` response. The public proof of concept — an M-SEARCH with an
//! oversized `uuid:` search target — crashes the service and is never sent. No
//! build number is reachable (`os_version` is a CFE board variable), so the
//! ceiling is High/Probable.

use async_trait::async_trait;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::config::ExclusionSet;
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, Remediation, ScanContext};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::Scanner;
use crate::mdns::parse_ssdp_response;

/// `DD-WRT` `upnpd` exposure scanner.
pub struct DdwrtUpnpScanner;

/// SSDP multicast group and port.
const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;

/// Window for collecting responses.
const COLLECT_WINDOW: Duration = Duration::from_secs(3);

/// Cap on responses processed per scan.
const MAX_RESPONSES: usize = 256;

const RECV_BUF: usize = 4096;

/// The vulnerable daemon build string.
const VULNERABLE_UPNPD: &str = "upnpd/0.9.0";

/// CVE-2021-27137, in CISA KEV since 2026-07-21.
const DDWRT_CVE: &str = "CVE-2021-27137";

/// An ordinary `ssdp:discover` search. `MX` is the documented maximum wait and
/// `ST` is the root-device target every `UPnP` root answers.
const M_SEARCH: &str = "M-SEARCH * HTTP/1.1\r\n\
                        HOST: 239.255.255.250:1900\r\n\
                        MAN: \"ssdp:discover\"\r\n\
                        MX: 1\r\n\
                        ST: upnp:rootdevice\r\n\
                        \r\n";

// ── Banner classification ───────────────────────────────────────────────────

/// What a `SERVER` header says about the `UPnP` daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonVerdict {
    /// `DD-WRT` together with the vulnerable `upnpd/0.9.0` build string.
    VulnerableUpnpd,
    /// `DD-WRT`, but the daemon string is not `upnpd/0.9.0`.
    DdwrtOther,
    /// Not the affected daemon — includes every `MiniUPnPd` banner.
    NotAffected,
}

/// Classify a `SERVER` header.
///
/// Both halves are required: `DD-WRT` alone appears on builds that run
/// `MiniUPnPd`, and `upnpd/0.9.0` alone appears on other Broadcom firmware whose
/// patch state this scan cannot reason about.
fn classify_server(server: &str) -> DaemonVerdict {
    let lower = server.to_ascii_lowercase();
    if lower.contains("miniupnpd") {
        return DaemonVerdict::NotAffected;
    }
    if !lower.contains("dd-wrt") {
        return DaemonVerdict::NotAffected;
    }
    if lower.contains(VULNERABLE_UPNPD) {
        DaemonVerdict::VulnerableUpnpd
    } else {
        DaemonVerdict::DdwrtOther
    }
}

/// `DD-WRT` reports `os_version` in the banner but it is a board variable, not a
/// build number: keep it as evidence only.
fn banner_os_version(server: &str) -> Option<&str> {
    let start = server.to_ascii_lowercase().find("dd-wrt/")? + "dd-wrt/".len();
    let rest = server.get(start..)?;
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let value = rest.get(..end)?.trim();
    (!value.is_empty()).then_some(value)
}

// ── Findings ────────────────────────────────────────────────────────────────

fn ddwrt_references() -> Vec<String> {
    refs![
        "https://ssd-disclosure.com/ssd-advisory-dd-wrt-upnp-buffer-overflow/",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-27137",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "https://www.fortinet.com/blog/threat-research/inside-cross-platform-propagation-of-new-gafgyt-variant-c0xmo",
    ]
}

fn ddwrt_remediation() -> Remediation {
    Remediation {
        description: "Turn off UPnP on the router, or move to a build that does not ship \
                      the Broadcom upnpd daemon."
            .to_owned(),
        steps: vec![
            "In the DD-WRT web interface, NAT/QoS > UPnP, set UPnP Service to Disable and \
             clear any existing port-forward entries it created."
                .to_owned(),
            "Update to a current DD-WRT build; recent builds use MiniUPnPd rather than \
             the Broadcom upnpd daemon this issue is in."
                .to_owned(),
            "If UPnP is needed for a specific application, forward that port manually \
             instead and leave the daemon off."
                .to_owned(),
            "Confirm UDP 1900 is not reachable from the WAN side.".to_owned(),
        ],
        effort: Some("15 minutes".to_owned()),
    }
}

/// Finding for one answering host.
fn ddwrt_finding(ip: IpAddr, server: &str, verdict: DaemonVerdict) -> Option<Finding> {
    let os_version = banner_os_version(server).unwrap_or("unreported");
    let (title, description, severity, confidence) = match verdict {
        DaemonVerdict::VulnerableUpnpd => (
            format!("DD-WRT UPnP daemon vulnerable to CVE-2021-27137 on {ip}:{SSDP_PORT}"),
            format!(
                "The host at {ip} answered an SSDP search with a DD-WRT banner naming the \
                 Broadcom upnpd 0.9.0 daemon (os_version {os_version}). That daemon copies \
                 the M-SEARCH search target with an unbounded strcpy (CVE-2021-27137), \
                 which is remote code execution on the router from any host that can send \
                 it a datagram; CISA lists the issue as exploited in the wild and the \
                 c0xmo/Gafgyt botnet variant weaponises it on UDP 1900. DD-WRT exposes no \
                 build number over UPnP — os_version is a board variable, not a firmware \
                 build — so the version cannot be checked and this is a daemon-identity \
                 match. This scan sent only an ordinary ssdp:discover search; the public \
                 proof of concept crashes the service and was not used. Disable UPnP."
            ),
            Severity::High,
            Confidence::Probable,
        ),
        DaemonVerdict::DdwrtOther => (
            format!("DD-WRT UPnP service reachable on {ip}:{SSDP_PORT}"),
            format!(
                "The host at {ip} answered an SSDP search with a DD-WRT banner \
                 (os_version {os_version}) that does not name the upnpd 0.9.0 daemon \
                 affected by CVE-2021-27137. UPnP is still an unauthenticated service that \
                 lets any host on this network open port forwards through the router. Turn \
                 it off unless something needs it."
            ),
            Severity::Low,
            Confidence::Inferred,
        ),
        DaemonVerdict::NotAffected => return None,
    };

    let finding = Finding::new("ddwrt_upnp", &title, &description, severity)
        .with_confidence(confidence)
        .with_ip(ip)
        .with_port(SSDP_PORT)
        .with_service("UPnP/SSDP")
        .with_evidence(format!("SERVER: {server}"))
        .with_remediation(ddwrt_remediation())
        .with_references(ddwrt_references())
        .with_device_hint(
            DeviceHint::new()
                .with_device_type(DeviceType::Router)
                .with_os_guess("DD-WRT"),
        );

    Some(match verdict {
        DaemonVerdict::VulnerableUpnpd => finding
            .with_cwe("CWE-120")
            .with_cve_ids(vec![DDWRT_CVE.to_owned()]),
        DaemonVerdict::DdwrtOther => finding.with_cwe("CWE-284"),
        DaemonVerdict::NotAffected => unreachable!("filtered above"),
    })
}

// ── Probe ───────────────────────────────────────────────────────────────────

/// Send one ordinary M-SEARCH to the group and to each target, then collect the
/// `SERVER` headers. Nothing else is ever sent.
async fn collect_servers(targets: &[IpAddr], exclusions: &ExclusionSet) -> HashMap<IpAddr, String> {
    let mut servers: HashMap<IpAddr, String> = HashMap::new();
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        tracing::warn!("could not bind an SSDP socket");
        return servers;
    };

    let group = SocketAddr::from((SSDP_GROUP, SSDP_PORT));
    if let Err(e) = socket.send_to(M_SEARCH.as_bytes(), group).await {
        tracing::debug!("could not send the SSDP multicast search: {e}");
    }
    for &ip in targets {
        // Defence in depth: `scan` pre-filters, and no excluded host is probed
        // even if a caller passes one.
        if exclusions.excludes_ip(ip) {
            continue;
        }
        if let Err(e) = socket
            .send_to(M_SEARCH.as_bytes(), SocketAddr::new(ip, SSDP_PORT))
            .await
        {
            tracing::debug!(%ip, "could not send the SSDP search: {e}");
        }
    }

    let deadline = Instant::now() + COLLECT_WINDOW;
    let mut buf = vec![0u8; RECV_BUF];
    let mut seen = 0usize;
    while seen < MAX_RESPONSES {
        let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
        else {
            break;
        };
        seen += 1;
        let ip = from.ip();
        if exclusions.excludes_ip(ip) {
            continue;
        }
        let Some(chunk) = buf.get(..n) else { continue };
        let text = String::from_utf8_lossy(chunk);
        if let Some(server) = parse_ssdp_response(&text).and_then(|s| s.server) {
            servers.entry(ip).or_insert(server);
        }
    }

    servers
}

#[async_trait]
impl Scanner for DdwrtUpnpScanner {
    fn id(&self) -> &'static str {
        "ddwrt_upnp"
    }

    fn name(&self) -> &'static str {
        "DD-WRT UPnP Daemon Exposure"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running DD-WRT UPnP daemon scan");
        let mut findings = Vec::new();

        // Sends datagrams: Active intensity and above only.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping DD-WRT UPnP scan in quick scan mode");
            return Ok(findings);
        }

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "ddwrt_upnp".to_owned(),
                message: e.to_string(),
            })?;

        let targets: Vec<IpAddr> = ctx
            .discovered_devices
            .iter()
            .filter(|d| !exclusions.excludes_device(d))
            .map(|d| d.ip)
            .collect();

        for (ip, server) in collect_servers(&targets, &exclusions).await {
            let verdict = classify_server(&server);
            if verdict != DaemonVerdict::NotAffected {
                tracing::debug!(%ip, %server, "DD-WRT UPnP banner");
            }
            findings.extend(ddwrt_finding(ip, &server, verdict));
        }

        tracing::info!(
            findings_count = findings.len(),
            "DD-WRT UPnP daemon scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Banner emitted by `router/upnp/src/ssdp.c`.
    const DDWRT_BANNER: &str = "DD-WRT/v24-sp2 UPnP/1.0 upnpd/0.9.0";
    /// Same daemon family on an OEM build; `os_name` is still hardcoded.
    const BUFFALO_BANNER: &str = "DD-WRT/24.28.15 UPnP/1.0 upnpd/0.9.0";
    /// The negative indicator.
    const MINIUPNPD_BANNER: &str = "Linux/3.10 UPnP/1.1 MiniUPnPd/2.1";

    fn ip() -> IpAddr {
        IpAddr::from([192, 168, 1, 1])
    }

    // ── Classification ──────────────────────────────────────────────

    #[test]
    fn identifies_the_vulnerable_daemon() {
        assert_eq!(
            classify_server(DDWRT_BANNER),
            DaemonVerdict::VulnerableUpnpd
        );
        assert_eq!(
            classify_server(BUFFALO_BANNER),
            DaemonVerdict::VulnerableUpnpd
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(
            classify_server("dd-wrt/v24 upnp/1.0 UPNPD/0.9.0"),
            DaemonVerdict::VulnerableUpnpd
        );
    }

    #[test]
    fn miniupnpd_is_a_negative_indicator() {
        assert_eq!(
            classify_server(MINIUPNPD_BANNER),
            DaemonVerdict::NotAffected
        );
        // Even on a DD-WRT build that runs MiniUPnPd.
        assert_eq!(
            classify_server("DD-WRT/v3.0 UPnP/1.1 MiniUPnPd/2.3.0"),
            DaemonVerdict::NotAffected
        );
    }

    #[test]
    fn upnpd_without_ddwrt_is_not_claimed() {
        assert_eq!(
            classify_server("Linux/2.6 UPnP/1.0 upnpd/0.9.0"),
            DaemonVerdict::NotAffected
        );
    }

    #[test]
    fn ddwrt_with_another_daemon_version() {
        assert_eq!(
            classify_server("DD-WRT/v24-sp2 UPnP/1.0 upnpd/1.0"),
            DaemonVerdict::DdwrtOther
        );
    }

    #[test]
    fn unrelated_banners_are_not_affected() {
        for banner in [
            "",
            "Linux/4.9 UPnP/1.0 Sonos/70.3-35220",
            "Windows NT/10.0 UPnP/1.0",
        ] {
            assert_eq!(classify_server(banner), DaemonVerdict::NotAffected);
        }
    }

    #[test]
    fn extracts_the_os_version_token() {
        assert_eq!(banner_os_version(DDWRT_BANNER), Some("v24-sp2"));
        assert_eq!(banner_os_version(BUFFALO_BANNER), Some("24.28.15"));
        assert_eq!(banner_os_version("DD-WRT/"), None);
        assert_eq!(banner_os_version(MINIUPNPD_BANNER), None);
    }

    // ── Request shape ───────────────────────────────────────────────

    #[test]
    fn search_is_an_ordinary_ssdp_discover() {
        assert!(M_SEARCH.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(M_SEARCH.contains("MAN: \"ssdp:discover\""));
        assert!(M_SEARCH.contains("ST: upnp:rootdevice"));
        // The proof of concept is an oversized uuid search target.
        assert!(!M_SEARCH.contains("uuid:"));
        assert!(M_SEARCH.len() < 200, "search target is not oversized");
    }

    // ── Findings ────────────────────────────────────────────────────

    #[test]
    fn vulnerable_finding_is_high_probable_with_the_kev_cve() {
        let finding =
            ddwrt_finding(ip(), DDWRT_BANNER, DaemonVerdict::VulnerableUpnpd).expect("finding");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Probable);
        assert_eq!(finding.cve_ids, vec![DDWRT_CVE.to_owned()]);
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-120"));
        assert!(finding.evidence.unwrap().contains("upnpd/0.9.0"));
    }

    #[test]
    fn vulnerable_finding_states_that_no_build_number_is_reachable() {
        let finding =
            ddwrt_finding(ip(), DDWRT_BANNER, DaemonVerdict::VulnerableUpnpd).expect("finding");
        assert!(finding.description.contains("board variable"));
    }

    #[test]
    fn other_ddwrt_finding_carries_no_cve() {
        let finding = ddwrt_finding(
            ip(),
            "DD-WRT/v3.0 UPnP/1.0 upnpd/1.1",
            DaemonVerdict::DdwrtOther,
        )
        .expect("finding");
        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.cve_ids.is_empty());
    }

    #[test]
    fn unaffected_banners_produce_no_finding() {
        assert!(ddwrt_finding(ip(), MINIUPNPD_BANNER, DaemonVerdict::NotAffected).is_none());
    }

    #[test]
    fn titles_are_stable_across_os_versions() {
        let a = ddwrt_finding(ip(), DDWRT_BANNER, DaemonVerdict::VulnerableUpnpd)
            .unwrap()
            .title;
        let b = ddwrt_finding(ip(), BUFFALO_BANNER, DaemonVerdict::VulnerableUpnpd)
            .unwrap()
            .title;
        assert_eq!(a, b);
    }

    #[test]
    fn hint_names_the_firmware_not_a_model() {
        let hint = ddwrt_finding(ip(), DDWRT_BANNER, DaemonVerdict::VulnerableUpnpd)
            .unwrap()
            .device_hint
            .expect("hint");
        assert_eq!(hint.device_type, Some(DeviceType::Router));
        assert_eq!(hint.os_guess.as_deref(), Some("DD-WRT"));
        assert!(hint.model.is_none());
    }

    proptest! {
        /// Classification is total over arbitrary banner text.
        #[test]
        fn classify_never_panics(server in ".*") {
            let verdict = classify_server(&server);
            let _ = banner_os_version(&server);
            let _ = ddwrt_finding(ip(), &server, verdict);
        }

        /// Arbitrary datagrams reach the shared SSDP parser without panicking.
        #[test]
        fn ssdp_parsing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..800)) {
            let text = String::from_utf8_lossy(&bytes);
            if let Some(server) = parse_ssdp_response(&text).and_then(|s| s.server) {
                let _ = classify_server(&server);
            }
        }
    }
}
