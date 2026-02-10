use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

use crate::Scanner;

/// Router security scanner — checks for admin interfaces, `UPnP`, telnet,
/// and HTTPS enforcement on the gateway.
pub struct RouterScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Check if a TCP port is open on the given IP.
async fn is_port_open(ip: IpAddr, port: u16) -> bool {
    let addr = SocketAddr::new(ip, port);
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .is_ok_and(|r| r.is_ok())
}

/// Check if HTTP on port 80 redirects to HTTPS.
async fn check_http_redirect(ip: IpAddr) -> Option<bool> {
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;

    let url = format!("http://{ip}/");
    client.get(&url).send().await.ok().map(|resp| {
        if resp.status().is_redirection() {
            resp.headers()
                .get("location")
                .is_some_and(|location| {
                    location
                        .to_str()
                        .unwrap_or("")
                        .starts_with("https://")
                })
        } else {
            // Got a response but no redirect — HTTP is served directly
            false
        }
    })
}

/// Check if `UPnP` root description is accessible.
async fn check_upnp(ip: IpAddr) -> bool {
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .unwrap_or_default();

    // Common UPnP description URLs
    let urls = [
        format!("http://{ip}:49152/rootDesc.xml"),
        format!("http://{ip}:1900/rootDesc.xml"),
        format!("http://{ip}:5000/rootDesc.xml"),
    ];

    for url in &urls {
        if let Ok(resp) = client.get(url).send().await {
            if resp.status().is_success() {
                return true;
            }
        }
    }
    false
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl Scanner for RouterScanner {
    fn id(&self) -> &'static str {
        "router"
    }

    fn name(&self) -> &'static str {
        "Router Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running router security scan");
        let mut findings = Vec::new();

        let Some(gateway) = ctx.gateway else {
            tracing::info!("no gateway detected, skipping router scan");
            findings.push(Finding::new(
                "router",
                "No gateway detected — router scan skipped",
                "Cannot perform router security checks without a detected gateway.",
                Severity::Info,
            ));
            return Ok(findings);
        };

        tracing::info!(%gateway, "scanning router");

        // Check admin ports
        let admin_ports: &[(u16, &str)] = &[
            (80, "HTTP"),
            (443, "HTTPS"),
            (8080, "HTTP-Alt"),
            (8443, "HTTPS-Alt"),
            (8888, "HTTP-Alt-2"),
        ];

        let mut open_admin_ports = Vec::new();
        for &(port, service) in admin_ports {
            if is_port_open(gateway, port).await {
                tracing::debug!(port, service, "admin port open on gateway");
                open_admin_ports.push((port, service));
            }
        }

        if !open_admin_ports.is_empty() {
            let ports_str: Vec<String> = open_admin_ports
                .iter()
                .map(|(p, s)| format!("{p} ({s})"))
                .collect();
            findings.push(
                Finding::new(
                    "router",
                    "Router admin interface detected",
                    &format!(
                        "The router at {gateway} has web admin interface(s) on port(s): {}",
                        ports_str.join(", ")
                    ),
                    Severity::Info,
                )
                .with_ip(gateway),
            );
        }

        // Check if HTTP port 80 redirects to HTTPS
        if open_admin_ports.iter().any(|&(p, _)| p == 80) {
            match check_http_redirect(gateway).await {
                Some(true) => {
                    findings.push(
                        Finding::new(
                            "router",
                            "Router admin redirects HTTP to HTTPS",
                            "The router correctly redirects HTTP to HTTPS for its admin interface.",
                            Severity::Info,
                        )
                        .with_ip(gateway)
                        .with_port(80),
                    );
                }
                Some(false) => {
                    findings.push(
                        Finding::new(
                            "router",
                            "Router admin accessible over unencrypted HTTP",
                            &format!(
                                "The router admin interface at {gateway}:80 does not redirect \
                                 to HTTPS. Admin credentials could be intercepted on the network."
                            ),
                            Severity::High,
                        )
                        .with_ip(gateway)
                        .with_port(80)
                        .with_service("HTTP")
                        .with_cwe("CWE-319"),
                    );
                }
                None => {
                    tracing::debug!("could not check HTTP redirect on gateway");
                }
            }
        }

        // Check Telnet on gateway
        if is_port_open(gateway, 23).await {
            findings.push(
                Finding::new(
                    "router",
                    "Telnet enabled on router",
                    &format!(
                        "Telnet (port 23) is open on the router at {gateway}. Telnet transmits \
                         all data including passwords in cleartext. Disable Telnet and use SSH."
                    ),
                    Severity::High,
                )
                .with_ip(gateway)
                .with_port(23)
                .with_service("Telnet")
                .with_cwe("CWE-319"),
            );
        }

        // Check FTP on gateway
        if is_port_open(gateway, 21).await {
            findings.push(
                Finding::new(
                    "router",
                    "FTP enabled on router",
                    &format!(
                        "FTP (port 21) is open on the router at {gateway}. FTP transmits \
                         credentials in cleartext. Consider disabling it or using SFTP."
                    ),
                    Severity::Medium,
                )
                .with_ip(gateway)
                .with_port(21)
                .with_service("FTP")
                .with_cwe("CWE-319"),
            );
        }

        // Check UPnP
        if check_upnp(gateway).await {
            findings.push(
                Finding::new(
                    "router",
                    "UPnP enabled on router",
                    &format!(
                        "UPnP is enabled on the router at {gateway}. UPnP allows any \
                         device on the network to automatically open ports on the router, \
                         which can be exploited by malware to expose internal services."
                    ),
                    Severity::Medium,
                )
                .with_ip(gateway)
                .with_service("UPnP")
                .with_cwe("CWE-284")
                .with_references(vec![
                    "https://www.upnp-hacks.org/".to_owned(),
                ]),
            );
        }

        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        15
    }
}
