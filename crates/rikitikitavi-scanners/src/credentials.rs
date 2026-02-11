use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Scanner;

/// Credential hygiene scanner — anonymous FTP check, SMB exposure advisory,
/// HTTP admin no-auth detection.
pub struct CredentialScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Check if a host accepts anonymous FTP login.
/// Returns the FTP response code if we got one.
async fn check_anonymous_ftp(ip: IpAddr) -> Option<u16> {
    let addr = SocketAddr::new(ip, 21);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Read banner
    let mut buf = vec![0u8; 1024];
    let _ = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    // Send anonymous login
    tokio::time::timeout(
        READ_TIMEOUT,
        stream.write_all(b"USER anonymous\r\n"),
    )
    .await
    .ok()?
    .ok()?;

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    let user_resp = String::from_utf8_lossy(&buf[..n]);

    // If we get 331 (password required), send password
    if user_resp.starts_with("331") {
        tokio::time::timeout(
            READ_TIMEOUT,
            stream.write_all(b"PASS test@rikitikitavi\r\n"),
        )
        .await
        .ok()?
        .ok()?;

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
            .await
            .ok()?
            .ok()?;
        let pass_resp = String::from_utf8_lossy(&buf[..n]);
        return extract_ftp_code(&pass_resp);
    }

    extract_ftp_code(&user_resp)
}

/// Extract the 3-digit FTP response code from a response line.
fn extract_ftp_code(response: &str) -> Option<u16> {
    let code_str: String = response.chars().take(3).collect();
    code_str.parse().ok()
}

/// Check if an HTTP admin interface is accessible without authentication.
async fn check_http_no_auth(ip: IpAddr, port: u16) -> Option<bool> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let request = format!("GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n");
    tokio::time::timeout(READ_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    let response = String::from_utf8_lossy(&buf[..n]);
    let first_line = response.lines().next().unwrap_or("");

    // 200 OK without redirect to login = potentially no auth
    // 401/403 = auth required (good)
    // 302/301 to /login = auth required (good)
    if first_line.contains("200") {
        // Check if the body suggests a login page despite 200
        let body_lower = response.to_lowercase();
        if body_lower.contains("login") || body_lower.contains("password") || body_lower.contains("sign in") {
            return Some(false); // Has login page
        }
        return Some(true); // No auth needed
    }

    Some(false) // Not a 200 = some form of auth or redirect
}

/// Check FTP credentials on a target and push findings.
async fn check_ftp_credentials(ip: IpAddr, findings: &mut Vec<Finding>) {
    if let Some(code) = check_anonymous_ftp(ip).await {
        if code == 230 {
            findings.push(
                Finding::new(
                    "credentials",
                    &format!("Anonymous FTP login accepted on {ip}"),
                    &format!(
                        "FTP server at {ip}:21 accepts anonymous login. Anyone on the \
                         network can read (and possibly write) files."
                    ),
                    Severity::High,
                )
                .with_ip(ip)
                .with_port(21)
                .with_service("FTP")
                .with_cwe("CWE-287")
                .with_opt_remediation(crate::remediation::get(
                    "rikitikitavi.credentials.anonymous-ftp",
                    &[],
                )),
            );
        } else if code == 530 {
            findings.push(
                Finding::new(
                    "credentials",
                    &format!("FTP rejects anonymous login on {ip}"),
                    &format!(
                        "FTP at {ip}:21 correctly rejects anonymous login (code 530)."
                    ),
                    Severity::Info,
                )
                .with_ip(ip)
                .with_port(21)
                .with_service("FTP"),
            );
        }
    }
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl Scanner for CredentialScanner {
    fn id(&self) -> &'static str {
        "credentials"
    }

    fn name(&self) -> &'static str {
        "Credential Hygiene"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running credential hygiene scan");
        let mut findings = Vec::new();

        // ── Adaptive mode: use Phase 1 discovered devices ───────────
        if !ctx.discovered_devices.is_empty() {
            // In Passive mode, only check the gateway/router
            let target_devices: Vec<_> = if ctx.config.intensity.at_least(
                rikitikitavi_models::config::ScanIntensity::Active,
            ) {
                ctx.discovered_devices.iter().collect()
            } else {
                ctx.discovered_devices
                    .iter()
                    .filter(|d| ctx.gateway == Some(d.ip))
                    .collect()
            };

            tracing::info!(
                device_count = target_devices.len(),
                "adaptive credential scan using discovered devices"
            );

            for device in &target_devices {
                let ip = device.ip;
                let has_port = |p: u16| device.open_ports.iter().any(|op| op.port == p);

                // FTP: only check if port 21 is actually open
                if has_port(21) {
                    check_ftp_credentials(ip, &mut findings).await;
                }

                // Telnet: flag if open (cleartext protocol)
                if has_port(23) {
                    findings.push(
                        Finding::new(
                            "credentials",
                            &format!("Telnet service with potential default credentials on {ip}"),
                            &format!(
                                "Telnet on {ip}:23 transmits credentials in cleartext. \
                                 Many devices ship with default telnet passwords. \
                                 Disable telnet and use SSH instead."
                            ),
                            Severity::High,
                        )
                        .with_ip(ip)
                        .with_port(23)
                        .with_service("Telnet")
                        .with_cwe("CWE-319"),
                    );
                }

                // SMB: flag if port 445 is open
                if has_port(445) {
                    findings.push(
                        Finding::new(
                            "credentials",
                            &format!("SMB/CIFS exposed on {ip}:445"),
                            &format!(
                                "SMB file sharing is open on {ip}:445. Verify that guest access \
                                 is disabled and shares require authentication. SMB is a frequent \
                                 target for lateral movement attacks."
                            ),
                            Severity::Medium,
                        )
                        .with_ip(ip)
                        .with_port(445)
                        .with_service("SMB")
                        .with_cwe("CWE-287"),
                    );
                }

                // RDP: flag if port 3389 is open
                if has_port(3389) {
                    findings.push(
                        Finding::new(
                            "credentials",
                            &format!("RDP exposed on {ip}:3389"),
                            &format!(
                                "Remote Desktop Protocol on {ip}:3389 is accessible. \
                                 Ensure Network Level Authentication (NLA) is enabled \
                                 and brute-force protection is in place."
                            ),
                            Severity::Medium,
                        )
                        .with_ip(ip)
                        .with_port(3389)
                        .with_service("RDP")
                        .with_cwe("CWE-287"),
                    );
                }

                // HTTP admin panels: check on any HTTP port (not just gateway)
                let http_ports: Vec<u16> = device
                    .open_ports
                    .iter()
                    .filter(|p| matches!(p.port, 80 | 443 | 8080 | 8443 | 8888 | 3000 | 9090))
                    .map(|p| p.port)
                    .collect();

                for port in http_ports {
                    if check_http_no_auth(ip, port).await == Some(true) {
                        let label = if ctx.gateway == Some(ip) {
                            "Router admin panel"
                        } else {
                            "Web admin panel"
                        };
                        findings.push(
                            Finding::new(
                                "credentials",
                                &format!("{label} without auth on {ip}:{port}"),
                                &format!(
                                    "The admin interface at {ip}:{port} returned HTTP 200 \
                                     without requiring authentication."
                                ),
                                Severity::Medium,
                            )
                            .with_ip(ip)
                            .with_port(port)
                            .with_service("HTTP")
                            .with_cwe("CWE-306"),
                        );
                    }
                }
            }

            tracing::info!(findings_count = findings.len(), "adaptive credential scan complete");
            return Ok(findings);
        }

        // ── Fallback: classic mode using ARP cache ──────────────────
        let arp_entries = rikitikitavi_network::read_arp_cache().map_err(|e| {
            ScanError::ScannerFailed {
                scanner: "credentials".to_owned(),
                message: format!("failed to read ARP cache: {e}"),
            }
        })?;

        let targets: Vec<IpAddr> = ctx.target_network.as_ref().map_or_else(
            || arp_entries.iter().map(|e| e.ip).collect(),
            |network| {
                arp_entries
                    .iter()
                    .filter(|e| network.contains(e.ip))
                    .map(|e| e.ip)
                    .collect()
            },
        );

        for &ip in &targets {
            check_ftp_credentials(ip, &mut findings).await;

            if ctx.gateway == Some(ip) {
                for &port in &[80, 443, 8080, 8443] {
                    if check_http_no_auth(ip, port).await == Some(true) {
                        findings.push(
                            Finding::new(
                                "credentials",
                                &format!("Router admin panel without auth on {ip}:{port}"),
                                &format!(
                                    "The router admin panel at {ip}:{port} returned HTTP 200 \
                                     without requiring authentication."
                                ),
                                Severity::Medium,
                            )
                            .with_ip(ip)
                            .with_port(port)
                            .with_service("HTTP")
                            .with_cwe("CWE-306"),
                        );
                    }
                }
            }

            // SMB check
            let addr = SocketAddr::new(ip, 445);
            if tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
                .await
                .is_ok_and(|r| r.is_ok())
            {
                findings.push(
                    Finding::new(
                        "credentials",
                        &format!("SMB/CIFS exposed on {ip}:445"),
                        &format!(
                            "SMB file sharing is open on {ip}:445. Verify that guest access is \
                             disabled and shares require authentication."
                        ),
                        Severity::Medium,
                    )
                    .with_ip(ip)
                    .with_port(445)
                    .with_service("SMB")
                    .with_cwe("CWE-287"),
                );
            }
        }

        tracing::info!(findings_count = findings.len(), "credential hygiene scan complete");
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        45
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ftp_code_230() {
        assert_eq!(extract_ftp_code("230 Login successful."), Some(230));
    }

    #[test]
    fn test_extract_ftp_code_530() {
        assert_eq!(extract_ftp_code("530 Login incorrect."), Some(530));
    }

    #[test]
    fn test_extract_ftp_code_331() {
        assert_eq!(
            extract_ftp_code("331 Please specify the password."),
            Some(331)
        );
    }

    #[test]
    fn test_extract_ftp_code_empty() {
        assert_eq!(extract_ftp_code(""), None);
    }

    #[test]
    fn test_extract_ftp_code_garbage() {
        assert_eq!(extract_ftp_code("Hello"), None);
    }
}
