use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, Remediation, ScanContext};
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
            // Check anonymous FTP
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
                        .with_remediation(Remediation {
                            description: "Disable anonymous FTP access.".to_owned(),
                            steps: vec![
                                "Open the FTP server configuration.".to_owned(),
                                "Disable anonymous login.".to_owned(),
                                "Require named user accounts with strong passwords.".to_owned(),
                                "Consider switching to SFTP instead.".to_owned(),
                            ],
                            effort: Some("5 minutes".to_owned()),
                        }),
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

            // Check HTTP admin interfaces on gateway
            if ctx.gateway == Some(ip) {
                for &port in &[80, 443, 8080, 8443] {
                    if let Some(no_auth) = check_http_no_auth(ip, port).await {
                        if no_auth {
                            findings.push(
                                Finding::new(
                                    "credentials",
                                    &format!("Router admin panel without auth on {ip}:{port}"),
                                    &format!(
                                        "The router admin panel at {ip}:{port} returned HTTP 200 \
                                         without requiring authentication. This may allow anyone on \
                                         the network to change router settings."
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
            }
        }

        // SMB exposure advisory — check if any host has port 445 open
        // This is advisory since we don't attempt SMB authentication
        for &ip in &targets {
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
                             disabled and shares require authentication. SMB is a frequent \
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
