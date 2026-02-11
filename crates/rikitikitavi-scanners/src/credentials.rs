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

/// Result of an anonymous FTP check.
struct FtpCheckResult {
    code: u16,
    listing: Option<String>,
}

/// Check if a host accepts anonymous FTP login.
/// Returns the FTP response code and, on success (230), a directory listing.
async fn check_anonymous_ftp(ip: IpAddr) -> Option<FtpCheckResult> {
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
    let code = if user_resp.starts_with("331") {
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
        extract_ftp_code(&pass_resp)?
    } else {
        extract_ftp_code(&user_resp)?
    };

    // If login succeeded (230), try PASV + LIST for directory listing evidence
    let listing = if code == 230 {
        try_ftp_listing(&mut stream, ip).await
    } else {
        None
    };

    Some(FtpCheckResult { code, listing })
}

/// Attempt to get a directory listing via FTP PASV mode.
async fn try_ftp_listing(stream: &mut TcpStream, _ip: IpAddr) -> Option<String> {
    // Send PASV command
    tokio::time::timeout(READ_TIMEOUT, stream.write_all(b"PASV\r\n"))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    let pasv_resp = String::from_utf8_lossy(&buf[..n]);

    let data_addr = parse_pasv_response(&pasv_resp)?;

    // Connect to data port
    let mut data_stream =
        tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(data_addr))
            .await
            .ok()?
            .ok()?;

    // Send LIST command on control connection
    tokio::time::timeout(READ_TIMEOUT, stream.write_all(b"LIST\r\n"))
        .await
        .ok()?
        .ok()?;

    // Read listing from data connection
    let mut listing_buf = vec![0u8; 2048];
    let listing_n =
        tokio::time::timeout(READ_TIMEOUT, data_stream.read(&mut listing_buf))
            .await
            .ok()?
            .ok()?;

    if listing_n == 0 {
        return None;
    }

    let listing = String::from_utf8_lossy(&listing_buf[..listing_n])
        .trim()
        .to_owned();
    if listing.is_empty() { None } else { Some(listing) }
}

/// Extract the 3-digit FTP response code from a response line.
fn extract_ftp_code(response: &str) -> Option<u16> {
    let code_str: String = response.chars().take(3).collect();
    code_str.parse().ok()
}

/// Result of an HTTP no-auth check.
struct HttpCheckResult {
    no_auth: bool,
    evidence: Option<String>,
}

/// Check if an HTTP admin interface is accessible without authentication.
/// On success (200 without login form), captures evidence: first HTTP line,
/// Server header, and page title.
async fn check_http_no_auth(ip: IpAddr, port: u16) -> Option<HttpCheckResult> {
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
        if body_lower.contains("login")
            || body_lower.contains("password")
            || body_lower.contains("sign in")
        {
            return Some(HttpCheckResult {
                no_auth: false,
                evidence: None,
            });
        }
        // Build evidence: first HTTP line + Server header + page title
        let mut evidence_parts = vec![first_line.to_owned()];
        for line in response.lines().skip(1) {
            if line.to_lowercase().starts_with("server:") {
                evidence_parts.push(line.trim().to_owned());
                break;
            }
        }
        if let Some(title) = extract_html_title(&response) {
            evidence_parts.push(format!("Title: {title}"));
        }
        return Some(HttpCheckResult {
            no_auth: true,
            evidence: Some(evidence_parts.join("\n")),
        });
    }

    Some(HttpCheckResult {
        no_auth: false,
        evidence: None,
    })
}

/// Capture the telnet login prompt/banner (non-destructive).
///
/// Connects to port 23, reads the initial banner, and strips telnet IAC
/// sequences (0xFF xx xx) to produce clean text.
async fn capture_telnet_prompt(ip: IpAddr) -> Option<String> {
    let addr = SocketAddr::new(ip, 23);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    // Strip telnet IAC sequences (0xFF followed by 2 bytes)
    let cleaned = strip_telnet_iac(&buf[..n]);
    let text = String::from_utf8_lossy(&cleaned);
    let trimmed = text.trim().to_owned();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

/// Strip telnet IAC (Interpret As Command) sequences from raw bytes.
///
/// IAC sequences start with 0xFF followed by a command byte and optionally
/// an option byte. Commands 251-254 (WILL/WONT/DO/DONT) take one option byte.
fn strip_telnet_iac(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0xFF && i + 1 < data.len() {
            let cmd = data[i + 1];
            if (251..=254).contains(&cmd) && i + 2 < data.len() {
                // WILL/WONT/DO/DONT + option byte: skip 3 bytes
                i += 3;
            } else {
                // Other IAC commands: skip 2 bytes
                i += 2;
            }
        } else {
            result.push(data[i]);
            i += 1;
        }
    }
    result
}

/// Extract the `<title>` content from an HTML response.
fn extract_html_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let start = lower.find("<title>")? + 7;
    let end = lower[start..].find("</title>")? + start;
    let title = body[start..end].trim().to_owned();
    if title.is_empty() { None } else { Some(title) }
}

/// Parse an FTP PASV response to extract the data port address.
///
/// PASV response format: `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).`
fn parse_pasv_response(response: &str) -> Option<SocketAddr> {
    let start = response.find('(')? + 1;
    let end = response.find(')')?;
    let parts: Vec<&str> = response[start..end].split(',').collect();
    if parts.len() != 6 {
        return None;
    }
    let nums: Vec<u8> = parts.iter().filter_map(|p| p.trim().parse().ok()).collect();
    if nums.len() != 6 {
        return None;
    }
    let ip_addr: IpAddr = format!("{}.{}.{}.{}", nums[0], nums[1], nums[2], nums[3])
        .parse()
        .ok()?;
    let port = u16::from(nums[4]) * 256 + u16::from(nums[5]);
    Some(SocketAddr::new(ip_addr, port))
}

/// Check FTP credentials on a target and push findings.
async fn check_ftp_credentials(ip: IpAddr, findings: &mut Vec<Finding>) {
    if let Some(result) = check_anonymous_ftp(ip).await {
        if result.code == 230 {
            let mut finding = Finding::new(
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
            ));
            if let Some(listing) = &result.listing {
                finding = finding.with_evidence(format!("Directory listing:\n{listing}"));
            }
            findings.push(finding);
        } else if result.code == 530 {
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
                    let mut finding = Finding::new(
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
                    .with_cwe("CWE-319")
                    .with_opt_remediation(crate::remediation::get(
                        "rikitikitavi.credentials.telnet-default",
                        &[],
                    ));
                    if ctx.config.intensity.at_least(
                        rikitikitavi_models::config::ScanIntensity::Active,
                    ) {
                        if let Some(prompt) = capture_telnet_prompt(ip).await {
                            finding =
                                finding.with_evidence(format!("Login prompt: {prompt}"));
                        }
                    }
                    findings.push(finding);
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
                        .with_cwe("CWE-287")
                        .with_opt_remediation(crate::remediation::get(
                            "rikitikitavi.credentials.smb-exposed",
                            &[],
                        )),
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
                        .with_cwe("CWE-287")
                        .with_opt_remediation(crate::remediation::get(
                            "rikitikitavi.credentials.rdp-exposed",
                            &[],
                        )),
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
                    if let Some(result) = check_http_no_auth(ip, port).await {
                        if result.no_auth {
                            let label = if ctx.gateway == Some(ip) {
                                "Router admin panel"
                            } else {
                                "Web admin panel"
                            };
                            let mut finding = Finding::new(
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
                            .with_cwe("CWE-306")
                            .with_opt_remediation(crate::remediation::get(
                                "rikitikitavi.credentials.http-no-auth",
                                &[],
                            ));
                            if let Some(evidence) = result.evidence {
                                finding = finding.with_evidence(evidence);
                            }
                            findings.push(finding);
                        }
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
                    if let Some(result) = check_http_no_auth(ip, port).await {
                        if result.no_auth {
                            let mut finding = Finding::new(
                                "credentials",
                                &format!(
                                    "Router admin panel without auth on {ip}:{port}"
                                ),
                                &format!(
                                    "The router admin panel at {ip}:{port} returned \
                                     HTTP 200 without requiring authentication."
                                ),
                                Severity::Medium,
                            )
                            .with_ip(ip)
                            .with_port(port)
                            .with_service("HTTP")
                            .with_cwe("CWE-306")
                            .with_opt_remediation(crate::remediation::get(
                                "rikitikitavi.credentials.http-no-auth",
                                &[],
                            ));
                            if let Some(evidence) = result.evidence {
                                finding = finding.with_evidence(evidence);
                            }
                            findings.push(finding);
                        }
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
                    .with_cwe("CWE-287")
                    .with_opt_remediation(crate::remediation::get(
                        "rikitikitavi.credentials.smb-exposed",
                        &[],
                    )),
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

    // ── parse_pasv_response tests ─────────────────────────────────

    #[test]
    fn test_parse_pasv_standard() {
        let resp = "227 Entering Passive Mode (192,168,1,1,39,5).";
        let addr = parse_pasv_response(resp).unwrap();
        assert_eq!(addr.ip(), IpAddr::from([192, 168, 1, 1]));
        // port = 39*256 + 5 = 9989
        assert_eq!(addr.port(), 9989);
    }

    #[test]
    fn test_parse_pasv_high_port() {
        let resp = "227 Entering Passive Mode (10,0,0,1,200,100).";
        let addr = parse_pasv_response(resp).unwrap();
        assert_eq!(addr.ip(), IpAddr::from([10, 0, 0, 1]));
        // port = 200*256 + 100 = 51300
        assert_eq!(addr.port(), 51300);
    }

    #[test]
    fn test_parse_pasv_no_parens() {
        assert!(parse_pasv_response("227 No parens here").is_none());
    }

    #[test]
    fn test_parse_pasv_wrong_part_count() {
        assert!(parse_pasv_response("227 (1,2,3,4,5)").is_none());
    }

    #[test]
    fn test_parse_pasv_non_numeric() {
        assert!(parse_pasv_response("227 (a,b,c,d,e,f)").is_none());
    }

    // ── extract_html_title tests ──────────────────────────────────

    #[test]
    fn test_extract_title_basic() {
        let html = "<html><head><title>Router Admin</title></head></html>";
        assert_eq!(extract_html_title(html), Some("Router Admin".to_owned()));
    }

    #[test]
    fn test_extract_title_mixed_case() {
        let html = "<HTML><HEAD><TITLE>My Panel</TITLE></HEAD></HTML>";
        assert_eq!(extract_html_title(html), Some("My Panel".to_owned()));
    }

    #[test]
    fn test_extract_title_whitespace() {
        let html = "<title>  Spaced Title  </title>";
        assert_eq!(extract_html_title(html), Some("Spaced Title".to_owned()));
    }

    #[test]
    fn test_extract_title_empty() {
        let html = "<title>  </title>";
        assert_eq!(extract_html_title(html), None);
    }

    #[test]
    fn test_extract_title_missing() {
        let html = "<html><body>No title here</body></html>";
        assert_eq!(extract_html_title(html), None);
    }

    // ── strip_telnet_iac tests ────────────────────────────────────

    #[test]
    fn test_strip_iac_no_sequences() {
        let data = b"Hello World";
        assert_eq!(strip_telnet_iac(data), data.to_vec());
    }

    #[test]
    fn test_strip_iac_will_do_sequences() {
        // IAC WILL ECHO (FF FB 01) + IAC DO TERMINAL_TYPE (FF FD 18) + "login: "
        let mut data = vec![0xFF, 0xFB, 0x01, 0xFF, 0xFD, 0x18];
        data.extend_from_slice(b"login: ");
        assert_eq!(strip_telnet_iac(&data), b"login: ".to_vec());
    }

    #[test]
    fn test_strip_iac_other_command() {
        // IAC NOP (FF F1) + "data"
        let mut data = vec![0xFF, 0xF1];
        data.extend_from_slice(b"data");
        assert_eq!(strip_telnet_iac(&data), b"data".to_vec());
    }

    #[test]
    fn test_strip_iac_mixed() {
        // "BusyBox" + IAC WONT ECHO (FF FC 01) + " login: "
        let mut data = b"BusyBox".to_vec();
        data.extend_from_slice(&[0xFF, 0xFC, 0x01]);
        data.extend_from_slice(b" login: ");
        assert_eq!(strip_telnet_iac(&data), b"BusyBox login: ".to_vec());
    }

    #[test]
    fn test_strip_iac_empty() {
        assert_eq!(strip_telnet_iac(&[]), Vec::<u8>::new());
    }
}
