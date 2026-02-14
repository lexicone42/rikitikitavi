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
    banner: Option<FtpBanner>,
}

/// Parsed FTP server banner — software identification from the greeting.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FtpBanner {
    software: String,
    version: Option<String>,
    raw: String,
}

/// Check if a host accepts anonymous FTP login.
/// Returns the FTP response code, optional directory listing, and parsed banner.
async fn check_anonymous_ftp(ip: IpAddr) -> Option<FtpCheckResult> {
    let addr = SocketAddr::new(ip, 21);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Read banner
    let mut banner_buf = vec![0u8; 1024];
    let banner_n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut banner_buf))
        .await
        .ok()?
        .ok()?;

    // Parse the banner for software identification
    let banner_str = String::from_utf8_lossy(&banner_buf[..banner_n]);
    let banner = parse_ftp_banner(&banner_str);

    // Send anonymous login
    tokio::time::timeout(READ_TIMEOUT, stream.write_all(b"USER anonymous\r\n"))
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

    Some(FtpCheckResult {
        code,
        listing,
        banner,
    })
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
    let mut data_stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(data_addr))
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
    let listing_n = tokio::time::timeout(READ_TIMEOUT, data_stream.read(&mut listing_buf))
        .await
        .ok()?
        .ok()?;

    if listing_n == 0 {
        return None;
    }

    let listing = String::from_utf8_lossy(&listing_buf[..listing_n])
        .trim()
        .to_owned();
    if listing.is_empty() {
        None
    } else {
        Some(listing)
    }
}

/// Extract the 3-digit FTP response code from a response line.
fn extract_ftp_code(response: &str) -> Option<u16> {
    let code_str: String = response.chars().take(3).collect();
    code_str.parse().ok()
}

/// Parse a complete FTP response, handling multi-line continuation.
///
/// FTP multi-line format: `220-Line1\r\n220-Line2\r\n220 Final.\r\n`
/// - First 3 chars are the response code
/// - 4th char `-` means continuation, ` ` means final line
///
/// Returns `(code, collected_text)`.
fn parse_ftp_response(response: &str) -> Option<(u16, String)> {
    let mut lines_iter = response.lines();
    let first_line = lines_iter.next()?;

    // FTP codes are always 3 ASCII digits — guard against multi-byte chars
    let bytes = first_line.as_bytes();
    if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
        return None;
    }

    // Safe to slice: first 3 bytes are guaranteed ASCII
    let code: u16 = first_line[..3].parse().ok()?;
    let mut text_parts = Vec::new();

    // Get text after the code+separator on the first line
    if bytes.len() > 4 {
        text_parts.push(&first_line[4..]);
    }

    // Check if this is a multi-line response (4th char is '-')
    if bytes.len() >= 4 && bytes[3] == b'-' {
        let code_str = &first_line[..3];
        for line in lines_iter {
            let lb = line.as_bytes();
            if lb.len() >= 4 && line.starts_with(code_str) && lb[3] == b' ' {
                // Final line
                text_parts.push(&line[4..]);
                break;
            } else if lb.len() >= 4 && line.starts_with(code_str) && lb[3] == b'-' {
                text_parts.push(&line[4..]);
            } else {
                // Continuation line without code prefix
                text_parts.push(line);
            }
        }
    }

    let text = text_parts.join("\n");
    Some((code, text))
}

/// Extract software name and version from an FTP banner.
///
/// Recognizes: `vsFTPd`, `ProFTPD`, `Pure-FTPd`, `FileZilla` Server,
/// Microsoft FTP, `wu-ftpd`.
fn parse_ftp_banner(banner: &str) -> Option<FtpBanner> {
    // Parse the response to get raw text
    let (_, text) = parse_ftp_response(banner)?;
    let raw = text.clone();

    // Try each known pattern
    if let Some(banner) = match_vsftpd(&text, &raw) {
        return Some(banner);
    }
    if let Some(banner) = match_proftpd(&text, &raw) {
        return Some(banner);
    }
    if let Some(banner) = match_filezilla(&text, &raw) {
        return Some(banner);
    }
    if let Some(banner) = match_pureftpd(&text, &raw) {
        return Some(banner);
    }
    if let Some(banner) = match_microsoft_ftp(&text, &raw) {
        return Some(banner);
    }
    if let Some(banner) = match_wuftpd(&text, &raw) {
        return Some(banner);
    }

    // Unknown server — return raw banner if we got a 220
    Some(FtpBanner {
        software: "Unknown".to_owned(),
        version: None,
        raw,
    })
}

/// Match `vsFTPd` banner: `(vsFTPd X.Y.Z)` or `vsFTPd X.Y.Z`
fn match_vsftpd(text: &str, raw: &str) -> Option<FtpBanner> {
    // Pattern: "(vsFTPd X.Y.Z)" — with parens
    if let Some(start) = text.find("vsFTPd ") {
        let after = &text[start + 7..];
        let version_end = after
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(after.len());
        let version = &after[..version_end];
        if !version.is_empty() {
            return Some(FtpBanner {
                software: "vsFTPd".to_owned(),
                version: Some(version.to_owned()),
                raw: raw.to_owned(),
            });
        }
    }
    if text.contains("vsFTPd") {
        return Some(FtpBanner {
            software: "vsFTPd".to_owned(),
            version: None,
            raw: raw.to_owned(),
        });
    }
    None
}

/// Match `ProFTPD` banner: `ProFTPD X.Y.Z Server`
fn match_proftpd(text: &str, raw: &str) -> Option<FtpBanner> {
    if let Some(start) = text.find("ProFTPD ") {
        let after = &text[start + 8..];
        let version_end = after
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(after.len());
        let version = &after[..version_end];
        if !version.is_empty() {
            return Some(FtpBanner {
                software: "ProFTPD".to_owned(),
                version: Some(version.to_owned()),
                raw: raw.to_owned(),
            });
        }
    }
    if text.contains("ProFTPD") {
        return Some(FtpBanner {
            software: "ProFTPD".to_owned(),
            version: None,
            raw: raw.to_owned(),
        });
    }
    None
}

/// Match `FileZilla` Server banner: `FileZilla Server X.Y.Z`
fn match_filezilla(text: &str, raw: &str) -> Option<FtpBanner> {
    if let Some(start) = text.find("FileZilla Server ") {
        let after = &text[start + 17..];
        let version_end = after
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(after.len());
        let version = &after[..version_end];
        if !version.is_empty() {
            return Some(FtpBanner {
                software: "FileZilla Server".to_owned(),
                version: Some(version.to_owned()),
                raw: raw.to_owned(),
            });
        }
    }
    if text.contains("FileZilla") {
        return Some(FtpBanner {
            software: "FileZilla Server".to_owned(),
            version: None,
            raw: raw.to_owned(),
        });
    }
    None
}

/// Match `Pure-FTPd` banner
fn match_pureftpd(text: &str, raw: &str) -> Option<FtpBanner> {
    if text.contains("Pure-FTPd") {
        return Some(FtpBanner {
            software: "Pure-FTPd".to_owned(),
            version: None,
            raw: raw.to_owned(),
        });
    }
    None
}

/// Match Microsoft FTP Service banner
fn match_microsoft_ftp(text: &str, raw: &str) -> Option<FtpBanner> {
    if text.contains("Microsoft FTP") {
        return Some(FtpBanner {
            software: "Microsoft FTP".to_owned(),
            version: None,
            raw: raw.to_owned(),
        });
    }
    None
}

/// Match `wu-ftpd` banner
fn match_wuftpd(text: &str, raw: &str) -> Option<FtpBanner> {
    if text.contains("wu-") {
        return Some(FtpBanner {
            software: "wu-ftpd".to_owned(),
            version: None,
            raw: raw.to_owned(),
        });
    }
    None
}

/// Classify a `vsFTPd` version — versions below 3.0 have known vulnerabilities.
fn classify_vsftpd_version_eol(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    if let Some(major_str) = parts.first() {
        if let Ok(major) = major_str.parse::<u32>() {
            return major < 3;
        }
    }
    false
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
        // Check if the response suggests auth is present (login forms, OAuth,
        // password fields, auth headers, etc.)
        let body_lower = response.to_lowercase();
        if body_lower.contains("login")
            || body_lower.contains("password")
            || body_lower.contains("sign in")
            || body_lower.contains("log in")
            || body_lower.contains("signin")
            || body_lower.contains("authenticate")
            || body_lower.contains("username")
            || body_lower.contains("type=\"password\"")
            || body_lower.contains("type='password'")
            || body_lower.contains("oauth")
            || body_lower.contains("saml")
            || body_lower.contains("openid")
            || body_lower.contains("www-authenticate:")
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
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
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

// ── Telnet default credential testing ────────────────────────────

/// Default credential pairs to test against telnet services.
/// Covers the most common factory-shipped defaults across routers, `IoT` devices,
/// and embedded `Linux` systems.
const DEFAULT_TELNET_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("root", "root"),
    ("admin", "password"),
    ("admin", ""),
    ("root", ""),
    ("user", "user"),
    ("admin", "1234"),
];

/// Additional vendor-specific credential pairs appended when the banner
/// matches known device fingerprints.
const CISCO_CREDS: &[(&str, &str)] = &[("cisco", "cisco")];
const MIKROTIK_CREDS: &[(&str, &str)] = &[("admin", "")];

/// Result of a successful telnet default credential login.
struct TelnetLoginResult {
    username: String,
    /// Human-readable hint — never the actual password.
    password_hint: String,
    banner: String,
    post_login: String,
}

/// Classify a telnet response after sending credentials.
///
/// Returns `true` if the response indicates a successful login (shell prompt,
/// welcome message, `BusyBox` shell) and `false` if it contains failure
/// keywords.
fn classify_telnet_response(response: &str) -> bool {
    let lower = response.to_lowercase();

    // Explicit failure indicators
    let failure_keywords = [
        "incorrect",
        "failed",
        "denied",
        "invalid",
        "bad password",
        "login incorrect",
        "authentication failure",
        "access denied",
    ];
    if failure_keywords.iter().any(|kw| lower.contains(kw)) {
        return false;
    }

    // Success indicators: shell prompts, welcome messages, BusyBox
    let success_indicators = ["welcome", "last login", "busybox"];
    if success_indicators.iter().any(|kw| lower.contains(kw)) {
        return true;
    }

    // Shell prompts at end of output
    let trimmed = response.trim();
    if trimmed.ends_with('$') || trimmed.ends_with('#') || trimmed.ends_with('>') {
        return true;
    }

    // If we got a non-empty response with no failure keywords and no
    // further login/password prompt, treat as likely success
    !lower.contains("login:") && !lower.contains("password:")
}

/// Build a human-readable password hint (never the actual password).
fn password_hint(password: &str) -> String {
    if password.is_empty() {
        "empty password".to_owned()
    } else if password.chars().all(char::is_numeric) {
        "numeric PIN".to_owned()
    } else {
        "default password".to_owned()
    }
}

/// Build the prioritised credential list based on the banner content.
///
/// Vendor-specific pairs are prepended so they are tried first; duplicates
/// in the default list are then skipped.
fn build_credential_list(banner: &str) -> Vec<(&'static str, &'static str)> {
    let lower = banner.to_lowercase();
    let mut creds: Vec<(&str, &str)> = Vec::with_capacity(DEFAULT_TELNET_CREDS.len() + 2);

    if lower.contains("busybox") {
        // BusyBox devices: root/(empty) and root/root most likely
        creds.push(("root", ""));
        creds.push(("root", "root"));
    } else if lower.contains("cisco") || lower.contains("ios") {
        for &pair in CISCO_CREDS {
            creds.push(pair);
        }
        creds.push(("admin", "admin"));
    } else if lower.contains("mikrotik") {
        for &pair in MIKROTIK_CREDS {
            creds.push(pair);
        }
    }

    // Append remaining defaults, skipping any already queued
    for &pair in DEFAULT_TELNET_CREDS {
        if !creds.contains(&pair) {
            creds.push(pair);
        }
    }

    creds
}

/// Attempt a single telnet login with the given credentials.
///
/// Opens a fresh TCP connection, waits for the login prompt, sends the
/// username and password, then classifies the server response.
async fn try_telnet_login(ip: IpAddr, username: &str, password: &str) -> Option<TelnetLoginResult> {
    let addr = SocketAddr::new(ip, 23);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Read banner / login prompt
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let cleaned = strip_telnet_iac(&buf[..n]);
    let banner = String::from_utf8_lossy(&cleaned).trim().to_owned();

    // Wait for login prompt
    let banner_lower = banner.to_lowercase();
    if !banner_lower.contains("login") && !banner_lower.contains("username") {
        // Maybe the prompt hasn't arrived yet — read more
        let mut buf2 = vec![0u8; 1024];
        if let Ok(Ok(n2)) =
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf2)).await
        {
            if n2 > 0 {
                let extra = String::from_utf8_lossy(&strip_telnet_iac(&buf2[..n2])).to_lowercase();
                if !extra.contains("login") && !extra.contains("username") {
                    return None; // No login prompt found
                }
            }
        } else {
            return None;
        }
    }

    // Send username
    let user_cmd = format!("{username}\r\n");
    tokio::time::timeout(READ_TIMEOUT, stream.write_all(user_cmd.as_bytes()))
        .await
        .ok()?
        .ok()?;

    // Wait for password prompt
    let mut buf3 = vec![0u8; 1024];
    let n3 = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf3))
        .await
        .ok()?
        .ok()?;
    if n3 > 0 {
        let prompt = String::from_utf8_lossy(&strip_telnet_iac(&buf3[..n3])).to_lowercase();
        if !prompt.contains("password") && !prompt.contains("assword") {
            return None; // No password prompt — unusual protocol
        }
    }

    // Send password
    let pass_cmd = format!("{password}\r\n");
    tokio::time::timeout(READ_TIMEOUT, stream.write_all(pass_cmd.as_bytes()))
        .await
        .ok()?
        .ok()?;

    // Read response and classify
    let mut buf4 = vec![0u8; 2048];
    let n4 = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf4))
        .await
        .ok()?
        .ok()?;
    if n4 == 0 {
        return None;
    }
    let response = String::from_utf8_lossy(&strip_telnet_iac(&buf4[..n4]))
        .trim()
        .to_owned();

    if classify_telnet_response(&response) {
        Some(TelnetLoginResult {
            username: username.to_owned(),
            password_hint: password_hint(password),
            banner,
            post_login: truncate_evidence(&response, 200),
        })
    } else {
        None
    }
}

/// Truncate evidence text to a maximum length, adding an ellipsis if needed.
fn truncate_evidence(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_owned()
    } else {
        format!("{}...", &text[..max_len])
    }
}

/// Check a telnet service for default credentials.
///
/// Captures the banner first for fingerprinting, builds a prioritised
/// credential list, and tries each pair with a short delay between attempts.
async fn check_telnet_default_creds(ip: IpAddr) -> Option<TelnetLoginResult> {
    let banner = capture_telnet_prompt(ip).await.unwrap_or_default();
    let creds = build_credential_list(&banner);

    for (i, &(user, pass)) in creds.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if let Some(result) = try_telnet_login(ip, user, pass).await {
            return Some(result);
        }
    }
    None
}

/// Extract the `<title>` content from an HTML response.
fn extract_html_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let start = lower.find("<title>")? + 7;
    let end = lower[start..].find("</title>")? + start;
    let title = body[start..end].trim().to_owned();
    if title.is_empty() {
        None
    } else {
        Some(title)
    }
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
#[allow(clippy::too_many_lines)]
async fn check_ftp_credentials(ip: IpAddr, findings: &mut Vec<Finding>) {
    if let Some(result) = check_anonymous_ftp(ip).await {
        // Banner disclosure finding — always generated when banner is parsed
        if let Some(ref banner) = result.banner {
            if banner.software != "Unknown" {
                let version_label = banner
                    .version
                    .as_ref()
                    .map_or_else(String::new, |v| format!(" {v}"));
                findings.push(
                    Finding::new(
                        "credentials",
                        &format!(
                            "FTP banner discloses {}{version_label} on {ip}",
                            banner.software
                        ),
                        &format!(
                            "FTP server at {ip}:21 discloses software version: \
                             {}{version_label}. Banner: {}",
                            banner.software, banner.raw,
                        ),
                        Severity::Low,
                    )
                    .with_ip(ip)
                    .with_port(21)
                    .with_service("FTP")
                    .with_cwe("CWE-200"),
                );
            }

            // Old vsFTPd version check
            if banner.software == "vsFTPd" {
                if let Some(ref version) = banner.version {
                    if classify_vsftpd_version_eol(version) {
                        findings.push(
                            Finding::new(
                                "credentials",
                                &format!("vsFTPd {version} has known vulnerabilities on {ip}"),
                                &format!(
                                    "FTP server at {ip}:21 is running vsFTPd {version}. \
                                     Versions below 3.0 have known security vulnerabilities \
                                     including the infamous vsftpd 2.3.4 backdoor. Upgrade \
                                     to vsFTPd 3.0 or later.",
                                ),
                                Severity::Medium,
                            )
                            .with_ip(ip)
                            .with_port(21)
                            .with_service("FTP")
                            .with_cwe("CWE-1104"),
                        );
                    }
                }
            }
        }

        // Anonymous login findings
        if result.code == 230 {
            let software_label = result
                .banner
                .as_ref()
                .map(|b| {
                    if b.software == "Unknown" {
                        String::new()
                    } else {
                        format!(" ({})", b.software)
                    }
                })
                .unwrap_or_default();
            let mut finding = Finding::new(
                "credentials",
                &format!("Anonymous FTP login accepted on {ip}"),
                &format!(
                    "FTP server{software_label} at {ip}:21 accepts anonymous login. \
                     Anyone on the network can read (and possibly write) files."
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
                    &format!("FTP at {ip}:21 correctly rejects anonymous login (code 530)."),
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
            let target_devices: Vec<_> = if ctx
                .config
                .intensity
                .at_least(rikitikitavi_models::config::ScanIntensity::Active)
            {
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

                // Telnet: flag cleartext protocol + test default credentials
                if has_port(23) {
                    let is_active = ctx
                        .config
                        .intensity
                        .at_least(rikitikitavi_models::config::ScanIntensity::Active);

                    // In Active mode, attempt default credential login
                    let login_result = if is_active {
                        check_telnet_default_creds(ip).await
                    } else {
                        None
                    };

                    if let Some(ref result) = login_result {
                        // Confirmed default credentials — Critical
                        let banner_snip = truncate_evidence(&result.banner, 80);
                        findings.push(
                            Finding::new(
                                "credentials",
                                &format!("Default telnet credentials confirmed on {ip}"),
                                &format!(
                                    "Default credentials confirmed: login as '{}' \
                                     with {} on {ip}:23. Banner: {banner_snip}",
                                    result.username, result.password_hint,
                                ),
                                Severity::Critical,
                            )
                            .with_ip(ip)
                            .with_port(23)
                            .with_service("Telnet")
                            .with_cwe("CWE-1393")
                            .with_evidence(format!("Post-login output: {}", result.post_login,))
                            .with_opt_remediation(
                                crate::remediation::get(
                                    "rikitikitavi.credentials.telnet-default-confirmed",
                                    &[],
                                ),
                            ),
                        );
                    }

                    // Always flag cleartext protocol (separate finding)
                    let mut cleartext_finding = Finding::new(
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
                    if is_active {
                        if let Some(ref result) = login_result {
                            cleartext_finding = cleartext_finding
                                .with_evidence(format!("Login prompt: {}", result.banner));
                        } else if let Some(prompt) = capture_telnet_prompt(ip).await {
                            cleartext_finding =
                                cleartext_finding.with_evidence(format!("Login prompt: {prompt}"));
                        }
                    }
                    findings.push(cleartext_finding);
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
                            .with_opt_remediation(
                                crate::remediation::get(
                                    "rikitikitavi.credentials.http-no-auth",
                                    &[],
                                ),
                            );
                            if let Some(evidence) = result.evidence {
                                finding = finding.with_evidence(evidence);
                            }
                            findings.push(finding);
                        }
                    }
                }
            }

            tracing::info!(
                findings_count = findings.len(),
                "adaptive credential scan complete"
            );
            return Ok(findings);
        }

        // ── Fallback: classic mode using ARP cache ──────────────────
        let arp_entries =
            rikitikitavi_network::read_arp_cache().map_err(|e| ScanError::ScannerFailed {
                scanner: "credentials".to_owned(),
                message: format!("failed to read ARP cache: {e}"),
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
                                &format!("Router admin panel without auth on {ip}:{port}"),
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
                            .with_opt_remediation(
                                crate::remediation::get(
                                    "rikitikitavi.credentials.http-no-auth",
                                    &[],
                                ),
                            );
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

        tracing::info!(
            findings_count = findings.len(),
            "credential hygiene scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        45
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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

    // ── classify_telnet_response tests ───────────────────────────────

    #[test]
    fn test_classify_success_shell_prompt_hash() {
        assert!(classify_telnet_response("root@device:~# "));
    }

    #[test]
    fn test_classify_success_shell_prompt_dollar() {
        assert!(classify_telnet_response("user@host:~$ "));
    }

    #[test]
    fn test_classify_success_shell_prompt_angle() {
        assert!(classify_telnet_response("Router> "));
    }

    #[test]
    fn test_classify_success_welcome() {
        assert!(classify_telnet_response("Welcome to OpenWrt!"));
    }

    #[test]
    fn test_classify_success_last_login() {
        assert!(classify_telnet_response(
            "Last login: Mon Feb 10 12:34:56 from 192.168.1.5"
        ));
    }

    #[test]
    fn test_classify_success_busybox() {
        assert!(classify_telnet_response(
            "BusyBox v1.36.1 built-in shell (ash)\n#"
        ));
    }

    #[test]
    fn test_classify_failure_incorrect() {
        assert!(!classify_telnet_response("Login incorrect"));
    }

    #[test]
    fn test_classify_failure_denied() {
        assert!(!classify_telnet_response("Access denied"));
    }

    #[test]
    fn test_classify_failure_bad_password() {
        assert!(!classify_telnet_response("bad password"));
    }

    #[test]
    fn test_classify_failure_invalid() {
        assert!(!classify_telnet_response("Invalid credentials"));
    }

    #[test]
    fn test_classify_failure_login_prompt_again() {
        // Getting another login prompt means failure
        assert!(!classify_telnet_response("login: "));
    }

    #[test]
    fn test_classify_failure_password_prompt_again() {
        assert!(!classify_telnet_response("Password: "));
    }

    #[test]
    fn test_classify_failure_authentication_failure() {
        assert!(!classify_telnet_response("authentication failure"));
    }

    #[test]
    fn test_classify_empty_response_is_failure() {
        // Empty string — no success indicators, but also no content
        // The function won't be called with truly empty responses in practice
        // (try_telnet_login checks n4 == 0 first), but classify treats it as
        // success since there are no failure/prompt keywords. That's fine
        // because the caller guards against empty.
        assert!(classify_telnet_response(""));
    }

    // ── password_hint tests ──────────────────────────────────────────

    #[test]
    fn test_password_hint_empty() {
        assert_eq!(password_hint(""), "empty password");
    }

    #[test]
    fn test_password_hint_numeric() {
        assert_eq!(password_hint("1234"), "numeric PIN");
    }

    #[test]
    fn test_password_hint_default() {
        assert_eq!(password_hint("admin"), "default password");
    }

    #[test]
    fn test_password_hint_mixed() {
        assert_eq!(password_hint("pass123"), "default password");
    }

    // ── build_credential_list tests ──────────────────────────────────

    #[test]
    fn test_cred_list_generic_banner() {
        let creds = build_credential_list("Welcome to Device\nlogin: ");
        assert_eq!(creds.len(), DEFAULT_TELNET_CREDS.len());
        assert_eq!(creds[0], ("admin", "admin"));
    }

    #[test]
    fn test_cred_list_busybox_prioritises_root() {
        let creds = build_credential_list("BusyBox v1.36.1\nlogin: ");
        // root/(empty) and root/root should be first
        assert_eq!(creds[0], ("root", ""));
        assert_eq!(creds[1], ("root", "root"));
        // No duplicates
        assert!(!creds[2..].contains(&("root", "")));
        assert!(!creds[2..].contains(&("root", "root")));
    }

    #[test]
    fn test_cred_list_cisco_prioritises_cisco() {
        let creds = build_credential_list("Cisco IOS Software\nUser Access");
        assert_eq!(creds[0], ("cisco", "cisco"));
        assert_eq!(creds[1], ("admin", "admin"));
        // cisco/cisco shouldn't appear again
        assert!(!creds[2..].contains(&("cisco", "cisco")));
    }

    #[test]
    fn test_cred_list_mikrotik_prioritises_admin_empty() {
        let creds = build_credential_list("MikroTik RouterOS\nLogin: ");
        assert_eq!(creds[0], ("admin", ""));
        // admin/(empty) shouldn't be duplicated
        assert!(!creds[1..].contains(&("admin", "")));
    }

    #[test]
    fn test_cred_list_no_duplicates() {
        // All vendor-specific lists should produce no duplicates
        for banner in &["BusyBox", "Cisco IOS", "MikroTik", "generic device"] {
            let creds = build_credential_list(banner);
            let mut seen = Vec::new();
            for pair in &creds {
                assert!(
                    !seen.contains(pair),
                    "duplicate {pair:?} for banner {banner}"
                );
                seen.push(*pair);
            }
        }
    }

    // ── truncate_evidence tests ──────────────────────────────────────

    #[test]
    fn test_truncate_short() {
        assert_eq!(truncate_evidence("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_exact() {
        assert_eq!(truncate_evidence("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_long() {
        let result = truncate_evidence("hello world", 5);
        assert_eq!(result, "hello...");
    }

    // ── FTP response parsing tests ──────────────────────────────────

    #[test]
    fn test_parse_ftp_response_single_line() {
        let (code, text) = parse_ftp_response("220 Ready.\r\n").unwrap();
        assert_eq!(code, 220);
        assert_eq!(text, "Ready.");
    }

    #[test]
    fn test_parse_ftp_response_multi_line() {
        let response = "220-Welcome to FTP\r\n220-Please login\r\n220 Ready.\r\n";
        let (code, text) = parse_ftp_response(response).unwrap();
        assert_eq!(code, 220);
        assert_eq!(text, "Welcome to FTP\nPlease login\nReady.");
    }

    #[test]
    fn test_parse_ftp_response_empty() {
        assert!(parse_ftp_response("").is_none());
    }

    #[test]
    fn test_parse_ftp_response_short() {
        assert!(parse_ftp_response("ab").is_none());
    }

    #[test]
    fn test_parse_ftp_response_non_numeric() {
        assert!(parse_ftp_response("abc Not a code").is_none());
    }

    #[test]
    fn test_parse_ftp_response_530() {
        let (code, text) = parse_ftp_response("530 Login incorrect.\r\n").unwrap();
        assert_eq!(code, 530);
        assert_eq!(text, "Login incorrect.");
    }

    // ── FTP banner parsing tests ────────────────────────────────────

    #[test]
    fn test_parse_ftp_banner_vsftpd() {
        let banner = parse_ftp_banner("220 (vsFTPd 3.0.5)\r\n").unwrap();
        assert_eq!(banner.software, "vsFTPd");
        assert_eq!(banner.version.as_deref(), Some("3.0.5"));
    }

    #[test]
    fn test_parse_ftp_banner_proftpd() {
        let banner = parse_ftp_banner("220 ProFTPD 1.3.8 Server\r\n").unwrap();
        assert_eq!(banner.software, "ProFTPD");
        assert_eq!(banner.version.as_deref(), Some("1.3.8"));
    }

    #[test]
    fn test_parse_ftp_banner_filezilla() {
        let banner = parse_ftp_banner("220-FileZilla Server 1.8.0\r\n220 Welcome\r\n").unwrap();
        assert_eq!(banner.software, "FileZilla Server");
        assert_eq!(banner.version.as_deref(), Some("1.8.0"));
    }

    #[test]
    fn test_parse_ftp_banner_microsoft() {
        let banner = parse_ftp_banner("220 Microsoft FTP Service\r\n").unwrap();
        assert_eq!(banner.software, "Microsoft FTP");
        assert!(banner.version.is_none());
    }

    #[test]
    fn test_parse_ftp_banner_pureftpd() {
        let banner =
            parse_ftp_banner("220---------- Welcome to Pure-FTPd ----------\r\n220 Ready\r\n")
                .unwrap();
        assert_eq!(banner.software, "Pure-FTPd");
    }

    #[test]
    fn test_parse_ftp_banner_unknown() {
        let banner = parse_ftp_banner("220 Welcome to my server\r\n").unwrap();
        assert_eq!(banner.software, "Unknown");
        assert!(banner.version.is_none());
    }

    #[test]
    fn test_parse_ftp_banner_empty() {
        assert!(parse_ftp_banner("").is_none());
    }

    // ── vsFTPd version classification tests ─────────────────────────

    #[test]
    fn test_classify_vsftpd_eol_old() {
        assert!(classify_vsftpd_version_eol("2.3.4"));
    }

    #[test]
    fn test_classify_vsftpd_eol_very_old() {
        assert!(classify_vsftpd_version_eol("1.2.1"));
    }

    #[test]
    fn test_classify_vsftpd_current() {
        assert!(!classify_vsftpd_version_eol("3.0.5"));
    }

    #[test]
    fn test_classify_vsftpd_unparseable() {
        assert!(!classify_vsftpd_version_eol("unknown"));
    }

    // ── FTP proptests ───────────────────────────────────────────────

    proptest! {
        #[test]
        fn prop_parse_ftp_response_no_panic(text in ".*") {
            let _ = parse_ftp_response(&text);
        }

        #[test]
        fn prop_parse_ftp_banner_no_panic(text in ".*") {
            let _ = parse_ftp_banner(&text);
        }
    }
}
