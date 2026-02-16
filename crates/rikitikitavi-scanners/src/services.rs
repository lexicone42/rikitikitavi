use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Scanner;

/// Banner-grabbing services scanner — connects to common service ports,
/// reads banners, identifies versions, and performs protocol-level probes
/// (SSH key-exchange analysis, SMTP `EHLO`, FTP `FEAT`).
pub struct ServicesScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const BANNER_TIMEOUT: Duration = Duration::from_secs(5);

// ── SSH key-exchange analysis ────────────────────────────────────────

/// Weak SSH key-exchange algorithms that should be avoided.
const WEAK_KEX_ALGORITHMS: &[&str] = &[
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
];

/// Weak SSH ciphers (CBC mode, DES, RC4).
const WEAK_SSH_CIPHERS: &[&str] = &[
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "3des-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
];

/// Weak SSH MAC algorithms.
const WEAK_SSH_MACS: &[&str] = &["hmac-md5", "hmac-md5-96", "hmac-sha1-96"];

/// Parsed SSH `kex_init` algorithm lists.
#[derive(Debug, Default)]
pub struct SshKexInfo {
    pub kex_algorithms: Vec<String>,
    pub ciphers_client: Vec<String>,
    pub macs_client: Vec<String>,
    pub host_key_algorithms: Vec<String>,
}

/// Parse an SSH `kex_init` packet from raw bytes.
///
/// The SSH transport protocol sends `kex_init` (message type 20) after the
/// version exchange. Layout after the SSH packet header:
/// - 1 byte: message type (20)
/// - 16 bytes: cookie (random)
/// - Then 10 name-lists (uint32 length + comma-separated ASCII names)
pub fn parse_ssh_kex_init(data: &[u8]) -> Option<SshKexInfo> {
    // Find SSH_MSG_KEXINIT (type 20) in the packet data
    // Skip the 4-byte packet length + 1-byte padding length prefix
    let payload = if data.len() > 5 && data[5] == 20 {
        &data[5..]
    } else if !data.is_empty() && data[0] == 20 {
        data
    } else {
        return None;
    };

    // Skip message type (1) + cookie (16) = 17 bytes
    if payload.len() < 18 {
        return None;
    }

    let mut offset = 17;
    let mut lists = Vec::new();

    // Parse up to 4 name-lists (kex, host_key, ciphers_c2s, ciphers_s2c,
    // macs_c2s ...). We only need the first 5 to get kex, host_key, cipher_c2s, cipher_s2c, mac_c2s.
    for _ in 0..5 {
        if offset + 4 > payload.len() {
            break;
        }
        let len = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;
        if offset + len > payload.len() {
            break;
        }
        let names = String::from_utf8_lossy(&payload[offset..offset + len]);
        lists.push(
            names
                .split(',')
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<String>>(),
        );
        offset += len;
    }

    if lists.is_empty() {
        return None;
    }

    Some(SshKexInfo {
        kex_algorithms: lists.first().cloned().unwrap_or_default(),
        host_key_algorithms: lists.get(1).cloned().unwrap_or_default(),
        ciphers_client: lists.get(2).cloned().unwrap_or_default(),
        macs_client: lists.get(4).cloned().unwrap_or_default(),
    })
}

/// Classify weak SSH algorithms from a `kex_init` exchange.
pub fn classify_ssh_kex(ip: IpAddr, port: u16, info: &SshKexInfo) -> Vec<Finding> {
    let mut findings = Vec::new();

    let weak_kex: Vec<&str> = info
        .kex_algorithms
        .iter()
        .filter(|a| WEAK_KEX_ALGORITHMS.iter().any(|w| a.contains(w)))
        .map(String::as_str)
        .collect();

    if !weak_kex.is_empty() {
        findings.push(
            Finding::new(
                "services",
                &format!("Weak SSH key exchange on {ip}:{port}"),
                &format!(
                    "SSH server at {ip}:{port} offers weak key exchange algorithms: {}. \
                     These use SHA-1 or small DH groups vulnerable to downgrade attacks.",
                    weak_kex.join(", ")
                ),
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("SSH")
            .with_cwe("CWE-327"),
        );
    }

    let weak_ciphers: Vec<&str> = info
        .ciphers_client
        .iter()
        .filter(|a| WEAK_SSH_CIPHERS.iter().any(|w| a.contains(w)))
        .map(String::as_str)
        .collect();

    if !weak_ciphers.is_empty() {
        findings.push(
            Finding::new(
                "services",
                &format!("Weak SSH ciphers on {ip}:{port}"),
                &format!(
                    "SSH server at {ip}:{port} offers weak ciphers: {}. \
                     CBC-mode ciphers are vulnerable to padding oracle attacks \
                     (CVE-2008-5161).",
                    weak_ciphers.join(", ")
                ),
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("SSH")
            .with_cwe("CWE-327")
            .with_references(vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2008-5161".to_owned()
            ]),
        );
    }

    let weak_macs: Vec<&str> = info
        .macs_client
        .iter()
        .filter(|a| WEAK_SSH_MACS.iter().any(|w| a.contains(w)))
        .map(String::as_str)
        .collect();

    if !weak_macs.is_empty() {
        findings.push(
            Finding::new(
                "services",
                &format!("Weak SSH MACs on {ip}:{port}"),
                &format!(
                    "SSH server at {ip}:{port} offers weak MAC algorithms: {}. \
                     MD5-based and truncated MACs provide reduced integrity protection.",
                    weak_macs.join(", ")
                ),
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("SSH")
            .with_cwe("CWE-328"),
        );
    }

    findings
}

/// Probe SSH `kex_init` by connecting and reading the server's key exchange.
async fn probe_ssh_kex(ip: IpAddr, port: u16) -> Option<SshKexInfo> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Read version string first
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }

    // Send our version string to trigger kex_init
    let version = b"SSH-2.0-rikitikitavi_audit\r\n";
    tokio::time::timeout(BANNER_TIMEOUT, stream.write_all(version))
        .await
        .ok()?
        .ok()?;

    // Read kex_init response
    let mut kex_buf = vec![0u8; 8192];
    let kn = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut kex_buf))
        .await
        .ok()?
        .ok()?;
    if kn == 0 {
        return None;
    }

    parse_ssh_kex_init(&kex_buf[..kn])
}

// ── SMTP EHLO probe ─────────────────────────────────────────────────

/// Parsed SMTP `EHLO` response.
#[derive(Debug, Default)]
pub struct SmtpEhloInfo {
    pub supports_starttls: bool,
    pub supports_auth: bool,
    pub banner: String,
    pub extensions: Vec<String>,
}

/// Parse SMTP `EHLO` response lines.
pub fn parse_smtp_ehlo(response: &str) -> SmtpEhloInfo {
    let mut info = SmtpEhloInfo::default();

    for line in response.lines() {
        let lower = line.to_lowercase();
        // First line is the greeting banner (220 ...)
        if lower.starts_with("220") && info.banner.is_empty() {
            line.trim().clone_into(&mut info.banner);
            continue;
        }
        // EHLO responses start with 250
        if lower.starts_with("250") {
            // Strip "250-" or "250 " prefix
            let ext = if line.len() > 4 { line[4..].trim() } else { "" };
            if !ext.is_empty() {
                info.extensions.push(ext.to_owned());
            }
            if lower.contains("starttls") {
                info.supports_starttls = true;
            }
            if lower.contains("auth") {
                info.supports_auth = true;
            }
        }
    }

    info
}

/// Classify SMTP findings from an `EHLO` probe.
pub fn classify_smtp_ehlo(ip: IpAddr, port: u16, info: &SmtpEhloInfo) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !info.supports_starttls {
        findings.push(
            Finding::new(
                "services",
                &format!("SMTP without STARTTLS on {ip}:{port}"),
                &format!(
                    "SMTP server at {ip}:{port} does not advertise STARTTLS. \
                     Email sent through this server may be transmitted in cleartext. \
                     Banner: {}",
                    info.banner
                ),
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("SMTP")
            .with_cwe("CWE-319"),
        );
    }

    if !info.supports_auth {
        findings.push(
            Finding::new(
                "services",
                &format!("SMTP open relay risk on {ip}:{port}"),
                &format!(
                    "SMTP server at {ip}:{port} does not advertise AUTH extensions. \
                     Without authentication, this server may accept mail from anyone \
                     (open relay). Extensions: {}",
                    info.extensions.join(", ")
                ),
                Severity::High,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("SMTP")
            .with_cwe("CWE-284"),
        );
    }

    // Info finding with all details
    if !info.extensions.is_empty() {
        findings.push(
            Finding::new(
                "services",
                &format!("SMTP capabilities on {ip}:{port}"),
                &format!(
                    "SMTP EHLO extensions: {}. STARTTLS: {}, AUTH: {}. Banner: {}",
                    info.extensions.join(", "),
                    if info.supports_starttls { "yes" } else { "no" },
                    if info.supports_auth { "yes" } else { "no" },
                    info.banner
                ),
                Severity::Info,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("SMTP"),
        );
    }

    findings
}

/// Probe SMTP with `EHLO` to enumerate capabilities.
async fn probe_smtp_ehlo(ip: IpAddr, port: u16) -> Option<SmtpEhloInfo> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Read greeting
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let greeting = String::from_utf8_lossy(&buf[..n]).to_string();

    // Send EHLO
    let ehlo = "EHLO rikitikitavi.audit\r\n";
    tokio::time::timeout(BANNER_TIMEOUT, stream.write_all(ehlo.as_bytes()))
        .await
        .ok()?
        .ok()?;

    // Read EHLO response
    let en = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    // Send QUIT
    let _ = tokio::time::timeout(Duration::from_secs(1), stream.write_all(b"QUIT\r\n")).await;

    if en == 0 {
        return None;
    }
    let ehlo_response = String::from_utf8_lossy(&buf[..en]);
    let combined = format!("{greeting}{ehlo_response}");
    Some(parse_smtp_ehlo(&combined))
}

// ── FTP FEAT probe ──────────────────────────────────────────────────

/// Parsed FTP `FEAT` response.
#[derive(Debug, Default)]
pub struct FtpFeatInfo {
    pub banner: String,
    pub features: Vec<String>,
    pub supports_tls: bool,
    pub supports_utf8: bool,
}

/// Parse FTP `FEAT` response.
pub fn parse_ftp_feat(response: &str) -> FtpFeatInfo {
    let mut info = FtpFeatInfo::default();

    for line in response.lines() {
        let lower = line.to_lowercase();
        // 220 banner
        if lower.starts_with("220") && info.banner.is_empty() {
            line.trim().clone_into(&mut info.banner);
            continue;
        }
        // FEAT lines start with a space (inside 211-..211 block)
        if line.starts_with(' ') {
            let feat = line.trim().to_owned();
            let feat_lower = feat.to_lowercase();
            if feat_lower.contains("auth tls") || feat_lower.contains("auth ssl") {
                info.supports_tls = true;
            }
            if feat_lower.contains("utf8") {
                info.supports_utf8 = true;
            }
            if !feat.is_empty() {
                info.features.push(feat);
            }
        }
    }

    info
}

/// Classify FTP findings from a `FEAT` probe.
pub fn classify_ftp_feat(ip: IpAddr, port: u16, info: &FtpFeatInfo) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !info.supports_tls {
        findings.push(
            Finding::new(
                "services",
                &format!("FTP without TLS on {ip}:{port}"),
                &format!(
                    "FTP server at {ip}:{port} does not advertise AUTH TLS/SSL. \
                     Credentials and file transfers are sent in cleartext. \
                     Banner: {}",
                    info.banner
                ),
                Severity::High,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("FTP")
            .with_cwe("CWE-319"),
        );
    }

    if !info.features.is_empty() {
        findings.push(
            Finding::new(
                "services",
                &format!("FTP capabilities on {ip}:{port}"),
                &format!(
                    "FTP FEAT: {}. TLS: {}, UTF8: {}. Banner: {}",
                    info.features.join(", "),
                    if info.supports_tls { "yes" } else { "no" },
                    if info.supports_utf8 { "yes" } else { "no" },
                    info.banner
                ),
                Severity::Info,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("FTP"),
        );
    }

    findings
}

/// Probe FTP with `FEAT` to enumerate capabilities.
async fn probe_ftp_feat(ip: IpAddr, port: u16) -> Option<FtpFeatInfo> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Read greeting
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let greeting = String::from_utf8_lossy(&buf[..n]).to_string();

    // Send FEAT
    tokio::time::timeout(BANNER_TIMEOUT, stream.write_all(b"FEAT\r\n"))
        .await
        .ok()?
        .ok()?;

    // Read FEAT response
    let fn_ = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    // Send QUIT
    let _ = tokio::time::timeout(Duration::from_secs(1), stream.write_all(b"QUIT\r\n")).await;

    if fn_ == 0 {
        return None;
    }
    let feat_response = String::from_utf8_lossy(&buf[..fn_]);
    let combined = format!("{greeting}{feat_response}");
    Some(parse_ftp_feat(&combined))
}

/// Ports that send a banner immediately upon connection.
const BANNER_PORTS: &[u16] = &[21, 22, 23, 25, 110, 143, 3306, 5432, 6379];

/// Ports where we need to send an HTTP request to get a response.
const HTTP_PORTS: &[u16] = &[80, 8080, 8443, 8888];

/// Grab a banner from a TCP service that speaks first.
async fn grab_banner(ip: IpAddr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 1024];
    let mut stream = stream;
    let n = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n > 0 {
        Some(String::from_utf8_lossy(&buf[..n]).trim().to_owned())
    } else {
        None
    }
}

/// Grab an HTTP Server header.
async fn grab_http_server(ip: IpAddr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let request = format!("HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n");
    tokio::time::timeout(BANNER_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    let response = String::from_utf8_lossy(&buf[..n]);
    // Extract Server header (case-insensitive)
    for line in response.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("server:") {
            return Some(line[7..].trim().to_owned());
        }
    }
    None
}

/// Extract an OS guess from an SSH version banner.
///
/// Returns `None` for bare `OpenSSH` without OS suffix (too ambiguous).
fn parse_os_from_ssh_banner(banner: &str) -> Option<String> {
    let lower = banner.to_lowercase();
    if lower.contains("dropbear") {
        return Some("Linux (embedded)".to_owned());
    }
    // OpenSSH_X.Yp1 Debian-5+deb11u5 → extract deb version
    if lower.contains("debian") {
        if let Some(detail) = parse_debian_version(banner) {
            return Some(detail);
        }
        return Some("Linux (Debian)".to_owned());
    }
    // OpenSSH_X.Yp1 Ubuntu-3ubuntu0.4 → extract Ubuntu version from OpenSSH mapping
    if lower.contains("ubuntu") {
        if let Some(detail) = parse_ubuntu_version(banner) {
            return Some(detail);
        }
        return Some("Linux (Ubuntu)".to_owned());
    }
    // OpenSSH_X.Yp1 FreeBSD-20230316 → extract FreeBSD version
    if lower.contains("freebsd") {
        return Some("FreeBSD".to_owned());
    }
    None
}

/// OS fingerprint with optional EOL information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsFingerprint {
    /// Distro name + version (e.g. "Debian 11 Bullseye").
    pub display: String,
    /// EOL date if known (YYYY-MM-DD).
    pub eol_date: Option<&'static str>,
    /// Whether the distro is currently EOL.
    pub is_eol: bool,
}

/// Parse Debian version from SSH banner suffix.
///
/// Format: `Debian-N+debXXuY` where XX is the Debian major version.
/// Examples:
///   - `Debian-5+deb11u5` → Debian 11 Bullseye
///   - `Debian-2+deb12u1` → Debian 12 Bookworm
fn parse_debian_version(banner: &str) -> Option<String> {
    // Look for +deb\d+ pattern (the actual Debian version suffix, not "Debian" word)
    let lower = banner.to_lowercase();
    let deb_idx = lower.find("+deb")?;
    let after_deb = &lower[deb_idx + 4..];
    let version_str: String = after_deb.chars().take_while(char::is_ascii_digit).collect();
    let version: u32 = version_str.parse().ok()?;

    let (codename, eol) = debian_version_info(version);
    Some(codename.map_or_else(
        || format!("Linux (Debian {version})"),
        |name| format!("Linux (Debian {version} {name}, EOL: {eol})"),
    ))
}

/// Map Debian major version to codename and EOL date.
const fn debian_version_info(version: u32) -> (Option<&'static str>, &'static str) {
    match version {
        8 => (Some("Jessie"), "2020-06-30"),
        9 => (Some("Stretch"), "2022-07-01"),
        10 => (Some("Buster"), "2024-06-30"),
        11 => (Some("Bullseye"), "2026-06-30"),
        12 => (Some("Bookworm"), "2028-06-30"),
        13 => (Some("Trixie"), "2030-06-30"),
        _ => (None, "unknown"),
    }
}

/// Parse Ubuntu version from SSH banner. The SSH package version
/// encodes which Ubuntu release it belongs to.
///
/// We map the OpenSSH version bundled with each Ubuntu release:
///   - `OpenSSH_8.9p1` → Ubuntu 22.04 Jammy
///   - `OpenSSH_9.3p1` → Ubuntu 23.10 Mantic
///   - `OpenSSH_9.6p1` → Ubuntu 24.04 Noble
fn parse_ubuntu_version(banner: &str) -> Option<String> {
    // Extract the OpenSSH version to map to Ubuntu release
    let (major, minor) = extract_ssh_version(banner)?;
    let (release, codename, eol) = ubuntu_from_openssh(major, minor)?;
    Some(format!("Linux (Ubuntu {release} {codename}, EOL: {eol})"))
}

/// Map `OpenSSH` (major, minor) to Ubuntu release, codename, and EOL date.
///
/// Ubuntu ships specific `OpenSSH` versions with each release. This mapping
/// is not 100% precise (PPAs can override), but the combination of
/// `OpenSSH` version + "Ubuntu" in the banner makes it reliable.
const fn ubuntu_from_openssh(major: u32, minor: u32) -> Option<(&'static str, &'static str, &'static str)> {
    match (major, minor) {
        (7, 2) => Some(("18.04", "Bionic", "2028-04-30")),
        (7, 6) => Some(("18.10", "Cosmic", "2019-07-18")),
        (7, 9) => Some(("19.04", "Disco", "2020-01-23")),
        (8, 0) => Some(("19.10", "Eoan", "2020-07-17")),
        (8, 2) => Some(("20.04", "Focal", "2030-04-30")),
        (8, 4) => Some(("20.10", "Groovy", "2021-07-22")),
        (8, 6) => Some(("21.10", "Impish", "2022-07-14")),
        (8, 9) => Some(("22.04", "Jammy", "2032-04-30")),
        (9, 0) => Some(("22.10", "Kinetic", "2023-07-20")),
        (9, 3) => Some(("23.10", "Mantic", "2024-07-11")),
        (9, 6 | 7) => Some(("24.04", "Noble", "2034-04-30")),
        (9, 9) => Some(("24.10", "Oracular", "2025-07-10")),
        _ => None,
    }
}

/// Check whether an OS fingerprint from an SSH banner indicates an EOL distro,
/// and if so, generate a finding.
pub fn check_os_eol(ip: IpAddr, port: u16, banner: &str) -> Option<Finding> {
    let lower = banner.to_lowercase();

    // Debian: extract version from +deb\d+ pattern
    if lower.contains("debian") {
        let deb_idx = lower.find("+deb")?;
        let after_deb = &lower[deb_idx + 4..];
        let version_str: String = after_deb.chars().take_while(char::is_ascii_digit).collect();
        let version: u32 = version_str.parse().ok()?;

        let (codename, eol_date) = debian_version_info(version);
        if is_date_past(eol_date) {
            let name = codename.unwrap_or("unknown");
            return Some(
                Finding::new(
                    "services",
                    &format!("End-of-life OS on {ip}:{port}"),
                    &format!(
                        "SSH banner indicates Debian {version} {name} which reached end-of-life \
                         on {eol_date}. EOL operating systems receive no security patches. \
                         Banner: {banner}"
                    ),
                    Severity::High,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("SSH")
                .with_cwe("CWE-1104"),
            );
        }
        return None;
    }

    // Ubuntu: map OpenSSH version → release → EOL
    if lower.contains("ubuntu") {
        let (major, minor) = extract_ssh_version(banner)?;
        let (release, codename, eol_date) = ubuntu_from_openssh(major, minor)?;
        if is_date_past(eol_date) {
            return Some(
                Finding::new(
                    "services",
                    &format!("End-of-life OS on {ip}:{port}"),
                    &format!(
                        "SSH banner indicates Ubuntu {release} {codename} which reached \
                         end-of-life on {eol_date}. EOL operating systems receive no \
                         security patches. Banner: {banner}"
                    ),
                    Severity::High,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("SSH")
                .with_cwe("CWE-1104"),
            );
        }
        return None;
    }

    None
}

/// Check if a YYYY-MM-DD date is in the past.
fn is_date_past(date_str: &str) -> bool {
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let y: i32 = parts[0].parse().unwrap_or(9999);
    let m: u32 = parts[1].parse().unwrap_or(1);
    let d: u32 = parts[2].parse().unwrap_or(1);

    chrono::NaiveDate::from_ymd_opt(y, m, d).is_some_and(|eol| {
        eol < chrono::Utc::now().date_naive()
    })
}

/// Classify a banner finding based on the service and version info.
#[allow(clippy::too_many_lines)]
fn classify_banner(ip: IpAddr, port: u16, banner: &str) -> Option<Finding> {
    let banner_lower = banner.to_lowercase();

    // Redis — check for no-auth
    if port == 6379
        && banner_lower.contains("redis")
        && !banner_lower.contains("noauth")
        && !banner_lower.contains("err")
    {
        return Some(
            Finding::new(
                "services",
                &format!("Redis without authentication on {ip}:{port}"),
                &format!(
                    "Redis at {ip}:{port} responded without requiring authentication. \
                     Anyone on the network can read/write data. Banner: {banner}"
                ),
                Severity::Critical,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("Redis")
            .with_cwe("CWE-306")
            .with_opt_remediation(crate::remediation::get(
                "rikitikitavi.services.redis-no-auth",
                &[],
            )),
        );
    }

    // MySQL exposed
    if port == 3306 && banner_lower.contains("mysql") {
        return Some(
            Finding::new(
                "services",
                &format!("MySQL server exposed on {ip}:{port}"),
                &format!(
                    "MySQL is listening on the network at {ip}:{port}. \
                     Version info: {banner}"
                ),
                Severity::High,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("MySQL")
            .with_cwe("CWE-284")
            .with_opt_remediation(crate::remediation::get(
                "rikitikitavi.services.mysql-exposed",
                &[],
            )),
        );
    }

    // PostgreSQL exposed
    if port == 5432 {
        return Some(
            Finding::new(
                "services",
                &format!("PostgreSQL server exposed on {ip}:{port}"),
                &format!("PostgreSQL is listening on the network at {ip}:{port}."),
                Severity::High,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("PostgreSQL")
            .with_cwe("CWE-284")
            .with_opt_remediation(crate::remediation::get(
                "rikitikitavi.services.postgresql-exposed",
                &[],
            )),
        );
    }

    // SSH version disclosure
    if port == 22 && banner_lower.contains("ssh") {
        // Detect Dropbear SSH (common on embedded/IoT devices)
        if banner_lower.contains("dropbear") {
            let hint = DeviceHint::new()
                .with_device_type(DeviceType::IoT)
                .with_os_guess("Linux (embedded)");
            return Some(
                Finding::new(
                    "services",
                    &format!("Dropbear SSH on {ip}:{port} (embedded/IoT)"),
                    &format!(
                        "Dropbear SSH detected at {ip}:{port}. Dropbear is commonly used on \
                         embedded and IoT devices which may have default credentials or \
                         limited security update support. Banner: {banner}"
                    ),
                    Severity::Medium,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("SSH")
                .with_cwe("CWE-798")
                .with_opt_remediation(crate::remediation::get(
                    "rikitikitavi.services.dropbear-ssh",
                    &[],
                ))
                .with_device_hint(hint),
            );
        }

        // Full version-aware CVE analysis
        if let Some((major, minor)) = extract_ssh_version(banner) {
            let cves = check_openssh_cves(major, minor);
            if !cves.is_empty() {
                // Use the highest severity CVE for the finding
                let max_severity = cves
                    .iter()
                    .map(|c| c.2)
                    .max()
                    .unwrap_or(Severity::Low);

                let cve_list: Vec<String> = cves
                    .iter()
                    .map(|(id, desc, sev)| format!("{id} ({sev:?}): {desc}"))
                    .collect();

                let cve_ids: Vec<String> = cves
                    .iter()
                    .map(|(id, _, _)| (*id).to_owned())
                    .collect();

                let cve_refs: Vec<String> = cves
                    .iter()
                    .map(|(id, _, _)| format!("https://nvd.nist.gov/vuln/detail/{id}"))
                    .collect();

                let title = if max_severity >= Severity::High {
                    format!("Vulnerable OpenSSH on {ip}:{port}")
                } else {
                    format!("OpenSSH with known CVEs on {ip}:{port}")
                };

                let mut finding = Finding::new(
                    "services",
                    &title,
                    &format!(
                        "OpenSSH {major}.{minor} at {ip}:{port} is affected by {} known \
                         vulnerabilities:\n{}",
                        cves.len(),
                        cve_list.join("\n")
                    ),
                    max_severity,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("SSH")
                .with_cwe("CWE-1104")
                .with_cve_ids(cve_ids)
                .with_references(cve_refs)
                .with_evidence(banner);

                if max_severity >= Severity::High {
                    finding = finding.with_opt_remediation(crate::remediation::get(
                        "rikitikitavi.services.eol-openssh",
                        &[],
                    ));
                } else {
                    finding = finding.with_opt_remediation(crate::remediation::get(
                        "rikitikitavi.services.outdated-ssh",
                        &[],
                    ));
                }

                if let Some(os) = parse_os_from_ssh_banner(banner) {
                    finding = finding.with_device_hint(DeviceHint::new().with_os_guess(os));
                }

                return Some(finding);
            }
        }

        // No known CVEs — basic version disclosure
        let severity = if banner_lower.contains("openssh") {
            match extract_ssh_major_version(banner) {
                Some(v) if v < 7 => Severity::High,
                Some(v) if v < 8 => Severity::Medium,
                _ => Severity::Low,
            }
        } else {
            Severity::Low
        };

        let mut finding = Finding::new(
            "services",
            &format!("SSH version disclosure on {ip}:{port}"),
            &format!("SSH banner: {banner}"),
            severity,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("SSH");

        if let Some(os) = parse_os_from_ssh_banner(banner) {
            finding = finding.with_device_hint(DeviceHint::new().with_os_guess(os));
        }

        return Some(finding);
    }

    // FTP banner
    if port == 21 && banner_lower.contains("ftp") {
        return Some(
            Finding::new(
                "services",
                &format!("FTP service version disclosure on {ip}:{port}"),
                &format!("FTP banner: {banner}"),
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("FTP"),
        );
    }

    // Generic version disclosure for other services
    if !banner.is_empty() {
        return Some(
            Finding::new(
                "services",
                &format!("Service banner on {ip}:{port}"),
                &format!("Banner: {banner}"),
                Severity::Info,
            )
            .with_ip(ip)
            .with_port(port),
        );
    }

    None
}

/// Try to extract the major version number from an OpenSSH banner.
fn extract_ssh_major_version(banner: &str) -> Option<u32> {
    let (major, _) = extract_ssh_version(banner)?;
    Some(major)
}

/// Parsed `OpenSSH` version from a banner string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshVersion {
    pub major: u32,
    pub minor: u32,
    pub patch_label: String,
}

/// Extract full `OpenSSH` version (major, minor) from a banner.
///
/// Typical format: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4`
/// Returns `(major, minor)`.
fn extract_ssh_version(banner: &str) -> Option<(u32, u32)> {
    let lower = banner.to_lowercase();
    let idx = lower.find("openssh_")?;
    let rest = &banner[idx + 8..];
    let version_chunk: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let parts: Vec<&str> = version_chunk.split('.').collect();
    let major: u32 = parts.first()?.parse().ok()?;
    let minor: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    Some((major, minor))
}

/// Check an `OpenSSH` version for known CVEs.
///
/// Returns a list of `(CVE-ID, description, severity)` tuples for the given version.
pub fn check_openssh_cves(major: u32, minor: u32) -> Vec<(&'static str, &'static str, Severity)> {
    let mut cves = Vec::new();

    // CVE-2024-6387 "regreSSHion" — OpenSSH 8.5p1..9.7p1 (glibc-based Linux)
    // Signal handler race condition → unauthenticated RCE
    if (major == 8 && minor >= 5) || (major == 9 && minor <= 7) {
        cves.push((
            "CVE-2024-6387",
            "regreSSHion: signal handler race condition allowing unauthenticated \
             remote code execution on glibc-based Linux systems",
            Severity::Critical,
        ));
    }

    // CVE-2023-38408 — OpenSSH < 9.3p2, PKCS#11 remote code execution via forwarded agent
    if major < 9 || (major == 9 && minor < 3) {
        cves.push((
            "CVE-2023-38408",
            "PKCS#11 provider loading via forwarded ssh-agent allows remote code execution",
            Severity::High,
        ));
    }

    // CVE-2023-48795 "Terrapin" — OpenSSH < 9.6, prefix truncation attack on chacha20-poly1305
    if major < 9 || (major == 9 && minor < 6) {
        cves.push((
            "CVE-2023-48795",
            "Terrapin attack: prefix truncation on chacha20-poly1305 and \
             CBC-mode with encrypt-then-MAC allows message manipulation",
            Severity::Medium,
        ));
    }

    // CVE-2021-41617 — OpenSSH 6.2..8.7, privilege separation bypass
    if (major == 6 && minor >= 2) || major == 7 || (major == 8 && minor <= 7) {
        cves.push((
            "CVE-2021-41617",
            "AuthorizedKeysCommand/AuthorizedPrincipalsCommand privilege escalation \
             when run as a different user",
            Severity::Medium,
        ));
    }

    // CVE-2018-15473 — OpenSSH < 7.8, user enumeration
    if major < 7 || (major == 7 && minor < 8) {
        cves.push((
            "CVE-2018-15473",
            "User enumeration via malformed authentication request timing differences",
            Severity::Medium,
        ));
    }

    cves
}

// ── HTTP Server header version intelligence ─────────────────────────

/// Parsed version from a Server header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerVersion {
    /// Canonical product name (lowercase).
    pub product: String,
    /// Major version number.
    pub major: u32,
    /// Minor version number.
    pub minor: u32,
    /// Patch version number (0 if absent).
    pub patch: u32,
    /// Raw version string as reported.
    pub raw: String,
}

/// Parse an HTTP `Server` header into a structured product/version.
///
/// Handles common formats:
/// - `nginx/1.18.0`
/// - `Apache/2.4.41 (Ubuntu)`
/// - `lighttpd/1.4.55`
/// - `Microsoft-IIS/10.0`
/// - `MiniServ/1.950` (Webmin)
/// - `Jetty(9.4.31.v20200723)`
/// - `openresty/1.19.9.1`
pub fn parse_server_header(header: &str) -> Option<ServerVersion> {
    let trimmed = header.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Try product/version format (most common)
    if let Some((product, version_rest)) = trimmed.split_once('/') {
        let product_clean = product.trim().to_lowercase();
        if let Some(ver) = parse_version_numbers(version_rest) {
            return Some(ServerVersion {
                product: product_clean,
                major: ver.0,
                minor: ver.1,
                patch: ver.2,
                raw: trimmed.to_owned(),
            });
        }
    }

    // Try Jetty(version) format
    let lower = trimmed.to_lowercase();
    if lower.starts_with("jetty(") || lower.starts_with("jetty/") {
        let rest = &trimmed[6..];
        let version_part = rest.trim_end_matches(')');
        if let Some(ver) = parse_version_numbers(version_part) {
            return Some(ServerVersion {
                product: "jetty".to_owned(),
                major: ver.0,
                minor: ver.1,
                patch: ver.2,
                raw: trimmed.to_owned(),
            });
        }
    }

    None
}

/// Extract (major, minor, patch) from a version string like "1.18.0", "2.4.41 (Ubuntu)", "10.0".
fn parse_version_numbers(version: &str) -> Option<(u32, u32, u32)> {
    let cleaned: String = version
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();

    let parts: Vec<&str> = cleaned.split('.').collect();
    let major: u32 = parts.first()?.parse().ok()?;
    let minor: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch: u32 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    Some((major, minor, patch))
}

/// Known EOL / vulnerable server version ranges.
///
/// Returns `(severity, description, optional_cwe, optional_cve_refs)` if the version
/// is known-bad, or `None` if the version is acceptable/unknown.
#[allow(clippy::too_many_lines)]
pub fn check_server_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    match sv.product.as_str() {
        "nginx" => check_nginx_version(sv),
        "apache" => check_apache_version(sv),
        "lighttpd" => check_lighttpd_version(sv),
        "microsoft-iis" => check_iis_version(sv),
        "openresty" => check_openresty_version(sv),
        "mini_httpd" | "mini-httpd" | "minihttpd" => Some(ServerVersionIssue {
            severity: Severity::Medium,
            description: format!(
                "mini_httpd {} is lightweight embedded HTTP server often shipped \
                 with default configs and no security updates. Review if this is \
                 intentionally exposed.",
                sv.raw
            ),
            cwe: Some("CWE-1104"),
            cve_refs: Vec::new(),
        }),
        "miniserv" => check_miniserv_version(sv),
        "jetty" => check_jetty_version(sv),
        _ => None,
    }
}

/// Issue found for a specific server version.
#[derive(Debug, Clone)]
pub struct ServerVersionIssue {
    pub severity: Severity,
    pub description: String,
    pub cwe: Option<&'static str>,
    pub cve_refs: Vec<String>,
}

fn check_nginx_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    // nginx 1.24 is current stable (Apr 2023), 1.25 is mainline
    // Anything below 1.22 is EOL
    if sv.major == 1 && sv.minor < 22 {
        let mut refs = Vec::new();
        // nginx < 1.17.7 vulnerable to request smuggling (CVE-2019-20372)
        if sv.minor < 17 || (sv.minor == 17 && sv.patch < 7) {
            refs.push("https://nvd.nist.gov/vuln/detail/CVE-2019-20372".to_owned());
        }
        // nginx < 1.21.0 vulnerable to DNS resolver (CVE-2021-23017)
        if sv.minor < 21 {
            refs.push("https://nvd.nist.gov/vuln/detail/CVE-2021-23017".to_owned());
        }
        return Some(ServerVersionIssue {
            severity: if sv.minor < 18 {
                Severity::High
            } else {
                Severity::Medium
            },
            description: format!(
                "nginx {} is end-of-life. Current stable is 1.26.x. EOL versions \
                 do not receive security patches.",
                sv.raw
            ),
            cwe: Some("CWE-1104"),
            cve_refs: refs,
        });
    }
    None
}

fn check_apache_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    // Apache 2.4 is the only active branch; 2.2 EOL since 2017
    if sv.major == 2 && sv.minor <= 2 {
        let refs = vec!["https://nvd.nist.gov/vuln/detail/CVE-2017-9798".to_owned()];
        return Some(ServerVersionIssue {
            severity: Severity::High,
            description: format!(
                "Apache {} is end-of-life (2.2.x EOL since Dec 2017). Vulnerable to \
                 multiple known exploits including Optionsbleed (CVE-2017-9798). \
                 Upgrade to Apache 2.4.x.",
                sv.raw
            ),
            cwe: Some("CWE-1104"),
            cve_refs: refs,
        });
    }
    // Apache 2.4.x — check for known vulnerable patch levels
    if sv.major == 2 && sv.minor == 4 {
        let mut refs = Vec::new();
        // < 2.4.49: path traversal CVE-2021-41773 (only affects 2.4.49 with specific config,
        // but < 2.4.49 has other issues)
        // < 2.4.52: CVE-2021-44790 (mod_lua buffer overflow)
        if sv.patch < 52 {
            refs.push("https://nvd.nist.gov/vuln/detail/CVE-2021-44790".to_owned());
        }
        // < 2.4.54: CVE-2022-31813 (X-Forwarded-For bypass)
        if sv.patch < 54 {
            refs.push("https://nvd.nist.gov/vuln/detail/CVE-2022-31813".to_owned());
        }
        if !refs.is_empty() {
            return Some(ServerVersionIssue {
                severity: Severity::Medium,
                description: format!(
                    "Apache {} has known vulnerabilities. Current stable is 2.4.62+.",
                    sv.raw
                ),
                cwe: Some("CWE-1104"),
                cve_refs: refs,
            });
        }
    }
    None
}

fn check_lighttpd_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    // lighttpd 1.4.76+ is current; anything < 1.4.56 has CVE-2022-22707
    if sv.major == 1 && sv.minor == 4 && sv.patch < 56 {
        return Some(ServerVersionIssue {
            severity: Severity::Medium,
            description: format!(
                "lighttpd {} is outdated. Versions < 1.4.56 are vulnerable to \
                 CVE-2022-22707 (use-after-free). Current stable is 1.4.76+.",
                sv.raw
            ),
            cwe: Some("CWE-416"),
            cve_refs: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-22707".to_owned()],
        });
    }
    None
}

fn check_iis_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    // IIS 10.0 is current (Windows Server 2016+); IIS 7.5 → Server 2008 R2 (EOL)
    if sv.major < 8 {
        return Some(ServerVersionIssue {
            severity: Severity::High,
            description: format!(
                "IIS {} runs on an EOL Windows Server version. \
                 IIS 7.5 = Server 2008 R2 (EOL Jan 2020), \
                 IIS 7.0 = Server 2008 (EOL Jan 2020), \
                 IIS 6.0 = Server 2003 (EOL Jul 2015). \
                 No security patches are available.",
                sv.raw
            ),
            cwe: Some("CWE-1104"),
            cve_refs: Vec::new(),
        });
    }
    if sv.major == 8 {
        return Some(ServerVersionIssue {
            severity: Severity::Medium,
            description: format!(
                "IIS {} (Windows Server 2012) reached extended support end. \
                 Consider upgrading to a supported Windows Server version.",
                sv.raw
            ),
            cwe: Some("CWE-1104"),
            cve_refs: Vec::new(),
        });
    }
    None
}

fn check_openresty_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    // OpenResty bundles nginx; version correlates with nginx version
    // OpenResty < 1.19 bundles nginx < 1.19 which is EOL
    if sv.major == 1 && sv.minor < 19 {
        return Some(ServerVersionIssue {
            severity: Severity::Medium,
            description: format!(
                "OpenResty {} bundles an outdated nginx version. \
                 Current stable is 1.25.x. Upgrade to receive security patches.",
                sv.raw
            ),
            cwe: Some("CWE-1104"),
            cve_refs: Vec::new(),
        });
    }
    None
}

fn check_miniserv_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    // MiniServ is Webmin's HTTP server
    // Webmin < 1.990 vulnerable to CVE-2022-0824 (RCE)
    // Version format: MiniServ/1.950 (patch is really minor for Webmin)
    let webmin_version = sv.major * 1000 + sv.minor;
    if webmin_version < 1990 {
        return Some(ServerVersionIssue {
            severity: Severity::High,
            description: format!(
                "Webmin/MiniServ {} is outdated. Versions before 1.990 are vulnerable \
                 to CVE-2022-0824 (authenticated RCE). Current stable is 2.1+.",
                sv.raw
            ),
            cwe: Some("CWE-78"),
            cve_refs: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-0824".to_owned()],
        });
    }
    None
}

fn check_jetty_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    // Jetty 9.4.x is EOL (community support ended Jun 2023)
    // Jetty 10.0/11.0/12.0 are active
    if sv.major <= 9 {
        let mut refs = Vec::new();
        // Jetty < 9.4.51: CVE-2023-26048 (header overflow)
        if sv.major < 9 || (sv.major == 9 && sv.minor < 4)
            || (sv.major == 9 && sv.minor == 4 && sv.patch < 51)
        {
            refs.push("https://nvd.nist.gov/vuln/detail/CVE-2023-26048".to_owned());
        }
        return Some(ServerVersionIssue {
            severity: Severity::Medium,
            description: format!(
                "Jetty {} is end-of-life. The 9.x branch no longer receives \
                 security updates. Upgrade to Jetty 12.x.",
                sv.raw
            ),
            cwe: Some("CWE-1104"),
            cve_refs: refs,
        });
    }
    None
}

/// Classify an HTTP Server header with version intelligence.
///
/// Parses the Server header to extract product/version, then checks against
/// known EOL and vulnerable version databases. Returns a higher-severity
/// finding when the software version has known security issues.
fn classify_http_server(ip: IpAddr, port: u16, server: &str) -> Finding {
    if let Some(sv) = parse_server_header(server) {
        if let Some(issue) = check_server_version(&sv) {
            let mut finding = Finding::new(
                "services",
                &format!(
                    "Outdated {} on {ip}:{port}",
                    sv.product
                ),
                &issue.description,
                issue.severity,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP")
            .with_evidence(server);

            if let Some(cwe) = issue.cwe {
                finding = finding.with_cwe(cwe);
            }
            if !issue.cve_refs.is_empty() {
                finding = finding.with_references(issue.cve_refs);
            }

            return finding;
        }
    }

    // Fallback: plain version disclosure
    Finding::new(
        "services",
        &format!("HTTP server version disclosure on {ip}:{port}"),
        &format!("Server header: {server}"),
        Severity::Info,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service("HTTP")
}

/// Heuristic: is this port likely serving HTTP?
const fn is_likely_http_port(port: u16) -> bool {
    matches!(
        port,
        80 | 443
            | 3000
            | 5000
            | 8000
            | 8008
            | 8080
            | 8081
            | 8443
            | 8444
            | 8888
            | 8880
            | 9000
            | 9090
            | 9443
    )
}

/// Run deep protocol-specific probes on a port based on its well-known service.
async fn deep_probe(ip: IpAddr, port: u16) -> Vec<Finding> {
    match port {
        22 => probe_ssh_kex(ip, port)
            .await
            .map_or_else(Vec::new, |kex| classify_ssh_kex(ip, port, &kex)),
        25 | 587 => probe_smtp_ehlo(ip, port)
            .await
            .map_or_else(Vec::new, |ehlo| classify_smtp_ehlo(ip, port, &ehlo)),
        21 => probe_ftp_feat(ip, port)
            .await
            .map_or_else(Vec::new, |feat| classify_ftp_feat(ip, port, &feat)),
        _ => Vec::new(),
    }
}

#[async_trait]
impl Scanner for ServicesScanner {
    fn id(&self) -> &'static str {
        "services"
    }

    fn name(&self) -> &'static str {
        "Service Banner & Protocol Analysis"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[Perspective::Unauthenticated, Perspective::Authenticated, Perspective::Privileged]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running service banner scan");
        let mut findings = Vec::new();

        // ── Adaptive mode: use Phase 1 discovered devices ───────────
        if !ctx.discovered_devices.is_empty() {
            tracing::info!(
                device_count = ctx.discovered_devices.len(),
                "adaptive banner scan using discovered devices"
            );

            for device in &ctx.discovered_devices {
                let ip = device.ip;
                // Grab banners on all discovered open ports (not just hardcoded)
                for open_port in &device.open_ports {
                    let port = open_port.port;
                    if BANNER_PORTS.contains(&port) {
                        if let Some(banner) = grab_banner(ip, port).await {
                            if let Some(finding) = classify_banner(ip, port, &banner) {
                                findings.push(finding);
                            }
                            if let Some(os_finding) = check_os_eol(ip, port, &banner) {
                                findings.push(os_finding);
                            }
                        }
                        // Deep protocol probes for specific services
                        // (skipped in Passive mode for speed)
                        if ctx
                            .config
                            .intensity
                            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
                        {
                            findings.extend(deep_probe(ip, port).await);
                        }
                    } else if HTTP_PORTS.contains(&port) || is_likely_http_port(port) {
                        if let Some(server) = grab_http_server(ip, port).await {
                            findings.push(classify_http_server(ip, port, &server));
                        }
                    } else {
                        // Try banner grab on unknown ports too
                        if let Some(banner) = grab_banner(ip, port).await {
                            if let Some(finding) = classify_banner(ip, port, &banner) {
                                findings.push(finding);
                            }
                            if let Some(os_finding) = check_os_eol(ip, port, &banner) {
                                findings.push(os_finding);
                            }
                        }
                    }
                }
            }

            tracing::info!(
                findings_count = findings.len(),
                "adaptive banner scan complete"
            );
            return Ok(findings);
        }

        // ── Fallback: classic mode using ARP cache ──────────────────
        let arp_entries =
            rikitikitavi_network::read_arp_cache().map_err(|e| ScanError::ScannerFailed {
                scanner: "services".to_owned(),
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

        if targets.is_empty() {
            tracing::info!("no targets for banner grabbing");
            return Ok(Vec::new());
        }

        tracing::info!(target_count = targets.len(), "banner grabbing targets");

        for &ip in &targets {
            for &port in BANNER_PORTS {
                if let Some(banner) = grab_banner(ip, port).await {
                    if let Some(finding) = classify_banner(ip, port, &banner) {
                        findings.push(finding);
                    }
                    if let Some(os_finding) = check_os_eol(ip, port, &banner) {
                        findings.push(os_finding);
                    }
                }
            }

            for &port in HTTP_PORTS {
                if let Some(server) = grab_http_server(ip, port).await {
                    findings.push(classify_http_server(ip, port, &server));
                }
            }
        }

        tracing::info!(findings_count = findings.len(), "banner scan complete");
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        30
    }

    fn relevant_ports(&self) -> &[u16] {
        &[
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1883, 3389, 5900, 8080,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_extract_ssh_version() {
        assert_eq!(
            extract_ssh_major_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"),
            Some(8)
        );
        assert_eq!(extract_ssh_major_version("SSH-2.0-OpenSSH_7.4"), Some(7));
        assert_eq!(extract_ssh_major_version("SSH-2.0-OpenSSH_9.5"), Some(9));
        assert_eq!(extract_ssh_major_version("SSH-2.0-dropbear"), None);
    }

    #[test]
    fn test_parse_os_from_ssh_banner() {
        assert_eq!(
            parse_os_from_ssh_banner("SSH-2.0-dropbear_2020.81"),
            Some("Linux (embedded)".to_owned())
        );
        // Debian version extraction from deb11
        let debian_result = parse_os_from_ssh_banner("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1");
        assert!(debian_result.as_ref().is_some_and(|s| s.contains("Debian 11") && s.contains("Bullseye")));
        // Ubuntu version extraction from OpenSSH version mapping
        let ubuntu_result = parse_os_from_ssh_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4");
        assert!(ubuntu_result.as_ref().is_some_and(|s| s.contains("Ubuntu 22.04") && s.contains("Jammy")));
        assert_eq!(
            parse_os_from_ssh_banner("SSH-2.0-OpenSSH_9.0 FreeBSD-20230316"),
            Some("FreeBSD".to_owned())
        );
        // Bare OpenSSH — too ambiguous
        assert_eq!(parse_os_from_ssh_banner("SSH-2.0-OpenSSH_9.5"), None);
    }

    #[test]
    fn test_classify_ssh_banner_old() {
        let ip = "192.168.1.1".parse().unwrap();
        let finding = classify_banner(ip, 22, "SSH-2.0-OpenSSH_7.4").unwrap();
        // OpenSSH 7.4 now correctly flagged High (CVE-2023-38408 PKCS#11 RCE)
        assert!(finding.severity >= Severity::High);
        assert!(!finding.references.is_empty());
    }

    #[test]
    fn test_classify_ssh_banner_current() {
        let ip = "192.168.1.1".parse().unwrap();
        // Use 9.9 (latest) which has no known CVEs
        let finding = classify_banner(ip, 22, "SSH-2.0-OpenSSH_9.9").unwrap();
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn test_ssh_banner_debian_has_os_hint() {
        let ip = "192.168.1.10".parse().unwrap();
        let finding = classify_banner(ip, 22, "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1").unwrap();
        let hint = finding.device_hint.as_ref().unwrap();
        let os = hint.os_guess.as_deref().unwrap();
        assert!(os.contains("Debian 11"), "expected Debian 11, got: {os}");
        assert!(os.contains("Bullseye"), "expected Bullseye, got: {os}");
    }

    #[test]
    fn test_ssh_dropbear_has_iot_hint() {
        let ip = "192.168.1.20".parse().unwrap();
        let finding = classify_banner(ip, 22, "SSH-2.0-dropbear_2020.81").unwrap();
        let hint = finding.device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::IoT));
        assert_eq!(hint.os_guess.as_deref(), Some("Linux (embedded)"));
    }

    #[test]
    fn test_ssh_bare_openssh_no_hint() {
        let ip = "192.168.1.30".parse().unwrap();
        let finding = classify_banner(ip, 22, "SSH-2.0-OpenSSH_9.5").unwrap();
        assert!(finding.device_hint.is_none());
    }

    #[test]
    fn test_classify_redis_no_auth() {
        let ip = "192.168.1.50".parse().unwrap();
        let finding = classify_banner(ip, 6379, "+PONG\r\nredis_version:7.2.0").unwrap();
        // Contains "redis" and doesn't have "err" or "noauth" → Critical
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn test_classify_http_server_eol_nginx() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_http_server(ip, 80, "nginx/1.18.0");
        // nginx 1.18 is EOL → now correctly Medium+
        assert!(finding.severity >= Severity::Medium);
        assert_eq!(finding.scanner, "services");
        assert_eq!(finding.affected_port, Some(80));
        assert!(finding.cwe_id.is_some());
    }

    #[test]
    fn test_classify_http_server_current_nginx() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_http_server(ip, 80, "nginx/1.26.0");
        // Current version → Info disclosure only
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn test_classify_http_server_empty() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_http_server(ip, 8080, "");
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn test_classify_banner_mysql() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let finding = classify_banner(ip, 3306, "5.7.42-MySQL Community Server").unwrap();
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.affected_service.as_deref(), Some("MySQL"));
    }

    #[test]
    fn test_classify_banner_postgresql() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let finding = classify_banner(ip, 5432, "").unwrap();
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.affected_service.as_deref(), Some("PostgreSQL"));
    }

    #[test]
    fn test_classify_banner_ftp() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let finding = classify_banner(ip, 21, "220 ProFTPD 1.3.5 Server").unwrap();
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.affected_service.as_deref(), Some("FTP"));
    }

    #[test]
    fn test_classify_banner_generic() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let finding = classify_banner(ip, 25, "220 mail.local ESMTP").unwrap();
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn test_classify_banner_empty() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let finding = classify_banner(ip, 25, "");
        assert!(finding.is_none());
    }

    #[test]
    fn test_is_likely_http_port() {
        assert!(is_likely_http_port(80));
        assert!(is_likely_http_port(443));
        assert!(is_likely_http_port(8080));
        assert!(is_likely_http_port(3000));
        assert!(!is_likely_http_port(22));
        assert!(!is_likely_http_port(21));
        assert!(!is_likely_http_port(12345));
    }

    // ── SSH kex_init parsing tests ─────────────────────────────────

    /// Build a minimal SSH `kex_init` packet for testing.
    fn build_kex_init_packet(
        kex: &str,
        host_key: &str,
        cipher_c2s: &str,
        cipher_s2c: &str,
        mac_c2s: &str,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Packet length (placeholder) + padding length
        pkt.extend_from_slice(&[0, 0, 0, 0, 0]);
        // Message type 20 = SSH_MSG_KEXINIT
        pkt.push(20);
        // 16-byte cookie
        pkt.extend_from_slice(&[0u8; 16]);

        for list in [kex, host_key, cipher_c2s, cipher_s2c, mac_c2s] {
            let bytes = list.as_bytes();
            #[allow(clippy::cast_possible_truncation)] // test data, always small
            pkt.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            pkt.extend_from_slice(bytes);
        }
        pkt
    }

    #[test]
    fn test_parse_ssh_kex_init_weak_algorithms() {
        let pkt = build_kex_init_packet(
            "diffie-hellman-group1-sha1,curve25519-sha256",
            "ssh-rsa,ssh-ed25519",
            "aes128-cbc,aes256-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "hmac-md5,hmac-sha2-256",
        );
        let info = parse_ssh_kex_init(&pkt).unwrap();
        assert!(info
            .kex_algorithms
            .iter()
            .any(|a| a.contains("group1-sha1")));
        assert!(info.ciphers_client.iter().any(|a| a.contains("aes128-cbc")));
        assert!(info.macs_client.iter().any(|a| a.contains("hmac-md5")));
    }

    #[test]
    fn test_parse_ssh_kex_init_strong_only() {
        let pkt = build_kex_init_packet(
            "curve25519-sha256,diffie-hellman-group16-sha512",
            "ssh-ed25519",
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
            "chacha20-poly1305@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
        );
        let info = parse_ssh_kex_init(&pkt).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let findings = classify_ssh_kex(ip, 22, &info);
        assert!(
            findings.is_empty(),
            "strong algorithms should produce no findings"
        );
    }

    #[test]
    fn test_classify_ssh_kex_weak_kex() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let info = SshKexInfo {
            kex_algorithms: vec!["diffie-hellman-group1-sha1".to_owned()],
            ciphers_client: vec!["chacha20-poly1305@openssh.com".to_owned()],
            macs_client: vec!["hmac-sha2-256".to_owned()],
            host_key_algorithms: vec!["ssh-ed25519".to_owned()],
        };
        let findings = classify_ssh_kex(ip, 22, &info);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_classify_ssh_kex_weak_ciphers_and_macs() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let info = SshKexInfo {
            kex_algorithms: vec!["curve25519-sha256".to_owned()],
            ciphers_client: vec!["aes256-cbc".to_owned(), "3des-cbc".to_owned()],
            macs_client: vec!["hmac-md5".to_owned()],
            host_key_algorithms: vec!["ssh-rsa".to_owned()],
        };
        let findings = classify_ssh_kex(ip, 22, &info);
        assert_eq!(findings.len(), 2); // weak ciphers + weak MACs
    }

    #[test]
    fn test_parse_ssh_kex_init_too_short() {
        assert!(parse_ssh_kex_init(&[]).is_none());
        assert!(parse_ssh_kex_init(&[20; 10]).is_none());
    }

    // ── SMTP EHLO parsing tests ─────────────────────────────────────

    #[test]
    fn test_parse_smtp_ehlo_with_starttls() {
        let response = "220 mail.example.com ESMTP Postfix\r\n\
                         250-mail.example.com\r\n\
                         250-SIZE 52428800\r\n\
                         250-STARTTLS\r\n\
                         250-AUTH PLAIN LOGIN\r\n\
                         250 8BITMIME\r\n";
        let info = parse_smtp_ehlo(response);
        assert!(info.supports_starttls);
        assert!(info.supports_auth);
        assert!(info.banner.contains("Postfix"));
        assert!(!info.extensions.is_empty());
    }

    #[test]
    fn test_parse_smtp_ehlo_no_starttls() {
        let response = "220 oldmail.local SMTP\r\n\
                         250-oldmail.local\r\n\
                         250 SIZE 10485760\r\n";
        let info = parse_smtp_ehlo(response);
        assert!(!info.supports_starttls);
        assert!(!info.supports_auth);
    }

    #[test]
    fn test_classify_smtp_ehlo_insecure() {
        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        let info = SmtpEhloInfo {
            supports_starttls: false,
            supports_auth: false,
            banner: "220 mail ESMTP".to_owned(),
            extensions: vec!["SIZE 10485760".to_owned()],
        };
        let findings = classify_smtp_ehlo(ip, 25, &info);
        // No STARTTLS (Medium) + no AUTH (High) + info listing
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
        assert!(findings.iter().any(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn test_classify_smtp_ehlo_secure() {
        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        let info = SmtpEhloInfo {
            supports_starttls: true,
            supports_auth: true,
            banner: "220 mail ESMTP".to_owned(),
            extensions: vec!["STARTTLS".to_owned(), "AUTH PLAIN LOGIN".to_owned()],
        };
        let findings = classify_smtp_ehlo(ip, 25, &info);
        // Only the info listing
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    // ── FTP FEAT parsing tests ──────────────────────────────────────

    #[test]
    fn test_parse_ftp_feat_with_tls() {
        let response = "220 ProFTPD Server ready\r\n\
                         211-Features:\r\n \
                         AUTH TLS\r\n \
                         PBSZ\r\n \
                         PROT\r\n \
                         UTF8\r\n\
                         211 End\r\n";
        let info = parse_ftp_feat(response);
        assert!(info.supports_tls);
        assert!(info.supports_utf8);
        assert!(info.banner.contains("ProFTPD"));
    }

    #[test]
    fn test_parse_ftp_feat_no_tls() {
        let response = "220 vsftpd 3.0.3\r\n\
                         211-Features:\r\n \
                         PASV\r\n \
                         SIZE\r\n\
                         211 End\r\n";
        let info = parse_ftp_feat(response);
        assert!(!info.supports_tls);
        assert!(!info.supports_utf8);
    }

    #[test]
    fn test_classify_ftp_feat_no_tls() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let info = FtpFeatInfo {
            banner: "220 vsftpd".to_owned(),
            features: vec!["PASV".to_owned(), "SIZE".to_owned()],
            supports_tls: false,
            supports_utf8: false,
        };
        let findings = classify_ftp_feat(ip, 21, &info);
        assert_eq!(findings.len(), 2); // no-TLS (High) + info
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_classify_ftp_feat_with_tls() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let info = FtpFeatInfo {
            banner: "220 ProFTPD".to_owned(),
            features: vec!["AUTH TLS".to_owned(), "PBSZ".to_owned()],
            supports_tls: true,
            supports_utf8: false,
        };
        let findings = classify_ftp_feat(ip, 21, &info);
        // Only info listing
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    // ── Server header parsing tests ──────────────────────────────────

    #[test]
    fn test_parse_server_nginx() {
        let sv = parse_server_header("nginx/1.18.0").unwrap();
        assert_eq!(sv.product, "nginx");
        assert_eq!(sv.major, 1);
        assert_eq!(sv.minor, 18);
        assert_eq!(sv.patch, 0);
    }

    #[test]
    fn test_parse_server_apache_with_os() {
        let sv = parse_server_header("Apache/2.4.41 (Ubuntu)").unwrap();
        assert_eq!(sv.product, "apache");
        assert_eq!(sv.major, 2);
        assert_eq!(sv.minor, 4);
        assert_eq!(sv.patch, 41);
    }

    #[test]
    fn test_parse_server_iis() {
        let sv = parse_server_header("Microsoft-IIS/10.0").unwrap();
        assert_eq!(sv.product, "microsoft-iis");
        assert_eq!(sv.major, 10);
        assert_eq!(sv.minor, 0);
    }

    #[test]
    fn test_parse_server_lighttpd() {
        let sv = parse_server_header("lighttpd/1.4.55").unwrap();
        assert_eq!(sv.product, "lighttpd");
        assert_eq!(sv.major, 1);
        assert_eq!(sv.minor, 4);
        assert_eq!(sv.patch, 55);
    }

    #[test]
    fn test_parse_server_miniserv() {
        let sv = parse_server_header("MiniServ/1.950").unwrap();
        assert_eq!(sv.product, "miniserv");
        assert_eq!(sv.major, 1);
        assert_eq!(sv.minor, 950);
    }

    #[test]
    fn test_parse_server_openresty() {
        let sv = parse_server_header("openresty/1.19.9.1").unwrap();
        assert_eq!(sv.product, "openresty");
        assert_eq!(sv.major, 1);
        assert_eq!(sv.minor, 19);
        assert_eq!(sv.patch, 9);
    }

    #[test]
    fn test_parse_server_jetty_parens() {
        let sv = parse_server_header("Jetty(9.4.31.v20200723)").unwrap();
        assert_eq!(sv.product, "jetty");
        assert_eq!(sv.major, 9);
        assert_eq!(sv.minor, 4);
        assert_eq!(sv.patch, 31);
    }

    #[test]
    fn test_parse_server_empty() {
        assert!(parse_server_header("").is_none());
    }

    #[test]
    fn test_parse_server_no_version() {
        assert!(parse_server_header("cloudflare").is_none());
    }

    #[test]
    fn test_parse_server_bare_product_slash() {
        // e.g. "AkamaiGHost/" — no version digits
        assert!(parse_server_header("AkamaiGHost/").is_none());
    }

    // ── Server version checks ─────────────────────────────────────────

    #[test]
    fn test_check_nginx_eol() {
        let sv = parse_server_header("nginx/1.16.1").unwrap();
        let issue = check_server_version(&sv).unwrap();
        assert_eq!(issue.severity, Severity::High);
        assert!(!issue.cve_refs.is_empty());
    }

    #[test]
    fn test_check_nginx_recent_eol() {
        let sv = parse_server_header("nginx/1.20.2").unwrap();
        let issue = check_server_version(&sv).unwrap();
        assert_eq!(issue.severity, Severity::Medium);
    }

    #[test]
    fn test_check_nginx_current() {
        let sv = parse_server_header("nginx/1.26.0").unwrap();
        assert!(check_server_version(&sv).is_none());
    }

    #[test]
    fn test_check_apache_22_eol() {
        let sv = parse_server_header("Apache/2.2.34").unwrap();
        let issue = check_server_version(&sv).unwrap();
        assert_eq!(issue.severity, Severity::High);
    }

    #[test]
    fn test_check_apache_24_outdated() {
        let sv = parse_server_header("Apache/2.4.41").unwrap();
        let issue = check_server_version(&sv).unwrap();
        assert_eq!(issue.severity, Severity::Medium);
        assert!(!issue.cve_refs.is_empty());
    }

    #[test]
    fn test_check_apache_24_current() {
        let sv = parse_server_header("Apache/2.4.62").unwrap();
        assert!(check_server_version(&sv).is_none());
    }

    #[test]
    fn test_check_iis_6_eol() {
        let sv = parse_server_header("Microsoft-IIS/6.0").unwrap();
        let issue = check_server_version(&sv).unwrap();
        assert_eq!(issue.severity, Severity::High);
    }

    #[test]
    fn test_check_iis_10_current() {
        let sv = parse_server_header("Microsoft-IIS/10.0").unwrap();
        assert!(check_server_version(&sv).is_none());
    }

    #[test]
    fn test_check_lighttpd_vulnerable() {
        let sv = parse_server_header("lighttpd/1.4.48").unwrap();
        let issue = check_server_version(&sv).unwrap();
        assert_eq!(issue.severity, Severity::Medium);
        assert!(!issue.cve_refs.is_empty());
    }

    #[test]
    fn test_check_lighttpd_patched() {
        let sv = parse_server_header("lighttpd/1.4.76").unwrap();
        assert!(check_server_version(&sv).is_none());
    }

    #[test]
    fn test_check_miniserv_vulnerable() {
        let sv = parse_server_header("MiniServ/1.950").unwrap();
        let issue = check_server_version(&sv).unwrap();
        assert_eq!(issue.severity, Severity::High);
    }

    #[test]
    fn test_check_miniserv_patched() {
        let sv = parse_server_header("MiniServ/2.100").unwrap();
        assert!(check_server_version(&sv).is_none());
    }

    #[test]
    fn test_check_jetty_eol() {
        let sv = parse_server_header("Jetty(9.4.31.v20200723)").unwrap();
        let issue = check_server_version(&sv).unwrap();
        assert_eq!(issue.severity, Severity::Medium);
    }

    #[test]
    fn test_check_jetty_current() {
        let sv = parse_server_header("Jetty(12.0.3)").unwrap();
        assert!(check_server_version(&sv).is_none());
    }

    #[test]
    fn test_check_openresty_eol() {
        let sv = parse_server_header("openresty/1.17.8.2").unwrap();
        let issue = check_server_version(&sv).unwrap();
        assert_eq!(issue.severity, Severity::Medium);
    }

    // ── classify_http_server integration tests ────────────────────────

    #[test]
    fn test_classify_http_server_nginx_eol() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_http_server(ip, 80, "nginx/1.14.2");
        assert!(finding.severity >= Severity::Medium);
        assert!(finding.cwe_id.is_some());
    }

    #[test]
    fn test_classify_http_server_unknown_product() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_http_server(ip, 80, "SynoHTTP/1.0");
        // Unknown product → plain version disclosure (Info)
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn test_classify_http_server_no_version() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_http_server(ip, 80, "cloudflare");
        assert_eq!(finding.severity, Severity::Info);
    }

    // ── SSH version extraction tests ──────────────────────────────────

    #[test]
    fn test_extract_ssh_version_full() {
        assert_eq!(
            extract_ssh_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"),
            Some((8, 9))
        );
        assert_eq!(extract_ssh_version("SSH-2.0-OpenSSH_7.4"), Some((7, 4)));
        assert_eq!(extract_ssh_version("SSH-2.0-OpenSSH_9.5"), Some((9, 5)));
        assert_eq!(extract_ssh_version("SSH-2.0-OpenSSH_9.6"), Some((9, 6)));
    }

    #[test]
    fn test_extract_ssh_version_non_openssh() {
        assert_eq!(extract_ssh_version("SSH-2.0-dropbear_2020.81"), None);
    }

    // ── OpenSSH CVE checks ────────────────────────────────────────────

    #[test]
    fn test_openssh_cves_regresshion() {
        let cves = check_openssh_cves(9, 7);
        assert!(cves.iter().any(|(id, _, _)| *id == "CVE-2024-6387"));
    }

    #[test]
    fn test_openssh_cves_9_8_no_regresshion() {
        let cves = check_openssh_cves(9, 8);
        assert!(!cves.iter().any(|(id, _, _)| *id == "CVE-2024-6387"));
    }

    #[test]
    fn test_openssh_cves_8_4_no_regresshion() {
        // regreSSHion only affects 8.5+
        let cves = check_openssh_cves(8, 4);
        assert!(!cves.iter().any(|(id, _, _)| *id == "CVE-2024-6387"));
    }

    #[test]
    fn test_openssh_cves_terrapin() {
        let cves = check_openssh_cves(9, 5);
        assert!(cves.iter().any(|(id, _, _)| *id == "CVE-2023-48795"));
    }

    #[test]
    fn test_openssh_cves_9_6_no_terrapin() {
        let cves = check_openssh_cves(9, 6);
        assert!(!cves.iter().any(|(id, _, _)| *id == "CVE-2023-48795"));
    }

    #[test]
    fn test_openssh_cves_user_enum() {
        let cves = check_openssh_cves(7, 4);
        assert!(cves.iter().any(|(id, _, _)| *id == "CVE-2018-15473"));
    }

    #[test]
    fn test_openssh_cves_7_8_no_user_enum() {
        let cves = check_openssh_cves(7, 8);
        assert!(!cves.iter().any(|(id, _, _)| *id == "CVE-2018-15473"));
    }

    #[test]
    fn test_openssh_cves_latest_clean() {
        // OpenSSH 9.9 should have no CVEs in our database
        let cves = check_openssh_cves(9, 9);
        assert!(cves.is_empty(), "expected no CVEs for 9.9, got: {cves:?}");
    }

    #[test]
    fn test_classify_ssh_banner_with_cves() {
        let ip = "192.168.1.1".parse().unwrap();
        let finding = classify_banner(ip, 22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4").unwrap();
        // OpenSSH 8.9 has regreSSHion (Critical), Terrapin, PKCS#11
        assert!(finding.severity >= Severity::High);
        assert!(!finding.references.is_empty());
    }

    #[test]
    fn test_classify_ssh_banner_9_6_has_regresshion() {
        let ip = "192.168.1.1".parse().unwrap();
        let finding = classify_banner(ip, 22, "SSH-2.0-OpenSSH_9.6").unwrap();
        // 9.6 is in the regreSSHion range (8.5..9.7) → Critical
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.references.iter().any(|r| r.contains("CVE-2024-6387")));
    }

    #[test]
    fn test_classify_ssh_banner_9_8_clean() {
        let ip = "192.168.1.1".parse().unwrap();
        let finding = classify_banner(ip, 22, "SSH-2.0-OpenSSH_9.8").unwrap();
        // 9.8 is patched for all known CVEs → Low (simple disclosure)
        assert_eq!(finding.severity, Severity::Low);
    }

    // ── OS fingerprinting and EOL detection ────────────────────────────

    #[test]
    fn test_parse_debian_version() {
        let result = parse_debian_version("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u5");
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("Debian 11"));
        assert!(s.contains("Bullseye"));
        assert!(s.contains("2026-06-30"));
    }

    #[test]
    fn test_parse_debian_version_bookworm() {
        let result = parse_debian_version("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3");
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("Debian 12"));
        assert!(s.contains("Bookworm"));
    }

    #[test]
    fn test_parse_ubuntu_version() {
        let result = parse_ubuntu_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4");
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("Ubuntu 22.04"));
        assert!(s.contains("Jammy"));
    }

    #[test]
    fn test_check_os_eol_debian_buster() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // Debian 10 Buster is EOL
        let finding = check_os_eol(ip, 22, "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4");
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.title.contains("End-of-life OS"));
        assert!(f.description.contains("Debian 10"));
    }

    #[test]
    fn test_check_os_eol_debian_bullseye_not_eol() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // Debian 11 Bullseye EOL is June 2026 — still alive as of Feb 2026
        let finding = check_os_eol(ip, 22, "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u5");
        assert!(finding.is_none());
    }

    #[test]
    fn test_check_os_eol_ubuntu_cosmic_eol() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // Ubuntu 18.10 Cosmic is EOL (2019-07-18)
        let finding = check_os_eol(ip, 22, "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3");
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.description.contains("Ubuntu 18.10"));
    }

    #[test]
    fn test_check_os_eol_ubuntu_noble_not_eol() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // Ubuntu 24.04 Noble EOL is 2034
        let finding = check_os_eol(ip, 22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5");
        assert!(finding.is_none());
    }

    #[test]
    fn test_check_os_eol_no_os_info() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // Bare OpenSSH — no OS info
        let finding = check_os_eol(ip, 22, "SSH-2.0-OpenSSH_9.5");
        assert!(finding.is_none());
    }

    #[test]
    fn test_debian_version_info() {
        let (name, eol) = debian_version_info(11);
        assert_eq!(name, Some("Bullseye"));
        assert_eq!(eol, "2026-06-30");
    }

    #[test]
    fn test_ubuntu_from_openssh() {
        assert_eq!(
            ubuntu_from_openssh(8, 9),
            Some(("22.04", "Jammy", "2032-04-30"))
        );
        assert_eq!(
            ubuntu_from_openssh(9, 6),
            Some(("24.04", "Noble", "2034-04-30"))
        );
        assert_eq!(ubuntu_from_openssh(10, 0), None);
    }

    #[test]
    fn test_is_date_past() {
        assert!(is_date_past("2020-01-01"));
        assert!(!is_date_past("2099-12-31"));
        assert!(!is_date_past("invalid"));
    }

    proptest! {
        /// classify_http_server never panics on arbitrary strings
        #[test]
        fn prop_classify_http_server_no_panic(server in ".*") {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = classify_http_server(ip, 80, &server);
        }

        /// classify_banner never panics on arbitrary strings
        #[test]
        fn prop_classify_banner_no_panic(banner in ".*", port in 1_u16..=65535_u16) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = classify_banner(ip, port, &banner);
        }

        /// extract_ssh_major_version never panics on arbitrary strings
        #[test]
        fn prop_extract_ssh_version_no_panic(banner in ".*") {
            let _ = extract_ssh_major_version(&banner);
        }

        /// `parse_server_header` never panics on arbitrary strings
        #[test]
        fn prop_parse_server_header_no_panic(header in ".*") {
            let _ = parse_server_header(&header);
        }

        /// `check_openssh_cves` never panics on any version
        #[test]
        fn prop_check_openssh_cves_no_panic(major in 0_u32..100_u32, minor in 0_u32..100_u32) {
            let _ = check_openssh_cves(major, minor);
        }

        /// `parse_ssh_kex_init` never panics on arbitrary bytes
        #[test]
        fn prop_parse_ssh_kex_init_no_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_ssh_kex_init(&data);
        }

        /// `parse_smtp_ehlo` never panics on arbitrary strings
        #[test]
        fn prop_parse_smtp_ehlo_no_panic(response in ".*") {
            let _ = parse_smtp_ehlo(&response);
        }

        /// `parse_ftp_feat` never panics on arbitrary strings
        #[test]
        fn prop_parse_ftp_feat_no_panic(response in ".*") {
            let _ = parse_ftp_feat(&response);
        }

        /// `check_os_eol` never panics on arbitrary banners
        #[test]
        fn prop_check_os_eol_no_panic(banner in ".*", port in 1_u16..=65535_u16) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = check_os_eol(ip, port, &banner);
        }

        /// `parse_os_from_ssh_banner` never panics on arbitrary strings
        #[test]
        fn prop_parse_os_from_ssh_banner_no_panic(banner in ".*") {
            let _ = parse_os_from_ssh_banner(&banner);
        }
    }
}
