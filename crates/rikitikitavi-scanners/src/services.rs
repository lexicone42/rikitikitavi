use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
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
const WEAK_SSH_MACS: &[&str] = &[
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1-96",
];

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
                "https://nvd.nist.gov/vuln/detail/CVE-2008-5161".to_owned(),
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
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        stream.write_all(b"QUIT\r\n"),
    )
    .await;

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
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        stream.write_all(b"QUIT\r\n"),
    )
    .await;

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

/// Classify a banner finding based on the service and version info.
#[allow(clippy::too_many_lines)]
fn classify_banner(ip: IpAddr, port: u16, banner: &str) -> Option<Finding> {
    let banner_lower = banner.to_lowercase();

    // Redis — check for no-auth
    if port == 6379 && banner_lower.contains("redis")
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
            .with_opt_remediation(crate::remediation::get("rikitikitavi.services.redis-no-auth", &[])),
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
            .with_opt_remediation(crate::remediation::get("rikitikitavi.services.mysql-exposed", &[])),
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
            .with_opt_remediation(crate::remediation::get("rikitikitavi.services.postgresql-exposed", &[])),
        );
    }

    // SSH version disclosure
    if port == 22 && banner_lower.contains("ssh") {
        // Detect Dropbear SSH (common on embedded/IoT devices)
        if banner_lower.contains("dropbear") {
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
                .with_opt_remediation(crate::remediation::get("rikitikitavi.services.dropbear-ssh", &[])),
            );
        }

        let severity = if banner_lower.contains("openssh") {
            match extract_ssh_major_version(banner) {
                Some(v) if v < 7 => Severity::High,
                Some(v) if v < 8 => Severity::Medium,
                _ => Severity::Low,
            }
        } else {
            Severity::Low
        };

        let title = match severity {
            Severity::High => format!("EOL OpenSSH version on {ip}:{port}"),
            Severity::Medium => format!("Outdated SSH version on {ip}:{port}"),
            _ => format!("SSH version disclosure on {ip}:{port}"),
        };

        let description = match severity {
            Severity::High => format!(
                "OpenSSH < 7.0 detected at {ip}:{port}. This version is end-of-life and \
                 vulnerable to CVE-2018-15473 (user enumeration) and other known issues. \
                 Banner: {banner}"
            ),
            _ => format!("SSH banner: {banner}"),
        };

        let mut finding = Finding::new("services", &title, &description, severity)
            .with_ip(ip)
            .with_port(port)
            .with_service("SSH");

        if severity == Severity::High {
            finding = finding
                .with_cwe("CWE-200")
                .with_references(vec!["https://nvd.nist.gov/vuln/detail/CVE-2018-15473".to_owned()])
                .with_opt_remediation(crate::remediation::get("rikitikitavi.services.eol-openssh", &[]));
        } else if severity == Severity::Medium {
            finding = finding.with_opt_remediation(crate::remediation::get("rikitikitavi.services.outdated-ssh", &[]));
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
    // Typical: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
    let lower = banner.to_lowercase();
    let idx = lower.find("openssh_")?;
    let rest = &banner[idx + 8..];
    let version_str: String = rest.chars().take_while(char::is_ascii_digit).collect();
    version_str.parse().ok()
}

/// Classify an HTTP Server header.
fn classify_http_server(ip: IpAddr, port: u16, server: &str) -> Finding {
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
        80 | 443 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8443 | 8444 | 8888 | 8880
            | 9000 | 9090 | 9443
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
        &[Perspective::Authenticated, Perspective::Privileged]
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
                        }
                        // Deep protocol probes for specific services
                        // (skipped in Passive mode for speed)
                        if ctx.config.intensity.at_least(
                            rikitikitavi_models::config::ScanIntensity::Active,
                        ) {
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
                        }
                    }
                }
            }

            tracing::info!(findings_count = findings.len(), "adaptive banner scan complete");
            return Ok(findings);
        }

        // ── Fallback: classic mode using ARP cache ──────────────────
        let arp_entries = rikitikitavi_network::read_arp_cache().map_err(|e| {
            ScanError::ScannerFailed {
                scanner: "services".to_owned(),
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
        &[21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1883, 3389, 5900, 8080]
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
    fn test_classify_ssh_banner_old() {
        let ip = "192.168.1.1".parse().unwrap();
        let finding = classify_banner(ip, 22, "SSH-2.0-OpenSSH_7.4").unwrap();
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn test_classify_ssh_banner_current() {
        let ip = "192.168.1.1".parse().unwrap();
        let finding = classify_banner(ip, 22, "SSH-2.0-OpenSSH_9.5").unwrap();
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn test_classify_redis_no_auth() {
        let ip = "192.168.1.50".parse().unwrap();
        let finding =
            classify_banner(ip, 6379, "+PONG\r\nredis_version:7.2.0").unwrap();
        // Contains "redis" and doesn't have "err" or "noauth" → Critical
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn test_classify_http_server_info() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_http_server(ip, 80, "nginx/1.18.0");
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.scanner, "services");
        assert_eq!(finding.affected_port, Some(80));
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
        assert!(info.kex_algorithms.iter().any(|a| a.contains("group1-sha1")));
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
        assert!(findings.is_empty(), "strong algorithms should produce no findings");
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
    }
}
