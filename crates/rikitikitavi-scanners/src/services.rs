use async_trait::async_trait;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::config::ExclusionSet;
use rikitikitavi_models::{
    Device, DeviceHint, DeviceType, Finding, MacAddr, Remediation, ScanContext,
};
use rikitikitavi_network::ArpEntry;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Scanner;
use crate::eol_db;
use crate::recog;
use crate::recog_db::RecogKey;

/// Service banner scanner: banner grabs, HTTP `Server` header version checks,
/// and protocol probes (SSH `kex_init`, SMTP `EHLO`, FTP `FEAT`).
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

/// Parse an SSH `kex_init` packet (message type 20).
///
/// Layout: [4] packet length, [1] padding length, [1] type=20, [16] cookie,
/// then name-lists (u32 BE length + comma-separated names).
pub fn parse_ssh_kex_init(data: &[u8]) -> Option<SshKexInfo> {
    let payload = if data.len() > 5 && data[5] == 20 {
        &data[5..]
    } else if !data.is_empty() && data[0] == 20 {
        data
    } else {
        return None;
    };

    if payload.len() < 18 {
        return None;
    }

    let mut offset = 17;
    let mut lists = Vec::new();

    // First 5 name-lists: kex, host_key, enc_c2s, enc_s2c, mac_c2s.
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
        let Some(end) = offset.checked_add(len).filter(|&end| end <= payload.len()) else {
            break;
        };
        let names = String::from_utf8_lossy(&payload[offset..end]);
        lists.push(
            names
                .split(',')
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<String>>(),
        );
        offset = end;
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
            .with_references(refs!["https://nvd.nist.gov/vuln/detail/CVE-2008-5161"]),
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

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }

    let version = b"SSH-2.0-rikitikitavi_audit\r\n";
    tokio::time::timeout(BANNER_TIMEOUT, stream.write_all(version))
        .await
        .ok()?
        .ok()?;

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
        if lower.starts_with("220") && info.banner.is_empty() {
            line.trim().clone_into(&mut info.banner);
            continue;
        }
        if lower.starts_with("250") {
            let ext = line.get(4..).map_or("", str::trim);
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

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let greeting = String::from_utf8_lossy(&buf[..n]).to_string();

    let ehlo = "EHLO rikitikitavi.audit\r\n";
    tokio::time::timeout(BANNER_TIMEOUT, stream.write_all(ehlo.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let en = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

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
        if lower.starts_with("220") && info.banner.is_empty() {
            line.trim().clone_into(&mut info.banner);
            continue;
        }
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

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let greeting = String::from_utf8_lossy(&buf[..n]).to_string();

    tokio::time::timeout(BANNER_TIMEOUT, stream.write_all(b"FEAT\r\n"))
        .await
        .ok()?
        .ok()?;

    let fn_ = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    let _ = tokio::time::timeout(Duration::from_secs(1), stream.write_all(b"QUIT\r\n")).await;

    if fn_ == 0 {
        return None;
    }
    let feat_response = String::from_utf8_lossy(&buf[..fn_]);
    let combined = format!("{greeting}{feat_response}");
    Some(parse_ftp_feat(&combined))
}

/// First line of a banner, whitespace trimmed.
fn first_line(banner: &str) -> &str {
    banner.lines().next().unwrap_or("").trim()
}

/// Strip an FTP/SMTP three-digit reply code and its `\x20` or `-` separator.
///
/// Recog's `ftp.banner` and `smtp.banner` patterns match the greeting text, not
/// the reply code, so a banner that keeps the code matches nothing.
fn strip_reply_code(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let code = bytes.first_chunk::<3>()?;
    if !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if !matches!(bytes.get(3), Some(b' ' | b'-')) {
        return None;
    }
    Some(line.get(4..)?.trim())
}

/// Strip a POP3 or IMAP status indicator, which Recog's patterns also omit.
fn strip_status<'a>(line: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    prefixes.iter().find_map(|prefix| {
        line.get(..prefix.len())
            .filter(|head| head.eq_ignore_ascii_case(prefix))
            .and_then(|_| line.get(prefix.len()..))
            .map(str::trim)
    })
}

/// Identify a raw TCP banner with the Recog fingerprint tables.
///
/// The key follows the banner, not only the port: an SSH identification string
/// is an SSH identification string wherever it is listening. Each table expects
/// the greeting with its protocol status prefix already removed.
fn recog_banner(ip: IpAddr, port: u16, banner: &str) -> Option<Finding> {
    if let Some(software) = recog::ssh_software(banner) {
        return recog::identify_finding("services", ip, Some(port), RecogKey::SshBanner, software);
    }
    let (key, body) = match port {
        21 => (RecogKey::FtpBanner, strip_reply_code(first_line(banner))?),
        23 => (RecogKey::TelnetBanner, banner.trim()),
        25 => (RecogKey::SmtpBanner, strip_reply_code(first_line(banner))?),
        110 => (
            RecogKey::PopBanner,
            strip_status(first_line(banner), &["+OK ", "-ERR "])?,
        ),
        143 => (
            RecogKey::ImapBanner,
            strip_status(first_line(banner), &["* OK ", "* PREAUTH "])?,
        ),
        _ => return None,
    };
    recog::identify_finding("services", ip, Some(port), key, body)
}

/// Ports that send a banner immediately upon connection.
const BANNER_PORTS: &[u16] = &[21, 22, 23, 25, 110, 143, 3306, 5432, 6379, 53282];

/// Ports probed with an HTTP `HEAD` request.
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
    for line in response.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("server:") {
            return Some(line[7..].trim().to_owned());
        }
    }
    None
}

/// OS guess from an SSH banner suffix; `None` for bare `OpenSSH`.
fn parse_os_from_ssh_banner(banner: &str) -> Option<String> {
    let lower = banner.to_lowercase();
    if lower.contains("dropbear") {
        return Some("Linux (embedded)".to_owned());
    }
    if lower.contains("debian") {
        if let Some(detail) = parse_debian_version(banner) {
            return Some(detail);
        }
        return Some("Linux (Debian)".to_owned());
    }
    if lower.contains("ubuntu") {
        if let Some(detail) = parse_ubuntu_version(banner) {
            return Some(detail);
        }
        return Some("Linux (Ubuntu)".to_owned());
    }
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

/// Debian major release from a `+deb<N>` banner suffix (`Debian-5+deb11u5` → 11).
fn debian_release(banner: &str) -> Option<u32> {
    let lower = banner.to_lowercase();
    let deb_idx = lower.find("+deb")?;
    let digits: String = lower[deb_idx + 4..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Debian release from the `+debXXuY` banner suffix (e.g. `Debian-5+deb11u5` → Debian 11).
fn parse_debian_version(banner: &str) -> Option<String> {
    let version = debian_release(banner)?;
    let named = eol_db::lookup("debian", &version.to_string())
        .and_then(|entry| entry.codename.zip(entry.eol_from));
    Some(named.map_or_else(
        || format!("Linux (Debian {version})"),
        |(name, eol)| format!("Linux (Debian {version} {name}, EOL: {eol})"),
    ))
}

/// Ubuntu release inferred from the bundled `OpenSSH` version (e.g. 8.9 → 22.04).
fn parse_ubuntu_version(banner: &str) -> Option<String> {
    let (major, minor) = extract_ssh_version(banner)?;
    let releases = ubuntu_from_openssh(major, minor);
    let (first, rest) = releases.split_first()?;
    if !rest.is_empty() {
        // Ambiguous: name every candidate and the latest of their EOL dates.
        let names = releases.join(" or ");
        let eol = ubuntu_last_eol(releases).unwrap_or("unknown");
        return Some(format!("Linux (Ubuntu {names}, EOL by {eol})"));
    }
    let entry = eol_db::lookup("ubuntu", first);
    let codename = entry
        .and_then(|e| e.codename)
        .map_or_else(String::new, |name| format!(" {name}"));
    let eol = entry.and_then(|e| e.eol_from).unwrap_or("unknown");
    Some(format!("Linux (Ubuntu {first}{codename}, EOL: {eol})"))
}

/// Latest `eol_from` among `releases`; the safe claim when the release is ambiguous.
fn ubuntu_last_eol(releases: &[&'static str]) -> Option<&'static str> {
    releases
        .iter()
        .filter_map(|r| eol_db::lookup("ubuntu", r).and_then(|e| e.eol_from))
        .max()
}

/// Ubuntu releases that shipped `OpenSSH` (major, minor), newest last.
///
/// Some versions shipped in two releases, so every candidate is returned.
const fn ubuntu_from_openssh(major: u32, minor: u32) -> &'static [&'static str] {
    match (major, minor) {
        (7, 2) => &["16.04"],
        (7, 6) => &["18.04"],
        (7, 7) => &["18.10"],
        (7, 9) => &["19.04"],
        (8, 0) => &["19.10"],
        (8, 2) => &["20.04"],
        (8, 3) => &["20.10"],
        (8, 4) => &["21.04", "21.10"],
        (8, 9) => &["22.04"],
        (9, 0) => &["22.10", "23.04"],
        (9, 3) => &["23.10"],
        (9, 6) => &["24.04"],
        (9, 7) => &["24.10"],
        (9, 9) => &["25.04"],
        _ => &[],
    }
}

/// Finding if the SSH banner indicates an EOL, or LTS-only, Debian/Ubuntu release.
///
/// Dates come from `eol_db`. Debian is tiered on both of its dates (`eoas_from`
/// Medium, `eol_from` High); Ubuntu only on `eol_from`, since its `eoas_from` is
/// a point-release date, not a patching change.
pub fn check_os_eol(ip: IpAddr, port: u16, banner: &str) -> Option<Finding> {
    let lower = banner.to_lowercase();
    let today = today();

    if lower.contains("debian") {
        return check_debian_eol(ip, port, banner, &today);
    }
    if lower.contains("ubuntu") {
        return check_ubuntu_eol(ip, port, banner, &today);
    }
    None
}

/// Debian tier from the `+debN` banner suffix: LTS ended (High), or only LTS left (Medium).
fn check_debian_eol(ip: IpAddr, port: u16, banner: &str, today: &str) -> Option<Finding> {
    let version = debian_release(banner)?;
    let entry = eol_db::lookup("debian", &version.to_string())?;
    let name = entry.codename.unwrap_or("unknown");

    if eol_db::is_eol_on(entry, today) {
        let ended = entry.eol_from.unwrap_or("an unpublished date");
        return Some(
            Finding::new(
                "services",
                &format!("End-of-life OS on {ip}:{port}"),
                &format!(
                    "SSH banner indicates Debian {version} {name}, whose support including \
                     Debian LTS ended {ended} (endoflife.date snapshot {}). EOL operating \
                     systems receive no security patches. Banner: {banner}",
                    eol_db::EOL_SNAPSHOT
                ),
                Severity::High,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("SSH")
            .with_confidence(Confidence::Probable)
            .with_cwe("CWE-1104"),
        );
    }

    // Debian's own security team has stopped; only the community LTS project
    // remains, on a narrower architecture and package set.
    let eoas = entry.eoas_from.filter(|date| *date <= today)?;
    let lts_ends = entry.eol_from.unwrap_or("an unpublished date");
    Some(
        Finding::new(
            "services",
            &format!("OS on security-team support only on {ip}:{port}"),
            &format!(
                "SSH banner indicates Debian {version} {name}. Debian's own security team \
                 stopped updating it on {eoas}; the community Debian LTS project covers it \
                 until {lts_ends}, on a reduced set of architectures and packages \
                 (endoflife.date snapshot {}). Plan the upgrade to Debian {} before then. \
                 Banner: {banner}",
                eol_db::EOL_SNAPSHOT,
                eol_db::current("debian").map_or("stable", |c| c.cycle),
            ),
            Severity::Medium,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("SSH")
        .with_confidence(Confidence::Probable)
        .with_cwe("CWE-1104"),
    )
}

/// Ubuntu tier, inferred from the bundled `OpenSSH` version.
///
/// When the version maps to more than one release, every candidate must be EOL
/// before this fires, and the finding names them all with the latest of their
/// dates — so an ambiguous banner is never reported as a specific release.
fn check_ubuntu_eol(ip: IpAddr, port: u16, banner: &str, today: &str) -> Option<Finding> {
    let (major, minor) = extract_ssh_version(banner)?;
    let releases = ubuntu_from_openssh(major, minor);
    let (first, rest) = releases.split_first()?;

    let entries: Vec<_> = releases
        .iter()
        .filter_map(|r| eol_db::lookup("ubuntu", r))
        .collect();
    if entries.len() != releases.len() || !entries.iter().all(|e| eol_db::is_eol_on(e, today)) {
        return None;
    }

    let which = if rest.is_empty() {
        let name = entries[0].codename.unwrap_or("unknown");
        let ended = entries[0].eol_from.unwrap_or("an unpublished date");
        format!("Ubuntu {first} {name}, whose standard security maintenance ended {ended}")
    } else {
        let names = releases.join(" or ");
        let ended = ubuntu_last_eol(releases).unwrap_or("an unpublished date");
        format!(
            "Ubuntu {names} — that OpenSSH shipped in both, and standard security \
             maintenance ended no later than {ended}"
        )
    };

    Some(
        Finding::new(
            "services",
            &format!("End-of-life OS on {ip}:{port}"),
            &format!(
                "The bundled OpenSSH {major}.{minor} points to {which} (endoflife.date \
                 snapshot {}). The release is inferred from the SSH version, not read \
                 directly, and an ESM subscription can still be receiving patches. \
                 Banner: {banner}",
                eol_db::EOL_SNAPSHOT
            ),
            Severity::High,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("SSH")
        .with_confidence(Confidence::Inferred)
        .with_cwe("CWE-1104"),
    )
}

/// Today as `YYYY-MM-DD`, the form `eol_db` compares against.
pub(crate) fn today() -> String {
    chrono::Utc::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string()
}

/// endoflife.date product name for a banner product token, where one exists.
///
/// Absent upstream, so deliberately unmapped: `openssh`, `lighttpd`,
/// `microsoft-iis`, `openresty`, `miniserv` (Webmin). Tracked upstream but
/// unmapped because no row is embedded for them: `mysql`, `mariadb`, `redis`
/// — those versions come from `database.rs`, which does not call `eol_db`.
pub(crate) fn eol_product(token: &str) -> Option<&'static str> {
    match token {
        "nginx" => Some("nginx"),
        "apache" | "apache-httpd" | "httpd" => Some("apache-http-server"),
        "jetty" => Some("eclipse-jetty"),
        "openssl" => Some("openssl"),
        "python" => Some("python"),
        "php" | "php-fpm" => Some("php"),
        _ => None,
    }
}

/// Sentence naming a still-supported branch of `product`, from `eol_db`.
///
/// Phrased as "upgrade to X" only where upstream supports exactly one branch.
pub(crate) fn upgrade_target(product: &str) -> String {
    let Some(current) = eol_db::current(product) else {
        return String::new();
    };
    let release = current
        .latest
        .map_or_else(String::new, |latest| format!(" (latest {latest})"));
    let cycle = current.cycle;
    match (current.is_lts, current.other_supported) {
        (true, _) => format!(" Upstream's long-term-support branch is {cycle}{release}."),
        (false, true) => format!(
            " The newest branch upstream still supports is {cycle}{release}; older branches \
             are supported too, so move to the newest release on the track you are on."
        ),
        (false, false) => format!(" The only branch upstream still supports is {cycle}{release}."),
    }
}

/// End-of-life sentence for `product` at `version`, or `None` while supported.
pub(crate) fn eol_summary(product: &str, version: &str) -> Option<String> {
    let entry = eol_db::lookup(product, version)?;
    if !eol_db::is_eol_on(entry, &today()) {
        return None;
    }
    let ended = entry.eol_from.map_or_else(
        || {
            format!(
                "{product} {} is flagged end-of-life upstream with no date published",
                entry.cycle
            )
        },
        |date| format!("{product} {} reached end-of-life on {date}", entry.cycle),
    );
    Some(format!(
        "{ended} (endoflife.date snapshot {}).{} A distribution backport can still be \
         patching a cycle upstream calls dead.",
        eol_db::EOL_SNAPSHOT,
        upgrade_target(product),
    ))
}

/// ASUS `AyySSHush` backdoor listener port (CVE-2023-39780, KEV 2025-06-02).
const AYYSSHUSH_PORT: u16 = 53282;

/// Alternate SSH ports an administrator commonly picks deliberately.
const COMMON_ALT_SSH_PORTS: &[u16] = &[222, 2022, 2222, 22222];

/// True if any early line is an RFC 4253 section 4.2 identification string.
///
/// `SSH-<protoversion>-<software>`, and protoversion always starts with a digit
/// ("SSH-2.0-", "SSH-1.99-"). The digit check is what separates an identification
/// string from public-key material (`ssh-rsa AAAA...`, `ssh-ed25519 ...`), which
/// some services push unsolicited.
fn is_ssh_banner(banner: &str) -> bool {
    banner.lines().take(8).any(|line| {
        line.trim_start()
            .as_bytes()
            .first_chunk::<5>()
            .is_some_and(|p| p[..4].eq_ignore_ascii_case(b"SSH-") && p[4].is_ascii_digit())
    })
}

/// True when `s` names ASUS as a token: `pegasus` is not ASUS hardware, and
/// `dropbear` alone is not ASUS firmware (`OpenWrt` ships it too).
fn names_asus(s: &str) -> bool {
    s.split(|c: char| !c.is_ascii_alphanumeric()).any(|tok| {
        ["asus", "asustek", "asuswrt"]
            .iter()
            .any(|k| tok.eq_ignore_ascii_case(k))
    })
}

/// What the scan knows about a host's routing role. The `AyySSHush` attribution
/// needs more than an open port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostRole {
    /// The host is this network's default gateway.
    pub is_gateway: bool,
    /// Device type or OUI vendor says router or access point.
    pub router_like: bool,
    /// Vendor names ASUS as a token. CVE-2023-39780 is ASUS-only, so only this
    /// tier carries it.
    pub is_asus: bool,
}

impl HostRole {
    /// The default gateway, hardware unidentified.
    pub const GATEWAY: Self = Self {
        is_gateway: true,
        router_like: true,
        is_asus: false,
    };

    /// A host with no known routing role.
    pub const UNKNOWN: Self = Self {
        is_gateway: false,
        router_like: false,
        is_asus: false,
    };

    /// Role of a discovered device. `is_asus` reads the vendor only: hostname
    /// and OS guess are strings the scanned host chooses.
    fn of_device(device: &Device, is_gateway: bool) -> Self {
        let is_asus = device.vendor.as_deref().is_some_and(names_asus);
        let router_like = is_gateway
            || is_asus
            || matches!(
                device.device_type,
                DeviceType::Router | DeviceType::AccessPoint
            );
        Self {
            is_gateway,
            router_like,
            is_asus,
        }
    }
}

/// Remediation for an `AyySSHush`-style NVRAM SSH backdoor.
fn ayysshush_remediation() -> Remediation {
    Remediation {
        description: "A firmware update does not evict the attacker's key: the authorized \
                      key lives in NVRAM and survives both reboot and upgrade. Only a factory \
                      reset followed by manual reconfiguration clears it."
            .to_owned(),
        steps: vec![
            "Disconnect the router's WAN link before working on it.".to_owned(),
            "Factory reset with the hardware reset button. Do not restore a settings \
             backup — a backup re-imports the NVRAM entry."
                .to_owned(),
            "Reconfigure by hand: new admin password, SSH disabled, remote/WAN \
             administration disabled, AiCloud disabled."
                .to_owned(),
            "Update to the latest firmware, then confirm SSH is off and no authorized \
             key is listed in the administration UI."
                .to_owned(),
            "Rotate credentials and keys that were used across this router while the \
             backdoor was reachable."
                .to_owned(),
        ],
        effort: Some("30-60 minutes; the device loses its configuration".to_owned()),
    }
}

/// Remediation when TCP/53282 answers on a host the scan cannot tie to ASUS
/// hardware: identify the listener before acting on either reading.
fn unattributed_port_remediation() -> Remediation {
    Remediation {
        description: "A relocated SSH server and a compromised router look identical from \
                      outside. Identify what holds the port before acting."
            .to_owned(),
        steps: vec![
            "On the host, name the listener: `ss -tlnp | grep 53282` (Linux) or \
             `lsof -iTCP:53282 -sTCP:LISTEN` (macOS)."
                .to_owned(),
            "If it is a service or container port you published, record it in the baseline \
             file so later scans stay quiet."
                .to_owned(),
            "If the host is in fact an ASUS router or access point, treat it as the \
             AyySSHush backdoor: factory reset and reconfigure by hand. A firmware update \
             leaves the attacker's NVRAM key in place."
                .to_owned(),
        ],
        effort: Some("10 minutes to identify the listener".to_owned()),
    }
}

/// Remediation for SSH on an unexpected port of the gateway: establish intent
/// before the destructive step. The finding is `Probable`, not `Confirmed`.
fn gateway_ssh_remediation(port: u16) -> Remediation {
    Remediation {
        description: "Consumer routers ship with SSH off. Establish whether you moved it \
                      here before treating the router as compromised; the recovery is \
                      destructive."
            .to_owned(),
        steps: vec![
            format!(
                "In the router's administration UI, check whether SSH is enabled and on port {port}."
            ),
            "Check the authorized-key list in the same UI. A key you do not recognise means \
             the router is compromised."
                .to_owned(),
            "If SSH is deliberate, turn off remote/WAN administration for it and record the \
             port in the baseline file so later scans stay quiet."
                .to_owned(),
            "If it is not deliberate, factory reset and reconfigure by hand. A firmware \
             update leaves the attacker's NVRAM key in place, and a settings backup \
             re-imports it."
                .to_owned(),
        ],
        effort: Some("15 minutes to check; 30-60 more if a reset is needed".to_owned()),
    }
}

/// TCP/53282 answering SSH on identified ASUS hardware: the campaign artefact.
fn ayysshush_finding(ip: IpAddr, banner: &str) -> Finding {
    Finding::new(
        "services",
        "ASUS AyySSHush SSH backdoor listener on TCP/53282",
        &format!(
            "An SSH server answered on {ip}:{AYYSSHUSH_PORT}. That port is the only \
             network-visible artefact of the AyySSHush campaign against ASUS routers \
             (CVE-2023-39780, CISA KEV 2025-06-02): the attacker enables SSH there and \
             stores an authorized key in NVRAM. Logging is disabled and no malware is \
             dropped, so nothing else shows. Treat the device as compromised until it \
             has been factory reset and reconfigured by hand."
        ),
        Severity::Critical,
    )
    .with_ip(ip)
    .with_port(AYYSSHUSH_PORT)
    .with_service("SSH")
    .with_cwe("CWE-78")
    .with_confidence(Confidence::Confirmed)
    .with_cve_ids(vec!["CVE-2023-39780".to_owned()])
    .with_references(refs![
        "https://www.greynoise.io/blog/stealthy-backdoor-campaign-affecting-asus-routers",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-39780",
    ])
    .with_evidence(banner)
    .with_remediation(ayysshush_remediation())
}

/// TCP/53282 answering SSH on a host the scan cannot tie to ASUS hardware: the
/// port is the campaign's, the attribution is not. `Probable`, no CVE, and the
/// title claims only what the protocol answered.
fn unattributed_port_finding(ip: IpAddr, banner: &str) -> Finding {
    Finding::new(
        "services",
        "SSH server on TCP/53282, the AyySSHush backdoor port",
        &format!(
            "An SSH server answered on {ip}:{AYYSSHUSH_PORT}. That is the listener the \
             AyySSHush campaign opens on compromised ASUS routers (CVE-2023-39780, CISA KEV \
             2025-06-02), but nothing identifies this host as ASUS hardware, so a \
             deliberately relocated SSH server or a published container port explains it \
             equally well. Identify the listener before acting."
        ),
        Severity::High,
    )
    .with_ip(ip)
    .with_port(AYYSSHUSH_PORT)
    .with_service("SSH")
    .with_cwe("CWE-912")
    .with_confidence(Confidence::Probable)
    .with_references(refs![
        "https://www.greynoise.io/blog/stealthy-backdoor-campaign-affecting-asus-routers",
    ])
    .with_evidence(banner)
    .with_remediation(unattributed_port_remediation())
}

/// SSH answering on a port it has no business listening on.
///
/// TCP/53282 is the `AyySSHush` artefact. The campaign attribution — and its
/// destructive remediation — is asserted only where the vendor
/// (`HostRole::is_asus`) or the banner names ASUS; every other host gets the
/// vendor-neutral finding. SSH on another non-22 port of the gateway stays
/// `Probable`.
pub fn classify_backdoor_ssh(
    ip: IpAddr,
    port: u16,
    banner: &str,
    role: HostRole,
) -> Option<Finding> {
    if !is_ssh_banner(banner) {
        return None;
    }

    if port == AYYSSHUSH_PORT {
        return Some(if role.is_asus || names_asus(banner) {
            ayysshush_finding(ip, banner)
        } else {
            unattributed_port_finding(ip, banner)
        });
    }

    if !role.is_gateway || port == 22 {
        return None;
    }

    let severity = if COMMON_ALT_SSH_PORTS.contains(&port) {
        Severity::Medium
    } else {
        Severity::High
    };

    Some(
        Finding::new(
            "services",
            "SSH listening on a non-standard port on the gateway",
            &format!(
                "An SSH server answered on the gateway at {ip}:{port}. Consumer routers ship \
                 with SSH off, and campaigns such as AyySSHush (CVE-2023-39780) enable it on an \
                 arbitrary high port with an attacker key stored in NVRAM. If you did not move \
                 SSH to this port yourself, treat the router as compromised: a firmware update \
                 does not remove such a key."
            ),
            severity,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("SSH")
        .with_cwe("CWE-912")
        .with_confidence(Confidence::Probable)
        .with_references(refs![
            "https://www.greynoise.io/blog/stealthy-backdoor-campaign-affecting-asus-routers",
        ])
        .with_evidence(banner)
        .with_remediation(gateway_ssh_remediation(port)),
    )
}

/// Role of a host with no discovered device: the ARP cache's MAC carries the
/// OUI vendor, which is all `is_asus` reads.
fn role_from_arp(ip: IpAddr, is_gateway: bool, entries: &[ArpEntry]) -> HostRole {
    let is_asus = entries
        .iter()
        .filter(|e| e.ip == ip)
        .any(|e| crate::oui_db::ieee_oui_lookup(&e.mac).is_some_and(names_asus));
    HostRole {
        is_gateway,
        router_like: is_gateway || is_asus,
        is_asus,
    }
}

/// Banner-grab one TCP port directly and classify what answers. Used for ports no
/// scan list reaches, where the answering port is itself the signal.
async fn probe_ssh_port(ip: IpAddr, port: u16, role: HostRole) -> Option<Finding> {
    let banner = grab_banner(ip, port).await?;
    classify_backdoor_ssh(ip, port, &banner, role)
}

/// True when `entries` resolve `ip` to at least one MAC and none of them, nor the
/// IP itself, is excluded.
fn arp_clears_ip(entries: &[ArpEntry], ip: IpAddr, exclusions: &ExclusionSet) -> bool {
    if exclusions.excludes_ip(ip) {
        return false;
    }
    let mut resolved = false;
    for entry in entries.iter().filter(|e| e.ip == ip) {
        let Ok(mac) = entry.mac.parse::<MacAddr>() else {
            continue;
        };
        if exclusions.excludes_mac(mac) {
            return false;
        }
        resolved = true;
    }
    resolved
}

/// May we connect to an address that no discovered device vouched for? With
/// exclusions configured, the ARP cache must resolve it to a MAC that is not
/// excluded: `ExclusionSet` excludes by MAC as well as by IP, an excluded device is
/// simply absent from `discovered_devices`, and an unresolved MAC cannot be cleared.
fn unvouched_probe_allowed(ip: IpAddr, exclusions: &ExclusionSet) -> bool {
    exclusions.is_empty()
        || rikitikitavi_network::read_arp_cache()
            .is_ok_and(|entries| arp_clears_ip(&entries, ip, exclusions))
}

/// ARP entries in scope and excluded by neither IP nor MAC.
fn select_banner_targets(
    entries: &[ArpEntry],
    in_scope: impl Fn(IpAddr) -> bool,
    exclusions: &ExclusionSet,
) -> Vec<IpAddr> {
    entries
        .iter()
        .filter(|e| in_scope(e.ip))
        .filter(|e| !exclusions.excludes_ip(e.ip))
        .filter(|e| {
            !e.mac
                .parse::<MacAddr>()
                .is_ok_and(|m| exclusions.excludes_mac(m))
        })
        .map(|e| e.ip)
        .collect()
}

/// Classify a banner finding based on the service and version info.
#[allow(clippy::too_many_lines)]
fn classify_banner(ip: IpAddr, port: u16, banner: &str) -> Option<Finding> {
    let banner_lower = banner.to_lowercase();

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

    if is_ssh_banner(banner) || (port == 22 && banner_lower.contains("ssh")) {
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

        if let Some((major, minor)) = extract_ssh_version(banner) {
            let cves = check_openssh_cves(major, minor);
            if !cves.is_empty() {
                let max_severity = cves.iter().map(|c| c.2).max().unwrap_or(Severity::Low);

                let cve_list: Vec<String> = cves
                    .iter()
                    .map(|(id, desc, sev)| format!("{id} ({sev:?}): {desc}"))
                    .collect();

                let cve_ids: Vec<String> = cves.iter().map(|(id, _, _)| (*id).to_owned()).collect();

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
    let rest = lower.get(idx + 8..)?;
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

    // CVE-2024-6387 regreSSHion: 8.5p1..9.7p1
    if (major == 8 && minor >= 5) || (major == 9 && minor <= 7) {
        cves.push((
            "CVE-2024-6387",
            "regreSSHion: signal handler race condition allowing unauthenticated \
             remote code execution on glibc-based Linux systems",
            Severity::Critical,
        ));
    }

    // CVE-2023-38408 PKCS#11 agent RCE: < 9.3p2
    if major < 9 || (major == 9 && minor < 3) {
        cves.push((
            "CVE-2023-38408",
            "PKCS#11 provider loading via forwarded ssh-agent allows remote code execution",
            Severity::High,
        ));
    }

    // CVE-2023-48795 Terrapin: < 9.6
    if major < 9 || (major == 9 && minor < 6) {
        cves.push((
            "CVE-2023-48795",
            "Terrapin attack: prefix truncation on chacha20-poly1305 and \
             CBC-mode with encrypt-then-MAC allows message manipulation",
            Severity::Medium,
        ));
    }

    // CVE-2021-41617: 6.2..8.7
    if (major == 6 && minor >= 2) || major == 7 || (major == 8 && minor <= 7) {
        cves.push((
            "CVE-2021-41617",
            "AuthorizedKeysCommand/AuthorizedPrincipalsCommand privilege escalation \
             when run as a different user",
            Severity::Medium,
        ));
    }

    // CVE-2018-15473 user enumeration: < 7.8
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

/// Parse an HTTP `Server` header: `product/version[ (os)]` or `Jetty(version)`.
pub fn parse_server_header(header: &str) -> Option<ServerVersion> {
    let trimmed = header.trim();
    if trimmed.is_empty() {
        return None;
    }

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

/// Known EOL / vulnerable version ranges per product; `None` if acceptable or unknown.
///
/// Hand-coded rules carry the CVE detail; anything they pass falls through to
/// the `eol_db` table, which is the only source of support dates.
#[allow(clippy::too_many_lines)]
pub fn check_server_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    let hand_coded = match sv.product.as_str() {
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
    };
    hand_coded.or_else(|| check_eol_table(sv))
}

/// End-of-life straight from `eol_db`, for versions no hand-coded rule caught.
fn check_eol_table(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    let product = eol_product(&sv.product)?;
    let summary = eol_summary(product, &format!("{}.{}.{}", sv.major, sv.minor, sv.patch))?;
    Some(ServerVersionIssue {
        severity: eol_severity(&sv.raw),
        description: format!("{summary} Banner: {}", sv.raw),
        cwe: Some("CWE-1104"),
        cve_refs: Vec::new(),
    })
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
    // < 1.22 is EOL
    if sv.major == 1 && sv.minor < 22 {
        let mut refs = Vec::new();
        // < 1.17.7: CVE-2019-20372 (request smuggling)
        if sv.minor < 17 || (sv.minor == 17 && sv.patch < 7) {
            refs.push("https://nvd.nist.gov/vuln/detail/CVE-2019-20372".to_owned());
        }
        // < 1.21.0: CVE-2021-23017 (resolver)
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
                "nginx {} is end-of-life; EOL branches do not receive security patches.{}",
                sv.raw,
                upgrade_target("nginx")
            ),
            cwe: Some("CWE-1104"),
            cve_refs: refs,
        });
    }
    None
}

fn check_apache_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    // 2.2 EOL since 2017
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
    if sv.major == 2 && sv.minor == 4 {
        let mut refs = Vec::new();
        // < 2.4.52: CVE-2021-44790 (mod_lua)
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
                    "Apache {} has known vulnerabilities.{}",
                    sv.raw,
                    upgrade_target("apache-http-server")
                ),
                cwe: Some("CWE-1104"),
                cve_refs: refs,
            });
        }
    }
    None
}

fn check_lighttpd_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    // < 1.4.56: CVE-2022-22707
    if sv.major == 1 && sv.minor == 4 && sv.patch < 56 {
        return Some(ServerVersionIssue {
            severity: Severity::Medium,
            // endoflife.date does not track lighttpd, so no dated claim is made here.
            description: format!(
                "lighttpd {} is outdated. Versions < 1.4.56 are vulnerable to \
                 CVE-2022-22707 (use-after-free). Upgrade to the latest 1.4.x release.",
                sv.raw
            ),
            cwe: Some("CWE-416"),
            cve_refs: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-22707".to_owned()],
        });
    }
    None
}

fn check_iis_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    // < 8: Server 2008 R2 and older (EOL)
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
    // < 1.19 bundles EOL nginx
    if sv.major == 1 && sv.minor < 19 {
        return Some(ServerVersionIssue {
            severity: Severity::Medium,
            // endoflife.date does not track OpenResty; the bundled nginx branch is
            // what the table can speak to.
            description: format!(
                "OpenResty {} bundles an outdated nginx branch.{} Upgrade to receive \
                 security patches.",
                sv.raw,
                upgrade_target("nginx")
            ),
            cwe: Some("CWE-1104"),
            cve_refs: Vec::new(),
        });
    }
    None
}

fn check_miniserv_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    // Webmin (MiniServ) < 1.990: CVE-2022-0824; `1.950` parses as major=1, minor=950
    let webmin_version = u64::from(sv.major) * 1000 + u64::from(sv.minor);
    if webmin_version < 1990 {
        return Some(ServerVersionIssue {
            severity: Severity::High,
            // endoflife.date does not track Webmin, so no "current version" claim.
            description: format!(
                "Webmin/MiniServ {} is outdated. Versions before 1.990 are vulnerable \
                 to CVE-2022-0824 (authenticated RCE). Upgrade to a current Webmin release.",
                sv.raw
            ),
            cwe: Some("CWE-78"),
            cve_refs: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-0824".to_owned()],
        });
    }
    None
}

fn check_jetty_version(sv: &ServerVersion) -> Option<ServerVersionIssue> {
    // <= 9.x is EOL
    if sv.major <= 9 {
        let mut refs = Vec::new();
        // < 9.4.51: CVE-2023-26048
        if sv.major < 9
            || (sv.major == 9 && sv.minor < 4)
            || (sv.major == 9 && sv.minor == 4 && sv.patch < 51)
        {
            refs.push("https://nvd.nist.gov/vuln/detail/CVE-2023-26048".to_owned());
        }
        return Some(ServerVersionIssue {
            severity: Severity::Medium,
            description: format!(
                "Jetty {} is end-of-life. The 9.x branch no longer receives \
                 security updates.{}",
                sv.raw,
                upgrade_target("eclipse-jetty")
            ),
            cwe: Some("CWE-1104"),
            cve_refs: refs,
        });
    }
    None
}

/// Distribution markers in a `Server` or `X-Powered-By` value: a parenthesised
/// distribution name, or a distribution suffix on the version.
const DISTRO_MARKERS: &[&str] = &[
    "(debian",
    "(centos",
    "(red hat",
    "(rocky",
    "(almalinux",
    "(fedora",
    "(suse",
    "(amazon",
    "(raspbian",
    "(alpine",
    "ubuntu",
    "+deb",
    "~deb",
    "~bpo",
    ".el7",
    ".el8",
    ".el9",
];

/// True when `lower` names a distribution generation that is itself
/// end-of-life, so no backport is patching the component either.
fn dead_distro_marker(lower: &str) -> bool {
    // CentOS Linux 7 ended 2024-06-30 and 8 ended 2021-12; Stream is separate.
    if lower.contains("(centos") && !lower.contains("(centos stream") {
        return true;
    }
    if lower.contains(".el7") || lower.contains(".el8") {
        return true;
    }
    // `~deb11u1` names the same release as `+deb11u1`.
    debian_release(&lower.replace('~', "+")).is_some_and(|release| {
        eol_db::lookup("debian", &release.to_string())
            .is_some_and(|entry| eol_db::is_eol_on(entry, &today()))
    })
}

/// Severity for an EOL join made from the `eol_db` table alone.
///
/// The table carries upstream dates. A distribution backport can still be
/// patching a cycle upstream calls dead, so a distribution marker in `context`
/// drops the claim to `Low` — unless the marker names a distribution generation
/// that is itself dead, where nothing is backporting.
pub(crate) fn eol_severity(context: &str) -> Severity {
    let lower = context.to_ascii_lowercase();
    if DISTRO_MARKERS.iter().any(|m| lower.contains(m)) && !dead_distro_marker(&lower) {
        Severity::Low
    } else {
        Severity::Medium
    }
}

/// EOL findings for secondary `name/version` tokens in a `Server` header.
///
/// `Apache/2.4.6 (CentOS) OpenSSL/1.0.2k PHP/5.4.45` — the leading token is
/// `check_server_version`'s, so it is skipped here.
fn check_header_components(ip: IpAddr, port: u16, server: &str) -> Vec<Finding> {
    server
        .split_whitespace()
        .skip(1)
        .filter_map(|token| {
            let (name, version) = token.split_once('/')?;
            let product = eol_product(&name.to_ascii_lowercase())?;
            let summary = eol_summary(product, version)?;
            Some(
                Finding::new(
                    "services",
                    &format!("End-of-life {product} component on {ip}:{port}"),
                    &format!("The Server header advertises {token}. {summary} Header: {server}"),
                    eol_severity(server),
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("HTTP")
                .with_confidence(Confidence::Probable)
                .with_cwe("CWE-1104")
                .with_evidence(server),
            )
        })
        .collect()
}

/// Findings for a `Server` header: version issue if known, else Info disclosure,
/// plus any end-of-life component named in the rest of the header.
fn classify_http_server(ip: IpAddr, port: u16, server: &str) -> Vec<Finding> {
    let mut findings = check_header_components(ip, port, server);

    if let Some(sv) = parse_server_header(server)
        && let Some(issue) = check_server_version(&sv)
    {
        let mut finding = Finding::new(
            "services",
            &format!("Outdated {} on {ip}:{port}", sv.product),
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

        findings.insert(0, finding);
        return findings;
    }

    findings.insert(
        0,
        Finding::new(
            "services",
            &format!("HTTP server version disclosure on {ip}:{port}"),
            &format!("Server header: {server}"),
            Severity::Info,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("HTTP"),
    );
    findings
}

/// True when this scanner should Recog-identify an HTTP port.
///
/// The HTTP audit identifies its own ports from header, realm and title
/// together, but only at Active+ and only on `AUDIT_PORTS`; every other
/// HTTP-ish port is ours at every intensity.
fn recog_identifies_http(port: u16, active: bool) -> bool {
    !(active && crate::http_audit::AUDIT_PORTS.contains(&port))
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
async fn deep_probe(ip: IpAddr, port: u16, banner: Option<&str>) -> Vec<Finding> {
    if port == 22 || banner.is_some_and(is_ssh_banner) {
        return probe_ssh_kex(ip, port)
            .await
            .map_or_else(Vec::new, |kex| classify_ssh_kex(ip, port, &kex));
    }

    match port {
        25 | 587 => probe_smtp_ehlo(ip, port)
            .await
            .map_or_else(Vec::new, |ehlo| classify_smtp_ehlo(ip, port, &ehlo)),
        21 => probe_ftp_feat(ip, port)
            .await
            .map_or_else(Vec::new, |feat| classify_ftp_feat(ip, port, &feat)),
        _ => Vec::new(),
    }
}

/// Banner and protocol probes for one discovered device.
async fn probe_device(device: &Device, role: HostRole, active: bool) -> Vec<Finding> {
    let ip = device.ip;
    let mut findings = Vec::new();

    // Reach for TCP/53282 on router-shaped hosts unless phase 1 already found it.
    if active && role.router_like && !device.open_ports.iter().any(|p| p.port == AYYSSHUSH_PORT) {
        findings.extend(probe_ssh_port(ip, AYYSSHUSH_PORT, role).await);
    }

    for open_port in &device.open_ports {
        let port = open_port.port;
        if BANNER_PORTS.contains(&port) {
            let banner = grab_banner(ip, port).await;
            if let Some(banner) = banner.as_deref() {
                findings.extend(classify_banner(ip, port, banner));
                findings.extend(check_os_eol(ip, port, banner));
                findings.extend(classify_backdoor_ssh(ip, port, banner, role));
                findings.extend(recog_banner(ip, port, banner));
            }
            if active {
                findings.extend(deep_probe(ip, port, banner.as_deref()).await);
            }
        } else if HTTP_PORTS.contains(&port) || is_likely_http_port(port) {
            if let Some(server) = grab_http_server(ip, port).await {
                findings.extend(classify_http_server(ip, port, &server));
                if recog_identifies_http(port, active) {
                    findings.extend(recog::identify_finding(
                        "services",
                        ip,
                        Some(port),
                        RecogKey::HttpServer,
                        &server,
                    ));
                }
            }
        } else {
            // Unknown port: plain banner grab
            if let Some(banner) = grab_banner(ip, port).await {
                findings.extend(classify_banner(ip, port, &banner));
                findings.extend(check_os_eol(ip, port, &banner));
                findings.extend(classify_backdoor_ssh(ip, port, &banner, role));
                findings.extend(recog_banner(ip, port, &banner));
            }
        }
    }

    findings
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
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running service banner scan");
        let mut findings = Vec::new();

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "services".to_owned(),
                message: e.to_string(),
            })?;
        let active = ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active);

        if !ctx.discovered_devices.is_empty() {
            tracing::info!(
                device_count = ctx.discovered_devices.len(),
                "adaptive banner scan using discovered devices"
            );

            for device in &ctx.discovered_devices {
                if exclusions.excludes_device(device) {
                    continue;
                }
                let role = HostRole::of_device(device, ctx.gateway == Some(device.ip));
                findings.extend(probe_device(device, role, active).await);
            }

            // Discovery can miss the gateway; it is the highest-value target here.
            // An excluded gateway is also missing from `discovered_devices` — by MAC
            // as well as by IP — so clear it against the ARP cache before connecting.
            if let Some(gateway) = ctx.gateway
                && active
                && !ctx.discovered_devices.iter().any(|d| d.ip == gateway)
                && unvouched_probe_allowed(gateway, &exclusions)
            {
                let arp = rikitikitavi_network::read_arp_cache().unwrap_or_default();
                let role = role_from_arp(gateway, true, &arp);
                findings.extend(probe_ssh_port(gateway, AYYSSHUSH_PORT, role).await);
            }

            tracing::info!(
                findings_count = findings.len(),
                "adaptive banner scan complete"
            );
            return Ok(findings);
        }

        let arp_entries =
            rikitikitavi_network::read_arp_cache().map_err(|e| ScanError::ScannerFailed {
                scanner: "services".to_owned(),
                message: format!("failed to read ARP cache: {e}"),
            })?;

        let targets = select_banner_targets(
            &arp_entries,
            |ip| ctx.target_network.as_ref().is_none_or(|n| n.contains(ip)),
            &exclusions,
        );

        if targets.is_empty() {
            tracing::info!("no targets for banner grabbing");
            return Ok(Vec::new());
        }

        tracing::info!(target_count = targets.len(), "banner grabbing targets");

        for &ip in &targets {
            let role = role_from_arp(ip, ctx.gateway == Some(ip), &arp_entries);
            for &port in BANNER_PORTS {
                // Nothing suggested 53282 was open; only reach for it at Active+.
                if port == AYYSSHUSH_PORT && !active {
                    continue;
                }
                if let Some(banner) = grab_banner(ip, port).await {
                    findings.extend(classify_banner(ip, port, &banner));
                    findings.extend(check_os_eol(ip, port, &banner));
                    findings.extend(classify_backdoor_ssh(ip, port, &banner, role));
                    findings.extend(recog_banner(ip, port, &banner));
                }
            }

            for &port in HTTP_PORTS {
                if let Some(server) = grab_http_server(ip, port).await {
                    findings.extend(classify_http_server(ip, port, &server));
                    findings.extend(recog::identify_finding(
                        "services",
                        ip,
                        Some(port),
                        RecogKey::HttpServer,
                        &server,
                    ));
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
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1883, 3389, 5900, 8080, 53282,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// An SSH identification string is identified wherever it listens, including
    /// the `AyySSHush` port.
    #[test]
    fn recog_banner_identifies_ssh_on_any_port() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        for port in [22u16, 2222, AYYSSHUSH_PORT] {
            let finding =
                recog_banner(ip, port, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4").unwrap();
            assert_eq!(finding.affected_port, Some(port));
            assert_eq!(finding.confidence, Confidence::Probable);
            assert_eq!(finding.severity, Severity::Info);
        }
    }

    /// Ports with no Recog table and no SSH banner produce nothing.
    #[test]
    fn recog_banner_is_silent_on_unmapped_ports() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(recog_banner(ip, 6379, "+PONG").is_none());
        assert!(recog_banner(ip, 21, "220 zzzz").is_none());
    }

    /// The reply code is not part of what Recog matches.
    #[test]
    fn recog_banner_strips_the_ftp_reply_code() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding =
            recog_banner(ip, 21, "220 ProFTPD 1.3.5 Server (Debian) [10.0.0.1]\r\n").unwrap();
        assert!(
            finding
                .affected_service
                .as_deref()
                .is_some_and(|s| s.contains("ProFTPD"))
        );
        // The same greeting with the code still attached matches nothing.
        assert!(
            crate::recog::identify(
                RecogKey::FtpBanner,
                "220 ProFTPD 1.3.5 Server (Debian) [10.0.0.1]"
            )
            .is_none()
        );
    }

    #[test]
    fn strip_reply_code_needs_three_digits_and_a_separator() {
        assert_eq!(strip_reply_code("220 hello"), Some("hello"));
        assert_eq!(strip_reply_code("220-hello"), Some("hello"));
        assert_eq!(strip_reply_code("22 hello"), None);
        assert_eq!(strip_reply_code("220xhello"), None);
        assert_eq!(strip_reply_code("220"), None);
        assert_eq!(strip_reply_code(""), None);
    }

    #[test]
    fn strip_status_matches_case_insensitively() {
        assert_eq!(
            strip_status("+OK Dovecot ready", &["+OK "]),
            Some("Dovecot ready")
        );
        assert_eq!(
            strip_status("* ok [CAPABILITY] ready", &["* OK "]),
            Some("[CAPABILITY] ready")
        );
        assert_eq!(strip_status("nope", &["+OK "]), None);
    }

    proptest! {
        #[test]
        fn prop_recog_banner_no_panic(banner in ".*", port in any::<u16>()) {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            let _ = recog_banner(ip, port, &banner);
        }
    }

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
        assert!(
            debian_result
                .as_ref()
                .is_some_and(|s| s.contains("Debian 11") && s.contains("Bullseye"))
        );
        // Ubuntu version extraction from OpenSSH version mapping
        let ubuntu_result = parse_os_from_ssh_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4");
        assert!(
            ubuntu_result
                .as_ref()
                .is_some_and(|s| s.contains("Ubuntu 22.04") && s.contains("Jammy"))
        );
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
        let findings = classify_http_server(ip, 80, "nginx/1.18.0");
        let finding = &findings[0];
        // nginx 1.18 is EOL → now correctly Medium+
        assert!(finding.severity >= Severity::Medium);
        assert_eq!(finding.scanner, "services");
        assert_eq!(finding.affected_port, Some(80));
        assert!(finding.cwe_id.is_some());
    }

    #[test]
    fn test_classify_http_server_current_nginx() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // The newest supported branch comes from the table, so this test does not
        // go stale when the table is regenerated.
        let latest = eol_db::current("nginx").and_then(|c| c.latest).unwrap();
        let findings = classify_http_server(ip, 80, &format!("nginx/{latest}"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// The claim this table replaced: nginx 1.26.x was hard-coded as "current stable".
    #[test]
    fn test_classify_http_server_nginx_126_is_eol() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = classify_http_server(ip, 80, "nginx/1.26.0");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(
            findings[0]
                .description
                .contains("end-of-life on 2025-04-23")
        );
    }

    /// Secondary `Server` tokens are joined to the table independently. `CentOS`
    /// Linux is itself end-of-life, so the marker does not downgrade this one.
    #[test]
    fn test_classify_http_server_openssl_component() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = classify_http_server(ip, 443, "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips");
        let openssl = findings
            .iter()
            .find(|f| f.title.contains("openssl"))
            .expect("openssl component finding");
        assert_eq!(openssl.severity, Severity::Medium);
        assert!(openssl.description.contains("openssl 1.0.2"));
        assert_eq!(openssl.confidence, Confidence::Probable);
    }

    #[test]
    fn test_classify_http_server_empty() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = classify_http_server(ip, 8080, "");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_eol_product_mapping() {
        assert_eq!(eol_product("apache"), Some("apache-http-server"));
        assert_eq!(eol_product("jetty"), Some("eclipse-jetty"));
        assert_eq!(eol_product("nginx"), Some("nginx"));
        // Not tracked by endoflife.date, so deliberately unmapped.
        assert_eq!(eol_product("lighttpd"), None);
        assert_eq!(eol_product("microsoft-iis"), None);
        assert_eq!(eol_product("miniserv"), None);
        // Tracked upstream, but database.rs owns these versions and does not
        // call eol_db, so no rows are embedded and the token stays unmapped.
        assert_eq!(eol_product("mysql"), None);
        assert_eq!(eol_product("redis"), None);
    }

    /// A mapped token must have rows behind it, or it is a silent dead end.
    #[test]
    fn test_every_mapped_product_has_rows() {
        for token in [
            "nginx",
            "apache",
            "apache-httpd",
            "httpd",
            "jetty",
            "openssl",
            "python",
            "php",
            "php-fpm",
        ] {
            let product = eol_product(token).unwrap_or_else(|| panic!("{token} unmapped"));
            assert!(
                !eol_db::product_cycles(product).is_empty(),
                "{token} maps to {product}, which has no rows"
            );
        }
    }

    /// The remediation sentence declines to pick a branch when several are live.
    #[test]
    fn test_upgrade_target_does_not_recommend_mainline() {
        let nginx = upgrade_target("nginx");
        assert!(nginx.contains("older branches"), "{nginx}");
        assert!(nginx.contains("track you are on"), "{nginx}");
        // OpenSSL marks an LTS branch, so that one is named outright.
        let openssl = upgrade_target("openssl");
        assert!(
            openssl.contains("long-term-support branch is 3.5"),
            "{openssl}"
        );
        assert!(upgrade_target("not-a-product").is_empty());
    }

    /// Ubuntu's `eoas_from` is hardware enablement, so no tier keys on it:
    /// Jammy is past that date and still fully supported.
    #[test]
    fn test_check_os_eol_ubuntu_jammy_silent_past_eoas() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let jammy = eol_db::cycle("ubuntu", "22.04").expect("ubuntu 22.04");
        assert!(jammy.eoas_from.is_some_and(|d| d <= today().as_str()));
        assert!(!eol_db::is_eol_on(jammy, &today()));
        assert!(check_os_eol(ip, 22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13").is_none());
    }

    #[test]
    fn test_eol_summary_names_date_and_upgrade_target() {
        let summary = eol_summary("php", "7.4.33").expect("php 7.4 is EOL");
        assert!(summary.contains("php 7.4 reached end-of-life on 2022-11-28"));
        assert!(summary.contains("still supports"), "{summary}");
        // A supported branch yields nothing at all.
        let latest = eol_db::current("php").and_then(|c| c.latest).unwrap();
        assert!(eol_summary("php", latest).is_none());
        // Unknown product or version: no claim.
        assert!(eol_summary("nginx", "99.99").is_none());
        assert!(eol_summary("not-a-product", "1.0").is_none());
    }

    #[test]
    fn test_upgrade_target_is_table_derived() {
        let current = eol_db::current("nginx").expect("nginx current");
        assert!(upgrade_target("nginx").contains(current.cycle));
        assert_eq!(upgrade_target("not-a-product"), "");
    }

    /// A distribution build is still being patched; the upstream date alone is
    /// not evidence that it is not.
    #[test]
    fn distro_builds_downgrade_the_table_only_eol_join() {
        assert_eq!(eol_severity("Apache/2.4.57 (Debian)"), Severity::Low);
        assert_eq!(eol_severity("Apache/2.4.52 (Ubuntu)"), Severity::Low);
        assert_eq!(eol_severity("PHP/8.1.2-1ubuntu2.14"), Severity::Low);
        let live = eol_db::current("debian").expect("debian current").cycle;
        assert_eq!(
            eol_severity(&format!("nginx/1.26.0-1+deb{live}u1")),
            Severity::Low
        );
        // No distribution context: the upstream date is all there is.
        assert_eq!(
            eol_severity("Apache/2.4.6 OpenSSL/1.0.2k"),
            Severity::Medium
        );
        assert_eq!(eol_severity("PHP/5.6.40"), Severity::Medium);
        assert_eq!(eol_severity(""), Severity::Medium);
    }

    /// A distribution generation that is itself dead backports nothing, so the
    /// marker does not downgrade.
    #[test]
    fn a_dead_distro_generation_does_not_downgrade() {
        // Debian 10 Buster: LTS ended 2024-06-30.
        assert_eq!(eol_severity("nginx/1.14.2-2+deb10u4"), Severity::Medium);
        assert_eq!(
            eol_severity("Apache/2.4.6 (CentOS) PHP/5.4.45"),
            Severity::Medium
        );
        assert_eq!(eol_severity("PHP/7.2.24-1.el7.remi"), Severity::Medium);
        assert_eq!(eol_severity("nginx/1.18.0-6.1~deb11u3"), Severity::Medium);
        // CentOS Stream is a live distribution, not CentOS Linux.
        assert_eq!(
            eol_severity("Apache/2.4.62 (CentOS Stream) OpenSSL/3.2.2"),
            Severity::Low
        );
    }

    /// The leading token's own table-only EOL join takes the same severity rule.
    #[test]
    fn leading_token_eol_follows_the_distro_rule() {
        let sv = parse_server_header("PHP/8.1.2-1ubuntu2.14").expect("parsed");
        assert_eq!(
            check_server_version(&sv).expect("eol").severity,
            Severity::Low
        );
        let sv = parse_server_header("PHP/8.1.2").expect("parsed");
        assert_eq!(
            check_server_version(&sv).expect("eol").severity,
            Severity::Medium
        );
    }

    /// The `Server` header's own distribution marker reaches the component join.
    #[test]
    fn header_component_eol_is_low_on_a_distro_build() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let debian = check_header_components(ip, 80, "Apache/2.4.57 (Debian) OpenSSL/1.0.2k");
        assert_eq!(debian.len(), 1);
        assert_eq!(debian[0].severity, Severity::Low);
        let upstream = check_header_components(ip, 80, "Apache/2.4.57 OpenSSL/1.0.2k");
        assert_eq!(upstream.len(), 1);
        assert_eq!(upstream[0].severity, Severity::Medium);
        // Same title either way: only the severity moves.
        assert_eq!(debian[0].title, upstream[0].title);
    }

    #[test]
    fn test_check_header_components_skips_the_leading_token() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // nginx is the leading token: check_server_version's job, not this one.
        assert!(check_header_components(ip, 80, "nginx/1.18.0").is_empty());
        assert_eq!(
            check_header_components(ip, 80, "Apache/2.4.68 PHP/5.6.40").len(),
            1
        );
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
        assert!(
            info.kex_algorithms
                .iter()
                .any(|a| a.contains("group1-sha1"))
        );
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

    #[test]
    fn test_parse_ssh_kex_init_huge_name_list_length() {
        let mut pkt = vec![20u8];
        pkt.extend_from_slice(&[0u8; 16]);
        pkt.extend_from_slice(&u32::MAX.to_be_bytes());
        pkt.extend_from_slice(b"curve25519-sha256");
        assert!(parse_ssh_kex_init(&pkt).is_none());

        let mut pkt = vec![20u8];
        pkt.extend_from_slice(&[0u8; 16]);
        pkt.extend_from_slice(&4u32.to_be_bytes());
        pkt.extend_from_slice(b"a,bb");
        pkt.extend_from_slice(&u32::MAX.to_be_bytes());
        pkt.extend_from_slice(b"xyz");
        let info = parse_ssh_kex_init(&pkt).unwrap();
        assert_eq!(info.kex_algorithms, ["a", "bb"]);
        assert!(info.host_key_algorithms.is_empty());
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
        let latest = eol_db::current("nginx").and_then(|c| c.latest).unwrap();
        let sv = parse_server_header(&format!("nginx/{latest}")).unwrap();
        assert!(check_server_version(&sv).is_none());
    }

    /// The table catches branches the hand-coded `< 1.22` rule lets through.
    #[test]
    fn test_check_nginx_table_catches_post_122_eol() {
        let sv = parse_server_header("nginx/1.26.0").unwrap();
        let issue = check_server_version(&sv).unwrap();
        assert_eq!(issue.severity, Severity::Medium);
        assert_eq!(issue.cwe, Some("CWE-1104"));
        assert!(issue.description.contains("end-of-life on 2025-04-23"));
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
        let findings = classify_http_server(ip, 80, "nginx/1.14.2");
        assert!(findings[0].severity >= Severity::Medium);
        assert!(findings[0].cwe_id.is_some());
    }

    #[test]
    fn test_classify_http_server_unknown_product() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = classify_http_server(ip, 80, "SynoHTTP/1.0");
        // Unknown product → plain version disclosure (Info)
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_classify_http_server_no_version() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = classify_http_server(ip, 80, "cloudflare");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
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
        assert!(
            finding
                .references
                .iter()
                .any(|r| r.contains("CVE-2024-6387"))
        );
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
        // Date is the table's, not a hand-coded one.
        assert!(s.contains("2026-08-31"), "{s}");
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

    /// Trixie is on full security support, so neither tier fires.
    #[test]
    fn test_check_os_eol_debian_trixie_not_eol() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let trixie = eol_db::cycle("debian", "13").expect("debian 13");
        // Guard the wall clock: this stays meaningful only until 2028-08-09.
        assert!(trixie.eoas_from.is_some_and(|d| d > today().as_str()));
        assert!(check_os_eol(ip, 22, "SSH-2.0-OpenSSH_10.0p1 Debian-8+deb13u1").is_none());
    }

    #[test]
    fn test_check_os_eol_ubuntu_bionic_eol() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // 7.6p1-4ubuntu0.3 is bionic; standard security maintenance ended 2023-05-31.
        let finding = check_os_eol(ip, 22, "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3");
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.description.contains("Ubuntu 18.04"), "{}", f.description);
        // The release is inferred from the SSH version, so the finding says so.
        assert_eq!(f.confidence, Confidence::Inferred);
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
    fn test_debian_release_from_banner() {
        assert_eq!(
            debian_release("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u5"),
            Some(11)
        );
        assert_eq!(debian_release("SSH-2.0-OpenSSH_9.5"), None);
    }

    /// Codename and EOL date come from the table, not from this file.
    #[test]
    fn test_debian_release_dates_come_from_the_table() {
        let entry = eol_db::lookup("debian", "11").expect("debian 11");
        assert_eq!(entry.codename, Some("Bullseye"));
        assert_eq!(entry.eol_from, Some("2026-08-31"));
    }

    #[test]
    fn test_ubuntu_from_openssh() {
        assert_eq!(ubuntu_from_openssh(8, 9), ["22.04"]);
        assert_eq!(ubuntu_from_openssh(9, 6), ["24.04"]);
        // 7.6p1 is bionic (18.04), not cosmic: cosmic released with 7.7p1.
        assert_eq!(ubuntu_from_openssh(7, 6), ["18.04"]);
        assert!(ubuntu_from_openssh(10, 0).is_empty());
        // 8.4p1 and 9.0p1 each shipped in two releases; both candidates are kept.
        assert_eq!(ubuntu_from_openssh(8, 4), ["21.04", "21.10"]);
        assert_eq!(ubuntu_from_openssh(9, 0), ["22.10", "23.04"]);
    }

    /// Every mapped release exists in the table, so a hit can always be dated.
    #[test]
    fn test_ubuntu_openssh_map_is_covered_by_the_table() {
        for major in 6..=11 {
            for minor in 0..=12 {
                for release in ubuntu_from_openssh(major, minor) {
                    assert!(
                        eol_db::lookup("ubuntu", release).is_some(),
                        "ubuntu {release} missing from the table"
                    );
                }
            }
        }
    }

    /// An ambiguous OpenSSH version names both candidates, never one of them.
    #[test]
    fn test_check_os_eol_ubuntu_ambiguous_names_both() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let f = check_os_eol(ip, 22, "SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu7.4").unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(
            f.description.contains("Ubuntu 22.10 or 23.04"),
            "{}",
            f.description
        );
        // 23.04 is the later of the two, so it is the safe claim.
        assert!(
            f.description.contains("no later than 2024-01-20"),
            "{}",
            f.description
        );
        assert_eq!(f.confidence, Confidence::Inferred);
    }

    /// Debian between its own security-team end and its LTS end is Medium, not High.
    #[test]
    fn test_check_os_eol_debian_lts_only_tier() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let bookworm = eol_db::cycle("debian", "12").expect("debian 12");
        let f = check_os_eol(ip, 22, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u5");
        if eol_db::is_eol_on(bookworm, &today()) {
            // Past the LTS date the High tier takes over; this test then only
            // asserts that something still fires.
            assert_eq!(f.expect("debian 12 finding").severity, Severity::High);
            return;
        }
        let eoas = bookworm.eoas_from.expect("debian 12 eoas date");
        if eoas <= today().as_str() {
            let f = f.expect("debian 12 LTS-only finding");
            assert_eq!(f.severity, Severity::Medium);
            assert!(
                f.title.contains("security-team support only"),
                "{}",
                f.title
            );
            assert!(f.description.contains(eoas), "{}", f.description);
        } else {
            assert!(f.is_none(), "still on full security support");
        }
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

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn parse_smtp_ehlo_multibyte_after_code_does_not_panic() {
        // "250é": byte 4 is inside the 2-byte 'é'.
        let info = parse_smtp_ehlo("250é\n");
        assert!(info.extensions.is_empty() || !info.extensions[0].is_empty());
    }

    #[test]
    fn extract_ssh_version_non_ascii_prefix_does_not_panic() {
        // 'İ' (U+0130) lowercases to 3 bytes, shifting byte offsets.
        assert_eq!(extract_ssh_version("SSH-2.0-İOpenSSH_8.2"), Some((8, 2)));
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    fn ymd_strategy() -> impl Strategy<Value = chrono::NaiveDate> {
        (1_i32..=9999, 1_u32..=12, 1_u32..=28)
            .prop_map(|(y, m, d)| chrono::NaiveDate::from_ymd_opt(y, m, d).unwrap())
    }

    /// Arbitrary strings plus headers that reach every `check_server_version` arm.
    fn server_header_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            ".*",
            "(nginx|Apache|lighttpd|Microsoft-IIS|openresty|mini_httpd|MiniServ|Jetty)/[0-9]{1,10}(\\.[0-9]{1,10}){0,3}( \\(.*\\))?",
            "Jetty\\([0-9]{1,10}(\\.[0-9]{1,10}){0,3}\\)",
        ]
    }

    /// Banner spellings that `eol_product` maps, paired with the table product.
    const MAPPED_TOKENS: &[(&str, &str)] = &[
        ("nginx", "nginx"),
        ("Apache", "apache-http-server"),
        ("httpd", "apache-http-server"),
        ("Jetty", "eclipse-jetty"),
        ("OpenSSL", "openssl"),
        ("Python", "python"),
        ("PHP", "php"),
    ];

    /// `name/version` tokens built from real table cycles, so the join is
    /// actually exercised: a bare `".*"` strategy reaches a finding in roughly
    /// one run in a thousand, which makes any assertion inside the loop vacuous.
    fn real_tokens() -> Vec<String> {
        MAPPED_TOKENS
            .iter()
            .flat_map(|(token, product)| {
                eol_db::product_cycles(product).iter().flat_map(move |row| {
                    // Bare cycle and a patch release on it; both must resolve.
                    [
                        format!("{token}/{}", row.cycle),
                        format!("{token}/{}.3", row.cycle),
                    ]
                })
            })
            .collect()
    }

    /// Guards `prop_check_header_components_no_panic` against going vacuous:
    /// its assertions sit inside `for finding in ...`, so they only mean
    /// something while the strategy still reaches findings. Measured ~55%.
    #[test]
    fn arb_server_header_reaches_findings() {
        use proptest::test_runner::{Config, TestRunner};
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let mut runner = TestRunner::new(Config {
            cases: 256,
            ..Config::default()
        });
        let hits = std::cell::Cell::new(0_u32);
        runner
            .run(&arb_server_header(), |server| {
                if !check_header_components(ip, 443, &server).is_empty() {
                    hits.set(hits.get() + 1);
                }
                Ok(())
            })
            .unwrap();
        assert!(hits.get() > 20, "only {} of 256 samples fired", hits.get());
    }

    /// `Server`-shaped headers that reach the end-of-life join: a leading
    /// product token (which the parser skips) followed by real product/version
    /// pairs, mixed with junk and unmapped products.
    fn arb_server_header() -> impl Strategy<Value = String> {
        let token = prop_oneof![
            6 => prop::sample::select(real_tokens()),
            1 => (
                prop::sample::select(vec!["mysql", "redis", "lighttpd", "cowboy"]),
                "[0-9]{1,2}(\\.[0-9]{1,2}){0,3}",
            )
                .prop_map(|(name, version)| format!("{name}/{version}")),
            1 => "[!-~]{0,12}".prop_map(String::from),
        ];
        prop_oneof![
            1 => any::<String>(),
            9 => prop::collection::vec(token, 1..5).prop_map(|parts| parts.join(" ")),
        ]
    }

    const SERVER_PRODUCTS: &[&str] = &[
        "nginx",
        "apache",
        "lighttpd",
        "microsoft-iis",
        "openresty",
        "mini_httpd",
        "mini-httpd",
        "minihttpd",
        "miniserv",
        "jetty",
        "other",
    ];

    proptest! {
        /// `parse_debian_version` never panics; a hit names a Debian release.
        #[test]
        fn prop_parse_debian_version_total(banner in ".*") {
            if let Some(os) = parse_debian_version(&banner) {
                prop_assert!(os.contains("Debian "), "{}", os);
            }
        }

        /// `+deb<N>` always yields `Linux (Debian <N>` followed by ` ` or `)`.
        #[test]
        fn prop_parse_debian_version_hit(
            prefix in "[^+]*",
            version in 0_u32..1000,
            tail in "([^0-9].*)?",
        ) {
            let os = parse_debian_version(&format!("{prefix}+deb{version}{tail}"));
            let head = format!("Linux (Debian {version}");
            let rest = os.as_deref().and_then(|s| s.strip_prefix(head.as_str()));
            prop_assert!(rest.is_some_and(|r| r.starts_with(' ') || r.starts_with(')')), "{:?}", os);
        }

        /// `parse_ubuntu_version` never panics; a hit names an Ubuntu release.
        #[test]
        fn prop_parse_ubuntu_version_total(banner in ".*") {
            if let Some(os) = parse_ubuntu_version(&banner) {
                prop_assert!(os.contains("Ubuntu "), "{}", os);
            }
        }

        /// `OpenSSH_<M>.<m>` round-trips through `extract_ssh_version`; the Ubuntu hit matches the table.
        #[test]
        fn prop_openssh_version_roundtrip(
            prefix in "(SSH-2\\.0-)?",
            major in 0_u32..20,
            minor in 0_u32..20,
            tail in "(p[0-9].*)?",
        ) {
            let banner = format!("{prefix}OpenSSH_{major}.{minor}{tail}");
            prop_assert_eq!(extract_ssh_version(&banner), Some((major, minor)));
            prop_assert_eq!(
                parse_ubuntu_version(&banner).is_some(),
                !ubuntu_from_openssh(major, minor).is_empty()
            );
        }

        /// `parse_version_numbers` never panics.
        #[test]
        fn prop_parse_version_numbers_no_panic(version in ".*") {
            let _ = parse_version_numbers(&version);
        }

        /// `parse_version_numbers` round-trips `a.b.c` with any non-numeric suffix.
        #[test]
        fn prop_parse_version_numbers_roundtrip(
            major in any::<u32>(),
            minor in any::<u32>(),
            patch in any::<u32>(),
            tail in "([^0-9.].*)?",
        ) {
            let version = format!("{major}.{minor}.{patch}{tail}");
            prop_assert_eq!(parse_version_numbers(&version), Some((major, minor, patch)));
        }

        /// `product/a.b.c` parses to the lowercased product, exact numbers and raw header.
        #[test]
        fn prop_parse_server_header_roundtrip(
            product in "[A-Za-z][A-Za-z0-9_-]{0,15}",
            major in any::<u32>(),
            minor in any::<u32>(),
            patch in any::<u32>(),
            tail in "( \\(.*\\))?",
        ) {
            let header = format!("{product}/{major}.{minor}.{patch}{tail}");
            let expected = ServerVersion {
                product: product.to_lowercase(),
                major,
                minor,
                patch,
                raw: header.clone(),
            };
            prop_assert_eq!(parse_server_header(&header), Some(expected));
        }

        /// `parse_server_header` then `check_server_version` never panics on any header.
        #[test]
        fn prop_check_server_version_from_header_no_panic(header in server_header_strategy()) {
            let _ = parse_server_header(&header).and_then(|sv| check_server_version(&sv));
        }

        /// `check_server_version` never panics for any product and version numbers.
        #[test]
        fn prop_check_server_version_no_panic(
            product in proptest::sample::select(SERVER_PRODUCTS),
            major in any::<u32>(),
            minor in any::<u32>(),
            patch in any::<u32>(),
        ) {
            let sv = ServerVersion {
                product: product.to_owned(),
                major,
                minor,
                patch,
                raw: format!("{product}/{major}.{minor}.{patch}"),
            };
            let _ = check_server_version(&sv);
        }

        /// The EOL verdict is monotone in the clock: once EOL, always EOL.
        #[test]
        fn prop_eol_verdict_is_monotone_in_time(
            first in ymd_strategy(),
            second in ymd_strategy(),
        ) {
            let (early, late) = if first <= second { (first, second) } else { (second, first) };
            for entry in ["1.18", "1.30"].iter().filter_map(|c| eol_db::cycle("nginx", c)) {
                let early_eol = eol_db::is_eol_on(entry, &early.format("%Y-%m-%d").to_string());
                let late_eol = eol_db::is_eol_on(entry, &late.format("%Y-%m-%d").to_string());
                prop_assert!(late_eol || !early_eol);
            }
        }

        /// `check_header_components` never panics on arbitrary `Server` headers.
        #[test]
        fn prop_check_header_components_no_panic(server in arb_server_header()) {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            for finding in check_header_components(ip, 443, &server) {
                prop_assert!(finding.title.starts_with("End-of-life "));
                prop_assert_eq!(finding.severity, Severity::Medium);
                prop_assert_eq!(finding.cwe_id.as_deref(), Some("CWE-1104"));
            }
        }

        /// Findings only ever name a mapped product, and the first token is never judged.
        #[test]
        fn prop_check_header_components_only_maps_known_products(
            server in arb_server_header(),
        ) {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            for finding in check_header_components(ip, 443, &server) {
                let product = finding
                    .title
                    .strip_prefix("End-of-life ")
                    .and_then(|rest| rest.split(' ').next())
                    .unwrap_or("");
                prop_assert!(
                    !eol_db::product_cycles(product).is_empty(),
                    "{}",
                    finding.title
                );
            }
        }

        /// The first token names the server itself and is judged by
        /// `check_server_version`, not here — so a one-token header is silent
        /// however end-of-life that token is.
        #[test]
        fn prop_check_header_components_skips_the_first_token(
            server in arb_server_header(),
        ) {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            let Some(leading) = server.split_whitespace().next() else {
                return Ok(());
            };
            prop_assert!(check_header_components(ip, 443, leading).is_empty(), "{leading}");
        }

        /// `check_os_eol` never panics on arbitrary Debian/Ubuntu-flavoured banners.
        #[test]
        fn prop_check_os_eol_no_panic(banner in ".*") {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            let _ = check_os_eol(ip, 22, &banner);
            let _ = check_os_eol(ip, 22, &format!("SSH-2.0-OpenSSH_9.2p1 Debian-{banner}"));
            let _ = check_os_eol(ip, 22, &format!("SSH-2.0-OpenSSH_{banner} Ubuntu"));
        }
    }
}

#[cfg(test)]
mod backdoor_ssh_tests {
    use super::*;
    use proptest::prelude::*;

    const GW: &str = "192.168.1.1";
    const HOST: &str = "192.168.1.50";
    const CVE: &str = "CVE-2023-39780";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Real ASUS/Dropbear identification string (RT-AX55 firmware line).
    const DROPBEAR_BANNER: &str = "SSH-2.0-dropbear_2020.81";

    /// An ASUS access point that is not the gateway.
    const ASUS_AP: HostRole = HostRole {
        is_gateway: false,
        router_like: true,
        is_asus: true,
    };

    /// The gateway, identified as ASUS hardware.
    const ASUS_GATEWAY: HostRole = HostRole {
        is_gateway: true,
        router_like: true,
        is_asus: true,
    };

    #[test]
    fn ssh_banner_recognised() {
        assert!(is_ssh_banner("SSH-2.0-OpenSSH_9.6"));
        assert!(is_ssh_banner(DROPBEAR_BANNER));
        assert!(is_ssh_banner("SSH-1.99-Cisco-1.25"));
        // Pre-identification lines are allowed before the ident string.
        assert!(is_ssh_banner(
            "Authorized users only\r\nSSH-2.0-OpenSSH_8.4"
        ));
        // Case-insensitive per RFC 4253 readers in the wild.
        assert!(is_ssh_banner("ssh-2.0-x"));
    }

    #[test]
    fn non_ssh_banner_rejected() {
        assert!(!is_ssh_banner(""));
        assert!(!is_ssh_banner("220 ProFTPD Server ready"));
        assert!(!is_ssh_banner("HTTP/1.0 200 OK"));
        assert!(!is_ssh_banner("SSH"));
        assert!(!is_ssh_banner("SSH-"));
        // "SSH" must lead the line, not merely appear in it.
        assert!(!is_ssh_banner("welcome to SSH-2.0"));
    }

    #[test]
    fn public_key_material_is_not_an_identification_string() {
        // RFC 4253 protoversion is numeric; key-type prefixes are not.
        assert!(!is_ssh_banner(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB user@host"
        ));
        assert!(!is_ssh_banner("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
        assert!(!is_ssh_banner("ssh-dss AAAAB3NzaC1kc3MAAACB"));
        assert!(!is_ssh_banner("Ssh-rsa AAAAB3NzaC1yc2E"));
        assert!(!is_ssh_banner("ecdsa-sha2-nistp256 AAAAE2VjZHNh"));
    }

    #[test]
    fn ssh_banner_multibyte_prefix_does_not_panic() {
        assert!(!is_ssh_banner("İSSH-2.0-OpenSSH_8.2"));
        assert!(!is_ssh_banner("İİ"));
    }

    #[test]
    fn ayysshush_port_on_asus_router_is_critical_and_confirmed() {
        let f = classify_backdoor_ssh(ip(GW), 53282, DROPBEAR_BANNER, ASUS_GATEWAY).unwrap();
        assert_eq!(f.title, "ASUS AyySSHush SSH backdoor listener on TCP/53282");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert_eq!(f.affected_port, Some(53282));
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-78"));
        assert!(f.cve_ids.iter().any(|c| c == CVE));
        assert_eq!(f.evidence.as_deref(), Some(DROPBEAR_BANNER));
        // Firmware update is not remediation: the key lives in NVRAM.
        let rem = f.remediation.unwrap();
        assert!(rem.steps.iter().any(|s| s.contains("Factory reset")));
    }

    #[test]
    fn ayysshush_port_on_asus_access_point_is_also_critical() {
        let f = classify_backdoor_ssh(ip(HOST), 53282, DROPBEAR_BANNER, ASUS_AP).unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.confidence, Confidence::Confirmed);
    }

    #[test]
    fn ayysshush_port_on_an_ordinary_host_is_not_attributed() {
        // A published container port reaches 53282 too; the protocol answer only
        // confirms "SSH listens here", not "this router is backdoored".
        let f = classify_backdoor_ssh(ip(HOST), 53282, "SSH-2.0-OpenSSH_9.6", HostRole::UNKNOWN)
            .unwrap();
        assert_eq!(
            f.title,
            "SSH server on TCP/53282, the AyySSHush backdoor port"
        );
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Probable);
        assert_eq!(f.affected_port, Some(53282));
        assert!(f.cve_ids.is_empty(), "no CVE asserted without attribution");
        let rem = f.remediation.unwrap();
        assert!(!rem.steps.iter().any(|s| s.starts_with("Factory reset")));
    }

    /// CVE-2023-39780 is ASUS-only: a non-ASUS gateway (`OpenWrt`, pfSense, a
    /// Linux box) gets the vendor-neutral finding, not a factory-reset order.
    #[test]
    fn ayysshush_port_on_a_non_asus_gateway_is_not_attributed() {
        let f =
            classify_backdoor_ssh(ip(GW), 53282, "SSH-2.0-OpenSSH_9.6", HostRole::GATEWAY).unwrap();
        assert_eq!(
            f.title,
            "SSH server on TCP/53282, the AyySSHush backdoor port"
        );
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Probable);
        assert!(
            f.cve_ids.is_empty(),
            "{CVE} does not apply to this hardware"
        );
    }

    /// ASUS is read from the vendor alone; hostname and OS guess are the
    /// scanned host's own claims.
    #[test]
    fn host_role_identifies_asus_hardware() {
        let mut d = Device::new(ip(HOST));
        assert!(!HostRole::of_device(&d, true).is_asus, "gateway alone");

        d.vendor = Some("ASUSTek COMPUTER INC.".to_owned());
        assert!(HostRole::of_device(&d, false).is_asus);

        d.vendor = None;
        d.hostname = Some("RT-AX55-asus.lan".to_owned());
        d.os_guess = Some("ASUSWRT 3.0.0.4".to_owned());
        assert!(
            !HostRole::of_device(&d, false).is_asus,
            "mDNS name and banner hint are claims, not hardware"
        );
    }

    /// Token match, not substring: `Pegasus` is a real OUI vendor.
    #[test]
    fn a_pegasus_host_is_not_asus_hardware() {
        let mut d = Device::new(ip(HOST));
        d.vendor = Some("Pegasus Technologies".to_owned());
        d.hostname = Some("pegasus.lan".to_owned());
        let role = HostRole::of_device(&d, false);
        assert!(!role.is_asus);
        assert!(!role.router_like, "and it is not probed as a router");

        let f = classify_backdoor_ssh(ip(HOST), 53282, "SSH-2.0-OpenSSH_9.6", role).unwrap();
        assert_eq!(
            f.title,
            "SSH server on TCP/53282, the AyySSHush backdoor port"
        );
        assert!(f.cve_ids.is_empty());
    }

    /// The firmware banner attributes too; `dropbear` alone does not, since
    /// `OpenWrt` ships it.
    #[test]
    fn an_asuswrt_banner_attributes_without_vendor_data() {
        let f = classify_backdoor_ssh(ip(GW), 53282, "SSH-2.0-asuswrt_dropbear", HostRole::GATEWAY)
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.confidence, Confidence::Confirmed);

        let f = classify_backdoor_ssh(ip(GW), 53282, DROPBEAR_BANNER, HostRole::GATEWAY).unwrap();
        assert_eq!(f.confidence, Confidence::Probable);
        assert!(f.cve_ids.is_empty());
    }

    #[test]
    fn ayysshush_port_without_ssh_banner_is_not_flagged() {
        for role in [HostRole::GATEWAY, HostRole::UNKNOWN] {
            assert!(classify_backdoor_ssh(ip(GW), 53282, "HTTP/1.1 404 Not Found", role).is_none());
            assert!(classify_backdoor_ssh(ip(GW), 53282, "", role).is_none());
        }
    }

    #[test]
    fn gateway_ssh_on_odd_high_port_is_high_probable() {
        let f = classify_backdoor_ssh(ip(GW), 41253, DROPBEAR_BANNER, HostRole::GATEWAY).unwrap();
        assert_eq!(
            f.title,
            "SSH listening on a non-standard port on the gateway"
        );
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Probable);
        assert_eq!(f.affected_port, Some(41253));
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-912"));
        // Probable, so the remediation checks intent before the destructive step.
        let rem = f.remediation.unwrap();
        assert!(rem.steps[0].contains("administration UI"));
        assert!(rem.steps[0].contains("41253"));
        assert!(rem.steps.iter().any(|s| s.contains("factory reset")));
    }

    #[test]
    fn gateway_ssh_on_conventional_alt_port_is_only_medium() {
        for port in [222, 2022, 2222, 22222] {
            let f = classify_backdoor_ssh(ip(GW), port, "SSH-2.0-OpenSSH_9.6", HostRole::GATEWAY)
                .unwrap();
            assert_eq!(f.severity, Severity::Medium, "port {port}");
            assert_eq!(f.confidence, Confidence::Probable, "port {port}");
        }
    }

    #[test]
    fn gateway_ssh_on_port_22_is_not_flagged() {
        assert!(
            classify_backdoor_ssh(ip(GW), 22, "SSH-2.0-OpenSSH_9.6", HostRole::GATEWAY).is_none()
        );
    }

    #[test]
    fn non_gateway_ssh_on_odd_port_is_not_flagged() {
        // Moving SSH on an ordinary host is routine; only the gateway matters here.
        for role in [HostRole::UNKNOWN, ASUS_AP] {
            assert!(classify_backdoor_ssh(ip(HOST), 2222, "SSH-2.0-OpenSSH_9.6", role).is_none());
            assert!(classify_backdoor_ssh(ip(HOST), 41253, DROPBEAR_BANNER, role).is_none());
        }
    }

    #[test]
    fn titles_are_stable_across_hosts_and_ports() {
        let a = classify_backdoor_ssh(ip(GW), 53282, "SSH-2.0-A", ASUS_GATEWAY).unwrap();
        let b = classify_backdoor_ssh(ip(HOST), 53282, "SSH-2.0-B", ASUS_AP).unwrap();
        assert_eq!(a.title, b.title);

        let c = classify_backdoor_ssh(ip(GW), 41253, "SSH-2.0-A", HostRole::GATEWAY).unwrap();
        let d = classify_backdoor_ssh(ip(GW), 8022, "SSH-2.0-B", HostRole::GATEWAY).unwrap();
        assert_eq!(c.title, d.title);
        assert_ne!(c.fingerprint(), d.fingerprint(), "port separates them");
    }

    #[test]
    fn banner_classifier_reaches_ssh_on_non_standard_ports() {
        // Before 53282 was added, an SSH banner off port 22 fell through to the
        // generic "Service banner" arm and lost CVE correlation.
        let f = classify_banner(ip(GW), 53282, "SSH-2.0-OpenSSH_8.9p1").unwrap();
        assert_eq!(f.affected_service.as_deref(), Some("SSH"));
    }

    /// Ports the HTTP audit never visits stay identified at every intensity.
    #[test]
    fn recog_identifies_http_ports_the_audit_skips() {
        for port in [5000u16, 8008, 8444, 8880, 9000, 9443] {
            assert!(is_likely_http_port(port) || HTTP_PORTS.contains(&port));
            assert!(
                !crate::http_audit::AUDIT_PORTS.contains(&port),
                "{port} is audited"
            );
            assert!(recog_identifies_http(port, true), "{port} at Active");
            assert!(recog_identifies_http(port, false), "{port} at Passive");
        }
        // The audit's own ports are left to it at Active+ only.
        for &port in crate::http_audit::AUDIT_PORTS {
            assert!(!recog_identifies_http(port, true), "{port} at Active");
            assert!(recog_identifies_http(port, false), "{port} at Passive");
        }
    }

    #[test]
    fn backdoor_port_is_reachable_by_the_banner_pass() {
        assert_eq!(AYYSSHUSH_PORT, 53282);
        assert!(BANNER_PORTS.contains(&AYYSSHUSH_PORT));
        assert!(ServicesScanner.relevant_ports().contains(&AYYSSHUSH_PORT));
    }

    #[test]
    fn host_role_marks_routers_and_asus_hardware() {
        let mut d = Device::new(ip(HOST));
        assert!(!HostRole::of_device(&d, false).router_like);
        assert!(
            HostRole::of_device(&d, true).router_like,
            "gateway is a router"
        );
        assert!(HostRole::of_device(&d, true).is_gateway);

        d.device_type = DeviceType::Router;
        assert!(HostRole::of_device(&d, false).router_like);

        d.device_type = DeviceType::AccessPoint;
        assert!(HostRole::of_device(&d, false).router_like);

        d.device_type = DeviceType::Unknown;
        d.vendor = Some("ASUSTek COMPUTER INC.".to_owned());
        assert!(HostRole::of_device(&d, false).router_like);

        d.vendor = Some("Raspberry Pi Trading Ltd".to_owned());
        assert!(!HostRole::of_device(&d, false).router_like);
    }

    fn arp(ip_s: &str, mac: &str) -> ArpEntry {
        ArpEntry {
            ip: ip(ip_s),
            mac: mac.to_owned(),
            interface: "eth0".to_owned(),
        }
    }

    fn exclusions(nets: &[&str], devices: &[&str]) -> ExclusionSet {
        let nets: Vec<String> = nets.iter().map(|s| (*s).to_owned()).collect();
        let devices: Vec<String> = devices.iter().map(|s| (*s).to_owned()).collect();
        ExclusionSet::parse(&nets, &devices).unwrap()
    }

    #[test]
    fn arp_clears_ip_honours_mac_exclusions() {
        let entries = [arp(GW, "aa:bb:cc:dd:ee:ff"), arp(HOST, "11:22:33:44:55:66")];

        // The gateway excluded by MAC only: its IP is not listed, so an IP-only
        // check would wave it through.
        let by_mac = exclusions(&[], &["AA:BB:CC:DD:EE:FF"]);
        assert!(!by_mac.excludes_ip(ip(GW)));
        assert!(!arp_clears_ip(&entries, ip(GW), &by_mac));
        assert!(arp_clears_ip(&entries, ip(HOST), &by_mac));

        assert!(!arp_clears_ip(&entries, ip(GW), &exclusions(&[], &[GW])));
        assert!(!arp_clears_ip(
            &entries,
            ip(GW),
            &exclusions(&["192.168.1.0/24"], &[])
        ));
    }

    #[test]
    fn arp_clears_ip_refuses_an_unresolvable_address() {
        let entries = [arp(HOST, "11:22:33:44:55:66")];
        let set = exclusions(&[], &["AA:BB:CC:DD:EE:FF"]);
        // No ARP entry, so no MAC to clear against the exclusion list.
        assert!(!arp_clears_ip(&entries, ip(GW), &set));
        // An unparsable MAC is no evidence either.
        assert!(!arp_clears_ip(&[arp(GW, "(incomplete)")], ip(GW), &set));
    }

    #[test]
    fn unvouched_probe_allowed_without_exclusions_skips_the_arp_read() {
        assert!(unvouched_probe_allowed(ip(GW), &ExclusionSet::default()));
    }

    #[test]
    fn select_banner_targets_drops_excluded_ip_cidr_and_mac() {
        let entries = [
            arp("192.168.1.10", "aa:aa:aa:aa:aa:aa"),
            arp("192.168.1.40", "bb:bb:bb:bb:bb:bb"),
            arp("192.168.1.41", "cc:cc:cc:cc:cc:cc"),
            arp("10.0.0.2", "dd:dd:dd:dd:dd:dd"),
            arp("172.16.0.5", "ee:ee:ee:ee:ee:ee"),
        ];
        let set = exclusions(&["10.0.0.0/30"], &["192.168.1.40", "CC:CC:CC:CC:CC:CC"]);
        let in_scope = |i: IpAddr| !matches!(i, IpAddr::V4(v4) if v4.octets()[0] == 172);
        assert_eq!(
            select_banner_targets(&entries, in_scope, &set),
            vec![ip("192.168.1.10")]
        );
    }

    /// Drive the direct probe against a one-shot local server on an ephemeral
    /// port, so the test never depends on 53282 being free.
    async fn probe_fake_server(greeting: &'static str, role: HostRole) -> (u16, Option<Finding>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind ephemeral loopback port");
        let port = listener.local_addr().expect("local_addr").port();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(greeting.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        let finding = probe_ssh_port(ip("127.0.0.1"), port, role).await;
        server.abort();
        let _ = server.await;
        (port, finding)
    }

    #[tokio::test]
    async fn probe_reports_an_ssh_server_answering_where_it_should_not() {
        let (port, finding) =
            probe_fake_server("SSH-2.0-dropbear_2020.81\r\n", HostRole::GATEWAY).await;
        let f = finding.expect("SSH banner on the gateway's odd port must be reported");
        assert_eq!(
            f.title,
            "SSH listening on a non-standard port on the gateway"
        );
        assert_eq!(f.confidence, Confidence::Probable);
        assert_eq!(f.affected_port, Some(port));
        assert_eq!(f.affected_ip, Some(ip("127.0.0.1")));
    }

    #[tokio::test]
    async fn probe_ignores_a_non_ssh_server() {
        let (_, finding) =
            probe_fake_server("HTTP/1.1 400 Bad Request\r\n", HostRole::GATEWAY).await;
        assert!(finding.is_none(), "an HTTP server is not an SSH backdoor");
    }

    #[tokio::test]
    async fn probe_reports_nothing_when_the_port_is_closed() {
        // Bind, note the port, drop the listener: nothing is listening there.
        let port = {
            let l = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            l.local_addr().unwrap().port()
        };
        assert!(
            probe_ssh_port(ip("127.0.0.1"), port, HostRole::GATEWAY)
                .await
                .is_none()
        );
    }

    proptest! {
        /// `is_ssh_banner` never panics on arbitrary text.
        #[test]
        fn prop_is_ssh_banner_no_panic(s in ".*") {
            let _ = is_ssh_banner(&s);
        }

        /// `classify_backdoor_ssh` never panics on arbitrary bytes off the wire,
        /// and only fires when the peer sent an SSH identification string.
        #[test]
        fn prop_classify_backdoor_ssh_no_panic(
            data in proptest::collection::vec(any::<u8>(), 0..512),
            port in any::<u16>(),
            is_gateway in any::<bool>(),
            router_like in any::<bool>(),
            is_asus in any::<bool>(),
        ) {
            let role = HostRole {
                is_gateway,
                router_like: router_like || is_gateway,
                is_asus,
            };
            let banner = String::from_utf8_lossy(&data);
            let out = classify_backdoor_ssh(ip(GW), port, &banner, role);
            if let Some(f) = out {
                prop_assert!(is_ssh_banner(&banner));
                prop_assert!(port == AYYSSHUSH_PORT || (role.is_gateway && port != 22));
                // Campaign attribution only where ASUS is named.
                if f.confidence == Confidence::Confirmed {
                    prop_assert!(role.is_asus || names_asus(&banner));
                    prop_assert_eq!(port, AYYSSHUSH_PORT);
                }
            }
        }

        /// An SSH banner on 53282 is always reported; Critical only on ASUS
        /// hardware, and never attributed to the campaign otherwise.
        #[test]
        fn prop_ayysshush_port_always_reported(
            software in "[ -~]{0,64}",
            is_asus in any::<bool>(),
        ) {
            let role = HostRole { is_gateway: false, router_like: true, is_asus };
            let banner = format!("SSH-2.0-{software}");
            let f = classify_backdoor_ssh(ip(GW), AYYSSHUSH_PORT, &banner, role).unwrap();
            if is_asus || names_asus(&banner) {
                prop_assert_eq!(f.severity, Severity::Critical);
                prop_assert_eq!(f.confidence, Confidence::Confirmed);
            } else {
                prop_assert_eq!(f.confidence, Confidence::Probable);
                prop_assert!(f.cve_ids.is_empty());
            }
        }
    }
}
