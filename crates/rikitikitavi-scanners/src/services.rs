use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Scanner;

/// Banner-grabbing services scanner — connects to common service ports,
/// reads banners, and identifies versions and potential vulnerabilities.
pub struct ServicesScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const BANNER_TIMEOUT: Duration = Duration::from_secs(5);

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
            .with_cwe("CWE-306"),
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
            .with_cwe("CWE-284"),
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
            .with_cwe("CWE-284"),
        );
    }

    // SSH version disclosure
    if port == 22 && banner_lower.contains("ssh") {
        let severity = if banner_lower.contains("openssh")
            && extract_ssh_major_version(banner).is_some_and(|v| v < 8)
        {
            Severity::Medium
        } else {
            Severity::Low
        };

        let title = if severity == Severity::Medium {
            format!("Outdated SSH version on {ip}:{port}")
        } else {
            format!("SSH version disclosure on {ip}:{port}")
        };

        return Some(
            Finding::new("services", &title, &format!("SSH banner: {banner}"), severity)
                .with_ip(ip)
                .with_port(port)
                .with_service("SSH"),
        );
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

#[async_trait]
impl Scanner for ServicesScanner {
    fn id(&self) -> &'static str {
        "services"
    }

    fn name(&self) -> &'static str {
        "Service Banner Grabbing"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[Perspective::Authenticated, Perspective::Privileged]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running service banner scan");

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

        let mut findings = Vec::new();

        for &ip in &targets {
            // Banner ports (service speaks first)
            for &port in BANNER_PORTS {
                if let Some(banner) = grab_banner(ip, port).await {
                    if let Some(finding) = classify_banner(ip, port, &banner) {
                        findings.push(finding);
                    }
                }
            }

            // HTTP ports (we send request)
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
