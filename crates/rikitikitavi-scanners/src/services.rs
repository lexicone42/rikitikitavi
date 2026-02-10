use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, Remediation, ScanContext};
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
            .with_remediation(Remediation {
                description: "Enable Redis authentication and restrict network access.".to_owned(),
                steps: vec![
                    "Edit redis.conf and set 'requirepass <strong-password>'.".to_owned(),
                    "Bind Redis to 127.0.0.1 if only local access is needed.".to_owned(),
                    "Use firewall rules to restrict port 6379 access.".to_owned(),
                ],
                effort: Some("10 minutes".to_owned()),
            }),
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
            .with_remediation(Remediation {
                description: "Restrict MySQL network access.".to_owned(),
                steps: vec![
                    "Edit my.cnf and set 'bind-address = 127.0.0.1' to bind to localhost only.".to_owned(),
                    "Remove any 'skip-networking' comments and ensure it is not exposed.".to_owned(),
                    "Use firewall rules to block external access to port 3306.".to_owned(),
                ],
                effort: Some("10 minutes".to_owned()),
            }),
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
            .with_remediation(Remediation {
                description: "Restrict PostgreSQL network access.".to_owned(),
                steps: vec![
                    "Edit postgresql.conf and set \"listen_addresses = 'localhost'\".".to_owned(),
                    "Review pg_hba.conf to restrict which hosts can connect.".to_owned(),
                    "Use firewall rules to block external access to port 5432.".to_owned(),
                ],
                effort: Some("10 minutes".to_owned()),
            }),
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
                .with_remediation(Remediation {
                    description: "Secure the embedded SSH service.".to_owned(),
                    steps: vec![
                        "Change default credentials on the device immediately.".to_owned(),
                        "Check the vendor for firmware updates with patched Dropbear.".to_owned(),
                        "Restrict SSH access to this device via firewall rules.".to_owned(),
                        "Consider disabling SSH if remote access is not needed.".to_owned(),
                    ],
                    effort: Some("10 minutes".to_owned()),
                }),
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
                .with_remediation(Remediation {
                    description: "Upgrade to a supported OpenSSH version immediately.".to_owned(),
                    steps: vec![
                        "Update OpenSSH via your package manager (apt, yum, etc.).".to_owned(),
                        "For EOL operating systems, plan a full OS upgrade.".to_owned(),
                        "After upgrading, regenerate host keys if they use DSA.".to_owned(),
                    ],
                    effort: Some("15 minutes".to_owned()),
                });
        } else if severity == Severity::Medium {
            finding = finding.with_remediation(Remediation {
                description: "Upgrade SSH to a current supported version.".to_owned(),
                steps: vec![
                    "Update the SSH server package via your system's package manager.".to_owned(),
                    "For embedded devices, check for firmware updates from the vendor.".to_owned(),
                    "After upgrading, restart the SSH service and verify the new version.".to_owned(),
                ],
                effort: Some("10 minutes".to_owned()),
            });
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
    }
}
