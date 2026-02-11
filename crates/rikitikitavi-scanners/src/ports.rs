use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::config::PortRange;
use rikitikitavi_models::{Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::Scanner;

/// Port scanner — async TCP connect scanning with service identification.
pub struct PortScanner;

/// Result of probing a single port.
struct PortResult {
    ip: IpAddr,
    port: u16,
    open: bool,
}

/// Map a port number to a well-known service name.
const fn port_to_service(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPCBind",
        135 => "MSRPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        548 => "AFP",
        554 => "RTSP",
        587 => "Submission",
        631 => "IPP",
        993 => "IMAPS",
        995 => "POP3S",
        1080 => "SOCKS",
        1433 => "MSSQL",
        1883 => "MQTT",
        1900 => "SSDP/UPnP",
        2049 => "NFS",
        3306 => "MySQL",
        3389 => "RDP",
        5000 => "UPnP/DLNA",
        5060 => "SIP",
        5353 => "mDNS",
        5432 => "PostgreSQL",
        5900 => "VNC",
        5985 => "WinRM-HTTP",
        5986 => "WinRM-HTTPS",
        6379 => "Redis",
        6667 => "IRC",
        8080 => "HTTP-Proxy",
        8443 => "HTTPS-Alt",
        8883 => "MQTT-TLS",
        8888 => "HTTP-Alt",
        9100 => "RAW-Printing",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        49152 => "UPnP",
        _ => "Unknown",
    }
}

/// Common ports for a home network scan (~40 ports).
fn common_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 548, 554, 587, 631,
        993, 995, 1080, 1433, 1883, 1900, 2049, 3306, 3389, 5000, 5060, 5353, 5432, 5900,
        6379, 6667, 8080, 8443, 8883, 8888, 9100, 9200, 27017, 49152,
    ]
}

/// Extended port list (~100 ports).
fn extended_ports() -> Vec<u16> {
    let mut ports = common_ports();
    ports.extend_from_slice(&[
        20, 69, 88, 113, 119, 123, 137, 138, 161, 162, 179, 389, 427, 500, 514, 515, 520,
        523, 546, 547, 636, 873, 902, 990, 992, 1194, 1701, 1723, 1812, 1813, 2000, 2082,
        2083, 2086, 2087, 2222, 3000, 3128, 3268, 3269, 3690, 4443, 4444, 4567, 5001, 5004,
        5005, 5050, 5051, 5222, 5269, 5357, 5800, 5901, 5938, 6000, 6001, 6443, 6881, 7070,
        7443, 7547, 8000, 8008, 8081, 8090, 8291, 8444, 8880, 8889, 9000, 9001, 9090, 9091,
        9443, 10000, 11211, 27018, 50000,
    ]);
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Get ports to scan based on the configured range.
fn get_ports(range: &PortRange) -> Vec<u16> {
    match range {
        PortRange::Common => common_ports(),
        PortRange::Extended => extended_ports(),
        PortRange::Full => (1..=65535).collect(),
        PortRange::Custom(ports) => ports.clone(),
    }
}

/// Attempt a TCP connect to the given address with a timeout.
async fn tcp_connect_probe(addr: SocketAddr, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .is_ok_and(|r| r.is_ok())
}

/// Classify an open port into a finding with appropriate severity.
#[allow(clippy::too_many_lines)]
fn classify_port(ip: IpAddr, port: u16) -> Finding {
    let service = port_to_service(port);
    match port {
        23 => Finding::new(
            "ports",
            &format!("Telnet open on {ip}:{port}"),
            "Telnet transmits data including credentials in cleartext. \
             It should be replaced with SSH.",
            Severity::High,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service(service)
        .with_cwe("CWE-319"),

        21 => Finding::new(
            "ports",
            &format!("FTP open on {ip}:{port}"),
            "FTP transmits credentials in cleartext. Consider SFTP or FTPS instead.",
            Severity::Medium,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service(service)
        .with_cwe("CWE-319"),

        110 | 143 => Finding::new(
            "ports",
            &format!("{service} open on {ip}:{port}"),
            &format!(
                "{service} is an unencrypted mail protocol. Use {}/TLS instead.",
                if port == 110 { "POP3S (995)" } else { "IMAPS (993)" }
            ),
            Severity::Medium,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service(service)
        .with_cwe("CWE-319"),

        3389 => Finding::new(
            "ports",
            &format!("RDP open on {ip}:{port}"),
            "Remote Desktop Protocol is exposed on the local network. \
             Ensure it is protected with strong authentication and NLA.",
            Severity::Medium,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service(service)
        .with_cwe("CWE-284"),

        5900 => Finding::new(
            "ports",
            &format!("VNC open on {ip}:{port}"),
            "VNC is exposed on the local network. VNC often lacks strong \
             authentication and may transmit sessions unencrypted.",
            Severity::Medium,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service(service)
        .with_cwe("CWE-284"),

        3306 | 5432 | 27017 | 6379 => Finding::new(
            "ports",
            &format!("{service} database exposed on {ip}:{port}"),
            &format!(
                "{service} is listening on the network. Databases should not be \
                 directly accessible from the LAN without authentication and \
                 firewall restrictions."
            ),
            Severity::Medium,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service(service)
        .with_cwe("CWE-284"),

        1883 => Finding::new(
            "ports",
            &format!("MQTT (unencrypted) open on {ip}:{port}"),
            "MQTT without TLS (port 1883) transmits IoT messages in cleartext. \
             Use MQTT over TLS (port 8883) instead.",
            Severity::Medium,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service(service)
        .with_cwe("CWE-319"),

        1900 | 49152 => Finding::new(
            "ports",
            &format!("UPnP service on {ip}:{port}"),
            "UPnP can automatically open ports on the router, allowing \
             malware or attackers to expose internal services to the internet.",
            Severity::Medium,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service(service)
        .with_cwe("CWE-284"),

        22 => Finding::new(
            "ports",
            &format!("SSH open on {ip}:{port}"),
            "SSH is accessible. While SSH is generally secure, exposed SSH \
             services should use key-based auth and disable password login.",
            Severity::Low,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service(service),

        9100 | 631 => Finding::new(
            "ports",
            &format!("Printer service on {ip}:{port}"),
            &format!(
                "Printer service ({service}) is accessible on the network. \
                 Printers often have weak security and can be used for \
                 lateral movement."
            ),
            Severity::Low,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service(service),

        _ => Finding::new(
            "ports",
            &format!("Open port {port} ({service}) on {ip}"),
            &format!("Port {port} ({service}) is open on {ip}."),
            Severity::Info,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service(service),
    }
}

#[async_trait]
impl Scanner for PortScanner {
    fn id(&self) -> &'static str {
        "ports"
    }

    fn name(&self) -> &'static str {
        "Port Scanner"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running port scan");

        // Collect target IPs from ARP cache, filtered to target network
        let arp_entries = rikitikitavi_network::read_arp_cache().map_err(|e| {
            ScanError::ScannerFailed {
                scanner: "ports".to_owned(),
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
            tracing::info!("no targets found for port scanning");
            return Ok(Vec::new());
        }

        let ports = get_ports(&ctx.config.port_scan_range);
        // Adapt timeout based on scan intensity
        let timeout = if ctx.config.intensity.at_least(rikitikitavi_models::config::ScanIntensity::Aggressive) {
            Duration::from_secs(5)
        } else if ctx.config.intensity.at_least(rikitikitavi_models::config::ScanIntensity::Active) {
            Duration::from_secs(2)
        } else {
            Duration::from_secs(1)
        };
        let parallelism = ctx.config.parallelism.max(1);
        let semaphore = std::sync::Arc::new(Semaphore::new(parallelism));

        tracing::info!(
            target_count = targets.len(),
            port_count = ports.len(),
            parallelism,
            "starting TCP connect scan"
        );

        // Build all probe tasks
        let mut tasks = Vec::new();
        for &ip in &targets {
            for &port in &ports {
                let sem = semaphore.clone();
                let task = tokio::spawn(async move {
                    let _permit = sem.acquire().await;
                    let addr = SocketAddr::new(ip, port);
                    let open = tcp_connect_probe(addr, timeout).await;
                    PortResult { ip, port, open }
                });
                tasks.push(task);
            }
        }

        // Collect results
        let mut findings = Vec::new();
        let mut open_ports_per_host: std::collections::HashMap<IpAddr, Vec<u16>> =
            std::collections::HashMap::new();

        for task in tasks {
            if let Ok(result) = task.await {
                if result.open {
                    tracing::debug!(ip = %result.ip, port = result.port, "port open");
                    open_ports_per_host
                        .entry(result.ip)
                        .or_default()
                        .push(result.port);
                    findings.push(classify_port(result.ip, result.port));
                }
            }
        }

        // Flag hosts with many open ports
        for (ip, ports) in &open_ports_per_host {
            if ports.len() > 10 {
                findings.push(
                    Finding::new(
                        "ports",
                        &format!("Host {ip} has {} open ports", ports.len()),
                        &format!(
                            "Host {ip} has {} open ports, which increases the attack surface. \
                             Review whether all services are necessary.",
                            ports.len()
                        ),
                        Severity::Medium,
                    )
                    .with_ip(*ip)
                    .with_cwe("CWE-284"),
                );
            }
        }

        let total_open: usize = open_ports_per_host.values().map(Vec::len).sum();
        tracing::info!(
            hosts_scanned = targets.len(),
            total_open,
            "port scan complete"
        );

        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        120
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_core::Severity;

    // ── port_to_service tests ───────────────────────────────────────

    #[test]
    fn test_port_to_service_known_ports() {
        assert_eq!(port_to_service(21), "FTP");
        assert_eq!(port_to_service(22), "SSH");
        assert_eq!(port_to_service(23), "Telnet");
        assert_eq!(port_to_service(25), "SMTP");
        assert_eq!(port_to_service(53), "DNS");
        assert_eq!(port_to_service(80), "HTTP");
        assert_eq!(port_to_service(443), "HTTPS");
        assert_eq!(port_to_service(445), "SMB");
        assert_eq!(port_to_service(3306), "MySQL");
        assert_eq!(port_to_service(3389), "RDP");
        assert_eq!(port_to_service(5432), "PostgreSQL");
        assert_eq!(port_to_service(5900), "VNC");
        assert_eq!(port_to_service(6379), "Redis");
        assert_eq!(port_to_service(8080), "HTTP-Proxy");
        assert_eq!(port_to_service(27017), "MongoDB");
    }

    #[test]
    fn test_port_to_service_unknown() {
        assert_eq!(port_to_service(12345), "Unknown");
        assert_eq!(port_to_service(0), "Unknown");
        assert_eq!(port_to_service(65535), "Unknown");
    }

    // ── common_ports / extended_ports tests ──────────────────────────

    #[test]
    fn test_common_ports_contains_expected() {
        let ports = common_ports();
        assert!(ports.contains(&22), "SSH missing");
        assert!(ports.contains(&80), "HTTP missing");
        assert!(ports.contains(&443), "HTTPS missing");
        assert!(ports.contains(&21), "FTP missing");
        assert!(ports.contains(&23), "Telnet missing");
        assert!(ports.contains(&445), "SMB missing");
        assert!(ports.contains(&3389), "RDP missing");
    }

    #[test]
    fn test_common_ports_reasonable_size() {
        let ports = common_ports();
        assert!(ports.len() >= 30, "too few common ports");
        assert!(ports.len() <= 100, "too many common ports");
    }

    #[test]
    fn test_extended_ports_superset() {
        let common = common_ports();
        let extended = extended_ports();
        for port in &common {
            assert!(
                extended.contains(port),
                "extended_ports missing common port {port}"
            );
        }
        assert!(extended.len() > common.len());
    }

    #[test]
    fn test_extended_ports_sorted_and_deduped() {
        let extended = extended_ports();
        for window in extended.windows(2) {
            assert!(
                window[0] < window[1],
                "extended_ports not sorted/deduped: {} >= {}",
                window[0],
                window[1]
            );
        }
    }

    // ── get_ports tests ─────────────────────────────────────────────

    #[test]
    fn test_get_ports_common() {
        let ports = get_ports(&PortRange::Common);
        assert_eq!(ports, common_ports());
    }

    #[test]
    fn test_get_ports_extended() {
        let ports = get_ports(&PortRange::Extended);
        assert_eq!(ports, extended_ports());
    }

    #[test]
    fn test_get_ports_full() {
        let ports = get_ports(&PortRange::Full);
        assert_eq!(ports.len(), 65535);
        assert_eq!(*ports.first().unwrap(), 1);
        assert_eq!(*ports.last().unwrap(), 65535);
    }

    #[test]
    fn test_get_ports_custom() {
        let custom = vec![22, 80, 443];
        let ports = get_ports(&PortRange::Custom(custom.clone()));
        assert_eq!(ports, custom);
    }

    #[test]
    fn test_get_ports_custom_empty() {
        let ports = get_ports(&PortRange::Custom(Vec::new()));
        assert!(ports.is_empty());
    }

    // ── classify_port tests ─────────────────────────────────────────

    #[test]
    fn test_classify_telnet_high() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_port(ip, 23);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.affected_port, Some(23));
        assert_eq!(finding.affected_service.as_deref(), Some("Telnet"));
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-319"));
    }

    #[test]
    fn test_classify_ftp_medium() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_port(ip, 21);
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn test_classify_ssh_low() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_port(ip, 22);
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn test_classify_http_info() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_port(ip, 80);
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn test_classify_rdp_medium() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_port(ip, 3389);
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn test_classify_vnc_medium() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_port(ip, 5900);
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn test_classify_databases_medium() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        for port in [3306, 5432, 27017, 6379] {
            let finding = classify_port(ip, port);
            assert_eq!(finding.severity, Severity::Medium, "port {port}");
        }
    }

    #[test]
    fn test_classify_upnp_medium() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(classify_port(ip, 1900).severity, Severity::Medium);
        assert_eq!(classify_port(ip, 49152).severity, Severity::Medium);
    }

    #[test]
    fn test_classify_printer_low() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(classify_port(ip, 9100).severity, Severity::Low);
        assert_eq!(classify_port(ip, 631).severity, Severity::Low);
    }

    #[test]
    fn test_classify_mail_medium() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(classify_port(ip, 110).severity, Severity::Medium);
        assert_eq!(classify_port(ip, 143).severity, Severity::Medium);
    }

    #[test]
    fn test_classify_unknown_info() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_port(ip, 12345);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.affected_service.as_deref(), Some("Unknown"));
    }

    #[test]
    fn test_classify_port_always_has_ip_and_port() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for port in [22, 23, 80, 443, 3389, 5900, 6379, 12345] {
            let finding = classify_port(ip, port);
            assert_eq!(finding.affected_ip, Some(ip));
            assert_eq!(finding.affected_port, Some(port));
            assert_eq!(finding.scanner, "ports");
        }
    }

    // ── Proptests ───────────────────────────────────────────────────

    proptest! {
        /// port_to_service never panics on any u16
        #[test]
        fn prop_port_to_service_no_panic(port in 0_u16..=u16::MAX) {
            let _ = port_to_service(port);
        }

        /// classify_port always returns a valid Finding for any port
        #[test]
        fn prop_classify_port_valid(
            a in 0_u8..=255_u8,
            b in 0_u8..=255_u8,
            c in 0_u8..=255_u8,
            d in 0_u8..=255_u8,
            port in 1_u16..=65535_u16,
        ) {
            let ip: IpAddr = format!("{a}.{b}.{c}.{d}").parse().unwrap();
            let finding = classify_port(ip, port);
            assert!(!finding.title.is_empty());
            assert!(!finding.scanner.is_empty());
            assert_eq!(finding.affected_ip, Some(ip));
            assert_eq!(finding.affected_port, Some(port));
        }
    }
}
