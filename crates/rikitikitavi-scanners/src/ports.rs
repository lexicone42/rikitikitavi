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
        let timeout = Duration::from_secs(2);
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
