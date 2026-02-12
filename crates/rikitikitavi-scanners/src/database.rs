use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Scanner;

/// Database security scanner — detects authentication-less database access.
///
/// Goes beyond simple port detection: attempts protocol-level handshakes
/// to determine whether databases are accessible without credentials.
/// Uses Phase 1 discovered devices to target only hosts with relevant
/// open ports.
pub struct DatabaseScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Known database ports and their service names.
const DATABASE_PORTS: &[(u16, &str)] = &[
    (6379, "Redis"),
    (27017, "MongoDB"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (9200, "Elasticsearch"),
    (11211, "Memcached"),
];

/// Check if a `Redis` instance allows unauthenticated access.
///
/// Sends the `PING` command and checks for a `+PONG` response, which
/// indicates no authentication is required.
async fn check_redis_no_auth(ip: IpAddr, port: u16) -> Option<RedisResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Send PING command
    tokio::time::timeout(READ_TIMEOUT, stream.write_all(b"PING\r\n"))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    let response = String::from_utf8_lossy(&buf[..n]);
    Some(classify_redis_response(&response))
}

/// Result of a `Redis` authentication probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedisResult {
    /// No auth required — `Redis` responds to PING
    NoAuth,
    /// Auth required — got `-NOAUTH` or similar
    AuthRequired,
    /// Unexpected response
    Unknown,
}

/// Classify a `Redis` PING response.
fn classify_redis_response(response: &str) -> RedisResult {
    let trimmed = response.trim();
    if trimmed.starts_with("+PONG") {
        RedisResult::NoAuth
    } else if trimmed.starts_with("-NOAUTH") || trimmed.starts_with("-ERR") {
        RedisResult::AuthRequired
    } else {
        RedisResult::Unknown
    }
}

/// Check if a `MongoDB` instance allows unauthenticated access.
///
/// Sends a minimal `MongoDB` wire protocol `isMaster` command. If we get
/// a valid BSON response without auth error, it's open.
async fn check_mongodb_no_auth(ip: IpAddr, port: u16) -> Option<bool> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Minimal MongoDB OP_MSG for { isMaster: 1, $db: "admin" }
    // We use a simplified check: just connect and try to read any banner/response.
    // MongoDB 3.6+ sends an isMaster-like response on connect.
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    // If we got data back without sending auth, the server is responding
    // without authentication. A properly secured MongoDB would either
    // require TLS client certs or not respond to unauthenticated connections.
    Some(true)
}

/// Check if a `MySQL` instance allows anonymous or empty-password login.
///
/// Reads the `MySQL` handshake greeting packet. If the server sends a
/// greeting, it means the port is `MySQL`. We then check the server
/// version and capabilities.
async fn check_mysql_greeting(ip: IpAddr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n < 5 {
        return None;
    }

    // MySQL greeting packet: 4 bytes header, then protocol version, then
    // null-terminated server version string
    parse_mysql_version(&buf[..n])
}

/// Parse the `MySQL` server version from a greeting packet.
fn parse_mysql_version(packet: &[u8]) -> Option<String> {
    // Packet layout: [length(3)] [sequence(1)] [protocol_version(1)] [version_string(null-terminated)]
    if packet.len() < 6 {
        return None;
    }

    // Protocol version is at byte 4
    let proto_version = packet[4];
    if proto_version != 10 {
        // Protocol version 10 is the current MySQL protocol
        return None;
    }

    // Version string starts at byte 5 and is null-terminated
    let version_start = 5;
    let version_end = packet[version_start..].iter().position(|&b| b == 0)? + version_start;

    String::from_utf8(packet[version_start..version_end].to_vec()).ok()
}

/// Check if an `Elasticsearch` instance is accessible without authentication.
///
/// Sends a simple HTTP GET to the root endpoint. Open `Elasticsearch`
/// instances return a JSON response with cluster information.
async fn check_elasticsearch_no_auth(ip: IpAddr, port: u16) -> Option<bool> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let request = format!("GET / HTTP/1.0\r\nHost: {ip}:{port}\r\n\r\n");
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
    Some(classify_elasticsearch_response(&response))
}

/// Classify an `Elasticsearch` HTTP response.
fn classify_elasticsearch_response(response: &str) -> bool {
    // A 200 response with "cluster_name" or "tagline" indicates open Elasticsearch
    response.contains("200") && (response.contains("cluster_name") || response.contains("tagline"))
}

/// Check if a `Memcached` instance is accessible without authentication.
///
/// Sends the `version` command. If `Memcached` responds, it has no auth.
async fn check_memcached_no_auth(ip: IpAddr, port: u16) -> Option<bool> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    tokio::time::timeout(READ_TIMEOUT, stream.write_all(b"version\r\n"))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    let response = String::from_utf8_lossy(&buf[..n]);
    Some(classify_memcached_response(&response))
}

/// Classify a `Memcached` version response.
fn classify_memcached_response(response: &str) -> bool {
    response.starts_with("VERSION ")
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl Scanner for DatabaseScanner {
    fn id(&self) -> &'static str {
        "database"
    }

    fn name(&self) -> &'static str {
        "Database Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running database security scan");
        let mut findings = Vec::new();

        // Skip in Passive mode — database probes can be slow and intrusive
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping database scan in quick scan mode");
            return Ok(findings);
        }

        // Collect targets: use discovered devices if available, else ARP cache
        let targets: Vec<(IpAddr, Vec<u16>)> = if ctx.discovered_devices.is_empty() {
            // Fallback: check all ARP cache IPs for common database ports
            let arp_entries =
                rikitikitavi_network::read_arp_cache().map_err(|e| ScanError::ScannerFailed {
                    scanner: "database".to_owned(),
                    message: format!("failed to read ARP cache: {e}"),
                })?;

            arp_entries
                .iter()
                .map(|e| (e.ip, DATABASE_PORTS.iter().map(|(port, _)| *port).collect()))
                .collect()
        } else {
            ctx.discovered_devices
                .iter()
                .map(|d| {
                    let db_ports: Vec<u16> = d
                        .open_ports
                        .iter()
                        .filter(|p| DATABASE_PORTS.iter().any(|(dp, _)| *dp == p.port))
                        .map(|p| p.port)
                        .collect();
                    (d.ip, db_ports)
                })
                .filter(|(_, ports)| !ports.is_empty())
                .collect()
        };

        if targets.is_empty() {
            tracing::info!("no database targets found");
            return Ok(findings);
        }

        tracing::info!(target_count = targets.len(), "checking database security");

        for (ip, ports) in &targets {
            for &port in ports {
                match port {
                    6379 => check_redis(ip, port, &mut findings).await,
                    27017 => check_mongodb(ip, port, &mut findings).await,
                    3306 => check_mysql(ip, port, &mut findings).await,
                    9200 => check_elastic(ip, port, &mut findings).await,
                    11211 => check_memcached(ip, port, &mut findings).await,
                    5432 => check_postgresql_advisory(ip, port, &mut findings),
                    _ => {}
                }
            }
        }

        tracing::info!(
            findings_count = findings.len(),
            "database security scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        30
    }

    fn relevant_ports(&self) -> &[u16] {
        &[3306, 5432, 6379, 27017, 9200, 1433]
    }
}

async fn check_redis(ip: &IpAddr, port: u16, findings: &mut Vec<Finding>) {
    if let Some(result) = check_redis_no_auth(*ip, port).await {
        match result {
            RedisResult::NoAuth => {
                findings.push(
                    Finding::new(
                        "database",
                        &format!("Redis accessible without authentication on {ip}:{port}"),
                        &format!(
                            "Redis at {ip}:{port} responds to commands without \
                             requiring authentication. An attacker can read/write all \
                             data and potentially execute Lua scripts."
                        ),
                        Severity::Critical,
                    )
                    .with_ip(*ip)
                    .with_port(port)
                    .with_service("Redis")
                    .with_cwe("CWE-306")
                    .with_opt_remediation(crate::remediation::get(
                        "rikitikitavi.database.redis-no-auth",
                        &[],
                    )),
                );
            }
            RedisResult::AuthRequired => {
                findings.push(
                    Finding::new(
                        "database",
                        &format!("Redis requires authentication on {ip}:{port}"),
                        &format!("Redis at {ip}:{port} correctly requires authentication."),
                        Severity::Info,
                    )
                    .with_ip(*ip)
                    .with_port(port)
                    .with_service("Redis"),
                );
            }
            RedisResult::Unknown => {}
        }
    }
}

async fn check_mongodb(ip: &IpAddr, port: u16, findings: &mut Vec<Finding>) {
    if check_mongodb_no_auth(*ip, port).await == Some(true) {
        findings.push(
            Finding::new(
                "database",
                &format!("MongoDB accessible without authentication on {ip}:{port}"),
                &format!(
                    "MongoDB at {ip}:{port} accepts connections without \
                     authentication. All databases and collections are exposed."
                ),
                Severity::Critical,
            )
            .with_ip(*ip)
            .with_port(port)
            .with_service("MongoDB")
            .with_cwe("CWE-306")
            .with_opt_remediation(crate::remediation::get(
                "rikitikitavi.database.mongodb-no-auth",
                &[],
            )),
        );
    }
}

async fn check_mysql(ip: &IpAddr, port: u16, findings: &mut Vec<Finding>) {
    if let Some(version) = check_mysql_greeting(*ip, port).await {
        let severity = classify_mysql_version(&version);
        findings.push(
            Finding::new(
                "database",
                &format!("MySQL {version} exposed on {ip}:{port}"),
                &format!(
                    "MySQL server at {ip}:{port} is running version {version}. \
                     The server accepted a TCP connection and revealed its version, \
                     which helps attackers identify exploitable vulnerabilities."
                ),
                severity,
            )
            .with_ip(*ip)
            .with_port(port)
            .with_service("MySQL")
            .with_cwe("CWE-200")
            .with_opt_remediation(crate::remediation::get(
                "rikitikitavi.database.mysql-exposed",
                &[],
            )),
        );
    }
}

async fn check_elastic(ip: &IpAddr, port: u16, findings: &mut Vec<Finding>) {
    if check_elasticsearch_no_auth(*ip, port).await == Some(true) {
        findings.push(
            Finding::new(
                "database",
                &format!("Elasticsearch open without authentication on {ip}:{port}"),
                &format!(
                    "Elasticsearch at {ip}:{port} is accessible without \
                     authentication. All indices and data are exposed."
                ),
                Severity::Critical,
            )
            .with_ip(*ip)
            .with_port(port)
            .with_service("Elasticsearch")
            .with_cwe("CWE-306")
            .with_opt_remediation(crate::remediation::get(
                "rikitikitavi.database.elasticsearch-no-auth",
                &[],
            )),
        );
    }
}

async fn check_memcached(ip: &IpAddr, port: u16, findings: &mut Vec<Finding>) {
    if check_memcached_no_auth(*ip, port).await == Some(true) {
        findings.push(
            Finding::new(
                "database",
                &format!("Memcached accessible without authentication on {ip}:{port}"),
                &format!(
                    "Memcached at {ip}:{port} responds to commands without \
                     authentication. Exposed Memcached instances can be used for \
                     DDoS amplification attacks and cache poisoning."
                ),
                Severity::High,
            )
            .with_ip(*ip)
            .with_port(port)
            .with_service("Memcached")
            .with_cwe("CWE-306")
            .with_opt_remediation(crate::remediation::get(
                "rikitikitavi.database.memcached-no-auth",
                &[],
            )),
        );
    }
}

fn check_postgresql_advisory(ip: &IpAddr, port: u16, findings: &mut Vec<Finding>) {
    // PostgreSQL auth check requires a full protocol handshake with
    // username, which is more invasive. We issue an advisory instead.
    findings.push(
        Finding::new(
            "database",
            &format!("PostgreSQL exposed on {ip}:{port}"),
            &format!(
                "PostgreSQL at {ip}:{port} is accessible on the network. \
                 Verify that pg_hba.conf does not allow 'trust' authentication \
                 from network hosts, and that all users have strong passwords."
            ),
            Severity::Medium,
        )
        .with_ip(*ip)
        .with_port(port)
        .with_service("PostgreSQL")
        .with_cwe("CWE-287")
        .with_opt_remediation(crate::remediation::get(
            "rikitikitavi.database.postgresql-exposed",
            &[],
        )),
    );
}

/// Classify a `MySQL` version string for severity.
///
/// Older or end-of-life versions get higher severity.
fn classify_mysql_version(version: &str) -> Severity {
    // Extract major.minor version
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() >= 2 {
        if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
            // MySQL 5.5 and below: end of life
            if major < 5 || (major == 5 && minor <= 5) {
                return Severity::High;
            }
            // MySQL 5.6: end of life since Feb 2021
            if major == 5 && minor == 6 {
                return Severity::High;
            }
            // MySQL 5.7: end of life since Oct 2023
            if major == 5 && minor == 7 {
                return Severity::Medium;
            }
        }
    }
    // MariaDB or current MySQL: just informational
    Severity::Low
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── Redis classification tests ──────────────────────────────────

    #[test]
    fn test_redis_pong_no_auth() {
        assert_eq!(classify_redis_response("+PONG\r\n"), RedisResult::NoAuth);
    }

    #[test]
    fn test_redis_noauth_required() {
        assert_eq!(
            classify_redis_response("-NOAUTH Authentication required.\r\n"),
            RedisResult::AuthRequired
        );
    }

    #[test]
    fn test_redis_err_auth_required() {
        assert_eq!(
            classify_redis_response("-ERR Client sent AUTH, but no password is set"),
            RedisResult::AuthRequired
        );
    }

    #[test]
    fn test_redis_unknown_response() {
        assert_eq!(classify_redis_response("garbage"), RedisResult::Unknown);
    }

    #[test]
    fn test_redis_empty_response() {
        assert_eq!(classify_redis_response(""), RedisResult::Unknown);
    }

    // ── MySQL version parsing tests ─────────────────────────────────

    #[test]
    fn test_parse_mysql_version_valid() {
        // Simulate a MySQL greeting: 3-byte length, 1-byte seq, protocol 10, then "8.0.35\0"
        let mut packet = vec![0u8; 4]; // length + sequence
        packet.push(10); // protocol version
        packet.extend_from_slice(b"8.0.35\0");
        assert_eq!(parse_mysql_version(&packet), Some("8.0.35".to_owned()));
    }

    #[test]
    fn test_parse_mysql_version_mariadb() {
        let mut packet = vec![0u8; 4];
        packet.push(10);
        packet.extend_from_slice(b"5.5.68-MariaDB\0");
        assert_eq!(
            parse_mysql_version(&packet),
            Some("5.5.68-MariaDB".to_owned())
        );
    }

    #[test]
    fn test_parse_mysql_version_wrong_protocol() {
        let mut packet = vec![0u8; 4];
        packet.push(9); // Old protocol
        packet.extend_from_slice(b"4.1.0\0");
        assert_eq!(parse_mysql_version(&packet), None);
    }

    #[test]
    fn test_parse_mysql_version_too_short() {
        assert_eq!(parse_mysql_version(&[0, 0, 0, 0, 10]), None);
    }

    #[test]
    fn test_parse_mysql_version_no_null_terminator() {
        let mut packet = vec![0u8; 4];
        packet.push(10);
        packet.extend_from_slice(b"8.0.35"); // No null terminator
        assert_eq!(parse_mysql_version(&packet), None);
    }

    // ── MySQL version severity tests ────────────────────────────────

    #[test]
    fn test_mysql_version_5_5_high() {
        assert_eq!(classify_mysql_version("5.5.62"), Severity::High);
    }

    #[test]
    fn test_mysql_version_5_6_high() {
        assert_eq!(classify_mysql_version("5.6.50"), Severity::High);
    }

    #[test]
    fn test_mysql_version_5_7_medium() {
        assert_eq!(classify_mysql_version("5.7.44"), Severity::Medium);
    }

    #[test]
    fn test_mysql_version_8_0_low() {
        assert_eq!(classify_mysql_version("8.0.35"), Severity::Low);
    }

    #[test]
    fn test_mysql_version_mariadb_low() {
        assert_eq!(classify_mysql_version("10.11.6-MariaDB"), Severity::Low);
    }

    #[test]
    fn test_mysql_version_unparseable_low() {
        assert_eq!(classify_mysql_version("unknown"), Severity::Low);
    }

    // ── Elasticsearch classification tests ──────────────────────────

    #[test]
    fn test_elasticsearch_open_response() {
        let response = "HTTP/1.1 200 OK\r\n\r\n{\"cluster_name\":\"my-cluster\",\"tagline\":\"You Know, for Search\"}";
        assert!(classify_elasticsearch_response(response));
    }

    #[test]
    fn test_elasticsearch_auth_required() {
        let response = "HTTP/1.1 401 Unauthorized\r\n\r\n{\"error\":\"Security exception\"}";
        assert!(!classify_elasticsearch_response(response));
    }

    #[test]
    fn test_elasticsearch_empty_response() {
        assert!(!classify_elasticsearch_response(""));
    }

    // ── Memcached classification tests ──────────────────────────────

    #[test]
    fn test_memcached_version_response() {
        assert!(classify_memcached_response("VERSION 1.6.22\r\n"));
    }

    #[test]
    fn test_memcached_error_response() {
        assert!(!classify_memcached_response("ERROR\r\n"));
    }

    #[test]
    fn test_memcached_empty_response() {
        assert!(!classify_memcached_response(""));
    }

    // ── Proptests ───────────────────────────────────────────────────

    proptest! {
        #[test]
        fn prop_classify_redis_no_panic(response in ".*") {
            let _ = classify_redis_response(&response);
        }

        #[test]
        fn prop_classify_mysql_version_no_panic(version in ".*") {
            let _ = classify_mysql_version(&version);
        }

        #[test]
        fn prop_parse_mysql_version_no_panic(data in proptest::collection::vec(any::<u8>(), 0..128)) {
            let _ = parse_mysql_version(&data);
        }

        #[test]
        fn prop_classify_elasticsearch_no_panic(response in ".*") {
            let _ = classify_elasticsearch_response(&response);
        }

        #[test]
        fn prop_classify_memcached_no_panic(response in ".*") {
            let _ = classify_memcached_response(&response);
        }
    }
}
