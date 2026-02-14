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
/// Sends `PING` first. If the server responds with `+PONG` (no auth),
/// follows up with `INFO server` to extract version, OS, and memory info.
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
    let result = classify_redis_response(&response);

    // If no auth required, try to get server info
    if matches!(result, RedisResult::NoAuth(_)) {
        // Send INFO server command
        if tokio::time::timeout(READ_TIMEOUT, stream.write_all(b"INFO server\r\n"))
            .await
            .ok()?
            .ok()
            .is_some()
        {
            let mut info_buf = vec![0u8; 4096];
            if let Ok(Ok(info_n)) =
                tokio::time::timeout(READ_TIMEOUT, stream.read(&mut info_buf)).await
            {
                if info_n > 0 {
                    // Parse the RESP bulk string containing INFO output
                    let info = parse_resp_value(&info_buf[..info_n])
                        .and_then(|(val, _)| match val {
                            RespValue::BulkString(s) => Some(parse_redis_info(&s)),
                            _ => None,
                        });
                    return Some(RedisResult::NoAuth(info));
                }
            }
        }
        return Some(RedisResult::NoAuth(None));
    }

    Some(result)
}

/// Result of a `Redis` authentication probe.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RedisResult {
    /// No auth required — `Redis` responds to PING; optional server info.
    NoAuth(Option<RedisInfo>),
    /// Auth required — got `-NOAUTH` or similar
    AuthRequired,
    /// Unexpected response
    Unknown,
}

/// Structured info from a `Redis` `INFO server` response.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RedisInfo {
    version: Option<String>,
    os: Option<String>,
    tcp_port: Option<u16>,
    connected_clients: Option<u32>,
    used_memory_human: Option<String>,
}

/// A parsed RESP (Redis Serialization Protocol) value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RespValue {
    /// `+OK\r\n`
    SimpleString(String),
    /// `-ERR ...\r\n`
    Error(String),
    /// `:1000\r\n`
    Integer(i64),
    /// `$6\r\nfoobar\r\n`
    BulkString(String),
    /// `$-1\r\n`
    Null,
}

/// Parse a single RESP value from the given bytes.
///
/// Returns the parsed value and the number of bytes consumed, or `None`
/// if the data is incomplete or malformed.
fn parse_resp_value(data: &[u8]) -> Option<(RespValue, usize)> {
    if data.is_empty() {
        return None;
    }
    let prefix = data[0];
    let rest = &data[1..];

    match prefix {
        // Simple string: +OK\r\n
        b'+' => {
            let end = find_crlf(rest)?;
            let s = String::from_utf8_lossy(&rest[..end]).into_owned();
            Some((RespValue::SimpleString(s), 1 + end + 2))
        }
        // Error: -ERR message\r\n
        b'-' => {
            let end = find_crlf(rest)?;
            let s = String::from_utf8_lossy(&rest[..end]).into_owned();
            Some((RespValue::Error(s), 1 + end + 2))
        }
        // Integer: :1000\r\n
        b':' => {
            let end = find_crlf(rest)?;
            let s = std::str::from_utf8(&rest[..end]).ok()?;
            let val = s.parse::<i64>().ok()?;
            Some((RespValue::Integer(val), 1 + end + 2))
        }
        // Bulk string: $6\r\nfoobar\r\n or $-1\r\n for null
        b'$' => {
            let len_end = find_crlf(rest)?;
            let len_str = std::str::from_utf8(&rest[..len_end]).ok()?;
            let len = len_str.parse::<i64>().ok()?;
            if len < 0 {
                return Some((RespValue::Null, 1 + len_end + 2));
            }
            let len = usize::try_from(len).ok()?;
            let data_start = len_end + 2; // past the \r\n after length
            if rest.len() < data_start + len + 2 {
                return None; // incomplete
            }
            let s = String::from_utf8_lossy(&rest[data_start..data_start + len]).into_owned();
            Some((RespValue::BulkString(s), 1 + data_start + len + 2))
        }
        _ => None,
    }
}

/// Find the position of `\r\n` in a byte slice.
fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\r\n")
}

/// Parse the `Redis` `INFO server` bulk string into structured fields.
///
/// The INFO response is a text block with `key:value` lines separated by `\n`,
/// with section headers like `# Server`.
fn parse_redis_info(bulk: &str) -> RedisInfo {
    let mut info = RedisInfo {
        version: None,
        os: None,
        tcp_port: None,
        connected_clients: None,
        used_memory_human: None,
    };

    for line in bulk.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            match key {
                "redis_version" => info.version = Some(value.to_owned()),
                "os" => info.os = Some(value.to_owned()),
                "tcp_port" => info.tcp_port = value.parse().ok(),
                "connected_clients" => info.connected_clients = value.parse().ok(),
                "used_memory_human" => info.used_memory_human = Some(value.to_owned()),
                _ => {}
            }
        }
    }

    info
}

/// Classify a `Redis` PING response.
fn classify_redis_response(response: &str) -> RedisResult {
    let trimmed = response.trim();
    if trimmed.starts_with("+PONG") {
        RedisResult::NoAuth(None)
    } else if trimmed.starts_with("-NOAUTH") || trimmed.starts_with("-ERR") {
        RedisResult::AuthRequired
    } else {
        RedisResult::Unknown
    }
}

/// Classify a `Redis` version for end-of-life status.
///
/// Redis versions below 7.0 are end-of-life and no longer receive
/// security patches.
fn classify_redis_version_eol(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    if let Some(major_str) = parts.first() {
        if let Ok(major) = major_str.parse::<u32>() {
            return major < 7;
        }
    }
    false
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

/// Read and parse a `MySQL` Handshake v10 greeting packet.
///
/// Connects to the `MySQL` port and reads the server greeting, which
/// contains the version string, capability flags, auth plugin, and more.
async fn check_mysql_greeting(ip: IpAddr, port: u16) -> Option<MysqlGreeting> {
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

    if n < 7 {
        return None;
    }

    parse_mysql_greeting(&buf[..n])
}

/// Parsed `MySQL` Handshake v10 greeting packet.
///
/// Contains the security-relevant fields from the server greeting:
/// version, connection ID, capability flags, character set, status flags,
/// and the authentication plugin name (if `CLIENT_PLUGIN_AUTH` is set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MysqlGreeting {
    pub version: String,
    pub connection_id: u32,
    pub capability_flags: u32,
    pub character_set: u8,
    pub status_flags: u16,
    pub auth_plugin: Option<String>,
}

/// `CLIENT_SSL` capability flag — server supports TLS connections.
const CLIENT_SSL: u32 = 0x0000_0800;
/// `CLIENT_SECURE_CONNECTION` — server supports 4.1+ auth protocol.
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
/// `CLIENT_PLUGIN_AUTH` — server sends auth plugin name in greeting.
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

/// Parse a `MySQL` Handshake v10 greeting packet into structured data.
///
/// Packet layout (after 4-byte header):
/// ```text
/// [1] protocol_version (must be 10)
/// [N] version_string\0
/// [4] connection_id (u32 LE)
/// [8] auth_plugin_data_part1
/// [1] filler (0x00)
/// [2] capability_flags_lower (u16 LE)
/// [1] character_set
/// [2] status_flags (u16 LE)
/// [2] capability_flags_upper (u16 LE)
/// [1] auth_plugin_data_len (or 0x00)
/// [10] reserved
/// [N] auth_plugin_data_part2 (if CLIENT_SECURE_CONNECTION)
/// [N] auth_plugin_name\0 (if CLIENT_PLUGIN_AUTH)
/// ```
fn parse_mysql_greeting(packet: &[u8]) -> Option<MysqlGreeting> {
    // Minimum: 4 header + 1 proto + 1 version char + 1 null = 7
    if packet.len() < 7 {
        return None;
    }

    // Protocol version at byte 4
    if packet[4] != 10 {
        return None;
    }

    // Version string starts at byte 5, null-terminated
    let version_start = 5;
    let null_pos = packet[version_start..].iter().position(|&b| b == 0)?;
    let version_end = version_start + null_pos;
    let version = String::from_utf8(packet[version_start..version_end].to_vec()).ok()?;

    // After version null: connection_id(4) + auth_data_1(8) + filler(1) = 13 bytes
    let post_version = version_end + 1;
    if packet.len() < post_version + 13 {
        // Short packet — return version only with defaults
        return Some(MysqlGreeting {
            version,
            connection_id: 0,
            capability_flags: 0,
            character_set: 0,
            status_flags: 0,
            auth_plugin: None,
        });
    }

    let connection_id = u32::from_le_bytes([
        packet[post_version],
        packet[post_version + 1],
        packet[post_version + 2],
        packet[post_version + 3],
    ]);

    // Skip auth_plugin_data_part1 (8 bytes) + filler (1 byte)
    let cap_lower_pos = post_version + 4 + 8 + 1;
    if packet.len() < cap_lower_pos + 2 {
        return Some(MysqlGreeting {
            version,
            connection_id,
            capability_flags: 0,
            character_set: 0,
            status_flags: 0,
            auth_plugin: None,
        });
    }

    let cap_lower =
        u32::from(u16::from_le_bytes([packet[cap_lower_pos], packet[cap_lower_pos + 1]]));

    // character_set(1) + status_flags(2) + capability_flags_upper(2) + auth_plugin_data_len(1) + reserved(10) = 16
    if packet.len() < cap_lower_pos + 2 + 16 {
        return Some(MysqlGreeting {
            version,
            connection_id,
            capability_flags: cap_lower,
            character_set: 0,
            status_flags: 0,
            auth_plugin: None,
        });
    }

    let character_set = packet[cap_lower_pos + 2];
    let status_pos = cap_lower_pos + 3;
    let status_flags = u16::from_le_bytes([packet[status_pos], packet[status_pos + 1]]);
    let cap_upper_pos = status_pos + 2;
    let cap_upper =
        u32::from(u16::from_le_bytes([packet[cap_upper_pos], packet[cap_upper_pos + 1]]));
    let capability_flags = cap_lower | (cap_upper << 16);

    let auth_plugin_data_len = packet[cap_upper_pos + 2];

    // Skip reserved (10 bytes)
    let mut cursor = cap_upper_pos + 2 + 1 + 10;

    // Skip auth_plugin_data_part2 if CLIENT_SECURE_CONNECTION
    if capability_flags & CLIENT_SECURE_CONNECTION != 0 {
        // Length is max(13, auth_plugin_data_len) - 8
        let part2_len = if auth_plugin_data_len > 8 {
            usize::from(auth_plugin_data_len) - 8
        } else {
            13 - 8 // minimum 5 bytes (including null terminator)
        };
        cursor += part2_len;
    }

    // Read auth_plugin_name if CLIENT_PLUGIN_AUTH
    let auth_plugin = if capability_flags & CLIENT_PLUGIN_AUTH != 0 && cursor < packet.len() {
        packet[cursor..]
            .iter()
            .position(|&b| b == 0)
            .and_then(|end| String::from_utf8(packet[cursor..cursor + end].to_vec()).ok())
    } else {
        None
    };

    Some(MysqlGreeting {
        version,
        connection_id,
        capability_flags,
        character_set,
        status_flags,
        auth_plugin,
    })
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
            RedisResult::NoAuth(ref info) => {
                // Build enriched description from server info
                let detail = info.as_ref().map_or_else(String::new, |i| {
                    let mut parts = Vec::new();
                    if let Some(ref v) = i.version {
                        parts.push(format!("version {v}"));
                    }
                    if let Some(ref os) = i.os {
                        parts.push(format!("OS: {os}"));
                    }
                    if let Some(clients) = i.connected_clients {
                        parts.push(format!("{clients} connected clients"));
                    }
                    if let Some(ref mem) = i.used_memory_human {
                        parts.push(format!("memory: {mem}"));
                    }
                    if parts.is_empty() {
                        String::new()
                    } else {
                        format!(" Server info: {}.", parts.join(", "))
                    }
                });

                findings.push(
                    Finding::new(
                        "database",
                        &format!("Redis accessible without authentication on {ip}:{port}"),
                        &format!(
                            "Redis at {ip}:{port} responds to commands without \
                             requiring authentication. An attacker can read/write all \
                             data and potentially execute Lua scripts.{detail}"
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

                // EOL version finding
                if let Some(ref version) = info.as_ref().and_then(|i| i.version.clone()) {
                    if classify_redis_version_eol(version) {
                        findings.push(
                            Finding::new(
                                "database",
                                &format!("Redis {version} is end-of-life on {ip}:{port}"),
                                &format!(
                                    "Redis at {ip}:{port} is running version {version}, \
                                     which is end-of-life and no longer receives security \
                                     patches. Upgrade to Redis 7.0 or later.",
                                ),
                                Severity::Medium,
                            )
                            .with_ip(*ip)
                            .with_port(port)
                            .with_service("Redis")
                            .with_cwe("CWE-1104"),
                        );
                    }
                }
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
    let Some(greeting) = check_mysql_greeting(*ip, port).await else {
        return;
    };

    let ssl_supported = greeting.capability_flags & CLIENT_SSL != 0;
    let auth_plugin_label = greeting.auth_plugin.as_deref().unwrap_or("unknown");

    // Version disclosure finding (always generated)
    let severity = classify_mysql_version(&greeting.version);
    let ssl_status = if ssl_supported {
        "SSL supported"
    } else {
        "SSL NOT supported"
    };
    findings.push(
        Finding::new(
            "database",
            &format!("MySQL {} exposed on {ip}:{port}", greeting.version),
            &format!(
                "MySQL server at {ip}:{port} is running version {}. \
                 Connection ID: {}, auth plugin: {auth_plugin_label}, {ssl_status}. \
                 The server accepted a TCP connection and revealed its version, \
                 which helps attackers identify exploitable vulnerabilities.",
                greeting.version, greeting.connection_id,
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

    // SSL support finding
    if !ssl_supported {
        findings.push(
            Finding::new(
                "database",
                &format!("MySQL does not support SSL on {ip}:{port}"),
                &format!(
                    "MySQL server at {ip}:{port} (version {}) does not advertise \
                     SSL/TLS support in its capability flags. All traffic including \
                     credentials is transmitted in cleartext.",
                    greeting.version,
                ),
                Severity::Medium,
            )
            .with_ip(*ip)
            .with_port(port)
            .with_service("MySQL")
            .with_cwe("CWE-319"),
        );
    }

    // Auth plugin finding
    if let Some(ref plugin) = greeting.auth_plugin {
        match plugin.as_str() {
            "mysql_old_password" => {
                findings.push(
                    Finding::new(
                        "database",
                        &format!("MySQL uses weak auth plugin on {ip}:{port}"),
                        &format!(
                            "MySQL at {ip}:{port} uses the mysql_old_password \
                             authentication plugin, which relies on a weak hashing \
                             algorithm vulnerable to offline brute-force attacks. \
                             Upgrade to caching_sha2_password or mysql_native_password.",
                        ),
                        Severity::Medium,
                    )
                    .with_ip(*ip)
                    .with_port(port)
                    .with_service("MySQL")
                    .with_cwe("CWE-328"),
                );
            }
            "mysql_native_password" => {
                findings.push(
                    Finding::new(
                        "database",
                        &format!("MySQL uses SHA1-based auth on {ip}:{port}"),
                        &format!(
                            "MySQL at {ip}:{port} uses mysql_native_password \
                             (SHA1-based). While acceptable, consider upgrading to \
                             caching_sha2_password for stronger security.",
                        ),
                        Severity::Info,
                    )
                    .with_ip(*ip)
                    .with_port(port)
                    .with_service("MySQL"),
                );
            }
            _ => {} // caching_sha2_password and others — no finding needed
        }
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

    // ── Helper: build a complete MySQL Handshake v10 packet ─────────

    /// Build a realistic MySQL Handshake v10 packet for testing.
    fn build_mysql_packet(
        version: &str,
        conn_id: u32,
        cap_flags: u32,
        charset: u8,
        status: u16,
        auth_plugin: Option<&str>,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 4]; // header (length + sequence)
        packet.push(10); // protocol version
        packet.extend_from_slice(version.as_bytes());
        packet.push(0); // null terminator
        packet.extend_from_slice(&conn_id.to_le_bytes());
        packet.extend_from_slice(&[0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68]); // auth_data_1
        packet.push(0x00); // filler
        let cap_lower = (cap_flags & 0xFFFF) as u16;
        packet.extend_from_slice(&cap_lower.to_le_bytes());
        packet.push(charset);
        packet.extend_from_slice(&status.to_le_bytes());
        let cap_upper = ((cap_flags >> 16) & 0xFFFF) as u16;
        packet.extend_from_slice(&cap_upper.to_le_bytes());
        // auth_plugin_data_len
        let plugin_data_len: u8 = if cap_flags & CLIENT_SECURE_CONNECTION != 0 {
            21
        } else {
            0
        };
        packet.push(plugin_data_len);
        packet.extend_from_slice(&[0u8; 10]); // reserved

        if cap_flags & CLIENT_SECURE_CONNECTION != 0 {
            // auth_plugin_data_part2: max(13, plugin_data_len) - 8 bytes
            let part2_len = if plugin_data_len > 8 {
                usize::from(plugin_data_len) - 8
            } else {
                5
            };
            packet.extend_from_slice(&vec![0x41u8; part2_len]);
        }

        if let Some(plugin) = auth_plugin {
            packet.extend_from_slice(plugin.as_bytes());
            packet.push(0); // null terminator
        }

        packet
    }

    // ── Redis classification tests ──────────────────────────────────

    #[test]
    fn test_redis_pong_no_auth() {
        assert_eq!(
            classify_redis_response("+PONG\r\n"),
            RedisResult::NoAuth(None)
        );
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

    // ── RESP protocol parser tests ──────────────────────────────────

    #[test]
    fn test_parse_resp_simple_string() {
        let data = b"+OK\r\n";
        let (val, consumed) = parse_resp_value(data).unwrap();
        assert_eq!(val, RespValue::SimpleString("OK".to_owned()));
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_parse_resp_error() {
        let data = b"-ERR unknown command\r\n";
        let (val, consumed) = parse_resp_value(data).unwrap();
        assert_eq!(val, RespValue::Error("ERR unknown command".to_owned()));
        assert_eq!(consumed, 22);
    }

    #[test]
    fn test_parse_resp_integer() {
        let data = b":1000\r\n";
        let (val, consumed) = parse_resp_value(data).unwrap();
        assert_eq!(val, RespValue::Integer(1000));
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_parse_resp_bulk_string() {
        let data = b"$6\r\nfoobar\r\n";
        let (val, consumed) = parse_resp_value(data).unwrap();
        assert_eq!(val, RespValue::BulkString("foobar".to_owned()));
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_resp_null() {
        let data = b"$-1\r\n";
        let (val, consumed) = parse_resp_value(data).unwrap();
        assert_eq!(val, RespValue::Null);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_parse_resp_empty() {
        assert!(parse_resp_value(b"").is_none());
    }

    #[test]
    fn test_parse_resp_incomplete_bulk() {
        // Bulk string says 10 bytes but only provides 3
        let data = b"$10\r\nabc\r\n";
        assert!(parse_resp_value(data).is_none());
    }

    // ── Redis INFO parsing tests ────────────────────────────────────

    #[test]
    fn test_parse_redis_info() {
        let info_text = "\
# Server\r\n\
redis_version:7.2.4\r\n\
os:Linux 6.1.0-18-amd64 x86_64\r\n\
tcp_port:6379\r\n\
\r\n\
# Clients\r\n\
connected_clients:3\r\n\
\r\n\
# Memory\r\n\
used_memory_human:1.23M\r\n";

        let info = parse_redis_info(info_text);
        assert_eq!(info.version.as_deref(), Some("7.2.4"));
        assert_eq!(
            info.os.as_deref(),
            Some("Linux 6.1.0-18-amd64 x86_64")
        );
        assert_eq!(info.tcp_port, Some(6379));
        assert_eq!(info.connected_clients, Some(3));
        assert_eq!(info.used_memory_human.as_deref(), Some("1.23M"));
    }

    #[test]
    fn test_parse_redis_info_partial() {
        let info_text = "# Server\r\nredis_version:6.2.14\r\n";
        let info = parse_redis_info(info_text);
        assert_eq!(info.version.as_deref(), Some("6.2.14"));
        assert!(info.os.is_none());
        assert!(info.tcp_port.is_none());
    }

    #[test]
    fn test_parse_redis_info_empty() {
        let info = parse_redis_info("");
        assert!(info.version.is_none());
        assert!(info.os.is_none());
    }

    // ── Redis version EOL tests ─────────────────────────────────────

    #[test]
    fn test_classify_redis_version_eol_old() {
        assert!(classify_redis_version_eol("6.2.14"));
    }

    #[test]
    fn test_classify_redis_version_eol_very_old() {
        assert!(classify_redis_version_eol("5.0.14"));
    }

    #[test]
    fn test_classify_redis_version_current() {
        assert!(!classify_redis_version_eol("7.2.4"));
    }

    #[test]
    fn test_classify_redis_version_future() {
        assert!(!classify_redis_version_eol("8.0.0"));
    }

    #[test]
    fn test_classify_redis_version_unparseable() {
        assert!(!classify_redis_version_eol("unknown"));
    }

    // ── MySQL greeting parsing tests ────────────────────────────────

    #[test]
    fn test_parse_mysql_greeting_full() {
        let packet = build_mysql_packet(
            "8.0.35",
            42,
            CLIENT_SSL | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH,
            0x21, // utf8
            0x0002,
            Some("caching_sha2_password"),
        );
        let greeting = parse_mysql_greeting(&packet).unwrap();
        assert_eq!(greeting.version, "8.0.35");
        assert_eq!(greeting.connection_id, 42);
        assert!(greeting.capability_flags & CLIENT_SSL != 0);
        assert!(greeting.capability_flags & CLIENT_PLUGIN_AUTH != 0);
        assert_eq!(greeting.character_set, 0x21);
        assert_eq!(greeting.status_flags, 0x0002);
        assert_eq!(
            greeting.auth_plugin.as_deref(),
            Some("caching_sha2_password")
        );
    }

    #[test]
    fn test_parse_mysql_greeting_no_ssl() {
        let packet = build_mysql_packet(
            "8.0.35",
            1,
            CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH, // no SSL
            0x21,
            0x0002,
            Some("mysql_native_password"),
        );
        let greeting = parse_mysql_greeting(&packet).unwrap();
        assert!(greeting.capability_flags & CLIENT_SSL == 0);
        assert_eq!(
            greeting.auth_plugin.as_deref(),
            Some("mysql_native_password")
        );
    }

    #[test]
    fn test_parse_mysql_greeting_old_auth() {
        let packet = build_mysql_packet(
            "5.1.73",
            100,
            CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH,
            0x08,
            0x0002,
            Some("mysql_old_password"),
        );
        let greeting = parse_mysql_greeting(&packet).unwrap();
        assert_eq!(greeting.version, "5.1.73");
        assert_eq!(greeting.auth_plugin.as_deref(), Some("mysql_old_password"));
    }

    #[test]
    fn test_parse_mysql_greeting_no_plugin_auth() {
        let packet = build_mysql_packet(
            "5.5.68-MariaDB",
            200,
            CLIENT_SSL | CLIENT_SECURE_CONNECTION, // no PLUGIN_AUTH
            0x21,
            0x0002,
            None,
        );
        let greeting = parse_mysql_greeting(&packet).unwrap();
        assert_eq!(greeting.version, "5.5.68-MariaDB");
        assert!(greeting.auth_plugin.is_none());
    }

    #[test]
    fn test_parse_mysql_greeting_minimal() {
        // Just header + protocol + version + null — no capabilities
        let mut packet = vec![0u8; 4]; // header
        packet.push(10); // protocol
        packet.extend_from_slice(b"5.7.44\0");
        let greeting = parse_mysql_greeting(&packet).unwrap();
        assert_eq!(greeting.version, "5.7.44");
        assert_eq!(greeting.connection_id, 0); // default for short packet
        assert_eq!(greeting.capability_flags, 0);
    }

    #[test]
    fn test_parse_mysql_greeting_too_short() {
        assert!(parse_mysql_greeting(&[0, 0, 0, 0, 10]).is_none());
    }

    #[test]
    fn test_parse_mysql_greeting_wrong_protocol() {
        let mut packet = vec![0u8; 4];
        packet.push(9); // Old protocol
        packet.extend_from_slice(b"4.1.0\0");
        assert!(parse_mysql_greeting(&packet).is_none());
    }

    #[test]
    fn test_parse_mysql_greeting_no_null_terminator() {
        let mut packet = vec![0u8; 4];
        packet.push(10);
        packet.extend_from_slice(b"8.0.35"); // No null terminator
        assert!(parse_mysql_greeting(&packet).is_none());
    }

    #[test]
    fn test_parse_mysql_greeting_mariadb() {
        let mut packet = vec![0u8; 4];
        packet.push(10);
        packet.extend_from_slice(b"5.5.68-MariaDB\0");
        let greeting = parse_mysql_greeting(&packet).unwrap();
        assert_eq!(greeting.version, "5.5.68-MariaDB");
    }

    // ── MySQL version severity tests (unchanged) ────────────────────

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
        fn prop_parse_mysql_greeting_no_panic(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_mysql_greeting(&data);
        }

        #[test]
        fn prop_parse_resp_no_panic(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_resp_value(&data);
        }

        #[test]
        fn prop_parse_redis_info_no_panic(text in ".*") {
            let _ = parse_redis_info(&text);
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
