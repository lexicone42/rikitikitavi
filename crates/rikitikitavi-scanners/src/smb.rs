use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Scanner;

/// SMB security scanner — detects `SMBv1`, null sessions, and insecure shares.
///
/// Probes port 445 on discovered devices to check for:
/// - `SMBv1` support (vulnerable to `EternalBlue` / `WannaCry`)
/// - Null session access (anonymous enumeration)
/// - `NetBIOS` over TCP (port 139) exposure
///
/// To reduce false positives, the scanner:
/// - Validates the `SMBv1` negotiate response (dialect index, security mode)
/// - Also performs an `SMBv2` negotiate to distinguish legacy-only vs backward-compat
/// - Adjusts severity based on whether `SMBv2`+ is also available
pub struct SmbScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Parsed details from an `SMBv1` negotiate response.
#[derive(Debug, Clone)]
struct SmbV1NegotiateDetails {
    /// Whether the server actually accepted the `SMBv1` dialect.
    dialect_accepted: bool,
    /// Whether SMB signing is required by the server.
    signing_required: bool,
    /// Whether extended security (`SPNEGO`/`NTLMSSP`) is used.
    extended_security: bool,
    /// Raw security mode byte.
    security_mode: u8,
    /// Raw capabilities dword.
    capabilities: u32,
}

/// SMB negotiate protocol request for `SMBv1`.
///
/// This is a minimal SMB1 negotiate packet that only offers the
/// `NT LM 0.12` dialect. If the server responds with a valid
/// negotiate response using `SMBv1`, the server supports `SMBv1`.
fn build_smb1_negotiate() -> Vec<u8> {
    // NetBIOS Session header (4 bytes) + SMB Header (32 bytes) + Negotiate payload
    let dialect = b"\x02NT LM 0.12\x00";

    // SMB1 header
    let mut smb_header = vec![
        0xFF, b'S', b'M', b'B', // Protocol ID: \xFFSMB
        0x72, // Command: Negotiate (0x72)
        0x00, 0x00, 0x00, 0x00, // Status: SUCCESS
        0x18, // Flags: case-insensitive pathnames
        0x53, 0xC8, // Flags2: long names + extended security + unicode
        0x00, 0x00, // PID High
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
        0x00, 0x00, // Reserved
        0x00, 0x00, // TID
        0x00, 0x00, // PID
        0x00, 0x00, // UID
        0x00, 0x00, // MID
    ];

    // Negotiate request body
    let word_count: u8 = 0;
    #[allow(clippy::cast_possible_truncation)]
    let byte_count = dialect.len() as u16;

    smb_header.push(word_count);
    smb_header.extend_from_slice(&byte_count.to_le_bytes());
    smb_header.extend_from_slice(dialect);

    // NetBIOS session header (length of SMB data)
    #[allow(clippy::cast_possible_truncation)]
    let smb_len = smb_header.len() as u32;
    let mut packet = Vec::with_capacity(4 + smb_header.len());
    packet.push(0x00); // Session message
    packet.push(((smb_len >> 16) & 0xFF) as u8);
    packet.push(((smb_len >> 8) & 0xFF) as u8);
    packet.push((smb_len & 0xFF) as u8);
    packet.extend_from_slice(&smb_header);

    packet
}

/// Send an `SMBv1` negotiate and check if the server responds with `SMBv1`.
async fn check_smbv1(ip: IpAddr, port: u16) -> Option<SmbVersion> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let negotiate = build_smb1_negotiate();
    tokio::time::timeout(READ_TIMEOUT, stream.write_all(&negotiate))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n < 9 {
        return None;
    }

    Some(classify_smb_response(&buf[..n]))
}

/// SMB version detected.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SmbVersion {
    /// Server supports `SMBv1` (responds to `SMBv1` negotiate with accepted dialect)
    V1(SmbV1Info),
    /// Server rejected `SMBv1` or responded with `SMBv2`+
    V2Plus,
    /// Unrecognized response
    Unknown,
}

/// Summarized info from an `SMBv1` negotiate response.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SmbV1Info {
    /// Whether the server actually accepted the offered dialect.
    dialect_accepted: bool,
    /// Whether signing is required.
    signing_required: bool,
    /// Whether extended security is used.
    extended_security: bool,
}

/// Classify an SMB negotiate response to determine protocol version.
/// For `SMBv1` responses, also parse negotiate details to validate the dialect
/// was actually accepted (reducing false positives from servers that respond
/// with `SMBv1` framing but reject the offered dialect).
fn classify_smb_response(response: &[u8]) -> SmbVersion {
    // Skip NetBIOS header (4 bytes), check SMB magic
    if response.len() < 8 {
        return SmbVersion::Unknown;
    }

    // Check for SMBv1 magic: \xFFSMB
    if response[4] == 0xFF && &response[5..8] == b"SMB" {
        let details = parse_smbv1_negotiate_details(response);
        return SmbVersion::V1(SmbV1Info {
            dialect_accepted: details.dialect_accepted,
            signing_required: details.signing_required,
            extended_security: details.extended_security,
        });
    }

    // Check for SMBv2 magic: \xFESMB
    if response[4] == 0xFE && &response[5..8] == b"SMB" {
        return SmbVersion::V2Plus;
    }

    SmbVersion::Unknown
}

/// Parse negotiate details from an `SMBv1` response.
///
/// `SMBv1` NEGOTIATE response layout (after 4-byte `NetBIOS` + 32-byte SMB header):
/// - Byte 36: `WordCount` (typically 17 for `NT LM 0.12` dialect)
/// - Bytes 37-38: `DialectIndex` (LE u16, `0xFFFF` = no dialect accepted)
/// - Byte 39: `SecurityMode` (bit 0 = signing supported, bit 1 = signing required)
/// - Bytes 44-47: `Capabilities` (LE u32, bit 31 = extended security)
fn parse_smbv1_negotiate_details(response: &[u8]) -> SmbV1NegotiateDetails {
    // Default: assume dialect not accepted
    let mut details = SmbV1NegotiateDetails {
        dialect_accepted: false,
        signing_required: false,
        extended_security: false,
        security_mode: 0,
        capabilities: 0,
    };

    // Need at least past the WordCount + DialectIndex (offset 38)
    if response.len() < 39 {
        return details;
    }

    let word_count = response[36];
    // NT LM 0.12 response should have WordCount = 17 (or 13 for older)
    if word_count == 0 {
        // WordCount 0 means error / no dialect accepted
        return details;
    }

    // DialectIndex at offset 37-38 (little-endian)
    let dialect_index = u16::from_le_bytes([response[37], response[38]]);
    // 0xFFFF means no dialect was accepted
    details.dialect_accepted = dialect_index != 0xFFFF;

    // SecurityMode at offset 39 (if available)
    if response.len() > 39 {
        details.security_mode = response[39];
        // Bit 1 (0x02) = signing required
        details.signing_required = details.security_mode & 0x02 != 0;
    }

    // Capabilities at offset 44-47 (if available)
    if response.len() >= 48 {
        details.capabilities =
            u32::from_le_bytes([response[44], response[45], response[46], response[47]]);
        // Bit 31 (0x8000_0000) = CAP_EXTENDED_SECURITY
        details.extended_security = details.capabilities & 0x8000_0000 != 0;
    }

    details
}

/// Check if a host also supports `SMBv2`+ by sending an `SMBv2` negotiate.
/// Returns true if the server responds with a valid `SMBv2` negotiate response.
async fn check_smbv2_support(ip: IpAddr, port: u16) -> bool {
    let addr = SocketAddr::new(ip, port);
    let Ok(Ok(mut stream)) = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await
    else {
        return false;
    };

    let negotiate = build_smb2_negotiate();
    if tokio::time::timeout(READ_TIMEOUT, stream.write_all(&negotiate))
        .await
        .is_err()
    {
        return false;
    }

    let mut buf = vec![0u8; 512];
    let Ok(Ok(n)) = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf)).await else {
        return false;
    };

    // Valid SMBv2 response: at least 8 bytes, with \xFESMB magic
    n >= 8 && buf[4] == 0xFE && &buf[5..8] == b"SMB"
}

/// Build an `SMBv2` NEGOTIATE request.
fn build_smb2_negotiate() -> Vec<u8> {
    // SMBv2 header (64 bytes) + Negotiate request (36 bytes + dialect list)
    let mut smb2_header = vec![
        0xFE, b'S', b'M', b'B', // Protocol ID: \xFESMB
        0x40, 0x00, // Structure Size: 64
        0x00, 0x00, // Credit Charge: 0
        0x00, 0x00, 0x00, 0x00, // Status: SUCCESS
        0x00, 0x00, // Command: NEGOTIATE (0x0000)
        0x00, 0x00, // Credit Request: 1
        0x00, 0x00, 0x00, 0x00, // Flags
        0x00, 0x00, 0x00, 0x00, // Next Command
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
        0x00, 0x00, 0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, // Tree ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (first half)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (second half)
    ];

    // Negotiate request body
    let negotiate_body = vec![
        0x24, 0x00, // StructureSize: 36
        0x02, 0x00, // DialectCount: 2
        0x01, 0x00, // SecurityMode: signing enabled
        0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, // Capabilities
        // ClientGuid (16 bytes of zeros)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, // ClientStartTime (or NegotiateContextOffset for 3.1.1)
        // Dialects
        0x02, 0x02, // SMB 2.0.2
        0x10, 0x02, // SMB 2.1
    ];

    smb2_header.extend_from_slice(&negotiate_body);

    // NetBIOS session header
    #[allow(clippy::cast_possible_truncation)]
    let smb_len = smb2_header.len() as u32;
    let mut packet = Vec::with_capacity(4 + smb2_header.len());
    packet.push(0x00);
    packet.push(((smb_len >> 16) & 0xFF) as u8);
    packet.push(((smb_len >> 8) & 0xFF) as u8);
    packet.push((smb_len & 0xFF) as u8);
    packet.extend_from_slice(&smb2_header);

    packet
}

/// Build a minimal `SMBv2` `SESSION_SETUP` request with empty credentials (null session).
fn build_smb2_session_setup_anonymous() -> Vec<u8> {
    let mut smb2_header = vec![
        0xFE, b'S', b'M', b'B', // Protocol ID
        0x40, 0x00, // Structure Size: 64
        0x00, 0x00, // Credit Charge
        0x00, 0x00, 0x00, 0x00, // Status
        0x01, 0x00, // Command: SESSION_SETUP (0x0001)
        0x01, 0x00, // Credit Request: 1
        0x00, 0x00, 0x00, 0x00, // Flags
        0x00, 0x00, 0x00, 0x00, // Next Command
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID: 1
        0x00, 0x00, 0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, // Tree ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // Session Setup request body with empty security buffer (anonymous)
    let session_body = vec![
        0x19, 0x00, // StructureSize: 25
        0x00, // Flags: 0
        0x01, // SecurityMode: signing enabled
        0x00, 0x00, 0x00, 0x00, // Capabilities
        0x00, 0x00, 0x00, 0x00, // Channel
        0x58, 0x00, // SecurityBufferOffset: 88 (64 header + 24 body so far)
        0x00, 0x00, // SecurityBufferLength: 0 (empty = anonymous)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PreviousSessionId
    ];

    smb2_header.extend_from_slice(&session_body);

    // NetBIOS session header
    #[allow(clippy::cast_possible_truncation)]
    let smb_len = smb2_header.len() as u32;
    let mut packet = Vec::with_capacity(4 + smb2_header.len());
    packet.push(0x00);
    packet.push(((smb_len >> 16) & 0xFF) as u8);
    packet.push(((smb_len >> 8) & 0xFF) as u8);
    packet.push((smb_len & 0xFF) as u8);
    packet.extend_from_slice(&smb2_header);

    packet
}

/// Status codes from SMB2 responses.
const STATUS_SUCCESS: u32 = 0x0000_0000;

/// Result of an `SMBv2` null session check.
struct NullSessionResult {
    /// Whether anonymous access was granted.
    allowed: bool,
    /// Session ID from the `SMBv2` response header (bytes 44-51).
    session_id: Option<u64>,
}

/// Attempt an anonymous `SMBv2` session setup (null session).
/// Returns session result with session ID evidence on success,
/// or `None` if we couldn't connect or parse the response.
async fn check_null_session(ip: IpAddr, port: u16) -> Option<NullSessionResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Step 1: Send SMBv2 NEGOTIATE
    let negotiate = build_smb2_negotiate();
    tokio::time::timeout(READ_TIMEOUT, stream.write_all(&negotiate))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    // Verify we got an SMBv2 response
    if n < 12 || buf[4] != 0xFE || &buf[5..8] != b"SMB" {
        return None;
    }

    // Step 2: Send SESSION_SETUP with empty credentials
    let session_setup = build_smb2_session_setup_anonymous();
    tokio::time::timeout(READ_TIMEOUT, stream.write_all(&session_setup))
        .await
        .ok()?
        .ok()?;

    let mut resp = vec![0u8; 512];
    let n2 = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut resp))
        .await
        .ok()?
        .ok()?;

    if n2 < 16 || resp[4] != 0xFE || &resp[5..8] != b"SMB" {
        return None;
    }

    // Extract NT Status from bytes 12-15 (little-endian)
    let nt_status = u32::from_le_bytes([resp[12], resp[13], resp[14], resp[15]]);
    let allowed = nt_status == STATUS_SUCCESS;

    // Extract Session ID from SMBv2 header bytes 44-51 (packet offset 48-55)
    let session_id = if allowed && n2 >= 56 {
        Some(u64::from_le_bytes([
            resp[48], resp[49], resp[50], resp[51], resp[52], resp[53], resp[54], resp[55],
        ]))
    } else {
        None
    };

    Some(NullSessionResult {
        allowed,
        session_id,
    })
}

/// Check `NetBIOS` Session Service on port 139.
async fn check_netbios(ip: IpAddr) -> bool {
    let addr = SocketAddr::new(ip, 139);
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .is_ok_and(|r| r.is_ok())
}

/// Build a human-readable summary of `SMBv1` protocol details.
fn format_smbv1_details(info: &SmbV1Info) -> String {
    let mut parts = Vec::new();
    if info.signing_required {
        parts.push("signing required");
    } else {
        parts.push("signing NOT required");
    }
    if info.extended_security {
        parts.push("extended security (SPNEGO)");
    } else {
        parts.push("legacy auth (no SPNEGO)");
    }
    parts.join(", ")
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl Scanner for SmbScanner {
    fn id(&self) -> &'static str {
        "smb"
    }

    fn name(&self) -> &'static str {
        "SMB Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running SMB security scan");
        let mut findings = Vec::new();

        // Collect targets with port 445 or 139 open
        let targets: Vec<IpAddr> = if ctx.discovered_devices.is_empty() {
            // Fallback: probe all ARP cache IPs
            let arp_entries =
                rikitikitavi_network::read_arp_cache().map_err(|e| ScanError::ScannerFailed {
                    scanner: "smb".to_owned(),
                    message: format!("failed to read ARP cache: {e}"),
                })?;
            arp_entries.iter().map(|e| e.ip).collect()
        } else {
            ctx.discovered_devices
                .iter()
                .filter(|d| d.open_ports.iter().any(|p| p.port == 445 || p.port == 139))
                .map(|d| d.ip)
                .collect()
        };

        if targets.is_empty() {
            tracing::info!("no SMB targets found");
            return Ok(findings);
        }

        tracing::info!(target_count = targets.len(), "checking SMB security");

        for &ip in &targets {
            // Check for SMBv1 support
            if let Some(version) = check_smbv1(ip, 445).await {
                match version {
                    SmbVersion::V1(ref info) => {
                        if info.dialect_accepted {
                            // Confirmed SMBv1 support — now check if SMBv2+ is also available
                            let also_v2 = check_smbv2_support(ip, 445).await;
                            let details = format_smbv1_details(info);

                            if also_v2 {
                                // Server supports both SMBv1 and SMBv2+.
                                // SMBv1 is likely enabled for backward compatibility.
                                // Still a risk (downgrade attacks possible) but lower
                                // severity than a legacy-only SMBv1 system.
                                findings.push(
                                    Finding::new(
                                        "smb",
                                        &format!("SMBv1 enabled alongside SMBv2+ on {ip}:445"),
                                        &format!(
                                            "Host {ip} supports SMBv1 in addition to SMBv2+. \
                                             While the server supports modern protocols, having \
                                             SMBv1 enabled allows protocol downgrade attacks and \
                                             exposes the host to EternalBlue (MS17-010) if \
                                             unpatched. Protocol details: {details}."
                                        ),
                                        Severity::High,
                                    )
                                    .with_ip(ip)
                                    .with_port(445)
                                    .with_service("SMB")
                                    .with_cwe("CWE-327")
                                    .with_references(vec![
                                        "https://attack.mitre.org/techniques/T1210/".to_owned(),
                                    ])
                                    .with_opt_remediation(
                                        crate::remediation::get(
                                            "rikitikitavi.smb.smbv1-enabled",
                                            &[],
                                        ),
                                    ),
                                );
                            } else {
                                // Server only supports SMBv1 — legacy system, most dangerous
                                findings.push(
                                    Finding::new(
                                        "smb",
                                        &format!("SMBv1-only server at {ip}:445"),
                                        &format!(
                                            "Host {ip} supports only SMBv1 with no SMBv2+ \
                                             support. This indicates a legacy or severely \
                                             misconfigured system vulnerable to EternalBlue \
                                             (MS17-010), WannaCry, and other critical exploits. \
                                             SMBv1 has been deprecated since 2014. \
                                             Protocol details: {details}."
                                        ),
                                        Severity::Critical,
                                    )
                                    .with_ip(ip)
                                    .with_port(445)
                                    .with_service("SMB")
                                    .with_cwe("CWE-327")
                                    .with_opt_remediation(
                                        crate::remediation::get(
                                            "rikitikitavi.smb.smbv1-enabled",
                                            &[],
                                        ),
                                    ),
                                );
                            }
                        } else {
                            // Server responded with SMBv1 framing but rejected the dialect.
                            // This is NOT a confirmed SMBv1 vulnerability — the server
                            // understood the SMBv1 protocol frame but chose not to accept
                            // our offered dialect. Commonly seen on modern Windows that
                            // still processes SMBv1 frames to redirect to SMBv2.
                            tracing::debug!(
                                ip = %ip,
                                "SMBv1 response received but dialect rejected — not vulnerable"
                            );
                            findings.push(
                                Finding::new(
                                    "smb",
                                    &format!("SMB service on {ip}:445 — SMBv1 dialect rejected"),
                                    &format!(
                                        "Host {ip} responded to an SMBv1 negotiate but did not \
                                         accept the offered dialect. This typically indicates a \
                                         modern server that processes SMBv1 frames for protocol \
                                         negotiation but does not support SMBv1 file sharing."
                                    ),
                                    Severity::Info,
                                )
                                .with_ip(ip)
                                .with_port(445)
                                .with_service("SMB"),
                            );
                        }
                    }
                    SmbVersion::V2Plus => {
                        findings.push(
                            Finding::new(
                                "smb",
                                &format!("SMB service on {ip}:445 uses SMBv2+"),
                                &format!(
                                    "Host {ip} correctly uses SMBv2 or later for SMB. \
                                     SMBv1 is not enabled."
                                ),
                                Severity::Info,
                            )
                            .with_ip(ip)
                            .with_port(445)
                            .with_service("SMB"),
                        );
                    }
                    SmbVersion::Unknown => {
                        findings.push(
                            Finding::new(
                                "smb",
                                &format!("Unrecognized service on {ip}:445"),
                                &format!(
                                    "Port 445 on {ip} is open but responded with an \
                                     unrecognized protocol. This may not be an SMB service. \
                                     Manual verification recommended."
                                ),
                                Severity::Low,
                            )
                            .with_ip(ip)
                            .with_port(445)
                            .with_service("unknown"),
                        );
                    }
                }
            }

            // Check for anonymous/null session access
            if let Some(result) = check_null_session(ip, 445).await {
                if result.allowed {
                    let mut finding = Finding::new(
                        "smb",
                        &format!("SMB null session allowed on {ip}:445"),
                        &format!(
                            "Host {ip} accepts anonymous SMBv2 session setup (null session). \
                             This allows unauthenticated users to enumerate shares, users, \
                             and other sensitive information."
                        ),
                        Severity::High,
                    )
                    .with_ip(ip)
                    .with_port(445)
                    .with_service("SMB")
                    .with_cwe("CWE-287")
                    .with_opt_remediation(crate::remediation::get(
                        "rikitikitavi.smb.null-session",
                        &[],
                    ));
                    if let Some(sid) = result.session_id {
                        finding = finding.with_evidence(format!(
                            "Anonymous SMBv2 session established (session ID: {sid:#x})"
                        ));
                    }
                    findings.push(finding);
                }
            }

            // Check NetBIOS on port 139
            if check_netbios(ip).await {
                findings.push(
                    Finding::new(
                        "smb",
                        &format!("NetBIOS Session Service exposed on {ip}:139"),
                        &format!(
                            "NetBIOS on {ip}:139 is accessible. NetBIOS over TCP exposes \
                             host names, workgroup information, and can be used for \
                             enumeration. It is generally unnecessary on modern networks."
                        ),
                        Severity::Medium,
                    )
                    .with_ip(ip)
                    .with_port(139)
                    .with_service("NetBIOS")
                    .with_cwe("CWE-200")
                    .with_references(vec![
                        "https://attack.mitre.org/techniques/T1046/".to_owned(),
                    ])
                    .with_opt_remediation(crate::remediation::get(
                        "rikitikitavi.smb.netbios-exposed",
                        &[],
                    )),
                );
            }
        }

        tracing::info!(
            findings_count = findings.len(),
            "SMB security scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        20
    }

    fn relevant_ports(&self) -> &[u16] {
        &[445, 139]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── SMB response classification tests ───────────────────────────

    #[test]
    fn test_classify_smbv1_response_accepted() {
        // NetBIOS header (4) + \xFFSMB + header padding + WordCount=17 + DialectIndex=0
        let mut response = vec![0x00, 0x00, 0x00, 0x40]; // NetBIOS
        response.push(0xFF); // SMBv1 magic
        response.extend_from_slice(b"SMB");
        response.extend_from_slice(&[0; 28]); // Rest of 32-byte SMB header
        response.push(17); // WordCount = 17 (NT LM 0.12 response)
        response.extend_from_slice(&[0x00, 0x00]); // DialectIndex = 0 (accepted)
        response.push(0x03); // SecurityMode: signing supported + required
        response.extend_from_slice(&[0; 4]); // padding to capabilities
        response.extend_from_slice(&0x8000_0000_u32.to_le_bytes()); // CAP_EXTENDED_SECURITY
        response.extend_from_slice(&[0; 16]); // padding
        let result = classify_smb_response(&response);
        assert_eq!(
            result,
            SmbVersion::V1(SmbV1Info {
                dialect_accepted: true,
                signing_required: true,
                extended_security: true,
            })
        );
    }

    #[test]
    fn test_classify_smbv1_response_dialect_rejected() {
        // Server responds with SMBv1 framing but DialectIndex = 0xFFFF
        let mut response = vec![0x00, 0x00, 0x00, 0x30]; // NetBIOS
        response.push(0xFF);
        response.extend_from_slice(b"SMB");
        response.extend_from_slice(&[0; 28]); // 32-byte header
        response.push(17); // WordCount
        response.extend_from_slice(&[0xFF, 0xFF]); // DialectIndex = 0xFFFF (rejected)
        response.push(0x00); // SecurityMode
        response.extend_from_slice(&[0; 20]); // padding
        let result = classify_smb_response(&response);
        match result {
            SmbVersion::V1(info) => {
                assert!(!info.dialect_accepted, "dialect should be rejected");
            }
            other => panic!("expected V1 with rejected dialect, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_smbv1_minimal_response() {
        // Minimal SMBv1 response (short, no negotiate details)
        let mut response = vec![0x00, 0x00, 0x00, 0x20];
        response.push(0xFF);
        response.extend_from_slice(b"SMB");
        // Only 4 more bytes — not enough for negotiate details
        response.extend_from_slice(&[0; 4]);
        let result = classify_smb_response(&response);
        match result {
            SmbVersion::V1(info) => {
                assert!(
                    !info.dialect_accepted,
                    "short response should not confirm dialect"
                );
            }
            other => panic!("expected V1 with unconfirmed dialect, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_smbv2_response() {
        let mut response = vec![0x00, 0x00, 0x00, 0x40];
        response.push(0xFE); // SMBv2 magic
        response.extend_from_slice(b"SMB");
        response.extend_from_slice(&[0; 60]);
        assert_eq!(classify_smb_response(&response), SmbVersion::V2Plus);
    }

    #[test]
    fn test_classify_smb_unknown() {
        let response = vec![0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(classify_smb_response(&response), SmbVersion::Unknown);
    }

    #[test]
    fn test_classify_smb_too_short() {
        assert_eq!(classify_smb_response(&[0; 4]), SmbVersion::Unknown);
    }

    #[test]
    fn test_classify_smb_empty() {
        assert_eq!(classify_smb_response(&[]), SmbVersion::Unknown);
    }

    // ── SMBv1 negotiate response detail parsing ─────────────────────

    #[test]
    fn test_parse_smbv1_details_signing_required() {
        let mut response = vec![0x00; 50];
        response[4] = 0xFF;
        response[5..8].copy_from_slice(b"SMB");
        response[36] = 17; // WordCount
        response[37] = 0x00; // DialectIndex = 0
        response[38] = 0x00;
        response[39] = 0x03; // SecurityMode: signing supported + required
        let details = parse_smbv1_negotiate_details(&response);
        assert!(details.dialect_accepted);
        assert!(details.signing_required);
    }

    #[test]
    fn test_parse_smbv1_details_no_signing() {
        let mut response = vec![0x00; 50];
        response[4] = 0xFF;
        response[5..8].copy_from_slice(b"SMB");
        response[36] = 17;
        response[37] = 0x00;
        response[38] = 0x00;
        response[39] = 0x01; // SecurityMode: signing supported only
        let details = parse_smbv1_negotiate_details(&response);
        assert!(details.dialect_accepted);
        assert!(!details.signing_required);
    }

    #[test]
    fn test_parse_smbv1_details_word_count_zero() {
        let mut response = vec![0x00; 50];
        response[4] = 0xFF;
        response[5..8].copy_from_slice(b"SMB");
        response[36] = 0; // WordCount = 0 → error response
        let details = parse_smbv1_negotiate_details(&response);
        assert!(!details.dialect_accepted);
    }

    #[test]
    fn test_format_smbv1_details_with_signing() {
        let info = SmbV1Info {
            dialect_accepted: true,
            signing_required: true,
            extended_security: true,
        };
        let s = format_smbv1_details(&info);
        assert!(s.contains("signing required"));
        assert!(s.contains("SPNEGO"));
    }

    #[test]
    fn test_format_smbv1_details_without_signing() {
        let info = SmbV1Info {
            dialect_accepted: true,
            signing_required: false,
            extended_security: false,
        };
        let s = format_smbv1_details(&info);
        assert!(s.contains("signing NOT required"));
        assert!(s.contains("legacy auth"));
    }

    // ── SMBv1 negotiate packet tests ────────────────────────────────

    #[test]
    fn test_smb1_negotiate_packet_valid() {
        let packet = build_smb1_negotiate();
        // Must start with NetBIOS session header
        assert_eq!(packet[0], 0x00);
        // SMB magic at offset 4
        assert_eq!(packet[4], 0xFF);
        assert_eq!(&packet[5..8], b"SMB");
        // Command: Negotiate (0x72)
        assert_eq!(packet[8], 0x72);
    }

    #[test]
    fn test_smb1_negotiate_contains_dialect() {
        let packet = build_smb1_negotiate();
        let packet_str = String::from_utf8_lossy(&packet);
        assert!(packet_str.contains("NT LM 0.12"));
    }

    // ── Proptests ───────────────────────────────────────────────────

    proptest! {
        #[test]
        fn prop_classify_smb_response_no_panic(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = classify_smb_response(&data);
        }

        #[test]
        fn prop_parse_smbv1_details_no_panic(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_smbv1_negotiate_details(&data);
        }

        #[test]
        fn prop_build_smb1_negotiate_is_valid(_dummy in 0_u8..1_u8) {
            let packet = build_smb1_negotiate();
            assert!(packet.len() > 8, "negotiate packet too short");
            assert_eq!(packet[4], 0xFF, "missing SMBv1 magic");
        }
    }
}
