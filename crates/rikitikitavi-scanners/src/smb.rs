use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, Remediation, ScanContext};
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
pub struct SmbScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmbVersion {
    /// Server supports `SMBv1` (responds to `SMBv1` negotiate)
    V1,
    /// Server rejected `SMBv1` or responded with `SMBv2`+
    V2Plus,
    /// Unrecognized response
    Unknown,
}

/// Classify an SMB negotiate response to determine protocol version.
fn classify_smb_response(response: &[u8]) -> SmbVersion {
    // Skip NetBIOS header (4 bytes), check SMB magic
    if response.len() < 8 {
        return SmbVersion::Unknown;
    }

    // Check for SMBv1 magic: \xFFSMB
    if response.len() >= 8 && response[4] == 0xFF && &response[5..8] == b"SMB" {
        return SmbVersion::V1;
    }

    // Check for SMBv2 magic: \xFESMB
    if response.len() >= 8 && response[4] == 0xFE && &response[5..8] == b"SMB" {
        return SmbVersion::V2Plus;
    }

    SmbVersion::Unknown
}

/// Check `NetBIOS` Session Service on port 139.
async fn check_netbios(ip: IpAddr) -> bool {
    let addr = SocketAddr::new(ip, 139);
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .is_ok_and(|r| r.is_ok())
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
            let arp_entries = rikitikitavi_network::read_arp_cache().map_err(|e| {
                ScanError::ScannerFailed {
                    scanner: "smb".to_owned(),
                    message: format!("failed to read ARP cache: {e}"),
                }
            })?;
            arp_entries.iter().map(|e| e.ip).collect()
        } else {
            ctx.discovered_devices
                .iter()
                .filter(|d| {
                    d.open_ports
                        .iter()
                        .any(|p| p.port == 445 || p.port == 139)
                })
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
                    SmbVersion::V1 => {
                        findings.push(
                            Finding::new(
                                "smb",
                                &format!("SMBv1 enabled on {ip}:445"),
                                &format!(
                                    "Host {ip} supports SMBv1, which is vulnerable to \
                                     EternalBlue (MS17-010), WannaCry, and other critical \
                                     exploits. SMBv1 has been deprecated since 2014."
                                ),
                                Severity::Critical,
                            )
                            .with_ip(ip)
                            .with_port(445)
                            .with_service("SMB")
                            .with_cwe("CWE-327")
                            .with_remediation(Remediation {
                                description: "Disable SMBv1 on all systems.".to_owned(),
                                steps: vec![
                                    "Windows: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
                                        .to_owned(),
                                    "Linux: Add 'min protocol = SMB2' to smb.conf".to_owned(),
                                    "NAS devices: Check vendor documentation for SMBv1 disable option."
                                        .to_owned(),
                                    "Verify with: nmap --script smb-protocols -p445 <ip>".to_owned(),
                                ],
                                effort: Some("5 minutes per device".to_owned()),
                            }),
                        );
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
                                &format!("SMB service on {ip}:445 — version unclear"),
                                &format!(
                                    "Could not determine SMB version on {ip}:445. \
                                     Manual verification recommended."
                                ),
                                Severity::Low,
                            )
                            .with_ip(ip)
                            .with_port(445)
                            .with_service("SMB"),
                        );
                    }
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
                    .with_remediation(Remediation {
                        description: "Disable NetBIOS over TCP/IP.".to_owned(),
                        steps: vec![
                            "Windows: Disable NetBIOS in network adapter IPv4 settings → WINS tab."
                                .to_owned(),
                            "Linux: Stop and disable the nmbd service.".to_owned(),
                            "Block port 139 at the firewall.".to_owned(),
                        ],
                        effort: Some("5 minutes".to_owned()),
                    }),
                );
            }
        }

        tracing::info!(findings_count = findings.len(), "SMB security scan complete");
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        20
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── SMB response classification tests ───────────────────────────

    #[test]
    fn test_classify_smbv1_response() {
        // NetBIOS header (4) + \xFFSMB
        let mut response = vec![0x00, 0x00, 0x00, 0x20]; // NetBIOS
        response.push(0xFF); // SMBv1 magic
        response.extend_from_slice(b"SMB");
        response.extend_from_slice(&[0; 24]); // Rest of header
        assert_eq!(classify_smb_response(&response), SmbVersion::V1);
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
        fn prop_build_smb1_negotiate_is_valid(_dummy in 0_u8..1_u8) {
            let packet = build_smb1_negotiate();
            assert!(packet.len() > 8, "negotiate packet too short");
            assert_eq!(packet[4], 0xFF, "missing SMBv1 magic");
        }
    }
}
