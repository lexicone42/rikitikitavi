use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Scanner;

/// MQTT broker anonymous-access scanner.
///
/// MQTT is the workhorse pub/sub protocol of consumer and industrial `IoT`.
/// A broker that accepts anonymous CONNECTs lets anyone on the LAN subscribe
/// to every topic (sensor readings, camera events, lock state) and publish
/// forged control messages. This scanner performs a single, non-destructive
/// MQTT v3.1.1 CONNECT/CONNACK exchange to determine whether the broker
/// requires authentication. It never subscribes or publishes.
///
/// Like [`crate::database::DatabaseScanner`], it only probes hosts that Phase 1
/// discovered with the relevant port open — it never blindly connects to every
/// host on the network.
pub struct MqttScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Plaintext MQTT and MQTT-over-TLS ports.
const MQTT_PORTS: &[u16] = &[1883, 8883];

/// Client identifier sent in the CONNECT probe. Short, benign, and identifies
/// the scan in broker logs so operators can see what connected.
const MQTT_CLIENT_ID: &str = "rikitikitavi-scan";

/// Verdict from classifying an MQTT CONNACK packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnackVerdict {
    /// Return code `0x00` — broker accepted an anonymous connection.
    Accepted,
    /// Return code `0x04` — bad username or password (auth is enforced).
    BadCredentials,
    /// Return code `0x05` — not authorized (auth is enforced).
    NotAuthorized,
    /// Some other non-zero return code (e.g. identifier rejected).
    Refused(u8),
    /// Response was not a well-formed CONNACK.
    Malformed,
}

/// Encode a value as an MQTT "remaining length" variable byte integer.
///
/// MQTT encodes lengths in 1–4 bytes, 7 bits per byte, with the high bit of
/// each byte signalling continuation. Values up to `268_435_455` are legal.
fn encode_remaining_length(mut len: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = u8::try_from(len % 128).unwrap_or(0);
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
}

/// Build a minimal MQTT v3.1.1 CONNECT packet.
///
/// Layout (protocol level 4, clean session, no username/password):
/// ```text
/// Fixed header:
///   [1] packet type + flags: 0x10 (CONNECT)
///   [n] remaining length (variable byte integer)
/// Variable header:
///   [2] protocol name length: 0x00 0x04
///   [4] protocol name: "MQTT"
///   [1] protocol level: 0x04 (v3.1.1)
///   [1] connect flags: 0x02 (clean session only)
///   [2] keep alive: 0x00 0x3C (60s)
/// Payload:
///   [2] client id length
///   [n] client id bytes
/// ```
fn build_connect_packet(client_id: &str) -> Vec<u8> {
    let mut body = Vec::new();
    // Protocol name "MQTT"
    body.extend_from_slice(&[0x00, 0x04]);
    body.extend_from_slice(b"MQTT");
    // Protocol level 4 (MQTT v3.1.1)
    body.push(0x04);
    // Connect flags: bit 1 = clean session; username/password bits clear.
    body.push(0x02);
    // Keep alive: 60 seconds.
    body.extend_from_slice(&[0x00, 0x3C]);
    // Payload: client identifier, length-prefixed (big-endian u16).
    let id_len = u16::try_from(client_id.len()).unwrap_or(0);
    body.extend_from_slice(&id_len.to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());

    let mut packet = Vec::with_capacity(body.len() + 5);
    packet.push(0x10); // CONNECT control packet type
    encode_remaining_length(body.len(), &mut packet);
    packet.extend_from_slice(&body);
    packet
}

/// Classify a CONNACK response.
///
/// A CONNACK is `0x20 0x02 <ack flags> <return code>`. We treat return code
/// `0x00` as proof the broker accepts anonymous connections. Anything that is
/// not a well-formed CONNACK is [`ConnackVerdict::Malformed`].
fn classify_connack(data: &[u8]) -> ConnackVerdict {
    // Need at least: type(1) + remaining len(1) + ack flags(1) + return code(1).
    if data.len() < 4 || data[0] != 0x20 {
        return ConnackVerdict::Malformed;
    }
    match data[3] {
        0x00 => ConnackVerdict::Accepted,
        0x04 => ConnackVerdict::BadCredentials,
        0x05 => ConnackVerdict::NotAuthorized,
        other => ConnackVerdict::Refused(other),
    }
}

/// Human-readable label for an MQTT v3.1.1 CONNACK return code.
const fn connack_reason(code: u8) -> &'static str {
    match code {
        0x00 => "connection accepted",
        0x01 => "unacceptable protocol version",
        0x02 => "identifier rejected",
        0x03 => "server unavailable",
        0x04 => "bad username or password",
        0x05 => "not authorized",
        _ => "unknown return code",
    }
}

/// Probe an MQTT broker: send a CONNECT, read the CONNACK, classify it.
///
/// Returns `None` on any connect/read/timeout error, or a [`ConnackVerdict`]
/// describing whether the broker accepted the anonymous connection.
async fn check_mqtt_anonymous(ip: IpAddr, port: u16) -> Option<ConnackVerdict> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let packet = build_connect_packet(MQTT_CLIENT_ID);
    tokio::time::timeout(READ_TIMEOUT, stream.write_all(&packet))
        .await
        .ok()?
        .ok()?;

    // A CONNACK is only 4 bytes; a small buffer is plenty.
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    Some(classify_connack(&buf[..n]))
}

#[async_trait]
impl Scanner for MqttScanner {
    fn id(&self) -> &'static str {
        "mqtt"
    }

    fn name(&self) -> &'static str {
        "MQTT Broker Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running MQTT broker security scan");
        let mut findings = Vec::new();

        // Skip in Passive mode — an application-layer handshake is more than a
        // quick scan should do.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping MQTT scan in quick scan mode");
            return Ok(findings);
        }

        // Only target hosts Phase 1 found with an MQTT port actually open. We
        // never blindly connect to every host, so if no port scan has run we
        // have nothing to probe.
        let targets: Vec<(IpAddr, Vec<u16>)> = ctx
            .discovered_devices
            .iter()
            .map(|d| {
                let mqtt_ports: Vec<u16> = d
                    .open_ports
                    .iter()
                    .filter(|p| MQTT_PORTS.contains(&p.port))
                    .map(|p| p.port)
                    .collect();
                (d.ip, mqtt_ports)
            })
            .filter(|(_, ports)| !ports.is_empty())
            .collect();

        if targets.is_empty() {
            tracing::info!("no MQTT targets found");
            return Ok(findings);
        }

        tracing::info!(
            target_count = targets.len(),
            "checking MQTT broker security"
        );

        for (ip, ports) in &targets {
            for &port in ports {
                match port {
                    1883 => check_mqtt_plain(ip, port, &mut findings).await,
                    8883 => check_mqtt_tls_advisory(ip, port, &mut findings),
                    _ => {}
                }
            }
        }

        tracing::info!(
            findings_count = findings.len(),
            "MQTT broker security scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        15
    }

    fn relevant_ports(&self) -> &[u16] {
        MQTT_PORTS
    }
}

/// Probe plaintext MQTT (1883) and emit findings based on the CONNACK.
async fn check_mqtt_plain(ip: &IpAddr, port: u16, findings: &mut Vec<Finding>) {
    let Some(verdict) = check_mqtt_anonymous(*ip, port).await else {
        return;
    };

    match verdict {
        ConnackVerdict::Accepted => {
            findings.push(
                Finding::new(
                    "mqtt",
                    &format!("MQTT broker allows anonymous connection on {ip}:{port}"),
                    &format!(
                        "The MQTT broker at {ip}:{port} accepted a CONNECT with no \
                         username or password (CONNACK return code 0x00). Any device \
                         on the network can subscribe to every topic — sensor data, \
                         camera and doorbell events, lock and alarm state — and publish \
                         forged control messages. Enable authentication (e.g. Mosquitto \
                         'allow_anonymous false' with a password file or client \
                         certificates) and restrict the broker to trusted hosts."
                    ),
                    Severity::High,
                )
                // The broker actually accepted our unauthenticated CONNECT —
                // this is demonstrated, not inferred.
                .with_confidence(rikitikitavi_core::Confidence::Confirmed)
                .with_ip(*ip)
                .with_port(port)
                .with_service("MQTT")
                .with_cwe("CWE-306")
                .with_evidence("CONNACK return code 0x00 (connection accepted)")
                .with_references(refs![
                    "https://cwe.mitre.org/data/definitions/306.html",
                    "https://owasp.org/www-project-internet-of-things/",
                ]),
            );
        }
        ConnackVerdict::NotAuthorized | ConnackVerdict::BadCredentials => {
            findings.push(
                Finding::new(
                    "mqtt",
                    &format!("MQTT broker requires authentication on {ip}:{port}"),
                    &format!(
                        "The MQTT broker at {ip}:{port} rejected an anonymous CONNECT \
                         and requires credentials. This is the correct posture."
                    ),
                    Severity::Info,
                )
                // We observed the rejection directly.
                .with_confidence(rikitikitavi_core::Confidence::Confirmed)
                .with_ip(*ip)
                .with_port(port)
                .with_service("MQTT"),
            );
        }
        // Identifier rejected / server unavailable / other: the broker is up but
        // the outcome does not demonstrate anonymous access, so we stay silent to
        // avoid noisy or misleading findings.
        ConnackVerdict::Refused(code) => {
            tracing::debug!(
                ip = %ip,
                port,
                code,
                reason = connack_reason(code),
                "MQTT broker refused connection with non-auth return code"
            );
        }
        ConnackVerdict::Malformed => {
            tracing::debug!(ip = %ip, port, "MQTT broker returned a non-CONNACK response");
        }
    }
}

/// Emit an informational finding for an MQTT-over-TLS broker (8883).
///
/// We deliberately do not perform the TLS handshake here — [`crate::ssl::SslScanner`]
/// covers certificate and protocol posture. This is a lightweight presence note
/// based on the open port, so its confidence is `Probable`.
fn check_mqtt_tls_advisory(ip: &IpAddr, port: u16, findings: &mut Vec<Finding>) {
    findings.push(
        Finding::new(
            "mqtt",
            &format!("MQTT-over-TLS broker present on {ip}:{port}"),
            &format!(
                "An MQTT-over-TLS broker is listening on {ip}:{port}. Anonymous-access \
                 checking would require a TLS handshake, which is not performed here; \
                 verify that the broker enforces authentication and review its TLS \
                 posture (certificate validity, protocol versions) in the SSL/TLS scan \
                 results."
            ),
            Severity::Info,
        )
        // Port-open inference plus the well-known service assignment — not a
        // completed handshake.
        .with_confidence(rikitikitavi_core::Confidence::Probable)
        .with_ip(*ip)
        .with_port(port)
        .with_service("MQTT-TLS"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── CONNECT packet builder tests ────────────────────────────────

    #[test]
    fn test_build_connect_packet_single_char_id() {
        let packet = build_connect_packet("A");
        // 0x10, remaining len 0x0D, then 13-byte body.
        let expected: Vec<u8> = vec![
            0x10, 0x0D, // fixed header
            0x00, 0x04, b'M', b'Q', b'T', b'T', // protocol name
            0x04, // protocol level (v3.1.1)
            0x02, // connect flags (clean session)
            0x00, 0x3C, // keep alive
            0x00, 0x01, b'A', // client id
        ];
        assert_eq!(packet, expected);
    }

    #[test]
    fn test_build_connect_packet_header_and_length() {
        let packet = build_connect_packet(MQTT_CLIENT_ID);
        assert_eq!(packet[0], 0x10, "must be a CONNECT control packet");
        // body = 10 (variable header) + 2 (id len) + client id length
        let expected_remaining = 12 + MQTT_CLIENT_ID.len();
        assert_eq!(usize::from(packet[1]), expected_remaining);
        // Total = 2-byte fixed header + body (remaining length is single-byte here).
        assert_eq!(packet.len(), 2 + expected_remaining);
    }

    #[test]
    fn test_build_connect_packet_protocol_fields() {
        let packet = build_connect_packet("x");
        // Protocol name "MQTT" sits right after the 2-byte fixed header.
        assert_eq!(&packet[2..8], &[0x00, 0x04, b'M', b'Q', b'T', b'T']);
        assert_eq!(packet[8], 0x04, "protocol level 4");
        assert_eq!(packet[9], 0x02, "clean session, no username/password");
        assert_eq!(&packet[10..12], &[0x00, 0x3C], "keep alive 60s");
    }

    #[test]
    fn test_build_connect_packet_empty_id() {
        let packet = build_connect_packet("");
        // body = 10 + 2 + 0 = 12; last two bytes are the zero-length client id.
        assert_eq!(packet[1], 12);
        assert_eq!(&packet[packet.len() - 2..], &[0x00, 0x00]);
    }

    // ── remaining-length varint tests ───────────────────────────────

    #[test]
    fn test_encode_remaining_length_examples() {
        // Canonical MQTT specification boundary values.
        let cases: &[(usize, &[u8])] = &[
            (0, &[0x00]),
            (127, &[0x7F]),
            (128, &[0x80, 0x01]),
            (16383, &[0xFF, 0x7F]),
            (16384, &[0x80, 0x80, 0x01]),
            (268_435_455, &[0xFF, 0xFF, 0xFF, 0x7F]),
        ];
        for (input, expected) in cases {
            let mut out = Vec::new();
            encode_remaining_length(*input, &mut out);
            assert_eq!(&out, expected, "encoding {input}");
        }
    }

    // ── CONNACK classifier tests ────────────────────────────────────

    #[test]
    fn test_classify_connack_accepted() {
        assert_eq!(
            classify_connack(&[0x20, 0x02, 0x00, 0x00]),
            ConnackVerdict::Accepted
        );
    }

    #[test]
    fn test_classify_connack_session_present_still_accepted() {
        // ack flags byte set (session present) but return code still 0x00.
        assert_eq!(
            classify_connack(&[0x20, 0x02, 0x01, 0x00]),
            ConnackVerdict::Accepted
        );
    }

    #[test]
    fn test_classify_connack_not_authorized() {
        assert_eq!(
            classify_connack(&[0x20, 0x02, 0x00, 0x05]),
            ConnackVerdict::NotAuthorized
        );
    }

    #[test]
    fn test_classify_connack_bad_credentials() {
        assert_eq!(
            classify_connack(&[0x20, 0x02, 0x00, 0x04]),
            ConnackVerdict::BadCredentials
        );
    }

    #[test]
    fn test_classify_connack_other_refused() {
        assert_eq!(
            classify_connack(&[0x20, 0x02, 0x00, 0x02]),
            ConnackVerdict::Refused(0x02)
        );
        assert_eq!(
            classify_connack(&[0x20, 0x02, 0x00, 0x03]),
            ConnackVerdict::Refused(0x03)
        );
    }

    #[test]
    fn test_classify_connack_wrong_packet_type() {
        // 0x30 is PUBLISH, not CONNACK.
        assert_eq!(
            classify_connack(&[0x30, 0x02, 0x00, 0x00]),
            ConnackVerdict::Malformed
        );
    }

    #[test]
    fn test_classify_connack_too_short() {
        assert_eq!(classify_connack(&[0x20, 0x02]), ConnackVerdict::Malformed);
        assert_eq!(classify_connack(&[]), ConnackVerdict::Malformed);
    }

    // ── reason label tests ──────────────────────────────────────────

    #[test]
    fn test_connack_reason_labels() {
        assert_eq!(connack_reason(0x00), "connection accepted");
        assert_eq!(connack_reason(0x05), "not authorized");
        assert_eq!(connack_reason(0xFF), "unknown return code");
    }

    // ── Proptests ───────────────────────────────────────────────────

    proptest! {
        /// The classifier never panics on arbitrary bytes.
        #[test]
        fn prop_classify_connack_no_panic(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = classify_connack(&data);
        }

        /// Only a leading 0x20 with a 0x00 return code (>= 4 bytes) is "Accepted".
        #[test]
        fn prop_accepted_requires_zero_return_code(
            data in proptest::collection::vec(any::<u8>(), 0..64)
        ) {
            if classify_connack(&data) == ConnackVerdict::Accepted {
                prop_assert!(data.len() >= 4);
                prop_assert_eq!(data[0], 0x20);
                prop_assert_eq!(data[3], 0x00);
            }
        }

        /// The builder always produces a CONNECT packet whose remaining-length
        /// field matches the actual body size, for short client ids.
        #[test]
        fn prop_build_connect_packet_wellformed(id in "[ -~]{0,115}") {
            let packet = build_connect_packet(&id);
            prop_assert_eq!(packet[0], 0x10);
            // id <= 115 keeps body_len <= 127, so remaining length is a single byte.
            let body_len = 12 + id.len();
            prop_assert_eq!(usize::from(packet[1]), body_len);
            prop_assert_eq!(packet.len(), 2 + body_len);
        }

        /// Encoding then re-reading a varint round-trips the value.
        #[test]
        fn prop_encode_remaining_length_roundtrip(value in 0usize..=268_435_455) {
            let mut out = Vec::new();
            encode_remaining_length(value, &mut out);
            // Decode per MQTT spec.
            let mut multiplier: usize = 1;
            let mut decoded: usize = 0;
            for &byte in &out {
                decoded += usize::from(byte & 0x7F) * multiplier;
                multiplier *= 128;
            }
            prop_assert_eq!(decoded, value);
            prop_assert!(out.len() <= 4);
        }
    }
}
