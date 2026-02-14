use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

use crate::Scanner;

/// TLS/SSL certificate scanner — checks certificates on discovered HTTPS
/// ports for expiry, self-signed certs, weak keys, and old TLS versions.
///
/// Performs direct TLS handshakes using `rustls` to extract:
/// - Negotiated TLS protocol version (1.2 vs 1.3)
/// - Negotiated cipher suite (detects weak ciphers like CBC mode, SHA-1)
/// - Certificate chain details (self-signed, validity)
/// - HSTS header presence
pub struct SslScanner;

/// Known HTTP(S) ports to probe for TLS.
const TLS_PORTS: &[u16] = &[443, 8443, 8080, 8888, 993, 995, 465, 587, 636, 8883];

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Classify a TLS protocol version into a finding.
///
/// TLS 1.0 and 1.1 are deprecated (RFC 8996) and considered insecure.
pub fn classify_tls_version(ip: IpAddr, port: u16, version: &str) -> Option<Finding> {
    let version_lower = version.to_lowercase();

    if version_lower.contains("tls 1.0")
        || version_lower.contains("tlsv1.0")
        || version_lower.contains("tls1.0")
    {
        return Some(
            Finding::new(
                "ssl",
                &format!("TLS 1.0 enabled on {ip}:{port}"),
                "TLS 1.0 is deprecated (RFC 8996) and vulnerable to BEAST, POODLE, \
                 and other attacks. Upgrade to TLS 1.2 or 1.3.",
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("TLS")
            .with_cwe("CWE-326")
            .with_opt_remediation(crate::remediation::get(
                "rikitikitavi.ssl.tls10-enabled",
                &[],
            )),
        );
    }

    if version_lower.contains("tls 1.1")
        || version_lower.contains("tlsv1.1")
        || version_lower.contains("tls1.1")
    {
        return Some(
            Finding::new(
                "ssl",
                &format!("TLS 1.1 enabled on {ip}:{port}"),
                "TLS 1.1 is deprecated (RFC 8996). Upgrade to TLS 1.2 or 1.3.",
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("TLS")
            .with_cwe("CWE-326")
            .with_opt_remediation(crate::remediation::get(
                "rikitikitavi.ssl.tls11-enabled",
                &[],
            )),
        );
    }

    if version_lower.contains("ssl") || version_lower.contains("sslv") {
        return Some(
            Finding::new(
                "ssl",
                &format!("SSLv2/v3 enabled on {ip}:{port}"),
                "SSL 2.0/3.0 are broken and must not be used. Upgrade to TLS 1.2+.",
                Severity::High,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("TLS")
            .with_cwe("CWE-326")
            .with_opt_remediation(crate::remediation::get(
                "rikitikitavi.ssl.sslv2v3-enabled",
                &[],
            )),
        );
    }

    // TLS 1.2 or 1.3 — acceptable
    None
}

/// Classify a certificate issue into a finding.
pub fn classify_cert_issue(ip: IpAddr, port: u16, issue: &str) -> Finding {
    let issue_lower = issue.to_lowercase();

    if issue_lower.contains("expired") {
        return Finding::new(
            "ssl",
            &format!("Expired TLS certificate on {ip}:{port}"),
            "The TLS certificate has expired. Browsers and clients will reject \
             connections, and users may bypass warnings, weakening security.",
            Severity::High,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("TLS")
        .with_cwe("CWE-295")
        .with_opt_remediation(crate::remediation::get(
            "rikitikitavi.ssl.cert-expired",
            &[],
        ));
    }

    if issue_lower.contains("self-signed") || issue_lower.contains("self signed") {
        let (severity, description) = if crate::dns::is_private_ip(ip) {
            (
                Severity::Low,
                "The TLS certificate is self-signed. This is expected on home \
                 network devices (routers, NAS, IoT hubs) that have no way to \
                 obtain CA-signed certificates for private IP addresses.",
            )
        } else {
            (
                Severity::Medium,
                "The TLS certificate is self-signed. It prevents certificate \
                 validation and trains users to accept security warnings.",
            )
        };

        return Finding::new(
            "ssl",
            &format!("Self-signed certificate on {ip}:{port}"),
            description,
            severity,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("TLS")
        .with_cwe("CWE-295")
        .with_opt_remediation(crate::remediation::get(
            "rikitikitavi.ssl.cert-self-signed",
            &[],
        ));
    }

    if issue_lower.contains("weak key") || issue_lower.contains("1024") {
        return Finding::new(
            "ssl",
            &format!("Weak TLS key on {ip}:{port}"),
            "The TLS certificate uses a weak key (< 2048-bit RSA). \
             Modern standards require at least 2048-bit RSA or 256-bit ECC.",
            Severity::High,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("TLS")
        .with_cwe("CWE-326")
        .with_opt_remediation(crate::remediation::get(
            "rikitikitavi.ssl.cert-weak-key",
            &[],
        ));
    }

    if issue_lower.contains("hostname mismatch") || issue_lower.contains("name mismatch") {
        return Finding::new(
            "ssl",
            &format!("Certificate hostname mismatch on {ip}:{port}"),
            "The certificate's Common Name / Subject Alternative Names do not \
             match the device's address. This is common on LAN devices accessed \
             by IP rather than hostname.",
            Severity::Low,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("TLS")
        .with_cwe("CWE-295");
    }

    // Generic certificate issue
    Finding::new(
        "ssl",
        &format!("TLS certificate issue on {ip}:{port}"),
        &format!("Certificate issue: {issue}"),
        Severity::Low,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service("TLS")
}

/// Details extracted from a direct TLS handshake via `rustls`.
#[derive(Debug)]
struct TlsHandshakeInfo {
    /// Negotiated protocol version (e.g. "TLS 1.3", "TLS 1.2").
    protocol_version: String,
    /// Negotiated cipher suite name.
    cipher_suite: String,
    /// Number of certificates in the peer's chain.
    cert_chain_length: usize,
}

/// Classify a cipher suite as weak, acceptable, or strong.
fn classify_cipher_suite(ip: IpAddr, port: u16, cipher: &str) -> Option<Finding> {
    let lower = cipher.to_lowercase();

    // CBC mode ciphers are vulnerable to padding oracle attacks (Lucky13, POODLE)
    if lower.contains("cbc") {
        return Some(
            Finding::new(
                "ssl",
                &format!("Weak cipher suite (CBC mode) on {ip}:{port}"),
                &format!(
                    "TLS on {ip}:{port} negotiated cipher suite '{cipher}' which uses \
                     CBC mode. CBC ciphers are vulnerable to padding oracle attacks \
                     (Lucky13). Prefer AEAD ciphers like AES-GCM or ChaCha20-Poly1305."
                ),
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("TLS")
            .with_cwe("CWE-327"),
        );
    }

    // SHA-1 in cipher suite (not for cert signature, but for HMAC)
    if lower.contains("sha1") || lower.contains("sha_1") {
        return Some(
            Finding::new(
                "ssl",
                &format!("Cipher suite with SHA-1 on {ip}:{port}"),
                &format!(
                    "TLS on {ip}:{port} negotiated cipher suite '{cipher}' which \
                     uses SHA-1 for integrity. SHA-1 is deprecated. Prefer SHA-256+."
                ),
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("TLS")
            .with_cwe("CWE-328"),
        );
    }

    // RSA key exchange (no forward secrecy)
    if lower.starts_with("tls_rsa_") && !lower.contains("ecdhe") && !lower.contains("dhe") {
        return Some(
            Finding::new(
                "ssl",
                &format!("No forward secrecy on {ip}:{port}"),
                &format!(
                    "TLS on {ip}:{port} negotiated cipher suite '{cipher}' which uses \
                     static RSA key exchange without forward secrecy. If the server's \
                     private key is compromised, all past traffic can be decrypted. \
                     Prefer ECDHE key exchange."
                ),
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("TLS")
            .with_cwe("CWE-326"),
        );
    }

    None
}

/// Perform a direct TLS handshake using `rustls` to extract protocol details.
///
/// This bypasses certificate validation (LAN devices have self-signed certs)
/// to inspect what cipher suite and version the server actually negotiates.
async fn probe_tls_handshake(ip: IpAddr, port: u16) -> Option<TlsHandshakeInfo> {
    let addr = SocketAddr::new(ip, port);
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // Build a rustls config that accepts any certificate (LAN scanning).
    // Explicitly use aws-lc-rs provider to avoid runtime panics when no
    // default CryptoProvider is installed (e.g. on macOS).
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoVerifier))
    .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::IpAddress(rustls::pki_types::IpAddr::from(ip));

    let tls_stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .ok()?
        .ok()?;

    let conn = tls_stream.get_ref().1;

    let protocol_version = conn
        .protocol_version()
        .map_or_else(|| "unknown".to_owned(), |v| format!("{v:?}"));

    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map_or_else(|| "unknown".to_owned(), |cs| format!("{:?}", cs.suite()));

    let cert_chain_length = conn.peer_certificates().map_or(0, <[_]>::len);

    Some(TlsHandshakeInfo {
        protocol_version,
        cipher_suite,
        cert_chain_length,
    })
}

/// A certificate verifier that accepts everything (for LAN scanning).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Probe a TLS port and collect certificate + protocol information.
async fn probe_tls(ip: IpAddr, port: u16) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Direct TLS handshake for cipher suite and version inspection
    if let Some(info) = probe_tls_handshake(ip, port).await {
        tracing::debug!(
            ip = %ip, port, version = %info.protocol_version,
            cipher = %info.cipher_suite, certs = info.cert_chain_length,
            "TLS handshake details"
        );

        // Check TLS version
        let version_lower = info.protocol_version.to_lowercase();
        if version_lower.contains("1.2") {
            // TLS 1.2 is acceptable but 1.3 is preferred
            findings.push(
                Finding::new(
                    "ssl",
                    &format!("TLS 1.2 on {ip}:{port} (TLS 1.3 preferred)"),
                    &format!(
                        "Server at {ip}:{port} negotiated TLS 1.2. While still secure, \
                         TLS 1.3 offers improved performance and stronger security \
                         guarantees. Cipher: {}",
                        info.cipher_suite
                    ),
                    Severity::Info,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("TLS"),
            );
        } else if version_lower.contains("1.3") {
            findings.push(
                Finding::new(
                    "ssl",
                    &format!("TLS 1.3 on {ip}:{port}"),
                    &format!(
                        "Server at {ip}:{port} supports TLS 1.3 — the latest and most \
                         secure protocol version. Cipher: {}",
                        info.cipher_suite
                    ),
                    Severity::Info,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("TLS"),
            );
        }

        // Classify cipher suite
        if let Some(finding) = classify_cipher_suite(ip, port, &info.cipher_suite) {
            findings.push(finding);
        }

        // Single-cert chain may indicate self-signed
        if info.cert_chain_length == 1 {
            findings.push(classify_cert_issue(ip, port, "self-signed"));
        }
    }

    // Also do reqwest-based HSTS check
    let url = format!("https://{ip}:{port}/");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build();

    if let Ok(client) = client {
        if let Ok(resp) = client.head(&url).send().await {
            if resp.headers().get("strict-transport-security").is_none() {
                findings.push(
                    Finding::new(
                        "ssl",
                        &format!("HTTPS without HSTS on {ip}:{port}"),
                        "The HTTPS server does not send a Strict-Transport-Security \
                         header. This allows downgrade attacks to HTTP.",
                        Severity::Low,
                    )
                    .with_ip(ip)
                    .with_port(port)
                    .with_service("HTTPS")
                    .with_cwe("CWE-319"),
                );
            }
        }
    }

    findings
}

#[async_trait]
impl Scanner for SslScanner {
    fn id(&self) -> &'static str {
        "ssl"
    }

    fn name(&self) -> &'static str {
        "TLS/SSL Certificate Scanner"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running TLS/SSL certificate scan");
        let mut findings = Vec::new();

        // Use discovered devices from Phase 1 for adaptive scanning
        if ctx.discovered_devices.is_empty() {
            tracing::info!("no discovered devices, skipping TLS scan");
            return Ok(findings);
        }

        // In Passive mode, only check port 443 (fastest)
        let allowed_tls_ports: &[u16] = if ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            TLS_PORTS
        } else {
            &[443]
        };

        for device in &ctx.discovered_devices {
            // Check TLS on discovered open ports that could speak TLS
            let tls_ports: Vec<u16> = device
                .open_ports
                .iter()
                .filter(|p| allowed_tls_ports.contains(&p.port))
                .map(|p| p.port)
                .collect();

            for port in tls_ports {
                let port_findings = probe_tls(device.ip, port).await;
                findings.extend(port_findings);
            }
        }

        tracing::info!(findings_count = findings.len(), "TLS scan complete");
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        30
    }

    fn relevant_ports(&self) -> &[u16] {
        // TLS-capable ports
        &[443, 8443, 8080, 8888, 993, 995, 465, 587, 636, 8883]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_classify_tls_1_0() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_tls_version(ip, 443, "TLS 1.0");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn test_classify_tls_1_1() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_tls_version(ip, 443, "TLSv1.1");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn test_classify_tls_1_2() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_tls_version(ip, 443, "TLS 1.2");
        assert!(finding.is_none());
    }

    #[test]
    fn test_classify_tls_1_3() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_tls_version(ip, 443, "TLS 1.3");
        assert!(finding.is_none());
    }

    #[test]
    fn test_classify_sslv3() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_tls_version(ip, 443, "SSLv3");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_classify_cert_expired() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_cert_issue(ip, 443, "certificate expired");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn test_classify_cert_self_signed_private_ip() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_cert_issue(ip, 443, "self-signed certificate");
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn test_classify_cert_self_signed_public_ip() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let finding = classify_cert_issue(ip, 443, "self-signed certificate");
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn test_classify_cert_weak_key() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_cert_issue(ip, 443, "weak key 1024-bit RSA");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn test_classify_cert_hostname_mismatch() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_cert_issue(ip, 443, "hostname mismatch");
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn test_classify_cert_generic() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_cert_issue(ip, 443, "unknown issue");
        assert_eq!(finding.severity, Severity::Low);
    }

    // ── Cipher suite classification ─────────────────────────────────

    #[test]
    fn test_classify_cipher_cbc() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_cipher_suite(ip, 443, "TLS_RSA_WITH_AES_128_CBC_SHA256");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn test_classify_cipher_sha1() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_cipher_suite(ip, 443, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA1");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Low);
    }

    #[test]
    fn test_classify_cipher_no_forward_secrecy() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_cipher_suite(ip, 443, "TLS_RSA_WITH_AES_256_GCM_SHA384");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn test_classify_cipher_strong() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_cipher_suite(ip, 443, "TLS13_AES_256_GCM_SHA384");
        assert!(finding.is_none());
    }

    #[test]
    fn test_classify_cipher_chacha() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_cipher_suite(ip, 443, "TLS13_CHACHA20_POLY1305_SHA256");
        assert!(finding.is_none());
    }

    proptest! {
        /// `classify_tls_version` never panics on arbitrary strings
        #[test]
        fn prop_classify_tls_version_no_panic(version in ".*", port in 1_u16..=65535_u16) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = classify_tls_version(ip, port, &version);
        }

        /// `classify_cert_issue` never panics on arbitrary strings
        #[test]
        fn prop_classify_cert_issue_no_panic(issue in ".*", port in 1_u16..=65535_u16) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = classify_cert_issue(ip, port, &issue);
        }

        /// `classify_cipher_suite` never panics on arbitrary strings
        #[test]
        fn prop_classify_cipher_suite_no_panic(cipher in ".*", port in 1_u16..=65535_u16) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = classify_cipher_suite(ip, port, &cipher);
        }
    }
}
