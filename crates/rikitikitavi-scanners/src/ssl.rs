use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use x509_parser::prelude::*;

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
    /// DER-encoded leaf certificate (if available).
    leaf_cert_der: Option<Vec<u8>>,
}

// ── X.509 certificate deep analysis ────────────────────────────────

/// Parsed certificate details for security analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertDetails {
    /// Subject Common Name.
    pub subject_cn: Option<String>,
    /// Issuer Common Name.
    pub issuer_cn: Option<String>,
    /// Not-before date (YYYY-MM-DD).
    pub not_before: String,
    /// Not-after date (YYYY-MM-DD).
    pub not_after: String,
    /// Days until expiry (negative = expired).
    pub days_until_expiry: i64,
    /// Public key algorithm (RSA, EC, Ed25519, etc.).
    pub key_algorithm: String,
    /// Key size in bits (RSA: 1024/2048/4096, EC: 256/384, etc.).
    pub key_bits: u32,
    /// Signature algorithm (sha256WithRSAEncryption, etc.).
    pub signature_algorithm: String,
    /// Whether the signature uses SHA-1.
    pub uses_sha1_signature: bool,
    /// Subject Alternative Names (DNS entries).
    pub san_dns: Vec<String>,
    /// Whether the cert is self-signed (subject == issuer).
    pub is_self_signed: bool,
}

/// Parse a DER-encoded X.509 certificate into structured details.
pub fn parse_cert_details(der: &[u8]) -> Option<CertDetails> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(ToOwned::to_owned));

    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(ToOwned::to_owned));

    let validity = cert.validity();
    let not_before = format_asn1_time(&validity.not_before);
    let not_after = format_asn1_time(&validity.not_after);

    // Days until expiry
    let now_epoch = chrono::Utc::now().timestamp();
    let expiry_epoch = validity.not_after.timestamp();
    let days_until_expiry = (expiry_epoch - now_epoch) / 86400;

    // Public key info
    let spki = cert.public_key();
    let (key_algorithm, key_bits) = classify_public_key(spki);

    // Signature algorithm
    let sig_alg = cert.signature_algorithm.algorithm.to_string();
    let sig_name = oid_to_sig_name(&sig_alg);
    let uses_sha1_signature = sig_name.contains("sha1") || sig_name.contains("SHA1");

    // Subject Alternative Names
    let san_dns = cert
        .extensions()
        .iter()
        .filter_map(|ext| {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                Some(san)
            } else {
                None
            }
        })
        .flat_map(|san| san.general_names.iter())
        .filter_map(|name| {
            if let GeneralName::DNSName(dns) = name {
                Some((*dns).to_owned())
            } else {
                None
            }
        })
        .collect();

    let is_self_signed = cert.subject() == cert.issuer();

    Some(CertDetails {
        subject_cn,
        issuer_cn,
        not_before,
        not_after,
        days_until_expiry,
        key_algorithm,
        key_bits,
        signature_algorithm: sig_name,
        uses_sha1_signature,
        san_dns,
        is_self_signed,
    })
}

/// Format an ASN.1 time as YYYY-MM-DD.
fn format_asn1_time(time: &ASN1Time) -> String {
    let ts = time.timestamp();
    chrono::DateTime::from_timestamp(ts, 0).map_or_else(
        || format!("{time}"),
        |dt: chrono::DateTime<chrono::Utc>| dt.format("%Y-%m-%d").to_string(),
    )
}

/// Classify a public key into algorithm name and bit size.
fn classify_public_key(spki: &SubjectPublicKeyInfo<'_>) -> (String, u32) {
    let oid = spki.algorithm.algorithm.to_string();

    // RSA: OID 1.2.840.113549.1.1.1
    if oid.contains("1.2.840.113549.1.1.1") {
        let bit_size = u32::try_from(spki.subject_public_key.data.len() * 8).unwrap_or(0);
        // RSA key size in the SPKI is the modulus + exponent in DER encoding;
        // the actual modulus is slightly smaller. Approximate to standard sizes.
        let approx_bits = match bit_size {
            0..=1200 => 1024,
            1201..=2200 => 2048,
            2201..=3200 => 3072,
            3201..=4200 => 4096,
            _ => bit_size,
        };
        return ("RSA".to_owned(), approx_bits);
    }

    // EC: OID 1.2.840.10045.2.1
    if oid.contains("1.2.840.10045.2.1") {
        // Determine curve from parameters
        let curve_bits = spki.algorithm.parameters.as_ref().map_or(256, |params| {
            let param_str = format!("{params:?}");
            if param_str.contains("1.2.840.10045.3.1.7") {
                256 // P-256 / prime256v1
            } else if param_str.contains("1.3.132.0.34") {
                384 // P-384 / secp384r1
            } else if param_str.contains("1.3.132.0.35") {
                521 // P-521 / secp521r1
            } else {
                256 // default guess
            }
        });
        return ("EC".to_owned(), curve_bits);
    }

    // Ed25519: OID 1.3.101.112
    if oid.contains("1.3.101.112") {
        return ("Ed25519".to_owned(), 256);
    }

    // Ed448: OID 1.3.101.113
    if oid.contains("1.3.101.113") {
        return ("Ed448".to_owned(), 448);
    }

    ("Unknown".to_owned(), 0)
}

/// Map OID strings to human-readable signature algorithm names.
fn oid_to_sig_name(oid: &str) -> String {
    // Common signature algorithm OIDs
    if oid.contains("1.2.840.113549.1.1.5") {
        return "sha1WithRSAEncryption".to_owned();
    }
    if oid.contains("1.2.840.113549.1.1.11") {
        return "sha256WithRSAEncryption".to_owned();
    }
    if oid.contains("1.2.840.113549.1.1.12") {
        return "sha384WithRSAEncryption".to_owned();
    }
    if oid.contains("1.2.840.113549.1.1.13") {
        return "sha512WithRSAEncryption".to_owned();
    }
    if oid.contains("1.2.840.10045.4.3.2") {
        return "ecdsaWithSHA256".to_owned();
    }
    if oid.contains("1.2.840.10045.4.3.3") {
        return "ecdsaWithSHA384".to_owned();
    }
    if oid.contains("1.2.840.10045.4.3.4") {
        return "ecdsaWithSHA512".to_owned();
    }
    if oid.contains("1.3.101.112") {
        return "Ed25519".to_owned();
    }
    oid.to_owned()
}

/// Compute total validity period in days from `not_before` to `not_after`.
fn compute_total_validity_days(cert: &CertDetails) -> i64 {
    // Parse YYYY-MM-DD dates to compute span
    let parse = |s: &str| -> Option<i64> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 3 {
            return None;
        }
        let y: i32 = parts[0].parse().ok()?;
        let m: u32 = parts[1].parse().ok()?;
        let d: u32 = parts[2].parse().ok()?;
        chrono::NaiveDate::from_ymd_opt(y, m, d)
            .and_then(|date| date.and_hms_opt(0, 0, 0).map(|dt| dt.and_utc().timestamp()))
    };

    match (parse(&cert.not_before), parse(&cert.not_after)) {
        (Some(before), Some(after)) => (after - before) / 86400,
        _ => cert.days_until_expiry, // fallback: assume it started ~now
    }
}

/// Analyze a parsed certificate and produce security findings.
#[allow(clippy::too_many_lines)]
pub fn analyze_certificate(ip: IpAddr, port: u16, cert: &CertDetails) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Expired certificate
    if cert.days_until_expiry < 0 {
        let days_ago = -cert.days_until_expiry;
        findings.push(
            Finding::new(
                "ssl",
                &format!("Expired certificate on {ip}:{port}"),
                &format!(
                    "TLS certificate on {ip}:{port} expired {} days ago (not-after: {}). \
                     Subject: {}. Expired certificates cause connection warnings and may \
                     indicate abandoned or unmaintained services.",
                    days_ago,
                    cert.not_after,
                    cert.subject_cn.as_deref().unwrap_or("(none)"),
                ),
                Severity::High,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("TLS")
            .with_cwe("CWE-295")
            .with_evidence(format!(
                "Subject: {}, Issuer: {}, Expired: {}, Key: {} {}bit",
                cert.subject_cn.as_deref().unwrap_or("?"),
                cert.issuer_cn.as_deref().unwrap_or("?"),
                cert.not_after,
                cert.key_algorithm,
                cert.key_bits,
            )),
        );
    }
    // 2. Expiring soon (within 30 days)
    else if cert.days_until_expiry <= 30 {
        findings.push(
            Finding::new(
                "ssl",
                &format!("Certificate expiring soon on {ip}:{port}"),
                &format!(
                    "TLS certificate on {ip}:{port} expires in {} days (not-after: {}). \
                     Subject: {}. Renew before it expires to avoid service disruption.",
                    cert.days_until_expiry,
                    cert.not_after,
                    cert.subject_cn.as_deref().unwrap_or("(none)"),
                ),
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("TLS")
            .with_cwe("CWE-295"),
        );
    }

    // 3. Weak RSA key (< 2048 bits)
    if cert.key_algorithm == "RSA" && cert.key_bits < 2048 {
        findings.push(
            Finding::new(
                "ssl",
                &format!("Weak {}-bit RSA key on {ip}:{port}", cert.key_bits),
                &format!(
                    "TLS certificate on {ip}:{port} uses a {}-bit RSA key. \
                     NIST recommends minimum 2048-bit RSA. Keys under 2048 bits \
                     are considered breakable with sufficient resources.",
                    cert.key_bits,
                ),
                Severity::High,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("TLS")
            .with_cwe("CWE-326"),
        );
    }

    // 4. SHA-1 signature
    if cert.uses_sha1_signature {
        findings.push(
            Finding::new(
                "ssl",
                &format!("SHA-1 certificate signature on {ip}:{port}"),
                &format!(
                    "TLS certificate on {ip}:{port} is signed with {} (SHA-1). \
                     SHA-1 is broken for collision resistance (SHAttered attack, 2017). \
                     All major browsers reject SHA-1 certificates.",
                    cert.signature_algorithm,
                ),
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("TLS")
            .with_cwe("CWE-328")
            .with_references(refs!["https://shattered.io/",]),
        );
    }

    // 5. Self-signed certificate
    if cert.is_self_signed {
        let (severity, desc) = if crate::dns::is_private_ip(ip) {
            (
                Severity::Low,
                format!(
                    "TLS certificate on {ip}:{port} is self-signed (subject and issuer: {}). \
                     This is common on LAN devices that cannot obtain CA-signed certificates \
                     for private IP addresses, but it prevents proper certificate validation.",
                    cert.subject_cn.as_deref().unwrap_or("(none)"),
                ),
            )
        } else {
            (
                Severity::Medium,
                format!(
                    "TLS certificate on {ip}:{port} is self-signed (subject and issuer: {}). \
                     Self-signed certificates prevent verification and train users to accept \
                     security warnings.",
                    cert.subject_cn.as_deref().unwrap_or("(none)"),
                ),
            )
        };
        findings.push(
            Finding::new("ssl", &format!("Self-signed certificate on {ip}:{port}"), &desc, severity)
                .with_ip(ip)
                .with_port(port)
                .with_service("TLS")
                .with_cwe("CWE-295")
                .with_references(refs![
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ]),
        );
    }

    // 6. Excessive certificate validity (>825 days / ~27 months per CA/B Forum baseline)
    // IoT devices often ship with 10-50 year certs that will never be rotated.
    if cert.days_until_expiry > 825 {
        // Calculate total validity in days from not_before to not_after
        let total_validity_days = compute_total_validity_days(cert);
        if total_validity_days > 825 {
            let years = total_validity_days / 365;
            let severity = if total_validity_days > 3650 {
                Severity::Medium // >10 years: almost certainly never-rotated IoT cert
            } else {
                Severity::Low // 2-10 years: long but less extreme
            };
            findings.push(
                Finding::new(
                    "ssl",
                    &format!("Excessive certificate validity on {ip}:{port}"),
                    &format!(
                        "TLS certificate on {ip}:{port} has a {years}-year validity period \
                         ({} to {}). CA/Browser Forum limits public certs to 398 days. \
                         Long-lived certificates on IoT/embedded devices indicate the cert \
                         will never be rotated, increasing risk if the key is compromised.",
                        cert.not_before, cert.not_after,
                    ),
                    severity,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("TLS")
                .with_cwe("CWE-324")
                .with_references(refs![
                    "https://cabforum.org/working-groups/server/baseline-requirements/",
                ]),
            );
        }
    }

    // 7. Certificate details (Info-level)
    findings.push(
        Finding::new(
            "ssl",
            &format!("Certificate details for {ip}:{port}"),
            &format!(
                "Subject: {}, Issuer: {}, Valid: {} to {} ({} days remaining), \
                 Key: {} {}-bit, Signature: {}, SANs: {}, Self-signed: {}",
                cert.subject_cn.as_deref().unwrap_or("(none)"),
                cert.issuer_cn.as_deref().unwrap_or("(none)"),
                cert.not_before,
                cert.not_after,
                cert.days_until_expiry,
                cert.key_algorithm,
                cert.key_bits,
                cert.signature_algorithm,
                if cert.san_dns.is_empty() {
                    "(none)".to_owned()
                } else {
                    cert.san_dns.join(", ")
                },
                cert.is_self_signed,
            ),
            Severity::Info,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("TLS")
        .with_evidence(format!(
            "CN={} Key={}/{} Sig={} Expiry={}",
            cert.subject_cn.as_deref().unwrap_or("?"),
            cert.key_algorithm,
            cert.key_bits,
            cert.signature_algorithm,
            cert.not_after,
        )),
    );

    findings
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
            .with_cwe("CWE-327")
            .with_references(refs![
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            ]),
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
            .with_cwe("CWE-328")
            .with_references(refs![
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            ]),
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
            .with_cwe("CWE-326")
            .with_references(refs![
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            ]),
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

    let certs = conn.peer_certificates();
    let cert_chain_length = certs.map_or(0, <[_]>::len);
    let leaf_cert_der = certs.and_then(|c| c.first()).map(|c| c.to_vec());

    Some(TlsHandshakeInfo {
        protocol_version,
        cipher_suite,
        cert_chain_length,
        leaf_cert_der,
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

        // Deep certificate analysis via X.509 parsing
        if let Some(der) = &info.leaf_cert_der {
            if let Some(cert_details) = parse_cert_details(der) {
                findings.extend(analyze_certificate(ip, port, &cert_details));
            } else if info.cert_chain_length == 1 {
                // Fallback: couldn't parse cert but chain length = 1 → likely self-signed
                findings.push(classify_cert_issue(ip, port, "self-signed"));
            }
        } else if info.cert_chain_length == 1 {
            // No cert DER available but chain length = 1
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

    if let Ok(client) = client
        && let Ok(resp) = client.head(&url).send().await
        && resp.headers().get("strict-transport-security").is_none()
    {
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
                    .with_cwe("CWE-319")
                    .with_references(refs![
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                    ]),
                );
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

    // ── Certificate analysis tests ────────────────────────────────────

    #[test]
    fn test_analyze_cert_expired() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cert = CertDetails {
            subject_cn: Some("router.local".to_owned()),
            issuer_cn: Some("router.local".to_owned()),
            not_before: "2020-01-01".to_owned(),
            not_after: "2023-01-01".to_owned(),
            days_until_expiry: -730,
            key_algorithm: "RSA".to_owned(),
            key_bits: 2048,
            signature_algorithm: "sha256WithRSAEncryption".to_owned(),
            uses_sha1_signature: false,
            san_dns: vec![],
            is_self_signed: true,
        };
        let findings = analyze_certificate(ip, 443, &cert);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Expired") && f.severity == Severity::High),
            "expected expired cert finding"
        );
    }

    #[test]
    fn test_analyze_cert_expiring_soon() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cert = CertDetails {
            subject_cn: Some("nas.local".to_owned()),
            issuer_cn: Some("nas.local".to_owned()),
            not_before: "2024-01-01".to_owned(),
            not_after: "2026-03-01".to_owned(),
            days_until_expiry: 14,
            key_algorithm: "EC".to_owned(),
            key_bits: 256,
            signature_algorithm: "ecdsaWithSHA256".to_owned(),
            uses_sha1_signature: false,
            san_dns: vec!["nas.local".to_owned()],
            is_self_signed: true,
        };
        let findings = analyze_certificate(ip, 443, &cert);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("expiring soon") && f.severity == Severity::Medium)
        );
    }

    #[test]
    fn test_analyze_cert_weak_rsa_key() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cert = CertDetails {
            subject_cn: Some("iot-device".to_owned()),
            issuer_cn: Some("iot-device".to_owned()),
            not_before: "2024-01-01".to_owned(),
            not_after: "2027-01-01".to_owned(),
            days_until_expiry: 365,
            key_algorithm: "RSA".to_owned(),
            key_bits: 1024,
            signature_algorithm: "sha256WithRSAEncryption".to_owned(),
            uses_sha1_signature: false,
            san_dns: vec![],
            is_self_signed: true,
        };
        let findings = analyze_certificate(ip, 443, &cert);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("1024-bit RSA") && f.severity == Severity::High)
        );
    }

    #[test]
    fn test_analyze_cert_sha1_signature() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cert = CertDetails {
            subject_cn: Some("printer.local".to_owned()),
            issuer_cn: Some("printer.local".to_owned()),
            not_before: "2024-01-01".to_owned(),
            not_after: "2027-01-01".to_owned(),
            days_until_expiry: 365,
            key_algorithm: "RSA".to_owned(),
            key_bits: 2048,
            signature_algorithm: "sha1WithRSAEncryption".to_owned(),
            uses_sha1_signature: true,
            san_dns: vec![],
            is_self_signed: true,
        };
        let findings = analyze_certificate(ip, 443, &cert);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("SHA-1") && f.severity == Severity::Medium)
        );
    }

    #[test]
    fn test_analyze_cert_healthy_ca_signed() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cert = CertDetails {
            subject_cn: Some("healthy.local".to_owned()),
            issuer_cn: Some("My CA".to_owned()),
            not_before: "2025-01-01".to_owned(),
            not_after: "2027-01-01".to_owned(),
            days_until_expiry: 365,
            key_algorithm: "EC".to_owned(),
            key_bits: 256,
            signature_algorithm: "ecdsaWithSHA256".to_owned(),
            uses_sha1_signature: false,
            san_dns: vec!["healthy.local".to_owned()],
            is_self_signed: false,
        };
        let findings = analyze_certificate(ip, 443, &cert);
        // CA-signed, valid, strong key → only Info-level details
        assert!(findings.iter().all(|f| f.severity == Severity::Info));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_analyze_cert_self_signed_private_ip() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cert = CertDetails {
            subject_cn: Some("router.local".to_owned()),
            issuer_cn: Some("router.local".to_owned()),
            not_before: "2025-01-01".to_owned(),
            not_after: "2027-01-01".to_owned(),
            days_until_expiry: 365,
            key_algorithm: "EC".to_owned(),
            key_bits: 256,
            signature_algorithm: "ecdsaWithSHA256".to_owned(),
            uses_sha1_signature: false,
            san_dns: vec![],
            is_self_signed: true,
        };
        let findings = analyze_certificate(ip, 443, &cert);
        // Self-signed on private IP → Low + Info details
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Self-signed") && f.severity == Severity::Low)
        );
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_analyze_cert_multiple_issues() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cert = CertDetails {
            subject_cn: Some("old-device".to_owned()),
            issuer_cn: Some("old-device".to_owned()),
            not_before: "2018-01-01".to_owned(),
            not_after: "2022-01-01".to_owned(),
            days_until_expiry: -1460,
            key_algorithm: "RSA".to_owned(),
            key_bits: 1024,
            signature_algorithm: "sha1WithRSAEncryption".to_owned(),
            uses_sha1_signature: true,
            san_dns: vec![],
            is_self_signed: true,
        };
        let findings = analyze_certificate(ip, 443, &cert);
        // expired + weak key + SHA-1 + self-signed + details = 5 findings
        assert_eq!(findings.len(), 5);
        assert!(findings.iter().any(|f| f.title.contains("Expired")));
        assert!(findings.iter().any(|f| f.title.contains("1024-bit")));
        assert!(findings.iter().any(|f| f.title.contains("Self-signed")));
        assert!(findings.iter().any(|f| f.title.contains("SHA-1")));
    }

    #[test]
    fn test_oid_to_sig_name_known() {
        assert_eq!(
            oid_to_sig_name("1.2.840.113549.1.1.11"),
            "sha256WithRSAEncryption"
        );
        assert_eq!(
            oid_to_sig_name("1.2.840.113549.1.1.5"),
            "sha1WithRSAEncryption"
        );
        assert_eq!(oid_to_sig_name("1.2.840.10045.4.3.2"), "ecdsaWithSHA256");
    }

    #[test]
    fn test_oid_to_sig_name_unknown() {
        assert_eq!(oid_to_sig_name("1.2.3.4.5"), "1.2.3.4.5");
    }

    #[test]
    fn test_analyze_cert_excessive_validity_iot() {
        let ip: IpAddr = "192.168.1.34".parse().unwrap();
        let cert = CertDetails {
            subject_cn: Some("Sound United".to_owned()),
            issuer_cn: Some("Sound United".to_owned()),
            not_before: "2019-03-12".to_owned(),
            not_after: "2069-02-27".to_owned(),
            days_until_expiry: 15717,
            key_algorithm: "RSA".to_owned(),
            key_bits: 2048,
            signature_algorithm: "sha256WithRSAEncryption".to_owned(),
            uses_sha1_signature: false,
            san_dns: vec![],
            is_self_signed: true,
        };
        let findings = analyze_certificate(ip, 443, &cert);
        // 50-year cert → Medium excessive validity + self-signed Low + Info details
        assert!(findings.iter().any(|f| f.title.contains("Excessive")));
        let excessive = findings
            .iter()
            .find(|f| f.title.contains("Excessive"))
            .unwrap();
        assert_eq!(excessive.severity, Severity::Medium);
    }

    #[test]
    fn test_analyze_cert_moderate_validity() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cert = CertDetails {
            subject_cn: Some("device".to_owned()),
            issuer_cn: Some("device".to_owned()),
            not_before: "2024-01-01".to_owned(),
            not_after: "2029-01-01".to_owned(),
            days_until_expiry: 1400,
            key_algorithm: "RSA".to_owned(),
            key_bits: 2048,
            signature_algorithm: "sha256WithRSAEncryption".to_owned(),
            uses_sha1_signature: false,
            san_dns: vec![],
            is_self_signed: true,
        };
        let findings = analyze_certificate(ip, 443, &cert);
        // 5-year cert → Low excessive validity
        assert!(findings.iter().any(|f| f.title.contains("Excessive")));
        let excessive = findings
            .iter()
            .find(|f| f.title.contains("Excessive"))
            .unwrap();
        assert_eq!(excessive.severity, Severity::Low);
    }

    #[test]
    fn test_analyze_cert_normal_validity() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cert = CertDetails {
            subject_cn: Some("device".to_owned()),
            issuer_cn: Some("My CA".to_owned()),
            not_before: "2025-06-01".to_owned(),
            not_after: "2027-06-01".to_owned(),
            days_until_expiry: 730,
            key_algorithm: "RSA".to_owned(),
            key_bits: 2048,
            signature_algorithm: "sha256WithRSAEncryption".to_owned(),
            uses_sha1_signature: false,
            san_dns: vec!["device.local".to_owned()],
            is_self_signed: false,
        };
        let findings = analyze_certificate(ip, 443, &cert);
        // 2-year cert, CA-signed → no excessive validity, no self-signed
        assert!(!findings.iter().any(|f| f.title.contains("Excessive")));
        assert!(!findings.iter().any(|f| f.title.contains("Self-signed")));
        assert_eq!(findings.len(), 1); // only Info details
    }

    #[test]
    fn test_compute_total_validity_days() {
        let cert = CertDetails {
            subject_cn: None,
            issuer_cn: None,
            not_before: "2019-03-12".to_owned(),
            not_after: "2069-02-27".to_owned(),
            days_until_expiry: 15717,
            key_algorithm: "RSA".to_owned(),
            key_bits: 2048,
            signature_algorithm: "sha256WithRSAEncryption".to_owned(),
            uses_sha1_signature: false,
            san_dns: vec![],
            is_self_signed: true,
        };
        let days = compute_total_validity_days(&cert);
        // ~50 years ≈ 18249 days (give or take leap years)
        assert!(days > 18000 && days < 18500);
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

        /// `parse_cert_details` never panics on arbitrary bytes
        #[test]
        fn prop_parse_cert_details_no_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = parse_cert_details(&data);
        }

        /// `analyze_certificate` never panics on any `CertDetails` combinations
        #[test]
        fn prop_analyze_cert_no_panic(
            days in -3650_i64..3650_i64,
            key_bits in 0_u32..8192_u32,
            sha1 in proptest::bool::ANY,
        ) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let cert = CertDetails {
                subject_cn: Some("test".to_owned()),
                issuer_cn: Some("test".to_owned()),
                not_before: "2020-01-01".to_owned(),
                not_after: "2030-01-01".to_owned(),
                days_until_expiry: days,
                key_algorithm: "RSA".to_owned(),
                key_bits,
                signature_algorithm: if sha1 {
                    "sha1WithRSAEncryption".to_owned()
                } else {
                    "sha256WithRSAEncryption".to_owned()
                },
                uses_sha1_signature: sha1,
                san_dns: vec![],
                is_self_signed: true,
            };
            let _ = analyze_certificate(ip, 443, &cert);
        }
    }
}
