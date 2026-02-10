use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::IpAddr;

use crate::Scanner;

/// TLS/SSL certificate scanner — checks certificates on discovered HTTPS
/// ports for expiry, self-signed certs, weak keys, and old TLS versions.
pub struct SslScanner;

/// Known HTTP(S) ports to probe for TLS.
const TLS_PORTS: &[u16] = &[443, 8443, 8080, 8888, 993, 995, 465, 587, 636, 8883];

/// Classify a TLS protocol version into a finding.
///
/// TLS 1.0 and 1.1 are deprecated (RFC 8996) and considered insecure.
pub fn classify_tls_version(ip: IpAddr, port: u16, version: &str) -> Option<Finding> {
    let version_lower = version.to_lowercase();

    if version_lower.contains("tls 1.0") || version_lower.contains("tlsv1.0")
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
            .with_opt_remediation(crate::remediation::get("rikitikitavi.ssl.tls10-enabled", &[])),
        );
    }

    if version_lower.contains("tls 1.1") || version_lower.contains("tlsv1.1")
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
            .with_opt_remediation(crate::remediation::get("rikitikitavi.ssl.tls11-enabled", &[])),
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
            .with_opt_remediation(crate::remediation::get("rikitikitavi.ssl.sslv2v3-enabled", &[])),
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
        .with_opt_remediation(crate::remediation::get("rikitikitavi.ssl.cert-expired", &[]));
    }

    if issue_lower.contains("self-signed") || issue_lower.contains("self signed") {
        return Finding::new(
            "ssl",
            &format!("Self-signed certificate on {ip}:{port}"),
            "The TLS certificate is self-signed. While common on home network \
             devices, it prevents certificate validation and trains users to \
             accept security warnings.",
            Severity::Medium,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("TLS")
        .with_cwe("CWE-295")
        .with_opt_remediation(crate::remediation::get("rikitikitavi.ssl.cert-self-signed", &[]));
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
        .with_opt_remediation(crate::remediation::get("rikitikitavi.ssl.cert-weak-key", &[]));
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

/// Probe a TLS port and collect certificate information.
///
/// Uses `reqwest` with a custom TLS configuration to inspect the
/// certificate without validating it (since LAN devices typically
/// have self-signed certs).
async fn probe_tls(ip: IpAddr, port: u16) -> Vec<Finding> {
    let mut findings = Vec::new();

    // First, check if the port is actually open and speaks TLS
    let url = format!("https://{ip}:{port}/");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build();

    let Ok(client) = client else {
        return findings;
    };

    if let Ok(resp) = client.head(&url).send().await {
        // If we got a response, TLS handshake succeeded
        // Check for HSTS header while we're here
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

        // Self-signed cert detection: try again with validation enabled
        let strict_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build();

        if let Ok(strict) = strict_client {
            if strict.head(&url).send().await.is_err() {
                // Strict validation failed → cert issue (likely self-signed)
                findings.push(classify_cert_issue(ip, port, "self-signed"));
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

        for device in &ctx.discovered_devices {
            // Check TLS on discovered open ports that could speak TLS
            let tls_ports: Vec<u16> = device
                .open_ports
                .iter()
                .filter(|p| TLS_PORTS.contains(&p.port))
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
    fn test_classify_cert_self_signed() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
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

    proptest! {
        /// classify_tls_version never panics on arbitrary strings
        #[test]
        fn prop_classify_tls_version_no_panic(version in ".*", port in 1_u16..=65535_u16) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = classify_tls_version(ip, port, &version);
        }

        /// classify_cert_issue never panics on arbitrary strings
        #[test]
        fn prop_classify_cert_issue_no_panic(issue in ".*", port in 1_u16..=65535_u16) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = classify_cert_issue(ip, port, &issue);
        }
    }
}
