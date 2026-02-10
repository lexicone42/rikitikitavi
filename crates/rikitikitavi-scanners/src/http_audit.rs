use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, Remediation, ScanContext};
use std::net::IpAddr;
use std::time::Duration;

use crate::Scanner;

/// HTTP security audit scanner — checks security headers, default pages,
/// admin panels, and directory listing on HTTP ports found in Phase 1.
pub struct HttpAuditScanner;

const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// HTTP(S) ports to audit.
const AUDIT_PORTS: &[u16] = &[80, 443, 8080, 8443, 8888, 8000, 8081, 3000, 9090];

/// Common admin paths to probe.
const ADMIN_PATHS: &[&str] = &[
    "/admin",
    "/login",
    "/setup",
    "/management",
    "/phpmyadmin",
    "/wp-admin",
    "/cgi-bin",
    "/manager",
    "/console",
    "/dashboard",
];

/// Classify missing security headers into findings.
pub fn classify_missing_headers(
    ip: IpAddr,
    port: u16,
    headers: &HeaderSet,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !headers.has_hsts {
        findings.push(
            Finding::new(
                "http_audit",
                &format!("Missing HSTS header on {ip}:{port}"),
                "The server does not send a Strict-Transport-Security header. \
                 Without HSTS, browsers may connect over unencrypted HTTP, \
                 enabling man-in-the-middle attacks.",
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP")
            .with_cwe("CWE-319")
            .with_remediation(Remediation {
                description: "Enable HSTS to force HTTPS connections.".to_owned(),
                steps: vec![
                    "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.".to_owned(),
                    "For Apache: Header always set Strict-Transport-Security in VirtualHost.".to_owned(),
                    "For nginx: add_header Strict-Transport-Security in server block.".to_owned(),
                ],
                effort: Some("5 minutes".to_owned()),
            }),
        );
    }

    if !headers.has_x_frame_options {
        findings.push(
            Finding::new(
                "http_audit",
                &format!("Missing X-Frame-Options on {ip}:{port}"),
                "The server does not send an X-Frame-Options header. This may \
                 allow clickjacking attacks where the page is embedded in an \
                 attacker's iframe.",
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP")
            .with_cwe("CWE-1021"),
        );
    }

    if !headers.has_content_security_policy {
        findings.push(
            Finding::new(
                "http_audit",
                &format!("Missing Content-Security-Policy on {ip}:{port}"),
                "The server does not send a Content-Security-Policy header. \
                 CSP helps prevent XSS and data injection attacks.",
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP")
            .with_cwe("CWE-79"),
        );
    }

    if !headers.has_x_content_type_options {
        findings.push(
            Finding::new(
                "http_audit",
                &format!("Missing X-Content-Type-Options on {ip}:{port}"),
                "The server does not send X-Content-Type-Options: nosniff. \
                 This allows browsers to MIME-sniff content, which can lead \
                 to security issues.",
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP")
            .with_cwe("CWE-16"),
        );
    }

    findings
}

/// Detect whether an HTTP response body is a default/unconfigured server page.
pub fn is_default_page(body: &str) -> bool {
    let lower = body.to_lowercase();

    // Apache default
    if lower.contains("it works!") && lower.contains("apache") {
        return true;
    }

    // nginx default
    if lower.contains("welcome to nginx") {
        return true;
    }

    // IIS default
    if lower.contains("welcome") && lower.contains("internet information services") {
        return true;
    }

    // lighttpd default
    if lower.contains("placeholder page") || lower.contains("lighttpd") && lower.contains("works") {
        return true;
    }

    false
}

/// Detect if a response indicates directory listing is enabled.
pub fn is_directory_listing(body: &str) -> bool {
    let lower = body.to_lowercase();
    (lower.contains("index of") || lower.contains("directory listing"))
        && lower.contains("<a href=")
}

/// Extract the Server header value and classify known vulnerable versions.
pub fn classify_server_header(ip: IpAddr, port: u16, server: &str) -> Option<Finding> {
    let lower = server.to_lowercase();

    // Apache < 2.4.50 had path traversal (CVE-2021-41773)
    if lower.contains("apache/2.4.4") && !lower.contains("apache/2.4.5") {
        return Some(
            Finding::new(
                "http_audit",
                &format!("Potentially vulnerable Apache on {ip}:{port}"),
                &format!(
                    "Server header indicates Apache 2.4.4x ({server}), which may \
                     be affected by path traversal vulnerabilities. Verify the \
                     exact version and patch status."
                ),
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP"),
        );
    }

    // Generic version disclosure
    if lower.contains('/') {
        return Some(
            Finding::new(
                "http_audit",
                &format!("Server version disclosure on {ip}:{port}"),
                &format!(
                    "The Server header reveals version information: {server}. \
                     This aids attackers in identifying known vulnerabilities."
                ),
                Severity::Info,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP"),
        );
    }

    None
}

/// Set of security headers found in a response.
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct HeaderSet {
    pub has_hsts: bool,
    pub has_x_frame_options: bool,
    pub has_content_security_policy: bool,
    pub has_x_content_type_options: bool,
    pub server: Option<String>,
}

impl HeaderSet {
    /// Parse headers from an HTTP response string.
    pub fn from_response(response: &str) -> Self {
        let mut set = Self::default();
        for line in response.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("strict-transport-security:") {
                set.has_hsts = true;
            } else if lower.starts_with("x-frame-options:") {
                set.has_x_frame_options = true;
            } else if lower.starts_with("content-security-policy:") {
                set.has_content_security_policy = true;
            } else if lower.starts_with("x-content-type-options:") {
                set.has_x_content_type_options = true;
            } else if lower.starts_with("server:") {
                set.server = Some(line[7..].trim().to_owned());
            }
        }
        set
    }
}

/// Audit a single HTTP endpoint.
#[allow(clippy::too_many_lines)]
async fn audit_http_endpoint(ip: IpAddr, port: u16) -> Vec<Finding> {
    let mut findings = Vec::new();
    let scheme = if port == 443 || port == 8443 {
        "https"
    } else {
        "http"
    };

    let Ok(client) = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
    else {
        return findings;
    };

    // Main page request
    let url = format!("{scheme}://{ip}:{port}/");
    if let Ok(resp) = client.get(&url).send().await {
        // Check security headers
        let headers = HeaderSet {
            has_hsts: resp.headers().contains_key("strict-transport-security"),
            has_x_frame_options: resp.headers().contains_key("x-frame-options"),
            has_content_security_policy: resp
                .headers()
                .contains_key("content-security-policy"),
            has_x_content_type_options: resp
                .headers()
                .contains_key("x-content-type-options"),
            server: resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned),
        };

        // Only report missing HSTS on HTTPS ports
        if scheme == "https" {
            findings.extend(classify_missing_headers(ip, port, &headers));
        } else {
            // For HTTP, still check other headers but skip HSTS
            let partial = HeaderSet {
                has_hsts: true, // Suppress HSTS finding for HTTP
                has_x_frame_options: headers.has_x_frame_options,
                has_content_security_policy: headers.has_content_security_policy,
                has_x_content_type_options: headers.has_x_content_type_options,
                server: None,
            };
            findings.extend(classify_missing_headers(ip, port, &partial));
        }

        // Server header analysis
        if let Some(ref server) = headers.server {
            if let Some(finding) = classify_server_header(ip, port, server) {
                findings.push(finding);
            }
        }

        // Check body for default pages
        if let Ok(body) = resp.text().await {
            if is_default_page(&body) {
                findings.push(
                    Finding::new(
                        "http_audit",
                        &format!("Default/unconfigured web server on {ip}:{port}"),
                        "The web server is showing its default welcome page, \
                         indicating it may not be properly configured or is \
                         exposing unnecessary services.",
                        Severity::Low,
                    )
                    .with_ip(ip)
                    .with_port(port)
                    .with_service("HTTP"),
                );
            }

            if is_directory_listing(&body) {
                findings.push(
                    Finding::new(
                        "http_audit",
                        &format!("Directory listing enabled on {ip}:{port}"),
                        "The web server has directory listing enabled, exposing \
                         file names and directory structure to anyone who can \
                         reach the server.",
                        Severity::Medium,
                    )
                    .with_ip(ip)
                    .with_port(port)
                    .with_service("HTTP")
                    .with_cwe("CWE-548")
                    .with_remediation(Remediation {
                        description: "Disable directory listing on the web server.".to_owned(),
                        steps: vec![
                            "Apache: Remove 'Options Indexes' or add 'Options -Indexes' in the config.".to_owned(),
                            "nginx: Ensure 'autoindex on;' is not set in location blocks.".to_owned(),
                            "Alternatively, add an index.html to each directory.".to_owned(),
                        ],
                        effort: Some("5 minutes".to_owned()),
                    }),
                );
            }
        }
    }

    // Probe admin paths
    for path in ADMIN_PATHS {
        let admin_url = format!("{scheme}://{ip}:{port}{path}");
        if let Ok(resp) = client.get(&admin_url).send().await {
            let status = resp.status().as_u16();
            // 200 without redirect to login = accessible without auth
            if status == 200 {
                let body = resp.text().await.unwrap_or_default().to_lowercase();
                // Skip if the 200 page is actually a login form
                if !body.contains("login") && !body.contains("password") && !body.contains("sign in") {
                    findings.push(
                        Finding::new(
                            "http_audit",
                            &format!("Admin panel accessible at {ip}:{port}{path}"),
                            &format!(
                                "The admin path '{path}' on {ip}:{port} returned HTTP 200 \
                                 without requiring authentication. This may allow anyone \
                                 on the network to access administrative functions."
                            ),
                            Severity::High,
                        )
                        .with_ip(ip)
                        .with_port(port)
                        .with_service("HTTP")
                        .with_cwe("CWE-306")
                        .with_remediation(Remediation {
                            description: "Restrict access to administrative interfaces.".to_owned(),
                            steps: vec![
                                "Add authentication to all admin paths (HTTP Basic Auth or application-level login).".to_owned(),
                                "Restrict admin access by source IP using firewall rules or web server config.".to_owned(),
                                "Move admin interfaces to a non-standard port or path.".to_owned(),
                            ],
                            effort: Some("15 minutes".to_owned()),
                        }),
                    );
                }
            }
        }
    }

    findings
}

#[async_trait]
impl Scanner for HttpAuditScanner {
    fn id(&self) -> &'static str {
        "http_audit"
    }

    fn name(&self) -> &'static str {
        "HTTP Security Audit"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running HTTP security audit");
        let mut findings = Vec::new();

        // Use discovered devices from Phase 1 for adaptive scanning
        if ctx.discovered_devices.is_empty() {
            tracing::info!("no discovered devices, skipping HTTP audit");
            return Ok(findings);
        }

        for device in &ctx.discovered_devices {
            // Only audit devices with HTTP ports open
            let http_ports: Vec<u16> = device
                .open_ports
                .iter()
                .filter(|p| AUDIT_PORTS.contains(&p.port))
                .map(|p| p.port)
                .collect();

            for port in http_ports {
                let port_findings = audit_http_endpoint(device.ip, port).await;
                findings.extend(port_findings);
            }
        }

        tracing::info!(
            findings_count = findings.len(),
            "HTTP security audit complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        45
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_classify_missing_all_headers() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let headers = HeaderSet::default();
        let findings = classify_missing_headers(ip, 443, &headers);
        assert_eq!(findings.len(), 4);
    }

    #[test]
    fn test_classify_all_headers_present() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let headers = HeaderSet {
            has_hsts: true,
            has_x_frame_options: true,
            has_content_security_policy: true,
            has_x_content_type_options: true,
            server: None,
        };
        let findings = classify_missing_headers(ip, 443, &headers);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_classify_missing_hsts_only() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let headers = HeaderSet {
            has_hsts: false,
            has_x_frame_options: true,
            has_content_security_policy: true,
            has_x_content_type_options: true,
            server: None,
        };
        let findings = classify_missing_headers(ip, 443, &headers);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_is_default_page_apache() {
        assert!(is_default_page(
            "<html><body><h1>It works!</h1><p>Apache server</p></body></html>"
        ));
    }

    #[test]
    fn test_is_default_page_nginx() {
        assert!(is_default_page(
            "<html><head><title>Welcome to nginx!</title></head></html>"
        ));
    }

    #[test]
    fn test_is_default_page_custom() {
        assert!(!is_default_page(
            "<html><head><title>My App</title></head><body>Hello</body></html>"
        ));
    }

    #[test]
    fn test_is_directory_listing() {
        assert!(is_directory_listing(
            "<html><body><h1>Index of /</h1><a href=\"file.txt\">file.txt</a></body></html>"
        ));
    }

    #[test]
    fn test_is_not_directory_listing() {
        assert!(!is_directory_listing(
            "<html><body><p>Hello world</p></body></html>"
        ));
    }

    #[test]
    fn test_classify_server_header_with_version() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_server_header(ip, 80, "nginx/1.18.0");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Info);
    }

    #[test]
    fn test_classify_server_header_no_version() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_server_header(ip, 80, "nginx");
        assert!(finding.is_none());
    }

    #[test]
    fn test_header_set_from_response() {
        let response = "HTTP/1.1 200 OK\r\n\
                         Strict-Transport-Security: max-age=31536000\r\n\
                         X-Frame-Options: DENY\r\n\
                         Content-Security-Policy: default-src 'self'\r\n\
                         X-Content-Type-Options: nosniff\r\n\
                         Server: Apache/2.4.51\r\n\r\n";
        let headers = HeaderSet::from_response(response);
        assert!(headers.has_hsts);
        assert!(headers.has_x_frame_options);
        assert!(headers.has_content_security_policy);
        assert!(headers.has_x_content_type_options);
        assert_eq!(headers.server.as_deref(), Some("Apache/2.4.51"));
    }

    #[test]
    fn test_header_set_from_empty_response() {
        let response = "HTTP/1.1 200 OK\r\n\r\n";
        let headers = HeaderSet::from_response(response);
        assert!(!headers.has_hsts);
        assert!(!headers.has_x_frame_options);
        assert!(!headers.has_content_security_policy);
        assert!(!headers.has_x_content_type_options);
        assert!(headers.server.is_none());
    }

    proptest! {
        /// classify_missing_headers never panics with any combination of bools
        #[test]
        fn prop_classify_missing_headers_no_panic(
            hsts in any::<bool>(),
            xfo in any::<bool>(),
            csp in any::<bool>(),
            xcto in any::<bool>(),
            port in 1_u16..=65535_u16,
        ) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let headers = HeaderSet {
                has_hsts: hsts,
                has_x_frame_options: xfo,
                has_content_security_policy: csp,
                has_x_content_type_options: xcto,
                server: None,
            };
            let findings = classify_missing_headers(ip, port, &headers);
            // Each missing header produces exactly one finding
            let expected = u32::from(!hsts) + u32::from(!xfo) + u32::from(!csp) + u32::from(!xcto);
            assert_eq!(findings.len(), expected as usize);
        }

        /// classify_server_header never panics on arbitrary strings
        #[test]
        fn prop_classify_server_header_no_panic(server in ".*", port in 1_u16..=65535_u16) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = classify_server_header(ip, port, &server);
        }

        /// is_default_page never panics on arbitrary strings
        #[test]
        fn prop_is_default_page_no_panic(body in ".*") {
            let _ = is_default_page(&body);
        }

        /// is_directory_listing never panics on arbitrary strings
        #[test]
        fn prop_is_directory_listing_no_panic(body in ".*") {
            let _ = is_directory_listing(&body);
        }

        /// HeaderSet::from_response never panics on arbitrary strings
        #[test]
        fn prop_header_set_from_response_no_panic(response in ".*") {
            let _ = HeaderSet::from_response(&response);
        }
    }
}
