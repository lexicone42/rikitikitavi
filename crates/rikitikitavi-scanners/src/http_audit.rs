use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
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
pub fn classify_missing_headers(ip: IpAddr, port: u16, headers: &HeaderSet) -> Vec<Finding> {
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
            .with_opt_remediation(crate::remediation::get(
                "rikitikitavi.http_audit.missing-hsts",
                &[],
            )),
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

/// Dangerous HTTP methods that should not be publicly exposed.
const DANGEROUS_METHODS: &[&str] = &["PUT", "DELETE", "TRACE", "CONNECT"];

/// Classify allowed HTTP methods from an `OPTIONS` response.
pub fn classify_http_methods(ip: IpAddr, port: u16, allow_header: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let methods: Vec<&str> = allow_header.split(',').map(str::trim).collect();

    let dangerous: Vec<&&str> = methods
        .iter()
        .filter(|m| DANGEROUS_METHODS.iter().any(|d| m.eq_ignore_ascii_case(d)))
        .collect();

    if !dangerous.is_empty() {
        let method_list: Vec<&str> = dangerous.iter().map(|m| **m).collect();
        findings.push(
            Finding::new(
                "http_audit",
                &format!("Dangerous HTTP methods on {ip}:{port}"),
                &format!(
                    "The HTTP OPTIONS response includes dangerous methods: {}. \
                     PUT/DELETE can allow file upload or deletion, TRACE enables \
                     cross-site tracing (XST) attacks.",
                    method_list.join(", ")
                ),
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP")
            .with_cwe("CWE-749"),
        );
    }

    // Info finding with all methods
    if !methods.is_empty() {
        findings.push(
            Finding::new(
                "http_audit",
                &format!("HTTP methods on {ip}:{port}"),
                &format!("Allowed methods: {allow_header}"),
                Severity::Info,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP"),
        );
    }

    findings
}

/// Detect web frameworks from response headers and body content.
pub fn detect_framework(
    ip: IpAddr,
    port: u16,
    powered_by: Option<&str>,
    body: &str,
) -> Option<Finding> {
    let body_lower = body.to_lowercase();

    // X-Powered-By header
    if let Some(pb) = powered_by {
        return Some(
            Finding::new(
                "http_audit",
                &format!("Framework disclosure on {ip}:{port}: {pb}"),
                &format!(
                    "X-Powered-By header reveals: {pb}. This helps attackers \
                     identify the technology stack and target known vulnerabilities."
                ),
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP")
            .with_cwe("CWE-200"),
        );
    }

    // Body-based framework detection
    let framework = if body_lower.contains("wp-content") || body_lower.contains("wp-includes") {
        Some("WordPress")
    } else if body_lower.contains("__next") || body_lower.contains("_next/static") {
        Some("Next.js")
    } else if body_lower.contains("drupal") && body_lower.contains("sites/default") {
        Some("Drupal")
    } else if body_lower.contains("joomla") || body_lower.contains("/media/system/") {
        Some("Joomla")
    } else if body_lower.contains("laravel")
        || body_lower.contains("csrf-token") && body_lower.contains("laravel")
    {
        Some("Laravel")
    } else if body_lower.contains("x-django") || body_lower.contains("csrfmiddlewaretoken") {
        Some("Django")
    } else if body_lower.contains("rails") && body_lower.contains("csrf-token") {
        Some("Ruby on Rails")
    } else {
        None
    };

    framework.map(|fw| {
        Finding::new(
            "http_audit",
            &format!("Framework detected on {ip}:{port}: {fw}"),
            &format!(
                "The response body contains markers for {fw}. Framework identification \
                 helps attackers target known vulnerabilities specific to that platform."
            ),
            Severity::Info,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("HTTP")
    })
}

// ── Admin panel authentication classification ──────────────────
//
// Instead of a crude "does the body contain 'login'?" check, we collect
// multiple weak signals from the HTTP response and score them.  Positive
// weight → evidence of auth protection; negative weight → evidence of
// exposed admin content.  The net score drives a three-way classification:
//   Protected  (score ≥  threshold) → suppress the finding
//   Exposed    (score ≤ −threshold) → High severity
//   Ambiguous  (in between)         → Medium severity

/// Individual signal detected in an HTTP response for auth classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSignal {
    /// `<input type="password">` found in body.
    PasswordInput,
    /// `WWW-Authenticate` response header present.
    AuthHeader,
    /// Login form detected (`<form>` with login/auth action or login button).
    LoginForm,
    /// `OAuth`, SAML, or `OpenID` Connect markers in body.
    OAuthMarkers,
    /// JS client-side redirect to login/auth URL.
    ClientRedirect,
    /// Login-related text anywhere in body (weak signal).
    LoginText,
    /// SPA framework shell (mount point + `<script>` tags).
    SpaShell,
    /// Response body < 512 bytes.
    TinyResponse,
    /// `RFC1918` private IP addresses visible in body (real network data).
    NetworkDataExposed,
    /// Admin structural content (tables + multiple config/settings keywords).
    AdminStructuralContent,
    /// Page `<title>` contains admin/dashboard/management.
    AdminTitle,
    /// Response body > 2048 bytes (full rendered page).
    SubstantialPage,
}

impl AuthSignal {
    /// Signed weight: positive = auth likely present, negative = content exposed.
    const fn weight(self) -> i32 {
        match self {
            Self::PasswordInput => 5,
            Self::AuthHeader => 4,
            Self::LoginForm | Self::OAuthMarkers => 3,
            Self::ClientRedirect => 2,
            Self::LoginText | Self::SpaShell | Self::TinyResponse => 1,
            Self::NetworkDataExposed | Self::AdminStructuralContent => -3,
            Self::AdminTitle | Self::SubstantialPage => -1,
        }
    }

    /// Human-readable label for evidence reporting.
    const fn label(self) -> &'static str {
        match self {
            Self::PasswordInput => "password input field",
            Self::AuthHeader => "WWW-Authenticate header",
            Self::LoginForm => "login form action",
            Self::OAuthMarkers => "OAuth/SAML markers",
            Self::ClientRedirect => "JS redirect to login",
            Self::LoginText => "login-related text",
            Self::SpaShell => "SPA framework shell",
            Self::TinyResponse => "minimal response (<512B)",
            Self::NetworkDataExposed => "private IPs in body",
            Self::AdminStructuralContent => "admin UI with config data",
            Self::AdminTitle => "admin-related page title",
            Self::SubstantialPage => "full page rendered (>2KB)",
        }
    }
}

/// Classification of admin panel authentication state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthClassification {
    /// Auth is present — login form, `OAuth`, password field, etc.
    Protected,
    /// Admin content is exposed without auth evidence.
    Exposed,
    /// Cannot determine — mixed or insufficient signals.
    Ambiguous,
}

/// Score threshold for classification decisions.
const AUTH_THRESHOLD: i32 = 3;

/// Classify admin panel authentication based on signal weights.
pub fn classify_auth(signals: &[AuthSignal]) -> AuthClassification {
    let score: i32 = signals.iter().map(|s| s.weight()).sum();
    if score >= AUTH_THRESHOLD {
        AuthClassification::Protected
    } else if score <= -AUTH_THRESHOLD {
        AuthClassification::Exposed
    } else {
        AuthClassification::Ambiguous
    }
}

/// Admin keywords for structural content detection (requires ≥ 2 alongside
/// HTML table elements).
const ADMIN_KEYWORDS: &[&str] = &[
    "settings",
    "configuration",
    "firmware",
    "users",
    "network",
    "wan ",
    "lan ",
    "dhcp",
    "dns server",
    "uptime",
    "cpu",
    "memory usage",
    "interface",
    "bandwidth",
    "firewall",
    "port forward",
];

/// Extract authentication signals from an HTTP response body and headers.
pub fn extract_auth_signals(body: &str, has_www_authenticate: bool) -> Vec<AuthSignal> {
    let lower = body.to_lowercase();
    let len = body.len();
    let mut signals = Vec::new();

    // ── Auth-present signals (positive weight) ──

    if has_www_authenticate {
        signals.push(AuthSignal::AuthHeader);
    }

    if lower.contains("type=\"password\"")
        || lower.contains("type='password'")
        || lower.contains("autocomplete=\"current-password\"")
    {
        signals.push(AuthSignal::PasswordInput);
    }

    if has_login_form_elements(&lower) {
        signals.push(AuthSignal::LoginForm);
    }

    if lower.contains("oauth")
        || lower.contains("openid")
        || lower.contains("saml")
        || (lower.contains("redirect_uri") && lower.contains("authorize"))
        || (lower.contains("client_id") && lower.contains("authorize"))
    {
        signals.push(AuthSignal::OAuthMarkers);
    }

    if has_client_redirect_to_auth(&lower) {
        signals.push(AuthSignal::ClientRedirect);
    }

    if has_login_related_text(&lower) {
        signals.push(AuthSignal::LoginText);
    }

    if is_spa_shell(&lower) {
        signals.push(AuthSignal::SpaShell);
    }

    if len < 512 {
        signals.push(AuthSignal::TinyResponse);
    }

    // ── Exposed-content signals (negative weight) ──

    if has_private_ips(&lower) {
        signals.push(AuthSignal::NetworkDataExposed);
    }

    if has_admin_structural_content(&lower) {
        signals.push(AuthSignal::AdminStructuralContent);
    }

    if has_admin_title(&lower) {
        signals.push(AuthSignal::AdminTitle);
    }

    if len > 2048 {
        signals.push(AuthSignal::SubstantialPage);
    }

    signals
}

/// Check for `<form>` with login/auth action or login-related submit button.
fn has_login_form_elements(lower: &str) -> bool {
    if lower.contains("<form")
        && (lower.contains("action=\"/login")
            || lower.contains("action=\"/auth")
            || lower.contains("action=\"/signin")
            || lower.contains("action=\"/session")
            || lower.contains("action='/login")
            || lower.contains("action='/auth"))
    {
        return true;
    }
    (lower.contains("<button") || lower.contains("<input"))
        && (lower.contains(">login<")
            || lower.contains(">sign in<")
            || lower.contains(">log in<")
            || lower.contains("value=\"login\"")
            || lower.contains("value=\"sign in\""))
}

/// Check for JavaScript client-side redirect to login/auth URL.
fn has_client_redirect_to_auth(lower: &str) -> bool {
    let has_js_redirect = lower.contains("window.location") || lower.contains("document.location");
    let has_meta_refresh = lower.contains("meta http-equiv=\"refresh\"");
    let has_auth_target = lower.contains("login") || lower.contains("auth") || lower.contains("signin");
    (has_js_redirect || has_meta_refresh) && has_auth_target
}

/// Check for login-related text anywhere in body.
fn has_login_related_text(lower: &str) -> bool {
    lower.contains("login")
        || lower.contains("sign in")
        || lower.contains("log in")
        || lower.contains("signin")
        || lower.contains("authenticate")
        || lower.contains("password")
        || lower.contains("username")
        || lower.contains("credentials")
}

/// Check for SPA framework shell (mount point + script tags, minimal visible text).
fn is_spa_shell(lower: &str) -> bool {
    (lower.contains("id=\"root\"")
        || lower.contains("id=\"app\"")
        || lower.contains("id=\"__next\"")
        || lower.contains("id=\"__nuxt\"")
        || lower.contains("id=\"__vue\""))
        && lower.contains("<script")
}

/// Check for `RFC1918` private IP addresses in body content.
///
/// Uses boundary-aware matching to avoid false positives on version strings.
fn has_private_ips(lower: &str) -> bool {
    lower.contains("192.168.")
        || lower.contains(">10.")
        || lower.contains(" 10.")
        || lower.contains("\"10.")
        || lower.contains(":10.")
}

/// Check for admin structural content (table elements + ≥ 2 admin keywords).
fn has_admin_structural_content(lower: &str) -> bool {
    if !lower.contains("<table") && !lower.contains("<tr") && !lower.contains("<dl") {
        return false;
    }
    let count = ADMIN_KEYWORDS.iter().filter(|kw| lower.contains(*kw)).count();
    count >= 2
}

/// Check if the page `<title>` suggests admin/management content.
fn has_admin_title(lower: &str) -> bool {
    extract_title_lower(lower).is_some_and(|title| {
        title.contains("admin")
            || title.contains("dashboard")
            || title.contains("management")
            || title.contains("configuration")
            || title.contains("settings")
            || title.contains("control panel")
            || title.contains("console")
    })
}

/// Extract the `<title>` text from already-lowercased HTML.
fn extract_title_lower(lower: &str) -> Option<&str> {
    let start = lower.find("<title>").map(|i| i + 7)?;
    let end = lower[start..].find("</title>").map(|i| i + start)?;
    let title = lower[start..end].trim();
    if title.is_empty() {
        None
    } else {
        Some(title)
    }
}

/// Format auth signals as human-readable evidence for finding descriptions.
fn format_auth_evidence(signals: &[AuthSignal]) -> String {
    let (auth_signals, exposure_signals): (Vec<&AuthSignal>, Vec<&AuthSignal>) =
        signals.iter().partition(|s| s.weight() > 0);

    let mut parts = Vec::new();

    if !exposure_signals.is_empty() {
        let labels: Vec<&str> = exposure_signals.iter().map(|s| s.label()).collect();
        parts.push(format!("Exposure indicators: {}", labels.join(", ")));
    }
    if !auth_signals.is_empty() {
        let labels: Vec<&str> = auth_signals.iter().map(|s| s.label()).collect();
        parts.push(format!("Auth indicators: {}", labels.join(", ")));
    }
    if parts.is_empty() {
        parts.push("No distinguishing signals detected".to_owned());
    }

    let score: i32 = signals.iter().map(|s| s.weight()).sum();
    parts.push(format!("confidence score: {score}"));
    parts.join(". ")
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
            has_content_security_policy: resp.headers().contains_key("content-security-policy"),
            has_x_content_type_options: resp.headers().contains_key("x-content-type-options"),
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

        // X-Powered-By framework detection
        let powered_by = resp
            .headers()
            .get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        // Check body for default pages and framework fingerprinting
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
                    .with_opt_remediation(crate::remediation::get(
                        "rikitikitavi.http_audit.directory-listing",
                        &[],
                    )),
                );
            }

            // Framework fingerprinting from body + X-Powered-By
            if let Some(fw_finding) = detect_framework(ip, port, powered_by.as_deref(), &body) {
                findings.push(fw_finding);
            }
        }
    }

    // OPTIONS method enumeration
    if let Ok(resp) = client.request(reqwest::Method::OPTIONS, &url).send().await {
        if let Some(allow) = resp.headers().get("allow").and_then(|v| v.to_str().ok()) {
            findings.extend(classify_http_methods(ip, port, allow));
        }
    }

    // Probe admin paths with signal-based auth classification
    for path in ADMIN_PATHS {
        let admin_url = format!("{scheme}://{ip}:{port}{path}");
        if let Ok(resp) = client.get(&admin_url).send().await {
            if resp.status().as_u16() == 200 {
                let has_www_auth = resp.headers().contains_key("www-authenticate");
                let body = resp.text().await.unwrap_or_default();
                let signals = extract_auth_signals(&body, has_www_auth);
                let classification = classify_auth(&signals);

                match classification {
                    AuthClassification::Protected => {
                        // Auth detected (login form, OAuth, etc.) — no finding
                    }
                    AuthClassification::Exposed => {
                        let evidence = format_auth_evidence(&signals);
                        findings.push(
                            Finding::new(
                                "http_audit",
                                &format!(
                                    "Unauthenticated admin panel at {ip}:{port}{path}"
                                ),
                                &format!(
                                    "The admin path '{path}' on {ip}:{port} exposes \
                                     administrative content without authentication. \
                                     {evidence}"
                                ),
                                Severity::High,
                            )
                            .with_ip(ip)
                            .with_port(port)
                            .with_service("HTTP")
                            .with_cwe("CWE-306")
                            .with_opt_remediation(crate::remediation::get(
                                "rikitikitavi.http_audit.admin-no-auth",
                                &[],
                            )),
                        );
                    }
                    AuthClassification::Ambiguous => {
                        let evidence = format_auth_evidence(&signals);
                        findings.push(
                            Finding::new(
                                "http_audit",
                                &format!(
                                    "Possibly exposed admin page at {ip}:{port}{path}"
                                ),
                                &format!(
                                    "The admin path '{path}' on {ip}:{port} returned \
                                     HTTP 200 but authentication state could not be \
                                     confidently determined. Review manually. {evidence}"
                                ),
                                Severity::Medium,
                            )
                            .with_ip(ip)
                            .with_port(port)
                            .with_service("HTTP")
                            .with_cwe("CWE-306")
                            .with_opt_remediation(crate::remediation::get(
                                "rikitikitavi.http_audit.admin-no-auth",
                                &[],
                            )),
                        );
                    }
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

        // Skip entirely in Passive mode — HTTP audit is slow and not essential
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping HTTP audit in quick scan mode");
            return Ok(findings);
        }

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

    fn relevant_ports(&self) -> &[u16] {
        &[80, 443, 8080, 8443, 8888, 8000, 8008, 8081, 8090, 3000]
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

    // ── HTTP methods tests ────────────────────────────────────────

    #[test]
    fn test_classify_http_methods_dangerous() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = classify_http_methods(ip, 80, "GET, POST, PUT, DELETE, OPTIONS");
        // Should have dangerous methods finding + info listing
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn test_classify_http_methods_safe() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = classify_http_methods(ip, 80, "GET, POST, HEAD, OPTIONS");
        // Only info listing, no dangerous methods
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_classify_http_methods_trace() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = classify_http_methods(ip, 80, "GET, TRACE");
        assert!(findings.iter().any(|f| f.severity == Severity::Medium));
    }

    // ── Framework detection tests ───────────────────────────────────

    #[test]
    fn test_detect_framework_powered_by() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = detect_framework(ip, 80, Some("Express"), "");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Low);
    }

    #[test]
    fn test_detect_framework_wordpress() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let body = "<link rel='stylesheet' href='/wp-content/themes/style.css'>";
        let finding = detect_framework(ip, 80, None, body);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert!(f.title.contains("WordPress"));
    }

    #[test]
    fn test_detect_framework_nextjs() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let body = "<script src=\"/_next/static/chunks/main.js\"></script>";
        let finding = detect_framework(ip, 80, None, body);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert!(f.title.contains("Next.js"));
    }

    #[test]
    fn test_detect_framework_django() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let body = "<input type=\"hidden\" name=\"csrfmiddlewaretoken\" value=\"abc123\">";
        let finding = detect_framework(ip, 80, None, body);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert!(f.title.contains("Django"));
    }

    #[test]
    fn test_detect_framework_none() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let body = "<html><body>Hello world</body></html>";
        let finding = detect_framework(ip, 80, None, body);
        assert!(finding.is_none());
    }

    // ── Auth classification tests ──────────────────────────────────

    #[test]
    fn test_classify_auth_login_page_protected() {
        let body = r#"<html><body>
            <form action="/login">
                <input type="text" name="username">
                <input type="password" name="password">
                <button>Login</button>
            </form>
        </body></html>"#;
        let signals = extract_auth_signals(body, false);
        assert_eq!(classify_auth(&signals), AuthClassification::Protected);
    }

    #[test]
    fn test_classify_auth_oauth_page_protected() {
        let body = r#"<html><body>
            <p>Redirecting to authorize...</p>
            <script>
              window.location = "/oauth/authorize?client_id=abc&redirect_uri=/cb"
            </script>
        </body></html>"#;
        let signals = extract_auth_signals(body, false);
        assert_eq!(classify_auth(&signals), AuthClassification::Protected);
    }

    #[test]
    fn test_classify_auth_www_authenticate_header() {
        let body = "<html><body></body></html>";
        let signals = extract_auth_signals(body, true);
        assert_eq!(classify_auth(&signals), AuthClassification::Protected);
    }

    #[test]
    fn test_classify_auth_exposed_dashboard() {
        let body = r"<html><head><title>Router Dashboard</title></head><body>
            <table>
                <tr><td>WAN IP</td><td>1.2.3.4</td></tr>
                <tr><td>LAN IP</td><td>192.168.1.1</td></tr>
                <tr><td>DHCP Range</td><td>192.168.1.100-200</td></tr>
                <tr><td>DNS Server</td><td>8.8.8.8</td></tr>
                <tr><td>Firmware</td><td>v2.1.3</td></tr>
                <tr><td>Uptime</td><td>14 days</td></tr>
            </table>
            <h2>Network Settings</h2>
            <h2>Firewall Rules</h2>
        </body></html>";
        let signals = extract_auth_signals(body, false);
        assert_eq!(classify_auth(&signals), AuthClassification::Exposed);
    }

    #[test]
    fn test_classify_auth_admin_tables_no_ips() {
        // Config tables without private IPs — still Exposed via structural content
        let body = r"<html><head><title>Settings</title></head><body>
            <h1>Configuration</h1>
            <table>
                <tr><td>Firmware Version</td><td>3.2.1</td></tr>
                <tr><td>DHCP Enabled</td><td>Yes</td></tr>
                <tr><td>DNS Server</td><td>8.8.8.8</td></tr>
            </table>
            <h2>Firewall Rules</h2>
            <table><tr><td>Rule 1</td><td>Allow HTTP</td></tr></table>
        </body></html>";
        let signals = extract_auth_signals(body, false);
        assert_eq!(classify_auth(&signals), AuthClassification::Exposed);
    }

    #[test]
    fn test_classify_auth_spa_shell_ambiguous() {
        let body = r#"<!DOCTYPE html>
        <html><head><title>App</title></head>
        <body><div id="root"></div>
        <script src="/static/js/main.abc123.js"></script>
        </body></html>"#;
        let signals = extract_auth_signals(body, false);
        assert_eq!(classify_auth(&signals), AuthClassification::Ambiguous);
    }

    #[test]
    fn test_classify_auth_empty_200_ambiguous() {
        let body = "<html><body></body></html>";
        let signals = extract_auth_signals(body, false);
        assert_eq!(classify_auth(&signals), AuthClassification::Ambiguous);
    }

    #[test]
    fn test_classify_auth_login_with_ip_mention() {
        // Login page that mentions 192.168.x in instructions — still Protected
        let body = r#"<html><body>
            <h1>Router Login</h1>
            <p>Connect to 192.168.1.1 to manage your router</p>
            <form action="/login">
                <input type="password" name="password">
                <button>Sign In</button>
            </form>
        </body></html>"#;
        let signals = extract_auth_signals(body, false);
        assert_eq!(classify_auth(&signals), AuthClassification::Protected);
    }

    #[test]
    fn test_classify_auth_saml_page_protected() {
        let body = r#"<html><body>
            <p>Authenticate via SAML to continue</p>
            <form action="/saml/login">
                <input type="password" name="pw">
            </form>
        </body></html>"#;
        let signals = extract_auth_signals(body, false);
        assert_eq!(classify_auth(&signals), AuthClassification::Protected);
    }

    // ── Signal extraction helper tests ──────────────────────────────

    #[test]
    fn test_extract_title_lower_basic() {
        assert_eq!(
            extract_title_lower("<title>my dashboard</title>"),
            Some("my dashboard")
        );
    }

    #[test]
    fn test_extract_title_lower_missing() {
        assert_eq!(
            extract_title_lower("<html><body>no title</body></html>"),
            None
        );
    }

    #[test]
    fn test_extract_title_lower_empty() {
        assert_eq!(extract_title_lower("<title>  </title>"), None);
    }

    #[test]
    fn test_has_private_ips_192() {
        assert!(has_private_ips("lan ip: 192.168.1.1"));
    }

    #[test]
    fn test_has_private_ips_10() {
        assert!(has_private_ips("gateway: 10.0.0.1"));
        assert!(has_private_ips("<td>10.42.1.1</td>"));
    }

    #[test]
    fn test_has_private_ips_false_on_public() {
        assert!(!has_private_ips("public ip: 8.8.8.8"));
    }

    #[test]
    fn test_has_admin_structural_content_with_tables() {
        let body = "<table><tr><td>firmware v2</td></tr>\
                     <tr><td>dhcp range</td></tr></table>";
        assert!(has_admin_structural_content(body));
    }

    #[test]
    fn test_has_admin_structural_content_no_tables() {
        let body = "<div>firmware v2 dhcp range</div>";
        assert!(!has_admin_structural_content(body));
    }

    #[test]
    fn test_has_admin_structural_content_one_keyword() {
        let body = "<table><tr><td>settings</td></tr></table>";
        assert!(!has_admin_structural_content(body));
    }

    #[test]
    fn test_is_spa_shell_react() {
        assert!(is_spa_shell(
            r#"<div id="root"></div><script src="/main.js"></script>"#
        ));
    }

    #[test]
    fn test_is_spa_shell_nextjs() {
        assert!(is_spa_shell(
            r#"<div id="__next"></div><script>window.__NEXT_DATA__</script>"#
        ));
    }

    #[test]
    fn test_is_spa_shell_no_script() {
        assert!(!is_spa_shell(r#"<div id="root"></div>"#));
    }

    #[test]
    fn test_is_spa_shell_no_mount() {
        assert!(!is_spa_shell(r#"<script src="/main.js"></script>"#));
    }

    #[test]
    fn test_format_auth_evidence_exposed_signals() {
        let signals = vec![
            AuthSignal::NetworkDataExposed,
            AuthSignal::AdminStructuralContent,
            AuthSignal::SubstantialPage,
        ];
        let evidence = format_auth_evidence(&signals);
        assert!(evidence.contains("Exposure indicators"));
        assert!(evidence.contains("private IPs in body"));
        assert!(evidence.contains("confidence score: -7"));
    }

    #[test]
    fn test_format_auth_evidence_mixed_signals() {
        let signals = vec![AuthSignal::LoginText, AuthSignal::AdminTitle];
        let evidence = format_auth_evidence(&signals);
        assert!(evidence.contains("Auth indicators"));
        assert!(evidence.contains("Exposure indicators"));
        assert!(evidence.contains("confidence score: 0"));
    }

    #[test]
    fn test_format_auth_evidence_no_signals() {
        let evidence = format_auth_evidence(&[]);
        assert!(evidence.contains("No distinguishing signals"));
        assert!(evidence.contains("confidence score: 0"));
    }

    #[test]
    fn test_classify_auth_score_boundaries() {
        // Exactly at threshold: score = 3 → Protected
        let signals = vec![AuthSignal::LoginForm]; // weight = 3
        assert_eq!(classify_auth(&signals), AuthClassification::Protected);

        // Exactly at negative threshold: score = -3 → Exposed
        let signals = vec![AuthSignal::NetworkDataExposed]; // weight = -3
        assert_eq!(classify_auth(&signals), AuthClassification::Exposed);

        // Just inside ambiguous: score = 2
        let signals = vec![AuthSignal::ClientRedirect]; // weight = 2
        assert_eq!(classify_auth(&signals), AuthClassification::Ambiguous);

        // Just inside ambiguous: score = -2
        let signals = vec![AuthSignal::AdminTitle, AuthSignal::SubstantialPage]; // -1 + -1 = -2
        assert_eq!(classify_auth(&signals), AuthClassification::Ambiguous);
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

        /// `HeaderSet::from_response` never panics on arbitrary strings
        #[test]
        fn prop_header_set_from_response_no_panic(response in ".*") {
            let _ = HeaderSet::from_response(&response);
        }

        /// `classify_http_methods` never panics on arbitrary strings
        #[test]
        fn prop_classify_http_methods_no_panic(allow in ".*") {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = classify_http_methods(ip, 80, &allow);
        }

        /// `detect_framework` never panics on arbitrary strings
        #[test]
        fn prop_detect_framework_no_panic(body in ".*") {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = detect_framework(ip, 80, None, &body);
        }

        /// `extract_auth_signals` never panics on arbitrary input
        #[test]
        fn prop_extract_auth_signals_no_panic(
            body in ".*",
            has_www_auth in any::<bool>(),
        ) {
            let _ = extract_auth_signals(&body, has_www_auth);
        }

        /// `classify_auth` is deterministic — same body produces same result
        #[test]
        fn prop_classify_auth_deterministic(
            body in ".*",
            has_www_auth in any::<bool>(),
        ) {
            let s1 = extract_auth_signals(&body, has_www_auth);
            let s2 = extract_auth_signals(&body, has_www_auth);
            assert_eq!(classify_auth(&s1), classify_auth(&s2));
        }

        /// Classification matches the computed score
        #[test]
        fn prop_classify_auth_matches_score(
            body in ".*",
            has_www_auth in any::<bool>(),
        ) {
            let signals = extract_auth_signals(&body, has_www_auth);
            let score: i32 = signals.iter().map(|s| s.weight()).sum();
            let classification = classify_auth(&signals);
            match classification {
                AuthClassification::Protected => {
                    assert!(score >= AUTH_THRESHOLD, "Protected but score {score}");
                }
                AuthClassification::Exposed => {
                    assert!(score <= -AUTH_THRESHOLD, "Exposed but score {score}");
                }
                AuthClassification::Ambiguous => {
                    assert!(
                        score > -AUTH_THRESHOLD && score < AUTH_THRESHOLD,
                        "Ambiguous but score {score}"
                    );
                }
            }
        }
    }
}
