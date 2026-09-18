use async_trait::async_trait;
use futures::stream::StreamExt;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::IpAddr;
use std::time::Duration;

use crate::Scanner;
use crate::http_util::unauthenticated_probe_client;
use crate::recog;
use crate::recog_db::RecogKey;

/// Upper bound on concurrently audited HTTP endpoints.
const MAX_AUDIT_CONCURRENCY: usize = 8;

/// HTTP audit scanner: security headers, CSP/CORS/cookie attributes, default
/// pages, directory listing, admin paths on Phase 1 HTTP ports.
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
        let (severity, description) = if crate::dns::is_private_ip(ip) {
            (
                Severity::Info,
                "The server does not send a Strict-Transport-Security header. \
                 On private network IPs, HSTS has no practical effect — browsers \
                 do not HSTS-pin raw IP addresses or RFC1918 ranges.",
            )
        } else {
            (
                Severity::Medium,
                "The server does not send a Strict-Transport-Security header. \
                 Without HSTS, browsers may connect over unencrypted HTTP, \
                 enabling man-in-the-middle attacks.",
            )
        };

        findings.push(
            Finding::new(
                "http_audit",
                &format!("Missing HSTS header on {ip}:{port}"),
                description,
                severity,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP")
            .with_cwe("CWE-319")
            .with_references(refs![
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
            ])
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
            .with_cwe("CWE-1021")
            .with_references(refs![
                "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
            ]),
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
            .with_cwe("CWE-79")
            .with_references(refs![
                "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            ]),
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
            .with_cwe("CWE-16")
            .with_references(refs!["https://owasp.org/www-project-secure-headers/",]),
        );
    }

    findings
}

/// Detect whether an HTTP response body is a default/unconfigured server page.
pub fn is_default_page(body: &str) -> bool {
    let lower = body.to_lowercase();

    if lower.contains("it works!") && lower.contains("apache") {
        return true;
    }

    if lower.contains("welcome to nginx") {
        return true;
    }

    if lower.contains("welcome") && lower.contains("internet information services") {
        return true;
    }

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

/// Identify Synology DSM, QNAP QTS, or Home Assistant web UIs from the `Server`
/// header and body. Probable-confidence Low finding; auth state is judged separately.
pub fn classify_nas_ha(ip: IpAddr, port: u16, server: Option<&str>, body: &str) -> Option<Finding> {
    let hay = format!("{} {}", server.unwrap_or(""), body).to_lowercase();

    let is_ha = hay.contains("home assistant")
        || hay.contains("home-assistant")
        || (port == 8123 && hay.contains("assistant"));

    let (product, why, advisory) =
        if hay.contains("synology") || hay.contains("diskstation") || hay.contains("synohdpack") {
            (
                "Synology DSM (NAS)",
                "Network-attached storage is a top ransomware target (eCh0raix and similar).",
                "https://www.synology.com/en-global/security/advisory",
            )
        } else if hay.contains("qnap") || hay.contains("quts") {
            (
                "QNAP QTS (NAS)",
                "QNAP NAS devices are heavily targeted by ransomware (Deadbolt, Qlocker).",
                "https://www.qnap.com/en/security-advisories",
            )
        } else if is_ha {
            (
                "Home Assistant",
                "A smart-home hub controls locks, cameras, and alarms; keep it patched and \
             never expose it directly to the internet.",
                "https://www.home-assistant.io/latest-security-alerts/",
            )
        } else {
            return None;
        };

    Some(
        Finding::new(
            "http_audit",
            &format!("{product} detected on {ip}:{port}"),
            &format!(
                "The web interface at {ip}:{port} appears to be {product}. {why} Keep its \
                 firmware/software current, require strong authentication, and ensure it is \
                 not reachable from the internet."
            ),
            Severity::Low,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("HTTP")
        .with_confidence(rikitikitavi_core::Confidence::Probable)
        .with_references(refs![advisory]),
    )
}

/// Parse the version triple following `apache/` in a lowercased `Server` header.
fn parse_apache_version(lower: &str) -> Option<(u32, u32, u32)> {
    let idx = lower.find("apache/")?;
    let rest = &lower[idx + "apache/".len()..];
    let version: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts = version.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    Some((major, minor, patch))
}

/// Extract the Server header value and classify known vulnerable versions.
pub fn classify_server_header(ip: IpAddr, port: u16, server: &str) -> Option<Finding> {
    let lower = server.to_lowercase();

    // Apache path traversal: CVE-2021-41773 (2.4.49) and CVE-2021-42013 (2.4.50).
    // 2.4.48 and earlier are unaffected; 2.4.51 fixed both.
    if let Some((2, 4, patch)) = parse_apache_version(&lower) {
        let cve = match patch {
            49 => Some("CVE-2021-41773"),
            50 => Some("CVE-2021-42013"),
            _ => None,
        };
        if let Some(cve_id) = cve {
            let cve_url = format!("https://nvd.nist.gov/vuln/detail/{cve_id}");
            return Some(
                Finding::new(
                    "http_audit",
                    &format!("Vulnerable Apache ({cve_id}) on {ip}:{port}"),
                    &format!(
                        "Server header indicates Apache 2.4.{patch} ({server}), affected by \
                         {cve_id} (path traversal / remote code execution). Patch to 2.4.51 \
                         or later immediately."
                    ),
                    Severity::High,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("HTTP")
                .with_confidence(rikitikitavi_core::Confidence::Probable)
                .with_cwe("CWE-22")
                .with_references(refs![cve_url]),
            );
        }
    }

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

/// End-of-life findings for versioned products named in `X-Powered-By`.
///
/// `PHP/8.0.30` is the common case; `ASP.NET` and `Express` carry no version and
/// yield nothing. The EOL join lives in `services` because that is where the
/// `eol_db` glue is.
pub fn check_powered_by_eol(ip: IpAddr, port: u16, powered_by: &str) -> Vec<Finding> {
    powered_by
        .split([',', ' ', ';'])
        .filter_map(|token| {
            let token = token.trim();
            let (name, version) = token.split_once('/')?;
            let product = crate::services::eol_product(&name.to_ascii_lowercase())?;
            let summary = crate::services::eol_summary(product, version)?;
            Some(
                Finding::new(
                    "http_audit",
                    &format!("End-of-life {product} on {ip}:{port}"),
                    &format!("The X-Powered-By header advertises {token}. {summary}"),
                    Severity::Medium,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("HTTP")
                .with_confidence(rikitikitavi_core::Confidence::Probable)
                .with_cwe("CWE-1104")
                .with_evidence(powered_by),
            )
        })
        .collect()
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
            .with_cwe("CWE-749")
            .with_references(refs![
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
            ]),
        );
    }

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
// Weighted signals are summed: score ≥ +3 → Protected (no finding),
// ≤ −3 → Exposed (High), otherwise Ambiguous (Medium).

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
    /// CSRF/XSRF token header present (`x-csrf-token`, `x-xsrf-token`, or
    /// referenced in `access-control-expose-headers`).
    CsrfTokenHeader,
    /// `Set-Cookie` header contains a session-like cookie name (`sid=`,
    /// `session`, `jsessionid`, `auth_token`, `token=`).
    SessionCookie,
    /// JS client-side redirect to login/auth URL.
    ClientRedirect,
    /// Body is a thin redirect page (`location.replace()` / `location.href=`)
    /// changing only the port or scheme, with no login/auth target.
    PortRedirect,
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

/// Header-derived auth signals, captured before the body is consumed.
#[derive(Debug, Default)]
pub struct ResponseHeaderSignals {
    /// `WWW-Authenticate` header present.
    pub has_www_authenticate: bool,
    /// CSRF/XSRF token evidence in headers (`x-csrf-token`, `x-xsrf-token`,
    /// or listed in `access-control-expose-headers`).
    pub has_csrf_token: bool,
    /// `Set-Cookie` header contains a session-like cookie name.
    pub has_session_cookie: bool,
}

impl AuthSignal {
    /// Signed weight: positive = auth likely present, negative = content exposed.
    const fn weight(self) -> i32 {
        match self {
            Self::PasswordInput => 5,
            Self::AuthHeader | Self::CsrfTokenHeader => 4,
            Self::LoginForm | Self::OAuthMarkers | Self::SessionCookie => 3,
            Self::ClientRedirect | Self::PortRedirect => 2,
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
            Self::CsrfTokenHeader => "CSRF token header",
            Self::SessionCookie => "session cookie",
            Self::LoginForm => "login form action",
            Self::OAuthMarkers => "OAuth/SAML markers",
            Self::ClientRedirect => "JS redirect to login",
            Self::PortRedirect => "port/scheme redirect",
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

/// Keywords for structural admin-content detection (≥ 2 required alongside table elements).
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
pub fn extract_auth_signals(body: &str, headers: &ResponseHeaderSignals) -> Vec<AuthSignal> {
    let lower = body.to_lowercase();
    let len = body.len();
    let mut signals = Vec::new();

    // ── Auth-present signals (positive weight) ──

    if headers.has_www_authenticate {
        signals.push(AuthSignal::AuthHeader);
    }

    if headers.has_csrf_token {
        signals.push(AuthSignal::CsrfTokenHeader);
    }

    if headers.has_session_cookie {
        signals.push(AuthSignal::SessionCookie);
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

    if is_port_redirect(&lower) {
        signals.push(AuthSignal::PortRedirect);
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
    let has_auth_target =
        lower.contains("login") || lower.contains("auth") || lower.contains("signin");
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
        || lower.contains("id=\"__vue\"")
        || lower.contains("id=\"portal-root\""))
        && lower.contains("<script")
}

/// Thin redirect page: `location.replace(` / `location.href` present and no
/// login/auth keywords.
fn is_port_redirect(lower: &str) -> bool {
    let has_redirect = lower.contains("location.replace(") || lower.contains("location.href");
    if !has_redirect {
        return false;
    }
    let has_auth_target =
        lower.contains("login") || lower.contains("auth") || lower.contains("signin");
    !has_auth_target
}

/// Detect `RFC1918`-looking addresses in the body (`192.168.` or delimiter-prefixed `10.`).
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
    let count = ADMIN_KEYWORDS
        .iter()
        .filter(|kw| lower.contains(*kw))
        .count();
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
    if title.is_empty() { None } else { Some(title) }
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

// ── Content-Security-Policy analysis ────────────────────────────

/// A parsed CSP directive: name + list of source expressions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspDirective {
    pub name: String,
    pub sources: Vec<String>,
}

/// Parse a CSP header (`name src1 src2; name2 src3`) into lowercased directives.
pub fn parse_csp(header: &str) -> Vec<CspDirective> {
    header
        .split(';')
        .filter_map(|d| {
            let trimmed = d.trim();
            if trimmed.is_empty() {
                return None;
            }
            let mut parts = trimmed.split_whitespace();
            let name = parts.next()?.to_lowercase();
            let sources: Vec<String> = parts.map(str::to_lowercase).collect();
            Some(CspDirective { name, sources })
        })
        .collect()
}

/// Sources for `name`, falling back to `default-src` (CSP inheritance).
fn csp_effective_sources<'a>(directives: &'a [CspDirective], name: &str) -> Option<&'a [String]> {
    directives
        .iter()
        .find(|d| d.name == name)
        .or_else(|| directives.iter().find(|d| d.name == "default-src"))
        .map(|d| d.sources.as_slice())
}

/// True if every source is `'none'` or `'self'`.
fn is_restrictive(sources: &[String]) -> bool {
    !sources.is_empty() && sources.iter().all(|s| s == "'none'" || s == "'self'")
}

/// Analyse a present CSP header for weaknesses. `has_x_frame_options`
/// suppresses the `frame-ancestors` finding.
#[allow(clippy::too_many_lines)]
pub fn analyze_csp(ip: IpAddr, port: u16, header: &str, has_x_frame_options: bool) -> Vec<Finding> {
    let directives = parse_csp(header);
    if directives.is_empty() {
        return Vec::new();
    }
    let mut findings = Vec::new();

    if let Some(sources) = csp_effective_sources(&directives, "script-src") {
        if sources.iter().any(|s| s == "'unsafe-inline'") {
            findings.push(
                Finding::new(
                    "http_audit",
                    &format!("CSP allows unsafe-inline scripts on {ip}:{port}"),
                    "The Content-Security-Policy includes 'unsafe-inline' in the \
                     script source directive. This defeats XSS protection because \
                     inline <script> tags and event handlers are allowed.",
                    Severity::Medium,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("HTTP")
                .with_cwe("CWE-79")
                .with_references(refs![
                    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                ]),
            );
        }

        if sources.iter().any(|s| s == "'unsafe-eval'") {
            findings.push(
                Finding::new(
                    "http_audit",
                    &format!("CSP allows unsafe-eval on {ip}:{port}"),
                    "The Content-Security-Policy includes 'unsafe-eval' in the \
                     script source directive, permitting dynamic code execution \
                     which is a common XSS attack vector.",
                    Severity::Medium,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("HTTP")
                .with_cwe("CWE-79")
                .with_references(refs![
                    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                ]),
            );
        }

        if sources.iter().any(|s| s == "data:") {
            findings.push(
                Finding::new(
                    "http_audit",
                    &format!("CSP allows data: URIs in scripts on {ip}:{port}"),
                    "The Content-Security-Policy allows data: URIs as script \
                     sources. An attacker can inject data:text/javascript,... \
                     to execute arbitrary code, bypassing the CSP.",
                    Severity::Medium,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("HTTP")
                .with_cwe("CWE-79")
                .with_references(refs![
                    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                ]),
            );
        }
    }

    let wildcard_directives: Vec<&str> = directives
        .iter()
        .filter(|d| d.sources.iter().any(|s| s == "*"))
        .map(|d| d.name.as_str())
        .collect();

    if !wildcard_directives.is_empty() {
        findings.push(
            Finding::new(
                "http_audit",
                &format!("CSP wildcard source on {ip}:{port}"),
                &format!(
                    "The Content-Security-Policy uses wildcard (*) sources in: {}. \
                     Wildcards allow loading resources from any origin, providing \
                     minimal security benefit.",
                    wildcard_directives.join(", ")
                ),
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP")
            .with_cwe("CWE-16"),
        );
    }

    let has_object_src = directives.iter().any(|d| d.name == "object-src");
    if !has_object_src {
        let default_restrictive = directives
            .iter()
            .find(|d| d.name == "default-src")
            .is_some_and(|d| is_restrictive(&d.sources));
        if !default_restrictive {
            findings.push(
                Finding::new(
                    "http_audit",
                    &format!("CSP missing object-src on {ip}:{port}"),
                    "The Content-Security-Policy does not define object-src and \
                     the default-src is not restrictive. Without object-src, \
                     plugin content (Flash, Java) may be injectable.",
                    Severity::Low,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("HTTP")
                .with_cwe("CWE-79")
                .with_references(refs![
                    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                ]),
            );
        }
    }

    if !directives.iter().any(|d| d.name == "base-uri") {
        findings.push(
            Finding::new(
                "http_audit",
                &format!("CSP missing base-uri on {ip}:{port}"),
                "The Content-Security-Policy does not restrict base-uri. An \
                 attacker who can inject HTML could add a <base> tag to redirect \
                 all relative URLs to a malicious domain.",
                Severity::Info,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP")
            .with_cwe("CWE-79"),
        );
    }

    if !directives.iter().any(|d| d.name == "frame-ancestors") && !has_x_frame_options {
        findings.push(
            Finding::new(
                "http_audit",
                &format!("CSP missing frame-ancestors on {ip}:{port}"),
                "Neither frame-ancestors in CSP nor X-Frame-Options is set. \
                 The page can be embedded in an attacker-controlled iframe for \
                 clickjacking attacks.",
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP")
            .with_cwe("CWE-1021"),
        );
    }

    findings
}

// ── CORS analysis ───────────────────────────────────────────────

/// Analyse CORS headers for misconfigurations.
pub fn analyze_cors(
    ip: IpAddr,
    port: u16,
    allow_origin: Option<&str>,
    allow_credentials: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let Some(origin) = allow_origin else {
        return findings;
    };

    if origin == "*" {
        if allow_credentials {
            // Browsers reject `*` + credentials; still a misconfiguration.
            findings.push(
                Finding::new(
                    "http_audit",
                    &format!("CORS wildcard with credentials on {ip}:{port}"),
                    "Access-Control-Allow-Origin is set to '*' alongside \
                     Access-Control-Allow-Credentials: true. Modern browsers \
                     reject this combination, but it indicates a fundamental \
                     CORS misconfiguration that may work in older clients.",
                    Severity::High,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("HTTP")
                .with_cwe("CWE-942")
                .with_references(refs![
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                ]),
            );
        } else {
            findings.push(
                Finding::new(
                    "http_audit",
                    &format!("Permissive CORS policy on {ip}:{port}"),
                    "Access-Control-Allow-Origin is set to '*', allowing any \
                     website to make cross-origin requests. On a network device, \
                     this means a malicious webpage could query its API while \
                     you browse the internet.",
                    Severity::Medium,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("HTTP")
                .with_cwe("CWE-942")
                .with_references(refs![
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                ]),
            );
        }
    } else if origin == "null" {
        findings.push(
            Finding::new(
                "http_audit",
                &format!("CORS allows null origin on {ip}:{port}"),
                "Access-Control-Allow-Origin is set to 'null'. The null origin \
                 can be forged via sandboxed iframes and data: URIs, making \
                 this effectively an open CORS policy.",
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(port)
            .with_service("HTTP")
            .with_cwe("CWE-942")
            .with_references(refs![
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            ]),
        );
    }

    findings
}

// ── Cookie attribute analysis ───────────────────────────────────

/// Security-relevant attributes parsed from a `Set-Cookie` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieAttributes {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
}

/// Parse a single `Set-Cookie` header value into security attributes.
pub fn parse_set_cookie(header: &str) -> CookieAttributes {
    let name = header.split('=').next().unwrap_or("").trim().to_lowercase();

    let lower = header.to_lowercase();
    let parts: Vec<&str> = lower.split(';').map(str::trim).collect();

    let secure = parts.contains(&"secure");
    let http_only = parts.contains(&"httponly");
    let same_site = parts
        .iter()
        .find_map(|p| p.strip_prefix("samesite=").map(|v| v.trim().to_owned()));

    CookieAttributes {
        name,
        secure,
        http_only,
        same_site,
    }
}

/// Check if a cookie name indicates a session or authentication cookie.
fn is_security_relevant_cookie(name: &str) -> bool {
    name == "sid"
        || name.contains("session")
        || name.contains("jsessionid")
        || name.contains("auth")
        || name.contains("token")
        || name.starts_with("__host-")
        || name.starts_with("__secure-")
}

/// Analyse session cookies for missing security attributes.
#[allow(clippy::too_many_lines)]
pub fn analyze_cookies(
    ip: IpAddr,
    port: u16,
    is_https: bool,
    cookies: &[CookieAttributes],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for cookie in cookies {
        if !is_security_relevant_cookie(&cookie.name) {
            continue;
        }

        if is_https && !cookie.secure {
            findings.push(
                Finding::new(
                    "http_audit",
                    &format!(
                        "Session cookie '{}' missing Secure flag on {ip}:{port}",
                        cookie.name
                    ),
                    &format!(
                        "The '{}' cookie is set over HTTPS without the Secure \
                         attribute. The browser may send it over plain HTTP \
                         connections, exposing the session to interception.",
                        cookie.name
                    ),
                    Severity::Medium,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("HTTP")
                .with_cwe("CWE-614")
                .with_references(refs![
                    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                ]),
            );
        }

        if !cookie.http_only {
            findings.push(
                Finding::new(
                    "http_audit",
                    &format!(
                        "Session cookie '{}' missing HttpOnly on {ip}:{port}",
                        cookie.name
                    ),
                    &format!(
                        "The '{}' cookie lacks the HttpOnly attribute. JavaScript \
                         (including XSS payloads) can read it via document.cookie.",
                        cookie.name
                    ),
                    Severity::Low,
                )
                .with_ip(ip)
                .with_port(port)
                .with_service("HTTP")
                .with_cwe("CWE-1004")
                .with_references(refs![
                    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                ]),
            );
        }

        match cookie.same_site.as_deref() {
            None => {
                findings.push(
                    Finding::new(
                        "http_audit",
                        &format!(
                            "Session cookie '{}' missing SameSite on {ip}:{port}",
                            cookie.name
                        ),
                        &format!(
                            "The '{}' cookie does not set SameSite. While modern \
                             browsers default to Lax, older browsers send it with \
                             all cross-site requests, enabling CSRF attacks.",
                            cookie.name
                        ),
                        Severity::Info,
                    )
                    .with_ip(ip)
                    .with_port(port)
                    .with_service("HTTP")
                    .with_cwe("CWE-352"),
                );
            }
            Some("none") => {
                findings.push(
                    Finding::new(
                        "http_audit",
                        &format!(
                            "Session cookie '{}' has SameSite=None on {ip}:{port}",
                            cookie.name
                        ),
                        &format!(
                            "The '{}' cookie uses SameSite=None, allowing it to be \
                             sent with all cross-site requests. On a network device \
                             session cookie, this increases CSRF risk.",
                            cookie.name
                        ),
                        Severity::Low,
                    )
                    .with_ip(ip)
                    .with_port(port)
                    .with_service("HTTP")
                    .with_cwe("CWE-352"),
                );
            }
            Some(_) => { /* Lax or Strict */ }
        }
    }

    findings
}

/// Extract header-level auth signals from a `reqwest::Response`.
fn extract_response_header_signals(resp: &reqwest::Response) -> ResponseHeaderSignals {
    let has_www_authenticate = resp.headers().contains_key("www-authenticate");

    let has_csrf_token = resp.headers().contains_key("x-csrf-token")
        || resp.headers().contains_key("x-xsrf-token")
        || resp
            .headers()
            .get("access-control-expose-headers")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                let lower = v.to_lowercase();
                lower.contains("csrf") || lower.contains("xsrf")
            });

    let has_session_cookie = resp.headers().get_all("set-cookie").iter().any(|v| {
        v.to_str()
            .is_ok_and(|s| is_session_cookie_value(&s.to_lowercase()))
    });

    ResponseHeaderSignals {
        has_www_authenticate,
        has_csrf_token,
        has_session_cookie,
    }
}

/// Check if a `Set-Cookie` value (lowercased) looks like a session cookie.
fn is_session_cookie_value(lower: &str) -> bool {
    lower.starts_with("sid=")
        || lower.contains("session")
        || lower.contains("jsessionid")
        || lower.starts_with("auth_token=")
        || lower.starts_with("token=")
}

/// ASCII-case-insensitive substring search that keeps byte indices valid.
fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    let n = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(n.len())
        .position(|w| w.eq_ignore_ascii_case(n))
}

/// The `<title>` with its original case; Recog's `html_title` patterns are
/// case-sensitive unless they carry `(?i)`.
fn extract_title(body: &str) -> Option<&str> {
    let open = find_ascii_ci(body, "<title")?;
    let start = body[open..].find('>')? + open + 1;
    let close = find_ascii_ci(body.get(start..)?, "</title>")? + start;
    let title = body.get(start..close)?.trim();
    (!title.is_empty()).then_some(title)
}

/// Identify an HTTP endpoint from the `Server` header, the `WWW-Authenticate`
/// realm and the page title together, as one finding.
fn recog_identify(
    ip: IpAddr,
    port: u16,
    server: Option<&str>,
    www_authenticate: Option<&str>,
    body: &str,
) -> Option<Finding> {
    let title = extract_title(body);
    let mut inputs: Vec<(RecogKey, &str)> = Vec::new();
    if let Some(server) = server {
        inputs.push((RecogKey::HttpServer, server));
    }
    if let Some(auth) = www_authenticate {
        inputs.push((RecogKey::HttpWwwAuth, auth));
    }
    if let Some(title) = title {
        inputs.push((RecogKey::HtmlTitle, title));
    }
    let matches = recog::identify_all(&inputs);
    recog::identification_finding("http_audit", ip, Some(port), &matches)
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

    let Ok(client) =
        unauthenticated_probe_client(HTTP_TIMEOUT, reqwest::redirect::Policy::limited(3))
    else {
        return findings;
    };

    let url = format!("{scheme}://{ip}:{port}/");
    if let Ok(resp) = client.get(&url).send().await {
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

        if scheme == "https" {
            findings.extend(classify_missing_headers(ip, port, &headers));
        } else {
            let partial = HeaderSet {
                has_hsts: true, // no HSTS finding on plain HTTP
                has_x_frame_options: headers.has_x_frame_options,
                has_content_security_policy: headers.has_content_security_policy,
                has_x_content_type_options: headers.has_x_content_type_options,
                server: None,
            };
            findings.extend(classify_missing_headers(ip, port, &partial));
        }

        if let Some(ref server) = headers.server
            && let Some(finding) = classify_server_header(ip, port, server)
        {
            findings.push(finding);
        }

        let www_authenticate = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        let powered_by = resp
            .headers()
            .get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        if let Some(ref pb) = powered_by {
            findings.extend(check_powered_by_eol(ip, port, pb));
        }

        let csp_value = resp
            .headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        let cors_origin = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let cors_credentials = resp
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));

        let cookies: Vec<CookieAttributes> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(parse_set_cookie)
            .collect();

        // Body read is capped (untrusted device).
        let body = crate::http_util::read_body_capped(resp, crate::http_util::MAX_BODY_BYTES).await;

        if let Some(f) = classify_nas_ha(ip, port, headers.server.as_deref(), &body) {
            findings.push(f);
        }

        findings.extend(recog_identify(
            ip,
            port,
            headers.server.as_deref(),
            www_authenticate.as_deref(),
            &body,
        ));
        {
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
                    .with_references(refs![
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                    ])
                    .with_opt_remediation(crate::remediation::get(
                        "rikitikitavi.http_audit.directory-listing",
                        &[],
                    )),
                );
            }

            if let Some(fw_finding) = detect_framework(ip, port, powered_by.as_deref(), &body) {
                findings.push(fw_finding);
            }
        }

        if let Some(ref csp) = csp_value {
            findings.extend(analyze_csp(ip, port, csp, headers.has_x_frame_options));
        }

        findings.extend(analyze_cors(
            ip,
            port,
            cors_origin.as_deref(),
            cors_credentials,
        ));

        let is_https = scheme == "https";
        findings.extend(analyze_cookies(ip, port, is_https, &cookies));
    }

    if let Ok(resp) = client.request(reqwest::Method::OPTIONS, &url).send().await
        && let Some(allow) = resp.headers().get("allow").and_then(|v| v.to_str().ok())
    {
        findings.extend(classify_http_methods(ip, port, allow));
    }

    for path in ADMIN_PATHS {
        let admin_url = format!("{scheme}://{ip}:{port}{path}");
        if let Ok(resp) = client.get(&admin_url).send().await
            && resp.status().as_u16() == 200
        {
            let header_signals = extract_response_header_signals(&resp);
            let body =
                crate::http_util::read_body_capped(resp, crate::http_util::MAX_BODY_BYTES).await;
            let signals = extract_auth_signals(&body, &header_signals);
            let classification = classify_auth(&signals);

            match classification {
                AuthClassification::Protected => {
                    // no finding
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
                            .with_references(refs![
                                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                            ])
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
                            &format!("Possibly exposed admin page at {ip}:{port}{path}"),
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

    findings
}

/// Flatten indexed per-endpoint findings back into input order.
fn flatten_by_index(mut indexed: Vec<(usize, Vec<Finding>)>) -> Vec<Finding> {
    indexed.sort_by_key(|(idx, _)| *idx);
    indexed.into_iter().flat_map(|(_, f)| f).collect()
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

        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping HTTP audit in quick scan mode");
            return Ok(findings);
        }

        if ctx.discovered_devices.is_empty() {
            tracing::info!("no discovered devices, skipping HTTP audit");
            return Ok(findings);
        }

        // Flatten to (ip, port) endpoints, then audit with bounded concurrency.
        let mut endpoints: Vec<(IpAddr, u16)> = Vec::new();
        for device in &ctx.discovered_devices {
            for p in &device.open_ports {
                if AUDIT_PORTS.contains(&p.port) {
                    endpoints.push((device.ip, p.port));
                }
            }
        }

        let concurrency = ctx.config.parallelism.clamp(1, MAX_AUDIT_CONCURRENCY);

        // `buffer_unordered` completes out of order; keep the input index to
        // restore deterministic ordering before flattening.
        let indexed: Vec<(usize, Vec<Finding>)> =
            futures::stream::iter(endpoints.into_iter().enumerate())
                .map(|(idx, (ip, port))| async move { (idx, audit_http_endpoint(ip, port).await) })
                .buffer_unordered(concurrency)
                .collect()
                .await;

        findings.extend(flatten_by_index(indexed));

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
    fn extract_title_keeps_the_original_case() {
        assert_eq!(
            extract_title("<html><head><TITLE>RouterOS router configuration page</TITLE>"),
            Some("RouterOS router configuration page")
        );
        assert_eq!(
            extract_title("<title lang=\"en\"> Spaced </title>"),
            Some("Spaced")
        );
        assert_eq!(extract_title("<title></title>"), None);
        assert_eq!(extract_title("<title>unterminated"), None);
        assert_eq!(extract_title("no title here"), None);
    }

    #[test]
    fn find_ascii_ci_is_byte_index_safe() {
        assert_eq!(find_ascii_ci("héllo<TITLE>", "<title"), Some(6));
        assert_eq!(find_ascii_ci("short", "much longer needle"), None);
    }

    /// A title Recog knows identifies the device; the finding stays Info/Probable.
    #[test]
    fn recog_identify_uses_the_page_title() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let body = "<html><head><title>RouterOS router configuration page</title></head></html>";
        let finding = recog_identify(ip, 80, None, None, body).unwrap();
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.confidence, rikitikitavi_core::Confidence::Probable);
        assert!(finding.title.contains("192.168.1.1:80"));
    }

    /// Nothing recognisable yields no finding at all.
    #[test]
    fn recog_identify_is_silent_without_a_match() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(recog_identify(ip, 80, None, None, "<title>zzzz</title>").is_none());
    }

    proptest! {
        #[test]
        fn prop_extract_title_no_panic(body in ".*") {
            let _ = extract_title(&body);
        }

        #[test]
        fn prop_recog_identify_no_panic(body in ".*", server in ".*") {
            let ip: IpAddr = "192.168.1.1".parse().unwrap();
            let _ = recog_identify(ip, 80, Some(&server), None, &body);
        }
    }

    #[test]
    fn test_flatten_by_index_restores_input_order() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let mk =
            |title: &str| vec![Finding::new("http_audit", title, "d", Severity::Info).with_ip(ip)];
        // Completion order is scrambled (2, 0, 1) as buffer_unordered would yield.
        let scrambled = vec![(2usize, mk("c")), (0usize, mk("a")), (1usize, mk("b"))];
        let flat = flatten_by_index(scrambled);
        let titles: Vec<&str> = flat.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_flatten_by_index_empty() {
        assert!(flatten_by_index(Vec::new()).is_empty());
    }

    #[test]
    fn test_classify_missing_all_headers() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let headers = HeaderSet::default();
        let findings = classify_missing_headers(ip, 443, &headers);
        assert_eq!(findings.len(), 4);
        // HSTS on private IP → Info
        assert_eq!(findings[0].severity, Severity::Info);
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
    fn test_classify_missing_hsts_only_private_ip() {
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
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_classify_missing_hsts_only_public_ip() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
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
    fn test_classify_nas_ha_identifies_products() {
        let ip: IpAddr = "192.168.1.220".parse().unwrap();
        // Synology (body marker)
        let f = classify_nas_ha(ip, 5000, None, "<title>DiskStation</title>").unwrap();
        assert!(f.description.contains("Synology"));
        // QNAP (server header marker)
        let f = classify_nas_ha(ip, 8080, Some("QTS"), "<html>QNAP Systems</html>").unwrap();
        assert!(f.description.contains("QNAP"));
        // Home Assistant (port + marker)
        let f = classify_nas_ha(ip, 8123, None, "<title>Home Assistant</title>").unwrap();
        assert!(f.description.contains("Home Assistant"));
    }

    #[test]
    fn test_classify_nas_ha_ignores_ordinary_pages() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        assert!(classify_nas_ha(ip, 80, Some("nginx/1.18.0"), "<h1>hello</h1>").is_none());
    }

    #[test]
    fn test_classify_server_header_no_version() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_server_header(ip, 80, "nginx");
        assert!(finding.is_none());
    }

    #[test]
    fn test_parse_apache_version() {
        assert_eq!(
            parse_apache_version("apache/2.4.49 (unix)"),
            Some((2, 4, 49))
        );
        assert_eq!(parse_apache_version("apache/2.4.4"), Some((2, 4, 4)));
        assert_eq!(parse_apache_version("nginx/1.18.0"), None);
    }

    #[test]
    fn test_apache_2448_not_flagged_for_traversal() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_server_header(ip, 80, "Apache/2.4.48 (Unix)").unwrap();
        // Version disclosure only — not a path-traversal CVE.
        assert_eq!(finding.severity, Severity::Info);
        assert!(!finding.title.contains("CVE-2021-41773"));
        assert!(!finding.title.contains("CVE-2021-42013"));
    }

    #[test]
    fn test_apache_2449_flags_cve_2021_41773() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_server_header(ip, 80, "Apache/2.4.49 (Unix)").unwrap();
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.title.contains("CVE-2021-41773"));
        assert!(
            finding
                .references
                .iter()
                .any(|r| r.contains("CVE-2021-41773"))
        );
    }

    #[test]
    fn test_apache_2450_flags_cve_2021_42013() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_server_header(ip, 80, "Apache/2.4.50 (Unix)").unwrap();
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.title.contains("CVE-2021-42013"));
        assert!(
            finding
                .references
                .iter()
                .any(|r| r.contains("CVE-2021-42013"))
        );
    }

    #[test]
    fn test_apache_2451_not_flagged_for_traversal() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = classify_server_header(ip, 80, "Apache/2.4.51 (Unix)").unwrap();
        assert_eq!(finding.severity, Severity::Info);
        assert!(!finding.title.contains("CVE-2021-41773"));
        assert!(!finding.title.contains("CVE-2021-42013"));
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
        let signals = extract_auth_signals(body, &ResponseHeaderSignals::default());
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
        let signals = extract_auth_signals(body, &ResponseHeaderSignals::default());
        assert_eq!(classify_auth(&signals), AuthClassification::Protected);
    }

    #[test]
    fn test_classify_auth_www_authenticate_header() {
        let body = "<html><body></body></html>";
        let headers = ResponseHeaderSignals {
            has_www_authenticate: true,
            ..ResponseHeaderSignals::default()
        };
        let signals = extract_auth_signals(body, &headers);
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
        let signals = extract_auth_signals(body, &ResponseHeaderSignals::default());
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
        let signals = extract_auth_signals(body, &ResponseHeaderSignals::default());
        assert_eq!(classify_auth(&signals), AuthClassification::Exposed);
    }

    #[test]
    fn test_classify_auth_spa_shell_ambiguous() {
        let body = r#"<!DOCTYPE html>
        <html><head><title>App</title></head>
        <body><div id="root"></div>
        <script src="/static/js/main.abc123.js"></script>
        </body></html>"#;
        let signals = extract_auth_signals(body, &ResponseHeaderSignals::default());
        assert_eq!(classify_auth(&signals), AuthClassification::Ambiguous);
    }

    #[test]
    fn test_classify_auth_empty_200_ambiguous() {
        let body = "<html><body></body></html>";
        let signals = extract_auth_signals(body, &ResponseHeaderSignals::default());
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
        let signals = extract_auth_signals(body, &ResponseHeaderSignals::default());
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
        let signals = extract_auth_signals(body, &ResponseHeaderSignals::default());
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

    // ── New header-based signal tests ──────────────────────────────

    #[test]
    fn test_classify_auth_csrf_token_header() {
        // CSRF token header alone: +4 ≥ 3 → Protected
        let body = "<html><body></body></html>";
        let headers = ResponseHeaderSignals {
            has_csrf_token: true,
            ..ResponseHeaderSignals::default()
        };
        let signals = extract_auth_signals(body, &headers);
        assert!(signals.contains(&AuthSignal::CsrfTokenHeader));
        assert_eq!(classify_auth(&signals), AuthClassification::Protected);
    }

    #[test]
    fn test_classify_auth_session_cookie_on_spa() {
        // Session cookie (+3) on SPA shell (+1) = +4 ≥ 3 → Protected
        let body = r#"<!DOCTYPE html>
        <html><head><title>App</title></head>
        <body><div id="root"></div>
        <script src="/static/js/main.abc123.js"></script>
        </body></html>"#;
        let headers = ResponseHeaderSignals {
            has_session_cookie: true,
            ..ResponseHeaderSignals::default()
        };
        let signals = extract_auth_signals(body, &headers);
        assert!(signals.contains(&AuthSignal::SessionCookie));
        assert!(signals.contains(&AuthSignal::SpaShell));
        assert_eq!(classify_auth(&signals), AuthClassification::Protected);
    }

    #[test]
    fn test_classify_auth_port_redirect() {
        // Thin redirect page: PortRedirect (+2) + TinyResponse (+1) = +3 → Protected
        // Use a hostname (not a private IP) to avoid triggering NetworkDataExposed.
        let body = r#"<html><script>location.replace("https://myhost:5001/")</script></html>"#;
        let signals = extract_auth_signals(body, &ResponseHeaderSignals::default());
        assert!(signals.contains(&AuthSignal::PortRedirect));
        assert_eq!(classify_auth(&signals), AuthClassification::Protected);
    }

    #[test]
    fn test_port_redirect_not_triggered_with_login() {
        // Redirect to login page should NOT trigger PortRedirect
        let body = r#"<script>window.location = "/login"</script>"#;
        let signals = extract_auth_signals(body, &ResponseHeaderSignals::default());
        assert!(!signals.contains(&AuthSignal::PortRedirect));
        // Should trigger ClientRedirect instead (window.location + login keyword)
        assert!(signals.contains(&AuthSignal::ClientRedirect));
    }

    #[test]
    fn test_spa_shell_portal_root() {
        // UniFi portal-root pattern
        assert!(is_spa_shell(
            r#"<div id="portal-root"></div><script src="/main.js"></script>"#
        ));
    }

    #[test]
    fn test_is_session_cookie_value_sid() {
        assert!(is_session_cookie_value("sid=abc123; httponly; path=/"));
    }

    #[test]
    fn test_is_session_cookie_value_jsessionid() {
        assert!(is_session_cookie_value(
            "jsessionid=abc123; httponly; secure"
        ));
    }

    #[test]
    fn test_is_session_cookie_value_tracking() {
        // A tracking cookie is NOT a session cookie
        assert!(!is_session_cookie_value("_ga=ga1.2.12345; path=/"));
    }

    #[test]
    fn test_is_port_redirect_location_replace() {
        assert!(is_port_redirect(
            r#"<script>location.replace("https://192.168.1.220:5001/")</script>"#
        ));
    }

    #[test]
    fn test_is_port_redirect_location_href() {
        assert!(is_port_redirect(
            r#"<script>location.href="https://host:5001/"</script>"#
        ));
    }

    #[test]
    fn test_is_port_redirect_false_with_login() {
        assert!(!is_port_redirect(
            r#"<script>location.replace("/login")</script>"#
        ));
    }

    // ── CSP parsing tests ──────────────────────────────────────────

    #[test]
    fn test_parse_csp_basic() {
        let directives =
            parse_csp("default-src 'self'; script-src 'unsafe-inline' cdn.example.com");
        assert_eq!(directives.len(), 2);
        assert_eq!(directives[0].name, "default-src");
        assert_eq!(directives[0].sources, vec!["'self'"]);
        assert_eq!(directives[1].name, "script-src");
        assert_eq!(
            directives[1].sources,
            vec!["'unsafe-inline'", "cdn.example.com"]
        );
    }

    #[test]
    fn test_parse_csp_trailing_semicolons() {
        let directives = parse_csp("default-src 'none';;; ");
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].name, "default-src");
    }

    #[test]
    fn test_parse_csp_empty() {
        assert!(parse_csp("").is_empty());
        assert!(parse_csp("   ").is_empty());
        assert!(parse_csp(";;;").is_empty());
    }

    #[test]
    fn test_parse_csp_case_insensitive() {
        let directives = parse_csp("Script-Src 'UNSAFE-INLINE' CDN.EXAMPLE.COM");
        assert_eq!(directives[0].name, "script-src");
        assert_eq!(directives[0].sources[0], "'unsafe-inline'");
    }

    #[test]
    fn test_analyze_csp_unsafe_inline() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = analyze_csp(ip, 443, "script-src 'unsafe-inline' 'self'", true);
        assert!(findings.iter().any(|f| f.title.contains("unsafe-inline")));
    }

    #[test]
    fn test_analyze_csp_unsafe_eval() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = analyze_csp(ip, 443, "script-src 'self' 'unsafe-eval'", true);
        assert!(findings.iter().any(|f| f.title.contains("unsafe-eval")));
    }

    #[test]
    fn test_analyze_csp_data_uri() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = analyze_csp(ip, 443, "script-src 'self' data:", true);
        assert!(findings.iter().any(|f| f.title.contains("data: URIs")));
    }

    #[test]
    fn test_analyze_csp_wildcard() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = analyze_csp(ip, 443, "default-src *", true);
        assert!(findings.iter().any(|f| f.title.contains("wildcard")));
    }

    #[test]
    fn test_analyze_csp_missing_object_src() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // default-src is permissive → object-src warning
        let findings = analyze_csp(ip, 443, "default-src 'self' https:", true);
        assert!(findings.iter().any(|f| f.title.contains("object-src")));
    }

    #[test]
    fn test_analyze_csp_object_src_ok_with_restrictive_default() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // default-src 'none' covers object-src implicitly
        let findings = analyze_csp(ip, 443, "default-src 'none'; script-src 'self'", true);
        assert!(!findings.iter().any(|f| f.title.contains("object-src")));
    }

    #[test]
    fn test_analyze_csp_explicit_object_src() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // Explicit object-src → no finding regardless of default-src
        let findings = analyze_csp(ip, 443, "default-src https:; object-src 'none'", true);
        assert!(!findings.iter().any(|f| f.title.contains("object-src")));
    }

    #[test]
    fn test_analyze_csp_missing_base_uri() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = analyze_csp(ip, 443, "default-src 'self'", true);
        assert!(findings.iter().any(|f| f.title.contains("base-uri")));
    }

    #[test]
    fn test_analyze_csp_has_base_uri() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = analyze_csp(ip, 443, "default-src 'self'; base-uri 'self'", true);
        assert!(!findings.iter().any(|f| f.title.contains("base-uri")));
    }

    #[test]
    fn test_analyze_csp_missing_frame_ancestors_with_xfo() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // XFO present → no frame-ancestors finding
        let findings = analyze_csp(ip, 443, "default-src 'self'", true);
        assert!(!findings.iter().any(|f| f.title.contains("frame-ancestors")));
    }

    #[test]
    fn test_analyze_csp_missing_frame_ancestors_without_xfo() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // Neither XFO nor frame-ancestors → finding
        let findings = analyze_csp(ip, 443, "default-src 'self'", false);
        assert!(findings.iter().any(|f| f.title.contains("frame-ancestors")));
    }

    #[test]
    fn test_analyze_csp_default_src_fallback() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // No explicit script-src → falls back to default-src
        let findings = analyze_csp(ip, 443, "default-src 'self' 'unsafe-inline'", true);
        assert!(findings.iter().any(|f| f.title.contains("unsafe-inline")));
    }

    #[test]
    fn test_analyze_csp_strict_policy_minimal_findings() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = analyze_csp(
            ip,
            443,
            "default-src 'none'; script-src 'self'; style-src 'self'; \
             base-uri 'self'; frame-ancestors 'self'; object-src 'none'",
            true,
        );
        // Well-configured CSP → should produce zero findings
        assert!(findings.is_empty(), "strict CSP produced: {findings:?}");
    }

    // ── CORS tests ──────────────────────────────────────────────────

    #[test]
    fn test_analyze_cors_wildcard() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = analyze_cors(ip, 80, Some("*"), false);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_analyze_cors_wildcard_with_credentials() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = analyze_cors(ip, 80, Some("*"), true);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_analyze_cors_null_origin() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = analyze_cors(ip, 80, Some("null"), false);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("null origin"));
    }

    #[test]
    fn test_analyze_cors_specific_origin() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        // A specific origin is fine
        let findings = analyze_cors(ip, 80, Some("https://example.com"), false);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_analyze_cors_no_header() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let findings = analyze_cors(ip, 80, None, false);
        assert!(findings.is_empty());
    }

    // ── Cookie attribute tests ──────────────────────────────────────

    #[test]
    fn test_parse_set_cookie_full() {
        let cookie =
            parse_set_cookie("session_id=abc123; Path=/; HttpOnly; Secure; SameSite=Strict");
        assert_eq!(cookie.name, "session_id");
        assert!(cookie.secure);
        assert!(cookie.http_only);
        assert_eq!(cookie.same_site.as_deref(), Some("strict"));
    }

    #[test]
    fn test_parse_set_cookie_minimal() {
        let cookie = parse_set_cookie("token=xyz");
        assert_eq!(cookie.name, "token");
        assert!(!cookie.secure);
        assert!(!cookie.http_only);
        assert!(cookie.same_site.is_none());
    }

    #[test]
    fn test_parse_set_cookie_samesite_none() {
        let cookie = parse_set_cookie("sid=abc; SameSite=None; Secure");
        assert_eq!(cookie.same_site.as_deref(), Some("none"));
        assert!(cookie.secure);
    }

    #[test]
    fn test_analyze_cookies_missing_secure_on_https() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cookies = vec![CookieAttributes {
            name: "session".to_owned(),
            secure: false,
            http_only: true,
            same_site: Some("lax".to_owned()),
        }];
        let findings = analyze_cookies(ip, 443, true, &cookies);
        assert!(findings.iter().any(|f| f.title.contains("Secure flag")));
    }

    #[test]
    fn test_analyze_cookies_secure_not_checked_on_http() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cookies = vec![CookieAttributes {
            name: "session".to_owned(),
            secure: false,
            http_only: true,
            same_site: Some("lax".to_owned()),
        }];
        // HTTP → don't flag missing Secure (it wouldn't work anyway)
        let findings = analyze_cookies(ip, 80, false, &cookies);
        assert!(!findings.iter().any(|f| f.title.contains("Secure flag")));
    }

    #[test]
    fn test_analyze_cookies_missing_httponly() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cookies = vec![CookieAttributes {
            name: "auth_token".to_owned(),
            secure: true,
            http_only: false,
            same_site: Some("lax".to_owned()),
        }];
        let findings = analyze_cookies(ip, 443, true, &cookies);
        assert!(findings.iter().any(|f| f.title.contains("HttpOnly")));
    }

    #[test]
    fn test_analyze_cookies_missing_samesite() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cookies = vec![CookieAttributes {
            name: "sid".to_owned(),
            secure: true,
            http_only: true,
            same_site: None,
        }];
        let findings = analyze_cookies(ip, 443, true, &cookies);
        assert!(findings.iter().any(|f| f.title.contains("SameSite")));
        assert_eq!(
            findings
                .iter()
                .find(|f| f.title.contains("SameSite"))
                .unwrap()
                .severity,
            Severity::Info
        );
    }

    #[test]
    fn test_analyze_cookies_samesite_none() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cookies = vec![CookieAttributes {
            name: "token".to_owned(),
            secure: true,
            http_only: true,
            same_site: Some("none".to_owned()),
        }];
        let findings = analyze_cookies(ip, 443, true, &cookies);
        assert!(findings.iter().any(|f| f.title.contains("SameSite=None")));
    }

    #[test]
    fn test_analyze_cookies_fully_secured() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cookies = vec![CookieAttributes {
            name: "session".to_owned(),
            secure: true,
            http_only: true,
            same_site: Some("strict".to_owned()),
        }];
        let findings = analyze_cookies(ip, 443, true, &cookies);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_analyze_cookies_ignores_non_session() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cookies = vec![CookieAttributes {
            name: "_ga".to_owned(),
            secure: false,
            http_only: false,
            same_site: None,
        }];
        // Analytics cookie → skip
        let findings = analyze_cookies(ip, 443, true, &cookies);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_is_security_relevant_cookie_names() {
        assert!(is_security_relevant_cookie("sid"));
        assert!(is_security_relevant_cookie("session_id"));
        assert!(is_security_relevant_cookie("jsessionid"));
        assert!(is_security_relevant_cookie("auth_token"));
        assert!(is_security_relevant_cookie("access_token"));
        assert!(is_security_relevant_cookie("__host-session"));
        assert!(is_security_relevant_cookie("__secure-auth"));
        assert!(!is_security_relevant_cookie("_ga"));
        assert!(!is_security_relevant_cookie("theme"));
        assert!(!is_security_relevant_cookie("lang"));
    }

    #[test]
    fn test_powered_by_eol_php() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let findings = check_powered_by_eol(ip, 80, "PHP/7.4.33");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].title, format!("End-of-life php on {ip}:80"));
        assert!(
            findings[0]
                .description
                .contains("end-of-life on 2022-11-28")
        );
        assert_eq!(findings[0].cwe_id.as_deref(), Some("CWE-1104"));
    }

    #[test]
    fn test_powered_by_eol_ignores_supported_and_unversioned() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let latest = crate::eol_db::current("php")
            .and_then(|c| c.latest)
            .unwrap();
        assert!(check_powered_by_eol(ip, 80, &format!("PHP/{latest}")).is_empty());
        assert!(check_powered_by_eol(ip, 80, "ASP.NET").is_empty());
        assert!(check_powered_by_eol(ip, 80, "Express").is_empty());
        assert!(check_powered_by_eol(ip, 80, "").is_empty());
    }

    /// Multi-token headers are split; each versioned product is judged separately.
    #[test]
    fn test_powered_by_eol_multiple_tokens() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let findings = check_powered_by_eol(ip, 80, "PHP/5.6.40, ASP.NET");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("php 5.6"));
    }

    /// `name/version` tokens built from real table cycles. A bare `".*"`
    /// strategy essentially never produces `PHP/7.4.33`, so assertions inside
    /// the findings loop would never execute.
    fn real_powered_by_tokens() -> Vec<String> {
        [("PHP", "php"), ("php-fpm", "php"), ("Python", "python")]
            .iter()
            .flat_map(|(token, product)| {
                crate::eol_db::product_cycles(product)
                    .iter()
                    .flat_map(move |row| {
                        [
                            format!("{token}/{}", row.cycle),
                            format!("{token}/{}.7", row.cycle),
                        ]
                    })
            })
            .collect()
    }

    /// `X-Powered-By`-shaped headers that reach the end-of-life join, mixed
    /// with unmapped products and junk.
    /// Guards `prop_powered_by_eol_no_panic` against going vacuous: its
    /// assertions sit inside `for finding in ...`, so they only mean something
    /// while the strategy still reaches findings. Measured ~69% of samples.
    #[test]
    fn arb_powered_by_reaches_findings() {
        use proptest::test_runner::{Config, TestRunner};
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut runner = TestRunner::new(Config {
            cases: 256,
            ..Config::default()
        });
        let hits = std::cell::Cell::new(0_u32);
        runner
            .run(&arb_powered_by(), |header| {
                if !check_powered_by_eol(ip, 80, &header).is_empty() {
                    hits.set(hits.get() + 1);
                }
                Ok(())
            })
            .unwrap();
        assert!(hits.get() > 20, "only {} of 256 samples fired", hits.get());
    }

    fn arb_powered_by() -> impl Strategy<Value = String> {
        let token = prop_oneof![
            6 => prop::sample::select(real_powered_by_tokens()),
            1 => (
                prop::sample::select(vec!["ASP.NET", "Express", "mysql"]),
                "[0-9]{1,2}(\\.[0-9]{1,2}){0,3}",
            )
                .prop_map(|(name, version)| format!("{name}/{version}")),
            1 => "[!-~]{0,12}".prop_map(String::from),
        ];
        prop_oneof![
            1 => any::<String>(),
            9 => prop::collection::vec(token, 1..4).prop_map(|parts| parts.join(", ")),
        ]
    }

    proptest! {
        /// `check_powered_by_eol` never panics, and only reports mapped products.
        #[test]
        fn prop_powered_by_eol_no_panic(header in arb_powered_by()) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            for finding in check_powered_by_eol(ip, 80, &header) {
                prop_assert!(finding.title.starts_with("End-of-life "));
                prop_assert_eq!(finding.cwe_id.as_deref(), Some("CWE-1104"));
                prop_assert_eq!(finding.severity, Severity::Medium);
                let product = finding
                    .title
                    .strip_prefix("End-of-life ")
                    .and_then(|rest| rest.split(' ').next())
                    .unwrap_or("");
                prop_assert!(
                    crate::services::eol_product(product).is_some(),
                    "{}",
                    finding.title
                );
            }
        }

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
            has_csrf in any::<bool>(),
            has_session in any::<bool>(),
        ) {
            let headers = ResponseHeaderSignals {
                has_www_authenticate: has_www_auth,
                has_csrf_token: has_csrf,
                has_session_cookie: has_session,
            };
            let _ = extract_auth_signals(&body, &headers);
        }

        /// `classify_auth` is deterministic — same body produces same result
        #[test]
        fn prop_classify_auth_deterministic(
            body in ".*",
            has_www_auth in any::<bool>(),
            has_csrf in any::<bool>(),
            has_session in any::<bool>(),
        ) {
            let headers = ResponseHeaderSignals {
                has_www_authenticate: has_www_auth,
                has_csrf_token: has_csrf,
                has_session_cookie: has_session,
            };
            let s1 = extract_auth_signals(&body, &headers);
            let s2 = extract_auth_signals(&body, &headers);
            assert_eq!(classify_auth(&s1), classify_auth(&s2));
        }

        /// `parse_csp` never panics on arbitrary strings
        #[test]
        fn prop_parse_csp_no_panic(header in ".*") {
            let _ = parse_csp(&header);
        }

        /// `analyze_csp` never panics on arbitrary strings
        #[test]
        fn prop_analyze_csp_no_panic(
            header in ".*",
            has_xfo in any::<bool>(),
        ) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = analyze_csp(ip, 443, &header, has_xfo);
        }

        /// `analyze_cors` never panics on arbitrary inputs
        #[test]
        fn prop_analyze_cors_no_panic(
            origin in proptest::option::of(".*"),
            creds in any::<bool>(),
        ) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let _ = analyze_cors(ip, 80, origin.as_deref(), creds);
        }

        /// `parse_set_cookie` never panics on arbitrary strings
        #[test]
        fn prop_parse_set_cookie_no_panic(header in ".*") {
            let _ = parse_set_cookie(&header);
        }

        /// `analyze_cookies` never panics on arbitrary cookie attributes
        #[test]
        fn prop_analyze_cookies_no_panic(
            name in "[a-z_]{1,20}",
            secure in any::<bool>(),
            http_only in any::<bool>(),
            is_https in any::<bool>(),
        ) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let cookies = vec![CookieAttributes {
                name,
                secure,
                http_only,
                same_site: None,
            }];
            let _ = analyze_cookies(ip, 443, is_https, &cookies);
        }

        /// Classification matches the computed score
        #[test]
        fn prop_classify_auth_matches_score(
            body in ".*",
            has_www_auth in any::<bool>(),
            has_csrf in any::<bool>(),
            has_session in any::<bool>(),
        ) {
            let headers = ResponseHeaderSignals {
                has_www_authenticate: has_www_auth,
                has_csrf_token: has_csrf,
                has_session_cookie: has_session,
            };
            let signals = extract_auth_signals(&body, &headers);
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
