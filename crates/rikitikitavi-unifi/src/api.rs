use anyhow::{Context, Result, bail};
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use rikitikitavi_scanners::http_util::{read_body_capped, unauthenticated_probe_client};
use serde::Deserialize;
use std::time::Duration;

use crate::models::{
    AdoptedDevice, FirewallRule, IdsEvent, NetworkConfig, Site, UniFiClientInfo, WlanConfig,
};

/// Body cap for the unauthenticated probe.
const PROBE_BODY_MAX: usize = 64 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Standard `UniFi` API JSON envelope.
#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    meta: ApiMeta,
    data: Vec<T>,
}

/// Envelope metadata.
#[derive(Debug, Deserialize)]
struct ApiMeta {
    rc: String,
    #[serde(default)]
    msg: Option<String>,
}

/// Controller API layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiLayout {
    /// Self-hosted Network application: `/api/login`, `/api/s/<site>/...`.
    Classic,
    /// `UniFi` OS console (UDM/UCG/UDR/UCK G2): `/api/auth/login`, `/proxy/network/api/s/<site>/...`.
    UniFiOs,
}

impl ApiLayout {
    /// Prefix for Network-application paths.
    #[must_use]
    pub const fn api_prefix(self) -> &'static str {
        match self {
            Self::Classic => "",
            Self::UniFiOs => "/proxy/network",
        }
    }

    /// Credential login path (never prefixed).
    #[must_use]
    pub const fn login_path(self) -> &'static str {
        match self {
            Self::Classic => "/api/login",
            Self::UniFiOs => "/api/auth/login",
        }
    }
}

/// Classic controllers answer their own login/site paths with 200 or 400; 401/404 means the
/// path is not served (`UniFi` OS).
const fn path_not_served(status: StatusCode) -> bool {
    matches!(status.as_u16(), 401 | 404)
}

/// `x-csrf-token` (classic, `UniFi` OS 2.x) or `x-updated-csrf-token` (`UniFi` OS 3.x+).
fn csrf_from(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get("x-updated-csrf-token")
        .or_else(|| headers.get("x-csrf-token"))
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
}

/// `UniFi` Controller API client.
pub struct UniFiClient {
    base_url: String,
    client: Client,
    csrf_token: Option<String>,
    site: String,
    layout: ApiLayout,
    authenticated: bool,
    /// If set, use Bearer token auth instead of session cookies.
    bearer_token: Option<String>,
}

impl UniFiClient {
    /// Create a new client for the given controller URL.
    pub fn new(base_url: &str, site: &str) -> Result<Self> {
        Self::build(base_url, site, false)
    }

    /// Preferred constructor: validates TLS unless `insecure`, which logs a warning.
    pub fn connect(base_url: &str, site: &str, insecure: bool) -> Result<Self> {
        if insecure {
            tracing::warn!(
                %base_url,
                "TLS certificate validation DISABLED for UniFi connection — \
                 admin credentials sent during login are exposed to on-path \
                 attackers. Only use --insecure on a trusted network."
            );
            eprintln!(
                "WARNING: TLS certificate validation is disabled for {base_url}. \
                 Your UniFi admin credentials are not protected against interception."
            );
            Self::new_insecure(base_url, site)
        } else {
            Self::new(base_url, site)
        }
    }

    /// Create a client that accepts self-signed certificates.
    pub fn new_insecure(base_url: &str, site: &str) -> Result<Self> {
        Self::build(base_url, site, true)
    }

    fn build(base_url: &str, site: &str, accept_invalid_certs: bool) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(accept_invalid_certs)
            .cookie_store(true)
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client,
            csrf_token: None,
            site: site.to_owned(),
            layout: ApiLayout::Classic,
            authenticated: false,
            bearer_token: None,
        })
    }

    /// Force a layout instead of detecting it at login.
    #[must_use]
    pub const fn with_layout(mut self, layout: ApiLayout) -> Self {
        self.layout = layout;
        self
    }

    /// Current layout; `Classic` until login detects otherwise.
    #[must_use]
    pub const fn layout(&self) -> ApiLayout {
        self.layout
    }

    /// `<base_url><api_prefix><path>` for Network-application paths.
    fn api_url(&self, path: &str) -> String {
        format!("{}{}{path}", self.base_url, self.layout.api_prefix())
    }

    /// `/api/s/<site>/<suffix>`.
    fn site_path(&self, suffix: &str) -> String {
        format!("/api/s/{}/{suffix}", self.site)
    }

    fn login_url(&self) -> String {
        format!("{}{}", self.base_url, self.layout.login_path())
    }

    async fn post_login(&self, body: &serde_json::Value) -> Result<reqwest::Response> {
        self.client
            .post(self.login_url())
            .json(body)
            .send()
            .await
            .context("failed to connect to UniFi controller")
    }

    /// Authenticate with username/password. Falls back to the `UniFi` OS layout when the
    /// classic login path is not served.
    pub async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        tracing::info!(base_url = %self.base_url, "authenticating with UniFi controller");

        let body = serde_json::json!({
            "username": username,
            "password": password,
        });

        let mut resp = self.post_login(&body).await?;
        let mut classic_status = None;
        if self.layout == ApiLayout::Classic && path_not_served(resp.status()) {
            classic_status = Some(resp.status());
            self.layout = ApiLayout::UniFiOs;
            tracing::debug!(status = %resp.status(), "classic login path not served; retrying as UniFi OS");
            resp = self.post_login(&body).await?;
        }

        if !resp.status().is_success() {
            let tried = classic_status.map_or_else(String::new, |s| format!(" (classic: {s})"));
            bail!(
                "UniFi login failed with status {}{tried} — check credentials",
                resp.status()
            );
        }

        self.csrf_token = csrf_from(resp.headers());
        self.authenticated = true;
        tracing::info!(layout = ?self.layout, "UniFi authentication successful");
        Ok(())
    }

    async fn verify_token(&self) -> Result<reqwest::Response> {
        self.get_request(&self.api_url("/api/self/sites"))
            .send()
            .await
            .context("failed to verify API token")
    }

    /// Authenticate with API token (`UniFi` OS 2.x+ / Network 9.x API key). Falls back to the
    /// `UniFi` OS layout when the classic sites path is not served.
    pub async fn login_token(&mut self, token: &str) -> Result<()> {
        tracing::info!(base_url = %self.base_url, "authenticating with API token");

        self.bearer_token = Some(token.to_owned());

        let mut resp = self.verify_token().await?;
        let mut classic_status = None;
        if self.layout == ApiLayout::Classic && path_not_served(resp.status()) {
            classic_status = Some(resp.status());
            self.layout = ApiLayout::UniFiOs;
            tracing::debug!(status = %resp.status(), "classic sites path not served; retrying as UniFi OS");
            resp = self.verify_token().await?;
        }

        if !resp.status().is_success() {
            self.bearer_token = None;
            let tried = classic_status.map_or_else(String::new, |s| format!(" (classic: {s})"));
            bail!(
                "API token verification failed with status {}{tried} — check token",
                resp.status()
            );
        }

        self.authenticated = true;
        tracing::info!(layout = ?self.layout, "UniFi token authentication successful");
        Ok(())
    }

    /// Add Bearer (and, on `UniFi` OS, `X-API-KEY`) and CSRF headers.
    fn authed(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.bearer_token {
            req = req.header("Authorization", format!("Bearer {token}"));
            if self.layout == ApiLayout::UniFiOs {
                req = req.header("X-API-KEY", token.as_str());
            }
        }
        if let Some(csrf) = &self.csrf_token {
            req = req.header("x-csrf-token", csrf.as_str());
        }
        req
    }

    /// Build an authenticated GET request.
    fn get_request(&self, url: &str) -> reqwest::RequestBuilder {
        self.authed(self.client.get(url))
    }

    /// Execute an API GET and deserialize the envelope.
    async fn api_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<Vec<T>> {
        let url = self.api_url(path);
        tracing::debug!(%url, "API GET");

        let resp = self
            .get_request(&url)
            .send()
            .await
            .with_context(|| format!("GET {path} failed"))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("API request {path} returned {status}: {body}");
        }

        let envelope: ApiResponse<T> = resp
            .json()
            .await
            .with_context(|| format!("failed to parse response from {path}"))?;

        if envelope.meta.rc != "ok" {
            bail!(
                "API returned rc={}: {}",
                envelope.meta.rc,
                envelope.meta.msg.as_deref().unwrap_or("unknown error")
            );
        }

        Ok(envelope.data)
    }

    /// Get all sites.
    pub async fn get_sites(&self) -> Result<Vec<Site>> {
        tracing::debug!("fetching sites");
        self.api_get("/api/self/sites").await
    }

    /// Get all adopted devices for the current site.
    pub async fn get_devices(&self) -> Result<Vec<AdoptedDevice>> {
        tracing::debug!(site = %self.site, "fetching devices");
        self.api_get(&self.site_path("stat/device")).await
    }

    /// Get all active clients.
    pub async fn get_clients(&self, historical: bool) -> Result<Vec<UniFiClientInfo>> {
        tracing::debug!(site = %self.site, historical, "fetching clients");
        let suffix = if historical { "rest/user" } else { "stat/sta" };
        self.api_get(&self.site_path(suffix)).await
    }

    /// Get network configurations.
    pub async fn get_networks(&self) -> Result<Vec<NetworkConfig>> {
        tracing::debug!(site = %self.site, "fetching networks");
        self.api_get(&self.site_path("rest/networkconf")).await
    }

    /// Get WLAN configurations.
    pub async fn get_wlans(&self) -> Result<Vec<WlanConfig>> {
        tracing::debug!(site = %self.site, "fetching WLANs");
        self.api_get(&self.site_path("rest/wlanconf")).await
    }

    /// Get firewall rules.
    pub async fn get_firewall_rules(&self) -> Result<Vec<FirewallRule>> {
        tracing::debug!(site = %self.site, "fetching firewall rules");
        self.api_get(&self.site_path("rest/firewallrule")).await
    }

    /// Get IDS/IPS events.
    pub async fn get_ids_events(&self, limit: u32) -> Result<Vec<IdsEvent>> {
        tracing::debug!(site = %self.site, limit, "fetching IDS events");
        // POST with a JSON body, unlike the other endpoints.
        let url = self.api_url(&self.site_path("stat/ips/event"));
        let body = serde_json::json!({
            "_limit": limit,
            "_sort": "-time",
        });

        let resp = self
            .authed(self.client.post(&url).json(&body))
            .send()
            .await
            .context("failed to fetch IDS events")?;

        if !resp.status().is_success() {
            bail!("IDS events request failed: {}", resp.status());
        }

        let envelope: ApiResponse<IdsEvent> = resp.json().await?;
        if envelope.meta.rc != "ok" {
            bail!("IDS events API returned rc={}", envelope.meta.rc);
        }

        Ok(envelope.data)
    }

    /// Unauthenticated liveness probe: a `UniFi` controller answers `/api/self/sites` with
    /// `api.err.LoginRequired` (classic) or `AUTHENTICATION_REQUIRED` (`UniFi` OS) in the body.
    /// Status alone is not trusted. Dedicated client: no cookies, no redirects, capped body.
    pub async fn probe(&self) -> bool {
        let Ok(client) = unauthenticated_probe_client(PROBE_TIMEOUT, Policy::none()) else {
            return false;
        };
        let url = self.api_url("/api/self/sites");
        let Ok(resp) = client.get(&url).send().await else {
            return false;
        };
        let body = read_body_capped(resp, PROBE_BODY_MAX).await;
        body.contains("api.err.LoginRequired") || body.contains("AUTHENTICATION_REQUIRED")
    }

    /// Check if authenticated.
    pub const fn is_authenticated(&self) -> bool {
        self.authenticated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    type Handler = dyn Fn(&str, &str, &str) -> String + Send + Sync;

    /// Serialised HTTP/1.1 response with `Connection: close`.
    fn http_response(status: u16, extra_headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}",
            body.len()
        )
    }

    fn content_length(head: &str) -> usize {
        head.lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().parse().unwrap_or(0))
            })
            .unwrap_or(0)
    }

    /// One-request-per-connection HTTP server; handler gets `(method, path, request head)`.
    async fn spawn_server(
        handler: impl Fn(&str, &str, &str) -> String + Send + Sync + 'static,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler: Arc<Handler> = Arc::new(handler);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                            continue;
                        };
                        let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
                        if buf.len() < pos + 4 + content_length(&head) {
                            continue;
                        }
                        let mut parts = head.split_whitespace();
                        let method = parts.next().unwrap_or("").to_owned();
                        let path = parts.next().unwrap_or("").to_owned();
                        let resp = handler(&method, &path, &head);
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                        return;
                    }
                });
            }
        });
        format!("http://{addr}")
    }

    const EMPTY_OK: &str = r#"{"meta":{"rc":"ok"},"data":[]}"#;

    #[test]
    fn test_client_creation() {
        let client = UniFiClient::new("https://192.168.1.1", "default");
        assert!(client.is_ok());
        let client = client.unwrap();
        assert!(!client.is_authenticated());
        assert_eq!(client.layout(), ApiLayout::Classic);
    }

    #[test]
    fn test_client_insecure() {
        let client = UniFiClient::new_insecure("https://192.168.1.1:443", "default");
        assert!(client.is_ok());
    }

    #[test]
    fn test_connect_builds_both_modes() {
        // Secure (validation on) is the default path; insecure is opt-in.
        assert!(UniFiClient::connect("https://192.168.1.1", "default", false).is_ok());
        assert!(UniFiClient::connect("https://192.168.1.1", "default", true).is_ok());
    }

    #[test]
    fn test_base_url_trailing_slash() {
        let client = UniFiClient::new("https://unifi.local/", "default").unwrap();
        assert_eq!(client.base_url, "https://unifi.local");
    }

    #[test]
    fn test_api_layout_prefix_and_login_path() {
        assert_eq!(ApiLayout::Classic.api_prefix(), "");
        assert_eq!(ApiLayout::Classic.login_path(), "/api/login");
        assert_eq!(ApiLayout::UniFiOs.api_prefix(), "/proxy/network");
        assert_eq!(ApiLayout::UniFiOs.login_path(), "/api/auth/login");
    }

    #[test]
    fn test_api_url_classic() {
        let client = UniFiClient::new("https://unifi.local:8443/", "office").unwrap();
        assert_eq!(client.login_url(), "https://unifi.local:8443/api/login");
        assert_eq!(
            client.api_url("/api/self/sites"),
            "https://unifi.local:8443/api/self/sites"
        );
        assert_eq!(
            client.api_url(&client.site_path("rest/wlanconf")),
            "https://unifi.local:8443/api/s/office/rest/wlanconf"
        );
        assert_eq!(
            client.api_url(&client.site_path("stat/ips/event")),
            "https://unifi.local:8443/api/s/office/stat/ips/event"
        );
    }

    #[test]
    fn test_api_url_unifi_os() {
        let client = UniFiClient::new("https://192.168.1.1", "default")
            .unwrap()
            .with_layout(ApiLayout::UniFiOs);
        assert_eq!(client.layout(), ApiLayout::UniFiOs);
        assert_eq!(client.login_url(), "https://192.168.1.1/api/auth/login");
        assert_eq!(
            client.api_url("/api/self/sites"),
            "https://192.168.1.1/proxy/network/api/self/sites"
        );
        assert_eq!(
            client.api_url(&client.site_path("rest/wlanconf")),
            "https://192.168.1.1/proxy/network/api/s/default/rest/wlanconf"
        );
        assert_eq!(
            client.api_url(&client.site_path("stat/ips/event")),
            "https://192.168.1.1/proxy/network/api/s/default/stat/ips/event"
        );
    }

    #[test]
    fn test_path_not_served() {
        assert!(path_not_served(StatusCode::NOT_FOUND));
        assert!(path_not_served(StatusCode::UNAUTHORIZED));
        assert!(!path_not_served(StatusCode::OK));
        assert!(!path_not_served(StatusCode::BAD_REQUEST));
        assert!(!path_not_served(StatusCode::FORBIDDEN));
    }

    #[test]
    fn test_csrf_from_prefers_updated_header() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert_eq!(csrf_from(&headers), None);
        headers.insert("x-csrf-token", "old".parse().unwrap());
        assert_eq!(csrf_from(&headers).as_deref(), Some("old"));
        headers.insert("x-updated-csrf-token", "new".parse().unwrap());
        assert_eq!(csrf_from(&headers).as_deref(), Some("new"));
    }

    #[test]
    fn test_api_response_deserialization() {
        let json = r#"{"meta":{"rc":"ok"},"data":[{"_id":"abc","name":"default","desc":null}]}"#;
        let resp: ApiResponse<Site> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.meta.rc, "ok");
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].name, "default");
    }

    #[test]
    fn test_api_response_error() {
        let json = r#"{"meta":{"rc":"error","msg":"api.err.LoginRequired"},"data":[]}"#;
        let resp: ApiResponse<Site> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.meta.rc, "error");
        assert_eq!(resp.meta.msg.as_deref(), Some("api.err.LoginRequired"));
    }

    #[tokio::test]
    async fn login_classic_keeps_classic_layout() {
        let base = spawn_server(|method, path, _| match (method, path) {
            ("POST", "/api/login") => http_response(200, "x-csrf-token: c1\r\n", EMPTY_OK),
            _ => http_response(404, "", "{}"),
        })
        .await;
        let mut client = UniFiClient::new(&base, "default").unwrap();
        client.login("admin", "pw").await.unwrap();
        assert!(client.is_authenticated());
        assert_eq!(client.layout(), ApiLayout::Classic);
        assert_eq!(client.csrf_token.as_deref(), Some("c1"));
    }

    #[tokio::test]
    async fn login_falls_back_to_unifi_os_on_404() {
        let base = spawn_server(|method, path, _| match (method, path) {
            ("POST", "/api/login") => http_response(404, "", "{}"),
            ("POST", "/api/auth/login") => http_response(200, "x-updated-csrf-token: c2\r\n", "{}"),
            _ => http_response(500, "", "{}"),
        })
        .await;
        let mut client = UniFiClient::new(&base, "default").unwrap();
        client.login("admin", "pw").await.unwrap();
        assert!(client.is_authenticated());
        assert_eq!(client.layout(), ApiLayout::UniFiOs);
        assert_eq!(client.csrf_token.as_deref(), Some("c2"));
    }

    #[tokio::test]
    async fn login_bad_credentials_on_classic_does_not_switch_layout() {
        let base = spawn_server(|method, path, _| match (method, path) {
            ("POST", "/api/login") => http_response(
                400,
                "",
                r#"{"meta":{"rc":"error","msg":"api.err.Invalid"},"data":[]}"#,
            ),
            _ => http_response(404, "", "{}"),
        })
        .await;
        let mut client = UniFiClient::new(&base, "default").unwrap();
        let err = client
            .login("admin", "wrong")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("400"), "{err}");
        assert!(!client.is_authenticated());
        assert_eq!(client.layout(), ApiLayout::Classic);
    }

    #[tokio::test]
    async fn login_token_unifi_os_sends_api_key_and_prefixes_paths() {
        let base = spawn_server(|method, path, head| {
            let head = head.to_ascii_lowercase();
            let has_key = head.contains("x-api-key: k1");
            let has_bearer = head.contains("authorization: bearer k1");
            match (method, path) {
                ("GET", "/api/self/sites") => http_response(401, "", "{}"),
                ("GET", "/proxy/network/api/self/sites") if has_key && has_bearer => {
                    http_response(200, "", EMPTY_OK)
                }
                ("GET", "/proxy/network/api/s/default/rest/wlanconf")
                | ("POST", "/proxy/network/api/s/default/stat/ips/event")
                    if has_key =>
                {
                    http_response(200, "", EMPTY_OK)
                }
                _ => http_response(403, "", "{}"),
            }
        })
        .await;
        let mut client = UniFiClient::new(&base, "default").unwrap();
        client.login_token("k1").await.unwrap();
        assert!(client.is_authenticated());
        assert_eq!(client.layout(), ApiLayout::UniFiOs);
        assert!(client.get_wlans().await.unwrap().is_empty());
        assert!(client.get_ids_events(5).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn login_token_classic_omits_api_key() {
        let base = spawn_server(|method, path, head| {
            if head.to_ascii_lowercase().contains("x-api-key") {
                return http_response(500, "", "{}");
            }
            match (method, path) {
                ("GET", "/api/self/sites" | "/api/s/default/rest/wlanconf") => {
                    http_response(200, "", EMPTY_OK)
                }
                _ => http_response(404, "", "{}"),
            }
        })
        .await;
        let mut client = UniFiClient::new(&base, "default").unwrap();
        client.login_token("k1").await.unwrap();
        assert_eq!(client.layout(), ApiLayout::Classic);
        assert!(client.get_wlans().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn login_token_invalid_reports_both_statuses() {
        let base = spawn_server(|_, _, _| http_response(401, "", "{}")).await;
        let mut client = UniFiClient::new(&base, "default").unwrap();
        let err = client.login_token("bad").await.unwrap_err().to_string();
        assert!(err.contains("401") && err.contains("classic: 401"), "{err}");
        assert!(!client.is_authenticated());
        assert!(client.bearer_token.is_none());
    }

    const LOGIN_REQUIRED: &str =
        r#"{"meta":{"rc":"error","msg":"api.err.LoginRequired"},"data":[]}"#;
    const AUTH_REQUIRED: &str = r#"{"code":"AUTHENTICATION_REQUIRED","message":"Login required"}"#;
    const BASIC_AUTH_HTML: &str =
        "<html><head><title>401 Authorization Required</title></head><body>login</body></html>";

    #[tokio::test]
    async fn probe_uses_layout_prefix() {
        let base = spawn_server(|method, path, _| match (method, path) {
            ("GET", "/proxy/network/api/self/sites") => http_response(401, "", AUTH_REQUIRED),
            _ => http_response(200, "", "<html>"),
        })
        .await;
        let classic = UniFiClient::new(&base, "default").unwrap();
        assert!(!classic.probe().await);
        let os = UniFiClient::new(&base, "default")
            .unwrap()
            .with_layout(ApiLayout::UniFiOs);
        assert!(os.probe().await);
    }

    #[tokio::test]
    async fn probe_accepts_marker_on_401_and_200() {
        let base = spawn_server(|_, _, _| http_response(401, "", LOGIN_REQUIRED)).await;
        assert!(UniFiClient::new(&base, "default").unwrap().probe().await);
        let base = spawn_server(|_, _, _| http_response(200, "", AUTH_REQUIRED)).await;
        assert!(UniFiClient::new(&base, "default").unwrap().probe().await);
    }

    #[tokio::test]
    async fn probe_rejects_basic_auth_401_without_marker() {
        let base = spawn_server(|_, _, _| {
            http_response(
                401,
                "WWW-Authenticate: Basic realm=\"router\"\r\n",
                BASIC_AUTH_HTML,
            )
        })
        .await;
        assert!(!UniFiClient::new(&base, "default").unwrap().probe().await);
        let base = spawn_server(|_, _, _| http_response(401, "", "{}")).await;
        assert!(!UniFiClient::new(&base, "default").unwrap().probe().await);
    }

    #[tokio::test]
    async fn probe_does_not_follow_redirects() {
        let base = spawn_server(|_, path, _| {
            if path == "/login" {
                http_response(401, "", LOGIN_REQUIRED)
            } else {
                http_response(302, "Location: /login\r\n", "")
            }
        })
        .await;
        assert!(!UniFiClient::new(&base, "default").unwrap().probe().await);
    }

    #[tokio::test]
    async fn probe_reads_at_most_body_cap() {
        let beyond = format!("{}{LOGIN_REQUIRED}", "x".repeat(PROBE_BODY_MAX));
        let base = spawn_server(move |_, _, _| http_response(401, "", &beyond)).await;
        assert!(!UniFiClient::new(&base, "default").unwrap().probe().await);
        let within = format!("{}{LOGIN_REQUIRED}", "x".repeat(PROBE_BODY_MAX / 2));
        let base = spawn_server(move |_, _, _| http_response(401, "", &within)).await;
        assert!(UniFiClient::new(&base, "default").unwrap().probe().await);
    }
}
