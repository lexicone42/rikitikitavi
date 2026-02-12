use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Deserialize;

use crate::models::{
    AdoptedDevice, FirewallRule, IdsEvent, NetworkConfig, Site, UniFiClientInfo, WlanConfig,
};

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

/// `UniFi` Controller API client.
pub struct UniFiClient {
    base_url: String,
    client: Client,
    csrf_token: Option<String>,
    site: String,
    authenticated: bool,
    /// If set, use Bearer token auth instead of session cookies.
    bearer_token: Option<String>,
}

impl UniFiClient {
    /// Create a new client for the given controller URL.
    pub fn new(base_url: &str, site: &str) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(false)
            .cookie_store(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client,
            csrf_token: None,
            site: site.to_owned(),
            authenticated: false,
            bearer_token: None,
        })
    }

    /// Create a client that accepts self-signed certificates.
    pub fn new_insecure(base_url: &str, site: &str) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .cookie_store(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client,
            csrf_token: None,
            site: site.to_owned(),
            authenticated: false,
            bearer_token: None,
        })
    }

    /// Authenticate with username/password.
    pub async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        tracing::info!(base_url = %self.base_url, "authenticating with UniFi controller");

        let url = format!("{}/api/login", self.base_url);
        let body = serde_json::json!({
            "username": username,
            "password": password,
        });

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("failed to connect to UniFi controller")?;

        if !resp.status().is_success() {
            bail!(
                "UniFi login failed with status {} — check credentials",
                resp.status()
            );
        }

        // Extract CSRF token from response headers
        if let Some(csrf) = resp.headers().get("x-csrf-token") {
            self.csrf_token = csrf.to_str().ok().map(ToOwned::to_owned);
        }

        self.authenticated = true;
        tracing::info!("UniFi authentication successful");
        Ok(())
    }

    /// Authenticate with API token (`UniFi` OS 2.x+).
    pub async fn login_token(&mut self, token: &str) -> Result<()> {
        tracing::info!(base_url = %self.base_url, "authenticating with API token");

        self.bearer_token = Some(token.to_owned());

        // Verify the token works by fetching sites
        let url = format!("{}/api/self/sites", self.base_url);
        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .context("failed to verify API token")?;

        if !resp.status().is_success() {
            self.bearer_token = None;
            bail!(
                "API token verification failed with status {} — check token",
                resp.status()
            );
        }

        self.authenticated = true;
        tracing::info!("UniFi token authentication successful");
        Ok(())
    }

    /// Build an authenticated GET request.
    fn get_request(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.client.get(url);
        if let Some(token) = &self.bearer_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(csrf) = &self.csrf_token {
            req = req.header("x-csrf-token", csrf.as_str());
        }
        req
    }

    /// Execute an API GET and deserialize the envelope.
    async fn api_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<Vec<T>> {
        let url = format!("{}{path}", self.base_url);
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
        self.api_get(&format!("/api/s/{}/stat/device", self.site))
            .await
    }

    /// Get all active clients.
    pub async fn get_clients(&self, historical: bool) -> Result<Vec<UniFiClientInfo>> {
        tracing::debug!(site = %self.site, historical, "fetching clients");
        let endpoint = if historical {
            format!("/api/s/{}/rest/user", self.site)
        } else {
            format!("/api/s/{}/stat/sta", self.site)
        };
        self.api_get(&endpoint).await
    }

    /// Get network configurations.
    pub async fn get_networks(&self) -> Result<Vec<NetworkConfig>> {
        tracing::debug!(site = %self.site, "fetching networks");
        self.api_get(&format!("/api/s/{}/rest/networkconf", self.site))
            .await
    }

    /// Get WLAN configurations.
    pub async fn get_wlans(&self) -> Result<Vec<WlanConfig>> {
        tracing::debug!(site = %self.site, "fetching WLANs");
        self.api_get(&format!("/api/s/{}/rest/wlanconf", self.site))
            .await
    }

    /// Get firewall rules.
    pub async fn get_firewall_rules(&self) -> Result<Vec<FirewallRule>> {
        tracing::debug!(site = %self.site, "fetching firewall rules");
        self.api_get(&format!("/api/s/{}/rest/firewallrule", self.site))
            .await
    }

    /// Get IDS/IPS events.
    pub async fn get_ids_events(&self, limit: u32) -> Result<Vec<IdsEvent>> {
        tracing::debug!(site = %self.site, limit, "fetching IDS events");
        // The IDS endpoint uses a POST with query parameters
        let url = format!("{}/api/s/{}/stat/ips/event", self.base_url, self.site);
        let body = serde_json::json!({
            "_limit": limit,
            "_sort": "-time",
        });

        let mut req = self.client.post(&url).json(&body);
        if let Some(token) = &self.bearer_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(csrf) = &self.csrf_token {
            req = req.header("x-csrf-token", csrf.as_str());
        }

        let resp = req.send().await.context("failed to fetch IDS events")?;

        if !resp.status().is_success() {
            bail!("IDS events request failed: {}", resp.status());
        }

        let envelope: ApiResponse<IdsEvent> = resp.json().await?;
        if envelope.meta.rc != "ok" {
            bail!("IDS events API returned rc={}", envelope.meta.rc);
        }

        Ok(envelope.data)
    }

    /// Check if authenticated.
    pub const fn is_authenticated(&self) -> bool {
        self.authenticated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = UniFiClient::new("https://192.168.1.1", "default");
        assert!(client.is_ok());
        let client = client.unwrap();
        assert!(!client.is_authenticated());
    }

    #[test]
    fn test_client_insecure() {
        let client = UniFiClient::new_insecure("https://192.168.1.1:443", "default");
        assert!(client.is_ok());
    }

    #[test]
    fn test_base_url_trailing_slash() {
        let client = UniFiClient::new("https://unifi.local/", "default").unwrap();
        assert_eq!(client.base_url, "https://unifi.local");
    }

    #[test]
    fn test_api_response_deserialization() {
        let json = r#"{"meta":{"rc":"ok"},"data":[{"id":"abc","name":"default","desc":null}]}"#;
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
}
