use anyhow::Result;
use reqwest::Client;

use crate::models::{
    AdoptedDevice, FirewallRule, IdsEvent, NetworkConfig, Site, UniFiClientInfo, WlanConfig,
};

/// `UniFi` Controller API client.
#[allow(dead_code)]
pub struct UniFiClient {
    base_url: String,
    client: Client,
    csrf_token: Option<String>,
    site: String,
    authenticated: bool,
}

impl UniFiClient {
    /// Create a new client for the given controller URL.
    pub fn new(base_url: &str, site: &str) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(false)
            .cookie_store(true)
            .build()?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client,
            csrf_token: None,
            site: site.to_owned(),
            authenticated: false,
        })
    }

    /// Create a client that accepts self-signed certificates.
    pub fn new_insecure(base_url: &str, site: &str) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .cookie_store(true)
            .build()?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client,
            csrf_token: None,
            site: site.to_owned(),
            authenticated: false,
        })
    }

    /// Authenticate with username/password.
    pub async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        tracing::info!(base_url = %self.base_url, "authenticating with UniFi controller");
        let _ = (username, password);
        // TODO: POST /api/login with { username, password }
        // Store CSRF token from response headers
        self.authenticated = true;
        Ok(())
    }

    /// Authenticate with API token.
    pub async fn login_token(&mut self, token: &str) -> Result<()> {
        tracing::info!(base_url = %self.base_url, "authenticating with API token");
        let _ = token;
        // TODO: Set authorization header
        self.authenticated = true;
        Ok(())
    }

    /// Get all sites.
    pub async fn get_sites(&self) -> Result<Vec<Site>> {
        tracing::debug!("fetching sites");
        // TODO: GET /api/self/sites
        Ok(Vec::new())
    }

    /// Get all adopted devices for the current site.
    pub async fn get_devices(&self) -> Result<Vec<AdoptedDevice>> {
        tracing::debug!(site = %self.site, "fetching devices");
        // TODO: GET /api/s/{site}/stat/device
        Ok(Vec::new())
    }

    /// Get all active clients.
    pub async fn get_clients(&self, _historical: bool) -> Result<Vec<UniFiClientInfo>> {
        tracing::debug!(site = %self.site, "fetching clients");
        // TODO: GET /api/s/{site}/stat/sta or /api/s/{site}/rest/user
        Ok(Vec::new())
    }

    /// Get network configurations.
    pub async fn get_networks(&self) -> Result<Vec<NetworkConfig>> {
        tracing::debug!(site = %self.site, "fetching networks");
        // TODO: GET /api/s/{site}/rest/networkconf
        Ok(Vec::new())
    }

    /// Get WLAN configurations.
    pub async fn get_wlans(&self) -> Result<Vec<WlanConfig>> {
        tracing::debug!(site = %self.site, "fetching WLANs");
        // TODO: GET /api/s/{site}/rest/wlanconf
        Ok(Vec::new())
    }

    /// Get firewall rules.
    pub async fn get_firewall_rules(&self) -> Result<Vec<FirewallRule>> {
        tracing::debug!(site = %self.site, "fetching firewall rules");
        // TODO: GET /api/s/{site}/rest/firewallrule
        Ok(Vec::new())
    }

    /// Get IDS/IPS events.
    pub async fn get_ids_events(&self, _limit: u32) -> Result<Vec<IdsEvent>> {
        tracing::debug!(site = %self.site, "fetching IDS events");
        // TODO: GET /api/s/{site}/stat/ips/event
        Ok(Vec::new())
    }

    /// Check if authenticated.
    pub const fn is_authenticated(&self) -> bool {
        self.authenticated
    }
}
