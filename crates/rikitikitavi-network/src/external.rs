use anyhow::{Result, anyhow};
use std::net::IpAddr;
use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Public IP address; providers are tried in sequence, first success wins.
pub async fn get_public_ip() -> Result<IpAddr> {
    tracing::debug!("detecting public IP");

    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()?;

    let providers: &[&str] = &[
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];

    for &url in providers {
        match try_get_ip(&client, url).await {
            Ok(ip) => {
                tracing::info!(%ip, provider = url, "detected public IP");
                return Ok(ip);
            }
            Err(e) => {
                tracing::debug!(provider = url, error = %e, "provider failed, trying next");
            }
        }
    }

    Err(anyhow!("failed to detect public IP from any provider"))
}

/// Try to get the public IP from a single provider.
async fn try_get_ip(client: &reqwest::Client, url: &str) -> Result<IpAddr> {
    let response = client
        .get(url)
        .header("User-Agent", "rikitikitavi/0.1")
        .send()
        .await?
        .error_for_status()?;
    let body = response.text().await?;
    let ip: IpAddr = body.trim().parse()?;
    Ok(ip)
}

/// NAT type detection via STUN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    None,
    FullCone,
    RestrictedCone,
    PortRestricted,
    Symmetric,
    Unknown,
}

/// Detect NAT type via STUN. Not implemented; always returns `NatType::Unknown`.
#[allow(clippy::unused_async)]
pub async fn detect_nat_type() -> Result<NatType> {
    tracing::debug!("detecting NAT type (not yet implemented)");
    Ok(NatType::Unknown)
}
