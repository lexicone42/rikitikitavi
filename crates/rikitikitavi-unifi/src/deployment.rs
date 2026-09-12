use anyhow::Result;
use std::path::Path;

/// Deploy to a remote `UniFi` device via SSH. Not implemented; always returns `Err`.
#[allow(clippy::unused_async)]
pub async fn deploy_to_device(host: &str, binary_path: &Path, persistent: bool) -> Result<()> {
    tracing::info!(%host, ?binary_path, persistent, "deploying to UniFi device");
    Err(anyhow::anyhow!("deployment not yet implemented"))
}

/// Installation status on a remote device. Not implemented; always returns `NotInstalled`.
#[allow(clippy::unused_async)]
pub async fn check_status(host: &str) -> Result<InstallStatus> {
    tracing::info!(%host, "checking installation status");
    let _ = host;
    Ok(InstallStatus::NotInstalled)
}

/// Uninstall from a remote device. Not implemented; always returns `Err`.
#[allow(clippy::unused_async)]
pub async fn uninstall(host: &str) -> Result<()> {
    tracing::info!(%host, "uninstalling from UniFi device");
    let _ = host;
    Err(anyhow::anyhow!("uninstall not yet implemented"))
}

/// Installation status on a remote device.
#[derive(Debug, Clone)]
pub enum InstallStatus {
    NotInstalled,
    Installed { version: String, persistent: bool },
    Running { version: String, pid: u32 },
}
