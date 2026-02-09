use anyhow::Result;
use std::path::Path;

/// Deploy rikitikitavi to a remote `UniFi` device via SSH.
pub async fn deploy_to_device(host: &str, binary_path: &Path, persistent: bool) -> Result<()> {
    tracing::info!(%host, ?binary_path, persistent, "deploying to UniFi device");
    // TODO: Implement SSH-based deployment
    // 1. SCP binary to /data/rikitikitavi/
    // 2. SCP config if needed
    // 3. If persistent, install on_boot.d script
    // 4. Set up cron job
    Err(anyhow::anyhow!("deployment not yet implemented"))
}

/// Check the status of a rikitikitavi installation on a remote `UniFi` device.
pub async fn check_status(host: &str) -> Result<InstallStatus> {
    tracing::info!(%host, "checking installation status");
    let _ = host;
    Ok(InstallStatus::NotInstalled)
}

/// Remove rikitikitavi from a `UniFi` device.
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
