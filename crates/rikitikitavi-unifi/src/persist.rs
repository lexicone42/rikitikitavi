use anyhow::Result;
use std::path::Path;

const ON_BOOT_DIR: &str = "/data/on_boot.d";
#[allow(dead_code)]
const INSTALL_DIR: &str = "/data/rikitikitavi";
const BOOT_SCRIPT_NAME: &str = "10-rikitikitavi.sh";

/// Install the `/data/on_boot.d` script (`UniFi` OS 2.x+; `/data` survives firmware upgrades).
/// Not implemented: the script is not written.
pub fn install_persistence() -> Result<()> {
    tracing::info!("installing firmware-update persistence");

    let boot_dir = Path::new(ON_BOOT_DIR);
    if !boot_dir.exists() {
        return Err(anyhow::anyhow!(
            "{ON_BOOT_DIR} does not exist — is this a UniFi OS 2.x+ device?"
        ));
    }

    let script_path = boot_dir.join(BOOT_SCRIPT_NAME);
    let _ = script_path;

    Ok(())
}

/// Check if persistence is installed.
pub fn is_persistence_installed() -> bool {
    Path::new(ON_BOOT_DIR).join(BOOT_SCRIPT_NAME).exists()
}

/// Remove persistence scripts.
pub fn remove_persistence() -> Result<()> {
    let script = Path::new(ON_BOOT_DIR).join(BOOT_SCRIPT_NAME);
    if script.exists() {
        std::fs::remove_file(&script)?;
        tracing::info!("removed persistence script");
    }
    Ok(())
}
