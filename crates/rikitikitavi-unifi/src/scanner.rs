use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};
use rikitikitavi_scanners::Scanner;

/// UniFi-specific security scanner.
///
/// When running on a `UniFi` device or connected to a `UniFi` controller, this
/// scanner performs deep audits of controller settings, firewall rules, `WiFi`
/// configuration, threat management, and client security.
pub struct UniFiScanner;

#[async_trait]
impl Scanner for UniFiScanner {
    fn id(&self) -> &'static str {
        "unifi"
    }

    fn name(&self) -> &'static str {
        "UniFi Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running UniFi security scan");
        let _ = ctx;
        // TODO: Implement UniFi-specific scans:
        // - Controller config audit
        // - Firmware version checks
        // - Firewall rule analysis
        // - WiFi security settings
        // - Threat management (IDS/IPS)
        // - VLAN isolation verification
        // - Client anomaly detection
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        90
    }
}
