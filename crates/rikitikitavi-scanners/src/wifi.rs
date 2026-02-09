use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// `WiFi` security scanner — encryption type, WPS, hidden networks, client isolation.
pub struct WifiScanner;

#[async_trait]
impl Scanner for WifiScanner {
    fn id(&self) -> &'static str {
        "wifi"
    }

    fn name(&self) -> &'static str {
        "WiFi Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Neighbor,
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running WiFi security scan");
        let _ = ctx;
        // TODO: Platform WiFi APIs, encryption detection, WPS, hidden networks, signal mapping
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        30
    }
}
