use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// Neighbor/proximity scanner — passive `WiFi` monitoring, probe requests, Bluetooth.
pub struct NeighborScanner;

#[async_trait]
impl Scanner for NeighborScanner {
    fn id(&self) -> &'static str {
        "neighbor"
    }

    fn name(&self) -> &'static str {
        "Neighbor/Proximity"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[Perspective::Neighbor]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running neighbor/proximity scan");
        let _ = ctx;
        // TODO: Passive WiFi monitoring, probe capture, WPS vuln, deauth testing, Bluetooth
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        60
    }

    fn requires_privileges(&self) -> bool {
        true
    }
}
