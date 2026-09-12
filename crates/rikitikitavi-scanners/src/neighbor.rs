use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// Neighbor/proximity scanner. Stub: returns no findings.
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
        // TODO: passive WiFi capture, WPS, deauth, Bluetooth
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        60
    }

    fn requires_privileges(&self) -> bool {
        true
    }
}
