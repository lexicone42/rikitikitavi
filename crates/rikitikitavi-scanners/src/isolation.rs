use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// Network isolation scanner — VLAN segmentation, cross-network routing, firewall inference.
pub struct IsolationScanner;

#[async_trait]
impl Scanner for IsolationScanner {
    fn id(&self) -> &'static str {
        "isolation"
    }

    fn name(&self) -> &'static str {
        "Network Isolation"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[Perspective::Authenticated, Perspective::Privileged]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running network isolation scan");
        let _ = ctx;
        // TODO: VLAN segmentation, cross-network routing, firewall inference, IoT isolation
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        40
    }
}
