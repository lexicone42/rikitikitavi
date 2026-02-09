use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// Port scanner — async TCP connect scanning with service identification.
pub struct PortScanner;

#[async_trait]
impl Scanner for PortScanner {
    fn id(&self) -> &'static str {
        "ports"
    }

    fn name(&self) -> &'static str {
        "Port Scanner"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running port scan");
        let _ = ctx;
        // TODO: Async TCP SYN scanning, service ID, banner grabbing, rate limiting
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        120
    }
}
