use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// Router security scanner — tests for default credentials, `UPnP`, remote
/// management, and firmware vulnerabilities.
pub struct RouterScanner;

#[async_trait]
impl Scanner for RouterScanner {
    fn id(&self) -> &'static str {
        "router"
    }

    fn name(&self) -> &'static str {
        "Router Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running router security scan");
        let _ = ctx;
        // TODO: Default credential testing, admin port detection, UPnP, remote management
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        45
    }
}
