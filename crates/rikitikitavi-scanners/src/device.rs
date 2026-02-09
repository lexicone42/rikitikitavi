use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// Device fingerprinting scanner — identifies device types, OS, and known CVEs.
pub struct DeviceScanner;

#[async_trait]
impl Scanner for DeviceScanner {
    fn id(&self) -> &'static str {
        "device"
    }

    fn name(&self) -> &'static str {
        "Device Fingerprinting"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running device fingerprinting scan");
        let _ = ctx;
        // TODO: TCP/IP stack fingerprinting, HTTP banners, service versions, CVE cross-ref
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        60
    }
}
