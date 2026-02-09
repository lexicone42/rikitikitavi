use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// External exposure scanner — public IP, Shodan/Censys, port forwarding, NAT.
pub struct ExposureScanner;

#[async_trait]
impl Scanner for ExposureScanner {
    fn id(&self) -> &'static str {
        "exposure"
    }

    fn name(&self) -> &'static str {
        "External Exposure"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running external exposure scan");
        let _ = ctx;
        // TODO: Public IP detection, Shodan API, Censys API, port forward detection, STUN NAT
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        15
    }
}
