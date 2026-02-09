use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// Network discovery scanner — finds devices on the local network via ARP,
/// mDNS, SSDP, and `NetBIOS`.
pub struct NetworkScanner;

#[async_trait]
impl Scanner for NetworkScanner {
    fn id(&self) -> &'static str {
        "network"
    }

    fn name(&self) -> &'static str {
        "Network Discovery"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running network discovery scan");
        let _ = ctx;
        // TODO: ARP scan, mDNS discovery, SSDP/UPnP, NetBIOS, OUI lookup
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        30
    }
}
