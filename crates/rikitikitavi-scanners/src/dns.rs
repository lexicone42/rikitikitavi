use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// DNS security scanner — checks DNS configuration, DoH/DoT, DNSSEC, hijacking.
pub struct DnsScanner;

#[async_trait]
impl Scanner for DnsScanner {
    fn id(&self) -> &'static str {
        "dns"
    }

    fn name(&self) -> &'static str {
        "DNS Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running DNS security scan");
        let _ = ctx;
        // TODO: DNS server enumeration, DoH/DoT testing, leak detection, DNSSEC, hijacking
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        20
    }
}
