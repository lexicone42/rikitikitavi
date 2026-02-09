use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// Credential hygiene scanner — default credential testing and anonymous access.
pub struct CredentialScanner;

#[async_trait]
impl Scanner for CredentialScanner {
    fn id(&self) -> &'static str {
        "credentials"
    }

    fn name(&self) -> &'static str {
        "Credential Hygiene"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running credential hygiene scan");
        let _ = ctx;
        // TODO: Default credential DB, anonymous SMB/FTP, rate-limited testing, audit logging
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        45
    }
}
