use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// Authenticated services scanner — SMB shares, permissions, certificates, API endpoints.
pub struct ServicesScanner;

#[async_trait]
impl Scanner for ServicesScanner {
    fn id(&self) -> &'static str {
        "services"
    }

    fn name(&self) -> &'static str {
        "Authenticated Services"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[Perspective::Authenticated, Perspective::Privileged]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running authenticated services scan");
        let _ = ctx;
        // TODO: SMB share enumeration, permission analysis, cert validation, API discovery
        Ok(Vec::new())
    }

    fn estimated_duration_secs(&self) -> u64 {
        30
    }
}
