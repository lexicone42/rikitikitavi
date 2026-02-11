use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

/// Scanner module trait — all scanners implement this.
///
/// Each scanner represents one category of security checks (e.g., port scanning,
/// DNS security, `WiFi` security). Scanners declare which attacker perspectives
/// they support and produce a list of [`Finding`]s when run.
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Unique identifier for this scanner.
    fn id(&self) -> &'static str;

    /// Human-readable name.
    fn name(&self) -> &'static str;

    /// Which perspectives this scanner supports.
    fn supported_perspectives(&self) -> &[Perspective];

    /// Run the scan and return findings.
    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError>;

    /// Estimated time to complete (seconds), used for progress reporting.
    fn estimated_duration_secs(&self) -> u64 {
        30
    }

    /// Whether this scanner requires root/admin privileges.
    fn requires_privileges(&self) -> bool {
        false
    }

    /// Ports this scanner is relevant for. An empty slice (default) means the
    /// scanner is always relevant regardless of which ports are open. A
    /// non-empty slice means the scanner should only run if at least one of
    /// these ports was discovered open during Phase 1.
    fn relevant_ports(&self) -> &[u16] {
        &[]
    }
}

/// Registry of all available scanners.
pub struct ScannerRegistry {
    scanners: Vec<Box<dyn Scanner>>,
}

impl ScannerRegistry {
    /// Create a registry with all built-in scanners.
    pub fn new() -> Self {
        Self {
            scanners: vec![
                // Phase 1: Discovery scanners
                Box::new(crate::network::NetworkScanner),
                Box::new(crate::ports::PortScanner),
                Box::new(crate::device::DeviceScanner),
                // Phase 2: Deep analysis scanners
                Box::new(crate::router::RouterScanner),
                Box::new(crate::dns::DnsScanner),
                Box::new(crate::wifi::WifiScanner),
                Box::new(crate::exposure::ExposureScanner),
                Box::new(crate::credentials::CredentialScanner),
                Box::new(crate::neighbor::NeighborScanner),
                Box::new(crate::isolation::IsolationScanner),
                Box::new(crate::services::ServicesScanner),
                Box::new(crate::ssl::SslScanner),
                Box::new(crate::mdns::MdnsScanner),
                Box::new(crate::http_audit::HttpAuditScanner),
                Box::new(crate::database::DatabaseScanner),
                Box::new(crate::smb::SmbScanner),
                Box::new(crate::arp::ArpScanner),
                Box::new(crate::dhcp::DhcpScanner),
            ],
        }
    }

    /// Return scanners applicable to the given perspective.
    pub fn for_perspective(&self, perspective: Perspective) -> Vec<&dyn Scanner> {
        self.scanners
            .iter()
            .filter(|s| s.supported_perspectives().contains(&perspective))
            .map(AsRef::as_ref)
            .collect()
    }

    /// Return all registered scanners.
    pub fn all(&self) -> Vec<&dyn Scanner> {
        self.scanners.iter().map(AsRef::as_ref).collect()
    }

    /// Get a scanner by ID.
    pub fn get(&self, id: &str) -> Option<&dyn Scanner> {
        self.scanners
            .iter()
            .find(|s| s.id() == id)
            .map(AsRef::as_ref)
    }
}

impl Default for ScannerRegistry {
    fn default() -> Self {
        Self::new()
    }
}
