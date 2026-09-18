use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError};
use rikitikitavi_models::{Finding, ScanContext};

/// Interface implemented by every scanner: declares supported perspectives and
/// produces [`Finding`]s.
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

    /// Run the scan, appending findings to `sink` as they are produced.
    ///
    /// The default forwards to [`scan`](Scanner::scan) and appends everything at
    /// the end, so a per-scanner timeout that fires mid-run keeps nothing. A
    /// scanner whose work is incremental (a host at a time, say) overrides this
    /// and pushes into `sink` as it goes; the runner then keeps whatever was
    /// collected before the deadline instead of discarding the whole result.
    async fn scan_collecting(
        &self,
        ctx: &ScanContext,
        sink: &mut Vec<Finding>,
    ) -> Result<(), ScanError> {
        sink.extend(self.scan(ctx).await?);
        Ok(())
    }

    /// Estimated time to complete (seconds), used for progress reporting.
    fn estimated_duration_secs(&self) -> u64 {
        30
    }

    /// Whether this scanner requires root/admin privileges.
    fn requires_privileges(&self) -> bool {
        false
    }

    /// Ports that gate this scanner in Phase 2. Empty (default) = always run;
    /// otherwise run only if one of these ports was found open in Phase 1.
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
                // Phase 1 (discovery)
                Box::new(crate::network::NetworkScanner),
                Box::new(crate::ports::PortScanner),
                Box::new(crate::device::DeviceScanner),
                // Phase 2 (deep analysis)
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
                Box::new(crate::mqtt::MqttScanner),
                Box::new(crate::mgmt_plane::MgmtPlaneScanner),
                Box::new(crate::printers::PrinterScanner),
                Box::new(crate::tr069::Tr069Scanner),
                Box::new(crate::snmp::SnmpScanner),
                Box::new(crate::rtsp::RtspScanner),
                Box::new(crate::upnp_igd::UpnpIgdScanner),
                Box::new(crate::cast::CastScanner),
                Box::new(crate::kasa::KasaScanner),
                Box::new(crate::modbus::ModbusScanner),
                Box::new(crate::papercut::PaperCutScanner),
                Box::new(crate::sadp::SadpScanner),
                Box::new(crate::tuya::TuyaScanner),
                Box::new(crate::nuclei_detect::NucleiDetectScanner),
                Box::new(crate::knx::KnxScanner),
                Box::new(crate::media_server::MediaServerScanner),
                Box::new(crate::print3d::Print3dScanner),
                Box::new(crate::ddwrt_upnp::DdwrtUpnpScanner),
                Box::new(crate::lan_client_exposure::LanClientExposureScanner),
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
