use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// Network discovery scanner — finds devices on the local network via ARP cache,
/// detects interfaces, gateway, and network topology.
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
        let mut findings = Vec::new();

        // Discover interfaces
        match rikitikitavi_network::list_interfaces() {
            Ok(interfaces) => {
                let active = interfaces
                    .iter()
                    .filter(|i| i.is_up && !i.is_loopback)
                    .count();
                tracing::info!(
                    total = interfaces.len(),
                    active,
                    "discovered network interfaces"
                );
            }
            Err(e) => {
                tracing::warn!("failed to list interfaces: {e}");
            }
        }

        // Check gateway
        match ctx.gateway {
            Some(gw) => {
                findings.push(
                    Finding::new(
                        "network",
                        "Default gateway detected",
                        &format!("Default gateway is at {gw}"),
                        Severity::Info,
                    )
                    .with_ip(gw),
                );
            }
            None => {
                findings.push(Finding::new(
                    "network",
                    "No default gateway detected",
                    "Could not determine the default gateway. Network scanning may be limited.",
                    Severity::Medium,
                ));
            }
        }

        // Report network CIDR
        if let Some(network) = &ctx.target_network {
            findings.push(Finding::new(
                "network",
                "Local network detected",
                &format!("Local network CIDR: {network}"),
                Severity::Info,
            ));
        }

        // Read ARP cache for device discovery
        let arp_entries = rikitikitavi_network::read_arp_cache().map_err(|e| {
            ScanError::ScannerFailed {
                scanner: "network".to_owned(),
                message: format!("failed to read ARP cache: {e}"),
            }
        })?;

        let device_count = arp_entries.len();
        tracing::info!(device_count, "devices found in ARP cache");

        if device_count == 0 {
            findings.push(Finding::new(
                "network",
                "No devices found in ARP cache",
                "The ARP cache is empty. Run the rikitikitavi-nethelper.sh script with \
                 sudo to populate it via ping sweep, then re-scan.",
                Severity::Info,
            ));
        } else {
            findings.push(Finding::new(
                "network",
                &format!("{device_count} devices discovered on the network"),
                &format!(
                    "Found {device_count} device(s) in the ARP cache. Each will be scanned \
                     for open ports and services."
                ),
                Severity::Info,
            ));
        }

        // Flag large device count
        if device_count > 30 {
            findings.push(
                Finding::new(
                    "network",
                    "Large number of devices on network",
                    &format!(
                        "Found {device_count} devices on the local network. A high device count \
                         may indicate an unsegmented flat network, increasing the attack surface."
                    ),
                    Severity::Low,
                )
                .with_cwe("CWE-1008")
                .with_references(vec![
                    "https://cwe.mitre.org/data/definitions/1008.html".to_owned(),
                ]),
            );
        }

        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        5
    }
}
