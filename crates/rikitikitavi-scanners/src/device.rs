use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, ScanContext};

use crate::Scanner;
use crate::oui_db::ieee_oui_lookup;

/// Device fingerprinting scanner — identifies device types via MAC OUI lookup
/// and open port profiling.
pub struct DeviceScanner;

/// Classify device type from vendor name (human-readable label for descriptions).
///
/// Vendor names come from the IEEE OUI database (normalized by the generator).
fn classify_by_vendor(vendor: &str) -> &'static str {
    match vendor {
        "Synology" => "NAS",
        "Sonos" | "D&M" | "Roku" => "Media player",
        "Sony" | "Nintendo" => "Game console",
        "Ring" => "Camera/doorbell",
        "Signify" | "Philips Lighting" | "Espressif" | "AI-Link" | "TI" => "IoT device",
        "Raspberry Pi" => "Single-board computer",
        "HP" => "Printer (likely)",
        "Ubiquiti" | "TP-Link" | "Netgear" | "D-Link" | "Belkin" => "Network equipment",
        "Amazon" => "Smart speaker/display",
        "Xiaomi" => "Smart home device",
        "Arris" | "CommScope" => "Cable modem/router",
        "Apple" => "Apple device",
        "Samsung" => "Samsung device",
        "Google" => "Google/Nest device",
        "LG" => "LG device",
        "Intel" | "Dell" | "Lenovo" | "Asus" => "PC/workstation",
        "Motorola" => "Mobile device",
        _ => "Unknown",
    }
}

/// Map a vendor name to a structured [`DeviceType`] for enrichment.
///
/// Only classifies when the mapping is unambiguous for a home network context.
/// Vendors that make diverse product lines (routers, phones, PCs) return
/// [`DeviceType::Unknown`] and rely on mDNS/UPnP for accurate classification.
const fn vendor_to_device_type(vendor: &str) -> DeviceType {
    match vendor.as_bytes() {
        b"Synology" => DeviceType::Nas,
        b"Sonos" | b"Roku" | b"D&M" => DeviceType::MediaPlayer,
        b"Sony" | b"Nintendo" => DeviceType::GameConsole,
        b"Ring" => DeviceType::Camera,
        b"Signify" | b"Philips Lighting" | b"Espressif" | b"AI-Link" | b"TI" | b"Amazon" => {
            DeviceType::IoT
        }
        b"HP" => DeviceType::Printer,
        b"Raspberry Pi" => DeviceType::Server,
        b"Ubiquiti" => DeviceType::Switch,
        b"Xiaomi" => DeviceType::Phone,
        _ => DeviceType::Unknown,
    }
}

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
        let mut findings = Vec::new();

        let arp_entries =
            rikitikitavi_network::read_arp_cache().map_err(|e| ScanError::ScannerFailed {
                scanner: "device".to_owned(),
                message: format!("failed to read ARP cache: {e}"),
            })?;

        let entries: Vec<_> = ctx.target_network.as_ref().map_or_else(
            || arp_entries.clone(),
            |network| {
                arp_entries
                    .iter()
                    .filter(|e| network.contains(e.ip))
                    .cloned()
                    .collect()
            },
        );

        let mut identified = 0u32;
        let mut unidentified = 0u32;

        for entry in &entries {
            let vendor = ieee_oui_lookup(&entry.mac);

            if let Some(vendor_name) = vendor {
                identified += 1;
                let device_class = classify_by_vendor(vendor_name);
                let hint = DeviceHint::new()
                    .with_vendor(vendor_name)
                    .with_device_type(vendor_to_device_type(vendor_name));
                findings.push(
                    Finding::new(
                        "device",
                        &format!("{vendor_name} device at {}", entry.ip),
                        &format!(
                            "MAC {mac} belongs to {vendor_name}. Likely device type: {device_class}.",
                            mac = entry.mac
                        ),
                        Severity::Info,
                    )
                    .with_ip(entry.ip)
                    .with_mac(&entry.mac)
                    .with_device_hint(hint),
                );
            } else {
                unidentified += 1;
            }
        }

        if unidentified > 0 {
            findings.push(Finding::new(
                "device",
                &format!("{unidentified} unidentified device(s) on network"),
                &format!(
                    "{unidentified} device(s) have MAC addresses from unknown vendors. \
                     These could be less common IoT devices, VMs with randomized MACs, \
                     or devices with privacy-focused MAC randomization."
                ),
                Severity::Low,
            ));
        }

        findings.push(Finding::new(
            "device",
            &format!(
                "Device fingerprinting summary: {identified} identified, {unidentified} unknown"
            ),
            &format!(
                "Of {} devices on the network, {identified} were identified by MAC vendor \
                 and {unidentified} remain unidentified.",
                entries.len()
            ),
            Severity::Info,
        ));

        tracing::info!(
            identified,
            unidentified,
            total = entries.len(),
            "device fingerprinting complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ieee_lookup_apple() {
        assert_eq!(ieee_oui_lookup("a4:83:e7:1a:2b:3c"), Some("Apple"));
    }

    #[test]
    fn test_ieee_lookup_ubiquiti() {
        assert_eq!(ieee_oui_lookup("68:d7:9a:ab:cd:ef"), Some("Ubiquiti"));
    }

    #[test]
    fn test_ieee_lookup_unknown() {
        assert_eq!(ieee_oui_lookup("ff:ff:ff:00:00:00"), None);
    }

    #[test]
    fn test_ieee_lookup_case_insensitive() {
        assert_eq!(ieee_oui_lookup("A4:83:E7:1A:2B:3C"), Some("Apple"));
    }

    #[test]
    fn test_classify_by_vendor() {
        assert_eq!(classify_by_vendor("Synology"), "NAS");
        assert_eq!(classify_by_vendor("Sonos"), "Media player");
        assert_eq!(classify_by_vendor("D&M"), "Media player");
        assert_eq!(classify_by_vendor("Ring"), "Camera/doorbell");
        assert_eq!(classify_by_vendor("Amazon"), "Smart speaker/display");
        assert_eq!(classify_by_vendor("Sony"), "Game console");
        assert_eq!(classify_by_vendor("Apple"), "Apple device");
        assert_eq!(classify_by_vendor("HP"), "Printer (likely)");
        assert_eq!(classify_by_vendor("Ubiquiti"), "Network equipment");
        assert_eq!(classify_by_vendor("Arris"), "Cable modem/router");
        assert_eq!(classify_by_vendor("Signify"), "IoT device");
        assert_eq!(classify_by_vendor("Philips Lighting"), "IoT device");
    }

    #[test]
    fn test_vendor_to_device_type() {
        assert_eq!(vendor_to_device_type("Synology"), DeviceType::Nas);
        assert_eq!(vendor_to_device_type("Sonos"), DeviceType::MediaPlayer);
        assert_eq!(vendor_to_device_type("Roku"), DeviceType::MediaPlayer);
        assert_eq!(vendor_to_device_type("D&M"), DeviceType::MediaPlayer);
        assert_eq!(vendor_to_device_type("Ring"), DeviceType::Camera);
        assert_eq!(vendor_to_device_type("Signify"), DeviceType::IoT);
        assert_eq!(vendor_to_device_type("Philips Lighting"), DeviceType::IoT);
        assert_eq!(vendor_to_device_type("Espressif"), DeviceType::IoT);
        assert_eq!(vendor_to_device_type("AI-Link"), DeviceType::IoT);
        assert_eq!(vendor_to_device_type("Amazon"), DeviceType::IoT);
        assert_eq!(vendor_to_device_type("TI"), DeviceType::IoT);
        assert_eq!(vendor_to_device_type("HP"), DeviceType::Printer);
        assert_eq!(vendor_to_device_type("Raspberry Pi"), DeviceType::Server);
        assert_eq!(vendor_to_device_type("Ubiquiti"), DeviceType::Switch);
        assert_eq!(vendor_to_device_type("Sony"), DeviceType::GameConsole);
        assert_eq!(vendor_to_device_type("Nintendo"), DeviceType::GameConsole);
        assert_eq!(vendor_to_device_type("Xiaomi"), DeviceType::Phone);
        // Multi-purpose vendors return Unknown
        assert_eq!(vendor_to_device_type("Apple"), DeviceType::Unknown);
        assert_eq!(vendor_to_device_type("Samsung"), DeviceType::Unknown);
        assert_eq!(vendor_to_device_type("Cisco"), DeviceType::Unknown);
    }
}
