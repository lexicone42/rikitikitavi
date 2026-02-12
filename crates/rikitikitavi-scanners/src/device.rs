use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};

use crate::Scanner;

/// Device fingerprinting scanner — identifies device types via MAC OUI lookup
/// and open port profiling.
pub struct DeviceScanner;

/// Common home network OUI prefixes (first 3 bytes of MAC → vendor).
/// Covers the most common consumer electronics and networking brands.
const OUI_TABLE: &[(&str, &str)] = &[
    // Apple
    ("00:03:93", "Apple"),
    ("3c:22:fb", "Apple"),
    ("a4:83:e7", "Apple"),
    ("f0:18:98", "Apple"),
    ("d0:e1:40", "Apple"),
    ("ac:bc:32", "Apple"),
    ("f8:ff:c2", "Apple"),
    // Samsung
    ("00:07:ab", "Samsung"),
    ("00:12:fb", "Samsung"),
    ("34:23:ba", "Samsung"),
    ("50:01:d9", "Samsung"),
    ("8c:71:f8", "Samsung"),
    // Google / Nest
    ("f4:f5:d8", "Google"),
    ("30:fd:38", "Google"),
    ("54:60:09", "Google"),
    ("a4:77:33", "Google"),
    // Amazon (Echo, Ring, Fire)
    ("00:fc:8b", "Amazon"),
    ("0c:47:c9", "Amazon"),
    ("34:d2:70", "Amazon"),
    ("38:f7:3d", "Amazon"),
    ("44:65:0d", "Amazon"),
    ("fc:65:de", "Amazon"),
    // Ubiquiti
    ("04:18:d6", "Ubiquiti"),
    ("24:5a:4c", "Ubiquiti"),
    ("68:d7:9a", "Ubiquiti"),
    ("78:8a:20", "Ubiquiti"),
    ("b4:fb:e4", "Ubiquiti"),
    ("e0:63:da", "Ubiquiti"),
    ("f4:92:bf", "Ubiquiti"),
    // TP-Link
    ("14:cc:20", "TP-Link"),
    ("50:c7:bf", "TP-Link"),
    ("60:32:b1", "TP-Link"),
    ("98:da:c4", "TP-Link"),
    // Synology
    ("00:11:32", "Synology"),
    // Sonos
    ("00:0e:58", "Sonos"),
    ("34:7e:5c", "Sonos"),
    ("48:a6:b8", "Sonos"),
    ("54:2a:1b", "Sonos"),
    ("b8:e9:37", "Sonos"),
    // Roku
    ("b0:a7:37", "Roku"),
    ("d8:31:34", "Roku"),
    ("dc:3a:5e", "Roku"),
    // Ring
    ("18:b4:30", "Ring"),
    ("50:dc:e7", "Ring"),
    // Netgear
    ("00:14:6c", "Netgear"),
    ("20:e5:2a", "Netgear"),
    ("a4:2b:8c", "Netgear"),
    ("c0:ff:d4", "Netgear"),
    // Intel
    ("00:1b:21", "Intel"),
    ("3c:97:0e", "Intel"),
    ("a4:34:d9", "Intel"),
    // Raspberry Pi
    ("b8:27:eb", "Raspberry Pi"),
    ("dc:a6:32", "Raspberry Pi"),
    ("e4:5f:01", "Raspberry Pi"),
    // Espressif (ESP32, ESP8266 — IoT)
    ("24:0a:c4", "Espressif"),
    ("24:62:ab", "Espressif"),
    ("30:ae:a4", "Espressif"),
    // HP (printers)
    ("00:1e:0b", "HP"),
    ("3c:d9:2b", "HP"),
    ("68:b5:99", "HP"),
    // LG
    ("00:1c:62", "LG"),
    ("a8:16:b2", "LG"),
    // Microsoft / Xbox
    ("00:50:f2", "Microsoft"),
    ("7c:ed:8d", "Microsoft"),
    // Philips Hue
    ("00:17:88", "Philips Hue"),
];

/// Map a MAC address prefix (first 3 octets) to a vendor name.
fn oui_lookup(mac: &str) -> Option<&'static str> {
    let prefix = mac.get(..8)?.to_lowercase();
    OUI_TABLE
        .iter()
        .find(|(oui, _)| *oui == prefix)
        .map(|(_, vendor)| *vendor)
}

/// Classify device type based on which ports are open.
#[cfg(test)] // Will be used in scan() once port scan results are cross-referenced
fn classify_by_ports(open_ports: &[u16]) -> Option<&'static str> {
    // Check for specific port combinations
    if open_ports.contains(&9100) || open_ports.contains(&631) {
        return Some("Printer");
    }
    if open_ports.contains(&554) || open_ports.contains(&8554) {
        return Some("Camera");
    }
    if open_ports.contains(&1883) || open_ports.contains(&8883) {
        return Some("IoT device");
    }
    if open_ports.contains(&62078) {
        return Some("iPhone/iPad");
    }
    if open_ports.contains(&5000) && open_ports.contains(&5001) {
        return Some("NAS");
    }
    if open_ports.contains(&8443) && open_ports.contains(&8880) {
        return Some("UniFi controller");
    }
    if open_ports.contains(&3689) || open_ports.contains(&5353) {
        return Some("Media device");
    }
    if open_ports.contains(&3389) {
        return Some("Windows PC");
    }
    None
}

/// Classify device type from vendor name.
fn classify_by_vendor(vendor: &str) -> &'static str {
    match vendor {
        "Synology" => "NAS",
        "Sonos" => "Speaker",
        "Roku" => "Media player",
        "Ring" => "Camera/doorbell",
        "Philips Hue" => "Smart lighting",
        "Espressif" => "IoT device",
        "Raspberry Pi" => "Single-board computer",
        "HP" => "Printer (likely)",
        _ => "Unknown",
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
            let vendor = oui_lookup(&entry.mac);
            let vendor_name = vendor.unwrap_or("Unknown");

            if vendor.is_some() {
                identified += 1;
                let device_class = classify_by_vendor(vendor_name);
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
                    .with_mac(&entry.mac),
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
    fn test_oui_lookup_apple() {
        assert_eq!(oui_lookup("a4:83:e7:1a:2b:3c"), Some("Apple"));
    }

    #[test]
    fn test_oui_lookup_ubiquiti() {
        assert_eq!(oui_lookup("68:d7:9a:ab:cd:ef"), Some("Ubiquiti"));
    }

    #[test]
    fn test_oui_lookup_unknown() {
        assert_eq!(oui_lookup("ff:ff:ff:00:00:00"), None);
    }

    #[test]
    fn test_oui_lookup_case_insensitive() {
        assert_eq!(oui_lookup("A4:83:E7:1A:2B:3C"), Some("Apple"));
    }

    #[test]
    fn test_classify_by_ports_printer() {
        assert_eq!(classify_by_ports(&[80, 443, 9100, 631]), Some("Printer"));
    }

    #[test]
    fn test_classify_by_ports_camera() {
        assert_eq!(classify_by_ports(&[80, 554]), Some("Camera"));
    }

    #[test]
    fn test_classify_by_ports_iot() {
        assert_eq!(classify_by_ports(&[1883]), Some("IoT device"));
    }

    #[test]
    fn test_classify_by_ports_nas() {
        assert_eq!(classify_by_ports(&[5000, 5001, 443]), Some("NAS"));
    }

    #[test]
    fn test_classify_by_ports_none() {
        assert_eq!(classify_by_ports(&[80, 443]), None);
    }

    #[test]
    fn test_classify_by_vendor() {
        assert_eq!(classify_by_vendor("Synology"), "NAS");
        assert_eq!(classify_by_vendor("Sonos"), "Speaker");
        assert_eq!(classify_by_vendor("Ring"), "Camera/doorbell");
        assert_eq!(classify_by_vendor("Apple"), "Unknown");
    }
}
