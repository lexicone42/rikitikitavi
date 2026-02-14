use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, ScanContext};

use crate::Scanner;

/// Device fingerprinting scanner — identifies device types via MAC OUI lookup
/// and open port profiling.
pub struct DeviceScanner;

/// Common home network OUI prefixes (first 3 bytes of MAC → vendor).
/// Covers the most common consumer electronics and networking brands.
/// Sorted by vendor for maintainability; looked up via linear scan (fast
/// for <150 entries on a cache-friendly array).
const OUI_TABLE: &[(&str, &str)] = &[
    // Amazon (Echo, Ring, Fire)
    ("00:fc:8b", "Amazon"),
    ("0c:47:c9", "Amazon"),
    ("1c:4d:66", "Amazon"),
    ("34:d2:70", "Amazon"),
    ("38:f7:3d", "Amazon"),
    ("44:65:0d", "Amazon"),
    ("94:3a:91", "Amazon"),
    ("fc:65:de", "Amazon"),
    // Apple
    ("00:03:93", "Apple"),
    ("3c:22:fb", "Apple"),
    ("5c:9b:a6", "Apple"),
    ("a4:83:e7", "Apple"),
    ("ac:bc:32", "Apple"),
    ("d0:e1:40", "Apple"),
    ("f0:18:98", "Apple"),
    ("f8:ff:c2", "Apple"),
    // D&M Holdings (Denon, Marantz)
    ("00:06:78", "Denon"),
    // Espressif (ESP32, ESP8266 — IoT)
    ("24:0a:c4", "Espressif"),
    ("24:62:ab", "Espressif"),
    ("30:ae:a4", "Espressif"),
    // Google / Nest
    ("30:fd:38", "Google"),
    ("54:60:09", "Google"),
    ("a4:77:33", "Google"),
    ("f4:f5:d8", "Google"),
    // HP (printers)
    ("00:1e:0b", "HP"),
    ("3c:d9:2b", "HP"),
    ("68:b5:99", "HP"),
    ("f8:0d:ac", "HP"),
    // Intel
    ("00:1b:21", "Intel"),
    ("3c:97:0e", "Intel"),
    ("5c:80:b6", "Intel"),
    ("a4:34:d9", "Intel"),
    // LG
    ("00:1c:62", "LG"),
    ("38:8c:50", "LG"),
    ("a8:16:b2", "LG"),
    // Microsoft / Xbox
    ("00:50:f2", "Microsoft"),
    ("7c:ed:8d", "Microsoft"),
    // Netgear
    ("00:14:6c", "Netgear"),
    ("20:e5:2a", "Netgear"),
    ("a4:2b:8c", "Netgear"),
    ("c0:ff:d4", "Netgear"),
    // Philips Hue / Signify
    ("00:17:88", "Philips Hue"),
    // Raspberry Pi
    ("b8:27:eb", "Raspberry Pi"),
    ("dc:a6:32", "Raspberry Pi"),
    ("e4:5f:01", "Raspberry Pi"),
    // Ring (doorbells, cameras)
    ("18:b4:30", "Ring"),
    ("50:dc:e7", "Ring"),
    ("9c:76:13", "Ring"),
    ("ac:9f:c3", "Ring"),
    // Roku
    ("b0:a7:37", "Roku"),
    ("d8:31:34", "Roku"),
    ("dc:3a:5e", "Roku"),
    // Samsung
    ("00:07:ab", "Samsung"),
    ("00:12:fb", "Samsung"),
    ("34:23:ba", "Samsung"),
    ("50:01:d9", "Samsung"),
    ("8c:71:f8", "Samsung"),
    ("f4:dd:06", "Samsung"),
    // Sichuan AI-Link (IoT modules)
    ("b4:61:e9", "AI-Link"),
    // Sonos
    ("00:0e:58", "Sonos"),
    ("34:7e:5c", "Sonos"),
    ("48:a6:b8", "Sonos"),
    ("54:2a:1b", "Sonos"),
    ("b8:e9:37", "Sonos"),
    // Sony Interactive Entertainment (PlayStation)
    ("5c:96:66", "Sony"),
    // Synology
    ("00:11:32", "Synology"),
    // Texas Instruments (IoT chipsets)
    ("3c:e0:64", "Texas Instruments"),
    // TP-Link
    ("14:cc:20", "TP-Link"),
    ("50:c7:bf", "TP-Link"),
    ("60:32:b1", "TP-Link"),
    ("98:da:c4", "TP-Link"),
    ("e4:c3:2a", "TP-Link"),
    // Ubiquiti
    ("04:18:d6", "Ubiquiti"),
    ("18:e8:29", "Ubiquiti"),
    ("24:5a:4c", "Ubiquiti"),
    ("28:70:4e", "Ubiquiti"),
    ("68:d7:9a", "Ubiquiti"),
    ("74:83:c2", "Ubiquiti"),
    ("78:45:58", "Ubiquiti"),
    ("78:8a:20", "Ubiquiti"),
    ("94:2a:6f", "Ubiquiti"),
    ("9c:05:d6", "Ubiquiti"),
    ("b4:fb:e4", "Ubiquiti"),
    ("e0:63:da", "Ubiquiti"),
    ("f4:92:bf", "Ubiquiti"),
    // Xiaomi
    ("64:90:c1", "Xiaomi"),
];

/// Map a MAC address prefix (first 3 octets) to a vendor name.
fn oui_lookup(mac: &str) -> Option<&'static str> {
    let prefix = mac.get(..8)?.to_lowercase();
    OUI_TABLE
        .iter()
        .find(|(oui, _)| *oui == prefix)
        .map(|(_, vendor)| *vendor)
}

/// Classify device type from vendor name (human-readable label for descriptions).
fn classify_by_vendor(vendor: &str) -> &'static str {
    match vendor {
        "Synology" => "NAS",
        "Sonos" | "Denon" | "Roku" | "Sony" => "Media player",
        "Ring" => "Camera/doorbell",
        "Philips Hue" | "Espressif" | "AI-Link" | "Texas Instruments" => "IoT device",
        "Raspberry Pi" => "Single-board computer",
        "HP" => "Printer (likely)",
        "Ubiquiti" => "Network switch",
        "Amazon" => "Smart speaker/display",
        "Xiaomi" => "Smart home device",
        _ => "Unknown",
    }
}

/// Map an OUI vendor name to a structured `DeviceType` for enrichment.
const fn vendor_to_device_type(vendor: &str) -> DeviceType {
    match vendor.as_bytes() {
        b"Synology" => DeviceType::Nas,
        b"Sonos" | b"Roku" | b"Denon" => DeviceType::MediaPlayer,
        b"Sony" => DeviceType::GameConsole,
        b"Ring" => DeviceType::Camera,
        b"Philips Hue" | b"Espressif" | b"AI-Link" | b"Texas Instruments" | b"Amazon" => DeviceType::IoT,
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
            let vendor = oui_lookup(&entry.mac);
            let vendor_name = vendor.unwrap_or("Unknown");

            if vendor.is_some() {
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
    fn test_classify_by_vendor() {
        assert_eq!(classify_by_vendor("Synology"), "NAS");
        assert_eq!(classify_by_vendor("Sonos"), "Media player");
        assert_eq!(classify_by_vendor("Ring"), "Camera/doorbell");
        assert_eq!(classify_by_vendor("Amazon"), "Smart speaker/display");
        assert_eq!(classify_by_vendor("Sony"), "Media player");
        assert_eq!(classify_by_vendor("Apple"), "Unknown");
    }

    #[test]
    fn test_vendor_to_device_type() {
        assert_eq!(vendor_to_device_type("Synology"), DeviceType::Nas);
        assert_eq!(vendor_to_device_type("Sonos"), DeviceType::MediaPlayer);
        assert_eq!(vendor_to_device_type("Roku"), DeviceType::MediaPlayer);
        assert_eq!(vendor_to_device_type("Denon"), DeviceType::MediaPlayer);
        assert_eq!(vendor_to_device_type("Ring"), DeviceType::Camera);
        assert_eq!(vendor_to_device_type("Philips Hue"), DeviceType::IoT);
        assert_eq!(vendor_to_device_type("Espressif"), DeviceType::IoT);
        assert_eq!(vendor_to_device_type("Amazon"), DeviceType::IoT);
        assert_eq!(vendor_to_device_type("AI-Link"), DeviceType::IoT);
        assert_eq!(vendor_to_device_type("Texas Instruments"), DeviceType::IoT);
        assert_eq!(vendor_to_device_type("HP"), DeviceType::Printer);
        assert_eq!(vendor_to_device_type("Raspberry Pi"), DeviceType::Server);
        assert_eq!(vendor_to_device_type("Ubiquiti"), DeviceType::Switch);
        assert_eq!(vendor_to_device_type("Sony"), DeviceType::GameConsole);
        assert_eq!(vendor_to_device_type("Xiaomi"), DeviceType::Phone);
        assert_eq!(vendor_to_device_type("Apple"), DeviceType::Unknown);
    }
}
