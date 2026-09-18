use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, MacAddr, ScanContext};

use crate::Scanner;
use crate::oui_db::ieee_oui_lookup;

/// Device fingerprinting scanner — MAC OUI lookup and open-port profiling.
pub struct DeviceScanner;

/// Human-readable device-type label for a vendor name (from the IEEE OUI database).
fn classify_by_vendor(vendor: &str) -> &'static str {
    match vendor {
        "Synology" => "NAS",
        "D&M" | "Roku" => "Media player",
        "Sonos" => "Smart speaker",
        "Sony" | "Nintendo" => "Game console",
        "Ring" => "Camera/doorbell",
        "Amcrest"
        | "Arlo"
        | "Wyze Labs"
        | "Hangzhou Hikvision Digital"
        | "Zhejiang Dahua Technology" => "Camera/NVR",
        "iRobot" | "Beijing Roborock Technology" => "Robot vacuum",
        "ecobee inc" => "Thermostat",
        "August Home" => "Smart lock",
        "Enphase Energy" | "SolarEdge" => "Solar inverter",
        "SmartThings" | "Lutron Electronics" => "Smart home hub",
        "Shelly Europe LTD" => "Smart plug/relay",
        "eero inc." => "Mesh access point",
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

/// Map a vendor name to a structured [`DeviceType`].
///
/// Multi-product-line vendors return [`DeviceType::Unknown`] to avoid misclassifying.
const fn vendor_to_device_type(vendor: &str) -> DeviceType {
    match vendor.as_bytes() {
        b"Synology" => DeviceType::Nas,
        b"Roku" | b"D&M" => DeviceType::MediaPlayer,
        b"Sonos" => DeviceType::Speaker,
        b"Sony" | b"Nintendo" => DeviceType::GameConsole,
        // Ring also ships cameras; `Camera` is the safe superset of its line.
        b"Ring"
        | b"Amcrest"
        | b"Arlo"
        | b"Wyze Labs"
        | b"Hangzhou Hikvision Digital"
        | b"Zhejiang Dahua Technology" => DeviceType::Camera,
        b"iRobot" | b"Beijing Roborock Technology" => DeviceType::Vacuum,
        b"ecobee inc" => DeviceType::Thermostat,
        b"August Home" => DeviceType::SmartLock,
        b"Enphase Energy" | b"SolarEdge" => DeviceType::Inverter,
        b"SmartThings" | b"Lutron Electronics" => DeviceType::Hub,
        b"Shelly Europe LTD" => DeviceType::SmartPlug,
        b"eero inc." => DeviceType::AccessPoint,
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
            // Locally-administered (randomized) MACs have no meaningful vendor OUI; skip lookup.
            if entry
                .mac
                .parse::<MacAddr>()
                .is_ok_and(|m| m.is_locally_administered())
            {
                unidentified += 1;
                findings.push(
                    Finding::new(
                        "device",
                        &format!("Randomized (private) MAC at {}", entry.ip),
                        &format!(
                            "MAC {} is locally-administered (randomized) — a privacy \
                             feature of modern phones and laptops. The hardware vendor \
                             cannot be identified from it, and it is not a stable device \
                             identifier across scans.",
                            entry.mac
                        ),
                        Severity::Info,
                    )
                    .with_ip(entry.ip)
                    .with_mac(&entry.mac),
                );
                continue;
            }

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
    use proptest::prelude::*;

    /// Vendor tables must be keyed on strings the OUI database actually emits;
    /// a typo here silently classifies nothing.
    #[test]
    fn vendor_table_keys_match_oui_registrant_names() {
        for (oui, vendor) in [
            ("4c:b9:ea", "iRobot"),
            ("24:9e:7d", "Beijing Roborock Technology"),
            ("44:61:32", "ecobee inc"),
            ("78:9c:85", "August Home"),
            ("00:1d:c0", "Enphase Energy"),
            ("00:27:02", "SolarEdge"),
            ("24:fd:5b", "SmartThings"),
            ("00:0f:e7", "Lutron Electronics"),
            ("84:00:ec", "Shelly Europe LTD"),
            ("00:ab:48", "eero inc."),
            ("00:65:1e", "Amcrest"),
            ("48:62:64", "Arlo"),
            ("2c:aa:8e", "Wyze Labs"),
            ("00:bc:99", "Hangzhou Hikvision Digital"),
            ("08:ed:ed", "Zhejiang Dahua Technology"),
        ] {
            assert_eq!(
                ieee_oui_lookup(&format!("{oui}:00:00:00")),
                Some(vendor),
                "OUI {oui} no longer maps to {vendor}"
            );
            assert_ne!(
                vendor_to_device_type(vendor),
                DeviceType::Unknown,
                "{vendor} has no structured device type"
            );
            assert_ne!(
                classify_by_vendor(vendor),
                "Unknown",
                "{vendor} has no vendor label"
            );
        }
    }

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
        assert_eq!(classify_by_vendor("Sonos"), "Smart speaker");
        assert_eq!(classify_by_vendor("Roku"), "Media player");
        assert_eq!(classify_by_vendor("iRobot"), "Robot vacuum");
        assert_eq!(classify_by_vendor("ecobee inc"), "Thermostat");
        assert_eq!(classify_by_vendor("August Home"), "Smart lock");
        assert_eq!(classify_by_vendor("SolarEdge"), "Solar inverter");
        assert_eq!(classify_by_vendor("SmartThings"), "Smart home hub");
        assert_eq!(classify_by_vendor("Shelly Europe LTD"), "Smart plug/relay");
        assert_eq!(classify_by_vendor("eero inc."), "Mesh access point");
        assert_eq!(classify_by_vendor("Amcrest"), "Camera/NVR");
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
        assert_eq!(vendor_to_device_type("Sonos"), DeviceType::Speaker);
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
        assert_eq!(vendor_to_device_type("iRobot"), DeviceType::Vacuum);
        assert_eq!(
            vendor_to_device_type("Beijing Roborock Technology"),
            DeviceType::Vacuum
        );
        assert_eq!(vendor_to_device_type("ecobee inc"), DeviceType::Thermostat);
        assert_eq!(vendor_to_device_type("August Home"), DeviceType::SmartLock);
        assert_eq!(
            vendor_to_device_type("Enphase Energy"),
            DeviceType::Inverter
        );
        assert_eq!(vendor_to_device_type("SolarEdge"), DeviceType::Inverter);
        assert_eq!(vendor_to_device_type("SmartThings"), DeviceType::Hub);
        assert_eq!(vendor_to_device_type("Lutron Electronics"), DeviceType::Hub);
        assert_eq!(
            vendor_to_device_type("Shelly Europe LTD"),
            DeviceType::SmartPlug
        );
        assert_eq!(vendor_to_device_type("eero inc."), DeviceType::AccessPoint);
        assert_eq!(vendor_to_device_type("Amcrest"), DeviceType::Camera);
        assert_eq!(
            vendor_to_device_type("Hangzhou Hikvision Digital"),
            DeviceType::Camera
        );
        // Multi-purpose vendors return Unknown
        assert_eq!(vendor_to_device_type("Apple"), DeviceType::Unknown);
        assert_eq!(vendor_to_device_type("Samsung"), DeviceType::Unknown);
        assert_eq!(vendor_to_device_type("Cisco"), DeviceType::Unknown);
    }

    /// Every match arm of both classifiers, plus real OUI names and near-misses.
    const VENDOR_SAMPLES: &[&str] = &[
        "Synology",
        "Sonos",
        "D&M",
        "Roku",
        "Sony",
        "Nintendo",
        "Ring",
        "Signify",
        "Philips Lighting",
        "Espressif",
        "AI-Link",
        "TI",
        "Raspberry Pi",
        "HP",
        "Ubiquiti",
        "TP-Link",
        "Netgear",
        "D-Link",
        "Belkin",
        "Amazon",
        "Xiaomi",
        "Arris",
        "CommScope",
        "Apple",
        "Samsung",
        "Google",
        "LG",
        "Intel",
        "Dell",
        "Lenovo",
        "Asus",
        "Motorola",
        "Cisco",
        "XEROX CORPORATION",
        "IEEE Registration Authority",
        "Hitachi Reftechno",
        "hp",
        "synology",
        "Synology ",
        "",
    ];

    fn vendor_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            proptest::sample::select(VENDOR_SAMPLES).prop_map(str::to_owned),
            ".*",
            "[A-Za-z&\\- ]{1,20}",
        ]
    }

    proptest! {
        /// A structured device type implies a non-`Unknown` vendor label.
        #[test]
        fn prop_device_type_implies_label(vendor in vendor_strategy()) {
            if vendor_to_device_type(&vendor) != DeviceType::Unknown {
                prop_assert_ne!(classify_by_vendor(&vendor), "Unknown", "{:?}", vendor);
            }
        }
    }
}
