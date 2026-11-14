//! Hostname patterns that name a device class.
//!
//! Patterns are anchored, ASCII case-insensitive globs: `*` matches any run,
//! `?` one character, `#` one digit. An entry with a vendor guard matches only
//! when the OUI vendor equals it (case-insensitive).

use rikitikitavi_models::DeviceType;

/// One hostname pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostnameRule {
    pub pattern: &'static str,
    /// Required OUI vendor, as emitted by the IEEE OUI table.
    pub vendor: Option<&'static str>,
    pub device_type: DeviceType,
    /// Free-text `device_subtype`.
    pub subtype: &'static str,
}

const fn rule(
    pattern: &'static str,
    vendor: Option<&'static str>,
    device_type: DeviceType,
    subtype: &'static str,
) -> HostnameRule {
    HostnameRule {
        pattern,
        vendor,
        device_type,
        subtype,
    }
}

const UBNT: Option<&str> = Some("Ubiquiti");
const TPLINK: Option<&str> = Some("TP-Link");
const RING: Option<&str> = Some("Ring");

/// First match wins.
pub const HOSTNAME_RULES: &[HostnameRule] = &[
    // UniFi access points.
    rule("U6*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("U7*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("E7*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("UAP*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("NanoHD*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("FlexHD*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("BeaconHD*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("IW-HD*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("AC-Pro*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("ACPro*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("AC-Lite*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("ACLite*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("AC-LR*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("ACLR*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("AC-Mesh*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    rule("ACMesh*", UBNT, DeviceType::AccessPoint, "unifi_ap"),
    // UniFi switches.
    rule("USW*", UBNT, DeviceType::Switch, "unifi_switch"),
    rule("US-*", UBNT, DeviceType::Switch, "unifi_switch"),
    rule("USL*", UBNT, DeviceType::Switch, "unifi_switch"),
    rule("USMINI*", UBNT, DeviceType::Switch, "unifi_switch"),
    // UniFi gateways.
    rule("UDM*", UBNT, DeviceType::Router, "unifi_gateway"),
    rule("UDR*", UBNT, DeviceType::Router, "unifi_gateway"),
    rule("UCG*", UBNT, DeviceType::Router, "unifi_gateway"),
    rule("UXG*", UBNT, DeviceType::Router, "unifi_gateway"),
    rule("USG*", UBNT, DeviceType::Router, "unifi_gateway"),
    // UniFi Protect.
    rule("G#-*", UBNT, DeviceType::Camera, "unifi_protect"),
    rule("UVC*", UBNT, DeviceType::Camera, "unifi_protect"),
    rule("UNVR*", UBNT, DeviceType::Nvr, "unifi_protect"),
    // Garage-door openers map to SmartLock.
    rule("MyQ-*", None, DeviceType::SmartLock, "myq"),
    rule("Schlage*", None, DeviceType::SmartLock, "schlage"),
    rule("DENALI-*", None, DeviceType::Thermostat, "denali"),
    rule("ecobee*", None, DeviceType::Thermostat, "ecobee"),
    rule("Dyson*", None, DeviceType::Appliance, "dyson"),
    rule("???-??-*", Some("Dyson"), DeviceType::Appliance, "dyson"),
    rule(
        "WhiskerRobots*",
        None,
        DeviceType::Appliance,
        "litter_robot",
    ),
    rule("LitterRobot*", None, DeviceType::Appliance, "litter_robot"),
    rule(
        "Samsung-FamilyHub*",
        None,
        DeviceType::Appliance,
        "samsung_familyhub",
    ),
    rule(
        "TeslaWallConnector*",
        None,
        DeviceType::EvCharger,
        "tesla_wall_connector",
    ),
    rule("RingDoorbell-*", RING, DeviceType::Doorbell, "ring"),
    rule("RingStickUpCam-*", RING, DeviceType::Camera, "ring"),
    rule("RingFloodlight*", RING, DeviceType::Camera, "ring"),
    rule("RingSpotlight*", RING, DeviceType::Camera, "ring"),
    // TP-Link Kasa plugs and switches.
    rule("HS1##*", TPLINK, DeviceType::SmartPlug, "kasa"),
    rule("HS2##*", TPLINK, DeviceType::SmartPlug, "kasa"),
    rule("KP###*", TPLINK, DeviceType::SmartPlug, "kasa"),
    rule("EP##*", TPLINK, DeviceType::SmartPlug, "kasa"),
    rule("LGwebOSTV*", None, DeviceType::SmartTv, "lg_webos"),
    rule("Denon-AVR-*", None, DeviceType::MediaPlayer, "denon"),
    rule("Roku*", None, DeviceType::MediaPlayer, "roku"),
    rule("Chromecast*", None, DeviceType::MediaPlayer, "chromecast"),
    rule("Philips-hue", None, DeviceType::Hub, "hue"),
    // Default names of Brother (`BRN`/`BRW` + MAC) and HP (`HP` + MAC tail) printers.
    rule("BRN????????????", None, DeviceType::Printer, "brother"),
    rule("BRW????????????", None, DeviceType::Printer, "brother"),
    rule("HP??????", Some("HP"), DeviceType::Printer, "hp"),
    rule("iPhone*", None, DeviceType::Phone, "iphone"),
    rule("iPad*", None, DeviceType::Tablet, "ipad"),
    rule("Pixel-*", None, DeviceType::Phone, "pixel"),
    rule("Galaxy-*", None, DeviceType::Phone, "galaxy"),
    rule("*-MBP", None, DeviceType::Laptop, "macbook"),
    rule("*MacBook*", None, DeviceType::Laptop, "macbook"),
];

/// First rule matching `hostname` whose vendor guard, if any, equals `vendor`.
#[must_use]
pub fn classify_hostname(hostname: &str, vendor: Option<&str>) -> Option<&'static HostnameRule> {
    HOSTNAME_RULES.iter().find(|r| {
        r.vendor
            .is_none_or(|g| vendor.is_some_and(|v| v.eq_ignore_ascii_case(g)))
            && glob_match(r.pattern.as_bytes(), hostname.as_bytes())
    })
}

/// Anchored ASCII case-insensitive glob over `*`, `?` and `#`.
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        let matches_one = pattern.get(p).is_some_and(|&c| match c {
            b'?' => true,
            b'#' => text[t].is_ascii_digit(),
            b'*' => false,
            _ => c.eq_ignore_ascii_case(&text[t]),
        });
        if matches_one {
            p += 1;
            t += 1;
        } else if pattern.get(p) == Some(&b'*') {
            star = Some((p, t));
            p += 1;
        } else if let Some((sp, st)) = star {
            p = sp + 1;
            t = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    pattern[p.min(pattern.len())..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn class(host: &str, vendor: Option<&str>) -> Option<DeviceType> {
        classify_hostname(host, vendor).map(|r| r.device_type)
    }

    #[test]
    fn hostname_glob_semantics() {
        assert!(glob_match(b"MyQ-*", b"myq-6c7"));
        assert!(glob_match(b"HS1##*", b"HS105"));
        assert!(!glob_match(b"HS1##*", b"HS1A5"));
        assert!(glob_match(b"*-MBP", b"Bryans-MBP"));
        assert!(!glob_match(b"*-MBP", b"Bryans-MBPx"));
        assert!(glob_match(b"???-??-*", b"K3A-US-PCA3065A"));
        assert!(!glob_match(b"???-??-*", b"K3AB-US-PCA3065A"));
        assert!(glob_match(b"*", b""));
        assert!(!glob_match(b"a", b""));
        assert!(glob_match(b"*a*b*", b"xxaxxbxx"));
    }

    #[test]
    fn hostname_unifi_models_need_ubiquiti_vendor() {
        let u = Some("Ubiquiti");
        assert_eq!(class("U7Pro", u), Some(DeviceType::AccessPoint));
        assert_eq!(class("U6Lite", u), Some(DeviceType::AccessPoint));
        assert_eq!(class("NanoHD", u), Some(DeviceType::AccessPoint));
        assert_eq!(class("ACPro", u), Some(DeviceType::AccessPoint));
        assert_eq!(class("USW-16-PoE", u), Some(DeviceType::Switch));
        assert_eq!(class("US-8-60W", u), Some(DeviceType::Switch));
        assert_eq!(class("USW-Pro-Max-16-PoE", u), Some(DeviceType::Switch));
        assert_eq!(class("g3-flex", u), Some(DeviceType::Camera));
        assert_eq!(class("UDM-Pro", u), Some(DeviceType::Router));
        assert_eq!(class("U7Pro", None), None);
        assert_eq!(class("U7Pro", Some("TP-Link")), None);
        assert_eq!(class("US-East", Some("Apple")), None);
    }

    #[test]
    fn hostname_house_devices() {
        assert_eq!(class("MyQ-6C7", None), Some(DeviceType::SmartLock));
        assert_eq!(class("Schlage", Some("TI")), Some(DeviceType::SmartLock));
        assert_eq!(
            class("DENALI-5CFCE1C7A955", None),
            Some(DeviceType::Thermostat)
        );
        assert_eq!(
            class("K3A-US-PCA3065A", Some("Dyson")),
            Some(DeviceType::Appliance)
        );
        assert_eq!(class("K3A-US-PCA3065A", Some("Espressif")), None);
        assert_eq!(class("WhiskerRobots", None), Some(DeviceType::Appliance));
        assert_eq!(
            class("RingDoorbell-de", Some("Ring")),
            Some(DeviceType::Doorbell)
        );
        assert_eq!(class("HS105", Some("TP-Link")), Some(DeviceType::SmartPlug));
        assert_eq!(class("EP40", Some("TP-Link")), Some(DeviceType::SmartPlug));
        assert_eq!(class("HP7BA8A8", Some("HP")), Some(DeviceType::Printer));
        assert_eq!(class("HP7BA8A8", Some("HPRO")), None);
        assert_eq!(class("LGwebOSTV", None), Some(DeviceType::SmartTv));
        assert_eq!(class("Pixel-10-Pro", None), Some(DeviceType::Phone));
        assert_eq!(class("joeyjojos-MBP", None), Some(DeviceType::Laptop));
    }

    #[test]
    fn hostname_patterns_are_anchored() {
        assert_eq!(class("laptop", Some("Ubiquiti")), None);
        assert_eq!(class("my-MyQ-6C7", None), None);
        assert_eq!(class("xSchlage", None), None);
        assert_eq!(class("anvil", None), None);
        assert_eq!(class("espressif", None), None);
    }

    #[test]
    fn hostname_rules_use_known_vendor_names() {
        let samples = [
            "9c:05:d6:00:00:00",
            "e4:fa:c4:00:00:00",
            "9c:76:13:00:00:00",
            "c8:ff:77:00:00:00",
            "f8:0d:ac:00:00:00",
        ];
        let known: Vec<&str> = samples
            .iter()
            .filter_map(|m| crate::oui_db::ieee_oui_lookup(m))
            .collect();
        for r in HOSTNAME_RULES {
            assert_ne!(r.device_type, DeviceType::Unknown, "{}", r.pattern);
            assert!(!r.pattern.is_empty() && !r.subtype.is_empty());
            if let Some(v) = r.vendor {
                assert!(known.contains(&v), "{v} is not an OUI vendor name");
            }
        }
    }

    proptest! {
        #[test]
        fn hostname_classify_never_panics(host in "\\PC{0,40}", vendor in proptest::option::of("\\PC{0,12}")) {
            let _ = classify_hostname(&host, vendor.as_deref());
        }

        #[test]
        fn hostname_match_is_case_insensitive(host in "[A-Za-z0-9-]{1,20}") {
            let u = Some("Ubiquiti");
            prop_assert_eq!(
                class(&host, u),
                class(&host.to_ascii_uppercase(), u)
            );
        }
    }
}
