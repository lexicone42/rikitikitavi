//! `UniFi` OS fixed-version floors from Security Advisory Bulletin 069.

use std::cmp::Ordering;
use std::net::IpAddr;

use rikitikitavi_core::{Confidence, Severity};
use rikitikitavi_models::{Device, DeviceType, Finding, Remediation};

use crate::models::{AdoptedDevice, UniFiDevice};

pub const SAB_069_URL: &str = "https://community.ui.com/releases/Security-Advisory-Bulletin-069-069/07e367a7-edec-4d85-a058-f97e5ce9ac9c";
pub const SAB_069_CVE_RECORD_URL: &str = "https://cveawg.mitre.org/api/cve/CVE-2026-77555";
pub const UNIFI_UPDATES_URL: &str =
    "https://help.ui.com/hc/en-us/articles/7605005245975-UniFi-Updates";

/// CVE records that cite SAB-069; all share the per-product floors below.
pub const SAB_069_CVES: &[&str] = &[
    "CVE-2026-77544",
    "CVE-2026-77555",
    "CVE-2026-77556",
    "CVE-2026-77558",
    "CVE-2026-95861",
    "CVE-2026-95862",
];

/// Affected product names in the SAB-069 CVE records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayFamily {
    DreamMachines,
    EnterpriseFirewalls,
    DreamRouters,
    CloudGateways,
    DreamWall,
    Express,
    Express7,
    UniFiGateways,
}

impl GatewayFamily {
    pub const ALL: [Self; 8] = [
        Self::DreamMachines,
        Self::EnterpriseFirewalls,
        Self::DreamRouters,
        Self::CloudGateways,
        Self::DreamWall,
        Self::Express,
        Self::Express7,
        Self::UniFiGateways,
    ];

    pub const fn product(self) -> &'static str {
        match self {
            Self::DreamMachines => "Dream Machines",
            Self::EnterpriseFirewalls => "Enterprise Firewalls",
            Self::DreamRouters => "Dream Routers",
            Self::CloudGateways => "Cloud Gateways",
            Self::DreamWall => "Dream Wall",
            Self::Express => "Express",
            Self::Express7 => "Express 7",
            Self::UniFiGateways => "UniFi Gateways",
        }
    }

    /// First unaffected version (`lessThan` in the CVE records).
    pub const fn sab069_floor(self) -> [u32; 3] {
        match self {
            Self::Express => [4, 0, 21],
            Self::UniFiGateways => [5, 1, 26],
            Self::DreamMachines
            | Self::EnterpriseFirewalls
            | Self::DreamRouters
            | Self::CloudGateways
            | Self::DreamWall
            | Self::Express7 => [5, 1, 31],
        }
    }

    pub const fn from_device(device: UniFiDevice) -> Option<Self> {
        match device {
            UniFiDevice::DreamMachine
            | UniFiDevice::DreamMachinePro
            | UniFiDevice::DreamMachineProMax
            | UniFiDevice::DreamMachineSE => Some(Self::DreamMachines),
            UniFiDevice::DreamRouter => Some(Self::DreamRouters),
            UniFiDevice::DreamWall => Some(Self::DreamWall),
            UniFiDevice::CloudGatewayUltra | UniFiDevice::CloudGatewayMax => {
                Some(Self::CloudGateways)
            }
            UniFiDevice::CloudKeyGen2Plus
            | UniFiDevice::SecurityGateway
            | UniFiDevice::SecurityGatewayPro4
            | UniFiDevice::AccessPoint
            | UniFiDevice::Switch
            | UniFiDevice::Unknown => None,
        }
    }

    /// Family for a controller `model` code; `None` when the code is not mapped.
    pub fn from_model(model: &str) -> Option<Self> {
        Self::from_device(crate::local::classify_board(model))
    }
}

/// Dotted numeric version (`4.0.6.6754`, `v5.0.12`); `None` for anything else.
pub fn parse_version(raw: &str) -> Option<Vec<u32>> {
    let s = raw.trim();
    let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
    let parts: Vec<u32> = s
        .split('.')
        .map(|p| {
            if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
                None
            } else {
                p.parse().ok()
            }
        })
        .collect::<Option<_>>()?;
    (2..=8).contains(&parts.len()).then_some(parts)
}

/// Component-wise comparison; missing trailing components count as zero.
pub fn compare_versions(a: &[u32], b: &[u32]) -> Ordering {
    let len = a.len().max(b.len());
    (0..len)
        .map(|i| {
            let x = a.get(i).copied().unwrap_or(0);
            let y = b.get(i).copied().unwrap_or(0);
            x.cmp(&y)
        })
        .find(|o| o.is_ne())
        .unwrap_or(Ordering::Equal)
}

/// `Some(true)` below the family floor, `Some(false)` at or above, `None` if unparseable.
pub fn below_sab069_floor(family: GatewayFamily, version: &str) -> Option<bool> {
    let v = parse_version(version)?;
    Some(compare_versions(&v, &family.sab069_floor()) == Ordering::Less)
}

fn floor_string(family: GatewayFamily) -> String {
    let [a, b, c] = family.sab069_floor();
    format!("{a}.{b}.{c}")
}

fn update_remediation(target: &str) -> Remediation {
    Remediation {
        description: format!("Update UniFi OS to {target} or later and turn on auto-update."),
        steps: vec![
            format!(
                "On the UniFi console open Settings > Control Plane > Updates ({UNIFI_UPDATES_URL})."
            ),
            format!("Update UniFi OS to {target} or later."),
            "Turn on automatic updates on the same page.".to_owned(),
        ],
        effort: Some("15 minutes".to_owned()),
    }
}

fn sab069_references() -> Vec<String> {
    vec![
        SAB_069_URL.to_owned(),
        SAB_069_CVE_RECORD_URL.to_owned(),
        UNIFI_UPDATES_URL.to_owned(),
    ]
}

/// Medium finding when `version` is below the family floor; `None` otherwise.
pub fn sab069_finding(family: GatewayFamily, version: &str, label: &str) -> Option<Finding> {
    if below_sab069_floor(family, version) != Some(true) {
        return None;
    }
    let floor = floor_string(family);
    Some(
        Finding::new(
            "unifi",
            &format!("UniFi OS below SAB-069 fix on {label}"),
            &format!(
                "{label} ({}) runs UniFi OS {version}. Ubiquiti Security Advisory Bulletin 069 \
                 fixes unauthenticated denial-of-service vulnerabilities reachable from the \
                 network in {} from UniFi OS {floor}.",
                family.product(),
                family.product(),
            ),
            Severity::Medium,
        )
        .with_confidence(Confidence::Confirmed)
        .with_cve_ids(SAB_069_CVES.iter().map(|s| (*s).to_owned()).collect())
        .with_references(sab069_references())
        .with_evidence(format!("version={version}"))
        .with_remediation(update_remediation(&floor)),
    )
}

/// SAB-069 findings for controller-reported devices with a mapped model.
pub fn audit_adopted_devices(devices: &[AdoptedDevice]) -> Vec<Finding> {
    devices
        .iter()
        .filter_map(|dev| {
            let family = GatewayFamily::from_model(&dev.model)?;
            let label = dev.name.as_deref().unwrap_or(&dev.model);
            let mut finding = sab069_finding(family, &dev.firmware_version, label)?;
            if let Some(ip) = dev.ip.as_deref().and_then(|s| s.parse::<IpAddr>().ok()) {
                finding = finding.with_ip(ip);
            }
            Some(finding.with_mac(dev.mac.as_str()))
        })
        .collect()
}

fn is_unifi_gateway(device: &Device, gateway: Option<IpAddr>) -> bool {
    let ubiquiti = device
        .vendor
        .as_deref()
        .is_some_and(|v| v.to_ascii_lowercase().contains("ubiquiti"));
    ubiquiti
        && (device.device_type == DeviceType::Router
            || device.device_subtype.as_deref() == Some("unifi_gateway")
            || gateway == Some(device.ip))
}

fn floors_summary() -> String {
    let mut groups: Vec<(String, Vec<&str>)> = Vec::new();
    for family in GatewayFamily::ALL {
        let floor = floor_string(family);
        match groups.iter_mut().find(|(f, _)| *f == floor) {
            Some((_, names)) => names.push(family.product()),
            None => groups.push((floor, vec![family.product()])),
        }
    }
    groups
        .iter()
        .map(|(floor, names)| format!("{floor} on {}", names.join(", ")))
        .collect::<Vec<_>>()
        .join("; ")
}

/// One Info advisory per scan when a `UniFi` gateway or console is identified without a version.
pub fn uncredentialed_advisory(devices: &[Device], gateway: Option<IpAddr>) -> Option<Finding> {
    let mut hits: Vec<&Device> = devices
        .iter()
        .filter(|d| is_unifi_gateway(d, gateway))
        .collect();
    hits.sort_by_key(|d| (gateway != Some(d.ip), d.ip));
    hits.dedup_by_key(|d| d.ip);
    let first = hits.first()?;
    let ips = hits
        .iter()
        .map(|d| d.ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut finding = Finding::new(
        "unifi",
        "UniFi OS version not readable without credentials (SAB-069)",
        &format!(
            "UniFi gateway or console identified at {ips}. Its UniFi OS version cannot be read \
             without controller credentials, so Security Advisory Bulletin 069 \
             (unauthenticated denial of service) could not be checked. Fixed versions: {}. \
             Check the version under Settings > Control Plane > Updates, or run \
             `rikitikitavi unifi scan` with credentials.",
            floors_summary()
        ),
        Severity::Info,
    )
    .with_confidence(Confidence::Inferred)
    .with_ip(first.ip)
    .with_references(sab069_references())
    .with_remediation(update_remediation("the latest release"));
    if let Some(mac) = first.mac {
        finding = finding.with_mac(mac.to_string());
    }
    Some(finding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
    }

    fn adopted(model: &str, version: &str) -> AdoptedDevice {
        AdoptedDevice {
            mac: "aa:bb:cc:dd:ee:ff".to_owned(),
            name: None,
            model: model.to_owned(),
            firmware_version: version.to_owned(),
            device_type: "udm".to_owned(),
            adopted: true,
            state: crate::models::DeviceState::Connected,
            ip: Some("192.168.1.1".to_owned()),
        }
    }

    #[test]
    fn floors_match_cve_record() {
        let floors: Vec<_> = GatewayFamily::ALL
            .iter()
            .map(|f| (f.product(), f.sab069_floor()))
            .collect();
        assert_eq!(
            floors,
            vec![
                ("Dream Machines", [5, 1, 31]),
                ("Enterprise Firewalls", [5, 1, 31]),
                ("Dream Routers", [5, 1, 31]),
                ("Cloud Gateways", [5, 1, 31]),
                ("Dream Wall", [5, 1, 31]),
                ("Express", [4, 0, 21]),
                ("Express 7", [5, 1, 31]),
                ("UniFi Gateways", [5, 1, 26]),
            ]
        );
    }

    #[test]
    fn family_from_device() {
        use GatewayFamily as F;
        use UniFiDevice as D;
        for (d, want) in [
            (D::DreamMachine, Some(F::DreamMachines)),
            (D::DreamMachinePro, Some(F::DreamMachines)),
            (D::DreamMachineProMax, Some(F::DreamMachines)),
            (D::DreamMachineSE, Some(F::DreamMachines)),
            (D::DreamRouter, Some(F::DreamRouters)),
            (D::DreamWall, Some(F::DreamWall)),
            (D::CloudGatewayUltra, Some(F::CloudGateways)),
            (D::CloudGatewayMax, Some(F::CloudGateways)),
            (D::CloudKeyGen2Plus, None),
            (D::SecurityGateway, None),
            (D::SecurityGatewayPro4, None),
            (D::AccessPoint, None),
            (D::Switch, None),
            (D::Unknown, None),
        ] {
            assert_eq!(GatewayFamily::from_device(d), want, "{d:?}");
        }
    }

    #[test]
    fn family_from_model_codes() {
        use GatewayFamily as F;
        for (model, want) in [
            ("UDMPRO", Some(F::DreamMachines)),
            ("UDM", Some(F::DreamMachines)),
            ("UDR", Some(F::DreamRouters)),
            ("UDW", Some(F::DreamWall)),
            ("UCG-Ultra", Some(F::CloudGateways)),
            ("UCGMAX", Some(F::CloudGateways)),
            ("U7PG2", None),
            ("USW-24-PoE", None),
            ("UCK-G2-PLUS", None),
            ("USG", None),
            ("UXG", None),
            ("", None),
        ] {
            assert_eq!(GatewayFamily::from_model(model), want, "{model}");
        }
    }

    #[test]
    fn parse_version_accepts_unifi_formats() {
        assert_eq!(parse_version("4.0.6.6754"), Some(vec![4, 0, 6, 6754]));
        assert_eq!(parse_version("5.0.12"), Some(vec![5, 0, 12]));
        assert_eq!(parse_version("7.0.50.15116"), Some(vec![7, 0, 50, 15116]));
        assert_eq!(parse_version(" v5.1.31 "), Some(vec![5, 1, 31]));
        assert_eq!(parse_version("5.1"), Some(vec![5, 1]));
    }

    #[test]
    fn parse_version_rejects_other_text() {
        for raw in [
            "",
            "5",
            "5.",
            ".5.1",
            "5..1",
            "5.1.x",
            "5.1.31-beta",
            "+5.1.31",
            "5.1.+3",
            "1.2.3.4.5.6.7.8.9",
            "5.1.9999999999",
            "unknown",
            "v",
            "５.1.31",
        ] {
            assert_eq!(parse_version(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn compare_versions_pads_with_zero() {
        assert_eq!(
            compare_versions(&[5, 1, 31], &[5, 1, 31, 0]),
            Ordering::Equal
        );
        assert_eq!(
            compare_versions(&[5, 1, 31, 1], &[5, 1, 31]),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions(&[5, 1, 30, 9999], &[5, 1, 31]),
            Ordering::Less
        );
        assert_eq!(compare_versions(&[5, 2], &[5, 1, 31]), Ordering::Greater);
        assert_eq!(compare_versions(&[4, 9, 99], &[5, 1, 26]), Ordering::Less);
    }

    #[test]
    fn verdict_edges() {
        use GatewayFamily as F;
        assert_eq!(below_sab069_floor(F::DreamMachines, "5.1.30"), Some(true));
        assert_eq!(below_sab069_floor(F::DreamMachines, "5.1.31"), Some(false));
        assert_eq!(
            below_sab069_floor(F::DreamMachines, "5.1.31.1234"),
            Some(false)
        );
        assert_eq!(
            below_sab069_floor(F::DreamMachines, "4.0.6.6754"),
            Some(true)
        );
        assert_eq!(below_sab069_floor(F::DreamMachines, "6.0.17"), Some(false));
        assert_eq!(below_sab069_floor(F::Express, "4.0.20"), Some(true));
        assert_eq!(below_sab069_floor(F::Express, "4.0.21"), Some(false));
        assert_eq!(below_sab069_floor(F::UniFiGateways, "5.1.25"), Some(true));
        assert_eq!(below_sab069_floor(F::UniFiGateways, "5.1.26"), Some(false));
        assert_eq!(below_sab069_floor(F::DreamMachines, "garbage"), None);
    }

    #[test]
    fn finding_below_floor() {
        let f = sab069_finding(GatewayFamily::DreamMachines, "4.0.6.6754", "UDMPRO").unwrap();
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert_eq!(f.cve_ids.len(), SAB_069_CVES.len());
        assert!(f.cve_ids.iter().any(|c| c == "CVE-2026-77555"));
        assert!(f.references.iter().any(|r| r == SAB_069_CVE_RECORD_URL));
        let rem = f.remediation.unwrap();
        assert!(
            rem.steps
                .iter()
                .any(|s| s.contains("Settings > Control Plane > Updates"))
        );
        assert!(rem.steps.iter().any(|s| s.contains(UNIFI_UPDATES_URL)));
        assert!(rem.description.contains("5.1.31"));
    }

    #[test]
    fn no_finding_at_floor_or_unparseable() {
        assert!(sab069_finding(GatewayFamily::DreamMachines, "5.1.31", "x").is_none());
        assert!(sab069_finding(GatewayFamily::DreamMachines, "", "x").is_none());
    }

    #[test]
    fn audit_adopted_devices_branches() {
        let mut named = adopted("UDMPRO", "4.0.6.6754");
        named.name = Some("Gateway".to_owned());
        let mut bad_ip = adopted("UDR", "5.0.12");
        bad_ip.ip = Some("not-an-ip".to_owned());
        let devices = [
            named,
            bad_ip,
            adopted("UDMPRO", "5.1.31"),
            adopted("U7PG2", "7.0.50.15116"),
            adopted("UXG", "1.0.0"),
            adopted("UDM", "unknown"),
        ];
        let findings = audit_adopted_devices(&devices);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.ends_with("Gateway"));
        assert_eq!(findings[0].affected_ip, Some(ip(1)));
        assert!(findings[0].affected_mac.is_some());
        assert!(findings[1].title.ends_with("UDR"));
        assert_eq!(findings[1].affected_ip, None);
    }

    fn ubnt(last: u8, ty: DeviceType) -> Device {
        let mut d = Device::new(ip(last)).with_device_type(ty);
        d.vendor = Some("Ubiquiti Inc".to_owned());
        d
    }

    #[test]
    fn advisory_once_for_several_gateways_gateway_first() {
        let mut sub = ubnt(5, DeviceType::Unknown);
        sub.device_subtype = Some("unifi_gateway".to_owned());
        let devices = [
            sub,
            ubnt(1, DeviceType::Router),
            ubnt(1, DeviceType::Router),
            ubnt(20, DeviceType::AccessPoint),
        ];
        let f = uncredentialed_advisory(&devices, Some(ip(1))).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.cve_ids.is_empty());
        assert_eq!(f.affected_ip, Some(ip(1)));
        assert!(f.description.contains("192.168.1.1, 192.168.1.5"));
        assert!(!f.description.contains("192.168.1.20"));
        assert!(f.description.contains("5.1.31 on Dream Machines"));
        assert!(f.description.contains("4.0.21 on Express"));
        assert!(f.description.contains("5.1.26 on UniFi Gateways"));
        assert!(f.remediation.is_some());
    }

    #[test]
    fn advisory_matches_gateway_ip_and_carries_mac() {
        let d = ubnt(1, DeviceType::Unknown).with_mac("aa:bb:cc:dd:ee:ff");
        let f = uncredentialed_advisory(&[d], Some(ip(1))).unwrap();
        assert!(f.affected_mac.is_some());
    }

    #[test]
    fn advisory_none_without_unifi_gateway() {
        assert!(uncredentialed_advisory(&[], None).is_none());
        let ap = ubnt(20, DeviceType::AccessPoint);
        assert!(uncredentialed_advisory(&[ap], Some(ip(1))).is_none());
        let other = Device::new(ip(1)).with_device_type(DeviceType::Router);
        assert!(uncredentialed_advisory(&[other], Some(ip(1))).is_none());
    }

    proptest! {
        #[test]
        fn prop_parse_version_never_panics(s in "\\PC{0,40}") {
            let _ = parse_version(&s);
            let _ = below_sab069_floor(GatewayFamily::Express, &s);
        }

        #[test]
        fn prop_parse_version_round_trips(parts in proptest::collection::vec(0_u32..1_000_000, 2..=8)) {
            let s = parts.iter().map(u32::to_string).collect::<Vec<_>>().join(".");
            prop_assert_eq!(parse_version(&s), Some(parts));
        }

        #[test]
        fn prop_compare_antisymmetric(
            a in proptest::collection::vec(0_u32..50, 0..6),
            b in proptest::collection::vec(0_u32..50, 0..6),
        ) {
            prop_assert_eq!(compare_versions(&a, &b), compare_versions(&b, &a).reverse());
        }
    }
}
