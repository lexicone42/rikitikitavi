use super::*;
use proptest::prelude::*;
use std::net::Ipv4Addr;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
const TODAY: &str = "2026-11-14";

fn service(txt: &[&str]) -> MdnsService {
    MdnsService {
        name: "Living Room".to_owned(),
        service_type: "_airplay._tcp.local".to_owned(),
        hostname: "Living-Room.local".to_owned(),
        ip: IP,
        port: 7000,
        txt_records: txt.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn hint() -> DeviceHint {
    DeviceHint::new()
}

#[test]
fn osvers_parses_one_to_three_components() {
    assert_eq!(parse_osvers("18"), Some((18, 0, 0)));
    assert_eq!(parse_osvers("18.4"), Some((18, 4, 0)));
    assert_eq!(parse_osvers(" 17.5.1 "), Some((17, 5, 1)));
}

#[test]
fn osvers_rejects_malformed() {
    for bad in [
        "",
        "18.",
        ".4",
        "18..4",
        "1.2.3.4",
        "+18.4",
        "18.4b",
        "v18",
        "18,4",
        "99999999999",
    ] {
        assert_eq!(parse_osvers(bad), None, "{bad}");
    }
    assert_eq!(parse_osvers(&"1".repeat(33)), None);
}

#[test]
fn flags_parse_with_and_without_prefix() {
    assert_eq!(parse_flags("0x10644"), Some(0x10644));
    assert_eq!(parse_flags("0X4"), Some(4));
    assert_eq!(parse_flags("644"), Some(0x644));
}

#[test]
fn flags_reject_malformed() {
    for bad in ["", "0x", "0x+4", "+4", "0xg", "0x11111111111111111", "-1"] {
        assert_eq!(parse_flags(bad), None, "{bad}");
    }
}

#[test]
fn pw_values() {
    assert_eq!(parse_pw("true"), Some(true));
    assert_eq!(parse_pw("TRUE"), Some(true));
    assert_eq!(parse_pw("1"), Some(true));
    assert_eq!(parse_pw("false"), Some(false));
    assert_eq!(parse_pw("0"), Some(false));
    assert_eq!(parse_pw("yes"), None);
}

#[test]
fn tvos_hardware_is_generation_five_and_up() {
    assert!(is_tvos_hardware("AppleTV5,3"));
    assert!(is_tvos_hardware("AppleTV6,2"));
    assert!(is_tvos_hardware("AppleTV14,1"));
    assert!(!is_tvos_hardware("AppleTV3,2"));
    assert!(!is_tvos_hardware("AppleTV"));
    assert!(!is_tvos_hardware("AppleTV6,"));
    assert!(!is_tvos_hardware("AppleTV,2"));
    assert!(!is_tvos_hardware("AppleTVx,2"));
    assert!(!is_tvos_hardware("AppleTV6,2a"));
    assert!(!is_tvos_hardware("AudioAccessory5,1"));
    assert!(!is_tvos_hardware("Mac14,3"));
}

#[test]
fn floor_table_is_sorted_and_cites_apple() {
    assert!(TVOS_FIX_FLOORS.windows(2).all(|w| w[0].fixed <= w[1].fixed));
    for f in TVOS_FIX_FLOORS {
        assert!(f.cve.starts_with("CVE-"), "{}", f.cve);
        assert!(
            f.reference.starts_with("https://support.apple.com/"),
            "{}",
            f.cve
        );
    }
}

#[test]
fn unfixed_floors_by_version() {
    assert_eq!(unfixed_floors((26, 3, 0)), Vec::<&TvosFixFloor>::new());
    assert_eq!(unfixed_floors((27, 2, 1)), Vec::<&TvosFixFloor>::new());
    let cves = |v| unfixed_floors(v).iter().map(|f| f.cve).collect::<Vec<_>>();
    assert_eq!(cves((26, 2, 0)), ["CVE-2026-20700"]);
    assert_eq!(
        cves((26, 0, 1)),
        ["CVE-2025-43510", "CVE-2025-43520", "CVE-2026-20700"]
    );
    assert_eq!(cves((17, 4, 9)).len(), 5);
    assert_eq!(cves((15, 1, 0)).len(), 6);
}

#[test]
fn version_format_drops_zero_patch() {
    assert_eq!(format_version((26, 3, 0)), "26.3");
    assert_eq!(format_version((17, 6, 1)), "17.6.1");
}

#[test]
fn fix_finding_below_floor_is_high_confirmed() {
    let f = tvos_fix_finding(IP, 7000, "AppleTV11,1", "26.2", &hint()).expect("finding");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert_eq!(f.cve_ids, ["CVE-2026-20700"]);
    assert!(f.title.contains("tvOS 26.2"));
    assert!(f.description.contains("fixed in tvOS 26.3, in CISA KEV"));
    assert_eq!(f.references, ["https://support.apple.com/en-us/126351"]);
    let r = f.remediation.expect("remediation");
    assert!(r.description.contains("26.3"));
    assert!(r.steps[0].contains("Settings > System > Software Updates"));
    assert!(r.steps[1].contains("Automatically Update"));
    assert!(r.steps[2].contains("replace it"));
}

#[test]
fn fix_finding_dedups_references() {
    let f = tvos_fix_finding(IP, 7000, "AppleTV11,1", "26.0", &hint()).expect("finding");
    assert_eq!(f.cve_ids.len(), 3);
    assert_eq!(f.references.len(), 2);
}

#[test]
fn fix_finding_absent_when_current_or_not_tvos() {
    assert!(tvos_fix_finding(IP, 7000, "AppleTV11,1", "26.3", &hint()).is_none());
    assert!(tvos_fix_finding(IP, 7000, "AppleTV14,1", "27.2.1", &hint()).is_none());
    assert!(tvos_fix_finding(IP, 7000, "AudioAccessory5,1", "18.4", &hint()).is_none());
    assert!(tvos_fix_finding(IP, 7000, "Mac14,3", "15.1", &hint()).is_none());
    assert!(tvos_fix_finding(IP, 7000, "AppleTV3,2", "8.4", &hint()).is_none());
    assert!(tvos_fix_finding(IP, 7000, "AppleTV11,1", "garbage", &hint()).is_none());
}

#[test]
fn eol_finding_for_capped_model_recommends_replacement() {
    let f = tvos_eol_finding(IP, 7000, "AppleTV5,3", "26.6.1", TODAY, &hint()).expect("finding");
    assert!(f.title.starts_with("End-of-life tvOS 26"));
    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert!(f.description.contains("Apple TV HD"));
    assert!(f.description.contains("2026-09-14"));
    assert!(f.references.iter().any(|r| r == TVOS_27_NOTE));
    let r = f.remediation.expect("remediation");
    assert!(r.description.starts_with("Replace the Apple TV HD"));
    assert_eq!(r.effort.as_deref(), Some("requires hardware change"));
}

#[test]
fn eol_finding_for_capable_model_recommends_update() {
    let f = tvos_eol_finding(IP, 7000, "AppleTV11,1", "26.6", TODAY, &hint()).expect("finding");
    assert!(!f.references.iter().any(|r| r == TVOS_27_NOTE));
    let r = f.remediation.expect("remediation");
    let current = eol_db::current("tvos").expect("tvos current").cycle;
    assert_eq!(
        r.description,
        format!("Update the Apple TV to tvOS {current}.")
    );
    assert!(r.steps[2].contains(&format!("does not offer tvOS {current}")));
}

#[test]
fn eol_finding_absent_when_supported_or_unknown() {
    assert!(tvos_eol_finding(IP, 7000, "AppleTV11,1", "27.2", TODAY, &hint()).is_none());
    assert!(tvos_eol_finding(IP, 7000, "AppleTV11,1", "26.6", "2026-09-13", &hint()).is_none());
    assert!(tvos_eol_finding(IP, 7000, "AppleTV11,1", "8.4", TODAY, &hint()).is_none());
    assert!(tvos_eol_finding(IP, 7000, "AppleTV11,1", "x", TODAY, &hint()).is_none());
    assert!(tvos_eol_finding(IP, 7000, "AudioAccessory5,1", "18.4", TODAY, &hint()).is_none());
}

#[test]
fn posture_from_flags_and_pw() {
    use AirPlayAccess::{HomeKitControlled, Open, Restricted, Unknown};
    assert_eq!(access_posture(Some("0x4"), Some("false")), Open);
    assert_eq!(access_posture(Some("0x44"), None), Open);
    assert_eq!(access_posture(Some("0x8"), None), Restricted);
    assert_eq!(access_posture(Some("0x80"), None), Restricted);
    assert_eq!(access_posture(Some("0x200"), None), Restricted);
    assert_eq!(access_posture(Some("0x604"), None), Restricted);
    assert_eq!(
        access_posture(Some("0x404"), Some("false")),
        HomeKitControlled
    );
    assert_eq!(access_posture(Some("0x4"), Some("true")), Restricted);
    assert_eq!(access_posture(None, Some("true")), Restricted);
    assert_eq!(access_posture(None, Some("false")), Unknown);
    assert_eq!(access_posture(Some("zz"), None), Unknown);
}

#[test]
fn open_apple_tv_gets_low_probable_with_apple_path() {
    let svc = service(&["model=AppleTV11,1", "flags=0x44", "pw=false", "osvers=27.2"]);
    let f = access_finding(&svc, Some("AppleTV11,1"), &hint()).expect("finding");
    assert_eq!(f.severity, Severity::Low);
    assert_eq!(f.confidence, Confidence::Probable);
    assert!(
        f.description
            .contains("\"Everyone\" from \"Anyone on the Same Network\"")
    );
    assert!(f.references.iter().any(|r| r == ALLOW_ACCESS_GUIDE));
    let r = f.remediation.expect("remediation");
    assert!(r.steps[0].contains("Settings > AirPlay and HomeKit > Allow Access"));
    assert!(r.steps[0].contains("Only People Sharing This Home"));
    assert!(r.steps[1].contains("Require Password"));
}

#[test]
fn open_third_party_gets_generic_remediation() {
    let svc = service(&["model=AVR-X3800H", "flags=0x4"]);
    let f = access_finding(&svc, Some("AVR-X3800H"), &hint()).expect("finding");
    assert_eq!(f.severity, Severity::Low);
    assert!(!f.references.iter().any(|r| r == ALLOW_ACCESS_GUIDE));
    let r = f.remediation.expect("remediation");
    assert!(r.steps[0].contains("AirPlay access or password setting"));
    assert!(!r.steps.iter().any(|s| s.contains("Settings > AirPlay")));

    let unnamed = access_finding(&service(&["flags=0x4"]), None, &hint()).expect("finding");
    assert!(unnamed.description.contains("The AirPlay receiver at"));
}

#[test]
fn homekit_only_is_info() {
    let svc = service(&["model=AppleTV14,1", "flags=0x30444", "pw=false"]);
    let f = access_finding(&svc, Some("AppleTV14,1"), &hint()).expect("finding");
    assert_eq!(f.severity, Severity::Info);
    assert_eq!(f.confidence, Confidence::Probable);
    assert!(f.title.contains("HomeKit"));
}

#[test]
fn restricted_or_unknown_gives_no_access_finding() {
    for txt in [
        &["flags=0x8c"][..],
        &["flags=0x4", "pw=true"],
        &["flags=0x204"],
        &["pw=false"],
        &[],
    ] {
        assert!(
            access_finding(&service(txt), None, &hint()).is_none(),
            "{txt:?}"
        );
    }
}

#[test]
fn airplay_findings_combines_checks() {
    let svc = service(&["model=AppleTV6,2", "osvers=26.2", "flags=0x44", "pw=false"]);
    let findings = airplay_findings(&svc, &hint(), TODAY);
    let titles: Vec<_> = findings.iter().map(|f| f.title.as_str()).collect();
    assert_eq!(findings.len(), 3, "{titles:?}");
    assert!(titles[0].starts_with("tvOS 26.2 below"));
    assert!(titles[1].starts_with("End-of-life tvOS 26"));
    assert!(titles[2].starts_with("AirPlay receiver without password"));

    let homepod = service(&["model=AudioAccessory5,1", "osvers=18.4", "flags=0x404"]);
    let findings = airplay_findings(&homepod, &hint(), TODAY);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info);

    assert!(airplay_findings(&service(&["osvers=18.4"]), &hint(), TODAY).is_empty());
}

#[test]
fn classify_mdns_service_routes_airplay_only() {
    let svc = service(&["model=AppleTV11,1", "osvers=26.2", "flags=0x404"]);
    let findings = crate::mdns::classify_mdns_service(&svc);
    assert!(findings.iter().any(|f| f.title.starts_with("tvOS 26.2")));

    let mut raop = svc;
    raop.service_type = "_raop._tcp.local".to_owned();
    let findings = crate::mdns::classify_mdns_service(&raop);
    assert!(!findings.iter().any(|f| f.title.starts_with("tvOS")));
}

proptest! {
    #[test]
    fn prop_osvers_never_panics(s in ".{0,40}") {
        let _ = parse_osvers(&s);
    }

    #[test]
    fn prop_osvers_roundtrips(a in 0u32..100, b in 0u32..100, c in 1u32..100) {
        prop_assert_eq!(parse_osvers(&format!("{a}.{b}.{c}")), Some((a, b, c)));
    }

    #[test]
    fn prop_flags_never_panics(s in ".{0,40}") {
        let _ = parse_flags(&s);
        let _ = access_posture(Some(&s), Some(&s));
    }

    #[test]
    fn prop_flags_roundtrip(v in any::<u64>()) {
        prop_assert_eq!(parse_flags(&format!("{v:#x}")), Some(v));
    }

    #[test]
    fn prop_findings_never_panic(model in ".{0,20}", osvers in ".{0,20}", flags in ".{0,20}") {
        let svc = service(&[
            &format!("model={model}"),
            &format!("osvers={osvers}"),
            &format!("flags={flags}"),
        ]);
        let _ = airplay_findings(&svc, &hint(), TODAY);
    }
}
