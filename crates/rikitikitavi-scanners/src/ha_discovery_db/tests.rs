use super::*;
use proptest::prelude::*;

// ── Table invariants ────────────────────────────────────────────────

/// Sorted by service type: [`zeroconf_domains`] uses `partition_point`.
#[test]
fn zeroconf_table_is_sorted_by_service_type() {
    assert!(
        ZEROCONF_MATCHERS
            .windows(2)
            .all(|w| w[0].service_type <= w[1].service_type)
    );
}

/// Strictly ascending: [`homekit_domain`] and the model set assume no duplicates.
#[test]
fn homekit_table_is_strictly_sorted() {
    assert!(HOMEKIT_MODELS.windows(2).all(|w| w[0].0 < w[1].0));
}

#[test]
fn ssdp_table_is_sorted_by_domain() {
    assert!(SSDP_MATCHERS.windows(2).all(|w| w[0].domain <= w[1].domain));
}

/// Sorted by nibble string: [`mac_prefix_match`] uses `partition_point`.
#[test]
fn mac_prefix_table_is_sorted() {
    assert!(
        DHCP_MAC_PREFIXES
            .windows(2)
            .all(|w| (w[0].nibbles, w[0].domain) <= (w[1].nibbles, w[1].domain))
    );
}

/// Strictly ascending: [`domain_device_type`] binary-searches it.
#[test]
fn domain_type_table_is_strictly_sorted() {
    assert!(DOMAIN_DEVICE_TYPES.windows(2).all(|w| w[0].0 < w[1].0));
}

// ── Format invariance ───────────────────────────────────────────────

#[test]
fn zeroconf_entries_are_normalised() {
    for m in ZEROCONF_MATCHERS {
        assert_eq!(m.service_type, m.service_type.to_ascii_lowercase());
        assert!(m.service_type.starts_with('_'), "{}", m.service_type);
        assert!(!m.service_type.ends_with('.'), "{}", m.service_type);
        assert!(
            m.service_type
                .rsplit_once('.')
                .is_some_and(|(_, tld)| tld == "local"),
            "{}",
            m.service_type
        );
        assert!(!m.domain.is_empty());
        if let Some(name) = m.name {
            assert_eq!(name, name.to_ascii_lowercase());
            // The glob matcher implements `*` and `?` only.
            assert!(!name.contains('['), "{name}");
        }
        for &(key, glob) in m.properties {
            assert_eq!(key, key.to_ascii_lowercase());
            assert_eq!(glob, glob.to_ascii_lowercase());
            assert!(!glob.contains('['), "{glob}");
        }
    }
}

#[test]
fn mac_prefixes_are_uppercase_hex_within_bounds() {
    for p in DHCP_MAC_PREFIXES {
        assert!(!p.nibbles.is_empty());
        assert!(p.nibbles.len() <= MAX_MAC_PREFIX_NIBBLES, "{}", p.nibbles);
        assert!(
            p.nibbles
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
            "{}",
            p.nibbles
        );
    }
}

#[test]
fn ssdp_matchers_constrain_at_least_one_field() {
    for m in SSDP_MATCHERS {
        let any = m.st.is_some()
            || m.nt.is_some()
            || m.device_type.is_some()
            || m.manufacturer.is_some()
            || m.manufacturer_url.is_some()
            || m.model_name.is_some()
            || m.model_description.is_some();
        assert!(any, "unconstrained SSDP matcher for {}", m.domain);
    }
}

/// A typo in our hand-written domain map would silently never fire.
#[test]
fn mapped_domains_all_occur_in_an_upstream_table() {
    let mut known: std::collections::HashSet<&str> = std::collections::HashSet::new();
    known.extend(ZEROCONF_MATCHERS.iter().map(|m| m.domain));
    known.extend(HOMEKIT_MODELS.iter().map(|&(_, d)| d));
    known.extend(SSDP_MATCHERS.iter().map(|m| m.domain));
    known.extend(DHCP_MAC_PREFIXES.iter().map(|p| p.domain));

    for &(domain, _) in DOMAIN_DEVICE_TYPES {
        assert!(
            known.contains(domain),
            "unknown domain in our map: {domain}"
        );
    }
}

// ── Every row is reachable through its lookup ───────────────────────

#[test]
fn every_unconditional_zeroconf_row_is_found() {
    for m in ZEROCONF_MATCHERS {
        if m.name.is_some() || !m.properties.is_empty() {
            continue;
        }
        let full = format!("instance.{}.", m.service_type);
        let found = zeroconf_domains(m.service_type, &full, &[]);
        assert!(found.contains(&m.domain), "{} {}", m.service_type, m.domain);
    }
}

#[test]
fn every_homekit_model_is_found() {
    for &(model, domain) in HOMEKIT_MODELS {
        assert_eq!(homekit_domain(model), Some(domain), "{model}");
        assert_eq!(homekit_domain(&format!("{model} Pro")), Some(domain));
    }
}

#[test]
fn every_mac_prefix_is_found() {
    for p in DHCP_MAC_PREFIXES {
        // Pad to a full 12-nibble MAC so the lookup sees a realistic input.
        let mac = format!("{:0<12}", p.nibbles);
        let hit = mac_prefix_match(&mac).unwrap_or_else(|| panic!("{}", p.nibbles));
        assert!(
            hit.domains.contains(&p.domain),
            "{} {}",
            p.nibbles,
            p.domain
        );
    }
}

#[test]
fn every_ssdp_row_is_found() {
    for m in SSDP_MATCHERS {
        let observed = SsdpFields {
            st: m.st,
            nt: m.nt,
            device_type: m.device_type,
            manufacturer: m.manufacturer,
            manufacturer_url: m.manufacturer_url,
            model_name: m.model_name,
            model_description: m.model_description,
        };
        assert!(ssdp_domains(&observed).contains(&m.domain), "{}", m.domain);
    }
}

/// The network crate's query list must cover every service type we can classify.
#[test]
fn service_queries_cover_every_zeroconf_type() {
    // DNS labels are case-insensitive (RFC 6762 §16); our table is lowercased.
    for m in ZEROCONF_MATCHERS {
        assert!(
            rikitikitavi_network::mdns::SERVICE_QUERIES
                .iter()
                .any(|q| q.eq_ignore_ascii_case(m.service_type)),
            "not queried: {}",
            m.service_type
        );
    }
}

// ── Lookup behaviour ────────────────────────────────────────────────

#[test]
fn glob_match_handles_stars_and_question_marks() {
    assert!(glob_match(
        "shelly*",
        "shellyplus1-aabbcc._http._tcp.local."
    ));
    assert!(glob_match("*zigate*", "my-zigate-gw._tcp.local."));
    assert!(glob_match("*", ""));
    assert!(glob_match("ab?d", "abcd"));
    assert!(!glob_match("ab?d", "abd"));
    assert!(!glob_match("shelly*", "tasmota-1._http._tcp.local."));
    assert!(glob_match("", ""));
    assert!(!glob_match("", "x"));
}

/// `_http._tcp` carries 27 matchers over 24 integrations; a flat pair table would
/// claim every mDNS HTTP responder.
#[test]
fn http_service_type_requires_a_name_or_property_match() {
    let generic = zeroconf_domains("_http._tcp.local", "printer._http._tcp.local.", &[]);
    assert!(generic.is_empty(), "{generic:?}");

    let shelly = zeroconf_domains(
        "_http._tcp.local",
        "shellyplus1pm-a0b1c2._http._tcp.local.",
        &[],
    );
    assert_eq!(shelly, vec!["shelly"]);
    assert_eq!(domain_device_type("shelly"), DeviceType::SmartPlug);
}

/// `_amzn-alexa._tcp` maps to roomba in HA, gated on the instance name — it is
/// not an Amazon Echo.
#[test]
fn amazon_alexa_service_type_only_matches_irobot_names() {
    let echo = zeroconf_domains(
        "_amzn-alexa._tcp.local",
        "echo._amzn-alexa._tcp.local.",
        &[],
    );
    assert!(echo.is_empty(), "{echo:?}");

    let roomba = zeroconf_domains(
        "_amzn-alexa._tcp.local",
        "roomba-31a._amzn-alexa._tcp.local.",
        &[],
    );
    assert_eq!(roomba, vec!["roomba"]);
    assert_eq!(domain_device_type("roomba"), DeviceType::Vacuum);
}

/// `_axis-video` serves both Axis cameras and `DoorBird` doorbells; upstream
/// separates them on the `macaddress` TXT key, not on the service type.
#[test]
fn axis_video_is_split_by_mac_property() {
    let bare = zeroconf_domains("_axis-video._tcp.local", "cam._axis-video._tcp.local.", &[]);
    assert!(bare.is_empty(), "{bare:?}");

    let axis = vec!["macaddress=00408C123456".to_owned()];
    let found = zeroconf_domains(
        "_axis-video._tcp.local",
        "cam._axis-video._tcp.local.",
        &axis,
    );
    assert_eq!(found, vec!["axis"]);
    assert_eq!(consensus_device_type(&found), DeviceType::Camera);

    let doorbird = vec!["macaddress=1CCAE3AABBCC".to_owned()];
    let found = zeroconf_domains(
        "_axis-video._tcp.local",
        "bell._axis-video._tcp.local.",
        &doorbird,
    );
    assert_eq!(found, vec!["doorbird"]);
    assert_eq!(consensus_device_type(&found), DeviceType::Doorbell);
}

/// One-to-many service types must not silently pick a winner.
#[test]
fn disagreeing_domains_yield_no_consensus_type() {
    let domains = zeroconf_domains(
        "_esphomelib._tcp.local",
        "tube-zb-gw._esphomelib._tcp.local.",
        &[],
    );
    assert_eq!(domains.len(), 2, "{domains:?}");
    assert!(domains.contains(&"esphome") && domains.contains(&"zha"));
    // IoT node vs Zigbee coordinator disagree, so no type is asserted.
    assert_eq!(consensus_device_type(&domains), DeviceType::Unknown);
}

#[test]
fn consensus_ignores_unmapped_domains() {
    assert_eq!(
        consensus_device_type(&["sonos", "no_such_integration"]),
        DeviceType::Speaker
    );
    assert_eq!(consensus_device_type(&[]), DeviceType::Unknown);
}

#[test]
fn zeroconf_property_predicates_are_checked() {
    let txt = vec!["model=AppleTV6,2".to_owned()];
    let appletv = zeroconf_domains("_airplay._tcp.local", "living._airplay._tcp.local.", &txt);
    assert!(appletv.contains(&"apple_tv"), "{appletv:?}");

    let samsung = vec!["manufacturer=Samsung Electronics".to_owned()];
    let tv = zeroconf_domains("_airplay._tcp.local", "tv._airplay._tcp.local.", &samsung);
    assert!(tv.contains(&"samsungtv"), "{tv:?}");
    assert_eq!(domain_device_type("samsungtv"), DeviceType::SmartTv);
}

/// Nibble-granular prefixes: a 7-nibble entry must not widen to its 3-byte OUI,
/// and it is the only kind allowed to assert a device class.
#[test]
fn longer_prefixes_win_and_do_not_widen() {
    let my_pv = mac_prefix_match("98:6D:35:C1:BB:CC").expect("7-nibble prefix");
    assert_eq!(my_pv.nibbles, 7);
    assert_eq!(my_pv.domains, vec!["my_pv"]);
    assert!(my_pv.finer_than_oui());
    assert_eq!(domain_device_type("my_pv"), DeviceType::Inverter);

    // The same OUI with a different fourth nibble matches nothing.
    assert!(mac_prefix_match("98:6D:35:01:BB:CC").is_none());
}

/// A whole-OUI prefix names the registrant; callers must not read a class out.
#[test]
fn oui_length_prefixes_are_not_finer_than_the_oui() {
    let unifi = mac_prefix_match("B4:FB:E4:11:22:33").expect("Ubiquiti OUI");
    assert_eq!(unifi.nibbles, OUI_NIBBLES);
    assert_eq!(unifi.domains, vec!["unifi_discovery"]);
    assert!(!unifi.finer_than_oui());
    // Ubiquiti's OUIs cover APs, switches, gateways and cameras alike, so the
    // domain is carried as a subtype with no `DeviceType` behind it.
    assert_eq!(domain_device_type("unifi_discovery"), DeviceType::Unknown);
}

/// Upstream ANDs `hostname` with `macaddress` in 154 of its 257 MAC entries; we
/// cannot evaluate a hostname, so none of those rows may be carried.
#[test]
fn only_mac_only_upstream_rows_are_carried() {
    assert_eq!(DHCP_MAC_PREFIXES.len(), 103);
    // `august` pairs `connect`/`august*` with WNC and AMPAK module OUIs, and
    // `ring`/`tesla_wall_connector` are hostname-gated too.
    for domain in ["august", "ring", "tesla_wall_connector"] {
        assert!(
            !DHCP_MAC_PREFIXES.iter().any(|p| p.domain == domain),
            "{domain}"
        );
    }
    assert!(mac_prefix_match("D8:61:62:AA:BB:CC").is_none());
    assert!(mac_prefix_match("E0:76:D0:AA:BB:CC").is_none());
}

#[test]
fn unknown_mac_and_domain_yield_nothing() {
    assert!(mac_prefix_match("02:00:00:00:00:01").is_none());
    assert!(mac_prefix_match("").is_none());
    assert_eq!(domain_device_type("nope"), DeviceType::Unknown);
}

#[test]
fn ssdp_st_only_matcher_types_sonos() {
    let observed = SsdpFields {
        st: Some("urn:schemas-upnp-org:device:ZonePlayer:1"),
        ..SsdpFields::default()
    };
    let domains = ssdp_domains(&observed);
    assert!(domains.contains(&"sonos"), "{domains:?}");
    assert_eq!(consensus_device_type(&domains), DeviceType::Speaker);
}

#[test]
fn ssdp_empty_observation_matches_nothing() {
    assert!(ssdp_domains(&SsdpFields::default()).is_empty());
}

/// A manufacturer-only matcher identifies the integration but not the device
/// class: Belkin ships routers as well as `WeMo` plugs.
#[test]
fn vendor_only_ssdp_matchers_are_not_specific() {
    let wemo = ssdp_hits(&SsdpFields {
        manufacturer: Some("Belkin International Inc."),
        ..SsdpFields::default()
    });
    assert_eq!(wemo.len(), 1, "{wemo:?}");
    assert_eq!(wemo[0].domain, "wemo");
    assert!(!wemo[0].specific);

    let udm = ssdp_hits(&SsdpFields {
        manufacturer: Some("Ubiquiti Networks"),
        model_description: Some("UniFi Dream Machine"),
        ..SsdpFields::default()
    });
    assert_eq!(udm.len(), 1, "{udm:?}");
    assert!(udm[0].specific);

    let sonos = ssdp_hits(&SsdpFields {
        st: Some("urn:schemas-upnp-org:device:ZonePlayer:1"),
        ..SsdpFields::default()
    });
    assert!(sonos.iter().all(|h| h.specific), "{sonos:?}");
}

// ── Proptest: never panic on arbitrary input ────────────────────────

proptest! {
    #[test]
    fn prop_glob_match_no_panic(pattern in ".*", value in ".*") {
        let _ = glob_match(&pattern, &value);
    }

    #[test]
    fn prop_mac_prefix_match_no_panic(mac in ".*") {
        let _ = mac_prefix_match(&mac);
    }

    #[test]
    fn prop_ssdp_hits_no_panic(
        st in ".*", manufacturer in ".*", model_name in ".*",
    ) {
        let _ = ssdp_hits(&SsdpFields {
            st: Some(&st),
            manufacturer: Some(&manufacturer),
            model_name: Some(&model_name),
            ..SsdpFields::default()
        });
    }

    #[test]
    fn prop_zeroconf_domains_no_panic(
        service_type in ".*",
        name in ".*",
        txt in proptest::collection::vec(".*", 0..8),
    ) {
        let _ = zeroconf_domains(&service_type, &name, &txt);
    }

    #[test]
    fn prop_homekit_domain_no_panic(model in ".*") {
        let _ = homekit_domain(&model);
    }
}
