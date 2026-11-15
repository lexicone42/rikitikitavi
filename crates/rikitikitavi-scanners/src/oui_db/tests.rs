use super::*;
use proptest::prelude::*;

#[test]
fn test_lookup_apple() {
    // Apple has many OUIs; a4:83:e7 is one
    assert_eq!(ieee_oui_lookup("a4:83:e7:1a:2b:3c"), Some("Apple"));
}

#[test]
fn test_lookup_case_insensitive() {
    assert_eq!(ieee_oui_lookup("A4:83:E7:1A:2B:3C"), Some("Apple"));
}

#[test]
fn test_lookup_dashes() {
    assert_eq!(ieee_oui_lookup("A4-83-E7-1A-2B-3C"), Some("Apple"));
}

#[test]
fn test_lookup_no_separator() {
    assert_eq!(ieee_oui_lookup("a483e71a2b3c"), Some("Apple"));
}

#[test]
fn test_lookup_unknown() {
    assert_eq!(ieee_oui_lookup("ff:ff:ff:00:00:00"), None);
}

#[test]
fn test_lookup_cisco() {
    // 00:00:0C is a well-known Cisco OUI
    assert!(
        matches!(ieee_oui_lookup("00:00:0C:aa:bb:cc"), Some(v) if v.contains("Cisco") || v == "Cisco")
    );
}

#[test]
fn test_lookup_ma_m() {
    assert_eq!(ieee_oui_lookup("04:a1:6f:10:4a:d4"), Some("iENSO"));
    assert_eq!(ieee_oui_lookup("DC-44-27-1A-BB-CC"), Some("Tesla,Inc."));
}

#[test]
fn test_lookup_ma_s() {
    assert_eq!(ieee_oui_lookup("70b3.d59f.0abc"), Some("FUJICOM"));
}

#[test]
fn test_lookup_subdivided_block_without_assignment() {
    // 70:B3:D5 is an MA-S parent block; 70B3D59F3 is a Registration Authority row.
    assert_eq!(ieee_oui_lookup("70:b3:d5:9f:3a:bc"), None);
}

#[test]
fn test_lookup_short_input_skips_longer_tables() {
    assert_eq!(ieee_oui_lookup("04:a1:6f"), None);
    assert_eq!(ieee_oui_lookup("04:a1:6f:1"), Some("iENSO"));
}

#[test]
fn test_no_registration_authority_rows() {
    let names = OUI_DB
        .iter()
        .map(|e| e.1)
        .chain(MAM_DB.iter().map(|e| e.1))
        .chain(MAS_DB.iter().map(|e| e.1));
    for name in names {
        assert_ne!(name, "IEEE Registration Authority");
    }
}

fn assert_strictly_sorted<K: Ord + std::fmt::Debug>(name: &str, table: &[(K, &str)]) {
    for window in table.windows(2) {
        assert!(
            window[0].0 < window[1].0,
            "{name} not sorted or not unique: {:?} >= {:?}",
            window[0].0,
            window[1].0
        );
    }
}

#[test]
fn test_db_is_sorted() {
    assert_strictly_sorted("OUI_DB", OUI_DB);
    assert_strictly_sorted("MAM_DB", MAM_DB);
    assert_strictly_sorted("MAS_DB", MAS_DB);
}

#[test]
fn test_keys_fit_prefix_width() {
    assert!(MAM_DB.iter().all(|e| e.0 < 1 << 28));
    assert!(MAS_DB.iter().all(|e| e.0 < 1 << 36));
}

#[test]
fn test_db_has_entries() {
    assert!(OUI_DB.len() > 30_000, "expected >30K MA-L entries");
    assert!(MAM_DB.len() > 5_000, "expected >5K MA-M entries");
    assert!(MAS_DB.len() > 5_000, "expected >5K MA-S entries");
}

#[test]
fn test_longest_prefix_wins() {
    let ma_l = &[([0x11, 0x22, 0x33], "L")];
    let ma_m = &[(0x112_2334, "M")];
    let ma_s = &[(0x1_1223_3445, "S")];
    assert_eq!(lookup_in(ma_l, ma_m, ma_s, "11:22:33:44:5f:ff"), Some("S"));
    assert_eq!(lookup_in(ma_l, ma_m, ma_s, "11:22:33:46:00:00"), Some("M"));
    assert_eq!(lookup_in(ma_l, ma_m, ma_s, "11:22:33:50:00:00"), Some("L"));
    assert_eq!(lookup_in(ma_l, ma_m, ma_s, "11:22:34:44:50:00"), None);
}

#[test]
fn test_parse_mac_prefix_short() {
    assert_eq!(parse_mac_prefix("aa:bb"), None);
}

#[test]
fn test_parse_mac_prefix_dot_format() {
    // Cisco-style: aabb.ccdd.eeff
    assert_eq!(parse_mac_prefix("a483.e71a.2b3c"), Some([0xA4, 0x83, 0xE7]));
}

/// Render `mac` as colon (0), dash (1), dotted (2) or bare (3); bit `i` of
/// `case_mask` upper-cases hex digit `i`.
fn render_mac(mac: [u8; 6], style: u8, case_mask: u16) -> String {
    let sep = match style % 4 {
        0 => ":",
        1 => "-",
        2 => ".",
        _ => "",
    };
    let group = if style % 4 == 2 { 4 } else { 2 };
    let mut out = String::new();
    for (i, nibble) in mac.iter().flat_map(|b| [b >> 4, b & 0x0f]).enumerate() {
        if i > 0 && i % group == 0 {
            out.push_str(sep);
        }
        let c = char::from_digit(u32::from(nibble), 16).unwrap();
        out.push(if case_mask & (1_u16 << i) != 0 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

proptest! {
    /// Every table entry is found by its own OUI and has a non-empty vendor name.
    #[test]
    fn prop_table_entry_lookup(idx in 0..OUI_DB.len()) {
        let (oui, vendor) = OUI_DB[idx];
        prop_assert!(!vendor.is_empty());
        let mac = render_mac([oui[0], oui[1], oui[2], 0, 0, 0], 0, 0);
        prop_assert_eq!(ieee_oui_lookup(&mac), Some(vendor));
    }

    /// Every MA-M entry is found by any MAC inside its block.
    #[test]
    fn prop_ma_m_entry_lookup(idx in 0..MAM_DB.len(), low in 0..(1_u64 << 20)) {
        let (prefix, vendor) = MAM_DB[idx];
        let mac = (u64::from(prefix) << 20 | low).to_be_bytes();
        let text = render_mac([mac[2], mac[3], mac[4], mac[5], mac[6], mac[7]], 0, 0);
        prop_assert_eq!(ieee_oui_lookup(&text), Some(vendor), "{}", text);
    }

    /// Every MA-S entry is found by any MAC inside its block.
    #[test]
    fn prop_ma_s_entry_lookup(idx in 0..MAS_DB.len(), low in 0..(1_u64 << 12)) {
        let (prefix, vendor) = MAS_DB[idx];
        let mac = (prefix << 12 | low).to_be_bytes();
        let text = render_mac([mac[2], mac[3], mac[4], mac[5], mac[6], mac[7]], 0, 0);
        prop_assert_eq!(ieee_oui_lookup(&text), Some(vendor), "{}", text);
    }

    /// With overlapping blocks the longest matching prefix wins; lookup never panics.
    #[test]
    fn prop_longest_prefix_wins(mac in any::<[u8; 6]>(), style in 0..4_u8) {
        let value = mac.iter().fold(0_u64, |acc, &b| acc << 8 | u64::from(b));
        let ma_l = &[([mac[0], mac[1], mac[2]], "L")];
        let ma_m = &[(u32::try_from(value >> 20).unwrap(), "M")];
        let ma_s = &[(value >> 12, "S")];
        let text = render_mac(mac, style, 0);
        prop_assert_eq!(lookup_in(ma_l, ma_m, ma_s, &text), Some("S"));
        prop_assert_eq!(lookup_in(ma_l, ma_m, &[], &text), Some("M"));
        prop_assert_eq!(lookup_in(ma_l, &[], &[], &text), Some("L"));
        prop_assert_eq!(lookup_in(&[], &[], &[], &text), None);
        let _ = ieee_oui_lookup(&text);
    }

    /// `ieee_oui_lookup` never panics on arbitrary input.
    #[test]
    fn prop_lookup_no_panic(s in ".*") {
        let _ = ieee_oui_lookup(&s);
    }

    /// Colon, dash, dotted, bare and any-case renderings parse to the same OUI and vendor.
    #[test]
    fn prop_mac_format_invariance(mac in any::<[u8; 6]>(), case_mask in any::<u16>()) {
        let oui = [mac[0], mac[1], mac[2]];
        let expected = ieee_oui_lookup(&render_mac(mac, 0, 0));
        for style in 0..4_u8 {
            for mask in [0, u16::MAX, case_mask] {
                let text = render_mac(mac, style, mask);
                prop_assert_eq!(parse_mac_prefix(&text), Some(oui), "{}", text);
                prop_assert_eq!(ieee_oui_lookup(&text), expected, "{}", text);
            }
        }
    }

    /// `parse_mac_prefix` never panics; a hit needs at least six hex digits.
    #[test]
    fn prop_parse_mac_prefix_no_panic(s in ".*") {
        if parse_mac_prefix(&s).is_some() {
            prop_assert!(s.chars().filter(char::is_ascii_hexdigit).count() >= 6);
        }
    }

    /// Over hex digits and separators only, a hit is exactly "at least six hex digits".
    #[test]
    fn prop_parse_mac_prefix_hex_and_separators(s in "[0-9a-fA-F:.\\-]{0,20}") {
        let hex_digits = s.chars().filter(char::is_ascii_hexdigit).count();
        prop_assert_eq!(parse_mac_prefix(&s).is_some(), hex_digits >= 6);
    }
}
