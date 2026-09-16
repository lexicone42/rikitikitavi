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
fn test_db_is_sorted() {
    for window in OUI_DB.windows(2) {
        assert!(
            window[0].0 < window[1].0,
            "OUI_DB not sorted: {:?} >= {:?}",
            window[0].0,
            window[1].0
        );
    }
}

#[test]
fn test_db_has_entries() {
    assert!(OUI_DB.len() > 30_000, "expected >30K OUI entries");
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
