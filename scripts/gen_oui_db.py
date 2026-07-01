#!/usr/bin/env python3
"""Generate oui_db.rs from IEEE OUI CSV.

Reads the IEEE MA-L OUI database (standards-oui.ieee.org/oui/oui.csv)
and produces a sorted Rust array with binary-search lookup.
"""

import csv
import sys
import unicodedata
from collections import defaultdict

def parse_hex(assignment: str) -> tuple[int, int, int]:
    """Parse 6-char hex assignment into 3 bytes."""
    h = assignment.strip().upper()
    return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))

def normalize_vendor(name: str) -> str:
    """Clean up vendor name for readability."""
    name = name.strip().strip('"')
    # Common suffixes that add noise
    for suffix in [
        ", Inc.", ", Inc", " Inc.", " Inc",
        ", Ltd.", ", Ltd", " Ltd.", " Ltd",
        " Co., Ltd.", " Co.,Ltd.", " Co., Ltd", " Co.,Ltd",
        " Corporation", " Corp.", " Corp",
        " International", " Intl.",
        " Technologies", " Technology",
        " Electronics", " Electric",
        " Holdings",
        " Group",
        " GmbH", " AG", " SA", " SAS", " S.A.", " S.A",
        " B.V.", " BV", " N.V.",
        " LLC", " L.L.C.",
        " Limited", " Pty",
        " Co.",
    ]:
        if name.endswith(suffix):
            name = name[:-len(suffix)].strip()
    # Special well-known normalizations
    replacements = {
        "Hewlett Packard": "HP",
        "Hewlett-Packard": "HP",
        "HP Enterprise": "HPE",
        "Apple": "Apple",
        "SAMSUNG ELECTRO-MECHANICS": "Samsung",
        "Samsung Electro-Mechanics": "Samsung",
        "Samsung Electro Mechanics": "Samsung",
        "SAMSUNG ELECTRO MECHANICS": "Samsung",
        "TP-LINK": "TP-Link",
        "Tp-Link": "TP-Link",
        "TP-Link Systems": "TP-Link",
        "HUAWEI TECHNOLOGIES": "Huawei",
        "Huawei Device": "Huawei",
        "HUAWEI TECHNOLOGIES CO.": "Huawei",
        "Google": "Google",
        "Google, LLC": "Google",
        "Amazon": "Amazon",
        "Amazon.com": "Amazon",
        "Ubiquiti": "Ubiquiti",
        "Ubiquiti Networks": "Ubiquiti",
        "Cisco Systems": "Cisco",
        "CISCO SYSTEMS": "Cisco",
        "Microsoft": "Microsoft",
        "Microsoft Mobile Oy": "Microsoft",
        "Raspberry Pi Trading": "Raspberry Pi",
        "Raspberry Pi (Trading)": "Raspberry Pi",
        "Raspberry Pi": "Raspberry Pi",
        "Intel Corporate": "Intel",
        "INTEL CORPORATE": "Intel",
        "Dell": "Dell",
        "Dell EMC": "Dell",
        "Sonos": "Sonos",
        "Ring LLC": "Ring",
        "Ring": "Ring",
        "Roku": "Roku",
        "NETGEAR": "Netgear",
        "Netgear": "Netgear",
        "Espressif": "Espressif",
        "Synology Incorporated": "Synology",
        "Synology": "Synology",
        "LG Electronics": "LG",
        "LG ELECTRONICS": "LG",
        "Xiaomi Communications": "Xiaomi",
        "Xiaomi": "Xiaomi",
        "Sony Interactive Entertainment": "Sony",
        "Sony Mobile Communications": "Sony",
        "SONY MOBILE COMMUNICATIONS": "Sony",
        "Sony": "Sony",
        "Nintendo": "Nintendo",
        "Nintendo Co.": "Nintendo",
        "Belkin": "Belkin",
        "Belkin International": "Belkin",
        "ARRIS Group": "Arris",
        "CommScope": "CommScope",
        "ASUSTek Computer": "Asus",
        "AsusTek Computer": "Asus",
        "ASUS": "Asus",
        "D-Link": "D-Link",
        "D-Link International": "D-Link",
        "Motorola Mobility": "Motorola",
        "Motorola Solutions": "Motorola",
        "Motorola": "Motorola",
        "Lenovo": "Lenovo",
        "Liteon": "Liteon",
        "LITE-ON": "Liteon",
        "Texas Instruments": "TI",
        "Murata Manufacturing": "Murata",
        "Hon Hai Precision Ind.": "Foxconn",
        "Hon Hai Precision": "Foxconn",
        "Shenzhen Skyworth Digital": "Skyworth",
        "Philips Lighting": "Philips Lighting",
        "Signify": "Signify",
        "D&M Holdings": "D&M",
    }
    for old, new in replacements.items():
        if name.lower() == old.lower():
            return new
    # Also do startswith matching for common prefixes
    prefix_map = {
        "hewlett packard": "HP",
        "hewlett-packard": "HP",
        "samsung electro": "Samsung",
        "huawei": "Huawei",
        "cisco": "Cisco",
        "tp-link": "TP-Link",
        "google": "Google",
        "amazon": "Amazon",
        "intel ": "Intel",
        "microsoft": "Microsoft",
        "raspberry pi": "Raspberry Pi",
        "xiaomi": "Xiaomi",
        "beijing xiaomi": "Xiaomi",
        "lg electro": "LG",
        "sony ": "Sony",
        "nintendo": "Nintendo",
        "motorola": "Motorola",
        "arris": "Arris",
        "asus": "Asus",
        "d-link": "D-Link",
        "lenovo": "Lenovo",
        "dell ": "Dell",
        "netgear": "Netgear",
        "ubiquiti": "Ubiquiti",
        "espressif": "Espressif",
        "hon hai": "Foxconn",
        "sichuan ai-link": "AI-Link",
        "philips lighting": "Philips Lighting",
        "signify": "Signify",
        "d&m": "D&M",
        "samsung": "Samsung",
        "synology": "Synology",
        "sonos": "Sonos",
        "roku": "Roku",
        "ring ": "Ring",
        "belkin": "Belkin",
        "commscope": "CommScope",
    }
    for prefix, replacement in prefix_map.items():
        if name.lower().startswith(prefix):
            return replacement
    # Normalize Unicode to NFC and strip invisible characters
    name = unicodedata.normalize("NFC", name)
    name = "".join(c for c in name if unicodedata.category(c) != "Cf")
    return name

def main():
    entries = []
    seen_oui = set()

    with open("/tmp/oui.csv", "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)  # Skip header

        for row in reader:
            if len(row) < 3:
                continue
            registry, assignment, org_name = row[0], row[1], row[2]
            if registry != "MA-L":
                continue
            if len(assignment.strip()) != 6:
                continue

            try:
                b0, b1, b2 = parse_hex(assignment)
            except (ValueError, IndexError):
                continue

            oui = (b0, b1, b2)
            if oui in seen_oui:
                continue
            seen_oui.add(oui)

            vendor = normalize_vendor(org_name)
            if not vendor:
                continue

            entries.append((b0, b1, b2, vendor))

    # Sort by OUI bytes for binary search
    entries.sort(key=lambda e: (e[0], e[1], e[2]))

    # Count unique vendors
    unique_vendors = len(set(e[3] for e in entries))

    print(f"// Auto-generated from IEEE MA-L OUI database", file=sys.stderr)
    print(f"// Entries: {len(entries)}, unique vendors: {unique_vendors}", file=sys.stderr)

    # Generate Rust source
    out = sys.stdout
    out.write(f"""//! IEEE OUI (MA-L) database — auto-generated.
//!
//! Source: <https://standards-oui.ieee.org/oui/oui.csv>
//! Generated: 2026-02-14
//! Entries: {len(entries):,} | Unique vendors: {unique_vendors:,}
//!
//! Each entry is a 3-byte OUI prefix paired with a vendor name.
//! The array is sorted by OUI bytes for `binary_search` (O(log n) ≈ 16 comparisons).

/// Look up a MAC address in the IEEE OUI database.
///
/// Accepts any common MAC format: `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF`,
/// `aabb.ccdd.eeff`, or raw `aabbccddeeff`. Only the first 3 octets matter.
///
/// Returns the vendor/organization name if found.
pub fn ieee_oui_lookup(mac: &str) -> Option<&'static str> {{
    let bytes = parse_mac_prefix(mac)?;
    OUI_DB
        .binary_search_by_key(&bytes, |(oui, _)| *oui)
        .ok()
        .map(|idx| OUI_DB[idx].1)
}}

/// Parse the first 3 octets of a MAC address string into bytes.
fn parse_mac_prefix(s: &str) -> Option<[u8; 3]> {{
    // Extract up to 6 hex digits, skipping separators
    let mut hex = [0u8; 6];
    let mut count = 0;
    for c in s.bytes() {{
        if count >= 6 {{
            break;
        }}
        match c {{
            b'0'..=b'9' => {{
                hex[count] = c - b'0';
                count += 1;
            }}
            b'a'..=b'f' => {{
                hex[count] = c - b'a' + 10;
                count += 1;
            }}
            b'A'..=b'F' => {{
                hex[count] = c - b'A' + 10;
                count += 1;
            }}
            b':' | b'-' | b'.' => {{}}
            _ => return None,
        }}
    }}
    if count < 6 {{
        return None;
    }}
    Some([
        hex[0] << 4 | hex[1],
        hex[2] << 4 | hex[3],
        hex[4] << 4 | hex[5],
    ])
}}

/// Sorted array of (OUI prefix bytes, vendor name).
/// Binary search: O(log {len(entries):,}) ≈ {len(entries).bit_length()} comparisons.
///
/// `rustfmt::skip` keeps this generated table one-entry-per-line; without it
/// rustfmt wraps long vendor rows and produces thousands of lines of churn.
#[rustfmt::skip]
static OUI_DB: &[([u8; 3], &str)] = &[
""")

    for b0, b1, b2, vendor in entries:
        # Escape any special chars in vendor name
        escaped = vendor.replace("\\", "\\\\").replace('"', '\\"')
        out.write(f'    ([0x{b0:02X}, 0x{b1:02X}, 0x{b2:02X}], "{escaped}"),\n')

    out.write("""];

#[cfg(test)]
mod tests {
    use super::*;

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
}
""")

if __name__ == "__main__":
    main()
