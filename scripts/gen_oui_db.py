#!/usr/bin/env python3
"""Generate oui_db.rs from the IEEE MA-L, MA-M and MA-S registries.

Usage:
    uv run python -I scripts/gen_oui_db.py --fetch <empty-dir> \\
        > crates/rikitikitavi-scanners/src/oui_db.rs
    uv run python -I scripts/gen_oui_db.py --input-dir <dir-with-csvs> > ...

`--fetch` downloads oui.csv, mam.csv and oui36.csv into a new or empty
directory (generic User-Agent, retry with backoff: the IEEE server returns
HTTP 418 intermittently). Input is untrusted: prefixes are validated as hex of
the exact registry length, names lose control characters and are capped.

Rows owned by "IEEE Registration Authority" are skipped in all three registries.
"""

import argparse
import csv
import datetime
import os
import sys
import time
import unicodedata
import urllib.error
import urllib.request

SOURCES = [
    # (registry, file name, URL, hex digits)
    ("MA-L", "oui.csv", "https://standards-oui.ieee.org/oui/oui.csv", 6),
    ("MA-M", "mam.csv", "https://standards-oui.ieee.org/oui28/mam.csv", 7),
    ("MA-S", "oui36.csv", "https://standards-oui.ieee.org/oui36/oui36.csv", 9),
]
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) oui-table-generator/1.0"
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_NAME_CHARS = 96
HEX = set("0123456789ABCDEF")
PARENT_ORG = "IEEE Registration Authority"


def fetch(url: str, dest: str) -> None:
    delay = 2.0
    for attempt in range(6):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/csv,*/*"})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = resp.read(MAX_DOWNLOAD + 1)
            if len(data) > MAX_DOWNLOAD:
                sys.exit(f"{url}: larger than {MAX_DOWNLOAD} bytes")
            with open(dest, "xb") as f:
                f.write(data)
            return
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"{url}: attempt {attempt + 1} failed: {e}", file=sys.stderr)
            time.sleep(delay)
            delay *= 2
    sys.exit(f"{url}: giving up")


def parse_prefix(assignment: str, digits: int) -> int | None:
    h = assignment.strip().upper()
    if len(h) != digits or not set(h) <= HEX:
        return None
    return int(h, 16)


def clean_name(raw: str) -> str:
    name = "".join(
        " " if c in "\t\r\n" else c
        for c in raw
        if c in "\t\r\n" or unicodedata.category(c) not in ("Cc", "Cf", "Cs", "Co", "Cn")
    )
    return name.strip()[:MAX_NAME_CHARS].strip()


def read_registry(path: str, registry: str, digits: int) -> dict[int, str]:
    entries: dict[int, str] = {}
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) < 3 or row[0].strip() != registry:
                continue
            prefix = parse_prefix(row[1], digits)
            if prefix is None or prefix in entries:
                continue
            org = clean_name(row[2])
            if org == PARENT_ORG:
                continue
            vendor = clean_name(normalize_vendor(org))
            if vendor:
                entries[prefix] = vendor
    return entries


def rust_str(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')

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

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--fetch", metavar="DIR", help="download the CSVs into this new or empty directory")
    src.add_argument("--input-dir", metavar="DIR", help="read previously downloaded CSVs from this directory")
    args = ap.parse_args()

    directory = args.fetch or args.input_dir
    if args.fetch:
        os.makedirs(directory, exist_ok=True)
        if os.listdir(directory):
            sys.exit(f"{directory}: not empty")
        for _, name, url, _ in SOURCES:
            fetch(url, os.path.join(directory, name))

    tables = {
        registry: read_registry(os.path.join(directory, name), registry, digits)
        for registry, name, _, digits in SOURCES
    }
    ma_l = sorted(tables["MA-L"].items())
    ma_m = sorted(tables["MA-M"].items())
    ma_s = sorted(tables["MA-S"].items())
    unique_vendors = len({v for t in tables.values() for v in t.values()})
    print(f"MA-L {len(ma_l)}, MA-M {len(ma_m)}, MA-S {len(ma_s)}, unique vendors {unique_vendors}", file=sys.stderr)

    out = sys.stdout
    today = datetime.date.today().isoformat()
    out.write(f"""//! IEEE MAC address block registries (MA-L, MA-M, MA-S), auto-generated.
//!
//! Sources:
//! - <https://standards-oui.ieee.org/oui/oui.csv>
//! - <https://standards-oui.ieee.org/oui28/mam.csv>
//! - <https://standards-oui.ieee.org/oui36/oui36.csv>
//!
//! Generated: {today}
//! Entries: MA-L {len(ma_l):,} | MA-M {len(ma_m):,} | MA-S {len(ma_s):,} | Unique vendors: {unique_vendors:,}
//!
//! Rows owned by "IEEE Registration Authority" are omitted. Each table is sorted
//! by prefix for `binary_search`.

/// Look up a MAC address in the IEEE registries.
///
/// Accepts `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF`, `aabb.ccdd.eeff` or
/// `aabbccddeeff`. Hex digits are read up to the first other character; six are
/// required, seven enable the MA-M table and nine the MA-S table.
///
/// Returns the vendor of the longest matching prefix: MA-S (36 bits), then MA-M
/// (28 bits), then MA-L (24 bits).
pub fn ieee_oui_lookup(mac: &str) -> Option<&'static str> {{
    lookup_in(OUI_DB, MAM_DB, MAS_DB, mac)
}}

fn lookup_in(
    ma_l: &[([u8; 3], &'static str)],
    ma_m: &[(u32, &'static str)],
    ma_s: &[(u64, &'static str)],
    mac: &str,
) -> Option<&'static str> {{
    let (nibbles, count) = parse_nibbles(mac);
    if count >= 9
        && let Some(vendor) = find(ma_s, &prefix_value(&nibbles[..9]))
    {{
        return Some(vendor);
    }}
    if count >= 7
        && let Ok(key) = u32::try_from(prefix_value(&nibbles[..7]))
        && let Some(vendor) = find(ma_m, &key)
    {{
        return Some(vendor);
    }}
    find(ma_l, &parse_mac_prefix(mac)?)
}}

fn find<K: Ord>(table: &[(K, &'static str)], key: &K) -> Option<&'static str> {{
    table
        .binary_search_by(|(k, _)| k.cmp(key))
        .ok()
        .map(|idx| table[idx].1)
}}

fn prefix_value(nibbles: &[u8]) -> u64 {{
    nibbles.iter().fold(0, |acc, &n| acc << 4 | u64::from(n))
}}

/// Up to nine hex digit values from `s`, skipping `:`, `-` and `.`, stopping at
/// any other character. Returns the digits and how many were read.
fn parse_nibbles(s: &str) -> ([u8; 9], usize) {{
    let mut out = [0u8; 9];
    let mut count = 0;
    for c in s.bytes() {{
        if count == out.len() {{
            break;
        }}
        out[count] = match c {{
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            b':' | b'-' | b'.' => continue,
            _ => break,
        }};
        count += 1;
    }}
    (out, count)
}}

/// Parse the first 3 octets of a MAC address string into bytes.
fn parse_mac_prefix(s: &str) -> Option<[u8; 3]> {{
    let (n, count) = parse_nibbles(s);
    (count >= 6).then(|| [n[0] << 4 | n[1], n[2] << 4 | n[3], n[4] << 4 | n[5]])
}}

/// MA-L: (24-bit OUI bytes, vendor), sorted.
#[rustfmt::skip]
static OUI_DB: &[([u8; 3], &str)] = &[
""")
    for prefix, vendor in ma_l:
        b0, b1, b2 = prefix >> 16, (prefix >> 8) & 0xFF, prefix & 0xFF
        out.write(f'    ([0x{b0:02X}, 0x{b1:02X}, 0x{b2:02X}], "{rust_str(vendor)}"),\n')
    out.write("""];

/// MA-M: (28-bit prefix as integer, vendor), sorted.
#[rustfmt::skip]
#[allow(clippy::unreadable_literal)]
static MAM_DB: &[(u32, &str)] = &[
""")
    for prefix, vendor in ma_m:
        out.write(f'    (0x{prefix:07X}, "{rust_str(vendor)}"),\n')
    out.write("""];

/// MA-S: (36-bit prefix as integer, vendor), sorted.
#[rustfmt::skip]
#[allow(clippy::unreadable_literal)]
static MAS_DB: &[(u64, &str)] = &[
""")
    for prefix, vendor in ma_s:
        out.write(f'    (0x{prefix:09X}, "{rust_str(vendor)}"),\n')
    out.write("""];

#[cfg(test)]
mod tests;
""")


if __name__ == "__main__":
    main()
