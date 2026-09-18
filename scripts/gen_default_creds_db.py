#!/usr/bin/env python3
"""Generate `default_creds_db.rs` — a curated default-credential corpus.

Source: RouterSploit wordlists, BSD-3-Clause ("Copyright 2018, The RouterSploit
Framework (RSF) by Threat9"). The full licence is reproduced in
THIRD-PARTY-NOTICES.md at the repository root.

  https://github.com/threat9/routersploit
  ref 723b574c36ae202857e3f93e4f3c2ab9a1638ed4 (2026-05-05)
  routersploit/resources/wordlists/defaults.txt  (653 lines, 9596 bytes)
  routersploit/resources/wordlists/snmp.txt      (120 lines,  839 bytes)

RouterSploit's `defaults.txt` is a flat `user:pass` list mixing enterprise and
home gear. We take only the pairs relevant to home / SOHO devices (routers,
access points, cameras, NVRs, printers, NAS) and attach a vendor token where the
device family is well known, so the credential scanner can try vendor-matching
pairs first. Every emitted pair is present verbatim in the upstream file; the
vendor grouping is our curation, not upstream metadata. `snmp.txt` is taken in
full (community strings, not logins).

No exploit code is imported. This corpus INFORMS findings; the credential
scanner only ever attempts a login at ScanIntensity::Aggressive, capped and
stopping at the first success.

Usage (offline, deterministic):
    uv run python scripts/gen_default_creds_db.py \
        > crates/rikitikitavi-scanners/src/default_creds_db.rs
    cargo fmt
"""

import sys

SOURCE_DEFAULTS = "routersploit defaults.txt"
SOURCE_SNMP = "routersploit snmp.txt"

# Generic home/SOHO defaults (vendor = None). Order here is not significant; the
# table is sorted before emission. Each pair is present in defaults.txt.
GENERIC = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "0000"),
    ("admin", "1111"),
    ("admin", "pass"),
    ("admin", "root"),
    ("admin", "changeme"),
    ("admin", "default"),
    ("admin", "setup"),
    ("admin", "admin1234"),
    ("admin", "7ujMko0admin"),
    ("root", "root"),
    ("root", ""),
    ("root", "admin"),
    ("root", "password"),
    ("root", "pass"),
    ("root", "1234"),
    ("root", "12345"),
    ("root", "default"),
    ("root", "changeme"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("guest", ""),
    ("support", "support"),
    ("supervisor", "supervisor"),
    ("superadmin", "secret"),
    # IoT camera / DVR families seen across many rebadged white-label devices;
    # these are the Mirai default set and are firmly home-relevant.
    ("root", "vizxv"),
    ("root", "xc3511"),
    ("root", "xmhdipc"),
    ("root", "juantech"),
    ("root", "hi3518"),
    ("root", "7ujMko0vizxv"),
    ("root", "hslwificam"),
    ("root", "cat1029"),
    ("root", "oelinux123"),
    ("admin", "aquario"),
]

# Vendor-tagged pairs. The key is the lowercase token matched against
# `Device::vendor` (case-insensitive substring). Every pair is present in
# defaults.txt; the vendor association is curated for prioritisation.
VENDOR = {
    "d-link": [("admin", ""), ("admin", "admin"), ("user", "")],
    "cisco": [("cisco", "cisco"), ("admin", "cisco"), ("admin", "admin")],
    "netgear": [("admin", "password"), ("admin", "1234"), ("admin", "")],
    "tp-link": [("admin", "admin"), ("admin", "")],
    "zyxel": [("admin", "1234"), ("admin", ""), ("supervisor", "zyad1234")],
    "zte": [("root", "Zte521"), ("admin", "zhongxing"), ("root", "zhongxing")],
    "ubiquiti": [("ubnt", "ubnt")],
    "mikrotik": [("admin", "")],
    "huawei": [
        ("admin", "admin"),
        ("telecomadmin", "admintelecom"),
        ("telecomadmin", "nE7jA%5m"),
    ],
    "draytek": [("admin", "1234"), ("draytek", "1234")],
    "technicolor": [("admin", "admin")],
    "asus": [("admin", "admin")],
    "linksys": [("admin", "admin"), ("admin", "")],
    "belkin": [("admin", "")],
    "billion": [("admin", "admin")],
    "hikvision": [("admin", "12345")],
    "dahua": [("admin", "admin"), ("888888", "888888"), ("666666", "666666")],
    "axis": [("root", "pass")],
    "synology": [("admin", ""), ("admin", "admin")],
    "qnap": [("admin", "admin")],
}

# Device classes that commonly ship default credentials, with the finding note.
# Keyed on the `DeviceType` Rust variant.
CLASSES = [
    ("Router", "consumer routers and gateways ship a documented default login"),
    ("AccessPoint", "wireless access points ship a documented default login"),
    ("Camera", "IP cameras are a top default-credential and botnet target"),
    ("Nvr", "NVRs and DVRs are a top default-credential and botnet target"),
    ("Doorbell", "video doorbells frequently ship a fixed default login"),
    ("Printer", "network printers often expose an admin page with a default or blank password"),
    ("Nas", "NAS appliances ship a documented default administrator login"),
    ("Nvr", "NVRs and DVRs are a top default-credential and botnet target"),
]

# RouterSploit snmp.txt, verbatim (119 community strings). Community strings are
# tried with a read-only SNMP GET, which is a read, not a login. Taken in full;
# entries with spaces ("all private", "s!a@m#n$p%c") are kept as-is.
SNMP = [
    "public", "private", "0", "0392a0", "1234", "2read", "4changes", "ANYCOM",
    "Admin", "C0de", "CISCO", "CR52401", "IBM", "ILMI", "Intermec", "NoGaH$@!",
    "OrigEquipMfr", "PRIVATE", "PUBLIC", "Private", "Public", "SECRET",
    "SECURITY", "SNMP", "SNMP_trap", "SUN", "SWITCH", "SYSTEM", "Secret",
    "Security", "Switch", "System", "TENmanUFactOryPOWER", "TEST", "access",
    "adm", "admin", "agent", "agent_steal", "all", "all private", "all public",
    "apc", "bintec", "blue", "c", "cable-d", "canon_admin", "cc", "cisco",
    "community", "core", "debug", "default", "dilbert", "enable", "field",
    "field-service", "freekevin", "fubar", "guest", "hello", "hp_admin", "ibm",
    "ilmi", "intermec", "internal", "l2", "l3", "manager", "mngt", "monitor",
    "netman", "network", "none", "openview", "pass", "password", "pr1v4t3",
    "proxy", "publ1c", "read", "read-only", "read-write", "readwrite", "red",
    "regional", "rmon", "rmon_admin", "ro", "root", "router", "rw", "rwa",
    "s!a@m#n$p%c", "san-fran", "sanfran", "scotty", "secret", "security", "seri",
    "snmp", "snmpd", "snmptrap", "solaris", "sun", "superuser", "switch",
    "system", "tech", "test", "test2", "tiv0li", "tivoli", "trap", "world",
    "write", "xyzzy", "yellow",
]


def rust_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> None:
    # Build (vendor, service, user, pass, source) rows. Service is "Any" for the
    # whole corpus: these are login pairs, tried against telnet, FTP or HTTP
    # admin alike. Dedup on (vendor, user, pass).
    rows = []
    seen = set()
    for user, pw in GENERIC:
        key = (None, user, pw)
        if key not in seen:
            seen.add(key)
            rows.append((None, "Any", user, pw, SOURCE_DEFAULTS))
    for vendor, pairs in VENDOR.items():
        for user, pw in pairs:
            key = (vendor, user, pw)
            if key not in seen:
                seen.add(key)
                rows.append((vendor, "Any", user, pw, SOURCE_DEFAULTS))

    # Sort: generic (vendor "") first, then by vendor, service, user, pass.
    rows.sort(key=lambda r: (r[0] or "", r[1], r[2], r[3]))

    communities = sorted(set(SNMP))

    classes = []
    seen_c = set()
    for variant, note in CLASSES:
        if variant not in seen_c:
            seen_c.add(variant)
            classes.append((variant, note))

    out = sys.stdout
    out.write(f"""//! Curated default-credential corpus — auto-generated, do not edit by hand.
//!
//! Source: `RouterSploit` wordlists, BSD-3-Clause. The copyright notice, the three
//! conditions and the disclaimer it requires are reproduced verbatim in
//! THIRD-PARTY-NOTICES.md at the repository root.
//!   <https://github.com/threat9/routersploit>
//!   ref 723b574c36ae202857e3f93e4f3c2ab9a1638ed4 (2026-05-05)
//!   defaults.txt (653 lines, 9596 bytes) -> {len(rows)} home/SOHO pairs
//!   snmp.txt     (120 lines,  839 bytes) -> {len(communities)} community strings
//!
//! Only the home / SOHO subset of `defaults.txt` is imported; the vendor tag on
//! a pair is this project's curation for prioritisation, not upstream metadata.
//! No exploit code is imported. The corpus only INFORMS findings — the scanner
//! attempts a login solely at `ScanIntensity::Aggressive`, capped and stopping
//! at the first success.
//!
//! Regenerate with `uv run python scripts/gen_default_creds_db.py`, then
//! `cargo fmt`.

use rikitikitavi_models::DeviceType;

/// The service a default-credential pair targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CredService {{
    /// Any login-capable service (telnet, FTP, or an HTTP admin panel).
    Any,
    /// Telnet (TCP/23).
    Telnet,
    /// FTP (TCP/21).
    Ftp,
    /// An HTTP admin panel (Basic/Digest auth).
    HttpAdmin,
}}

impl CredService {{
    /// Whether a pair declared for `self` may be tried against `other`.
    #[must_use]
    pub const fn covers(self, other: Self) -> bool {{
        matches!(self, Self::Any)
            || matches!(
                (self, other),
                (Self::Telnet, Self::Telnet)
                    | (Self::Ftp, Self::Ftp)
                    | (Self::HttpAdmin, Self::HttpAdmin)
            )
    }}
}}

/// One default-credential pair with optional vendor scope and its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultCred {{
    /// Lowercase vendor token matched against `Device::vendor`; `None` = generic.
    pub vendor: Option<&'static str>,
    /// Service the pair targets.
    pub service: CredService,
    /// Login username.
    pub username: &'static str,
    /// Login password; the empty string denotes a blank password.
    pub password: &'static str,
    /// Upstream wordlist the pair was taken from.
    pub source: &'static str,
}}

/// Number of credential pairs in the corpus.
pub const DEFAULT_CRED_COUNT: usize = {len(rows)};

/// Number of SNMP community strings in the corpus.
pub const SNMP_COMMUNITY_COUNT: usize = {len(communities)};

/// The corpus, sorted by (vendor, service, username, password).
#[rustfmt::skip]
pub static DEFAULT_CREDS: &[DefaultCred] = &[
""")

    for vendor, service, user, pw, source in rows:
        v = "None" if vendor is None else f"Some({rust_str(vendor)})"
        out.write(
            f"    DefaultCred {{ vendor: {v}, service: CredService::{service}, "
            f"username: {rust_str(user)}, password: {rust_str(pw)}, "
            f"source: {rust_str(source)} }},\n"
        )
    out.write("];\n\n")

    out.write(
        "/// SNMP community strings to try with a read-only GET, sorted and unique.\n"
    )
    out.write("pub static SNMP_COMMUNITIES: &[&str] = &[\n")
    for c in communities:
        out.write(f"    {rust_str(c)},\n")
    out.write("];\n\n")

    out.write(
        "/// Device classes that commonly ship default credentials, each with the\n"
        "/// note used in the advisory finding.\n"
    )
    out.write("#[rustfmt::skip]\n")
    out.write("pub static DEFAULT_CRED_CLASSES: &[(DeviceType, &str)] = &[\n")
    for variant, note in classes:
        out.write(f"    (DeviceType::{variant}, {rust_str(note)}),\n")
    out.write("];\n\n")

    out.write(
        """/// The advisory note for `dt` when its class commonly ships default
/// credentials, else `None`.
#[must_use]
pub fn class_default_note(dt: DeviceType) -> Option<&'static str> {
    DEFAULT_CRED_CLASSES
        .iter()
        .find(|(class, _)| *class == dt)
        .map(|(_, note)| *note)
}

#[cfg(test)]
mod tests;
"""
    )


if __name__ == "__main__":
    main()
