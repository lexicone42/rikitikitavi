//! Curated default-credential corpus — auto-generated, do not edit by hand.
//!
//! Source: `RouterSploit` wordlists, BSD-3-Clause. The copyright notice, the three
//! conditions and the disclaimer it requires are reproduced verbatim in
//! THIRD-PARTY-NOTICES.md at the repository root.
//!   <https://github.com/threat9/routersploit>
//!   ref 723b574c36ae202857e3f93e4f3c2ab9a1638ed4 (2026-05-05)
//!   defaults.txt (653 lines, 9596 bytes) -> 79 home/SOHO pairs
//!   snmp.txt     (120 lines,  839 bytes) -> 119 community strings
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
pub enum CredService {
    /// Any login-capable service (telnet, FTP, or an HTTP admin panel).
    Any,
    /// Telnet (TCP/23).
    Telnet,
    /// FTP (TCP/21).
    Ftp,
    /// An HTTP admin panel (Basic/Digest auth).
    HttpAdmin,
}

impl CredService {
    /// Whether a pair declared for `self` may be tried against `other`.
    #[must_use]
    pub const fn covers(self, other: Self) -> bool {
        matches!(self, Self::Any)
            || matches!(
                (self, other),
                (Self::Telnet, Self::Telnet)
                    | (Self::Ftp, Self::Ftp)
                    | (Self::HttpAdmin, Self::HttpAdmin)
            )
    }
}

/// One default-credential pair with optional vendor scope and its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultCred {
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
}

/// Number of credential pairs in the corpus.
pub const DEFAULT_CRED_COUNT: usize = 79;

/// Number of SNMP community strings in the corpus.
pub const SNMP_COMMUNITY_COUNT: usize = 119;

/// The corpus, sorted by (vendor, service, username, password).
#[rustfmt::skip]
pub static DEFAULT_CREDS: &[DefaultCred] = &[
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "0000", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "1111", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "1234", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "12345", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "123456", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "7ujMko0admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "admin1234", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "aquario", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "changeme", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "default", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "pass", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "password", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "root", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "admin", password: "setup", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "guest", password: "", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "guest", password: "guest", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "1234", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "12345", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "7ujMko0vizxv", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "cat1029", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "changeme", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "default", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "hi3518", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "hslwificam", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "juantech", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "oelinux123", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "pass", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "password", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "root", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "vizxv", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "xc3511", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "root", password: "xmhdipc", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "superadmin", password: "secret", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "supervisor", password: "supervisor", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "support", password: "support", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "user", password: "password", source: "routersploit defaults.txt" },
    DefaultCred { vendor: None, service: CredService::Any, username: "user", password: "user", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("asus"), service: CredService::Any, username: "admin", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("axis"), service: CredService::Any, username: "root", password: "pass", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("belkin"), service: CredService::Any, username: "admin", password: "", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("billion"), service: CredService::Any, username: "admin", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("cisco"), service: CredService::Any, username: "admin", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("cisco"), service: CredService::Any, username: "admin", password: "cisco", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("cisco"), service: CredService::Any, username: "cisco", password: "cisco", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("d-link"), service: CredService::Any, username: "admin", password: "", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("d-link"), service: CredService::Any, username: "admin", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("d-link"), service: CredService::Any, username: "user", password: "", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("dahua"), service: CredService::Any, username: "666666", password: "666666", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("dahua"), service: CredService::Any, username: "888888", password: "888888", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("dahua"), service: CredService::Any, username: "admin", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("draytek"), service: CredService::Any, username: "admin", password: "1234", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("draytek"), service: CredService::Any, username: "draytek", password: "1234", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("hikvision"), service: CredService::Any, username: "admin", password: "12345", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("huawei"), service: CredService::Any, username: "admin", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("huawei"), service: CredService::Any, username: "telecomadmin", password: "admintelecom", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("huawei"), service: CredService::Any, username: "telecomadmin", password: "nE7jA%5m", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("linksys"), service: CredService::Any, username: "admin", password: "", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("linksys"), service: CredService::Any, username: "admin", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("mikrotik"), service: CredService::Any, username: "admin", password: "", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("netgear"), service: CredService::Any, username: "admin", password: "", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("netgear"), service: CredService::Any, username: "admin", password: "1234", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("netgear"), service: CredService::Any, username: "admin", password: "password", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("qnap"), service: CredService::Any, username: "admin", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("synology"), service: CredService::Any, username: "admin", password: "", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("synology"), service: CredService::Any, username: "admin", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("technicolor"), service: CredService::Any, username: "admin", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("tp-link"), service: CredService::Any, username: "admin", password: "", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("tp-link"), service: CredService::Any, username: "admin", password: "admin", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("ubiquiti"), service: CredService::Any, username: "ubnt", password: "ubnt", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("zte"), service: CredService::Any, username: "admin", password: "zhongxing", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("zte"), service: CredService::Any, username: "root", password: "Zte521", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("zte"), service: CredService::Any, username: "root", password: "zhongxing", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("zyxel"), service: CredService::Any, username: "admin", password: "", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("zyxel"), service: CredService::Any, username: "admin", password: "1234", source: "routersploit defaults.txt" },
    DefaultCred { vendor: Some("zyxel"), service: CredService::Any, username: "supervisor", password: "zyad1234", source: "routersploit defaults.txt" },
];

/// SNMP community strings to try with a read-only GET, sorted and unique.
pub static SNMP_COMMUNITIES: &[&str] = &[
    "0",
    "0392a0",
    "1234",
    "2read",
    "4changes",
    "ANYCOM",
    "Admin",
    "C0de",
    "CISCO",
    "CR52401",
    "IBM",
    "ILMI",
    "Intermec",
    "NoGaH$@!",
    "OrigEquipMfr",
    "PRIVATE",
    "PUBLIC",
    "Private",
    "Public",
    "SECRET",
    "SECURITY",
    "SNMP",
    "SNMP_trap",
    "SUN",
    "SWITCH",
    "SYSTEM",
    "Secret",
    "Security",
    "Switch",
    "System",
    "TENmanUFactOryPOWER",
    "TEST",
    "access",
    "adm",
    "admin",
    "agent",
    "agent_steal",
    "all",
    "all private",
    "all public",
    "apc",
    "bintec",
    "blue",
    "c",
    "cable-d",
    "canon_admin",
    "cc",
    "cisco",
    "community",
    "core",
    "debug",
    "default",
    "dilbert",
    "enable",
    "field",
    "field-service",
    "freekevin",
    "fubar",
    "guest",
    "hello",
    "hp_admin",
    "ibm",
    "ilmi",
    "intermec",
    "internal",
    "l2",
    "l3",
    "manager",
    "mngt",
    "monitor",
    "netman",
    "network",
    "none",
    "openview",
    "pass",
    "password",
    "pr1v4t3",
    "private",
    "proxy",
    "publ1c",
    "public",
    "read",
    "read-only",
    "read-write",
    "readwrite",
    "red",
    "regional",
    "rmon",
    "rmon_admin",
    "ro",
    "root",
    "router",
    "rw",
    "rwa",
    "s!a@m#n$p%c",
    "san-fran",
    "sanfran",
    "scotty",
    "secret",
    "security",
    "seri",
    "snmp",
    "snmpd",
    "snmptrap",
    "solaris",
    "sun",
    "superuser",
    "switch",
    "system",
    "tech",
    "test",
    "test2",
    "tiv0li",
    "tivoli",
    "trap",
    "world",
    "write",
    "xyzzy",
    "yellow",
];

/// Device classes that commonly ship default credentials, each with the
/// note used in the advisory finding.
#[rustfmt::skip]
pub static DEFAULT_CRED_CLASSES: &[(DeviceType, &str)] = &[
    (DeviceType::Router, "consumer routers and gateways ship a documented default login"),
    (DeviceType::AccessPoint, "wireless access points ship a documented default login"),
    (DeviceType::Camera, "IP cameras are a top default-credential and botnet target"),
    (DeviceType::Nvr, "NVRs and DVRs are a top default-credential and botnet target"),
    (DeviceType::Doorbell, "video doorbells frequently ship a fixed default login"),
    (DeviceType::Printer, "network printers often expose an admin page with a default or blank password"),
    (DeviceType::Nas, "NAS appliances ship a documented default administrator login"),
];

/// The advisory note for `dt` when its class commonly ships default
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
