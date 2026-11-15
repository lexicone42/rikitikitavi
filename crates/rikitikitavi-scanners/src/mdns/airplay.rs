//! `_airplay._tcp` TXT checks: tvOS fix floors, tvOS end-of-life, and access posture.
//!
//! Floors are from Apple's per-release security notes. Status-flag bit meanings
//! are from the reverse-engineered openairplay spec, so access findings are
//! `Probable` at most.

use rikitikitavi_core::{Confidence, Severity};
use rikitikitavi_models::{DeviceHint, Finding, Remediation};
use rikitikitavi_network::MdnsService;
use rikitikitavi_network::mdns::txt_get;
use std::fmt::Write as _;
use std::net::IpAddr;

use crate::eol_db;

/// `(major, minor, patch)`; absent components are 0.
pub type OsVersion = (u32, u32, u32);

/// One CVE and the first tvOS release that fixes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TvosFixFloor {
    pub cve: &'static str,
    pub fixed: OsVersion,
    /// Component named in Apple's note.
    pub component: &'static str,
    /// In CISA KEV (catalog 2026.11.13).
    pub kev: bool,
    /// Apple security-content page listing the CVE under that release.
    pub reference: &'static str,
}

/// Sorted by `fixed`.
pub const TVOS_FIX_FLOORS: &[TvosFixFloor] = &[
    TvosFixFloor {
        cve: "CVE-2021-30952",
        fixed: (15, 2, 0),
        component: "WebKit",
        kev: true,
        reference: "https://support.apple.com/en-us/HT212980",
    },
    TvosFixFloor {
        cve: "CVE-2024-27834",
        fixed: (17, 5, 0),
        component: "WebKit",
        kev: true,
        reference: "https://support.apple.com/en-us/120901",
    },
    TvosFixFloor {
        cve: "CVE-2025-31277",
        fixed: (18, 6, 0),
        component: "WebKit",
        kev: true,
        reference: "https://support.apple.com/en-us/124153",
    },
    TvosFixFloor {
        cve: "CVE-2025-43510",
        fixed: (26, 1, 0),
        component: "Kernel",
        kev: true,
        reference: "https://support.apple.com/en-us/125637",
    },
    TvosFixFloor {
        cve: "CVE-2025-43520",
        fixed: (26, 1, 0),
        component: "Kernel",
        kev: true,
        reference: "https://support.apple.com/en-us/125637",
    },
    TvosFixFloor {
        cve: "CVE-2026-20700",
        fixed: (26, 3, 0),
        component: "dyld",
        kev: true,
        reference: "https://support.apple.com/en-us/126351",
    },
];

/// `(model identifier, product name, last tvOS major)`. tvOS 27 is listed for
/// "Apple TV 4K 2nd generation and later" only.
const LAST_MAJOR: &[(&str, &str, u32)] = &[
    ("AppleTV5,3", "Apple TV HD", 26),
    ("AppleTV6,2", "Apple TV 4K (1st generation)", 26),
];

const TVOS_27_NOTE: &str = "https://support.apple.com/en-us/149036";
const EOL_TVOS: &str = "https://endoflife.date/tvos";
const ALLOW_ACCESS_GUIDE: &str = "https://support.apple.com/en-kz/guide/tv/atvb0342111f/18/tvos";
const STATUS_FLAGS_SPEC: &str = "https://openairplay.github.io/airplay-spec/status_flags.html";

pub const FLAG_PIN_REQUIRED: u64 = 1 << 3;
pub const FLAG_PASSWORD_REQUIRED: u64 = 1 << 7;
pub const FLAG_ONE_TIME_PAIRING: u64 = 1 << 9;
pub const FLAG_HOMEKIT_ACCESS_CONTROL: u64 = 1 << 10;

/// Dotted decimal, one to three components, digits only.
#[must_use]
pub fn parse_osvers(raw: &str) -> Option<OsVersion> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 32 {
        return None;
    }
    let mut parts = [0u32; 3];
    for (i, part) in raw.split('.').enumerate() {
        if i == 3 || part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        parts[i] = part.parse().ok()?;
    }
    Some(parts.into())
}

/// Hex bitfield with optional `0x`, at most 16 digits.
#[must_use]
pub fn parse_flags(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    let digits = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// `true`/`1` or `false`/`0`, case-insensitive.
#[must_use]
pub fn parse_pw(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

/// `Some(n)` for `AppleTV{n},{m}`.
fn apple_tv_generation(model: &str) -> Option<u32> {
    let rest = model.strip_prefix("AppleTV")?;
    let (major, minor) = rest.split_once(',')?;
    if minor.is_empty() || !minor.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if major.is_empty() || !major.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    major.parse().ok()
}

/// `AppleTV{n},{m}` with `n >= 5`; `AppleTV1`–`3` run Apple TV Software, not tvOS.
#[must_use]
pub fn is_tvos_hardware(model: &str) -> bool {
    apple_tv_generation(model).is_some_and(|n| n >= 5)
}

fn last_major(model: &str) -> Option<(&'static str, u32)> {
    LAST_MAJOR
        .iter()
        .find(|(id, _, _)| *id == model)
        .map(|&(_, name, major)| (name, major))
}

/// Floors above `version`.
#[must_use]
pub fn unfixed_floors(version: OsVersion) -> Vec<&'static TvosFixFloor> {
    TVOS_FIX_FLOORS
        .iter()
        .filter(|f| version < f.fixed)
        .collect()
}

fn format_version((major, minor, patch): OsVersion) -> String {
    if patch == 0 {
        format!("{major}.{minor}")
    } else {
        format!("{major}.{minor}.{patch}")
    }
}

fn update_steps() -> Vec<String> {
    vec![
        "On the Apple TV open Settings > System > Software Updates and choose Update Software."
            .to_owned(),
        "Turn on Automatically Update.".to_owned(),
    ]
}

/// Finding for an Apple TV below one or more fix floors.
#[must_use]
pub fn tvos_fix_finding(
    ip: IpAddr,
    port: u16,
    model: &str,
    osvers: &str,
    hint: &DeviceHint,
) -> Option<Finding> {
    if !is_tvos_hardware(model) {
        return None;
    }
    let version = parse_osvers(osvers)?;
    let floors = unfixed_floors(version);
    let target = floors.iter().map(|f| f.fixed).max()?;
    let kev = floors.iter().any(|f| f.kev);

    let mut listed = String::new();
    for (i, f) in floors.iter().enumerate() {
        let sep = if i == 0 { "" } else { "; " };
        let kev_note = if f.kev { ", in CISA KEV" } else { "" };
        let _ = write!(
            listed,
            "{sep}{} ({}, fixed in tvOS {}{kev_note})",
            f.cve,
            f.component,
            format_version(f.fixed)
        );
    }
    let target = format_version(target);

    let mut steps = update_steps();
    steps.push(format!(
        "Confirm Settings > System > Software Updates shows tvOS {target} or later. If no \
         such update is offered, this model cannot run a fixed release: replace it."
    ));
    let mut refs: Vec<String> = Vec::new();
    for f in &floors {
        if !refs.iter().any(|r| r == f.reference) {
            refs.push(f.reference.to_owned());
        }
    }

    Some(
        Finding::new(
            "mdns",
            &format!("tvOS {osvers} below security fix floor on {ip}"),
            &format!(
                "The Apple TV ({model}) at {ip} reports tvOS {osvers} in its AirPlay TXT \
                 record (osvers). Apple's security notes fix the following in later \
                 releases: {listed}."
            ),
            if kev {
                Severity::High
            } else {
                Severity::Medium
            },
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("AirPlay")
        .with_confidence(Confidence::Confirmed)
        .with_cve_ids(floors.iter().map(|f| f.cve.to_owned()).collect())
        .with_evidence(format!("model={model} osvers={osvers}"))
        .with_references(refs)
        .with_device_hint(hint.clone())
        .with_remediation(Remediation {
            description: format!("Update the Apple TV to tvOS {target} or later."),
            steps,
            effort: Some("15 minutes".to_owned()),
        }),
    )
}

/// Finding for an Apple TV on a tvOS major that was end-of-life on `today`.
#[must_use]
pub fn tvos_eol_finding(
    ip: IpAddr,
    port: u16,
    model: &str,
    osvers: &str,
    today: &str,
    hint: &DeviceHint,
) -> Option<Finding> {
    if !is_tvos_hardware(model) {
        return None;
    }
    parse_osvers(osvers)?;
    let entry = eol_db::lookup("tvos", osvers)?;
    if !eol_db::is_eol_on(entry, today) {
        return None;
    }
    let ended = entry.eol_from.unwrap_or("an unpublished date");
    let current = eol_db::current("tvos").map(|c| c.cycle);
    let capped = last_major(model).filter(|&(_, major)| {
        current
            .and_then(|c| c.parse::<u32>().ok())
            .is_some_and(|c| major < c)
    });

    let mut description = format!(
        "The Apple TV ({model}) at {ip} reports tvOS {osvers} in its AirPlay TXT record \
         (osvers). endoflife.date marks tvOS {} end-of-life from {ended} (snapshot {}).",
        entry.cycle,
        eol_db::EOL_SNAPSHOT,
    );
    let mut refs = vec![EOL_TVOS.to_owned()];
    let remediation = if let Some((name, major)) = capped {
        let _ = write!(
            description,
            " Apple lists tvOS {} for Apple TV 4K 2nd generation and later, so this \
             {name} stays on tvOS {major}. Apple may still ship occasional tvOS {major} \
             updates, but the supported major has moved on.",
            current.unwrap_or("27"),
        );
        refs.push(TVOS_27_NOTE.to_owned());
        let mut steps = update_steps();
        steps.push(format!(
            "This {name} cannot run a supported tvOS major. Replace it with a model that \
             can to keep receiving security updates."
        ));
        Remediation {
            description: format!("Replace the {name}; it cannot move past tvOS {major}."),
            steps,
            effort: Some("requires hardware change".to_owned()),
        }
    } else {
        let target = current.unwrap_or("a supported release");
        let mut steps = update_steps();
        steps.push(format!(
            "If Update Software does not offer tvOS {target}, this model cannot run a \
             supported major: replace it."
        ));
        Remediation {
            description: format!("Update the Apple TV to tvOS {target}."),
            steps,
            effort: Some("15 minutes".to_owned()),
        }
    };

    Some(
        Finding::new(
            "mdns",
            &format!("End-of-life tvOS {} on {ip}", entry.cycle),
            &description,
            Severity::Medium,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("AirPlay")
        .with_confidence(Confidence::Confirmed)
        .with_cwe("CWE-1104")
        .with_evidence(format!("model={model} osvers={osvers}"))
        .with_references(refs)
        .with_device_hint(hint.clone())
        .with_remediation(remediation),
    )
}

/// Access posture read from `flags` and `pw`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AirPlayAccess {
    /// `pw` true, or bit 3, 7 or 9 set.
    Restricted,
    /// Only bit 10 set: `HomeKit` access control, mode unknown.
    HomeKitControlled,
    /// Bits 3, 7, 9 and 10 clear and `pw` not true.
    Open,
    /// No parseable `flags`.
    Unknown,
}

/// Posture from raw `flags` and `pw` values.
#[must_use]
pub fn access_posture(flags: Option<&str>, pw: Option<&str>) -> AirPlayAccess {
    if pw.and_then(parse_pw) == Some(true) {
        return AirPlayAccess::Restricted;
    }
    let Some(bits) = flags.and_then(parse_flags) else {
        return AirPlayAccess::Unknown;
    };
    if bits & (FLAG_PIN_REQUIRED | FLAG_PASSWORD_REQUIRED | FLAG_ONE_TIME_PAIRING) != 0 {
        AirPlayAccess::Restricted
    } else if bits & FLAG_HOMEKIT_ACCESS_CONTROL != 0 {
        AirPlayAccess::HomeKitControlled
    } else {
        AirPlayAccess::Open
    }
}

fn access_remediation(apple_tv: bool) -> Remediation {
    if apple_tv {
        Remediation {
            description: "Restrict who can AirPlay to this Apple TV.".to_owned(),
            steps: vec![
                "On the Apple TV open Settings > AirPlay and HomeKit > Allow Access and choose \
                 Only People Sharing This Home."
                    .to_owned(),
                "Or choose Require Password and set a password.".to_owned(),
            ],
            effort: Some("5 minutes".to_owned()),
        }
    } else {
        Remediation {
            description: "Restrict who can AirPlay to this receiver.".to_owned(),
            steps: vec![
                "Check the receiver's AirPlay access or password setting, in its setup menu or \
                 companion app, and turn on a password or access restriction."
                    .to_owned(),
                "If it has none, keep it on a network segment limited to the devices that \
                 should stream to it."
                    .to_owned(),
            ],
            effort: Some("10 minutes".to_owned()),
        }
    }
}

/// Finding for an `Open` or `HomeKitControlled` receiver.
#[must_use]
pub fn access_finding(
    service: &MdnsService,
    model: Option<&str>,
    hint: &DeviceHint,
) -> Option<Finding> {
    let (ip, port) = (service.ip, service.port);
    let txt = &service.txt_records;
    let flags = txt_get(txt, "flags");
    let pw = txt_get(txt, "pw");
    let posture = access_posture(flags, pw);
    let apple_tv = model.is_some_and(|m| m.starts_with("AppleTV"));
    let what = model.map_or_else(
        || "AirPlay receiver".to_owned(),
        |m| format!("AirPlay receiver ({m})"),
    );
    let flags_text = flags.unwrap_or("absent");
    let pw_text = pw.unwrap_or("absent");
    let source = "Bit meanings are from the reverse-engineered openairplay status-flags spec.";

    let (title, description, severity) = match posture {
        AirPlayAccess::Open => (
            format!("AirPlay receiver without password or PIN on {ip}:{port}"),
            format!(
                "The {what} at {ip} advertises flags={flags_text} and pw={pw_text}. \
                 PINRequired (bit 3), PasswordRequired (bit 7), OneTimePairingRequired \
                 (bit 9) and DeviceWasSetupForHKAccessControl (bit 10) are all clear, so it \
                 appears to accept AirPlay streams without a password or on-screen code. \
                 TXT cannot distinguish \"Everyone\" from \"Anyone on the Same Network\". \
                 {source}"
            ),
            Severity::Low,
        ),
        AirPlayAccess::HomeKitControlled => (
            format!("AirPlay access governed by HomeKit on {ip}:{port}"),
            format!(
                "The {what} at {ip} advertises flags={flags_text} and pw={pw_text}. Only \
                 DeviceWasSetupForHKAccessControl (bit 10) is set; PINRequired (bit 3), \
                 PasswordRequired (bit 7) and OneTimePairingRequired (bit 9) are clear. \
                 Access follows the HomeKit setting, which TXT does not reveal: it may be \
                 \"Only People Sharing This Home\" or a wider option. {source}"
            ),
            Severity::Info,
        ),
        AirPlayAccess::Restricted | AirPlayAccess::Unknown => return None,
    };

    Some(
        Finding::new("mdns", &title, &description, severity)
            .with_ip(ip)
            .with_port(port)
            .with_service("AirPlay")
            .with_confidence(Confidence::Probable)
            .with_cwe("CWE-306")
            .with_evidence(format!("flags={flags_text} pw={pw_text}"))
            .with_references(if apple_tv {
                refs![STATUS_FLAGS_SPEC, ALLOW_ACCESS_GUIDE]
            } else {
                refs![STATUS_FLAGS_SPEC]
            })
            .with_device_hint(hint.clone())
            .with_remediation(access_remediation(apple_tv)),
    )
}

/// All checks for one `_airplay._tcp` service.
#[must_use]
pub fn airplay_findings(service: &MdnsService, hint: &DeviceHint, today: &str) -> Vec<Finding> {
    let txt = &service.txt_records;
    let model = txt_get(txt, "model");
    let mut findings = Vec::new();
    if let (Some(model), Some(osvers)) = (model, txt_get(txt, "osvers")) {
        findings.extend(tvos_fix_finding(
            service.ip,
            service.port,
            model,
            osvers,
            hint,
        ));
        findings.extend(tvos_eol_finding(
            service.ip,
            service.port,
            model,
            osvers,
            today,
            hint,
        ));
    }
    findings.extend(access_finding(service, model, hint));
    findings
}

#[cfg(test)]
mod tests;
