//! Client-side LAN exposure: devices attacked as *clients* of a service another
//! host on the network offers, rather than through a listening port of their own.
//!
//! Matching is on the OUI vendor against a curated table; no probe is sent.
//!
//! No finding populates `cve_ids`: a name match is not version evidence, and
//! `enrich_exploit_intelligence` escalates on that field (see
//! `no_row_ever_populates_cve_ids`). The id is named in the description and
//! references instead.

use async_trait::async_trait;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::{Device, Finding, Remediation, ScanContext};

use crate::Scanner;

/// Client-side LAN exposure scanner.
pub struct LanClientExposureScanner;

/// One curated client-side exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClientExposure {
    /// Lowercase substring of the IEEE OUI vendor name.
    vendor: &'static str,
    /// Product family as this tool names it in finding titles.
    product: &'static str,
    /// Lowercase model tokens that confirm the affected model, when any
    /// identification the scan collected happens to carry one.
    affected_models: &'static [&'static str],
    /// Lowercase whole-word model tokens the advisory does not name. A match
    /// downgrades to `Info`; the tokens are also ordinary room names.
    unaffected_models: &'static [&'static str],
    /// Protocol the device speaks *as a client*.
    protocol: &'static str,
    /// CVE id. Named in the finding text only; never put in `cve_ids`.
    cve: &'static str,
    /// What the bug is, in one sentence.
    summary: &'static str,
    /// Why no version comparison is performed.
    version_note: &'static str,
}

/// Curated table, sorted by vendor. Rows are added only for issues where the
/// vulnerable code path is reached by the device connecting out.
const CLIENT_EXPOSURES: &[ClientExposure] = &[ClientExposure {
    vendor: "sonos",
    product: "Sonos speaker",
    affected_models: &["era 300", "era300"],
    unaffected_models: &[
        "one", "beam", "move", "port", "amp", "roam", "arc", "five", "play", "playbar", "playbase",
        "sub", "connect",
    ],
    protocol: "SMB",
    cve: "CVE-2026-4149",
    summary: "an out-of-bounds write in the speaker's SMB client, reached when it \
              connects to a music-library share, which a hostile SMB server on the \
              same network can trigger for remote code execution on the speaker",
    version_note: "Sonos published a fixed build (83.1-61240) that it dates to \
                   2025-02-04, below the affected build 91.0-70070, so comparing \
                   firmware versions against the published floor would clear \
                   vulnerable speakers; no version check is performed",
}];

// ── Matching ────────────────────────────────────────────────────────────────

/// The exposure row for a device, if its OUI vendor matches one.
fn exposure_for(device: &Device) -> Option<&'static ClientExposure> {
    let vendor = device.vendor.as_ref()?.to_ascii_lowercase();
    CLIENT_EXPOSURES.iter().find(|e| vendor.contains(e.vendor))
}

/// What the names a device publishes say about its model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelEvidence {
    /// A published name matches `affected_models`.
    Affected,
    /// A published name carries this `unaffected_models` token.
    Unaffected(&'static str),
    /// Nothing the scan collected names a model.
    Unknown,
}

/// Lowercased identification the device published, for model matching.
fn published_names(device: &Device) -> String {
    [
        device.hostname.as_deref(),
        device.device_subtype.as_deref(),
        device.os_guess.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase()
}

/// Classify a device against one row. Affected wins over unaffected; absence of
/// any name is `Unknown`, never `Unaffected`.
fn model_evidence(device: &Device, exposure: &ClientExposure) -> ModelEvidence {
    let haystack = published_names(device);
    if exposure
        .affected_models
        .iter()
        .any(|model| haystack.contains(model))
    {
        return ModelEvidence::Affected;
    }
    // Whole-word only: `unaffected_models` holds single tokens, and a substring
    // match would suppress on any name containing one ("stone" -> "one").
    haystack
        .split(|c: char| !c.is_ascii_alphanumeric())
        .find_map(|word| {
            exposure
                .unaffected_models
                .iter()
                .find(|model| **model == word)
        })
        .map_or(ModelEvidence::Unknown, |model| {
            ModelEvidence::Unaffected(model)
        })
}

// ── Findings ────────────────────────────────────────────────────────────────

fn remediation(exposure: &ClientExposure) -> Remediation {
    Remediation {
        description: format!(
            "A client-side issue is not fixed by closing ports on the affected device: \
             the attack arrives when it connects out. Update it, and reduce the number \
             of hosts on its network that could serve a hostile {} endpoint.",
            exposure.protocol
        ),
        steps: vec![
            "Update the device to its current firmware from the vendor's own app; \
             client-side fixes ship in ordinary firmware updates."
                .to_owned(),
            format!(
                "Remove {} shares the device no longer needs — a device that never \
                 connects out cannot be attacked this way.",
                exposure.protocol
            ),
            "Put the device on a network segment where you control every host, and \
             treat any compromised machine on that segment as able to reach it."
                .to_owned(),
            "Keep an inventory of which devices act as clients of services other hosts \
             on this network offer; a port scan of the victim shows nothing here."
                .to_owned(),
        ],
        effort: Some("30 minutes".to_owned()),
    }
}

fn references() -> Vec<String> {
    refs![
        "https://www.zerodayinitiative.com/advisories/ZDI-26-192/",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-4149",
        "https://cwe.mitre.org/data/definitions/119.html",
    ]
}

/// Finding for one matched device. A published name the advisory does not list
/// downgrades to `Info`, never drops the row (see
/// `a_room_named_after_a_model_does_not_hide_the_device`).
fn exposure_finding(device: &Device, exposure: &ClientExposure) -> Finding {
    let evidence = model_evidence(device, exposure);
    let ip = device.ip;
    let vendor = device.vendor.as_deref().unwrap_or(exposure.product);

    let (severity, identification, evidence_text) = match evidence {
        ModelEvidence::Affected => (
            Severity::Medium,
            "The model this issue affects was identified from the name the device \
             publishes."
                .to_owned(),
            "model matches the affected family".to_owned(),
        ),
        ModelEvidence::Unaffected(token) => {
            tracing::debug!(
                %ip,
                token,
                cve = exposure.cve,
                "published name names a model the advisory does not; reporting at Info"
            );
            (
                Severity::Info,
                format!(
                    "A name this device publishes contains \"{token}\", a model {} does not \
                     name, so this is recorded for reference only. That rests on the advisory \
                     being model-specific and on the published name being a model rather than \
                     a room name.",
                    exposure.cve
                ),
                format!("published name contains the unaffected model token {token}"),
            )
        }
        ModelEvidence::Unknown => (
            Severity::Low,
            format!(
                "The device is identified as {vendor} from its MAC address only, so whether \
                 it is the affected model is unconfirmed."
            ),
            "model not confirmed".to_owned(),
        ),
    };

    let finding = Finding::new(
        "lan_client_exposure",
        &format!(
            "Client-side LAN exposure on {ip}: {} {} client",
            exposure.product, exposure.protocol
        ),
        &format!(
            "The device at {ip} is a {}, which acts as an {} client. A published issue in \
             that client ({}) is {}. The exposure runs the opposite way to everything a port \
             scan measures: nothing needs to be listening on this device, and the attack \
             platform is any host on this network that an attacker already controls — a \
             compromised laptop, a rented VM on a flat guest network, an IoT device with a \
             weak password. {identification} No probe was sent to this device; this finding \
             records a relationship, not a demonstrated vulnerability, so {} is named here \
             for reference and is deliberately not attached as a machine-readable CVE id — \
             nothing read here could clear it on a patched device. Note also that {}.",
            exposure.product,
            exposure.protocol,
            exposure.cve,
            exposure.summary,
            exposure.cve,
            exposure.version_note,
        ),
        severity,
    )
    .with_confidence(Confidence::Inferred)
    .with_ip(ip)
    .with_service(exposure.protocol)
    .with_cwe("CWE-119")
    .with_evidence(format!("OUI vendor {vendor}; {evidence_text}"))
    .with_remediation(remediation(exposure))
    .with_references(references());

    match device.mac {
        Some(mac) => finding.with_mac(mac),
        None => finding,
    }
}

#[async_trait]
impl Scanner for LanClientExposureScanner {
    fn id(&self) -> &'static str {
        "lan_client_exposure"
    }

    fn name(&self) -> &'static str {
        "Client-Side LAN Exposure"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running client-side LAN exposure scan");

        // No probe is sent. The runner still drops this scanner at Passive: it is in
        // neither `passive_essential` nor `relevant_ports` (runner.rs `filter_phase2`).
        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "lan_client_exposure".to_owned(),
                message: e.to_string(),
            })?;

        let findings: Vec<Finding> = ctx
            .discovered_devices
            .iter()
            .filter(|device| !exclusions.excludes_device(device))
            .filter_map(|device| {
                exposure_for(device).map(|exposure| exposure_finding(device, exposure))
            })
            .collect();

        tracing::info!(
            findings_count = findings.len(),
            "client-side LAN exposure scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_models::DeviceType;
    use std::net::IpAddr;

    fn device(vendor: Option<&str>) -> Device {
        let mut device = Device::new(IpAddr::from([192, 168, 1, 77]));
        device.vendor = vendor.map(ToOwned::to_owned);
        device.device_type = DeviceType::Speaker;
        device
    }

    // ── Table integrity ─────────────────────────────────────────────

    #[test]
    fn table_is_sorted_by_vendor() {
        let vendors: Vec<&str> = CLIENT_EXPOSURES.iter().map(|e| e.vendor).collect();
        let mut sorted = vendors.clone();
        sorted.sort_unstable();
        assert_eq!(vendors, sorted);
    }

    #[test]
    fn every_row_is_resolvable_and_lowercase() {
        for row in CLIENT_EXPOSURES {
            assert_eq!(row.vendor, row.vendor.to_ascii_lowercase());
            assert!(!row.vendor.is_empty());
            assert!(row.cve.starts_with("CVE-"));
            assert!(!row.summary.is_empty());
            assert!(!row.version_note.is_empty());
            for model in row.affected_models {
                assert_eq!(*model, model.to_ascii_lowercase());
            }
            for model in row.unaffected_models {
                assert_eq!(*model, model.to_ascii_lowercase());
                assert!(
                    model.chars().all(|c| c.is_ascii_alphanumeric()),
                    "{model} is matched as a whole word, so it must be one token"
                );
                assert!(
                    !row.affected_models.iter().any(|a| a.contains(*model)),
                    "{model} is listed as both affected and unaffected"
                );
                // Whole-word too: an affected model naming this token would make
                // every affected device look unaffected.
                assert!(
                    !row.affected_models.iter().any(|affected| affected
                        .split(|c: char| !c.is_ascii_alphanumeric())
                        .any(|word| word == *model)),
                    "{model} is a word of an affected model name"
                );
            }
            // Each row must resolve from a device carrying that vendor string.
            let probe = device(Some(row.vendor));
            assert_eq!(exposure_for(&probe), Some(row));
        }
    }

    #[test]
    fn vendor_matching_is_case_insensitive_and_substring() {
        assert!(exposure_for(&device(Some("Sonos, Inc."))).is_some());
        assert!(exposure_for(&device(Some("SONOS"))).is_some());
        assert!(exposure_for(&device(Some("sonos inc"))).is_some());
    }

    #[test]
    fn unrelated_vendors_do_not_match() {
        assert!(exposure_for(&device(Some("Apple, Inc."))).is_none());
        assert!(exposure_for(&device(Some(""))).is_none());
        assert!(exposure_for(&device(None)).is_none());
    }

    // ── Model confirmation ──────────────────────────────────────────

    #[test]
    fn model_is_confirmed_from_published_names() {
        let exposure = &CLIENT_EXPOSURES[0];
        let mut dev = device(Some("Sonos, Inc."));
        assert_eq!(model_evidence(&dev, exposure), ModelEvidence::Unknown);

        dev.hostname = Some("Sonos-Era 300-Kitchen".to_owned());
        assert_eq!(model_evidence(&dev, exposure), ModelEvidence::Affected);

        dev.hostname = None;
        dev.device_subtype = Some("sonos_era300".to_owned());
        assert_eq!(model_evidence(&dev, exposure), ModelEvidence::Affected);
    }

    #[test]
    fn a_named_unaffected_model_reports_at_info_naming_the_token() {
        let exposure = &CLIENT_EXPOSURES[0];
        for (name, token) in [
            ("Sonos-Beam-Lounge", "beam"),
            ("sonos one sl", "one"),
            ("Sonos_Port", "port"),
            ("SONOS-ARC", "arc"),
        ] {
            let mut dev = device(Some("Sonos, Inc."));
            dev.hostname = Some(name.to_owned());
            assert_eq!(
                model_evidence(&dev, exposure),
                ModelEvidence::Unaffected(token),
                "{name}"
            );
            let finding = exposure_finding(&dev, exposure);
            assert_eq!(finding.severity, Severity::Info, "{name}");
            assert!(finding.description.contains(token), "{name}");
            assert!(finding.evidence.unwrap().contains(token), "{name}");
        }
    }

    #[test]
    fn a_room_named_after_a_model_does_not_hide_the_device() {
        let exposure = &CLIENT_EXPOSURES[0];
        let mut dev = device(Some("Sonos, Inc."));
        dev.hostname = Some("sonos-arc-room".to_owned());
        let finding = exposure_finding(&dev, exposure);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.affected_ip, Some(dev.ip));
    }

    #[test]
    fn unaffected_tokens_match_whole_words_only() {
        let exposure = &CLIENT_EXPOSURES[0];
        let mut dev = device(Some("Sonos, Inc."));
        dev.hostname = Some("sonos-stonehenge".to_owned());
        assert_eq!(model_evidence(&dev, exposure), ModelEvidence::Unknown);
        assert_eq!(exposure_finding(&dev, exposure).severity, Severity::Low);
    }

    #[test]
    fn an_affected_model_is_not_suppressed_by_a_stray_token() {
        let exposure = &CLIENT_EXPOSURES[0];
        let mut dev = device(Some("Sonos, Inc."));
        dev.hostname = Some("sonos era 300 arc room".to_owned());
        assert_eq!(model_evidence(&dev, exposure), ModelEvidence::Affected);
    }

    // ── Findings ────────────────────────────────────────────────────

    #[test]
    fn unconfirmed_model_is_low_inferred_without_a_cve() {
        let dev = device(Some("Sonos, Inc."));
        let finding = exposure_finding(&dev, &CLIENT_EXPOSURES[0]);
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.confidence, Confidence::Inferred);
        assert!(finding.cve_ids.is_empty());
        assert!(finding.description.contains("unconfirmed"));
        assert!(
            finding
                .description
                .contains("not attached as a machine-readable CVE id")
        );
    }

    #[test]
    fn confirmed_model_is_medium_and_still_carries_no_cve_id() {
        let mut dev = device(Some("Sonos, Inc."));
        dev.hostname = Some("sonos-era 300".to_owned());
        let finding = exposure_finding(&dev, &CLIENT_EXPOSURES[0]);
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.confidence, Confidence::Inferred);
        assert!(finding.cve_ids.is_empty());
    }

    /// `cve_ids` is what `enrich_exploit_intelligence` escalates on. A hostname
    /// substring is not version evidence, so no row may ever populate it.
    #[test]
    fn no_row_ever_populates_cve_ids() {
        for row in CLIENT_EXPOSURES {
            let mut dev = device(Some(row.vendor));
            for model in row.affected_models {
                dev.hostname = Some((*model).to_owned());
                let finding = exposure_finding(&dev, row);
                assert!(
                    finding.cve_ids.is_empty(),
                    "{} would escalate on the next KEV refresh",
                    row.cve
                );
                assert!(
                    finding.description.contains(row.cve),
                    "{} is not named in the description",
                    row.cve
                );
            }
        }
    }

    #[test]
    fn references_still_carry_the_advisory() {
        let finding = exposure_finding(&device(Some("Sonos")), &CLIENT_EXPOSURES[0]);
        assert!(
            finding
                .references
                .iter()
                .any(|r| r.contains("CVE-2026-4149"))
        );
    }

    #[test]
    fn finding_explains_why_no_version_check_runs() {
        let finding = exposure_finding(&device(Some("Sonos")), &CLIENT_EXPOSURES[0]);
        assert!(finding.description.contains("83.1-61240"));
        assert!(finding.description.contains("91.0-70070"));
    }

    #[test]
    fn finding_states_the_inverted_direction() {
        let finding = exposure_finding(&device(Some("Sonos")), &CLIENT_EXPOSURES[0]);
        assert!(finding.description.contains("opposite way"));
        assert!(finding.description.contains("No probe was sent"));
    }

    #[test]
    fn titles_are_stable_whether_or_not_the_model_is_confirmed() {
        let plain = device(Some("Sonos, Inc."));
        let mut named = plain.clone();
        named.hostname = Some("sonos-era 300".to_owned());
        assert_eq!(
            exposure_finding(&plain, &CLIENT_EXPOSURES[0]).title,
            exposure_finding(&named, &CLIENT_EXPOSURES[0]).title
        );
    }

    #[test]
    fn no_port_is_attached() {
        // The device listens on nothing relevant; attaching a port would imply
        // an inbound service.
        let finding = exposure_finding(&device(Some("Sonos")), &CLIENT_EXPOSURES[0]);
        assert!(finding.affected_port.is_none());
        assert_eq!(finding.affected_service.as_deref(), Some("SMB"));
    }

    proptest! {
        /// Arbitrary vendor and hostname strings never panic the matcher.
        #[test]
        fn matching_never_panics(vendor in ".*", hostname in ".*") {
            let mut dev = device(Some(&vendor));
            dev.hostname = Some(hostname);
            if let Some(exposure) = exposure_for(&dev) {
                let finding = exposure_finding(&dev, exposure);
                prop_assert!(finding.title.starts_with("Client-side LAN exposure"));
            }
        }
    }
}
