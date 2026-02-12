//! Passive `WiFi` monitoring — capture and analyse 802.11 management frames.
//!
//! Puts the `WiFi` interface into monitor mode, captures management frames for a
//! configurable duration, then analyses the captured data to produce security findings.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use rikitikitavi_core::Severity;
use rikitikitavi_models::Finding;
use rikitikitavi_network::wifi_frames::{
    self, BeaconFrame, DeauthFrame, DisassocFrame, EncryptionType, FrameType, MacAddress,
    ProbeRequestFrame,
};

// ── Scanner ID ──────────────────────────────────────────────────────────

const SCANNER_ID: &str = "passive_wifi";

// ── Thresholds ──────────────────────────────────────────────────────────

/// Number of deauth/disassoc frames from the same source that constitutes a flood.
const DEAUTH_FLOOD_THRESHOLD: usize = 10;

// ── Capture results ─────────────────────────────────────────────────────

/// Accumulated results from a passive `WiFi` capture session.
#[derive(Debug, Default)]
pub struct MonitorResults {
    /// Deduplicated beacons by BSSID.
    pub beacons: HashMap<MacAddress, BeaconFrame>,
    /// All observed probe requests.
    pub probe_requests: Vec<ProbeRequestFrame>,
    /// All deauthentication frames.
    pub deauth_events: Vec<DeauthFrame>,
    /// All disassociation frames.
    pub disassoc_events: Vec<DisassocFrame>,
    /// How long the capture ran.
    pub capture_duration: Duration,
    /// Total number of frames processed.
    pub frame_count: u64,
}

// ── pcap capture ────────────────────────────────────────────────────────

/// Run a passive capture on the given monitor interface for `duration`.
///
/// The interface must already be in monitor mode (via [`wifi_monitor::setup_monitor`]).
///
/// # Errors
///
/// Returns an error if pcap cannot open the interface or apply the BPF filter.
#[cfg(feature = "monitor")]
pub fn capture_frames(interface: &str, duration: Duration) -> anyhow::Result<MonitorResults> {
    use pcap::{Capture, Device};

    let device = Device::from(interface);
    let mut cap = Capture::from_device(device)?
        .timeout(1000) // 1-second read timeout for responsiveness
        .snaplen(512) // Management frames are small; 512 bytes is plenty
        .open()?;

    // BPF filter: only management frames (type 0)
    cap.filter("type mgt", true)?;

    let mut results = MonitorResults::default();
    let start = Instant::now();

    while start.elapsed() < duration {
        match cap.next_packet() {
            Ok(packet) => {
                results.frame_count += 1;
                if let Some(frame_type) = wifi_frames::parse_frame(packet.data) {
                    accumulate_frame(&mut results, frame_type);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => {
                tracing::warn!("pcap read error: {e}");
                break;
            }
        }
    }

    results.capture_duration = start.elapsed();
    tracing::info!(
        frames = results.frame_count,
        beacons = results.beacons.len(),
        probes = results.probe_requests.len(),
        deauths = results.deauth_events.len(),
        duration_secs = results.capture_duration.as_secs(),
        "passive capture complete"
    );

    Ok(results)
}

/// Accumulate a parsed frame into the results.
fn accumulate_frame(results: &mut MonitorResults, frame: FrameType) {
    match frame {
        FrameType::Beacon(b) => {
            // Keep the strongest-signal beacon per BSSID
            results
                .beacons
                .entry(b.bssid)
                .and_modify(|existing| {
                    if b.signal_dbm > existing.signal_dbm {
                        *existing = b.clone();
                    }
                })
                .or_insert(b);
        }
        FrameType::ProbeRequest(pr) => {
            results.probe_requests.push(pr);
        }
        FrameType::Deauth(d) => {
            results.deauth_events.push(d);
        }
        FrameType::Disassoc(d) => {
            results.disassoc_events.push(d);
        }
        // Probe responses tracked indirectly through beacons; Other frames ignored.
        FrameType::ProbeResponse(_) | FrameType::Other => {}
    }
}

// ── Analysis → Findings ─────────────────────────────────────────────────

/// Analyse captured monitor results and generate security findings.
///
/// `known_bssids` is a set of expected AP MAC addresses (e.g. your own APs).
/// `home_ssid` is the expected SSID of your home network (for rogue AP detection).
#[allow(clippy::too_many_lines)]
pub fn analyse_results<S: ::std::hash::BuildHasher>(
    results: &MonitorResults,
    known_bssids: &HashSet<MacAddress, S>,
    home_ssid: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // ── Capture summary (always) ────────────────────────────────────
    findings.push(
        Finding::new(
            SCANNER_ID,
            "Passive WiFi capture summary",
            &format!(
                "Captured {} frames in {}s: {} unique APs, {} probe requests, \
                 {} deauth frames, {} disassoc frames.",
                results.frame_count,
                results.capture_duration.as_secs(),
                results.beacons.len(),
                results.probe_requests.len(),
                results.deauth_events.len(),
                results.disassoc_events.len(),
            ),
            Severity::Info,
        )
        .with_evidence(format!(
            "Duration: {}s, Frames: {}",
            results.capture_duration.as_secs(),
            results.frame_count,
        )),
    );

    // ── Open/WEP networks ───────────────────────────────────────────
    detect_weak_encryption(&results.beacons, &mut findings);

    // ── Deauth/disassoc flood detection ─────────────────────────────
    detect_deauth_flood(
        &results.deauth_events,
        &results.disassoc_events,
        &mut findings,
    );

    // ── Rogue AP detection ──────────────────────────────────────────
    if let Some(ssid) = home_ssid {
        detect_rogue_aps(&results.beacons, known_bssids, ssid, &mut findings);
    }

    // ── Device tracking / privacy analysis ──────────────────────────
    detect_device_tracking(&results.probe_requests, &mut findings);

    findings
}

/// Detect open or WEP-encrypted networks.
fn detect_weak_encryption(beacons: &HashMap<MacAddress, BeaconFrame>, findings: &mut Vec<Finding>) {
    for beacon in beacons.values() {
        let ssid_display = beacon.ssid.as_deref().unwrap_or("<hidden>");

        match beacon.encryption {
            EncryptionType::Open => {
                let signal = beacon
                    .signal_dbm
                    .map_or(String::new(), |s| format!(" ({s} dBm)"));
                findings.push(
                    Finding::new(
                        SCANNER_ID,
                        &format!("Open WiFi network: {ssid_display}"),
                        &format!(
                            "Detected an unencrypted WiFi network \"{ssid_display}\" (BSSID: {}){signal}. \
                             Anyone within range can intercept all traffic on this network.",
                            wifi_frames::format_mac(&beacon.bssid),
                        ),
                        Severity::Critical,
                    )
                    .with_mac(wifi_frames::format_mac(&beacon.bssid))
                    .with_cwe("CWE-319"),
                );
            }
            EncryptionType::Wep => {
                findings.push(
                    Finding::new(
                        SCANNER_ID,
                        &format!("WEP-encrypted network: {ssid_display}"),
                        &format!(
                            "Detected a WEP-encrypted WiFi network \"{ssid_display}\" (BSSID: {}). \
                             WEP can be cracked in minutes with freely available tools.",
                            wifi_frames::format_mac(&beacon.bssid),
                        ),
                        Severity::High,
                    )
                    .with_mac(wifi_frames::format_mac(&beacon.bssid))
                    .with_cwe("CWE-326"),
                );
            }
            _ => {}
        }
    }
}

/// Detect deauthentication/disassociation floods (potential attack).
fn detect_deauth_flood(
    deauths: &[DeauthFrame],
    disassocs: &[DisassocFrame],
    findings: &mut Vec<Finding>,
) {
    // Count events per source MAC
    let mut source_counts: HashMap<MacAddress, usize> = HashMap::new();
    for d in deauths {
        *source_counts.entry(d.source).or_insert(0) += 1;
    }
    for d in disassocs {
        *source_counts.entry(d.source).or_insert(0) += 1;
    }

    for (source, count) in &source_counts {
        if *count >= DEAUTH_FLOOD_THRESHOLD {
            findings.push(
                Finding::new(
                    SCANNER_ID,
                    &format!("Deauth flood from {}", wifi_frames::format_mac(source),),
                    &format!(
                        "Detected {count} deauthentication/disassociation frames from {}. \
                         This may indicate a WiFi deauthentication attack attempting to \
                         disconnect devices or force them to reconnect to a rogue AP.",
                        wifi_frames::format_mac(source),
                    ),
                    Severity::High,
                )
                .with_mac(wifi_frames::format_mac(source))
                .with_cwe("CWE-400")
                .with_evidence(format!("{count} deauth/disassoc frames from single source")),
            );
        }
    }
}

/// Detect rogue APs broadcasting your home SSID with unknown BSSIDs.
fn detect_rogue_aps<S: ::std::hash::BuildHasher>(
    beacons: &HashMap<MacAddress, BeaconFrame>,
    known_bssids: &HashSet<MacAddress, S>,
    home_ssid: &str,
    findings: &mut Vec<Finding>,
) {
    for beacon in beacons.values() {
        let ssid_matches = beacon.ssid.as_deref().is_some_and(|s| s == home_ssid);

        if ssid_matches && !known_bssids.contains(&beacon.bssid) {
            let signal = beacon
                .signal_dbm
                .map_or(String::new(), |s| format!(" ({s} dBm)"));
            findings.push(
                Finding::new(
                    SCANNER_ID,
                    &format!(
                        "Possible rogue AP: {}",
                        wifi_frames::format_mac(&beacon.bssid),
                    ),
                    &format!(
                        "Detected an AP broadcasting your home SSID \"{home_ssid}\" with \
                         unknown BSSID {}{signal}. This could be an evil twin attack.",
                        wifi_frames::format_mac(&beacon.bssid),
                    ),
                    Severity::High,
                )
                .with_mac(wifi_frames::format_mac(&beacon.bssid))
                .with_cwe("CWE-290")
                .with_evidence(format!(
                    "SSID \"{home_ssid}\" from unknown BSSID {}",
                    wifi_frames::format_mac(&beacon.bssid),
                )),
            );
        }
    }
}

/// Detect device tracking via probe requests and MAC address analysis.
fn detect_device_tracking(probes: &[ProbeRequestFrame], findings: &mut Vec<Finding>) {
    // Group probes by source MAC
    let mut by_mac: HashMap<MacAddress, Vec<&ProbeRequestFrame>> = HashMap::new();
    for pr in probes {
        by_mac.entry(pr.source_mac).or_default().push(pr);
    }

    // Directed probes (privacy leak — reveals networks the device remembers)
    let mut directed_ssids: HashSet<String> = HashSet::new();
    let mut directed_macs: HashSet<MacAddress> = HashSet::new();

    for (mac, reqs) in &by_mac {
        for pr in reqs {
            if let Some(ref ssid) = pr.ssid {
                directed_ssids.insert(ssid.clone());
                directed_macs.insert(*mac);
            }
        }
    }

    if !directed_ssids.is_empty() {
        let ssid_list: Vec<&str> = directed_ssids.iter().map(String::as_str).collect();
        let truncated = if ssid_list.len() > 10 {
            format!(
                "{} (and {} more)",
                ssid_list[..10].join(", "),
                ssid_list.len() - 10
            )
        } else {
            ssid_list.join(", ")
        };

        findings.push(
            Finding::new(
                SCANNER_ID,
                &format!(
                    "Devices probing for {} specific network(s)",
                    directed_ssids.len(),
                ),
                &format!(
                    "{} device(s) are sending directed probe requests for specific SSIDs: {truncated}. \
                     This reveals remembered network names and can be used for device tracking.",
                    directed_macs.len(),
                ),
                Severity::Medium,
            )
            .with_cwe("CWE-200"),
        );
    }

    // MAC randomization check
    let mut non_random_macs: Vec<MacAddress> = Vec::new();
    for (mac, reqs) in &by_mac {
        if reqs.len() >= 2 && !wifi_frames::is_locally_administered(mac) {
            non_random_macs.push(*mac);
        }
    }

    if !non_random_macs.is_empty() {
        let mac_list: Vec<String> = non_random_macs
            .iter()
            .take(10)
            .map(wifi_frames::format_mac)
            .collect();

        findings.push(
            Finding::new(
                SCANNER_ID,
                &format!(
                    "{} device(s) not using MAC randomization",
                    non_random_macs.len(),
                ),
                &format!(
                    "The following device(s) are sending multiple probe requests with their \
                     real (globally unique) MAC address, enabling cross-network tracking: {}",
                    mac_list.join(", "),
                ),
                Severity::Low,
            )
            .with_cwe("CWE-200"),
        );
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_beacon(
        bssid: MacAddress,
        ssid: Option<&str>,
        encryption: EncryptionType,
    ) -> BeaconFrame {
        BeaconFrame {
            bssid,
            ssid: ssid.map(str::to_owned),
            channel: Some(6),
            encryption,
            signal_dbm: Some(-50),
        }
    }

    fn make_deauth(source: MacAddress) -> DeauthFrame {
        DeauthFrame {
            source,
            destination: [0xFF; 6],
            bssid: source,
            reason_code: 7,
        }
    }

    fn make_probe(source_mac: MacAddress, ssid: Option<&str>) -> ProbeRequestFrame {
        ProbeRequestFrame {
            source_mac,
            ssid: ssid.map(str::to_owned),
            signal_dbm: Some(-60),
        }
    }

    #[test]
    fn test_detect_open_network() {
        let mut beacons = HashMap::new();
        let bssid = [0xAA; 6];
        beacons.insert(
            bssid,
            make_beacon(bssid, Some("OpenCafe"), EncryptionType::Open),
        );

        let mut findings = Vec::new();
        detect_weak_encryption(&beacons, &mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("Open WiFi"));
    }

    #[test]
    fn test_detect_wep_network() {
        let mut beacons = HashMap::new();
        let bssid = [0xBB; 6];
        beacons.insert(
            bssid,
            make_beacon(bssid, Some("LegacyNet"), EncryptionType::Wep),
        );

        let mut findings = Vec::new();
        detect_weak_encryption(&beacons, &mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("WEP"));
    }

    #[test]
    fn test_no_finding_for_wpa2() {
        let mut beacons = HashMap::new();
        let bssid = [0xCC; 6];
        beacons.insert(
            bssid,
            make_beacon(bssid, Some("SecureNet"), EncryptionType::Wpa2),
        );

        let mut findings = Vec::new();
        detect_weak_encryption(&beacons, &mut findings);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_deauth_flood_detection() {
        let source = [0x11; 6];
        let deauths: Vec<_> = (0..15).map(|_| make_deauth(source)).collect();

        let mut findings = Vec::new();
        detect_deauth_flood(&deauths, &[], &mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("Deauth flood"));
    }

    #[test]
    fn test_deauth_below_threshold() {
        let source = [0x11; 6];
        let deauths: Vec<_> = (0..5).map(|_| make_deauth(source)).collect();

        let mut findings = Vec::new();
        detect_deauth_flood(&deauths, &[], &mut findings);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_deauth_flood_multiple_sources() {
        let src1 = [0x11; 6];
        let src2 = [0x22; 6];
        let mut deauths: Vec<_> = (0..15).map(|_| make_deauth(src1)).collect();
        deauths.extend((0..3).map(|_| make_deauth(src2)));

        let mut findings = Vec::new();
        detect_deauth_flood(&deauths, &[], &mut findings);

        // Only source 1 should trigger
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_rogue_ap_detection() {
        let known_bssid = [0xAA; 6];
        let rogue_bssid = [0xBB; 6];

        let mut beacons = HashMap::new();
        beacons.insert(
            known_bssid,
            make_beacon(known_bssid, Some("HomeNet"), EncryptionType::Wpa2),
        );
        beacons.insert(
            rogue_bssid,
            make_beacon(rogue_bssid, Some("HomeNet"), EncryptionType::Wpa2),
        );

        let mut known = HashSet::new();
        known.insert(known_bssid);

        let mut findings = Vec::new();
        detect_rogue_aps(&beacons, &known, "HomeNet", &mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("rogue AP"));
    }

    #[test]
    fn test_no_rogue_for_known_bssid() {
        let bssid = [0xAA; 6];
        let mut beacons = HashMap::new();
        beacons.insert(
            bssid,
            make_beacon(bssid, Some("HomeNet"), EncryptionType::Wpa2),
        );

        let mut known = HashSet::new();
        known.insert(bssid);

        let mut findings = Vec::new();
        detect_rogue_aps(&beacons, &known, "HomeNet", &mut findings);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_directed_probe_detection() {
        // Non-randomized MAC (bit 1 of first octet clear)
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let probes = vec![
            make_probe(mac, Some("WorkWifi")),
            make_probe(mac, Some("HomeWifi")),
        ];

        let mut findings = Vec::new();
        detect_device_tracking(&probes, &mut findings);

        // Should have both directed-probes finding and non-random MAC finding
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.severity == Severity::Medium));
        assert!(findings.iter().any(|f| f.severity == Severity::Low));
    }

    #[test]
    fn test_randomized_mac_no_finding() {
        // Locally administered MAC (bit 1 of first octet set)
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let probes = vec![
            make_probe(mac, None), // broadcast probes
            make_probe(mac, None),
        ];

        let mut findings = Vec::new();
        detect_device_tracking(&probes, &mut findings);

        // No directed probes, MAC is randomized → no findings
        assert!(findings.is_empty());
    }

    #[test]
    fn test_analyse_results_summary() {
        let results = MonitorResults {
            beacons: HashMap::new(),
            probe_requests: Vec::new(),
            deauth_events: Vec::new(),
            disassoc_events: Vec::new(),
            capture_duration: Duration::from_secs(30),
            frame_count: 100,
        };

        let findings = analyse_results(&results, &HashSet::new(), None);

        // Should always have at least the summary finding
        assert!(!findings.is_empty());
        assert!(findings[0].title.contains("summary"));
    }

    #[test]
    fn test_analyse_results_combined() {
        let open_bssid = [0xAA; 6];
        let attacker = [0xBB; 6];

        let mut beacons = HashMap::new();
        beacons.insert(
            open_bssid,
            make_beacon(open_bssid, Some("FreeWifi"), EncryptionType::Open),
        );

        let deauths: Vec<_> = (0..20).map(|_| make_deauth(attacker)).collect();

        let results = MonitorResults {
            beacons,
            probe_requests: Vec::new(),
            deauth_events: deauths,
            disassoc_events: Vec::new(),
            capture_duration: Duration::from_secs(60),
            frame_count: 500,
        };

        let findings = analyse_results(&results, &HashSet::new(), None);

        // Summary + open network + deauth flood = at least 3
        assert!(findings.len() >= 3);
    }

    #[test]
    fn test_accumulate_beacon_strongest_signal() {
        let bssid = [0xAA; 6];
        let weak = FrameType::Beacon(BeaconFrame {
            bssid,
            ssid: Some("Test".to_owned()),
            channel: Some(6),
            encryption: EncryptionType::Wpa2,
            signal_dbm: Some(-80),
        });
        let strong = FrameType::Beacon(BeaconFrame {
            bssid,
            ssid: Some("Test".to_owned()),
            channel: Some(6),
            encryption: EncryptionType::Wpa2,
            signal_dbm: Some(-40),
        });

        let mut results = MonitorResults::default();
        accumulate_frame(&mut results, weak);
        accumulate_frame(&mut results, strong);

        assert_eq!(results.beacons.len(), 1);
        assert_eq!(results.beacons[&bssid].signal_dbm, Some(-40));
    }
}
