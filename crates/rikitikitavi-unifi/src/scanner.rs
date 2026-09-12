use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, Remediation, ScanContext};
use rikitikitavi_scanners::Scanner;

use crate::api::UniFiClient;
use crate::models::{FirewallRule, WlanConfig};

/// `UniFi` scanner: audits WLAN configs, firewall rules, device firmware, and IDS events
/// via the controller API.
pub struct UniFiScanner;

/// SSID substrings that indicate a default or unconfigured network.
const DEFAULT_SSIDS: &[&str] = &[
    "UniFi", "UBNT", "Ubiquiti", "default", "linksys", "netgear", "HOME-", "SETUP",
];

/// Findings for one WLAN config.
#[allow(clippy::too_many_lines)]
pub fn audit_wlan(wlan: &WlanConfig) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !wlan.enabled {
        findings.push(Finding::new(
            "unifi",
            &format!("WLAN \"{}\" is disabled", wlan.name),
            &format!(
                "WLAN configuration \"{}\" exists but is disabled. This is informational.",
                wlan.name
            ),
            Severity::Info,
        ));
        return findings;
    }

    let security_lower = wlan.security.to_lowercase();
    if security_lower == "open" || security_lower.is_empty() {
        findings.push(
            Finding::new(
                "unifi",
                &format!("WLAN \"{}\" has no encryption", wlan.name),
                &format!(
                    "WLAN \"{}\" is configured as an open network with no encryption. \
                     All traffic is transmitted in cleartext.",
                    wlan.name
                ),
                Severity::Critical,
            )
            .with_cwe("CWE-319"),
        );
    }

    if let Some(wpa_mode) = &wlan.wpa_mode {
        let wpa_lower = wpa_mode.to_lowercase();
        if wpa_lower.contains("wpa1") || wpa_lower == "wpa" {
            findings.push(
                Finding::new(
                    "unifi",
                    &format!("WLAN \"{}\" uses WPA1 (weak)", wlan.name),
                    &format!(
                        "WLAN \"{}\" is configured with WPA1 (TKIP), which has known \
                         cryptographic weaknesses. Upgrade to WPA2 or WPA3.",
                        wlan.name
                    ),
                    Severity::High,
                )
                .with_cwe("CWE-327")
                .with_remediation(Remediation {
                    description: "Upgrade WLAN security to WPA2 or WPA3.".to_owned(),
                    steps: vec![
                        "Open UniFi Network Settings.".to_owned(),
                        format!("Edit WLAN \"{}\".", wlan.name),
                        "Change security protocol to WPA2 or WPA3.".to_owned(),
                    ],
                    effort: Some("2 minutes".to_owned()),
                }),
            );
        }
    }

    // PMF = Protected Management Frames (802.11w)
    if let Some(pmf) = &wlan.pmf_mode {
        let pmf_lower = pmf.to_lowercase();
        if pmf_lower == "disabled" || pmf_lower == "optional" {
            findings.push(
                Finding::new(
                    "unifi",
                    &format!(
                        "PMF {} on WLAN \"{}\"",
                        if pmf_lower == "disabled" {
                            "disabled"
                        } else {
                            "optional"
                        },
                        wlan.name
                    ),
                    &format!(
                        "WLAN \"{}\" has Protected Management Frames (802.11w) set to \"{}\". \
                         Without PMF, the network is vulnerable to deauthentication attacks. \
                         Enable PMF (required mode) for WPA3 compliance.",
                        wlan.name, pmf
                    ),
                    Severity::Medium,
                )
                .with_cwe("CWE-693"),
            );
        }
    }

    let ssid_lower = wlan.name.to_lowercase();
    let is_default = DEFAULT_SSIDS
        .iter()
        .any(|d| ssid_lower.contains(&d.to_lowercase()));
    if is_default {
        findings.push(Finding::new(
            "unifi",
            &format!("Default/common SSID: \"{}\"", wlan.name),
            &format!(
                "WLAN \"{}\" uses a default or commonly-seen SSID. While not a direct \
                 vulnerability, default SSIDs reveal the equipment brand and suggest the \
                 network may not have been fully configured.",
                wlan.name
            ),
            Severity::Low,
        ));
    }

    if wlan.is_guest {
        findings.push(Finding::new(
            "unifi",
            &format!("Guest network: \"{}\"", wlan.name),
            &format!(
                "WLAN \"{}\" is configured as a guest network. Verify that guest isolation \
                 is enabled and guests cannot access internal resources.",
                wlan.name
            ),
            Severity::Info,
        ));
    }

    findings
}

/// Findings for a set of firewall rules.
pub fn audit_firewall_rules(rules: &[FirewallRule]) -> Vec<Finding> {
    let mut findings = Vec::new();

    if rules.is_empty() {
        findings.push(Finding::new(
            "unifi",
            "No custom firewall rules configured",
            "No custom firewall rules are configured on the controller. The default \
             UniFi firewall allows all inter-VLAN traffic. Consider adding rules to \
             restrict traffic between VLANs.",
            Severity::Medium,
        ));
        return findings;
    }

    for rule in rules {
        let name = rule.name.as_deref().unwrap_or("(unnamed)");

        if !rule.enabled {
            findings.push(Finding::new(
                "unifi",
                &format!("Firewall rule disabled: \"{name}\""),
                &format!(
                    "Firewall rule \"{name}\" (action: {}) is disabled. Review whether \
                     this rule should be active.",
                    rule.action
                ),
                Severity::Info,
            ));
            continue;
        }

        let src_any = rule
            .src
            .as_deref()
            .is_none_or(|s| s == "any" || s.is_empty());
        let dst_any = rule
            .dst
            .as_deref()
            .is_none_or(|d| d == "any" || d.is_empty());

        if rule.action.to_lowercase() == "accept" && src_any && dst_any {
            findings.push(
                Finding::new(
                    "unifi",
                    &format!("Overly permissive firewall rule: \"{name}\""),
                    &format!(
                        "Firewall rule \"{name}\" allows all traffic from any source to \
                         any destination. This effectively disables the firewall for the \
                         affected traffic zone. Consider restricting source and destination \
                         to specific networks.",
                    ),
                    Severity::High,
                )
                .with_cwe("CWE-284")
                .with_remediation(Remediation {
                    description: "Restrict the firewall rule to specific networks.".to_owned(),
                    steps: vec![
                        "Open UniFi Firewall & Security settings.".to_owned(),
                        format!("Edit rule \"{name}\"."),
                        "Set specific source and destination networks.".to_owned(),
                    ],
                    effort: Some("5 minutes".to_owned()),
                }),
            );
        }
    }

    findings
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl Scanner for UniFiScanner {
    fn id(&self) -> &'static str {
        "unifi"
    }

    fn name(&self) -> &'static str {
        "UniFi Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running UniFi security scan");
        let mut findings = Vec::new();

        let local_env = crate::local::UniFiEnvironment::detect();
        if let Some(env) = &local_env {
            findings.push(Finding::new(
                "unifi",
                &format!("Running on UniFi device: {:?}", env.device_type),
                &format!(
                    "Detected UniFi device type: {:?}. UniFi OS version: {}. \
                     Network app version: {}.",
                    env.device_type,
                    env.unifi_os_version.as_deref().unwrap_or("unknown"),
                    env.network_app_version.as_deref().unwrap_or("unknown"),
                ),
                Severity::Info,
            ));
        }

        let controller_url = if local_env.is_some() {
            Some("https://localhost".to_owned())
        } else {
            ctx.gateway.map(|gw| format!("https://{gw}"))
        };

        let Some(url) = controller_url else {
            findings.push(Finding::new(
                "unifi",
                "No UniFi controller detected",
                "Could not detect a local UniFi environment or controller URL. \
                 Use `rikitikitavi unifi scan --controller <url>` for remote scanning.",
                Severity::Info,
            ));
            return Ok(findings);
        };

        // TLS validation intentionally disabled: unauthenticated probe, no credentials sent.
        let client =
            UniFiClient::new_insecure(&url, "default").map_err(|e| ScanError::ScannerFailed {
                scanner: "unifi".to_owned(),
                message: format!("failed to create UniFi client: {e}"),
            })?;

        if !client.is_authenticated() {
            findings.push(Finding::new(
                "unifi",
                &format!("UniFi controller detected at {url}"),
                &format!(
                    "A UniFi controller was detected at {url}. Full security audit \
                     requires authentication. Use `rikitikitavi unifi scan --username <user> \
                     --password <pass>` for authenticated scanning."
                ),
                Severity::Info,
            ));
            return Ok(findings);
        }

        match client.get_wlans().await {
            Ok(wlans) => {
                tracing::info!(wlan_count = wlans.len(), "fetched WLAN configs");
                for wlan in &wlans {
                    findings.extend(audit_wlan(wlan));
                }
            }
            Err(e) => {
                tracing::warn!("failed to fetch WLANs: {e}");
            }
        }

        match client.get_firewall_rules().await {
            Ok(rules) => {
                tracing::info!(rule_count = rules.len(), "fetched firewall rules");
                findings.extend(audit_firewall_rules(&rules));
            }
            Err(e) => {
                tracing::warn!("failed to fetch firewall rules: {e}");
            }
        }

        match client.get_devices().await {
            Ok(devices) => {
                for device in &devices {
                    let name = device.name.as_deref().unwrap_or(&device.model);
                    findings.push(Finding::new(
                        "unifi",
                        &format!("{name}: firmware {}", device.firmware_version),
                        &format!(
                            "UniFi device \"{name}\" (model: {}, MAC: {}) is running \
                             firmware version {}. Verify this is the latest version.",
                            device.model, device.mac, device.firmware_version
                        ),
                        Severity::Info,
                    ));
                }
            }
            Err(e) => {
                tracing::warn!("failed to fetch devices: {e}");
            }
        }

        match client.get_ids_events(100).await {
            Ok(events) => {
                if events.is_empty() {
                    findings.push(Finding::new(
                        "unifi",
                        "No IDS/IPS events recorded",
                        "No IDS/IPS events were found. This could mean IDS/IPS is disabled \
                         or no threats have been detected. Verify that Threat Management is \
                         enabled in UniFi settings.",
                        Severity::Low,
                    ));
                } else {
                    findings.push(Finding::new(
                        "unifi",
                        &format!("{} IDS/IPS events recorded", events.len()),
                        &format!(
                            "{} IDS/IPS events were recorded. Review the threat management \
                             dashboard for details.",
                            events.len()
                        ),
                        Severity::Info,
                    ));
                }
            }
            Err(e) => {
                tracing::warn!("failed to fetch IDS events: {e}");
            }
        }

        tracing::info!(findings_count = findings.len(), "UniFi scan complete");
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        90
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::Strategy;

    fn test_wlan(security: &str, wpa_mode: Option<&str>, pmf: Option<&str>) -> WlanConfig {
        WlanConfig {
            id: "test-id".to_owned(),
            name: "TestNet".to_owned(),
            security: security.to_owned(),
            wpa_mode: wpa_mode.map(ToOwned::to_owned),
            pmf_mode: pmf.map(ToOwned::to_owned),
            is_guest: false,
            enabled: true,
        }
    }

    #[test]
    fn test_audit_wlan_open() {
        let wlan = test_wlan("open", None, None);
        let findings = audit_wlan(&wlan);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_audit_wlan_wpa1() {
        let wlan = test_wlan("wpa-personal", Some("wpa1"), None);
        let findings = audit_wlan(&wlan);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_audit_wlan_pmf_disabled() {
        let wlan = test_wlan("wpa2-personal", Some("wpa2"), Some("disabled"));
        let findings = audit_wlan(&wlan);
        assert!(findings.iter().any(|f| f.title.contains("PMF")));
    }

    #[test]
    fn test_audit_wlan_disabled() {
        let mut wlan = test_wlan("open", None, None);
        wlan.enabled = false;
        let findings = audit_wlan(&wlan);
        // Should only have the "disabled" info finding, not the critical open finding
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_audit_wlan_default_ssid() {
        let mut wlan = test_wlan("wpa2-personal", Some("wpa2"), Some("required"));
        wlan.name = "UniFi".to_owned();
        let findings = audit_wlan(&wlan);
        assert!(findings.iter().any(|f| f.title.contains("Default")));
    }

    #[test]
    fn test_audit_wlan_guest() {
        let mut wlan = test_wlan("wpa2-personal", Some("wpa2"), Some("required"));
        wlan.is_guest = true;
        let findings = audit_wlan(&wlan);
        assert!(findings.iter().any(|f| f.title.contains("Guest")));
    }

    #[test]
    fn test_audit_firewall_empty() {
        let findings = audit_firewall_rules(&[]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("No custom"));
    }

    #[test]
    fn test_audit_firewall_permissive() {
        let rule = FirewallRule {
            id: "r1".to_owned(),
            name: Some("Allow All".to_owned()),
            action: "accept".to_owned(),
            src: Some("any".to_owned()),
            dst: Some("any".to_owned()),
            enabled: true,
        };
        let findings = audit_firewall_rules(&[rule]);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_audit_firewall_disabled_rule() {
        let rule = FirewallRule {
            id: "r1".to_owned(),
            name: Some("Block IoT".to_owned()),
            action: "drop".to_owned(),
            src: Some("iot".to_owned()),
            dst: Some("lan".to_owned()),
            enabled: false,
        };
        let findings = audit_firewall_rules(&[rule]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_audit_firewall_specific_rule() {
        let rule = FirewallRule {
            id: "r1".to_owned(),
            name: Some("Block IoT to LAN".to_owned()),
            action: "drop".to_owned(),
            src: Some("iot-vlan".to_owned()),
            dst: Some("lan".to_owned()),
            enabled: true,
        };
        let findings = audit_firewall_rules(&[rule]);
        // Specific drop rule should produce no findings
        assert!(findings.is_empty());
    }

    // ─── Property-based tests ─────────────────────────────────────────

    fn arb_wlan() -> impl proptest::strategy::Strategy<Value = WlanConfig> {
        (
            ".*",                             // id
            ".*",                             // name
            ".*",                             // security
            proptest::option::of(".*"),       // wpa_mode
            proptest::option::of(".*"),       // pmf_mode
            proptest::prelude::any::<bool>(), // is_guest
            proptest::prelude::any::<bool>(), // enabled
        )
            .prop_map(
                |(id, name, security, wpa_mode, pmf_mode, is_guest, enabled)| WlanConfig {
                    id,
                    name,
                    security,
                    wpa_mode,
                    pmf_mode,
                    is_guest,
                    enabled,
                },
            )
    }

    fn arb_firewall_rule() -> impl proptest::strategy::Strategy<Value = FirewallRule> {
        (
            ".*",                             // id
            proptest::option::of(".*"),       // name
            ".*",                             // action
            proptest::option::of(".*"),       // src
            proptest::option::of(".*"),       // dst
            proptest::prelude::any::<bool>(), // enabled
        )
            .prop_map(|(id, name, action, src, dst, enabled)| FirewallRule {
                id,
                name,
                action,
                src,
                dst,
                enabled,
            })
    }

    proptest::proptest! {
        /// audit_wlan never panics on arbitrary WLAN configs.
        #[test]
        fn prop_audit_wlan_no_panic(wlan in arb_wlan()) {
            let _ = audit_wlan(&wlan);
        }

        /// audit_wlan returns only valid Severity levels in findings.
        #[test]
        fn prop_audit_wlan_valid_findings(wlan in arb_wlan()) {
            let findings = audit_wlan(&wlan);
            for f in &findings {
                assert!(!f.scanner.is_empty());
                assert!(!f.title.is_empty());
                // Severity must be one of the defined variants — this is enforced by
                // the type system, but we verify the scanner field is always "unifi".
                assert_eq!(f.scanner, "unifi");
            }
        }

        /// Disabled WLANs produce at most one Info finding.
        #[test]
        fn prop_disabled_wlan_info_only(wlan in arb_wlan()) {
            if !wlan.enabled {
                let findings = audit_wlan(&wlan);
                assert!(findings.len() <= 1, "disabled WLAN produced {} findings", findings.len());
                for f in &findings {
                    assert_eq!(f.severity, Severity::Info);
                }
            }
        }

        /// audit_firewall_rules never panics on arbitrary rules.
        #[test]
        fn prop_audit_firewall_no_panic(rules in proptest::collection::vec(arb_firewall_rule(), 0..10)) {
            let _ = audit_firewall_rules(&rules);
        }

        /// Empty rule set always produces exactly one finding.
        #[test]
        fn prop_empty_firewall_one_finding(_unused in proptest::prelude::any::<u8>()) {
            let findings = audit_firewall_rules(&[]);
            assert_eq!(findings.len(), 1);
        }
    }
}
