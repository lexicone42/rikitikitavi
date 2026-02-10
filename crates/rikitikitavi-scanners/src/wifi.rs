use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use rikitikitavi_network::WifiEncryption;

use crate::Scanner;

/// `WiFi` security scanner — grades nearby networks by encryption strength,
/// detects WPS, open networks, and weak encryption.
pub struct WifiScanner;

/// Grade a `WiFi` encryption type into a severity level.
const fn encryption_severity(encryption: WifiEncryption) -> Severity {
    match encryption {
        WifiEncryption::Open | WifiEncryption::Wep => Severity::Critical,
        WifiEncryption::WpaPsk => Severity::High,
        WifiEncryption::Wpa2Psk | WifiEncryption::Wpa2Enterprise
        | WifiEncryption::Wpa3Sae | WifiEncryption::Wpa3Enterprise => Severity::Info,
        WifiEncryption::Unknown => Severity::Low,
    }
}

/// Human-friendly encryption name.
const fn encryption_name(encryption: WifiEncryption) -> &'static str {
    match encryption {
        WifiEncryption::Open => "Open (no encryption)",
        WifiEncryption::Wep => "WEP",
        WifiEncryption::WpaPsk => "WPA-PSK (TKIP)",
        WifiEncryption::Wpa2Psk => "WPA2-PSK (AES)",
        WifiEncryption::Wpa2Enterprise => "WPA2-Enterprise",
        WifiEncryption::Wpa3Sae => "WPA3-SAE",
        WifiEncryption::Wpa3Enterprise => "WPA3-Enterprise",
        WifiEncryption::Unknown => "Unknown",
    }
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl Scanner for WifiScanner {
    fn id(&self) -> &'static str {
        "wifi"
    }

    fn name(&self) -> &'static str {
        "WiFi Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Neighbor,
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, _ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running WiFi security scan");
        let mut findings = Vec::new();

        let networks = rikitikitavi_network::scan_wifi_networks().await.map_err(|e| {
            ScanError::ScannerFailed {
                scanner: "wifi".to_owned(),
                message: format!("WiFi scan failed: {e}"),
            }
        })?;

        if networks.is_empty() {
            findings.push(Finding::new(
                "wifi",
                "No WiFi networks detected",
                "Could not detect any WiFi networks. This may mean WiFi is disabled, \
                 the adapter doesn't support scanning, or elevated privileges are needed.",
                Severity::Info,
            ));
            return Ok(findings);
        }

        tracing::info!(network_count = networks.len(), "WiFi networks found");

        findings.push(Finding::new(
            "wifi",
            &format!("{} WiFi network(s) visible", networks.len()),
            &format!("Detected {} WiFi networks in range.", networks.len()),
            Severity::Info,
        ));

        for network in &networks {
            let severity = encryption_severity(network.encryption);
            let enc_name = encryption_name(network.encryption);

            // Only report networks with weak encryption as findings
            match network.encryption {
                WifiEncryption::Open => {
                    findings.push(
                        Finding::new(
                            "wifi",
                            &format!("Open WiFi network: \"{}\"", network.ssid),
                            &format!(
                                "Network \"{}\" (BSSID: {}) uses no encryption. All traffic \
                                 is transmitted in cleartext and can be intercepted by anyone \
                                 in range. Signal: {} dBm, Channel: {}",
                                network.ssid, network.bssid,
                                network.signal_strength_dbm, network.channel
                            ),
                            severity,
                        )
                        .with_cwe("CWE-319"),
                    );
                }
                WifiEncryption::Wep => {
                    findings.push(
                        Finding::new(
                            "wifi",
                            &format!("WEP-encrypted network: \"{}\"", network.ssid),
                            &format!(
                                "Network \"{}\" uses WEP encryption, which can be cracked in \
                                 minutes with freely available tools. WEP should be replaced \
                                 with WPA2 or WPA3. Signal: {} dBm, Channel: {}",
                                network.ssid, network.signal_strength_dbm, network.channel
                            ),
                            severity,
                        )
                        .with_cwe("CWE-327"),
                    );
                }
                WifiEncryption::WpaPsk => {
                    findings.push(
                        Finding::new(
                            "wifi",
                            &format!("WPA1 network (weak): \"{}\"", network.ssid),
                            &format!(
                                "Network \"{}\" uses WPA (TKIP), which has known weaknesses. \
                                 Upgrade to WPA2 (AES) or WPA3. Signal: {} dBm, Channel: {}",
                                network.ssid, network.signal_strength_dbm, network.channel
                            ),
                            severity,
                        )
                        .with_cwe("CWE-327"),
                    );
                }
                _ => {
                    // WPA2/WPA3 are fine — just report as info
                    findings.push(Finding::new(
                        "wifi",
                        &format!(
                            "WiFi \"{}\": {enc_name}",
                            network.ssid
                        ),
                        &format!(
                            "Network \"{}\" uses {enc_name}. \
                             Signal: {} dBm, Channel: {}",
                            network.ssid, network.signal_strength_dbm, network.channel
                        ),
                        Severity::Info,
                    ));
                }
            }

            // WPS check
            if network.wps_enabled {
                findings.push(
                    Finding::new(
                        "wifi",
                        &format!("WPS enabled on \"{}\"", network.ssid),
                        &format!(
                            "Network \"{}\" has WPS (WiFi Protected Setup) enabled. WPS PINs \
                             can be brute-forced offline. Disable WPS in your router settings.",
                            network.ssid
                        ),
                        Severity::Medium,
                    )
                    .with_cwe("CWE-330"),
                );
            }

            // Hidden network check
            if network.hidden {
                findings.push(Finding::new(
                    "wifi",
                    &format!("Hidden network detected (BSSID: {})", network.bssid),
                    &format!(
                        "A hidden WiFi network (BSSID: {}) was detected. Hiding an SSID \
                         provides no real security benefit and can actually make clients \
                         more vulnerable (they broadcast probe requests for the hidden SSID).",
                        network.bssid
                    ),
                    Severity::Low,
                ));
            }
        }

        tracing::info!(findings_count = findings.len(), "WiFi scan complete");
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        10
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_severity_critical() {
        assert_eq!(encryption_severity(WifiEncryption::Open), Severity::Critical);
        assert_eq!(encryption_severity(WifiEncryption::Wep), Severity::Critical);
    }

    #[test]
    fn test_encryption_severity_high() {
        assert_eq!(encryption_severity(WifiEncryption::WpaPsk), Severity::High);
    }

    #[test]
    fn test_encryption_severity_info() {
        assert_eq!(encryption_severity(WifiEncryption::Wpa2Psk), Severity::Info);
        assert_eq!(encryption_severity(WifiEncryption::Wpa3Sae), Severity::Info);
    }

    #[test]
    fn test_encryption_name() {
        assert_eq!(encryption_name(WifiEncryption::Open), "Open (no encryption)");
        assert_eq!(encryption_name(WifiEncryption::Wpa2Psk), "WPA2-PSK (AES)");
        assert_eq!(encryption_name(WifiEncryption::Wpa3Sae), "WPA3-SAE");
    }
}
