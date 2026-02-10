use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, Remediation, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

use crate::Scanner;

/// External exposure scanner — public IP detection, port forwarding checks,
/// NAT detection.
pub struct ExposureScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Ports commonly port-forwarded that pose security risks.
const EXPOSURE_PORTS: &[u16] = &[22, 80, 443, 3389, 8080];

/// Check if a port is reachable on the public IP (indicating port forwarding).
async fn check_port_forwarded(public_ip: IpAddr, port: u16) -> bool {
    let addr = SocketAddr::new(public_ip, port);
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .is_ok_and(|r| r.is_ok())
}

/// Determine if the local network is behind NAT by comparing the gateway
/// IP to the public IP.
fn is_behind_nat(gateway: Option<IpAddr>, public_ip: IpAddr) -> bool {
    gateway != Some(public_ip)
}

/// Map a port to a human-friendly service name for exposure reports.
const fn exposure_service_name(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        80 => "HTTP",
        443 => "HTTPS",
        3389 => "RDP",
        8080 => "HTTP-Alt",
        _ => "Unknown",
    }
}

#[async_trait]
impl Scanner for ExposureScanner {
    fn id(&self) -> &'static str {
        "exposure"
    }

    fn name(&self) -> &'static str {
        "External Exposure"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running external exposure scan");
        let mut findings = Vec::new();

        // Detect public IP
        let public_ip = match rikitikitavi_network::get_public_ip().await {
            Ok(ip) => {
                findings.push(Finding::new(
                    "exposure",
                    &format!("Public IP address: {ip}"),
                    &format!(
                        "Your external/public IP address is {ip}. This is the address \
                         visible to the internet."
                    ),
                    Severity::Info,
                ));
                ip
            }
            Err(e) => {
                tracing::warn!("could not detect public IP: {e}");
                findings.push(Finding::new(
                    "exposure",
                    "Could not detect public IP",
                    &format!(
                        "Failed to determine public IP: {e}. External exposure checks skipped."
                    ),
                    Severity::Info,
                ));
                return Ok(findings);
            }
        };

        // NAT detection
        let behind_nat = is_behind_nat(ctx.gateway, public_ip);
        if behind_nat {
            findings.push(Finding::new(
                "exposure",
                "Network is behind NAT",
                &format!(
                    "The local gateway ({gw}) differs from the public IP ({public_ip}), \
                     indicating NAT is in place. NAT provides a basic layer of protection \
                     by hiding internal hosts from the internet.",
                    gw = ctx
                        .gateway
                        .map_or_else(|| "unknown".to_owned(), |gw| gw.to_string())
                ),
                Severity::Info,
            ));
        } else {
            findings.push(
                Finding::new(
                    "exposure",
                    "No NAT detected — gateway has public IP",
                    &format!(
                        "The gateway IP ({public_ip}) appears to be a public IP. \
                         Devices on this network may be directly exposed to the internet. \
                         Ensure the firewall is properly configured."
                    ),
                    Severity::Medium,
                )
                .with_cwe("CWE-284"),
            );
        }

        // Check for port forwarding by connecting to our own public IP
        tracing::info!("checking for port forwarding on public IP {public_ip}");
        for &port in EXPOSURE_PORTS {
            if check_port_forwarded(public_ip, port).await {
                let service = exposure_service_name(port);
                findings.push(
                    Finding::new(
                        "exposure",
                        &format!("Port {port} ({service}) is forwarded to the internet"),
                        &format!(
                            "Port {port} ({service}) on your public IP {public_ip} is reachable \
                             from within the network, which strongly suggests it is port-forwarded \
                             to an internal host. This exposes the service to the entire internet."
                        ),
                        Severity::High,
                    )
                    .with_ip(public_ip)
                    .with_port(port)
                    .with_service(service)
                    .with_cwe("CWE-284")
                    .with_remediation(Remediation {
                        description: format!(
                            "Review whether {service} on port {port} needs to be internet-accessible."
                        ),
                        steps: vec![
                            "Check your router's port forwarding settings.".to_owned(),
                            format!("Remove the port forward for port {port} if not needed."),
                            "If needed, restrict access via firewall rules or VPN.".to_owned(),
                        ],
                        effort: Some("5 minutes".to_owned()),
                    }),
                );
            }
        }

        tracing::info!(findings_count = findings.len(), "exposure scan complete");
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        15
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_is_behind_nat_yes() {
        let gw = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let public = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        assert!(is_behind_nat(gw, public));
    }

    #[test]
    fn test_is_behind_nat_no() {
        let gw = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)));
        let public = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        assert!(!is_behind_nat(gw, public));
    }

    #[test]
    fn test_is_behind_nat_no_gateway() {
        let public = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        assert!(is_behind_nat(None, public));
    }

    #[test]
    fn test_exposure_service_name() {
        assert_eq!(exposure_service_name(22), "SSH");
        assert_eq!(exposure_service_name(80), "HTTP");
        assert_eq!(exposure_service_name(3389), "RDP");
        assert_eq!(exposure_service_name(9999), "Unknown");
    }
}
