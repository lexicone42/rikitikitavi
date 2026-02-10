use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
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

/// Read the first few bytes from a TCP connection to get a banner fingerprint.
/// Returns `None` if the connection or read fails.
async fn grab_banner(ip: IpAddr, port: u16) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // For HTTP ports, send a minimal request to elicit a response
    if matches!(port, 80 | 443 | 8080) {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            stream.write_all(b"HEAD / HTTP/1.0\r\nHost: check\r\n\r\n"),
        )
        .await;
    }

    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

/// Detect hairpin NAT by comparing banners from the public IP and an internal
/// device on the same port. If any internal device returns an identical banner,
/// the public IP connection is likely hairpin NAT, not true external exposure.
async fn is_hairpin_nat(
    public_ip: IpAddr,
    port: u16,
    internal_devices: &[IpAddr],
) -> bool {
    // Grab banner from public IP
    let public_banner = match grab_banner(public_ip, port).await {
        Some(b) if !b.is_empty() => b,
        _ => return false,
    };

    // Check if any internal device has the same banner on this port
    for &internal_ip in internal_devices {
        if let Some(internal_banner) = grab_banner(internal_ip, port).await {
            if !internal_banner.is_empty() && internal_banner == public_banner {
                tracing::info!(
                    %internal_ip,
                    %public_ip,
                    port,
                    "hairpin NAT detected: internal and public banners match"
                );
                return true;
            }
        }
    }

    false
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
#[allow(clippy::too_many_lines)]
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

        // Collect internal IPs with open ports for hairpin NAT detection
        let internal_ips_with_ports: Vec<(IpAddr, Vec<u16>)> = ctx
            .discovered_devices
            .iter()
            .filter(|d| !d.open_ports.is_empty())
            .map(|d| {
                let ports: Vec<u16> = d.open_ports.iter().map(|p| p.port).collect();
                (d.ip, ports)
            })
            .collect();

        // Check for port forwarding by connecting to our own public IP
        tracing::info!("checking for port forwarding on public IP {public_ip}");
        for &port in EXPOSURE_PORTS {
            if check_port_forwarded(public_ip, port).await {
                let service = exposure_service_name(port);

                // Hairpin NAT detection: check if an internal device responds
                // identically on the same port
                let candidates: Vec<IpAddr> = internal_ips_with_ports
                    .iter()
                    .filter(|(_, ports)| ports.contains(&port))
                    .map(|(ip, _)| *ip)
                    .collect();

                if behind_nat && !candidates.is_empty()
                    && is_hairpin_nat(public_ip, port, &candidates).await
                {
                    // Hairpin NAT detected — downgrade to Info
                    findings.push(
                        Finding::new(
                            "exposure",
                            &format!("Hairpin NAT on port {port} ({service}) — not externally exposed"),
                            &format!(
                                "Port {port} ({service}) is reachable on public IP {public_ip} from \
                                 within the network, but banner comparison with internal devices shows \
                                 this is hairpin NAT (NAT loopback), not true external exposure. The \
                                 router is reflecting internal traffic back."
                            ),
                            Severity::Info,
                        )
                        .with_ip(public_ip)
                        .with_port(port)
                        .with_service(service),
                    );
                } else {
                    // Genuine port forwarding
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
                        .with_opt_remediation({
                            let port_str = port.to_string();
                            crate::remediation::get(
                                "rikitikitavi.exposure.port-forwarded",
                                &[("service", service), ("port", &port_str)],
                            )
                        }),
                    );
                }
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
