//! Container / orchestration management-plane exposure scanner.
//!
//! The homelab segment's highest-value exposures are unauthenticated
//! container and orchestration control planes: an open Docker Engine API or
//! kubelet is equivalent to unauthenticated root on the host — a top
//! cryptojacking and host-takeover vector. This scanner performs pure,
//! non-destructive **detection** probes (read-only `GET`s that send no
//! credentials) against hosts that already have the relevant management port
//! open. It never brute-forces credentials and never mutates state.
//!
//! Detected surfaces:
//! - Docker Engine API on **2375** (plaintext HTTP): `GET /version`. A Docker
//!   version JSON body proves the API answers without authentication.
//! - Docker on **2376** (TLS): meant to use mutual-TLS client-cert auth. We do
//!   not implement mTLS; we only note that a TLS Docker endpoint exists.
//! - Kubelet on **10250** (HTTPS): `GET /pods`. A `PodList` response proves the
//!   kubelet read API answers anonymously.
//! - Kubernetes API server on **6443** (HTTPS): anonymous `GET /version`. A
//!   version JSON body proves the API server answers unauthenticated requests.

use async_trait::async_trait;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, Remediation, ScanContext};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

use crate::Scanner;
use crate::http_util::read_body_capped;

/// Container / orchestration management-plane exposure scanner.
pub struct MgmtPlaneScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on management-API response bodies. These endpoints return small JSON
/// documents; 256 KiB is ample while bounding a hostile or broken device.
const BODY_CAP: usize = 256 * 1024;

/// Management-plane ports and their service labels.
const MGMT_PORTS: &[(u16, &str)] = &[
    (2375, "Docker API (plaintext)"),
    (2376, "Docker API (TLS)"),
    (6443, "Kubernetes API server"),
    (10250, "Kubelet API"),
];

// ── Pure response classifiers (unit-tested) ─────────────────────────

/// Parsed subset of a Docker Engine `GET /version` response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct DockerVersion {
    version: Option<String>,
    api_version: Option<String>,
    os: Option<String>,
    arch: Option<String>,
}

/// Parsed subset of a Kubernetes `GET /version` response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct K8sVersion {
    git_version: Option<String>,
    major: Option<String>,
    minor: Option<String>,
    platform: Option<String>,
}

/// Extract a string-valued JSON field (`"key":"value"`) from a body.
///
/// Deliberately minimal: it scans for the first `"key"` token, then the next
/// `:` and the quoted value that follows. It does not handle escaped quotes
/// inside values, which is fine for the short, well-formed identifier fields
/// (versions, OS names, architectures) we read from these APIs. Returns a
/// borrow into `body`.
fn json_str_field<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let key_idx = body.find(&needle)?;
    let after_key = &body[key_idx + needle.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let inner = after_colon.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some(&inner[..end])
}

/// Classify a Docker Engine `GET /version` response body.
///
/// A genuine Docker `/version` document carries both an `ApiVersion` and an
/// `Os` field. Presence of both — returned to an unauthenticated request —
/// demonstrates the Engine API is exposed without authentication.
fn classify_docker_version(body: &str) -> Option<DockerVersion> {
    if !(body.contains("\"ApiVersion\"") && body.contains("\"Os\"")) {
        return None;
    }
    Some(DockerVersion {
        version: json_str_field(body, "Version").map(ToOwned::to_owned),
        api_version: json_str_field(body, "ApiVersion").map(ToOwned::to_owned),
        os: json_str_field(body, "Os").map(ToOwned::to_owned),
        arch: json_str_field(body, "Arch").map(ToOwned::to_owned),
    })
}

/// Classify a Kubernetes API server / kubelet `GET /version` response body.
///
/// The `/version` document reports `major`, `minor`, and a `gitVersion`. We
/// require `gitVersion` plus `major` to avoid matching unrelated JSON.
fn classify_k8s_version(body: &str) -> Option<K8sVersion> {
    if !(body.contains("\"gitVersion\"") && body.contains("\"major\"")) {
        return None;
    }
    Some(K8sVersion {
        git_version: json_str_field(body, "gitVersion").map(ToOwned::to_owned),
        major: json_str_field(body, "major").map(ToOwned::to_owned),
        minor: json_str_field(body, "minor").map(ToOwned::to_owned),
        platform: json_str_field(body, "platform").map(ToOwned::to_owned),
    })
}

/// Classify a kubelet `GET /pods` response body.
///
/// The kubelet read API returns a `PodList` object (`kind: "PodList"`) with an
/// `items` array. Receiving it from an unauthenticated request demonstrates the
/// kubelet API is anonymously accessible — exposing running workloads, mounted
/// secrets paths, and (through other verbs) command execution in containers.
fn classify_kubelet_pods(body: &str) -> bool {
    body.contains("\"PodList\"") || (body.contains("\"kind\"") && body.contains("\"items\""))
}

// ── Network probes (all I/O bounded by a timeout) ───────────────────

/// Build a reqwest client for management-plane detection probes.
///
/// `danger_accept_invalid_certs(true)` is an **intentional** TLS-verification
/// bypass: kubelet and the Kubernetes API server present self-signed or
/// cluster-CA certificates that a scanner has no trust anchor for, and we are
/// only issuing credential-free read GETs for detection — exactly like the
/// `UniFi` scanner's unauthenticated probe. No secret is ever transmitted, so the
/// lack of certificate validation carries no confidentiality risk here.
fn detection_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
        .ok()
}

/// Issue a credential-free GET and return the (capped) body if the server
/// answered with a 2xx status.
async fn get_ok_body(client: &reqwest::Client, url: &str) -> Option<String> {
    let resp = tokio::time::timeout(HTTP_TIMEOUT, client.get(url).send())
        .await
        .ok()?
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    tokio::time::timeout(HTTP_TIMEOUT, read_body_capped(resp, BODY_CAP))
        .await
        .ok()
}

/// Probe the plaintext Docker Engine API on the given port.
async fn probe_docker_plain(
    client: &reqwest::Client,
    ip: IpAddr,
    port: u16,
) -> Option<DockerVersion> {
    let url = format!("http://{ip}:{port}/version");
    let body = get_ok_body(client, &url).await?;
    classify_docker_version(&body)
}

/// Probe the Kubernetes API server `/version` on the given port.
async fn probe_k8s_api(client: &reqwest::Client, ip: IpAddr, port: u16) -> Option<K8sVersion> {
    let url = format!("https://{ip}:{port}/version");
    let body = get_ok_body(client, &url).await?;
    classify_k8s_version(&body)
}

/// Probe the kubelet read API `/pods` on the given port. Returns a short
/// evidence snippet of the response when the API answers anonymously.
async fn probe_kubelet(client: &reqwest::Client, ip: IpAddr, port: u16) -> Option<String> {
    let url = format!("https://{ip}:{port}/pods");
    let body = get_ok_body(client, &url).await?;
    if classify_kubelet_pods(&body) {
        Some(body)
    } else {
        None
    }
}

/// Confirm a TLS Docker endpoint is reachable (a bare TCP connect — we do not
/// perform the mutual-TLS handshake and send no data).
async fn tcp_reachable(ip: IpAddr, port: u16) -> bool {
    let addr = SocketAddr::new(ip, port);
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .is_ok_and(|r| r.is_ok())
}

// ── Finding builders ────────────────────────────────────────────────

fn docker_remediation() -> Remediation {
    Remediation {
        description: "Never expose the Docker Engine API on a TCP socket without \
                      authentication. Bind it to the local Unix socket only, or require \
                      mutual-TLS client certificates."
            .to_owned(),
        steps: vec![
            "Remove any `-H tcp://0.0.0.0:2375` / `tcp://<ip>:2375` flags from the \
             dockerd command line or /etc/docker/daemon.json `hosts` array."
                .to_owned(),
            "If remote access is required, enable TLS with client-certificate \
             verification (`--tlsverify`) and expose only port 2376."
                .to_owned(),
            "Block ports 2375/2376 at the host and network firewall for all untrusted \
             sources."
                .to_owned(),
        ],
        effort: Some("15 minutes".to_owned()),
    }
}

fn kubelet_remediation() -> Remediation {
    Remediation {
        description: "Disable anonymous authentication and enable authorization on the \
                      kubelet so its read/exec API cannot be reached without credentials."
            .to_owned(),
        steps: vec![
            "Set `authentication.anonymous.enabled: false` in the kubelet configuration."
                .to_owned(),
            "Set `authorization.mode: Webhook` so the API server authorizes kubelet \
             requests."
                .to_owned(),
            "Restrict TCP port 10250 to the control plane via network policy / firewall."
                .to_owned(),
        ],
        effort: Some("requires cluster configuration change".to_owned()),
    }
}

fn k8s_api_remediation() -> Remediation {
    Remediation {
        description: "Disable anonymous access to the Kubernetes API server and restrict \
                      network reachability of port 6443."
            .to_owned(),
        steps: vec![
            "Start kube-apiserver with `--anonymous-auth=false` (or scope the built-in \
             `system:public-info-viewer` binding) so unauthenticated clients get 401."
                .to_owned(),
            "Ensure RBAC does not bind `system:anonymous` / `system:unauthenticated` to \
             any meaningful role."
                .to_owned(),
            "Limit inbound access to port 6443 to trusted administrative networks.".to_owned(),
        ],
        effort: Some("requires cluster configuration change".to_owned()),
    }
}

async fn check_docker_plain(
    client: &reqwest::Client,
    ip: IpAddr,
    port: u16,
    out: &mut Vec<Finding>,
) {
    let Some(ver) = probe_docker_plain(client, ip, port).await else {
        return;
    };

    let mut detail = Vec::new();
    if let Some(v) = &ver.version {
        detail.push(format!("Docker {v}"));
    }
    if let Some(a) = &ver.api_version {
        detail.push(format!("API {a}"));
    }
    if let Some(o) = &ver.os {
        detail.push(o.clone());
    }
    if let Some(a) = &ver.arch {
        detail.push(a.clone());
    }
    let evidence = if detail.is_empty() {
        "Docker /version returned a version document".to_owned()
    } else {
        detail.join(", ")
    };

    out.push(
        Finding::new(
            "mgmt-plane",
            &format!("Docker Engine API exposed without authentication on {ip}:{port}"),
            &format!(
                "The Docker Engine API at http://{ip}:{port} answered an unauthenticated \
                 GET /version with a Docker version document ({evidence}). The API is \
                 exposed WITHOUT authentication — full host compromise. Anyone who can \
                 reach this port can create privileged containers that mount the host \
                 filesystem, giving root on the host. This is a top cryptojacking and \
                 host-takeover vector.",
            ),
            Severity::Critical,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("Docker API")
        .with_confidence(Confidence::Confirmed)
        .with_cwe("CWE-306")
        .with_evidence(evidence)
        .with_references(refs![
            "https://docs.docker.com/engine/security/protect-access/",
            "https://attack.mitre.org/techniques/T1610/",
            "https://cwe.mitre.org/data/definitions/306.html",
        ])
        .with_remediation(docker_remediation()),
    );
}

async fn check_docker_tls(ip: IpAddr, port: u16, out: &mut Vec<Finding>) {
    if !tcp_reachable(ip, port).await {
        return;
    }
    // We do not perform the mutual-TLS handshake, so we cannot confirm whether
    // client-certificate auth is actually enforced — hence Probable, and only
    // informational severity.
    out.push(
        Finding::new(
            "mgmt-plane",
            &format!("TLS Docker endpoint present on {ip}:{port}"),
            &format!(
                "A TLS Docker endpoint is listening on {ip}:{port}. Port 2376 is intended \
                 for the Docker API secured with mutual-TLS client-certificate \
                 authentication. This scan does not present a client certificate, so it \
                 cannot confirm whether authentication is enforced; verify that the daemon \
                 runs with `--tlsverify` and a restricted CA, and that the port is not \
                 reachable from untrusted networks.",
            ),
            Severity::Info,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("Docker API (TLS)")
        .with_confidence(Confidence::Probable)
        .with_cwe("CWE-306")
        .with_references(refs![
            "https://docs.docker.com/engine/security/protect-access/",
        ])
        .with_remediation(docker_remediation()),
    );
}

async fn check_kubelet(client: &reqwest::Client, ip: IpAddr, port: u16, out: &mut Vec<Finding>) {
    let Some(body) = probe_kubelet(client, ip, port).await else {
        return;
    };
    out.push(
        Finding::new(
            "mgmt-plane",
            &format!("Kubelet API exposed without authentication on {ip}:{port}"),
            &format!(
                "The kubelet read API at https://{ip}:{port}/pods answered an \
                 unauthenticated request with a PodList document. Anonymous access to the \
                 kubelet exposes running workloads and their secret mount paths, and \
                 (through other kubelet endpoints) allows command execution inside \
                 containers — a direct path to node and cluster compromise.",
            ),
            Severity::Critical,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("Kubelet")
        .with_confidence(Confidence::Confirmed)
        .with_cwe("CWE-306")
        .with_evidence(body)
        .with_references(refs![
            "https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/",
            "https://attack.mitre.org/techniques/T1610/",
        ])
        .with_remediation(kubelet_remediation()),
    );
}

async fn check_k8s_api(client: &reqwest::Client, ip: IpAddr, port: u16, out: &mut Vec<Finding>) {
    let Some(ver) = probe_k8s_api(client, ip, port).await else {
        return;
    };
    let version_label = ver
        .git_version
        .clone()
        .or_else(|| match (&ver.major, &ver.minor) {
            (Some(maj), Some(min)) => Some(format!("v{maj}.{min}")),
            _ => None,
        })
        .unwrap_or_else(|| "unknown".to_owned());

    out.push(
        Finding::new(
            "mgmt-plane",
            &format!("Kubernetes API server answers anonymous requests on {ip}:{port}"),
            &format!(
                "The Kubernetes API server at https://{ip}:{port}/version answered an \
                 anonymous, unauthenticated GET and disclosed its version ({version_label}). \
                 While /version is sometimes public by design, an API server that is \
                 network-reachable and serving anonymous requests is high-risk: verify that \
                 `--anonymous-auth=false` is set and that RBAC grants system:anonymous no \
                 meaningful access, or an attacker may enumerate and act on cluster \
                 resources.",
            ),
            Severity::High,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("Kubernetes API")
        .with_confidence(Confidence::Confirmed)
        .with_cwe("CWE-306")
        .with_evidence(version_label)
        .with_references(refs![
            "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests",
            "https://kubernetes.io/docs/concepts/security/",
        ])
        .with_remediation(k8s_api_remediation()),
    );
}

// ── Scanner impl ────────────────────────────────────────────────────

#[async_trait]
impl Scanner for MgmtPlaneScanner {
    fn id(&self) -> &'static str {
        "mgmt-plane"
    }

    fn name(&self) -> &'static str {
        "Management Plane Exposure"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running management-plane exposure scan");
        let mut findings = Vec::new();

        // These probes actively connect to control-plane APIs; skip in the
        // lightest (Passive) intensity, mirroring the database scanner.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping management-plane scan in quick scan mode");
            return Ok(findings);
        }

        // Target only hosts with a relevant management port open. Prefer
        // Phase 1 discovered devices; fall back to the ARP cache (probing all
        // management ports) when discovery has not run.
        let targets: Vec<(IpAddr, Vec<u16>)> = if ctx.discovered_devices.is_empty() {
            let arp_entries =
                rikitikitavi_network::read_arp_cache().map_err(|e| ScanError::ScannerFailed {
                    scanner: "mgmt-plane".to_owned(),
                    message: format!("failed to read ARP cache: {e}"),
                })?;
            arp_entries
                .iter()
                .map(|e| (e.ip, MGMT_PORTS.iter().map(|(p, _)| *p).collect()))
                .collect()
        } else {
            ctx.discovered_devices
                .iter()
                .map(|d| {
                    let ports: Vec<u16> = d
                        .open_ports
                        .iter()
                        .filter(|p| MGMT_PORTS.iter().any(|(mp, _)| *mp == p.port))
                        .map(|p| p.port)
                        .collect();
                    (d.ip, ports)
                })
                .filter(|(_, ports)| !ports.is_empty())
                .collect()
        };

        if targets.is_empty() {
            tracing::info!("no management-plane targets found");
            return Ok(findings);
        }

        let Some(client) = detection_client() else {
            tracing::warn!("failed to build detection HTTP client");
            return Ok(findings);
        };

        tracing::info!(
            target_count = targets.len(),
            "checking management-plane exposure"
        );

        for (ip, ports) in &targets {
            for &port in ports {
                match port {
                    2375 => check_docker_plain(&client, *ip, port, &mut findings).await,
                    2376 => check_docker_tls(*ip, port, &mut findings).await,
                    6443 => check_k8s_api(&client, *ip, port, &mut findings).await,
                    10250 => check_kubelet(&client, *ip, port, &mut findings).await,
                    _ => {}
                }
            }
        }

        tracing::info!(
            findings_count = findings.len(),
            "management-plane exposure scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        20
    }

    fn relevant_ports(&self) -> &[u16] {
        &[2375, 2376, 6443, 10250]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Realistic Docker Engine `GET /version` response body.
    const DOCKER_VERSION_BODY: &str = r#"{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine","Version":"24.0.5"}],"Version":"24.0.5","ApiVersion":"1.43","MinAPIVersion":"1.12","GitCommit":"a61e2b4","GoVersion":"go1.20.6","Os":"linux","Arch":"amd64","KernelVersion":"6.1.0-18-amd64","BuildTime":"2023-07-24T20:00:00.000000000+00:00"}"#;

    // Realistic Kubernetes `GET /version` response body.
    const K8S_VERSION_BODY: &str = r#"{"major":"1","minor":"28","gitVersion":"v1.28.2","gitCommit":"89a4ea3e1e4ddd7f7572286090359983e0387b2f","gitTreeState":"clean","buildDate":"2023-09-13T09:29:07Z","goVersion":"go1.20.8","compiler":"gc","platform":"linux/amd64"}"#;

    // Realistic kubelet `GET /pods` response body (truncated PodList).
    const KUBELET_PODS_BODY: &str = r#"{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[{"metadata":{"name":"coredns-abc","namespace":"kube-system"},"spec":{}}]}"#;

    // ── json_str_field ──────────────────────────────────────────────

    #[test]
    fn json_field_extracts_value() {
        assert_eq!(
            json_str_field(DOCKER_VERSION_BODY, "ApiVersion"),
            Some("1.43")
        );
        assert_eq!(json_str_field(DOCKER_VERSION_BODY, "Os"), Some("linux"));
        assert_eq!(json_str_field(DOCKER_VERSION_BODY, "Arch"), Some("amd64"));
    }

    #[test]
    fn json_field_handles_spaces_after_colon() {
        assert_eq!(json_str_field(r#"{"k" : "v"}"#, "k"), Some("v"));
    }

    #[test]
    fn json_field_missing_key_is_none() {
        assert_eq!(json_str_field(DOCKER_VERSION_BODY, "Nope"), None);
    }

    #[test]
    fn json_field_non_string_value_is_none() {
        // Numeric / object values are not string-quoted → None.
        assert_eq!(json_str_field(r#"{"count":5}"#, "count"), None);
        assert_eq!(json_str_field(r#"{"obj":{"a":"b"}}"#, "obj"), None);
    }

    // ── classify_docker_version ─────────────────────────────────────

    #[test]
    fn docker_version_detected() {
        let v = classify_docker_version(DOCKER_VERSION_BODY).expect("should detect");
        assert_eq!(v.version.as_deref(), Some("24.0.5"));
        assert_eq!(v.api_version.as_deref(), Some("1.43"));
        assert_eq!(v.os.as_deref(), Some("linux"));
        assert_eq!(v.arch.as_deref(), Some("amd64"));
    }

    #[test]
    fn docker_version_requires_both_markers() {
        // Has ApiVersion but no Os → not a Docker /version document.
        assert!(classify_docker_version(r#"{"ApiVersion":"1.43"}"#).is_none());
        // Has Os but no ApiVersion.
        assert!(classify_docker_version(r#"{"Os":"linux"}"#).is_none());
    }

    #[test]
    fn docker_version_rejects_unrelated_json() {
        assert!(classify_docker_version(r#"{"error":"unauthorized"}"#).is_none());
        assert!(classify_docker_version("not json at all").is_none());
        assert!(classify_docker_version("").is_none());
    }

    // ── classify_k8s_version ────────────────────────────────────────

    #[test]
    fn k8s_version_detected() {
        let v = classify_k8s_version(K8S_VERSION_BODY).expect("should detect");
        assert_eq!(v.git_version.as_deref(), Some("v1.28.2"));
        assert_eq!(v.major.as_deref(), Some("1"));
        assert_eq!(v.minor.as_deref(), Some("28"));
        assert_eq!(v.platform.as_deref(), Some("linux/amd64"));
    }

    #[test]
    fn k8s_version_requires_both_markers() {
        assert!(classify_k8s_version(r#"{"gitVersion":"v1.28.2"}"#).is_none());
        assert!(classify_k8s_version(r#"{"major":"1"}"#).is_none());
    }

    #[test]
    fn k8s_version_rejects_unrelated_json() {
        // A Docker body must not be misread as a k8s version.
        assert!(classify_k8s_version(DOCKER_VERSION_BODY).is_none());
        assert!(classify_k8s_version(r#"{"message":"Unauthorized","code":401}"#).is_none());
    }

    // ── classify_kubelet_pods ───────────────────────────────────────

    #[test]
    fn kubelet_podlist_detected() {
        assert!(classify_kubelet_pods(KUBELET_PODS_BODY));
    }

    #[test]
    fn kubelet_kind_items_detected() {
        assert!(classify_kubelet_pods(r#"{"kind":"Something","items":[]}"#));
    }

    #[test]
    fn kubelet_unauthorized_rejected() {
        assert!(!classify_kubelet_pods(
            r#"{"kind":"Status","status":"Failure","reason":"Unauthorized","code":401}"#
        ));
        assert!(!classify_kubelet_pods("Unauthorized"));
        assert!(!classify_kubelet_pods(""));
    }

    // ── Proptests: classifiers never panic ──────────────────────────

    proptest! {
        #[test]
        fn prop_json_field_no_panic(body in ".*", key in "[A-Za-z]{0,12}") {
            let _ = json_str_field(&body, &key);
        }

        #[test]
        fn prop_classify_docker_no_panic(body in ".*") {
            let _ = classify_docker_version(&body);
        }

        #[test]
        fn prop_classify_k8s_no_panic(body in ".*") {
            let _ = classify_k8s_version(&body);
        }

        #[test]
        fn prop_classify_kubelet_no_panic(body in ".*") {
            let _ = classify_kubelet_pods(&body);
        }
    }
}
