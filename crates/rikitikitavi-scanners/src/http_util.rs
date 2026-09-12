//! Shared HTTP helpers: bounded body reading and the unauthenticated probe client.
//! Scanners read bodies from untrusted LAN devices, so [`read_body_capped`] reads at
//! most `max_bytes` to bound memory use.

use reqwest::redirect::Policy;
use reqwest::{Client, Response};
use std::time::Duration;

/// Default body cap.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Read an HTTP response body, capped at `max_bytes`, as a lossy UTF-8 string.
///
/// Best-effort: a read error mid-stream returns what was collected so far.
pub async fn read_body_capped(mut resp: Response, max_bytes: usize) -> String {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < max_bytes {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = max_bytes - buf.len();
                if chunk.len() >= remaining {
                    buf.extend_from_slice(&chunk[..remaining]);
                    break;
                }
                buf.extend_from_slice(&chunk);
            }
            // End of body or read error.
            Ok(None) | Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Client for unauthenticated probes. Skips TLS validation; must never carry credentials.
pub fn unauthenticated_probe_client(
    timeout: Duration,
    redirect: Policy,
) -> reqwest::Result<Client> {
    Client::builder()
        .timeout(timeout)
        .redirect(redirect)
        .danger_accept_invalid_certs(true)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_client_builds() {
        assert!(unauthenticated_probe_client(Duration::from_secs(1), Policy::none()).is_ok());
    }

    #[test]
    fn invalid_cert_flag_only_in_http_util() {
        // Split so this file contains the flag name exactly once.
        const NEEDLE: &str = concat!("danger_accept_", "invalid_certs");
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut checked = 0;
        for entry in std::fs::read_dir(src_dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().is_none_or(|e| e != "rs")
                || path.file_name().is_some_and(|n| n == "http_util.rs")
            {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read source");
            assert!(
                !src.contains(NEEDLE),
                "{} sets {NEEDLE}; use unauthenticated_probe_client",
                path.display()
            );
            checked += 1;
        }
        assert!(checked > 20, "only {checked} sibling files checked");
    }
}
