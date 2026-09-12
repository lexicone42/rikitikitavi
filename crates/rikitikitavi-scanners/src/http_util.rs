//! Bounded HTTP body reading. Scanners read bodies from untrusted LAN devices,
//! so [`read_body_capped`] reads at most `max_bytes` to bound memory use.

use reqwest::Response;

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
