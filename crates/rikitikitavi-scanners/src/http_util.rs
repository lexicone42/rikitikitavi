//! Bounded HTTP body reading.
//!
//! Scanners fetch bodies from untrusted LAN devices (admin panels, `UPnP` device
//! descriptions). A hostile or broken device can return a gigantic — or
//! effectively endless — body; [`reqwest::Response::text`] would buffer all of
//! it and exhaust memory. [`read_body_capped`] reads at most `max_bytes`, so a
//! single misbehaving device can never OOM the scanner.

use reqwest::Response;

/// Default body cap. A couple of megabytes is ample for an `HTML` admin page or
/// a `UPnP` device description while bounding a hostile response.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Read an HTTP response body, but never more than `max_bytes`.
///
/// Returns the (possibly truncated) body as a lossy UTF-8 string. Best-effort:
/// a read error mid-stream yields whatever was collected so far rather than
/// discarding it, matching the previous `text().await.unwrap_or_default()`
/// behaviour at the call sites.
pub async fn read_body_capped(mut resp: Response, max_bytes: usize) -> String {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < max_bytes {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = max_bytes - buf.len();
                if chunk.len() >= remaining {
                    buf.extend_from_slice(&chunk[..remaining]);
                    break; // hit the cap
                }
                buf.extend_from_slice(&chunk);
            }
            // End of body, or a read error — return what we have.
            Ok(None) | Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}
