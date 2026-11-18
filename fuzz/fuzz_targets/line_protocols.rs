#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::{credentials, http_audit, mdns, printers, rtsp, upnp_igd};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    rtsp::fuzz::response(&text);
    credentials::fuzz::responses(&text);
    printers::fuzz::pjl(&text);
    upnp_igd::fuzz::responses(&text);
    let _ = mdns::airplay::parse_osvers(&text);
    let _ = mdns::airplay::parse_flags(&text);
    let _ = mdns::airplay::parse_pw(&text);
    let signals = http_audit::extract_auth_signals(&text, &http_audit::ResponseHeaderSignals::default());
    let _ = http_audit::classify_auth(&signals);
});
