#![no_main]
use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use rikitikitavi_models::{FindingFingerprint, MacAddr};
use rikitikitavi_network::wifi_frames::parse_mac;
use rikitikitavi_scanners::dns::{classify_dmarc, classify_spf};
use rikitikitavi_scanners::oui_db::ieee_oui_lookup;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok(mac) = MacAddr::from_str(&text) {
        assert_eq!(MacAddr::from_str(&mac.to_string()), Ok(mac));
    }
    if let Ok(fp) = FindingFingerprint::from_str(&text) {
        assert_eq!(FindingFingerprint::from_str(&fp.to_string()), Ok(fp));
    }
    let _ = parse_mac(&text);
    let _ = ieee_oui_lookup(&text);
    let _ = classify_spf(&text);
    let _ = classify_dmarc(&text);
});
