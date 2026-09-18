#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::recog::{identify, identify_all, ssh_software};
use rikitikitavi_scanners::recog_db::RecogKey;

fuzz_target!(|data: &[u8]| {
    static WARM: std::sync::Once = std::sync::Once::new();
    WARM.call_once(rikitikitavi_scanners::recog::warm_up);
    let text = String::from_utf8_lossy(data);
    for key in RecogKey::ALL {
        let _ = identify(key, &text);
    }
    let inputs: Vec<(RecogKey, &str)> = RecogKey::ALL.iter().map(|k| (*k, text.as_ref())).collect();
    let _ = identify_all(&inputs);
    let _ = ssh_software(&text);
});
