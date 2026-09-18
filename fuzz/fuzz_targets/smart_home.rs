#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::{cast, kasa, tuya};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = cast::fuzz::eureka(&text);
    let _ = cast::fuzz::tls(data);
    let _ = kasa::fuzz::decrypt(data);
    let _ = kasa::fuzz::json(&text);
    let _ = kasa::fuzz::sysinfo(&text);
    tuya::fuzz::datagram(data);
    let _ = tuya::fuzz::json(data);
    let _ = tuya::fuzz::broadcast(&text);
});
