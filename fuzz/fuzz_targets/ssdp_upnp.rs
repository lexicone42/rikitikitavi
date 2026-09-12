#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::mdns::{parse_ssdp_response, parse_upnp_device_xml};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = parse_ssdp_response(&text);
    let _ = parse_upnp_device_xml(&text);
});
