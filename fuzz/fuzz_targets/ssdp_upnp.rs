#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::mdns::{self, classify_upnp_device, parse_upnp_device_xml};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let ip = std::net::IpAddr::from([10, 0, 0, 7]);
    mdns::fuzz::ssdp(ip, &text);
    let info = parse_upnp_device_xml(&text);
    let _ = classify_upnp_device(ip, "http://10.0.0.7:80/desc.xml", &info);
});
