#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_network::mdns::parse_dns_packet;

fuzz_target!(|data: &[u8]| {
    let _ = parse_dns_packet(data);
});
