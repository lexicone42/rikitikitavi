#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::services::{classify_ssh_kex, parse_ssh_kex_init};

fuzz_target!(|data: &[u8]| {
    if let Some(info) = parse_ssh_kex_init(data) {
        let _ = classify_ssh_kex(std::net::IpAddr::from([10, 0, 0, 7]), 22, &info);
    }
});
