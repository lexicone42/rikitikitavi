#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::services::parse_ssh_kex_init;

fuzz_target!(|data: &[u8]| {
    let _ = parse_ssh_kex_init(data);
});
