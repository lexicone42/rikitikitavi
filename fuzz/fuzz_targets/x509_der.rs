#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::ssl::parse_cert_details;

fuzz_target!(|data: &[u8]| {
    let _ = parse_cert_details(data);
});
