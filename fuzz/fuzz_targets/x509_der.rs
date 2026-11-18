#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::ssl::{analyze_certificate, parse_cert_details};

fuzz_target!(|data: &[u8]| {
    if let Some(cert) = parse_cert_details(data) {
        let _ = analyze_certificate(std::net::IpAddr::from([10, 0, 0, 7]), 443, &cert);
    }
});
