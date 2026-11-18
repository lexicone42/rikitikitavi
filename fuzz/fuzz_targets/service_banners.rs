#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::services::{
    self, classify_ftp_feat, classify_smtp_ehlo, parse_ftp_feat, parse_server_header,
    parse_smtp_ehlo,
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let ip = std::net::IpAddr::from([10, 0, 0, 7]);
    let _ = classify_smtp_ehlo(ip, 25, &parse_smtp_ehlo(&text));
    let _ = classify_ftp_feat(ip, 21, &parse_ftp_feat(&text));
    let _ = parse_server_header(&text);
    services::fuzz::banner(ip, 22, &text);
});
