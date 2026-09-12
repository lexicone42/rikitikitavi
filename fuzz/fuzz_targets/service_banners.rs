#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::services::{parse_ftp_feat, parse_server_header, parse_smtp_ehlo};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = parse_smtp_ehlo(&text);
    let _ = parse_ftp_feat(&text);
    let _ = parse_server_header(&text);
});
