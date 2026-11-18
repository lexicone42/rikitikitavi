#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::{database, mqtt};

fuzz_target!(|data: &[u8]| {
    database::fuzz::binary(data);
    database::fuzz::text(&String::from_utf8_lossy(data));
    mqtt::fuzz::connack(data);
});
