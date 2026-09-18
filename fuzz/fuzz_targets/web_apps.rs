#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::{ddwrt_upnp, media_server, papercut, print3d};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = papercut::fuzz::asset(&text);
    let _ = media_server::fuzz::plex(&text);
    let _ = media_server::fuzz::jellyfin(&text);
    let _ = media_server::fuzz::discovery(&text);
    let _ = media_server::fuzz::version(&text);
    let _ = media_server::fuzz::authority(&text);
    let _ = print3d::fuzz::access(&text);
    let _ = print3d::fuzz::server(&text);
    let _ = print3d::fuzz::octoprint(&text);
    ddwrt_upnp::fuzz::server(&text);
});
