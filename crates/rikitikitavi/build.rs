//! Records the compiler version for `version --verbose`.

use std::process::Command;

fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok());
    if let Some(v) = version {
        println!("cargo:rustc-env=RUSTC_VERSION={}", v.trim());
    }
    println!("cargo:rerun-if-changed=build.rs");
}
