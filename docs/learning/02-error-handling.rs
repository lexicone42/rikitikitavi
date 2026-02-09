// ============================================================================
// RIKITIKITAVI LEARNING GUIDE #2: Error Handling in Rust
// ============================================================================
//
// Rust has no exceptions. Instead, functions that can fail return a
// Result<T, E> — either Ok(value) or Err(error).
//
// This project uses two error-handling crates:
//   - `thiserror`: For defining structured error enums (library code)
//   - `anyhow`: For ergonomic error propagation (application code)

// ── THISERROR: Structured Errors ──────────────────────────────────────────
//
// In crates/rikitikitavi-core/src/error.rs, we define error types:

use std::net::IpAddr;

/// The `#[derive(thiserror::Error)]` macro automatically implements
/// the `std::error::Error` trait and generates `Display` from `#[error(...)]`.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    // Each variant is a different kind of error.
    // The #[error("...")] attribute defines the Display message.

    #[error("scanner '{scanner}' failed: {message}")]
    ScannerFailed {
        scanner: String,  // Named fields let you include context
        message: String,
    },

    #[error("timeout scanning {target}")]
    Timeout { target: String },

    #[error("host unreachable: {host}")]
    HostUnreachable { host: IpAddr },

    // `#[from]` auto-generates a From<std::io::Error> impl,
    // so io::Error can be automatically converted to ScanError.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

// ── THE ? OPERATOR ────────────────────────────────────────────────────────
//
// The `?` operator is Rust's way of propagating errors. It means:
// "If this is Ok, unwrap it. If it's Err, return the error from this function."

fn example_with_question_mark() -> Result<String, ScanError> {
    // Without `?`:
    // let contents = match std::fs::read_to_string("file.txt") {
    //     Ok(c) => c,
    //     Err(e) => return Err(ScanError::Io(e)),
    // };

    // With `?` — does the same thing in one line!
    // The `#[from]` on ScanError::Io means io::Error auto-converts.
    let contents = std::fs::read_to_string("file.txt")?;
    Ok(contents)
}

// ── ANYHOW: Application-Level Errors ──────────────────────────────────────
//
// `anyhow::Result<T>` is shorthand for `Result<T, anyhow::Error>`.
// anyhow::Error can hold ANY error type, making it great for main()
// and command handlers where you don't need precise error matching.

fn example_with_anyhow() -> anyhow::Result<()> {
    // anyhow::bail!() is a shortcut for returning an error immediately
    if true {
        anyhow::bail!("something went wrong");
    }

    // anyhow::Context adds context to errors (like a stack trace)
    use anyhow::Context;
    let _data = std::fs::read_to_string("config.yaml")
        .context("failed to read configuration file")?;
    //  ↑ If read_to_string fails, the error message will be:
    //    "failed to read configuration file"
    //    Caused by: No such file or directory (os error 2)

    Ok(())
}

// ── WHEN TO USE WHICH ─────────────────────────────────────────────────────
//
// thiserror → Library code (scanners, models, core)
//   - Callers can match on specific error variants
//   - Forces you to think about error categories
//
// anyhow → Application code (main.rs, CLI handlers)
//   - Quick and ergonomic
//   - Good for "just tell me what went wrong" scenarios
//   - Supports error chains with .context()

fn main() {
    println!("Read the comments above to learn about Rust error handling.");
}
