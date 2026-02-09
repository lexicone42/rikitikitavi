// ============================================================================
// RIKITIKITAVI LEARNING GUIDE #1: Project Structure & Cargo Workspaces
// ============================================================================
//
// This file explains how the project is organized. You can't run this file
// directly — it's annotated pseudocode for learning.
//
// ── CARGO WORKSPACE ────────────────────────────────────────────────────────
//
// A Cargo **workspace** lets you split a large project into multiple
// **crates** (Rust's term for a package/library). Each crate has its own
// Cargo.toml but they all share:
//   - A single Cargo.lock (consistent dependency versions)
//   - A single target/ directory (faster builds, shared compilation)
//   - Workspace-level settings (lints, dependencies)
//
// Our workspace root Cargo.toml says:
//
//   [workspace]
//   members = [
//       "crates/rikitikitavi",           ← The binary (what users run)
//       "crates/rikitikitavi-core",      ← Shared error types & enums
//       "crates/rikitikitavi-models",    ← Data structures
//       "crates/rikitikitavi-scanners",  ← Scanner trait + implementations
//       ...
//   ]
//
// ── WHY MULTIPLE CRATES? ──────────────────────────────────────────────────
//
// 1. **Faster compilation**: Change one crate → only that crate recompiles
// 2. **Clear boundaries**: Each crate has a defined public API
// 3. **Feature flags**: The TUI and UniFi crates are optional
// 4. **Reusability**: The library crates could be used by other tools
//
// ── DEPENDENCY FLOW (no circular deps allowed!) ───────────────────────────
//
//   rikitikitavi (binary)
//       ├── rikitikitavi-core       ← Foundation: errors, enums
//       ├── rikitikitavi-models     ← depends on core
//       ├── rikitikitavi-network    ← depends on core, models
//       ├── rikitikitavi-scanners   ← depends on core, models, network
//       ├── rikitikitavi-analysis   ← depends on core, models
//       ├── rikitikitavi-export     ← depends on core, models
//       ├── rikitikitavi-tui        ← depends on core, models, scanners
//       └── rikitikitavi-unifi      ← depends on core, models, scanners
//
// ── WORKSPACE DEPENDENCIES ────────────────────────────────────────────────
//
// Instead of each crate specifying `serde = "1.0"` independently, we
// declare shared dependencies ONCE in the workspace root:
//
//   [workspace.dependencies]
//   serde = { version = "1", features = ["derive"] }
//   tokio = { version = "1", features = ["full"] }
//
// Then each crate's Cargo.toml just says:
//
//   [dependencies]
//   serde.workspace = true    ← Inherits version & features from workspace
//
// This prevents the nightmare of different crates using different versions
// of the same library.

fn main() {
    // This file is for reading, not running!
    println!("Read the comments above to learn about Cargo workspaces.");
}
