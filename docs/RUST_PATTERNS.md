# Rust Patterns & Learnings from rikitikitavi

A collection of interesting Rust patterns used in this project, with
explanations of *why* they work and when to use them. Written for Rust learners.

---

## 1. The Consuming Builder Pattern

**File**: `crates/rikitikitavi-models/src/finding.rs`

```rust
pub fn new(scanner: &str, title: &str, description: &str, severity: Severity) -> Self {
    Self { scanner: scanner.to_owned(), title: title.to_owned(), ... }
}

#[must_use]
pub const fn with_ip(mut self, ip: IpAddr) -> Self {
    self.affected_ip = Some(ip);
    self
}
```

Usage:
```rust
Finding::new("smb", "SMBv1 enabled", "...", Severity::Critical)
    .with_ip(ip)
    .with_port(445)
    .with_service("SMB")
    .with_cwe("CWE-327")
    .with_remediation(remediation)
```

**Why it's interesting**: Each `.with_*()` method takes `self` by value (not
`&mut self`) and returns `Self`. This means every call *consumes* the previous
value and returns a new one. Rust's move semantics make this zero-cost — there's
no copying, just moving ownership down the chain.

The `#[must_use]` annotation means the compiler warns you if you call
`.with_ip(ip)` without using the return value — catching the common mistake of
thinking it modifies in place.

Some of these are even `const fn`, meaning the compiler can evaluate them at
compile time when all inputs are known.

**When to use**: Structs with many optional fields. Avoids the "20 parameter
constructor" problem and the "mutable builder struct" pattern.

---

## 2. Pure Functions + I/O Wrapper for Testability

**File**: `crates/rikitikitavi-network/src/arp.rs`

```rust
// Pure function: takes &str, fully testable
fn parse_proc_net_arp(contents: &str) -> Vec<ArpEntry> {
    contents.lines().skip(1).filter_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // ... parse fields ...
    }).collect()
}

// I/O wrapper: reads file, delegates to pure function
pub fn read_arp_cache() -> Result<Vec<ArpEntry>> {
    let contents = std::fs::read_to_string("/proc/net/arp")?;
    Ok(parse_proc_net_arp(&contents))
}
```

**Why it's interesting**: Testing file-reading code is painful (need fixtures,
temp files, mock filesystems). By separating the *parsing logic* from the
*I/O*, we can test parsing with simple string literals:

```rust
#[test]
fn test_parse_proc_net_arp() {
    let contents = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n";
    let entries = parse_proc_net_arp(contents);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].mac, "aa:bb:cc:dd:ee:ff");
}
```

This same pattern is used throughout the `rikitikitavi-network` crate for
route tables, interface lists, and WiFi scan results.

**When to use**: Anywhere you parse structured text from files, commands, or
network responses. Test the parser, not the I/O.

---

## 3. Enum Dispatch Without Dynamic Dispatch

**File**: `crates/rikitikitavi-scanners/src/arp.rs`

```rust
enum ArpAnomaly {
    DuplicateIp { ip: IpAddr, macs: Vec<String>, is_gateway: bool },
    DuplicateMac { mac: String, ips: Vec<IpAddr> },
    BroadcastMac { ip: IpAddr, mac: String },
    IncompleteMac { ip: IpAddr },
}

fn anomaly_to_finding(anomaly: &ArpAnomaly) -> Finding {
    match anomaly {
        ArpAnomaly::DuplicateIp { ip, macs, is_gateway } => {
            let severity = if *is_gateway { Severity::Critical } else { Severity::High };
            Finding::new("arp", &format!("ARP spoofing: {ip}"), "...", severity)
                .with_ip(*ip)
                .with_cwe("CWE-290")
        }
        ArpAnomaly::BroadcastMac { ip, mac } => { ... }
        // ...
    }
}
```

**Why it's interesting**: Instead of trait objects (`Box<dyn Anomaly>`) with
virtual dispatch, we use an enum with data in each variant. The `match`
statement is exhaustive — if you add a new variant, the compiler forces you to
handle it everywhere. This is *compile-time polymorphism* and it's faster than
vtable dispatch.

Each variant can carry completely different data (note `DuplicateIp` has a
`Vec<String>` while `IncompleteMac` has just an `IpAddr`).

**When to use**: When you have a closed set of types (you control all variants).
Use trait objects when the set is open (plugins, user-defined types).

---

## 4. The `is_ok_and` / `is_some_and` Pattern

**File**: `crates/rikitikitavi-scanners/src/ports.rs`

```rust
// Instead of:
match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
    Ok(Ok(_)) => true,
    _ => false,
}

// Use:
tokio::time::timeout(timeout, TcpStream::connect(addr))
    .await
    .is_ok_and(|r| r.is_ok())
```

**Why it's interesting**: `is_ok_and` (stabilized in Rust 1.70) collapses the
common "check if Result is Ok AND the inner value satisfies a predicate" into
one call. It replaces the verbose `map_or(false, |x| x.is_ok())` pattern that
clippy pedantic used to suggest.

The dual is `is_some_and` for `Option`. Both avoid intermediate
`match`/`if let` blocks.

**When to use**: Boolean checks on nested `Result<Result<T>>` or `Option<T>`
where you just need true/false.

---

## 5. `const fn` for Zero-Cost Abstraction

**File**: `crates/rikitikitavi-scanners/src/ports.rs`

```rust
const fn port_to_service(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        80 => "HTTP",
        443 => "HTTPS",
        3306 => "MySQL",
        _ => "Unknown",
    }
}
```

**Why it's interesting**: The `const fn` annotation tells the compiler this
function has no side effects and can be evaluated at compile time. When called
with a literal like `port_to_service(22)`, the compiler may replace the entire
call with `"SSH"` — zero runtime cost.

Even when called with runtime values, `const fn` serves as documentation that
the function is pure: no allocations, no I/O, no panics (in this case).

Clippy pedantic's `missing_const_for_fn` lint will tell you when you *could*
make a function `const` but didn't.

**When to use**: Pure functions that only do matching, arithmetic, or field
access. If it can't fail and doesn't allocate, try making it `const`.

---

## 6. Property-Based Testing with `proptest`

**File**: `crates/rikitikitavi-scanners/src/arp.rs`

```rust
proptest! {
    #[test]
    fn prop_is_broadcast_mac_no_panic(mac in "[0-9a-fA-F:-]{0,20}") {
        let _ = is_broadcast_mac(&mac);
    }

    #[test]
    fn prop_detect_anomalies_no_panic(
        count in 0_usize..10,
        last_octet in proptest::collection::vec(1_u8..=254_u8, 0..10),
    ) {
        let entries: Vec<ArpEntryData> = last_octet.iter().take(count).map(|&o| {
            ArpEntryData {
                ip: format!("192.168.1.{o}").parse().unwrap(),
                mac: format!("aa:bb:cc:dd:ee:{o:02x}"),
            }
        }).collect();
        let _ = detect_arp_anomalies(&entries, None);
    }
}
```

And a more powerful example with *invariant checking*:

```rust
// From http_audit.rs — verifies a counting invariant
fn prop_classify_missing_headers_no_panic(
    hsts in any::<bool>(), xfo in any::<bool>(),
    csp in any::<bool>(), xcto in any::<bool>(),
    port in 1_u16..=65535_u16,
) {
    let headers = HeaderSet { has_hsts: hsts, has_x_frame_options: xfo, ... };
    let findings = classify_missing_headers(ip, port, &headers);
    // Invariant: one finding per missing header, exactly
    let expected = u32::from(!hsts) + u32::from(!xfo) + u32::from(!csp) + u32::from(!xcto);
    assert_eq!(findings.len(), expected as usize);
}
```

**Why it's interesting**: Instead of writing 5 test cases by hand, `proptest`
generates *hundreds* of random inputs and verifies your property holds for all
of them. The "no panic" tests are the baseline — they catch unexpected panics
on weird inputs (empty strings, zeros, huge values). The invariant test goes
further: it mathematically specifies what the function should return.

If proptest finds a failing input, it *shrinks* it to the minimal reproducing
case. So instead of failing on a 200-character string, it'll show you the
3-character string that breaks.

**When to use**: Parsers (should never panic on any input), classification
functions (invariants on output), serialization (roundtrip: decode(encode(x)) == x).

---

## 7. The Borrow Checker Dance: Deferred Mutation

**File**: `crates/rikitikitavi-tui/src/widgets/findings.rs`

```rust
pub fn render(frame: &mut Frame, app: &mut App) {
    let findings = app.findings(); // borrows app immutably

    // ... use findings to build rows, render table ...
    let table_area = chunks[0]; // save the Rect value

    frame.render_widget(table, table_area);

    // NOW we can mutate app — the immutable borrow from findings() is done
    app.hit_regions.list_area = Some(table_area);
    app.hit_regions.list_header_offset = 2;
}
```

**Why it's interesting**: `app.findings()` returns `&[Finding]` which borrows
`app` immutably. While that borrow is alive, you can't mutate `app`. The
solution isn't to clone the data — it's to structure your code so the mutation
happens *after* the borrow is no longer needed.

By saving `table_area` as a local `Rect` (which is `Copy`), we capture the
value we need. After `frame.render_widget()` consumes the last use of
`findings`, the borrow is released, and we can write to `app.hit_regions`.

**When to use**: Any time the borrow checker complains about "cannot borrow
`x` as mutable because it is also borrowed as immutable." Instead of reaching
for `Clone`, look at whether you can reorder operations.

---

## 8. Platform-Specific Code with `cfg` Attributes

**File**: `crates/rikitikitavi-network/src/arp.rs`

```rust
#[cfg(target_os = "linux")]
fn read_arp_cache_platform() -> Result<Vec<ArpEntry>> {
    let contents = std::fs::read_to_string("/proc/net/arp")?;
    Ok(parse_proc_net_arp(&contents))
}

#[cfg(target_os = "macos")]
fn read_arp_cache_platform() -> Result<Vec<ArpEntry>> {
    let output = std::process::Command::new("arp").arg("-a").output()?;
    let contents = String::from_utf8_lossy(&output.stdout);
    Ok(parse_arp_command_output(&contents))
}

// Make the macOS parser available in tests even on Linux
#[cfg(any(target_os = "macos", test))]
fn parse_arp_command_output(contents: &str) -> Vec<ArpEntry> { ... }
```

**Why it's interesting**: `#[cfg(target_os = "linux")]` makes the function
*only exist* on Linux — it's not even compiled on other platforms. This is
zero-cost: no runtime checks, no dead code in the binary.

The clever bit is `#[cfg(any(target_os = "macos", test))]` — the macOS parser
function is compiled on macOS AND during `cargo test` on any platform. This
means we can test the macOS parsing logic from a Linux CI server, because
the parser is a pure function taking `&str`.

**When to use**: Cross-platform code. Also useful with `#[cfg(test)]` for
test-only helper functions.

---

## 9. `HashMap::entry` API for Grouping

**File**: `crates/rikitikitavi-scanners/src/arp.rs`

```rust
let mut ip_to_macs: HashMap<IpAddr, Vec<&str>> = HashMap::new();
for entry in entries {
    ip_to_macs
        .entry(entry.ip)
        .or_default()
        .push(&entry.mac);
}
```

**Why it's interesting**: The entry API avoids the classic "check if key
exists, then insert or update" pattern. `.entry(key)` gives you a handle that
is either `Occupied` or `Vacant`. `.or_default()` inserts `Vec::new()` if
vacant, then returns `&mut Vec`. One hash lookup instead of two.

This is idiomatic for "group by" operations. The alternative with
`if let Some(v) = map.get_mut(&key)` is verbose and double-hashes.

**When to use**: Aggregation, grouping, counting, accumulating values by key.

---

## 10. Wire Protocol Parsing: SMBv1 Detection

**File**: `crates/rikitikitavi-scanners/src/smb.rs`

```rust
fn classify_smb_response(response: &[u8]) -> SmbVersion {
    if response.len() < 8 {
        return SmbVersion::Unknown;
    }
    // SMBv1 magic: \xFFSMB at offset 4 (after NetBIOS header)
    if response[4] == 0xFF && &response[5..8] == b"SMB" {
        return SmbVersion::V1;
    }
    // SMBv2 magic: \xFESMB
    if response[4] == 0xFE && &response[5..8] == b"SMB" {
        return SmbVersion::V2Plus;
    }
    SmbVersion::Unknown
}
```

**Why it's interesting**: This is real binary protocol parsing in safe Rust.
The `b"SMB"` syntax creates a byte string literal (`&[u8; 3]`), and we can
compare it directly against a slice. No unsafe pointer arithmetic needed.

The `&response[5..8]` is a *slice* — if `response` is shorter than 8 bytes,
the bounds check at `response.len() < 8` prevents a panic. This is Rust's
safety guarantee: the early return makes the slice access provably safe.

**When to use**: Any binary protocol parsing. Rust's slices and byte literals
make it clean and safe. Compare with C where you'd need manual bounds checking.

---

## 11. Workspace-Level Lint Configuration

**File**: `Cargo.toml` (workspace root)

```toml
[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
```

**Why it's interesting**: Instead of adding `#![warn(clippy::pedantic)]` to
every crate's `lib.rs`, workspace-level lints apply to all crates at once.
The `priority = -1` trick means "enable all pedantic/nursery lints as warnings"
and then individual `= "allow"` entries override specific noisy ones.

Combined with `-D warnings` in CI (`cargo clippy -- -D warnings`), this makes
any lint violation a hard error. It's strict but catches real bugs: wrong casts,
unnecessary allocations, missing error handling.

**When to use**: Any multi-crate workspace. Set it once, every crate inherits.

---

## 12. `let...else` for Early Returns

**File**: `crates/rikitikitavi-scanners/src/dhcp.rs`

```rust
// Instead of:
let interfaces = match rikitikitavi_network::list_interfaces() {
    Ok(ifaces) => ifaces,
    Err(_) => return Vec::new(),
};

// Use:
let Ok(interfaces) = rikitikitavi_network::list_interfaces() else {
    return Vec::new();
};
```

**Why it's interesting**: `let...else` (stabilized in Rust 1.65) is the
pattern-matching equivalent of a guard clause. The `else` branch *must*
diverge (return, break, continue, panic). This flattens the "if error, bail
early" pattern that's everywhere in Rust.

Clippy's `manual_let_else` lint will suggest this transformation.

**When to use**: Any place you have `let x = match ... { Ok(v) => v, Err(_) => return ... }`.
It's especially clean for functions that need to gracefully degrade when
something fails.

---

## 13. Newtype Pattern for Type Safety

**File**: `crates/rikitikitavi-models/src/finding.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FindingFingerprint(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceFingerprint(pub u64);
```

**Why it's interesting**: Both are wrappers around `u64`, but Rust treats them
as completely different types. You can't accidentally pass a `DeviceFingerprint`
where a `FindingFingerprint` is expected — the compiler catches it.

This is zero-cost: `FindingFingerprint(42)` has the same memory layout as
`42_u64`. The wrapping only exists at compile time.

The `Copy` derive means these are passed by value (like integers), not moved.
Small types (up to ~128 bits) should usually be `Copy` to avoid unnecessary
references.

**When to use**: Any time you have a raw `u64`, `String`, or `Vec<u8>` that
represents a specific concept. Wrap it to prevent mixing up semantically
different values.

---

## 14. Custom Serde Serialization

**File**: `crates/rikitikitavi-models/src/ocsf.rs`

```rust
fn serialize_epoch_ms<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_i64(dt.timestamp_millis())
}

#[derive(Serialize)]
pub struct OcsfFinding {
    #[serde(serialize_with = "serialize_epoch_ms")]
    pub time: DateTime<Utc>,
}
```

**Why it's interesting**: The field type stays `DateTime<Utc>` (ergonomic in
Rust), but the JSON output is epoch milliseconds (what OCSF requires). You get
type safety in Rust code AND protocol compliance in the output.

The `S: Serializer` generic means this works with any serde format (JSON,
MessagePack, CBOR). You write the function once.

**When to use**: When an external schema requires a different representation
than what's natural in Rust. Common cases: epoch timestamps, base64 blobs,
enum-to-integer mappings.

---

## 15. Feature-Gated Optional Dependencies

**File**: `crates/rikitikitavi/Cargo.toml`

```toml
[features]
default = ["tui", "unifi"]
monitor = ["rikitikitavi-scanners/monitor", "rikitikitavi-network/monitor"]

[dependencies]
rikitikitavi-tui = { path = "../rikitikitavi-tui", optional = true }
```

And in code:
```rust
#[cfg(feature = "monitor")]
pub mod passive_wifi;
```

**Why it's interesting**: The `monitor` feature requires `libpcap-dev` at build
time. By making it non-default, `cargo install` just works on any system. Users
who want WiFi monitoring opt in explicitly.

Features propagate through dependencies: enabling `monitor` on the binary
automatically enables `monitor` on the scanners crate, which enables it on the
network crate, which pulls in the `pcap` dependency. One flag controls the
entire feature tree.

**When to use**: When a feature has system dependencies (C libraries, hardware
access) or adds significant binary size. Keep `cargo install` simple by
default.

---

## 16. The `From` Trait for Type Conversion

**File**: `crates/rikitikitavi-models/src/ocsf.rs`

```rust
impl From<&Finding> for OcsfFinding {
    fn from(f: &Finding) -> Self {
        Self {
            class_uid: 2002,
            severity_id: f.severity.ocsf_id(),
            time: f.discovered_at,
            finding_info: OcsfFindingInfo {
                title: f.title.clone(),
                // ...
            },
            // ...
        }
    }
}

// Usage:
let ocsf = OcsfFinding::from(&finding);
// or equivalently:
let ocsf: OcsfFinding = (&finding).into();
```

**Why it's interesting**: `From` is Rust's standard conversion trait.
Implementing `From<&Finding>` also gives you `Into<OcsfFinding>` for free
(blanket implementation in the standard library). This convention makes
conversions discoverable and composable.

Using `&Finding` (reference) means we don't consume the original — important
when converting a list of findings where we still need the originals.

**When to use**: Any structured type conversion. Prefer `From` over custom
`to_foo()` methods for conversions between your own types.

---

## Summary: Principles at Work

| Principle | Pattern | Benefit |
|-----------|---------|---------|
| Separation of concerns | Pure parse fn + I/O wrapper | Testability |
| Make illegal states unrepresentable | Enum variants with different data | Compiler checks exhaustiveness |
| Zero-cost abstractions | `const fn`, consuming builders, newtypes | No runtime overhead |
| Fail fast, fail loud | `#[must_use]`, `-D warnings` | Catches bugs at compile time |
| Test the properties, not examples | proptest invariants | Hundreds of auto-generated test cases |
| Borrow, don't clone | Deferred mutation, slices | No unnecessary allocations |
| Type safety at zero cost | Newtype pattern, `From` trait | Compiler prevents mixing up types |
| Optional complexity | Feature flags, `#[cfg]` | Users only pay for what they use |
