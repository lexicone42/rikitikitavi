// ============================================================================
// RIKITIKITAVI LEARNING GUIDE #4: Ownership, Borrowing, and Lifetimes
// ============================================================================
//
// This is THE key concept in Rust. It's what makes Rust memory-safe without
// a garbage collector. Every value in Rust has exactly one owner.

// ── RULE 1: Each value has exactly one owner ──────────────────────────────

fn ownership_basics() {
    let s1 = String::from("hello");  // s1 owns the string
    let s2 = s1;                      // Ownership MOVES to s2
    // println!("{s1}");              // ERROR! s1 no longer owns the string

    // For simple types (integers, bools, chars), values are COPIED instead:
    let x = 42;
    let y = x;     // x is copied, not moved
    println!("{x} {y}");  // Both work! Because i32 implements Copy.
}

// ── RULE 2: Borrowing with & ──────────────────────────────────────────────
//
// Instead of transferring ownership, you can BORROW a value with &.
// This is like a read-only pointer.

fn borrowing_basics() {
    let findings = vec!["open port", "weak password", "no firewall"];

    // & means "borrow" — findings_ref is a reference, not an owner
    let count = count_findings(&findings);
    //                         ^ immutable borrow

    // findings is still usable here because we only borrowed it!
    println!("Found {count} issues in {:?}", findings);
}

fn count_findings(findings: &Vec<&str>) -> usize {
    //                       ^ This function BORROWS the vec, doesn't own it
    findings.len()
    // When this function returns, the borrow ends.
    // The Vec is NOT dropped because we don't own it.
}

// ── RULE 3: Mutable borrowing with &mut ───────────────────────────────────
//
// You can have EITHER:
//   - Any number of immutable borrows (&T), OR
//   - Exactly ONE mutable borrow (&mut T)
// Never both at the same time. This prevents data races at compile time!

fn mutable_borrowing() {
    let mut scores = vec![85, 92, 78];

    add_score(&mut scores, 95);
    //        ^^^^ mutable borrow — we're allowed to modify it

    println!("Scores: {:?}", scores);  // [85, 92, 78, 95]
}

fn add_score(scores: &mut Vec<i32>, score: i32) {
    //                ^^^^ mutable reference — can modify the original
    scores.push(score);
}

// ── HOW THIS SHOWS UP IN RIKITIKITAVI ─────────────────────────────────────
//
// In the Scanner trait:
//   async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError>;
//                 ^^^^^       ^^^^^^^^^^^
//                 │           └─ Borrows the scan context (read-only)
//                 └─ Borrows self (the scanner) immutably
//
// This means:
//   - Multiple scanners can share the same ScanContext simultaneously
//   - The scanner doesn't consume or modify itself during scanning
//   - The caller retains ownership of both the scanner and context
//
// In the TUI App:
//   pub fn handle_key(&mut self, key: KeyCode) {
//                     ^^^^^^^^^
//                     └─ Mutable borrow of self — can modify app state
//
// In the Finding builder:
//   pub fn with_ip(mut self, ip: IpAddr) -> Self {
//                  ^^^^^^^^
//                  └─ Takes OWNERSHIP of self (consumes it)
//                     Returns a new Self (builder pattern)

// ── LIFETIMES (the 'a thing) ──────────────────────────────────────────────
//
// Lifetimes tell the compiler how long references are valid.
// Usually the compiler infers them, but sometimes you need to be explicit.

// This function returns a reference. But reference to WHAT?
// The lifetime 'a says: "the returned reference lives as long as the input"
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

// 'static is a special lifetime meaning "lives for the entire program".
// String literals are &'static str because they're embedded in the binary.
fn scanner_id() -> &'static str {
    "network"  // This string is in the binary, lives forever
}

fn main() {
    ownership_basics();
    borrowing_basics();
    mutable_borrowing();

    let result = longest("hello", "world!");
    println!("Longest: {result}");
    println!("Scanner: {}", scanner_id());
}
