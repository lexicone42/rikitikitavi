// ============================================================================
// RIKITIKITAVI LEARNING GUIDE #8: Hashing, Fingerprints, and Change Tracking
// ============================================================================
//
// This file explains how rikitikitavi tracks findings across scans using
// deterministic fingerprints. The key Rust concepts: Hash trait, newtype
// pattern, and HashMap-based set operations.
//
// ── THE PROBLEM ─────────────────────────────────────────────────────────────
//
// You scan your network today and find "Redis has no auth on 192.168.1.50:6379".
// You scan again tomorrow. Is it the SAME finding or a NEW one?
//
// We can't compare by equality — the description might change, the timestamp
// definitely changes, the severity might be upgraded. We need a STABLE IDENTITY
// that survives cosmetic changes.
//
// ── SOLUTION: FINGERPRINTS ──────────────────────────────────────────────────
//
// A fingerprint is a hash of the fields that define a finding's identity:
//
//   (scanner_id, title, affected_ip, affected_port)
//
// If any of those change, it's a DIFFERENT finding. If only severity or
// description change, it's the SAME finding with updated details.
//
// ── THE HASH TRAIT ──────────────────────────────────────────────────────────
//
// Rust's `Hash` trait lets you feed values into any `Hasher`:
//
//   use std::hash::{Hash, Hasher};
//
//   /// FNV-1a 64: a fixed algorithm, so persisted fingerprints stay valid.
//   struct Fnv1a64(u64);
//
//   impl Hasher for Fnv1a64 {
//       fn finish(&self) -> u64 { self.0 }
//       fn write(&mut self, bytes: &[u8]) {
//           for &b in bytes {
//               self.0 ^= u64::from(b);
//               self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
//           }
//       }
//   }
//
//   impl Finding {
//       pub fn fingerprint(&self) -> FindingFingerprint {
//           let mut hasher = Fnv1a64::new();
//           hasher.write(self.scanner.as_bytes());
//           hasher.write_u8(0xff);
//           hasher.write(self.title.as_bytes());
//           hasher.write_u8(0xff);
//           match self.affected_ip {                 // tag byte, then octets
//               None => hasher.write_u8(0),
//               Some(IpAddr::V4(v4)) => { hasher.write_u8(4); hasher.write(&v4.octets()); }
//               Some(IpAddr::V6(v6)) => { hasher.write_u8(6); hasher.write(&v6.octets()); }
//           }
//           match self.affected_port {               // tag byte, then big-endian u16
//               None => hasher.write_u8(0),
//               Some(p) => { hasher.write_u8(1); hasher.write(&p.to_be_bytes()); }
//           }
//           FindingFingerprint(hasher.finish())
//       }
//   }
//
// Key points:
// - std's `DefaultHasher` (SipHash) is NOT guaranteed stable across Rust
//   releases. Fingerprints are written to baseline/suppression files, so the
//   code uses its own FNV-1a hasher, whose output never changes.
// - The bytes are written explicitly with fixed-width tags. Derived `Hash`
//   impls (e.g. for `Option<u16>`) write the enum discriminant as a native
//   `isize`, so the same value would hash differently on 32-bit or big-endian
//   machines and a baseline file would not be portable between them.
// - `.finish()` produces a u64 digest.
//
// ── THE NEWTYPE PATTERN ─────────────────────────────────────────────────────
//
// Instead of using a raw `u64` for fingerprints, we wrap it:
//
//   #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
//   pub struct FindingFingerprint(pub u64);
//
// Why? Type safety. You can't accidentally compare a FindingFingerprint with
// a DeviceFingerprint, even though both are u64 inside. The compiler treats
// them as different types.
//
// This is called the "newtype pattern" — a single-field tuple struct that
// adds type safety without runtime cost. `FindingFingerprint(42)` is the
// same size as `42_u64` in memory.
//
// ── SET OPERATIONS WITH HASHMAP ─────────────────────────────────────────────
//
// Scan comparison is really a set operation:
//
//   old_fingerprints = { fp1, fp2, fp3, fp4 }
//   new_fingerprints = { fp2, fp3, fp5, fp6 }
//
//   new_findings      = new - old     = { fp5, fp6 }
//   resolved_findings = old - new     = { fp1, fp4 }
//   unchanged         = old ∩ new     = { fp2, fp3 }  (if severity same)
//   severity_changed  = old ∩ new     = ...            (if severity differs)
//
// In Rust, we build HashMaps keyed by fingerprint:
//
//   let old_map: HashMap<FindingFingerprint, &Finding> = old_findings
//       .iter()
//       .map(|f| (f.fingerprint(), f))
//       .collect();
//
//   let new_map: HashMap<FindingFingerprint, &Finding> = new_findings
//       .iter()
//       .map(|f| (f.fingerprint(), f))
//       .collect();
//
//   // New findings: in new_map but not old_map
//   for (fp, finding) in &new_map {
//       if !old_map.contains_key(fp) {
//           new.push(finding);
//       }
//   }
//
// ── DEVICE FINGERPRINTS: PREFERRING MAC OVER IP ─────────────────────────────
//
// Devices are trickier. DHCP means IPs change, but MACs don't (usually).
// Device identity does not need a hash at all: an enum holds the identifying
// value directly, and derived `Eq`/`Hash` make it usable as a map key.
//
//   pub enum DeviceFingerprint {
//       Mac(MacAddr),
//       Ip(IpAddr),
//   }
//
//   impl Device {
//       pub fn fingerprint(&self) -> DeviceFingerprint {
//           self.mac
//               .map_or(DeviceFingerprint::Ip(self.ip), DeviceFingerprint::Mac)
//       }
//   }
//
// This means: if two devices have the same MAC, they're the "same" device
// even if the IP changed (DHCP lease renewal). Only if we don't know the MAC
// do we fall back to IP-based identity.
//
// ── PROPERTY TESTING THE DIFF ───────────────────────────────────────────────
//
// The most powerful test for scan comparison is an algebraic property:
//
//   proptest! {
//       #[test]
//       fn prop_diff_covers_all_findings(
//           old in vec(arb_finding(), 0..20),
//           new in vec(arb_finding(), 0..20),
//       ) {
//           let diff = diff_scan_results(&old, &new);
//
//           // Every new fingerprint is in exactly one category
//           let total_new = diff.new_findings.len()
//               + diff.unchanged_findings.len()
//               + diff.severity_changes.len();
//           // (We count unique fingerprints, not raw findings)
//       }
//   }
//
// This says: "for ANY two random lists of findings, the diff function
// partitions all fingerprints correctly." It's much stronger than testing
// with 3 hand-crafted examples.
//
// ── SCAN HISTORY PERSISTENCE ────────────────────────────────────────────────
//
// Scans are saved as timestamped JSON files in XDG data dir:
//
//   ~/.local/share/rikitikitavi/scans/
//   ├── scan_2026-02-12T10-30-00.json
//   ├── scan_2026-02-12T14-15-00.json
//   └── scan_2026-02-12T18-45-00.json
//
// The `dirs` crate finds the XDG base directory portably (Linux: ~/.local/share,
// macOS: ~/Library/Application Support). History is pruned to keep only the
// 10 most recent scans.
//
// ── KEY TAKEAWAYS ───────────────────────────────────────────────────────────
//
// 1. The Hash trait works with any Hasher; pick a fixed algorithm (FNV-1a)
//    when digests are persisted, since DefaultHasher may change between releases
// 2. Newtype pattern (struct Foo(u64)) adds type safety for free
// 3. HashMap set operations (contains_key, difference) map naturally to
//    scan comparison categories
// 4. Property tests verify algebraic invariants across random inputs
// 5. Option<T> implements Hash, so optional fields participate correctly

fn main() {
    println!("Read the comments above to learn about hashing and fingerprints.");
}
