//! Emit this crate's differential line signature on stdout, for the runner.
//!
//! `tests/differential/run_differential.py` shells out to this and compares the
//! result to the Python implementation's signature **and** to the committed
//! expectation. Three-way, because two implementations each checking themselves
//! against a file prove nothing about each other if one of them never ran.
//!
//! ⚠️ This is an `examples/` target, not a `[[bin]]`, on purpose: it is harness
//! machinery and must never be mistaken for a shipped scanner entry point. The
//! real CLI (`praetor`) still refuses to run — see `praetor/src/main.rs`.
//!
//! It reads one compiled-in corpus of text fixtures and prints a string. It does
//! not open the scan target, and there is no scan target. Nothing here widens the
//! "PRAETOR never executes what it scans" surface.
//!
//!     cargo run -q -p praetor-core --example emit_line_signature
//!
//! Output is exactly two lines, in the same `key value` shape as the committed
//! expectation file, so the runner parses one format rather than two:
//!
//!     cases 23
//!     signature 2:a;b 2:a;b 1:solo ...

use praetor_core::text::differential;

/// The shared corpus. `include_str!`, so a renamed or deleted corpus is a build
/// error here — not an emitter that silently prints an empty signature that a
/// naive comparison would happily match against another empty signature.
const CORPUS: &str = include_str!("../../../references/differential/line-splitting.txt");

fn main() {
    println!("cases {}", differential::cases(CORPUS).count());
    println!("signature {}", differential::signature(CORPUS));
}
