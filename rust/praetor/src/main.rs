//! PRAETOR CLI — Rust port, no engines wired yet.
//!
//! ⚠️ This binary deliberately does NOT scan anything yet, and it says so when
//! run. Detector work may exist in `praetor-core` before CLI orchestration is
//! ready; that does not make this entry point usable. The honest output remains
//! a refusal, not an empty report.
//!
//! Use `scripts/praetor.py` for real scans. See
//! `references/ADR-001-engine-language.md`.

fn main() {
    eprintln!(
        "praetor (Rust port) {} -- NO ENGINES WIRED YET.\n\
         \n\
         This binary cannot scan and will not pretend to. An empty report from an\n\
         engine that never ran is a false clean, which is the failure class this\n\
         tool exists to catch.\n\
         \n\
         Use the Python implementation for real scans:\n\
         \n    python scripts/praetor.py <target>\n\
         \n\
         Port status and conditions: references/ADR-001-engine-language.md",
        env!("CARGO_PKG_VERSION")
    );
    // Non-zero: a caller that wires this into a pipeline today must notice.
    std::process::exit(2);
}
