//! PRAETOR CLI — Rust port, scaffold only.
//!
//! ⚠️ This binary deliberately does NOT scan anything yet, and it says so when
//! run. A port that silently accepts a target and reports zero findings would be
//! the exact defect PRAETOR exists to catch — a clean-looking result from an
//! engine that never ran. Until the engines are ported, the honest output is a
//! refusal, not an empty report.
//!
//! Use `scripts/praetor.py` for real scans. See
//! `references/ADR-001-engine-language.md`.

fn main() {
    eprintln!(
        "praetor (Rust port) {} -- SCAFFOLD ONLY, no engines ported yet.\n\
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
