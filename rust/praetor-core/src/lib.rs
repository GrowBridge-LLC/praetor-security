//! PRAETOR engines — Rust port.
//!
//! 🔴 THE INVARIANT THAT OUTRANKS EVERYTHING IN THIS CRATE:
//! **PRAETOR NEVER EXECUTES, IMPORTS, INSTALLS OR BUILDS THE CODE IT SCANS.**
//!
//! This has been false once, in the Python implementation: the SCA path invoked
//! `pip-audit` in a mode that let pip *resolve* the target's requirements, which
//! builds source distributions and runs `setup.py` / PEP 517 backends from an
//! attacker-controlled tree. Arbitrary code execution, in a tool whose entire
//! promise is that it only reads. The fix is one flag — `--disable-pip`.
//!
//! ⚠️ **A Rust backend is a NEW backend, and every new backend widens that
//! surface.** Porting the argv construction without porting the test that guards
//! it would reintroduce the same hole in a language where nobody has looked for
//! it yet. Hence the binding rule for this port:
//!
//! > **No backend merges here before its never-execute invariant test does.**
//!
//! See `references/ADR-001-engine-language.md` for the decision, its four
//! conditions, and the counter-argument that lost.
//!
//! ## Status
//!
//! A `secrets` detector prototype exists on a parked side branch ahead of the
//! ADR-mandated port order. It is preserved work, not an accepted first port and
//! not wired into the binary; the binary still refuses to pretend it can scan.
//!
//! ⚠️ "Scaffold only" was the earlier wording and it undersold this: `text.rs`
//! (the shared line definition), `sca.rs` (argv construction plus the
//! never-execute guard) and `unicode_tables.rs` (a generated script table) are
//! real, tested, load-bearing code, not stubs. The parked detector adds a
//! `scan()` entry point in this crate only; it does not change CLI capability.
//!
//! Port order is fixed by ADR-001: `aisec` first (pure pattern matching, no
//! external tool dependencies), with `sast`/`sca` last because they own the
//! subprocess boundary above.
//!
//! ## Acceptance
//!
//! Correctness here is **differential**, not "the tests pass": this crate and the
//! Python implementation must emit identical `(engine, rule_id, file, line)` sets
//! over one shared corpus. Two implementations under continuous reconciliation
//! are a pair; the moment that harness stops being green and blocking, they are
//! a fork.

pub mod sca;
pub mod secrets;
pub mod text;
pub mod unicode_tables;

/// Engines PRAETOR fuses. Present so the differential harness has a stable
/// vocabulary to compare on while engines are ported incrementally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Engine {
    Sast,
    Secrets,
    Sca,
    Aisec,
}

impl Engine {
    /// The wire name. 🔴 Must match the Python `Finding.engine` values exactly —
    /// the differential harness compares on this string, so a divergence here
    /// would make two identical findings look like two different ones.
    pub fn as_str(&self) -> &'static str {
        match self {
            Engine::Sast => "sast",
            Engine::Secrets => "secrets",
            Engine::Sca => "sca",
            Engine::Aisec => "aisec",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_wire_names_match_the_python_implementation() {
        // These four strings are a contract with scripts/core.py, not a detail.
        assert_eq!(Engine::Sast.as_str(), "sast");
        assert_eq!(Engine::Secrets.as_str(), "secrets");
        assert_eq!(Engine::Sca.as_str(), "sca");
        assert_eq!(Engine::Aisec.as_str(), "aisec");
    }
}
