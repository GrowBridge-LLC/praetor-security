//! SCA command construction — **argv only, never execution**.
//!
//! 🔴 THIS MODULE EXISTS TO MAKE THE NEVER-EXECUTE INVARIANT TESTABLE BEFORE ANY
//! BACKEND CAN RUN.
//!
//! ADR-001 condition 2 is binding: *no Rust backend merges before its
//! never-execute invariant test does.* That is only enforceable if building the
//! command and running it are separate things — so command construction lives
//! here as **pure functions returning `Vec<String>`**, and nothing in this file
//! may spawn a process.
//!
//! The Python implementation's guard works the same way, and its docstring says
//! why: the tests *"capture the argv PRAETOR would hand to the subprocess,
//! without executing anything, so they fail when the flag stops reaching the
//! command line, not merely when a comment changes."*
//!
//! ## The flag that is the whole guarantee
//!
//! `--disable-pip` forbids pip from **resolving or building** the target's
//! requirements. Without it, `pip-audit` performs a full pip resolve, which
//! builds source distributions and executes attacker-controlled `setup.py` /
//! PEP 517 backends from the tree being scanned — arbitrary code execution in a
//! tool whose entire promise is that it only reads. This was real, not
//! hypothetical, in the Python implementation.
//!
//! ⚠️ `--no-deps` alone does NOT prevent it. Both are passed; `--disable-pip` is
//! the load-bearing one.
//!
//! ⚠️ **Never add a retry path that drops the flag.** If a requirements file
//! cannot be audited without resolving, the honest outcome is an ERROR — never a
//! fallback into a resolving mode, and never a clean "0 findings".

/// Build the `pip-audit` argv for one requirements file.
///
/// Returns the command line **without running it**. Callers execute; this
/// function must stay pure so the invariant can be asserted on its output.
pub fn pip_audit_argv(exe: &str, requirements_path: &str) -> Vec<String> {
    vec![
        exe.to_string(),
        "--format".to_string(),
        "json".to_string(),
        "--progress-spinner".to_string(),
        "off".to_string(),
        // SAFETY (CRITICAL): these two together forbid pip from resolving or
        // building the target's requirements. See the module docs.
        "--no-deps".to_string(),
        "--disable-pip".to_string(),
        "-r".to_string(),
        requirements_path.to_string(),
    ]
}

/// Build the `osv-scanner` argv for a target directory.
///
/// osv-scanner statically reads lockfiles; it never builds or runs the target,
/// so there is no equivalent load-bearing flag here. The invariant test still
/// covers it, because "this backend happens to be safe today" is a property of
/// the tool that could change under us — and because an unguarded backend is how
/// the pip-audit hole got in.
pub fn osv_scanner_argv(exe: &str, target_abs: &str) -> Vec<String> {
    vec![
        exe.to_string(),
        "--format".to_string(),
        "json".to_string(),
        "--recursive".to_string(),
        target_abs.to_string(),
    ]
}

/// Argv fragments that would let a package manager resolve, build, or install
/// from the scanned tree. **None of these may ever appear in a PRAETOR argv.**
///
/// Kept as data rather than prose so the test can assert over it, and so adding
/// a backend that reaches for one of these fails loudly instead of quietly.
pub const FORBIDDEN_RESOLVING_FLAGS: &[&str] = &[
    "--no-deps=false",
    "install",
    "download",
    "wheel",
    "build",
    "--use-pep517",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The load-bearing assertion. If this fails, the RCE is back.
    #[test]
    fn pip_audit_argv_carries_disable_pip() {
        let argv = pip_audit_argv("/usr/bin/pip-audit", "requirements.txt");

        assert!(
            !argv.is_empty(),
            "argv is empty -- the test is vacuous, fix the fixture not the assertion"
        );
        assert!(
            argv.iter().any(|a| a == "--disable-pip"),
            "RCE REGRESSION: pip-audit argv built WITHOUT --disable-pip. pip will resolve \
             and BUILD the target's requirements, executing attacker-controlled setup.py / \
             PEP517 backends from the scanned tree. argv was: {argv:?}"
        );
        assert!(
            argv.iter().any(|a| a == "--no-deps"),
            "--no-deps missing; it is passed alongside --disable-pip. argv was: {argv:?}"
        );
    }

    #[test]
    fn no_sca_argv_can_resolve_build_or_install() {
        // Covers EVERY backend at once, so a newly added one is caught by an
        // existing test rather than by remembering to write a new one.
        let argvs = [
            pip_audit_argv("pip-audit", "requirements.txt"),
            osv_scanner_argv("osv-scanner", "/tmp/target"),
        ];
        for argv in &argvs {
            for forbidden in FORBIDDEN_RESOLVING_FLAGS {
                assert!(
                    !argv.iter().any(|a| a == forbidden),
                    "INVARIANT VIOLATION: argv contains {forbidden:?}, which lets a package \
                     manager resolve/build/install from the scanned tree. PRAETOR never \
                     executes the code it scans. argv was: {argv:?}"
                );
            }
        }
    }

    #[test]
    fn osv_argv_targets_the_requested_path() {
        // Guards the keep direction: the invariant tests above must not be
        // satisfiable by a function that returns a harmless empty/rubbish argv.
        let argv = osv_scanner_argv("osv-scanner", "/tmp/target");
        assert!(argv.iter().any(|a| a == "/tmp/target"), "argv was: {argv:?}");
        assert_eq!(argv[0], "osv-scanner", "argv was: {argv:?}");
    }
}
