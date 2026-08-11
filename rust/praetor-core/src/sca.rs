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

    /// Every argv builder in this module, for the invariant sweep below.
    ///
    /// ⚠️ Hand-maintained, and therefore NOT self-extending — which is why
    /// `every_argv_builder_in_this_file_is_swept` exists to fail when this list
    /// falls behind the module.
    fn all_argvs() -> Vec<Vec<String>> {
        vec![
            pip_audit_argv("pip-audit", "requirements.txt"),
            osv_scanner_argv("osv-scanner", "/tmp/target"),
        ]
    }

    #[test]
    fn no_sca_argv_can_resolve_build_or_install() {
        let argvs = all_argvs();
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

    /// 🔴 THE ANTI-VACUITY GUARD, and it exists because the claim it now enforces
    /// was previously only a COMMENT.
    ///
    /// `no_sca_argv_can_resolve_build_or_install` used to assert that it "covers
    /// EVERY backend at once, so a newly added one is caught by an existing test".
    /// That was false: the list is hand-written, so a new backend added to this
    /// module and simply *not added to the list* was swept by nothing and passed
    /// silently. An independent audit proved it by adding an `npm_audit_argv`
    /// containing `"install"` — all three tests stayed green.
    ///
    /// A safety property is not a property of the mechanism; it is a scope
    /// decision made next to it. This test IS that scope decision, made checkable:
    /// it counts the argv builders the module actually defines and fails if the
    /// swept list has fallen behind, so the never-execute invariant cannot be
    /// widened by omission.
    ///
    /// ⚠️ **This is a TEXTUAL check, not an AST one, and the distinction is not
    /// cosmetic.** A second audit defeated the first version of it — which keyed on
    /// the literal prefix `"pub fn "` — with a `pub(crate) fn` builder, an ordinary
    /// visibility for something only `main.rs` calls. All tests stayed green. The
    /// detection below therefore strips any visibility modifier and matches on the
    /// function *name*, so a signature whose parenthesis sits on the next line is
    /// counted too.
    ///
    /// 🔴 **THIS CHECK IS POROUS AND MUST NOT BE RELIED ON ALONE.** An earlier
    /// version of this comment named macro-generation as the one uncovered gap. A
    /// third audit then demonstrated three more, all by mutation, all easier to
    /// hit by accident than a macro:
    ///
    /// - a builder **not named** `*_argv` (`npm_command`) — the name is the only
    ///   thing matched here, and a name is a promise a contributor can forget;
    /// - a builder in a **different file** — `include_str!` takes a literal path,
    ///   so this can never see a file that does not exist yet. **Unfixable in
    ///   Rust** without a `build.rs`, which this crate refuses because it runs
    ///   code at build time;
    /// - an **attribute sharing the line** (`#[allow(dead_code)] pub fn x_argv(`),
    ///   which defeats the first-token logic below.
    ///
    /// Under all three, this suite stayed **8/8 green** with builders containing
    /// the literal `"install"` present.
    ///
    /// ⇒ **`tests/test_rust_sca_argv_sweep.py` is the real enforcement.** It reads
    /// the crate directory, keys on the `-> Vec<String>` signature rather than a
    /// name, and asserts set membership in `all_argvs()` rather than a count. This
    /// test is kept as the fast in-language check, not as the guarantee.
    /// Macro-generated builders remain invisible to both.
    #[test]
    fn every_argv_builder_in_this_file_is_swept() {
        // Reading our own source is crude, and it is the only mechanism available
        // without a build script or a proc macro — both of which would run code at
        // build time, which this crate deliberately refuses.
        const SRC: &str = include_str!("sca.rs");

        let defined: Vec<&str> = SRC
            .lines()
            .map(str::trim_start)
            .filter_map(|l| {
                // Strip `pub`, `pub(crate)`, `pub(super)`, `pub(in ::path)`.
                let rest = match l.strip_prefix("pub") {
                    Some(r) => match r.strip_prefix('(') {
                        Some(after) => after.split_once(')')?.1,
                        None => r,
                    },
                    None => l,
                };
                // Requiring `fn ` at the START (after visibility) is what keeps this
                // from matching prose: the assertion messages below both contain the
                // text `fn *_argv(`, and a substring search would count them.
                let rest = rest.trim_start().strip_prefix("fn ")?;
                let name = rest
                    .split(|c: char| c == '(' || c == '<' || c.is_whitespace())
                    .next()?;
                if name.ends_with("_argv") {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();

        assert!(
            !defined.is_empty(),
            "found no `fn *_argv` definitions -- this guard has gone vacuous, \
             fix the detection rather than deleting the test"
        );
        assert_eq!(
            defined.len(),
            all_argvs().len(),
            "UNSWEPT BACKEND: this module defines {} argv builder(s) but only {} are \
             passed through the never-execute invariant sweep. Add the new one to \
             `all_argvs()`. An SCA backend whose argv nobody checks is exactly how \
             the pip-audit RCE got in. Defined: {:?}",
            defined.len(),
            all_argvs().len(),
            defined
        );
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
