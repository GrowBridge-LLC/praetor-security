//! Text handling shared by every engine — above all, **what a line is**.
//!
//! 🔴 ONE DEFINITION, AND IT BELONGS TO THE OUTSIDE WORLD.
//!
//! A finding's line number is part of its identity: the differential harness
//! compares `(engine, rule_id, file, line)`, and a human resolves it by opening
//! the file. So the definition of "line" is an interop contract with Semgrep,
//! `grep -n`, `sed`, git, GitHub and every editor — all of which count `\n`.
//!
//! ⚠️ The Python implementation once held **two** definitions at once, and the
//! disagreement was an attacker-controlled suppression primitive. Findings
//! carried `\n`-based numbers while the inline-ignore check resolved them against
//! `str.splitlines()`, which *also* breaks on `\v`, `\f`, `\x1c`-`\x1e`, `\x85`,
//! `U+2028` and `U+2029`. A `U+2028` in a scanned file slid the index until a
//! real finding landed on a line carrying an ignore marker:
//!
//! ```text
//! a<U+2028>b nosec        <- \n-line 1: holds the marker
//! payload<ZWSP>           <- \n-line 2: FLAGGED, and carries no marker
//! ```
//!
//! It reported *"suppressed by inline ignore marker on the flagged line"* for a
//! line that had none. That bug was found **by writing this port** — a green
//! suite, the self-scan and review had all passed straight over it, because a
//! single implementation never has to say out loud which definition it means.
//!
//! ⚠️ An earlier draft of this comment cited "64 passing tests". That was the
//! working tree's count at the moment of discovery, but the work was split into
//! separate commits afterwards, so no commit in history ever shows 64 — a reader
//! re-deriving it would find a different number and reasonably conclude the
//! comment was invented. The number is dropped rather than corrected: it was
//! never the point, and a figure that cannot be reconciled against the repo is
//! worse than no figure.
//!
//! `scripts/core.py::split_lines` is the same function. They are checked against
//! each other on a shared corpus, not merely written to look alike.

/// Split into lines on `\n` only, dropping one trailing `\r` per line.
///
/// ⚠️ **Not `str::lines()`**, though it is very nearly the same. `str::lines()`
/// leaves a lone trailing `\r` at end-of-input in place (`"a\r"` → `["a\r"]`)
/// while the Python side strips it, and a snippet is compared as text elsewhere.
/// Matching exactly is cheap; a "close enough" primitive under a differential
/// harness is a divergence waiting for the one input that reaches it.
///
/// A trailing newline does not produce a final empty line, so `len()` is the
/// number of lines — the same shape Python's `splitlines()` returns.
pub fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<&str> = text.split('\n').collect();
    if parts.last() == Some(&"") {
        parts.pop();
    }
    parts
        .into_iter()
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect()
}

/// The cross-language differential contract, as callable code.
///
/// ⚠️ Deliberately **not** `#[cfg(test)]`, and that is the point of the module.
/// These helpers used to be test-private, which made this crate's verdict
/// unobservable from outside: the only way to learn whether it agreed with the
/// contract was to run the test and believe the exit code. A test that is
/// renamed, `#[ignore]`d or `#[cfg]`-ed away still leaves `cargo test` exiting
/// 0 — so "both suites pass" silently stops meaning "both suites checked". That
/// was demonstrated, not assumed: diverging `split_lines` and marking these two
/// tests `#[ignore]` left `cargo test` reporting "ok. 6 passed; 2 ignored".
///
/// `tests/differential/run_differential.py` compares the two implementations
/// against **each other**, which requires this crate to *emit* its signature
/// rather than merely assert one. The test below and
/// `examples/emit_line_signature.rs` call exactly these functions, so the
/// emitted answer cannot drift from the asserted one.
///
/// The corpus is not embedded here on purpose: both callers `include_str!` it
/// themselves, so a missing or renamed corpus stays a build error on both paths.
pub mod differential {
    /// Pull a `key value` line out of the committed expectation file.
    pub fn expected(expectation: &str, key: &str) -> String {
        expectation
            .split('\n')
            .map(|l| l.trim())
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
            .unwrap_or_else(|| panic!("expectation file has no {key:?} line"))
    }

    /// The corpus's cases, decoded, in file order.
    ///
    /// ⚠️ Returns an ITERATOR, not `Vec<String>`, and that is load-bearing rather
    /// than a style choice. `tests/test_rust_sca_argv_sweep.py` forbids any
    /// production `fn ... -> Vec<String>` outside `sca.rs`: argv construction is
    /// confined to one module so the never-execute sweep can see all of it. The
    /// rule's whole value is that it needs no allowlist and cannot be evaded by
    /// naming, so this complies with it instead of asking for an exception. This
    /// function was `-> Vec<String>` when it was test-private and stripped by the
    /// `#[cfg(test)]` carve-out; promoting it to production code made it visible
    /// to the sweep, correctly.
    ///
    /// Do not "simplify" this back to `Vec<String>` -- the sweep will fail, and it
    /// will be right to.
    pub fn cases(corpus: &str) -> impl Iterator<Item = String> + '_ {
        corpus
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l))
            .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
            .map(unescape)
    }

    /// This crate's answer: `N:line;line;...` per case, cases space-separated.
    ///
    /// The runner compares this string to the Python implementation's and to the
    /// committed expectation. All three must agree.
    ///
    /// ⚠️ Do not recover the cases by splitting the result on `' '` — `escape`
    /// passes a literal space through, and one corpus case contains one.
    pub fn signature(corpus: &str) -> String {
        cases(corpus)
            .map(|c| {
                let lines = super::split_lines(&c);
                let body: Vec<String> = lines.iter().map(|l| escape(l)).collect();
                format!("{}:{}", lines.len(), body.join(";"))
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Decode the corpus escape format: `\n` `\r` `\t` `\\` `\u{XXXX}`.
    ///
    /// Deliberately strict — an unknown escape panics rather than being passed
    /// through. A corpus line that quietly means something other than intended
    /// is worse than one that fails to load.
    pub fn unescape(s: &str) -> String {
        let mut out = String::new();
        let mut it = s.chars();
        while let Some(c) = it.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match it.next().expect("corpus: trailing backslash") {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '\\' => out.push('\\'),
                'u' => {
                    assert_eq!(it.next(), Some('{'), "corpus: \\u must be followed by {{");
                    let hex: String = it.by_ref().take_while(|&c| c != '}').collect();
                    let cp = u32::from_str_radix(&hex, 16)
                        .unwrap_or_else(|_| panic!("corpus: bad hex {hex:?}"));
                    out.push(char::from_u32(cp)
                        .unwrap_or_else(|| panic!("corpus: bad code point U+{cp:04X}")));
                }
                other => panic!("corpus: unknown escape \\{other}"),
            }
        }
        out
    }

    /// Re-escape a produced line back into the corpus's ASCII format.
    ///
    /// 🔴 The signature must carry CONTENT, not just line counts. A counts-only
    /// signature was tried first and a mutation exposed it: swapping this
    /// module's `split_lines` for `str::lines()` changes `"a\r"` from `["a"]` to
    /// `["a\r"]` -- same count, different text -- and the cross-language contract
    /// passed the mutant while only a local unit test caught it. The contract is
    /// meant to be the authority; an authority blind to content is not one.
    pub fn escape(s: &str) -> String {
        let mut out = String::new();
        for c in s.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                ' '..='~' => out.push(c),
                _ => out.push_str(&format!("\\u{{{:04X}}}", c as u32)),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::differential::{cases, expected, signature};
    use super::*;

    /// The shared differential corpus. Compiled in, so a missing or renamed file
    /// is a build error rather than a silently skipped test.
    const CORPUS: &str = include_str!("../../../references/differential/line-splitting.txt");

    /// The committed expectation the Python implementation is held to as well.
    const EXPECTED: &str = include_str!("../../../references/differential/line-splitting.expected");

    /// 🔴 The load-bearing one. Computes the line COUNT for every corpus case and
    /// checks it against the COMMITTED expectation that
    /// `tests/test_line_numbering_consistency.py` is held to as well. A
    /// divergence between the two implementations fails a named test on both
    /// sides, rather than misaligning every ported detector in silence.
    #[test]
    fn signature_matches_the_committed_cross_language_expectation() {
        let cases: Vec<String> = cases(CORPUS).collect();

        // Anti-vacuity: an empty or truncated corpus would otherwise "agree"
        // with anything. The count is itself part of the committed contract.
        let want_cases: usize = expected(EXPECTED, "cases").parse().expect("bad cases count");
        assert_eq!(
            cases.len(),
            want_cases,
            "corpus has {} cases, expectation says {want_cases}. Either the corpus \
             changed (update the expectation deliberately, in the same commit as the \
             reason) or the loader is dropping cases and this test is going vacuous.",
            cases.len()
        );

        // count AND content, per case: `N:line;line;...` -- computed by the same
        // `differential::signature` the emitter calls, so the answer the runner
        // reads is the answer this test asserts.
        assert_eq!(
            signature(CORPUS),
            expected(EXPECTED, "signature"),
            "LINE-DEFINITION DIVERGENCE. This crate's split_lines disagrees with the \
             committed expectation that scripts/core.py::split_lines is also held to. \
             A line number is part of every finding's identity, so this misaligns every \
             ported detector at once. Do NOT regenerate the expectation to make this pass."
        );

        // Spot-anchors, so this test still means something on its own. Each is a
        // case where str::lines()/splitlines() would disagree with us.
        assert_eq!(split_lines("a\u{2028}b").len(), 1, "U+2028 is not a line break");
        assert_eq!(split_lines("a\u{0085}b").len(), 1, "U+0085 is not a line break");
        assert_eq!(split_lines("a\u{000B}b").len(), 1, "U+000B is not a line break");
    }

    #[test]
    fn matches_the_python_definition_on_the_shapes_that_differ() {
        assert_eq!(split_lines(""), Vec::<&str>::new(), "empty input -> no lines");
        assert_eq!(split_lines("a\nb"), vec!["a", "b"]);
        assert_eq!(split_lines("a\nb\n"), vec!["a", "b"], "trailing \\n adds no line");
        assert_eq!(split_lines("alpha\r\nbeta"), vec!["alpha", "beta"], "CRLF: \\r stripped");
        assert_eq!(split_lines("alpha\rbeta"), vec!["alpha\rbeta"], "lone CR is not a break");
        // The case where str::lines() and the Python side disagree.
        assert_eq!(split_lines("a\r"), vec!["a"], "trailing lone CR is stripped, as in Python");
        assert_eq!("a\r".lines().collect::<Vec<_>>(), vec!["a\r"],
                   "premise: str::lines() keeps it, which is why we do not use str::lines()");
    }

    #[test]
    fn the_reproduced_bypass_input_numbers_lines_the_way_a_reviewer_would() {
        // The exact shape that suppressed a real finding in the Python engine.
        // The marker is assembled from parts so this source file does not itself
        // carry a live ignore token -- see CLAUDE.md on test fixtures becoming
        // specimens of the thing under test.
        let marker = concat!("nos", "ec");
        let text = format!("a\u{2028}b {marker}\npayload\u{200B}\n");
        let lines = split_lines(&text);
        assert_eq!(lines.len(), 2, "the file has two \\n-lines, whatever U+2028 suggests");
        assert!(!lines[1].contains(marker),
                "line 2 must NOT carry the ignore marker -- that shift is the bypass");
    }
}
