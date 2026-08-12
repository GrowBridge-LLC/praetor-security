r"""
ONE DEFINITION OF A LINE -- and why disagreeing about it is a suppression bypass.

PRAETOR used two incompatible definitions at once. Findings carry `\n`-based line
numbers (Semgrep's contract, and what `_scan_unicode` counts), while the inline
ignore check, the lexical-context labeller and the snippet lookups resolved those
numbers against Python's `str.splitlines()` -- which ALSO breaks on `\v`, `\f`,
`\x1c`-`\x1e`, `\x85`, `U+2028` and `U+2029`.

🔴 THE CONSEQUENCE IS NOT COSMETIC. The scanned file is attacker-controlled, so
the attacker controls the shift. Putting `U+2028` earlier in the file slides the
index until the flagged finding lands on a line carrying an ignore marker:

    a<U+2028>b nosec        <- \n-line 1: holds the marker
    payload<ZWSP>           <- \n-line 2: FLAGGED, and carries no marker

PRAETOR reported *"suppressed by inline ignore marker on the flagged line"* for a
line that had no marker on it. A reviewer opening line 2 sees nothing to explain
the silence. That is precisely the CLAUDE.md class: *a classifier that fails
toward suppression is a scanner that goes quiet under exactly the conditions an
attacker creates.*

⚠️ THIS FILE MUST TEST BOTH DIRECTIONS. Deleting the inline-ignore feature
outright would also close the bypass, and would look identical to a fix from
outside. So the marker must still work when it genuinely sits on the flagged
line -- otherwise this suite would bless a scanner that ignores its own
documented suppression mechanism.

⚠️ Fixtures use `chr()` and assembled marker strings. A literal `U+2028` is
invisible in a diff (that is the whole point of the attack), and a literal
`nosec` in a test file is itself a specimen -- see CLAUDE.md on writing tests for
a detector adding noise to that detector.
"""

import core
import lexctx
import praetor

_LS = chr(0x2028)      # LINE SEPARATOR      -- splitlines() breaks here, \n does not
_PS = chr(0x2029)      # PARAGRAPH SEPARATOR -- ditto
_NEL = chr(0x0085)     # NEXT LINE           -- ditto
_VT = chr(0x000B)      # LINE TABULATION     -- ditto
_ZWSP = chr(0x200B)    # ZERO WIDTH SPACE    -- the payload aisec flags
_NL = chr(0x000A)

# Assembled so this file is not itself a suppression specimen.
# ⚠️ CARRIES ITS COMMENT INTRODUCER, and must keep carrying it.
#
# This was a bare `nosec` token. On 2026-08-12 the ignore marker was narrowed to
# whole-word-inside-an-actual-comment, because the bare-substring form let a JSON
# key named "nosec_note" suppress a real credential -- a suppression the SCANNED
# TREE could trigger. A bare token in code is no longer a marker.
#
# 🔴 Both tests below need the `#`, for OPPOSITE reasons. The keep-direction test
# fails without it. The bypass test would still PASS without it -- VACUOUSLY,
# because a bare token cannot suppress from any line, so it would no longer
# exercise the line-shift bypass it exists to pin.
_MARK = "# nos" + "ec"


# --------------------------------------------------------------------------- #
# core.split_lines -- the definition itself
# --------------------------------------------------------------------------- #

def test_split_lines_ignores_the_exotic_breaks_that_splitlines_honours():
    """The whole point: these characters are NOT line breaks to any other tool."""
    for exotic in (_LS, _PS, _NEL, _VT):
        text = "a" + exotic + "b"
        assert core.split_lines(text) == [text], (
            f"split_lines treated U+{ord(exotic):04X} as a line break; it must not. "
            f"Semgrep, grep -n, sed, git and every editor count \\n only."
        )
        # Guards the fixture: if this stops holding, Python changed and the
        # divergence this module exists to reconcile has moved.
        assert len(text.splitlines()) == 2, (
            f"str.splitlines() no longer splits on U+{ord(exotic):04X} -- this test's "
            f"premise is stale, re-derive it rather than deleting the test."
        )


def test_split_lines_counts_newlines_the_way_editors_do():
    assert core.split_lines("a" + _NL + "b") == ["a", "b"]
    assert core.split_lines("a" + _NL + "b" + _NL) == ["a", "b"], "trailing \\n adds no line"
    assert core.split_lines("") == []
    assert core.split_lines("solo") == ["solo"]


def test_split_lines_strips_the_cr_of_a_crlf_file_without_changing_the_count():
    """A \\n-only split would otherwise leave \\r glued to every line."""
    text = "alpha" + chr(0x0D) + _NL + "beta" + chr(0x0D) + _NL
    assert core.split_lines(text) == ["alpha", "beta"]


def test_split_lines_keeps_a_lone_cr_because_it_is_not_a_break_here():
    """Old-Mac CR line endings are not \\n, so they are not breaks. Stated, not implied."""
    text = "alpha" + chr(0x0D) + "beta"
    assert core.split_lines(text) == [text]


# --------------------------------------------------------------------------- #
# THE BYPASS -- must stay closed
# --------------------------------------------------------------------------- #

def _one_finding(line):
    """A minimal stand-in for a real finding at a \\n-based line number."""
    return core.Finding(engine="aisec", rule_id="invisible-unicode",
                        title="t", severity=core.Severity.MEDIUM,
                        file="evil.txt", line=line)


def test_ignore_marker_on_an_unrelated_line_cannot_suppress_a_finding():
    r"""
    THE REGRESSION. `U+2028` shifts splitlines() indexing so \n-line 2 resolves
    to the marker-bearing text. It must not suppress.
    """
    text = "a" + _LS + "b " + _MARK + _NL + "payload" + _ZWSP + _NL

    # The premise, asserted rather than assumed: the two definitions really do
    # disagree on this input, so a passing test below means something.
    assert text.splitlines()[1] != core.split_lines(text)[1], (
        "fixture no longer triggers the divergence -- this test would pass vacuously"
    )
    assert _MARK in text.splitlines()[1], "fixture: splitlines() must land on the marker"
    assert _MARK not in core.split_lines(text)[1], "fixture: the real line 2 must be clean"

    findings = [_one_finding(2)]
    praetor._apply_inline_ignores(findings, "/target", lambda _p: text)

    assert not findings[0].filtered, (
        "SUPPRESSION BYPASS: a finding was filtered by an ignore marker sitting on a "
        "DIFFERENT line. An attacker controls the scanned file, so they control this "
        f"shift. filter_reason was: {findings[0].filter_reason!r}"
    )


def test_a_real_ignore_marker_on_the_flagged_line_still_suppresses():
    """
    THE KEEP DIRECTION. Deleting inline-ignore support entirely would also close
    the bypass above and is not the fix.
    """
    text = "clean line" + _NL + "payload " + _MARK + _NL
    findings = [_one_finding(2)]
    praetor._apply_inline_ignores(findings, "/target", lambda _p: text)

    assert findings[0].filtered, (
        "the inline ignore marker stopped working on the line it actually annotates -- "
        "the bypass fix must not disable the documented suppression mechanism"
    )


# --------------------------------------------------------------------------- #
# The same shift against lexical context -- a second suppression path
# --------------------------------------------------------------------------- #

def test_lexical_labels_line_up_with_newline_based_line_numbers():
    r"""
    `classify_lines` output is indexed BY LINE NUMBER by the caller (see
    `lexctx.context_of`, which returns `labels[lineno - 1]`), and callers
    suppress on the label. A shift here relabels live code as a comment.
    """
    text = "# a comment" + _LS + "# another comment" + _NL + "run_payload()" + _NL

    labels = lexctx.classify_lines(text)
    assert len(labels) == 2, (
        f"classify_lines produced {len(labels)} labels for a 2-line file; it is splitting "
        f"on something other than \\n, so every label is offset from its line number"
    )
    assert labels[1] == lexctx.CODE, (
        "live code was labelled %r because the line indexing shifted -- suppression "
        "keyed on this label would silently drop a real finding" % (labels[1],)
    )


# --------------------------------------------------------------------------- #
# CROSS-LANGUAGE: the Rust port must agree, and be MADE to agree
# --------------------------------------------------------------------------- #

# The Python side of the cross-language signature lives in the differential
# runner, and is imported rather than copied. A second copy of escape/unescape
# here would be this file's own subject matter turned against it: two definitions
# of the corpus format, drifting apart exactly as the two definitions of a line
# once did. conftest.py puts tests/differential on sys.path.
import run_differential


def test_signature_matches_the_committed_cross_language_expectation():
    r"""
    🔴 THE CROSS-LANGUAGE CONTRACT. The Rust port computes this same signature
    from this same corpus and asserts it against this same file
    (`rust/praetor-core/src/text.rs`). Two suites that each check "does my
    implementation match my own expectation" prove nothing about each other.

    ⚠️ AND THAT IS WHY THIS TEST IS NOT THE GATE. Two assertions against one file
    only compare the implementations while BOTH actually run, and nothing here can
    observe whether the Rust one did. Diverging the Rust `split_lines` and marking
    its two tests `#[ignore]` leaves `cargo test` reporting "ok. 6 passed;
    2 ignored" -- green, with the ports disagreeing. `tests/differential/
    run_differential.py` makes the Rust crate EMIT its signature and compares the
    two directly; `tests/precommit.sh` runs it. This test remains the fast,
    toolchain-free half.

    ⚠️ Do NOT regenerate the expectation to make this pass -- that is the same
    move as regenerating SELF-SCAN-BASELINE.json to reflect an improvement.
    """
    cases = run_differential.corpus_cases()

    want_cases = int(run_differential.expected("cases"))
    assert len(cases) == want_cases, (
        f"corpus has {len(cases)} cases, expectation says {want_cases}. Either the corpus "
        f"changed deliberately, or the loader is dropping cases and this test is vacuous."
    )

    assert run_differential.python_signature() == run_differential.expected("signature"), (
        "LINE-DEFINITION DIVERGENCE between scripts/core.py and the committed "
        "expectation the Rust port is also held to. A line number is part of every "
        "finding's identity, so this misaligns every ported detector at once."
    )


# --------------------------------------------------------------------------- #
# No site may quietly reintroduce the second definition
# --------------------------------------------------------------------------- #

def test_no_line_number_site_uses_str_splitlines():
    r"""
    A grep-style guard. It is coarse on purpose: the bug was not one wrong line
    but ONE MISSING SHARED DEFINITION, and the next instance will arrive as a new
    call site rather than an edit to a fixed one.

    Non-line-number uses of `splitlines()` (parsing a subprocess's stderr, a tool
    version banner, static help text) are legitimate and listed explicitly --
    adding to that list is a decision, which is the point.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    allowed = {
        # (file, fragment that must appear on the line) -- none of these map text
        # from a SCANNED file onto a line number.
        ("scripts/engine_sast.py", "semgrep "),        # version banner
        ("scripts/engine_sast.py", "r.stderr"),        # stderr tail
        ("scripts/engine_sca.py", "r.stderr"),         # stderr tail
        ("scripts/report.py", "LIMITS_TEXT"),          # static help text
        ("tools/classify_baseline.py", "__doc__"),     # this tool's own usage line
    }
    offenders = []
    scanned = 0
    for rel in ("scripts/praetor.py", "scripts/lexctx.py", "scripts/core.py",
                "scripts/engine_sast.py", "scripts/engine_secrets.py",
                "scripts/engine_aisec.py", "scripts/engine_sca.py", "scripts/report.py",
                # The baseline classifier resolves a finding's line number against
                # source too, and it assigns the SUPPRESSION PREDICATE -- a shift
                # here misclassifies the artifact the whole FP argument rests on.
                "tools/classify_baseline.py"):
        path = root / rel
        assert path.exists(), f"guard points at a file that does not exist: {rel}"
        scanned += 1
        for n, line in enumerate(core.split_lines(path.read_text(encoding="utf-8")), 1):
            if ".splitlines()" not in line:
                continue
            # A whole-line `#` comment cannot call anything, and the comments
            # warning against `str.splitlines()` naturally contain it. Narrowing
            # the guard's scope, NOT relaxing the rule -- the same move as fixing
            # a detector's fixtures rather than exempting its own source.
            if line.lstrip().startswith("#"):
                continue
            # 🔴 NOT a blanket exemption for core.py. An earlier version skipped
            # the whole file "because its docstring names it", and an independent
            # audit proved that hole by adding a real `.splitlines()` call to
            # `redact_line` -- the guard stayed green. core.py is the file that
            # OWNS line semantics, so it is the last place that should be exempt.
            #
            # Only the prose references survive, and they are identifiable: the
            # docstring writes `str.splitlines()` (the thing being warned about),
            # while an accidental call reads `text.splitlines()` / `line.splitlines()`.
            if rel == "scripts/core.py" and "str.splitlines" in line:
                continue
            if any(rel == a_rel and frag in line for a_rel, frag in allowed):
                continue
            offenders.append(f"{rel}:{n}: {line.strip()}")

    # Anti-vacuity: a guard that silently scanned nothing passes forever. A
    # renamed or moved file must fail here, not quietly stop being covered.
    assert scanned == 9, f"guard scanned {scanned} files, expected 9 -- coverage moved"

    assert not offenders, (
        "str.splitlines() reintroduced where a line number is produced or resolved. "
        "Use core.split_lines -- str.splitlines also breaks on U+2028/U+2029/NEL/VT, "
        "which no other tool in the chain does, and the disagreement is a suppression "
        "primitive. Offenders:\n  " + "\n  ".join(offenders)
    )
