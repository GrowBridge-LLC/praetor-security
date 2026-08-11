r"""
Every argv builder in the Rust crate reaches the never-execute invariant sweep.

🔴 THIS GUARDS THE INVARIANT THAT OUTRANKS EVERYTHING: PRAETOR NEVER EXECUTES,
IMPORTS, INSTALLS OR BUILDS THE CODE IT SCANS.

## Why this test is in Python, guarding Rust

`rust/praetor-core/src/sca.rs` carries its own in-file sweep counter. It has now
failed an audit **twice**, and the second failure is the reason this file exists:

1. It filtered source lines on the literal prefix `pub fn `, so a `pub(crate) fn`
   builder returning `install` passed with every test green.
2. The repair matched on the function *name* ending in `_argv` and read its own
   source with `include_str!("sca.rs")`. A third audit then defeated *that* three
   more ways, all confirmed by mutation:
     - a builder simply **not named** `*_argv` (`npm_command`) -- invisible;
     - a builder in a **different file** (`npm.rs`) containing the literal
       `"install"` -- the whole suite stayed green, because `include_str!` reads
       exactly one file and can never read a file that does not exist yet;
     - an **attribute sharing the line** (`#[allow(dead_code)] pub fn x_argv(`) --
       the prefix logic required `fn` to be the first token.

⇒ The Rust test cannot fix the cross-file hole **in principle**: `include_str!`
takes a literal path, and enumerating the directory at compile time would need a
`build.rs`, which this crate deliberately refuses because it runs code at build
time. Python can simply read the directory. That is the whole reason for the
language split -- not preference.

## What "an argv builder" means here, and why not by name

Detection keys on the **signature** -- a function returning `Vec<String>` -- not on
a naming convention. A name is a promise a contributor can forget to make; a
return type is what the code actually is. This is the same lesson as the two
failures above: **the guard must key on the property, never on the spelling.**

## Known limits, stated because an incomplete gap list reads as exhaustive

- **Macro-generated builders are invisible.** They are not source text. If one is
  ever added, this guard must be replaced, not trusted.
- **`#[cfg(test)]` modules are excluded** -- see `_strip_cfg_test_modules` for the
  reasoning and its cost. A builder hidden in a test module is not detected.
- A builder that returns something other than `Vec<String>` (a newtype, a
  `Command`, an iterator) is not detected. Adding such a shape means extending
  `_ARGV_SIGNATURE` in the same change.
- This is a **textual** check over Rust source, not a parse. It strips comment
  lines before matching, but it is not a tokeniser and does not understand string
  literals.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CRATE_SRC = REPO / "rust" / "praetor-core" / "src"

# The one file argv construction is allowed to live in. Anything elsewhere is a
# finding, because the never-execute sweep is defined over this module.
SCA = "sca.rs"

# `fn NAME(...) -> Vec<String>`, tolerating generics, attributes earlier on the
# line, any visibility, and a signature broken across lines. `Vec<Vec<String>>`
# (the shape of `all_argvs` itself) deliberately does NOT match.
_ARGV_SIGNATURE = re.compile(
    r"(?<![\w:])fn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\([^;{]*?\)\s*->\s*Vec\s*<\s*String\s*>",
    re.DOTALL,
)


def _strip_cfg_test_modules(src: str) -> str:
    r"""Remove `#[cfg(test)] mod ... { ... }` blocks before looking for builders.

    🔴 THE CARVE-OUT, STATED RATHER THAN SILENT, because this project's rules
    require it: a `#[cfg(test)]` item is **not compiled into the shipped binary**,
    so it cannot construct an argv that PRAETOR ever runs. That is a real
    structural property of the build, not a path heuristic -- the distinction this
    codebase got wrong once before by suppressing on directory alone.

    ⚠️ It is still a carve-out, and it has a cost: a builder hidden inside a test
    module is invisible here. That is accepted deliberately, because such a
    function is unreachable from the scanner. If Rust test code ever becomes
    reachable at runtime, this narrowing is wrong and must go.

    `all_argvs()` itself lives in the test module, which is why the membership
    check below reads the UNSTRIPPED source -- the builders are production code,
    the list that sweeps them is test code.

    ⚠️ **Brace counting does not work here and was tried first.** `text.rs`
    contains `\u{2028}`-style escapes inside string literals, so the raw `{`/`}`
    counts in that file are 36 vs 34 -- a naive matcher never balances, silently
    strips nothing, and the guard reports a false positive on a test helper. This
    keys on line structure instead: a top-level `#[cfg(test)]` sits at column 0 and
    rustfmt closes its module with a `}` at column 0. Braces inside strings are
    invisible to that, which is the point.
    """
    lines = src.split("\n")
    out = []
    skipping = False
    for line in lines:
        if not skipping:
            if line.rstrip() == "#[cfg(test)]":
                skipping = True
                continue
            out.append(line)
        elif line.rstrip() == "}":
            # Column-0 close: the test module has ended.
            skipping = False
    return "\n".join(out)


def _strip_comment_lines(src: str) -> str:
    """Drop whole-line comments so prose cannot be mistaken for a definition.

    Deliberately conservative: only lines whose first non-space characters are
    `//` are removed. A trailing comment on a code line is left alone, because
    stripping it correctly requires knowing where string literals end.
    """
    kept = []
    for line in src.split("\n"):
        if line.lstrip().startswith("//"):
            continue
        kept.append(line)
    return "\n".join(kept)


def _builders_in(src: str):
    """Argv builders in PRODUCTION code only -- see `_strip_cfg_test_modules`."""
    return _ARGV_SIGNATURE.findall(
        _strip_comment_lines(_strip_cfg_test_modules(src))
    )


def _rust_sources():
    files = sorted(CRATE_SRC.glob("*.rs"))
    assert files, (
        f"no .rs files found under {CRATE_SRC} -- this guard has gone vacuous. "
        f"Fix the path, do not delete the test."
    )
    return files


def _all_argvs_body(src: str) -> str:
    """The text of `fn all_argvs()`, by brace matching from its opening `{`."""
    m = re.search(r"fn\s+all_argvs\s*\(", src)
    assert m, (
        "could not find `fn all_argvs(` in sca.rs. If the sweep list was renamed, "
        "update this test; if it was DELETED, the never-execute sweep has no "
        "membership list and that is the finding."
    )
    start = src.index("{", m.end())
    depth = 0
    for i in range(start, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start : i + 1]
    raise AssertionError("unbalanced braces in `all_argvs` -- cannot verify the sweep")


def test_no_argv_builder_lives_outside_sca_rs():
    """A builder in another file is swept by nothing. This is the cross-file hole.

    An auditor added `rust/praetor-core/src/npm.rs` with a `Vec<String>` builder
    containing the literal "install" -- a flag that lets a package manager resolve
    and BUILD from the scanned tree -- and the entire suite stayed green.
    """
    offenders = {}
    for path in _rust_sources():
        if path.name == SCA:
            continue
        found = _builders_in(path.read_text(encoding="utf-8"))
        if found:
            offenders[path.name] = found

    assert not offenders, (
        f"ARGV BUILDER OUTSIDE {SCA}: {offenders}\n\n"
        f"The never-execute invariant sweep is defined over {SCA} and cannot see "
        f"these. An SCA backend whose argv nobody checks is exactly how the "
        f"pip-audit RCE got in.\n\n"
        f"Move the builder into {SCA} and add it to `all_argvs()`."
    )


def test_every_argv_builder_in_sca_rs_is_in_the_sweep_list():
    """Set membership, not a count.

    The Rust-side check compares COUNTS, which is a proxy: two errors that cancel
    would satisfy it. This asserts each builder is actually named in `all_argvs()`.
    """
    src = (CRATE_SRC / SCA).read_text(encoding="utf-8")
    builders = _builders_in(src)

    assert len(builders) >= 2, (
        f"found {len(builders)} argv builder(s) in {SCA}; expected at least the "
        f"pip-audit and osv-scanner pair. This guard has gone vacuous -- fix the "
        f"detection rather than deleting the test."
    )

    body = _all_argvs_body(src)
    unswept = [name for name in builders if name not in body]

    assert not unswept, (
        f"UNSWEPT BACKEND(S): {unswept}\n\n"
        f"{SCA} defines these argv builders but `all_argvs()` does not call them, "
        f"so `no_sca_argv_can_resolve_build_or_install` never inspects their output. "
        f"Add them to `all_argvs()`.\n\n"
        f"Detected builders: {builders}"
    )


def test_the_known_builders_are_actually_detected():
    """Anti-vacuity in the other direction.

    If the signature regex silently stopped matching, both tests above would pass
    by finding nothing. Name the builders that must always be found.
    """
    builders = set(_builders_in((CRATE_SRC / SCA).read_text(encoding="utf-8")))

    for expected in ("pip_audit_argv", "osv_scanner_argv"):
        assert expected in builders, (
            f"`{expected}` was not detected by the argv-signature regex, but it is "
            f"defined in {SCA}. The DETECTION is broken, which means the two tests "
            f"above are passing vacuously. Fix `_ARGV_SIGNATURE`."
        )
