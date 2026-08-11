#!/usr/bin/env python3
r"""
Generate the Rust port's Unicode tables FROM the Python implementation.

    py -3.14 tools/gen_unicode_tables.py            # write the table
    py -3.14 tools/gen_unicode_tables.py --check    # verify it is current

🔴 WHY THIS EXISTS, AND WHY IT IS NOT AN OPTIMISATION

`scripts/engine_aisec.py` decides two things from Python's Unicode database:

    _WORD_RE  = re.compile(r"[^\W\d_]+", re.UNICODE)   # what counts as a token
    _script_of(ch) -> unicodedata.name(ch).split(" ")[0]   # what script it is in

Rust's standard library has **neither**. It has no Unicode name database and no
`\w` equivalent, and `praetor-core` deliberately carries zero dependencies (a
port of a security tool does not get to widen its own trust surface). So the
Rust side must carry a table -- and a hand-written table is a second, silently
divergent definition of "what is a letter", which is exactly the failure mode
the differential harness exists to prevent.

⚠️ THE DIVERGENCE THIS PREVENTS IS INVISIBLE BY CONSTRUCTION. If Rust's notion
of a word character differs from Python's by one code point, tokenisation
differs, the token boundaries differ, and a mixed-script token can fall out of
scope in one implementation while firing in the other. Nobody reviewing either
file would see it. So the table is GENERATED from the authority (Python's
`unicodedata`) and a test asserts the committed file still matches.

⚠️ THE TABLE IS A SNAPSHOT OF ONE UNICODE VERSION. It records which version it
came from. When Python's bundled `unicodedata` advances, this file goes stale --
and `tests/test_rust_unicode_tables_parity.py` fails, which is the point. Do not
"fix" that failure by editing the .rs file; re-run this generator.

## What is collapsed, deliberately, and what that costs

`_script_of` returns a script name for every code point. The detector only ever
asks two questions of it:

    "LATIN" in scripts            -- is this token partly Latin?
    scripts & _CONFUSABLE_SCRIPTS -- does it mix in a lookalike script?

So this table collapses the whole space to LATIN / the four confusable scripts /
OTHER. That is **behaviourally exact for the fire-or-not decision**, which is
what the differential harness compares.

🔴 It is NOT exact for the finding's *description*, which names each offending
code point via `unicodedata.name()`. Rust cannot reproduce those strings without
a name database. Stated plainly rather than left to be discovered: the harness
compares `(engine, rule_id, file, line)` and therefore **cannot catch
description drift between the two implementations**. That is a real, accepted
gap in the acceptance criterion, not an oversight.
"""

from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from pathlib import Path

# Mirrors engine_aisec._WORD_RE exactly. If that changes, this must change with
# it -- the parity test only proves the .rs file matches THIS file, not that
# this file matches the engine.
WORD_RE = re.compile(r"[^\W\d_]", re.UNICODE)

# Mirrors engine_aisec._CONFUSABLE_SCRIPTS, in a fixed order so the generated
# numeric ids are stable across runs.
CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE")

SCRIPT_IDS = {"OTHER": 0, "LATIN": 1}
for _i, _s in enumerate(CONFUSABLE_SCRIPTS, start=2):
    SCRIPT_IDS[_s] = _i

MAX_CP = 0x110000

OUT_PATH = Path(__file__).resolve().parent.parent / "rust" / "praetor-core" / "src" / "unicode_tables.rs"


def script_of(cp: int) -> str:
    """The exact rule from `engine_aisec._script_of`, by code point.

    Kept byte-for-byte equivalent to the engine's version, including the ASCII
    short-circuit -- ASCII is LATIN even for code points `unicodedata` gives no
    name to (digits and punctuation are excluded later by the word test).
    """
    ch = chr(cp)
    if ch.isascii():
        return "LATIN"
    try:
        prefix = unicodedata.name(ch).split(" ", 1)[0]
    except ValueError:      # unnamed / private-use code point
        return "UNKNOWN"
    if prefix == "LATIN" or prefix in CONFUSABLE_SCRIPTS:
        return prefix
    return "OTHER"


def to_ranges(values) -> list:
    """Collapse a sorted iterable of ints into inclusive (start, end) ranges."""
    ranges = []
    start = prev = None
    for v in values:
        if start is None:
            start = prev = v
        elif v == prev + 1:
            prev = v
        else:
            ranges.append((start, prev))
            start = prev = v
    if start is not None:
        ranges.append((start, prev))
    return ranges


def collect() -> tuple:
    word_cps = []
    script_cps = []          # (cp, script_id) for anything that is not OTHER
    for cp in range(MAX_CP):
        ch = chr(cp)
        if WORD_RE.fullmatch(ch):
            word_cps.append(cp)
        s = script_of(cp)
        if s in SCRIPT_IDS and s != "OTHER":
            script_cps.append((cp, SCRIPT_IDS[s]))

    word_ranges = to_ranges(word_cps)

    # Script ranges must not merge across differing ids.
    script_ranges = []
    for sid in sorted(set(i for _, i in script_cps)):
        for lo, hi in to_ranges([cp for cp, i in script_cps if i == sid]):
            script_ranges.append((lo, hi, sid))
    script_ranges.sort()
    return word_ranges, script_ranges


def fmt_ranges(rows, per_line: int) -> str:
    out, buf = [], []
    for r in rows:
        buf.append("(" + ", ".join(f"0x{v:04X}" if isinstance(v, int) and v > 9 else str(v) for v in r[:2])
                   + (f", {r[2]}" if len(r) == 3 else "") + ")")
        if len(buf) == per_line:
            out.append("    " + ", ".join(buf) + ",")
            buf = []
    if buf:
        out.append("    " + ", ".join(buf) + ",")
    return "\n".join(out)


def render() -> str:
    word_ranges, script_ranges = collect()
    consts = "\n".join(
        f"pub const SCRIPT_{name}: u8 = {sid};"
        for name, sid in sorted(SCRIPT_IDS.items(), key=lambda kv: kv[1])
    )
    return f"""//! GENERATED FILE -- DO NOT EDIT BY HAND.
//!
//! Produced by `tools/gen_unicode_tables.py` from Python's `unicodedata`
//! {unicodedata.unidata_version}, which is the authority the Python engine uses. Regenerate with:
//!
//! ```text
//! py -3.14 tools/gen_unicode_tables.py
//! ```
//!
//! 🔴 Editing this file by hand creates a second, divergent definition of "what
//! is a letter" and "what script is this" -- the precise class of drift the
//! differential harness exists to catch and the one it would be blind to,
//! because both implementations would agree with each other and disagree with
//! Unicode. `tests/test_rust_unicode_tables_parity.py` fails if this file stops
//! matching the generator. Do not silence that test by editing here.
//!
//! See the generator's module docstring for what is collapsed and what that
//! costs -- notably that the finding *description* cannot be reproduced from
//! this table, and the harness does not compare descriptions.

/// The Unicode version these tables were derived from. Recorded so a mismatch
/// is diagnosable rather than mysterious.
pub const UNICODE_VERSION: &str = "{unicodedata.unidata_version}";

{consts}

/// Code points matching Python's `[^\\W\\d_]` -- letters, excluding digits and
/// underscore. Inclusive `(start, end)` pairs, sorted, non-overlapping.
pub static WORD_RANGES: &[(u32, u32)] = &[
{fmt_ranges(word_ranges, 6)}
];

/// Code points whose script is Latin or one of the confusable scripts.
/// Inclusive `(start, end, script_id)`, sorted by start, non-overlapping.
/// Anything absent is `SCRIPT_OTHER`.
pub static SCRIPT_RANGES: &[(u32, u32, u8)] = &[
{fmt_ranges(script_ranges, 5)}
];
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if the committed file is not what this generator produces")
    args = ap.parse_args()

    text = render()
    if args.check:
        if not OUT_PATH.exists():
            print(f"MISSING: {OUT_PATH}", file=sys.stderr)
            return 1
        current = OUT_PATH.read_text(encoding="utf-8")
        if current != text:
            print(f"STALE: {OUT_PATH} does not match the generator output.\n"
                  f"Unicode version now {unicodedata.unidata_version}. "
                  f"Re-run: py -3.14 tools/gen_unicode_tables.py", file=sys.stderr)
            return 1
        print(f"OK: {OUT_PATH.name} is current (Unicode {unicodedata.unidata_version})")
        return 0

    OUT_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {OUT_PATH} (Unicode {unicodedata.unidata_version}, "
          f"{text.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
