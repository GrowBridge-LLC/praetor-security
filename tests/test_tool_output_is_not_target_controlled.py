"""
ONE TYPOGRAPHIC QUOTE COULD SWITCH OFF AN ENGINE.

MEASURED 2026-08-12, while investigating why this repo's own SAST engine was
reporting `[error]`. Every engine called:

    subprocess.run(..., capture_output=True, text=True)      # no encoding=

`text=True` alone decodes with the LOCALE codec -- cp1252 on a stock Windows
install -- and cp1252 leaves five bytes UNDEFINED: 0x81 0x8D 0x8F 0x90 0x9D.

Semgrep and osv-scanner embed SNIPPETS AND PATHS FROM THE SCANNED TREE in their
JSON. Those bytes therefore arrive from the thing being scanned.

    U+201D  ”  RIGHT DOUBLE QUOTATION MARK  ->  E2 80 9D     undecodable
    U+201C  “  LEFT  DOUBLE QUOTATION MARK  ->  E2 80 9C     harmless

A single right double quote -- in a docstring, a README, anything pasted out of
a word processor -- was enough. Its mirror was fine. Nothing about that
asymmetry is discoverable from the failure.

--------------------------------------------------------------------------- #
WHY IT DID NOT LOOK LIKE AN ENCODING BUG

The decode does not raise at the call site. It happens on subprocess's READER
THREAD, so `run` returns a CompletedProcess with **stdout=None** and prints an
unhandled-thread traceback to stderr. The engine's next statement was
`r.stdout.strip()`, outside its own try block, and the AttributeError surfaced
through the caller's broad handler as:

    [error] sast  'NoneType' object has no attribute 'strip'

which names nothing that leads a reader here.

⇒ ANY TREE COULD DISABLE PRAETOR'S SAST ENGINE AT WILL, and before the
exit-code gate landed on 2026-08-12 an engine that did not measure returned
exit 0 -- a false clean, chosen by the target. The gate contains the blast
radius to "degraded"; this removes the primitive.

📌 The same decode error hit the tooling used to diagnose it, twice, before it
was recognised. A defect in a shared assumption does not announce which layer
it is in.
"""

import ast
import pathlib
import subprocess
import sys

import core


def test_tool_output_is_decoded_as_utf8_not_the_locale_codec():
    """The bytes that broke it, through the real helper the engines now use.

    ⚠️ SCOPE, stated because a green run elsewhere is not proof: this is decisive
    on a non-UTF-8 locale -- Windows cp1252, where the defect was found and
    lives. Where the ambient locale is already UTF-8 it degenerates to a smoke
    test, so `test_no_engine_calls_subprocess_run_directly` below is the guard
    that holds on every platform.
    """
    payload = "K=”v”"
    helper = "import sys; sys.stdout.buffer.write({!r}.encode('utf-8'))".format(payload)

    r = core.run_tool([sys.executable, "-c", helper], timeout=60)

    assert r.stdout is not None, (
        "stdout came back None: the decode failed on subprocess's reader thread "
        "and `run` returned anyway. The caller's next `.strip()` raises an "
        "AttributeError naming nothing, and the engine reports a bare error."
    )
    assert payload in r.stdout, (
        f"tool output was mangled by the locale codec: {r.stdout!r}. A finding's "
        "snippet is diagnostic text -- it must survive, and it must never be able "
        "to take the run down."
    )


def test_undecodable_bytes_do_not_take_the_run_down():
    """errors='replace', not 'strict'. A tool may emit genuinely invalid UTF-8;
    losing one snippet to mojibake is right, losing every finding is not.

    This is the fail-safe direction for a DECODER, and it is the opposite of the
    fail-safe direction for a classifier: unproven text degrades, unproven
    findings are KEPT. Both choices preserve findings.
    """
    helper = "import sys; sys.stdout.buffer.write(b'ok:\\xff\\xfe:end')"

    r = core.run_tool([sys.executable, "-c", helper], timeout=60)

    assert r.stdout is not None and "ok:" in r.stdout and ":end" in r.stdout, (
        f"invalid UTF-8 anywhere in a tool's output discarded the whole run: {r.stdout!r}"
    )


def test_no_engine_calls_subprocess_run_directly():
    """THE ENFORCEMENT, and it holds on every platform.

    The behavioural test above cannot fail on a UTF-8 box, so on its own it would
    let this defect back in through any CI that is not Windows. This asserts the
    property structurally instead: every engine subprocess goes through
    `core.run_tool`, which fixes the encoding in one place.

    Deliberately a source-level guard rather than an assertion about run_tool's
    keyword arguments -- a test that checks a setting cannot notice the setting
    being bypassed by a NEW call site, which is exactly how this arrived.
    """
    root = pathlib.Path(__file__).resolve().parent.parent
    required = {
        "scripts/engine_sast.py",
        "scripts/engine_sca.py",
        "scripts/engine_secrets.py",
        "scripts/engine_aisec.py",
        "scripts/praetor.py",
    }
    allowed_calls = {("scripts/core.py", 152)}
    offenders = []
    scanned = set()
    for path in sorted((root / "scripts").glob("*.py")):
        rel = path.relative_to(root).as_posix()
        scanned.add(rel)
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=rel)
        lines = core.split_lines(source)
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr == "run"
            ):
                continue
            if (rel, node.lineno) in allowed_calls:
                continue
            offenders.append(f"{rel}:{node.lineno}: {lines[node.lineno - 1].strip()}")

    # Anti-vacuity: a guard that silently scanned nothing passes forever.
    assert len(scanned) >= len(required), (
        f"guard scanned only {len(scanned)} files; expected at least {len(required)}"
    )
    missing = required - scanned
    assert not missing, f"guard missed required engine files: {sorted(missing)}"
    assert not offenders, (
        "an engine calls subprocess.run directly. Use core.run_tool: a bare "
        "`text=True` decodes with the LOCALE codec, and the scanned tree supplies "
        "the bytes. Offenders:\n  " + "\n  ".join(offenders)
    )
