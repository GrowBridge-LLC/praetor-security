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
    property structurally instead: every first-level Python program in ``scripts/``
    is covered, so a newly added engine cannot escape through a hand-maintained
    filename tuple. Every discovered file is scanned unless it is explicitly named
    with a reason below; there are currently no such exclusions.

    ``core.py`` is covered too. Its one direct call is the implementation of
    ``core.run_tool`` itself, sanctioned by its exact source line rather than by
    excluding the whole file. Moving or duplicating that call fails this test for
    a deliberate review of the boundary.

    Deliberately a source-level guard rather than an assertion about run_tool's
    keyword arguments -- a test that checks a setting cannot notice the setting
    being bypassed by a NEW call site, which is exactly how this arrived.

    Limits, stated rather than implied exhaustive: this catches only the literal
    ``subprocess.run(...)`` AST form in first-level ``scripts/*.py``.
    It cannot see aliased/dynamic calls, ``Popen`` or other subprocess APIs,
    extensionless or nested scripts, generated code, or calls in dependencies.
    Those boundaries need separate guards if they enter PRAETOR's subprocess path.
    """
    root = pathlib.Path(__file__).resolve().parent.parent
    scripts = root / "scripts"
    discovered = sorted(scripts.glob("*.py"))
    relpaths = {path.relative_to(root).as_posix() for path in discovered}

    # An explicit out-of-scope entry must name why it is safe to omit. Empty today
    # is intentional: every first-level Python program participates in this guard.
    out_of_scope = {}
    assert set(out_of_scope).issubset(relpaths), (
        "an out-of-scope entry no longer names a discovered scripts/*.py file: "
        + repr(sorted(set(out_of_scope) - relpaths))
    )
    scanned_paths = relpaths - set(out_of_scope)
    assert scanned_paths | set(out_of_scope) == relpaths, (
        "every discovered scripts/*.py file must be scanned or explicitly named "
        "out of scope with a reason"
    )
    assert len(scanned_paths) >= 10, (
        "anti-vacuity floor: expected the current scripts/*.py program surface; "
        f"scanned={sorted(scanned_paths)}"
    )

    # The one permitted direct call is the wrapper itself. This is a line-level
    # exception: a second call in core.py is still an offender.
    sanctioned = {("scripts/core.py", 152): "core.run_tool implementation"}
    sanctioned_seen = set()
    offenders = []
    for path in discovered:
        rel = path.relative_to(root).as_posix()
        if rel in out_of_scope:
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=rel)
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "run"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
            ):
                continue
            location = (rel, node.lineno)
            if location in sanctioned:
                sanctioned_seen.add(location)
                continue
            line = core.split_lines(source)[node.lineno - 1].strip()
            offenders.append(f"{rel}:{node.lineno}: {line}")

    assert sanctioned_seen == set(sanctioned), (
        "the line-specific core.run_tool exemption moved or disappeared; review "
        f"the subprocess boundary. expected={sanctioned}, seen={sanctioned_seen}"
    )
    assert not offenders, (
        "a scripts/*.py program calls subprocess.run directly. Use core.run_tool: "
        "a bare `text=True` decodes with the LOCALE codec, and the scanned tree "
        "supplies the bytes. Offenders:\n  " + "\n  ".join(offenders)
    )
