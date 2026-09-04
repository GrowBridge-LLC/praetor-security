"""
The source itself must be well-formed, not merely importable.

🔴 WHY THIS FILE EXISTS. An edit wrote a literal NUL byte into `scripts/core.py`.
Stripping it left this line:

    if len(data) < 16 or b"" not in data:

`b"" in x` is True for every bytes object, so `b"" not in x` is always False. The
guard silently degraded to a bare length check. **The module imported. Every test
passed. The gate was green.** Only reading the raw bytes found it.

That is the lesson worth generalising: *importability is not integrity*. Python
will happily compile a file that a bad edit has changed the meaning of, and a
test suite only covers the behaviour someone thought to assert.

Two checks below, each catching one half of what happened:
  1. no tracked source carries a control byte that has no business in text;
  2. no membership test compares against an EMPTY literal, which is the shape a
     stripped byte leaves behind and which is always-True or always-False.
"""

import ast
import pathlib
import subprocess

_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Control bytes that never legitimately appear in this project's text sources.
#: TAB, LF and CR are excluded -- they are ordinary. Everything else in the C0
#: range, plus DEL, is corruption or a smuggling attempt, and this repository's
#: own `aisec` engine treats several of them as HIDDEN_CONTENT findings when it
#: sees them in a SCANNED tree. Holding its own source to the same standard is
#: the least it can do.
_FORBIDDEN_BYTES = bytes(
    b for b in range(0x00, 0x20) if b not in (0x09, 0x0A, 0x0D)
) + b"\x7f"

#: Files exempt from the byte check, by tracked path. Deliberately a path list
#: and deliberately empty: a corpus of deliberately hostile fixtures would belong
#: here, and today every such fixture is GENERATED at test time rather than
#: committed. If this list ever gains an entry, the entry needs a reason next to
#: it, because an exemption is where a real corruption would hide.
_BYTE_CHECK_EXEMPT: dict = {}


def _tracked_files():
    out = subprocess.run(
        ["git", "ls-files"], cwd=_ROOT, capture_output=True, text=True,
    )
    assert out.returncode == 0, "git ls-files failed; cannot enumerate the source"
    files = [f for f in out.stdout.split("\n") if f.strip()]
    # 🔴 POSITIVE CONTROL ON THE INSTRUMENT. A zero from an enumeration that
    # returned nothing is the failure this whole repository is about.
    assert len(files) > 50, f"only {len(files)} tracked files found; the scan did not run"
    return files


def test_no_tracked_source_carries_a_forbidden_control_byte():
    """🔴 THE DEMONSTRATED CORRUPTION. A heredoc wrote a real NUL into a `.py`
    file. Nothing noticed until the bytes were read directly."""
    offenders = []
    for rel in _tracked_files():
        if rel in _BYTE_CHECK_EXEMPT:
            continue
        path = _ROOT / rel
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        found = {bytes([b]) for b in _FORBIDDEN_BYTES if bytes([b]) in data}
        if found:
            offenders.append((rel, sorted(hex(f[0]) for f in found)))
    assert not offenders, (
        f"control bytes in tracked source: {offenders}. A NUL written here once "
        "silently disabled a security guard while the module still imported and "
        "the whole suite stayed green."
    )


def _empty_literal_membership_tests(tree):
    """Yield (lineno, source-ish description) for every `<empty literal> in x`.

    `"" in x` and `b"" in x` are True for every value, so the `not in` form is
    always False. Either way the test decides nothing, which is exactly how a
    stripped byte turns a live guard into dead code.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        for op in node.ops:
            if not isinstance(op, (ast.In, ast.NotIn)):
                continue
            left = node.left
            if isinstance(left, ast.Constant) and isinstance(left.value, (str, bytes)):
                if len(left.value) == 0:
                    yield node.lineno, ("not in" if isinstance(op, ast.NotIn) else "in")


def test_no_membership_test_compares_against_an_empty_literal():
    """🔴 THE SHAPE THE CORRUPTION LEFT BEHIND, caught as a class.

    `b"" not in data` is always False. It is not a typo Python will reject, it is
    not a runtime error, and no test failed because of it -- the surrounding
    condition simply stopped contributing. Any occurrence is either dead code or
    a guard that has quietly stopped guarding.
    """
    offenders = []
    for rel in _tracked_files():
        if not rel.endswith(".py"):
            continue
        path = _ROOT / rel
        if not path.is_file():
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            # A file that does not parse is a different problem, and the suite
            # would already be failing on it. Not this check's business.
            continue
        for lineno, form in _empty_literal_membership_tests(tree):
            offenders.append(f"{rel}:{lineno} ({form})")
    assert not offenders, (
        "always-True/always-False membership tests: " + ", ".join(offenders) +
        ". An empty literal on the left of `in` decides nothing; this is the "
        "exact shape a stripped NUL byte left in a live security guard."
    )


def test_the_empty_literal_detector_actually_detects(tmp_path):
    """🔴 POSITIVE CONTROL. Without this, the check above passes on a repository
    where the detector is broken, and a green result would mean nothing --
    which is the failure mode this whole project exists to prevent."""
    sample = (
        "def f(data):\n"
        "    if b'' not in data:\n"
        "        return None\n"
        "    if '' in data:\n"
        "        return 1\n"
        "    if b'\\x00' not in data:\n"   # the CORRECT form: must not be flagged
        "        return 2\n"
        "    return 3\n"
    )
    found = list(_empty_literal_membership_tests(ast.parse(sample)))
    assert len(found) == 2, f"expected exactly the two empty-literal tests, got {found}"
    assert {form for _line, form in found} == {"in", "not in"}


def test_the_byte_detector_actually_detects(tmp_path):
    """The other positive control. Proves the forbidden set contains NUL and
    that a file carrying one would be caught."""
    assert b"\x00" in _FORBIDDEN_BYTES
    corrupt = tmp_path / "corrupt.py"
    corrupt.write_bytes(b'x = 1\nif b"' + b"\x00" + b'" in y:\n    pass\n')
    data = corrupt.read_bytes()
    assert any(bytes([b]) in data for b in _FORBIDDEN_BYTES)


def test_tab_newline_and_carriage_return_are_not_forbidden():
    """The keep direction. Over-broadening this set would fail on every file in
    the repository and get the check deleted rather than fixed."""
    for ordinary in (0x09, 0x0A, 0x0D):
        assert bytes([ordinary]) not in _FORBIDDEN_BYTES
