"""
A file the walker refuses for SIZE must leave a record.

🔴 THE DEMONSTRATED FAILURE. A breaker audit padded a source file past
`--max-file-size`, put a live-shaped AWS key in it, and left one ordinary small
file beside it. PRAETOR reported `file_count: 1`, `kept_code_files: 1`, every
engine `ok`, zero findings, and exit 0. The oversized file appeared nowhere --
not in the text report, not in the JSON, not in any stat -- and because one
small file remained, the whole-tree "nothing was examined" floor never fired.

The report read as a complete, fully-measured clean scan. That is the exact
failure this tool exists to prevent, and it cost one padding character.

⚠️ The cap itself is not the defect. Reading a multi-gigabyte asset into memory
is not an option. Refusing SILENTLY was the defect: every other cap in this
codebase discloses itself -- long lines, unreadable files, skipped directories,
pattern excludes -- and this one did not.
"""

import json
import os
import subprocess
import sys

_AWS_KEY = "AKIA" + "QWERTYUIOPASDFGH"
_PRAETOR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "praetor.py"
)


def _run(target, *extra):
    """Run the real CLI. Reads the exit code from the process, never from a pipe."""
    proc = subprocess.run(
        [sys.executable, _PRAETOR, str(target), "--engines", "secrets",
         "--format", "json", "--quiet", *extra],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return proc


def _build_tree(tmp_path, big_bytes):
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    big = tmp_path / "big.py"
    big.write_text(f'KEY = "{_AWS_KEY}"\n' + ("# pad\n" * (big_bytes // 6)), encoding="utf-8")
    return big


def test_an_oversized_file_is_named_in_the_report(tmp_path):
    """The whole finding. A file nobody read must say so."""
    _build_tree(tmp_path, 200_000)
    proc = _run(tmp_path, "--max-file-size", "50000")
    data = json.loads(proc.stdout)

    assert data["meta"]["scope"]["oversize_files"] >= 1, \
        "a file refused for size must be counted"
    named = {ex["file"] for ex in data["meta"]["scope"]["oversize_examples"]}
    assert any("big.py" in n for n in named), \
        "the report must name the file it did not read"


def test_the_disclosure_reaches_the_findings_list_not_only_the_metadata(tmp_path):
    """A reader looks at findings, not at `meta`. A record only a JSON consumer
    can reach is not a disclosure to the person reading the report."""
    _build_tree(tmp_path, 200_000)
    proc = _run(tmp_path, "--max-file-size", "50000")
    data = json.loads(proc.stdout)

    rule_ids = {
        f["rule_id"] for f in data["findings"] + data["filtered"]
    }
    assert "file-too-large-skipped" in rule_ids


def test_a_scan_with_no_oversized_file_says_nothing_about_it(tmp_path):
    """THE KEEP DIRECTION. A disclosure that fires on every scan is noise, and
    noise is another way to hide a real finding."""
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    proc = _run(tmp_path)
    data = json.loads(proc.stdout)

    assert data["meta"]["scope"]["oversize_files"] == 0
    rule_ids = {
        f["rule_id"] for f in data["findings"] + data["filtered"]
    }
    assert "file-too-large-skipped" not in rule_ids


def test_the_disclosure_does_not_claim_the_skipped_file_is_clean(tmp_path):
    """🔴 THE WORDING IS THE POINT. The danger is a reader treating 'skipped'
    as 'nothing there'. The note must say the absence of findings from that file
    is not evidence about it."""
    _build_tree(tmp_path, 200_000)
    proc = _run(tmp_path, "--max-file-size", "50000")
    data = json.loads(proc.stdout)

    note = next(
        f for f in data["findings"] + data["filtered"]
        if f["rule_id"] == "file-too-large-skipped"
    )
    lowered = note["description"].lower()
    assert "not evidence they are clean" in lowered
    assert "safe" not in lowered
