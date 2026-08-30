"""F37: an unhandled entry-point failure must not collide with findings exit 1."""

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "praetor.py"


def test_f37_uncaught_main_exception_keeps_traceback_and_uses_internal_error(tmp_path):
    """A non-directory output target raises from main before any report is written."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "subject.py").write_text("answer = 1\n", encoding="utf-8")
    output_target = tmp_path / "not-a-directory"
    output_target.write_text("sentinel\n", encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(CLI),
            str(target),
            "--engines",
            "aisec",
            "--out",
            str(output_target),
            "--format",
            "json",
            "--quiet",
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    assert completed.returncode == 2, (
        "an unhandled main() failure is an internal error, not the ordinary "
        f"findings result 1; stderr was:\n{completed.stderr}"
    )
    assert "Traceback (most recent call last)" in completed.stderr
    assert "FileExistsError" in completed.stderr
    assert output_target.read_text(encoding="utf-8") == "sentinel\n"
    assert not (output_target / "praetor-report.json").exists()
    assert not (output_target / "praetor-report.txt").exists()
