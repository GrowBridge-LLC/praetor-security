"""
The GitHub Action must hand the SARIF file back to the caller.

🔴 THE FILE WAS WRITTEN AND THEN NEVER NAMED. `--out` already produced
`praetor-report.sarif`; `action.yml` declared `report-json` and stopped there.
So the one artifact that puts PRAETOR in a repository's Security tab existed on
disk inside the runner and was unreachable from the workflow that made it.

⚠️ THIS IS THE SAME SHAPE AS THE BROKEN INSTALL STEP. That step was marked done
because the file existed, and every run of it failed. A feature is delivered when
a caller can use it, never when the code that produces it is present.

⚠️ WHAT THIS FILE CANNOT CHECK. It reads `action.yml` as text and asserts the
wiring is declared. It cannot run a GitHub runner, so it cannot prove the upload
works end to end. That check belongs to a real workflow run, and this repository
has already recorded what happens when a distribution box is ticked on file
existence alone.
"""

import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_ACTION = _ROOT / "action.yml"


def _text():
    return _ACTION.read_text(encoding="utf-8")


def test_the_action_declares_a_sarif_output():
    """Without the declaration a caller cannot reference the file at all."""
    text = _text()
    assert re.search(r"^\s{2}report-sarif:", text, re.M), (
        "action.yml declares no `report-sarif` output, so the SARIF file it "
        "produces cannot be referenced by the calling workflow"
    )
    assert "steps.scan.outputs.report-sarif" in text


def test_the_run_step_actually_sets_that_output():
    """🔴 DECLARING AN OUTPUT DOES NOT PRODUCE ONE. A declared output whose value
    is never written resolves to the empty string, and `upload-sarif` then fails
    on a missing file -- which reads as a broken scanner rather than a broken
    wiring."""
    text = _text()
    assert 'echo "report-sarif=' in text, (
        "the run step never writes report-sarif to $GITHUB_OUTPUT"
    )
    assert "praetor-report.sarif" in text


def test_the_upload_caveat_is_documented():
    """⚠️ THE ACTION EXITS WITH PRAETOR'S OWN CODE, so a run that FOUND something
    fails the step -- and an upload step without `if: always()` is then skipped,
    losing precisely the results worth uploading. A user hits this on their first
    real finding, which is the worst moment to discover it."""
    text = _text()
    # ⚠️ BOTH, AND THE MUTATION TEST IS WHY. A single `in` check passed when the
    # warning sentence was deleted, because the worked example still contained
    # the same four words. A guard satisfied by either half of what it is
    # protecting is half a guard.
    assert "THE UPLOAD STEP NEEDS `if: always()`" in text, (
        "the report-sarif description must state the caveat in words"
    )
    assert re.search(r"^\s+if: always\(\)\s*$", text, re.M), (
        "and show it in the worked example, which is what a reader copies"
    )


def test_the_format_input_mentions_sarif():
    """An input whose documentation omits a valid value is an undiscoverable
    feature."""
    formats = _text().split("format:", 1)[1].split("fail-on:", 1)[0]
    assert "sarif" in formats.lower()
