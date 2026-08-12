"""
AN ENGINE THAT COULD NOT MEASURE MUST NEVER PRODUCE A PASSING EXIT CODE.

MEASURED DEFECT (2026-08-12), verified independently in `scripts/praetor.py`
before this file existed:

    if args.fail_on:
        threshold = core.Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in result["active"]):
            return 1
    return 0

The block consulted `result["active"]` and nothing else. So an engine that threw
-- a dead semgrep runtime, an unreachable Docker daemon, an unparseable tool
output -- contributed ZERO findings, and `--fail-on HIGH` returned **exit 0**,
byte-identical to a fully-measured clean scan. The exit code is what CI gates on.

🔴 The sharpest part of the defect, and the reason it is worth a dedicated file:
**PRAETOR already computed the answer.** `engine_meta` had 14 references, THIRTEEN
of them writes recording `ok`/`error`/`disabled` per engine. The fourteenth put it
in the report payload. It was never READ for any decision. The observable existed,
was correct, was populated, and was wired to the report instead of the gate.

⚠️ This is the same family as `test_sca_status_honesty.py` one layer up. That file
made each engine's STATUS honest; nothing made the DECISION read it. A scanner can
be honest in its report and still hand a gate a false clean.

WHAT IS ASSERTED, IN BOTH DIRECTIONS -- because narrowing the check and deleting
it look identical from outside:
  * an errored engine BLOCKS  (the fix)
  * a fully-measured clean scan still PASSES  (the fix did not just break the gate)
  * `disabled` and `not-applicable` do NOT block (operator choice / empty target)
  * an UNRECOGNISED status word blocks -- the guard for engines not written yet
"""

import json

import pytest

import core
import engine_sast
import engine_secrets
import praetor
import report


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _clean_target(tmp_path):
    """A target with nothing to find and no dependency manifests."""
    (tmp_path / "hello.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    return str(tmp_path)


def _break_secrets(monkeypatch):
    """Make the secrets engine raise, exactly as a broken runtime would."""
    def boom(*a, **kw):
        raise RuntimeError("simulated engine failure")

    monkeypatch.setattr(engine_secrets, "scan", boom)


def _run(argv):
    return praetor.main(argv)


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #

def test_errored_engine_does_not_return_a_passing_exit_code(tmp_path, monkeypatch, capsys):
    """THE HEADLINE. A broken engine must not be reported as a clean gate result."""
    _break_secrets(monkeypatch)
    rc = _run([_clean_target(tmp_path), "--engines", "secrets", "--fail-on", "HIGH",
               "--format", "json", "--quiet"])

    out = capsys.readouterr()
    payload = json.loads(out.out)
    assert payload["meta"]["engines"]["secrets"]["status"] == core.ENGINE_ERROR, (
        "the fixture did not actually break the engine -- test is vacuous, fix the "
        f'fixture, not the assertion (status={payload["meta"]["engines"]["secrets"]["status"]!r})'
    )
    assert payload["findings"] == [], "fixture assumption: the target is clean"

    assert rc != 0, (
        "FALSE CLEAN AT THE GATE: the only engine selected THREW, produced zero "
        "findings for that reason alone, and --fail-on HIGH still returned exit 0. "
        "CI cannot distinguish this from a scan that ran and found nothing."
    )
    assert rc == 3, f"expected exit 3 (scan degraded), got {rc}"


def test_fully_measured_clean_scan_still_exits_zero(tmp_path):
    """THE KEEP DIRECTION. Without this, the fix and a broken gate look the same."""
    rc = _run([_clean_target(tmp_path), "--engines", "secrets", "--fail-on", "HIGH",
               "--format", "json", "--quiet"])
    assert rc == 0, (
        f"a clean, fully-measured scan must still pass its gate, got exit {rc}. "
        "A gate that fails on everything gets switched off, which is the same "
        "outcome as no gate at all."
    )


def test_real_findings_outrank_degradation(tmp_path, monkeypatch, capsys):
    """1 beats 3: the actionable signal wins when both are true."""
    (tmp_path / "leak.py").write_text(
        # assembled from parts so this file does not trip the engine it tests
        'KEY = "' + "sk-" + "ant-" + "api03-" + "A" * 80 + '"\n',
        encoding="utf-8",
    )

    def half_broken(*a, **kw):
        raise RuntimeError("simulated sast failure")

    monkeypatch.setattr(engine_sast, "run", half_broken)
    rc = _run([str(tmp_path), "--engines", "secrets,sast", "--fail-on", "HIGH",
               "--format", "json", "--quiet"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_ERROR, (
        "fixture did not break sast -- test is vacuous"
    )
    assert payload["findings"], (
        "fixture produced no active finding, so this asserts nothing about ordering"
    )
    assert rc == 1, (
        f"a real finding at/above the threshold must report as a finding (1), not as "
        f"degradation (3); got {rc}"
    )


def test_allow_degraded_is_the_only_way_past(tmp_path, monkeypatch):
    """The opt-out is explicit, per-run, and cannot be reached by accident."""
    _break_secrets(monkeypatch)
    rc = _run([_clean_target(tmp_path), "--engines", "secrets", "--fail-on", "HIGH",
               "--allow-degraded", "--format", "json", "--quiet"])
    assert rc == 0, (
        f"--allow-degraded is the documented way to gate on findings alone; got {rc}"
    )


def test_operator_disabled_engines_do_not_block_the_gate(tmp_path):
    """`disabled` is a choice the operator made knowingly -- not a surprise blind spot.

    Without this, `--engines secrets` could never return 0, and the gate would be
    unusable for anyone scanning with a subset.
    """
    rc = _run([_clean_target(tmp_path), "--engines", "secrets", "--fail-on", "INFO",
               "--format", "json", "--quiet"])
    assert rc == 0, f"three engines were 'disabled' by the operator's own flag; got {rc}"


# --------------------------------------------------------------------------- #
# The classification itself -- the part that has to survive future engines
# --------------------------------------------------------------------------- #

def test_unrecognised_status_is_treated_as_a_blind_spot():
    """🔴 The guard for code nobody has written yet.

    Every previous narrowing defect in this repo took the same shape: a check that
    enumerated what its author had seen. A status word added by a future engine and
    never considered here MUST fail toward "unmeasured" -- the same way an unproven
    finding is KEPT rather than suppressed.
    """
    blind = core.engine_blind_spots({"future": {"status": "partial", "detail": "half a scan"}})
    assert blind == [("future", "partial", "half a scan")], (
        "an unknown status word was treated as trustworthy. The allowlist in "
        "core.GATE_TRUSTED_STATUSES must stay an ALLOWLIST -- if this ever becomes a "
        "denylist of known-bad statuses, every engine added later is silently trusted."
    )


@pytest.mark.parametrize("status", sorted(core.GATE_TRUSTED_STATUSES))
def test_trusted_statuses_are_exactly_the_three_defensible_ones(status):
    assert status in (core.ENGINE_OK, core.ENGINE_NOT_APPLICABLE, core.ENGINE_DISABLED), (
        f"{status!r} was added to the gate's trusted set. Only three states justify "
        "reading an engine's silence as meaningful: it ran (ok), there was nothing of "
        "its kind in the target (not-applicable), or the operator switched it off "
        "(disabled). Anything else means PRAETOR did not look."
    )


@pytest.mark.parametrize("status", [core.ENGINE_ERROR, core.ENGINE_UNAVAILABLE])
def test_both_failure_states_block(status):
    assert core.engine_blind_spots({"e": {"status": status, "detail": ""}}), (
        f"{status!r} must block a gate: the engine did not measure the target"
    )


# --------------------------------------------------------------------------- #
# The report -- the human reading path, same defect
# --------------------------------------------------------------------------- #

def test_empty_report_says_it_was_not_fully_measured():
    """"No active findings" is the line most likely to be misread as a clean bill."""
    result = {"active": [], "filtered": [], "summary": {}, "total_active": 0, "total_filtered": 0}
    meta = {"target": "t", "timestamp": "now", "version": "x", "file_count": 1,
            "engines": {"sast": {"status": core.ENGINE_ERROR, "detail": "semgrep died"}}}

    text = report.render_text(result, meta)
    assert "No active findings" in text, "fixture assumption changed"
    assert "NOT fully measured" in text, (
        "a reader who skips to 'No active findings' gets a clean bill of health from "
        "a scan whose engine died. The caveat must appear at that line, not only in "
        "the engine-status block above it."
    )


def test_unavailable_no_longer_renders_as_skipped():
    """`[skipped]` reads as 'nothing to do here'. It meant 'could not look'."""
    result = {"active": [], "filtered": [], "summary": {}, "total_active": 0, "total_filtered": 0}
    meta = {"target": "t", "timestamp": "now", "version": "x", "file_count": 1,
            "engines": {"sast": {"status": core.ENGINE_UNAVAILABLE,
                                 "detail": "no semgrep runtime found"}}}

    text = report.render_text(result, meta)
    assert "[skipped]" not in text, (
        "an engine that could not run was marked [skipped], the same word a reader "
        "applies to a step that was legitimately unnecessary"
    )
    assert "[BLIND]" in text
