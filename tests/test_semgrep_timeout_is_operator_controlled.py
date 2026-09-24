"""
A COVERAGE CEILING NOBODY CAN RAISE IS A SILENT ABSENCE OF STATIC ANALYSIS.

MEASURED (2026-08-23). `_SEMGREP_TIMEOUT` was a hard-coded 900 seconds with no
flag and no environment override. Pointed at a real 7,369-file target, Semgrep
exceeded it and the SAST engine returned `error` -- twice, once in a four-engine
run and once running alone.

✅ PRAETOR behaved correctly both times: an engine error is a malfunction, so it
returned exit 3 rather than a clean result. This was never a false clean.

🔴 But the only way to obtain ANY static analysis on that tree was to partition
it by hand and scan twenty directories separately. A CI caller cannot do that.
⇒ The failure mode of an unraisable ceiling is that SAST silently does not run
on exactly the largest and most interesting codebases -- the ones most worth
scanning -- and the operator has no lever.

⚠️ WHY THIS IS SAFE IN BOTH DIRECTIONS, which is why it is a knob at all:
a timeout produces an engine `error`, and the exit-code floor already converts
that to 3. **There is no value of this setting that turns a timeout into a
passing scan.** Raising it buys coverage; lowering it buys a faster failure.
Neither can manufacture a clean result.

WHAT IS ASSERTED:
  * one effective timeout reaches both eligibility resolution and the scan
  * the explicit CLI value, environment value, and shipped default each flow
    through production wiring without a shared fallback in the test double
  * the shipped default is unchanged at 900
"""

import importlib
import engine_sast
import praetor


def _spy_on_sast(monkeypatch):
    """Record explicit production timeout arguments without running Semgrep."""
    seen = []

    def coverage(*args, timeout, **kwargs):
        seen.append(("coverage", timeout))
        return {
            "detected": frozenset({"python"}),
            "covered": frozenset({"python"}),
            "uncovered": frozenset(),
            "eligible_files": 1,
            "pinned": frozenset({"python"}),
            "sources": {"python": [{"source": "pinned rules", "count": 1}]},
            "unresolved": (),
            "ignored_target_configs": (),
            "resolved_optional": (),
            "rules_loaded": True,
        }

    def scan(*args, timeout, **kwargs):
        seen.append(("scan", timeout))
        return {"findings": [], "status": "ok", "detail": "spy", "runtime": "test"}

    monkeypatch.setattr(engine_sast, "language_coverage", coverage)
    monkeypatch.setattr(engine_sast, "run", scan)
    return seen


def _target(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    return str(tmp_path)


def test_cli_timeout_reaches_coverage_and_scan(tmp_path, monkeypatch):
    seen = _spy_on_sast(monkeypatch)

    praetor.main([_target(tmp_path), "--engines", "sast", "--quiet",
                  "--semgrep-timeout", "2700"])

    assert seen == [("coverage", 2700), ("scan", 2700)]


def test_default_timeout_reaches_coverage_and_scan(tmp_path, monkeypatch):
    monkeypatch.delenv("PRAETOR_SEMGREP_TIMEOUT", raising=False)
    reloaded = importlib.reload(engine_sast)
    assert reloaded._SEMGREP_TIMEOUT_DEFAULT == 900
    assert reloaded._SEMGREP_TIMEOUT == 900
    seen = _spy_on_sast(monkeypatch)

    praetor.main([_target(tmp_path), "--engines", "sast", "--quiet"])

    assert seen == [("coverage", 900), ("scan", 900)]


def test_environment_timeout_reaches_coverage_and_scan(tmp_path, monkeypatch):
    monkeypatch.setenv("PRAETOR_SEMGREP_TIMEOUT", "3600")
    reloaded = importlib.reload(engine_sast)
    try:
        assert reloaded._SEMGREP_TIMEOUT == 3600
        seen = _spy_on_sast(monkeypatch)
        praetor.main([_target(tmp_path), "--engines", "sast", "--quiet"])
        assert seen == [("coverage", 3600), ("scan", 3600)]
    finally:
        monkeypatch.delenv("PRAETOR_SEMGREP_TIMEOUT", raising=False)
        importlib.reload(engine_sast)


def test_a_timeout_cannot_produce_a_passing_scan(tmp_path, monkeypatch):
    """The safety property that makes this a knob rather than a risk.

    Whatever the budget, exhausting it yields an engine `error`, and an errored
    engine must never reach exit 0.
    """
    def timed_out(*args, **kwargs):
        return {"findings": [], "status": "error",
                "detail": "semgrep timed out", "runtime": "test"}

    _spy_on_sast(monkeypatch)
    monkeypatch.setattr(engine_sast, "run", timed_out)

    rc = praetor.main([_target(tmp_path), "--engines", "sast", "--quiet",
                       "--semgrep-timeout", "1"])

    assert rc == 3, (
        "a timed-out engine measured nothing; reporting anything but 'not "
        "measured' would let a one-second budget manufacture a clean scan"
    )
