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
  * the flag reaches the engine
  * WITHOUT the flag, no timeout is passed at all -- so the engine default, and
    therefore PRAETOR_SEMGREP_TIMEOUT, still applies. Passing a value eagerly
    would freeze the default at import time and defeat the env var.
  * the environment override is honoured
  * the shipped default is unchanged at 900
"""

import importlib
import os

import engine_sast
import praetor


def _spy_on_sast(monkeypatch):
    """Record the kwargs praetor hands the SAST engine, without running it."""
    seen = {}

    def spy(*args, **kwargs):
        seen.clear()
        seen.update(kwargs)
        return {"findings": [], "status": "ok", "detail": "spy", "runtime": "test"}

    monkeypatch.setattr(engine_sast, "run", spy)
    return seen


def _target(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    return str(tmp_path)


def test_the_flag_reaches_the_engine(tmp_path, monkeypatch):
    """The operator's lever must actually move something."""
    seen = _spy_on_sast(monkeypatch)

    praetor.main([_target(tmp_path), "--engines", "sast", "--quiet",
                  "--semgrep-timeout", "2700"])

    assert seen.get("timeout") == 2700, (
        "the engine must receive the operator's budget; without this the flag is "
        "decoration and a large tree still cannot be scanned"
    )


def test_without_the_flag_no_timeout_is_passed_at_all(tmp_path, monkeypatch):
    """🔴 THE SUBTLE HALF, and the reason this test exists.

    Passing `args.semgrep_timeout` unconditionally would send the argparse
    default on every run, freezing the value at import time and silently
    defeating `PRAETOR_SEMGREP_TIMEOUT`. The env var would then appear to work
    (the module reads it) while having no effect on any real scan.
    """
    seen = _spy_on_sast(monkeypatch)

    praetor.main([_target(tmp_path), "--engines", "sast", "--quiet"])

    assert "timeout" not in seen, (
        "with no flag given, praetor must not pass a timeout -- the engine's own "
        "default and the environment override have to remain in charge"
    )


def test_the_environment_override_is_honoured(monkeypatch):
    """A CI caller sets an env var; it must reach the effective value."""
    monkeypatch.setenv("PRAETOR_SEMGREP_TIMEOUT", "3600")
    reloaded = importlib.reload(engine_sast)
    try:
        assert reloaded._SEMGREP_TIMEOUT == 3600, (
            "PRAETOR_SEMGREP_TIMEOUT must set the engine budget"
        )
    finally:
        monkeypatch.delenv("PRAETOR_SEMGREP_TIMEOUT", raising=False)
        importlib.reload(engine_sast)


def test_the_shipped_default_is_unchanged(monkeypatch):
    """A knob must not quietly move the setting everyone already relies on."""
    monkeypatch.delenv("PRAETOR_SEMGREP_TIMEOUT", raising=False)
    reloaded = importlib.reload(engine_sast)
    assert reloaded._SEMGREP_TIMEOUT_DEFAULT == 900
    assert reloaded._SEMGREP_TIMEOUT == 900, (
        "with no override the behaviour must be exactly what it was before this "
        "flag existed"
    )


def test_a_timeout_cannot_produce_a_passing_scan(tmp_path, monkeypatch):
    """The safety property that makes this a knob rather than a risk.

    Whatever the budget, exhausting it yields an engine `error`, and an errored
    engine must never reach exit 0.
    """
    def timed_out(*args, **kwargs):
        return {"findings": [], "status": "error",
                "detail": "semgrep timed out", "runtime": "test"}

    monkeypatch.setattr(engine_sast, "run", timed_out)

    rc = praetor.main([_target(tmp_path), "--engines", "sast", "--quiet",
                       "--semgrep-timeout", "1"])

    assert rc == 3, (
        "a timed-out engine measured nothing; reporting anything but 'not "
        "measured' would let a one-second budget manufacture a clean scan"
    )
