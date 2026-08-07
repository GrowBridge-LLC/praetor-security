"""
INVARIANT 1 -- PRAETOR NEVER EXECUTES THE CODE IT SCANS.

This invariant was briefly FALSE: the SCA/pip-audit path resolved an
attacker-controlled requirements.txt, built source distributions, and executed
setup.py / PEP517 backends -- arbitrary code execution. It was fixed by passing
`--disable-pip`, which removes pip's resolve-and-build step entirely.

The fix is one string in one argv list. Nothing in this repo guarded it until
this file existed: deleting `--disable-pip` restored the RCE and broke no test.

These tests assert the invariant BEHAVIOURALLY -- they capture the argv PRAETOR
would hand to the subprocess, without executing anything -- so they fail when the
flag stops reaching the command line, not merely when a comment changes.

Every new SCA backend widens this surface. Add a test here when you add one.
"""

import subprocess

import engine_sca


class _FakeCompleted:
    """Stands in for subprocess.CompletedProcess. Empty result set, clean exit."""

    returncode = 0
    stdout = '{"dependencies": []}'
    stderr = ""


def _capture_argv(monkeypatch, tool):
    """Route `tool` through a fake exec and record every argv it is called with."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return _FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(
        engine_sca.shutil, "which", lambda name: f"/usr/bin/{name}" if name == tool else None
    )
    return calls


def test_pip_audit_argv_carries_disable_pip(tmp_path, monkeypatch):
    """The load-bearing flag must reach the actual command line, not just the docstring."""
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n", encoding="utf-8")

    calls = _capture_argv(monkeypatch, "pip-audit")
    engine_sca._run_pip_audit([str(req)], str(tmp_path))

    assert calls, "pip-audit was never invoked -- test is vacuous, fix the fixture"
    argv = calls[0]
    assert "--disable-pip" in argv, (
        "RCE REGRESSION: pip-audit invoked WITHOUT --disable-pip. pip will resolve and "
        "BUILD the target's requirements, executing attacker-controlled setup.py / PEP517 "
        f"backends. argv was: {argv}"
    )


def test_pip_audit_never_retries_in_a_resolving_mode(tmp_path, monkeypatch):
    """
    An unauditable requirements file must ERROR, never fall back to a mode that resolves.

    The fallback is the tempting fix when --disable-pip refuses unpinned requirements --
    and it is exactly the RCE. Every invocation must carry the flag, not just the first.
    """
    req = tmp_path / "requirements.txt"
    req.write_text("requests\n", encoding="utf-8")  # unpinned: unauditable with --disable-pip

    calls = []

    def failing_run(cmd, **kwargs):
        calls.append(list(cmd))
        r = _FakeCompleted()
        r.returncode = 1
        r.stdout = ""  # no parseable output -> engine records an ERROR
        r.stderr = "requirements must be pinned"
        return r

    monkeypatch.setattr(subprocess, "run", failing_run)
    monkeypatch.setattr(
        engine_sca.shutil, "which", lambda name: "/usr/bin/pip-audit" if name == "pip-audit" else None
    )

    result = engine_sca._run_pip_audit([str(req)], str(tmp_path))

    assert calls, "pip-audit was never invoked -- test is vacuous, fix the fixture"
    for argv in calls:
        assert "--disable-pip" in argv, (
            f"RCE REGRESSION: a retry dropped --disable-pip. argv was: {argv}"
        )
    assert result["status"] == "error", (
        "An unauditable requirements file was laundered into a non-error result; "
        "a clean-looking 0 findings here is the dangerous outcome."
    )


def test_npm_audit_pins_the_registry_on_the_command_line(tmp_path, monkeypatch):
    """
    A target-controlled .npmrc must not be able to redirect the audit request.

    The dependency list travels with that request, so a redirect leaks it to an
    attacker host. CLI config outranks a project .npmrc -- only if it is actually passed.
    """
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")

    calls = _capture_argv(monkeypatch, "npm")
    engine_sca._run_npm_audit([str(tmp_path / "package-lock.json")], str(tmp_path))

    assert calls, "npm audit was never invoked -- test is vacuous, fix the fixture"
    argv = calls[0]
    assert "--registry" in argv, f"npm audit invoked without a pinned registry: {argv}"
    assert "https://registry.npmjs.org/" in argv, f"registry not pinned to npmjs: {argv}"
