"""
A BACKEND THAT ANALYSED NOTHING MUST NEVER REPORT `status: "ok"`.

`status` is the only signal telling a consumer whether a zero-finding result
means anything. `"status": "ok"` with zero findings is read by every consumer --
a human, `--fail-on`, a CI gate -- as "SCA ran and the target is clean". When
nothing was actually examined, that is a FALSE CLEAN, and it is worse in the
JSON contract than in the text report because the JSON is what gates consume.

MEASURED DEFECT (2026-08-10), reproduced end to end before it was fixed:

    praetor.py <no-manifest-dir> --engines sca                  -> "status": "not-applicable"
    praetor.py <no-manifest-dir> --engines sca --sca-backend osv -> "status": "ok"

The same target, scanned two ways, disagreed about whether the scan happened --
and the flag that produced the dishonest answer is the one an expert user is
more likely to pass. `_run_osv` mapped empty stdout to "ok" under the comment
"treat as clean-but-ran", while `_run_pip_audit` and `_run_npm_audit` already
treated the identical condition as not-ok. osv was the sole outlier.

The old comment also claimed "exit 128" while the code checked no return code at
all, so a *crashing* scanner was laundered into a clean result too. Hence the
two directions are asserted separately: exit 128 is a property of the TARGET
(not-applicable), any other empty-output exit is a property of the ENVIRONMENT
(error).

⚠️ The cross-backend test is the one that matters long-term: it fails for a NEW
backend that repeats the mistake, which no osv-specific test would.
"""

import subprocess

import pytest

import core
import engine_sca


class _Completed:
    """Stands in for subprocess.CompletedProcess with a chosen exit code / output."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_exec(monkeypatch, tool, result):
    """Make `tool` resolvable and route every subprocess.run to `result`."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return result

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(
        engine_sca.shutil, "which", lambda name: f"/usr/bin/{name}" if name == tool else None
    )
    return calls


# --------------------------------------------------------------------------- #
# osv -- the backend that carried the defect
# --------------------------------------------------------------------------- #

def test_osv_no_packages_is_not_applicable_not_ok(tmp_path, monkeypatch):
    """exit 128 + no output = nothing to scan. Honest, but NOT a clean scan."""
    calls = _fake_exec(monkeypatch, "osv-scanner", _Completed(returncode=128, stdout=""))
    res = engine_sca._run_osv(str(tmp_path))

    assert calls, "osv-scanner was never invoked -- test is vacuous, fix the fixture"
    assert res["status"] != "ok", (
        "FALSE CLEAN: osv-scanner analysed no packages, yet the result reports "
        f'status={res["status"]!r} with {len(res["findings"])} findings. A consumer '
        "cannot distinguish this from a target that was scanned and found clean."
    )
    assert res["status"] == core.ENGINE_NOT_APPLICABLE, (
        f'exit 128 means "no packages found" -- a property of the TARGET, so the '
        f'status should be "not-applicable", got {res["status"]!r}. It was spelled '
        '"unavailable" until 2026-08-12, when that word was narrowed to mean solely '
        '"the ENVIRONMENT could not run this engine" so that --fail-on could tell a '
        "manifest-free repo apart from a missing scanner."
    )
    assert res["status"] in core.GATE_TRUSTED_STATUSES, (
        "a target with no dependencies leaves nothing unmeasured, so this state must "
        "NOT block --fail-on; if it did, every manifest-free repo would fail its gate"
    )
    assert not res["findings"]


def test_osv_crash_with_no_output_is_error_not_ok(tmp_path, monkeypatch):
    """Any OTHER empty-output exit is an abnormal termination, not an empty target."""
    calls = _fake_exec(monkeypatch, "osv-scanner", _Completed(returncode=1, stdout=""))
    res = engine_sca._run_osv(str(tmp_path))

    assert calls, "osv-scanner was never invoked -- test is vacuous, fix the fixture"
    assert res["status"] == "error", (
        "A scanner that exited abnormally with no output did NOT complete. Reporting "
        f'anything but "error" hides a broken environment; got {res["status"]!r}. '
        "NOTE: the pre-fix code only *claimed* to check exit 128 and checked nothing, "
        "so this case was reported as a successful clean scan."
    )


def test_osv_real_output_still_reports_ok(tmp_path, monkeypatch):
    """The KEEP direction: a genuine empty result set is still a successful scan.

    Without this, narrowing the predicate and disabling the backend look identical.
    """
    calls = _fake_exec(
        monkeypatch, "osv-scanner", _Completed(returncode=0, stdout='{"results": []}')
    )
    res = engine_sca._run_osv(str(tmp_path))

    assert calls, "osv-scanner was never invoked -- test is vacuous, fix the fixture"
    assert res["status"] == "ok", (
        "osv-scanner returned a parseable, genuinely empty result set -- that IS a "
        f'completed scan and must stay "ok", got {res["status"]!r}'
    )
    assert not res["findings"]


# --------------------------------------------------------------------------- #
# The cross-backend invariant -- this is the one that guards FUTURE backends
# --------------------------------------------------------------------------- #

def _invoke_with_empty_output(backend, tmp_path, monkeypatch):
    """Drive each backend to the 'tool produced no output' branch."""
    if backend == "osv":
        _fake_exec(monkeypatch, "osv-scanner", _Completed(returncode=1, stdout=""))
        return engine_sca._run_osv(str(tmp_path))

    if backend == "pip-audit":
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\n", encoding="utf-8")
        _fake_exec(monkeypatch, "pip-audit", _Completed(returncode=1, stdout=""))
        return engine_sca._run_pip_audit([str(req)], str(tmp_path))

    lock = tmp_path / "package-lock.json"
    lock.write_text("{}", encoding="utf-8")
    _fake_exec(monkeypatch, "npm", _Completed(returncode=1, stdout=""))
    return engine_sca._run_npm_audit([str(lock)], str(tmp_path))


@pytest.mark.parametrize("backend", ["osv", "pip-audit", "npm"])
def test_no_backend_reports_ok_when_it_produced_no_output(backend, tmp_path, monkeypatch):
    """NO SCA backend may report a successful scan when its tool emitted nothing.

    Two of three backends already got this right and osv did not, which is exactly
    why the guard belongs at the class level rather than on one function: the next
    backend added here will be written by someone reading osv, not pip-audit.
    """
    res = _invoke_with_empty_output(backend, tmp_path, monkeypatch)

    assert res.get("ok") is True, (
        f"{backend}: the fixture did not reach the empty-output branch -- the tool was "
        "reported as absent instead. Test is vacuous; fix the fixture, not the assertion."
    )
    assert res["status"] != "ok", (
        f'FALSE CLEAN via {backend}: the tool emitted no output, yet status={res["status"]!r} '
        f'with {len(res.get("findings", []))} findings. Every consumer reads that as '
        '"this target was scanned and is clean."'
    )
