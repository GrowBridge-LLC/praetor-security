"""
A CAPABILITY PROBE MUST ANSWER THE QUESTION IT IS USED TO ANSWER.

MEASURED DEFECT (2026-08-11), found by an outside user running a real scan
against their own tree, and re-derived here from the source before the fix:

    if prefer in ("docker", "auto") and shutil.which("docker"):
        return {"mode": "docker", "prefix": ["docker"], "available": True, ...}

`shutil.which` proves the CLI is INSTALLED. Whether semgrep can run depends on
the DAEMON being REACHABLE -- a different question. On a box with Docker Desktop
installed but stopped, the probe answered `available: True`, and the scan then
died with a connect error PRAETOR surfaced as:

    [error] sast  Run 'docker run --help' for more information

...which names the wrong layer entirely: it reads as a malformed command rather
than a dead daemon, and it cost the reporter an investigation.

⚠️ The native and WSL branches were already right -- native runs `semgrep
--version`, WSL runs `which semgrep` INSIDE the distro. Docker was the sole
branch that asserted a capability instead of probing it, which is exactly the
shape that survives review: three cases in a row, one of them subtly different.

📌 Why it belongs in the same commit as the exit-code gate: a probe that reports
a dead runtime as available produces an `error` engine, and until 2026-08-12 an
`error` engine produced exit 0. The two defects composed into a false clean.
"""

import subprocess

import pytest

import core
import engine_sast


class _Completed:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _only_docker(monkeypatch):
    """No native semgrep, no WSL -- force detection down to the docker branch."""
    monkeypatch.setattr(
        engine_sast.shutil, "which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )


def _daemon(monkeypatch, result):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_docker_cli_without_a_live_daemon_is_not_available(monkeypatch):
    """THE DEFECT. Installed != reachable."""
    _only_docker(monkeypatch)
    calls = _daemon(monkeypatch, _Completed(
        returncode=1,
        stderr='error during connect: Head "http://%2F%2F.%2Fpipe%2FdockerDesktopLinuxEngine/_ping": '
               "open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.",
    ))

    rt = engine_sast.detect_runtime(prefer="auto")

    assert calls, (
        "the daemon was never probed -- detect_runtime answered from shutil.which "
        "alone, which is the defect. Test is not vacuous only if a probe ran."
    )
    assert rt["available"] is False, (
        "FALSE CAPABILITY: `docker` is on PATH but the daemon is down, and the probe "
        f'reported available={rt["available"]!r}. The scan then fails at run time with '
        "an error that names the wrong layer."
    )
    assert "daemon" in rt["detail"], (
        f'the reason must name the daemon so the operator knows what to start; got '
        f'{rt["detail"]!r}'
    )


def test_docker_with_a_live_daemon_is_still_available(monkeypatch):
    """THE KEEP DIRECTION. A working Docker must not be probed out of existence."""
    _only_docker(monkeypatch)
    _daemon(monkeypatch, _Completed(returncode=0, stdout="27.1.1\n"))

    rt = engine_sast.detect_runtime(prefer="auto")

    assert rt["available"] is True, (
        f'a reachable daemon reported unavailable -- the probe is now too strict and '
        f'Docker users lost SAST entirely: {rt["detail"]!r}'
    )
    assert rt["mode"] == "docker"


def test_a_hanging_daemon_does_not_hang_the_scan(monkeypatch):
    """A probe that blocks forever is its own outage."""
    _only_docker(monkeypatch)
    _daemon(monkeypatch, subprocess.TimeoutExpired(cmd="docker version", timeout=10))

    rt = engine_sast.detect_runtime(prefer="auto")
    assert rt["available"] is False
    assert "did not respond" in rt["detail"]


def test_the_probe_reads_nothing_from_the_target(monkeypatch, tmp_path):
    """🔴 The never-execute-the-target invariant, at the one new subprocess call.

    The probe asks Docker about ITSELF. It must not mount, copy, or name any part
    of the scan target -- and it must not start a container.
    """
    _only_docker(monkeypatch)
    calls = _daemon(monkeypatch, _Completed(returncode=0, stdout="27.1.1\n"))

    engine_sast.detect_runtime(prefer="auto")

    assert calls, "no probe ran -- test is vacuous"
    for argv in calls:
        assert "run" not in argv, f"the capability probe STARTED A CONTAINER: {argv}"
        assert not any("-v" == a or a.startswith("--volume") for a in argv), (
            f"the capability probe mounted a volume: {argv}"
        )
        assert str(tmp_path) not in " ".join(argv), (
            f"the capability probe named the scan target: {argv}"
        )


def test_an_unavailable_runtime_reaches_the_gate_as_a_blind_spot(monkeypatch):
    """The two halves compose: a dead runtime must end up blocking --fail-on.

    Asserted end-to-end at the classification boundary rather than trusted -- the
    probe being correct is worth nothing if `unavailable` is trusted downstream.
    """
    _only_docker(monkeypatch)
    _daemon(monkeypatch, _Completed(returncode=1, stderr="cannot connect"))

    rt = engine_sast.detect_runtime(prefer="auto")
    assert rt["available"] is False

    res = engine_sast.run("/nonexistent-target", None, prefer="auto")
    assert res["status"] == core.ENGINE_UNAVAILABLE, (
        f'a runtime that could not be reached must report "unavailable", got '
        f'{res["status"]!r}'
    )
    assert core.engine_blind_spots({"sast": res}), (
        "an unavailable SAST engine was classified as trustworthy, so --fail-on would "
        "return 0 on a scan where semgrep never ran"
    )
