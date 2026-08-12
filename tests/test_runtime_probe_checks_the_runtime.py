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

📌 Why it belonged in the same commit as the exit-code gate: a probe that reports
a dead runtime as available produces an `error` engine, and until 2026-08-12 an
`error` engine produced exit 0. The two defects composed into a false clean.

--------------------------------------------------------------------------- #
🔴 WHAT THIS FILE ASSERTED WHEN IT WAS WRITTEN, AND WHY IT WAS WRONG (2026-08-12)

It said, in this docstring and in a comment beside the fix:

    "The native and WSL branches were already right -- native runs `semgrep
     --version`, WSL runs `which semgrep` INSIDE the distro. Docker was the sole
     branch that asserted a capability instead of probing it."

Both clauses were false, and stating them is what stopped anyone from looking:

  * NATIVE ran `--version` through `_native_version`, which ignored the exit code
    and had `except Exception: return "semgrep"`. It could not fail. The result
    was used as a display label; `available: True` came from `shutil.which`.
  * WSL ran `which semgrep` in a NON-LOGIN shell, whose PATH is the bare system
    default rather than the one the operator's `~/.profile` builds. It answered
    about a PATH it would not use. Its prefix then invoked bare `semgrep`, so
    the run repeated that lookup and could fail after a passing probe.

MEASURED, on this repo's own development box: a pip-installed Windows
`semgrep.EXE` exiting 1 and printing nothing was reported available and PREFERRED
over a healthy WSL semgrep. SAST had not run here at all. Its silence was read as
"no findings" often enough that a self-scan count taken with the engine dead was
quoted as evidence. Turning it on surfaced two HIGH findings in this repo's own
CI workflow, first seen the day the probe was fixed.

⇒ The lesson is not about probes. Three near-identical branches were reviewed,
one defect was found and fixed, and the review then GENERALISED FROM THE FIXED
CASE and certified its siblings in prose. Fixing the demonstrated instance and
writing "the others are fine" is how a defect class survives its own repair.
"""

import json
import pathlib
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


# --------------------------------------------------------------------------- #
# NATIVE: the branch whose probe could not fail
# --------------------------------------------------------------------------- #

def _only_native(monkeypatch, exe="/usr/bin/semgrep"):
    """semgrep on PATH, no wsl, no docker."""
    monkeypatch.setattr(
        engine_sast.shutil, "which",
        lambda name: exe if name == "semgrep" else None,
    )


def test_a_broken_native_semgrep_is_not_available(monkeypatch):
    """THE DEFECT, exactly as measured: on PATH, exits 1, prints nothing."""
    _only_native(monkeypatch)
    calls = _daemon(monkeypatch, _Completed(returncode=1, stdout="", stderr=""))

    rt = engine_sast.detect_runtime(prefer="auto")

    assert calls, "no probe ran -- detect_runtime answered from shutil.which alone"
    assert rt["available"] is False, (
        "FALSE CAPABILITY: a semgrep that cannot report its own version was "
        f'reported available={rt["available"]!r}. PRAETOR then selects it over a '
        "working runtime, runs a scan, gets nothing, and reports [error] sast."
    )
    assert rt["mode"] != "native"


def test_a_native_semgrep_that_exits_zero_but_says_nothing_is_not_available(monkeypatch):
    """Exit 0 is not the whole test. A --version printing nothing will not produce
    parseable JSON either, and 'ran without error' is not 'works'."""
    _only_native(monkeypatch)
    _daemon(monkeypatch, _Completed(returncode=0, stdout="   \n", stderr=""))

    rt = engine_sast.detect_runtime(prefer="auto")
    assert rt["available"] is False, (
        "a silent --version was accepted as a working runtime on exit code alone"
    )


def test_a_working_native_semgrep_is_still_used(monkeypatch):
    """KEEP DIRECTION. A probe strict enough to reject every install is an outage,
    and looks identical to this fix if only the reject case is asserted."""
    _only_native(monkeypatch)
    _daemon(monkeypatch, _Completed(returncode=0, stdout="1.172.0\n"))

    rt = engine_sast.detect_runtime(prefer="auto")

    assert rt["available"] is True, f'a healthy semgrep was rejected: {rt["detail"]!r}'
    assert rt["mode"] == "native"
    assert "1.172.0" in rt["detail"], (
        f'the version the probe measured must reach the report: {rt["detail"]!r}'
    )


def test_a_broken_native_does_not_mask_a_working_wsl(monkeypatch):
    """🔴 THE COMPOSITION, and why `auto` falls through instead of failing.

    This is the state the development box was in: a broken native install sat in
    front of a healthy WSL semgrep, and native won on `shutil.which` alone.
    """
    monkeypatch.setattr(
        engine_sast.shutil, "which",
        lambda name: {"semgrep": "C:\\py\\Scripts\\semgrep.EXE",
                      "wsl": "C:\\Windows\\wsl.exe"}.get(name),
    )

    def fake_run(cmd, **kwargs):
        argv = list(cmd)
        if str(argv[0]).endswith("semgrep.EXE"):      # the broken native install
            return _Completed(returncode=1, stdout="", stderr="")
        if "command -v semgrep" in argv:              # login-shell resolution
            return _Completed(returncode=0, stdout="/home/u/.local/bin/semgrep\n")
        return _Completed(returncode=0, stdout="1.172.0\n")   # the WSL probe

    monkeypatch.setattr(subprocess, "run", fake_run)

    rt = engine_sast.detect_runtime(prefer="auto")

    assert rt["available"] is True, (
        f'a broken native install shadowed a healthy WSL semgrep and SAST was lost '
        f'entirely: {rt["detail"]!r}'
    )
    assert rt["mode"] == "wsl"


# --------------------------------------------------------------------------- #
# WSL: the probe and the invocation must resolve the SAME binary
# --------------------------------------------------------------------------- #

def _only_wsl(monkeypatch):
    monkeypatch.setattr(
        engine_sast.shutil, "which",
        lambda name: "C:\\Windows\\wsl.exe" if name == "wsl" else None,
    )


def test_wsl_resolution_uses_a_login_shell(monkeypatch):
    """`wsl -d <distro> which semgrep` starts a NON-login shell, so it reports on
    the bare system PATH rather than the one the operator's profile builds. A
    per-user install (pipx, a venv, ~/.local/bin) is invisible to it."""
    _only_wsl(monkeypatch)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        if "command -v semgrep" in cmd:
            return _Completed(returncode=0, stdout="/home/u/.local/bin/semgrep\n")
        return _Completed(returncode=0, stdout="1.172.0\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    engine_sast.detect_runtime(prefer="auto")

    resolution = [c for c in calls if any("semgrep" in str(a) for a in c)]
    assert resolution, "nothing tried to locate semgrep inside the distro"
    assert any("-lc" in c or "-l" in c for c in resolution), (
        "semgrep was located WITHOUT a login shell, so the probe reports on a PATH "
        f"the operator never configured: {resolution}"
    )


def test_the_wsl_prefix_carries_the_resolved_absolute_path(monkeypatch):
    """🔴 PROBE AND INVOCATION MUST RESOLVE THE SAME THING.

    The old prefix was `wsl -d <distro> semgrep`, which repeats the non-login PATH
    lookup AT RUN TIME. Fixing only the probe would leave a passing probe followed
    by a run that could not find the binary, reported as an errored engine.
    """
    _only_wsl(monkeypatch)

    def fake_run(cmd, **kwargs):
        if "command -v semgrep" in cmd:
            return _Completed(returncode=0, stdout="/home/u/.local/bin/semgrep\n")
        return _Completed(returncode=0, stdout="1.172.0\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    rt = engine_sast.detect_runtime(prefer="auto")

    assert rt["available"] is True and rt["mode"] == "wsl"
    assert "/home/u/.local/bin/semgrep" in rt["prefix"], (
        f'the prefix does not carry the path the probe verified: {rt["prefix"]}. '
        "A bare `semgrep` here re-runs the lookup in a non-login shell."
    )
    assert "semgrep" not in rt["prefix"][:-1], (
        f'a bare `semgrep` argument survives in the prefix: {rt["prefix"]}'
    )


def test_wsl_without_semgrep_installed_is_not_available(monkeypatch):
    """KEEP DIRECTION. Resolution failing must mean unavailable, not a prefix built
    around an empty string."""
    _only_wsl(monkeypatch)
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: _Completed(returncode=1, stdout="", stderr=""))

    rt = engine_sast.detect_runtime(prefer="auto")
    assert rt["available"] is False
    assert rt["mode"] == "none"


# --------------------------------------------------------------------------- #
# A finding's path must point INTO the scanned tree, whatever runtime found it
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("mode,raw,expected", [
    # WSL reports under the /mnt translation of the target...
    ("wsl", "/mnt/c/projects/P/.github/workflows/ci.yml", ".github/workflows/ci.yml"),
    # ...Docker under the mount point...
    ("docker", "/src/scripts/app.py", "scripts/app.py"),
    # ...native under the host path.
    ("native", "C:\\projects\\P\\scripts\\app.py", "scripts/app.py"),
])
def test_finding_paths_are_relative_to_the_scanned_tree(mode, raw, expected):
    """MEASURED: every WSL finding came back as
    `../../mnt/c/projects/PRAETOR/.github/workflows/invariants.yml`.

    `f.file` is the key inline-ignore suppression, lexical context, taint
    reachability and the baseline classifier all use to REOPEN the file. A path
    resolving to nothing degrades each of them, and because "cannot open ⇒ keep
    the finding" is the fail-safe direction, the breakage hides as noise.
    """
    root = engine_sast._report_root(mode, "C:\\projects\\P")
    got = engine_sast._relative_to_report_root(raw, root)
    assert got == expected, (
        f"{mode}: path {raw!r} mapped to {got!r}, expected {expected!r} -- a finding "
        "whose file cannot be opened silently disables every later pass"
    )
    assert not got.startswith(".."), f"{mode}: path escapes the scanned tree: {got!r}"


def test_an_unexpected_path_is_reported_as_semgrep_gave_it():
    """Never invent a path. If the root assumption is wrong, semgrep's own answer is
    worth more than a computed one pointing outside the tree."""
    got = engine_sast._relative_to_report_root("/somewhere/else/app.py", "/src")
    assert got == "/somewhere/else/app.py", (
        f"an unrecognised path was rewritten into {got!r} rather than kept verbatim"
    )


def test_a_wsl_finding_reaches_the_report_with_a_usable_path(monkeypatch, tmp_path):
    """🔴 THE WIRING, not the helper.

    The two tests above call `_relative_to_report_root` directly, so they pass
    whether or not `run()` actually uses it -- mutating the call site back to
    `os.path.relpath(raw_path, <Windows abspath>)` left both of them GREEN. A unit
    test of a component cannot notice the component being unplugged, which is the
    same shape as asserting a setting instead of the enforcement it configures.

    So this drives the real `run()` with a real semgrep payload.
    """
    monkeypatch.setattr(engine_sast, "detect_runtime", lambda *a, **k: {
        "mode": "wsl",
        "prefix": ["wsl", "-d", "Ubuntu", "/home/u/.local/bin/semgrep"],
        "available": True,
        "detail": "semgrep 1.172.0 (wsl:Ubuntu)",
    })

    payload = json.dumps({"results": [{
        "check_id": "rules.github-actions-mutable-action-tag",
        "path": engine_sast._win_to_wsl(str(tmp_path)) + "/.github/workflows/ci.yml",
        "start": {"line": 21}, "end": {"line": 21},
        "extra": {"message": "mutable action tag", "severity": "ERROR",
                  "lines": "- uses: actions/checkout@v4", "metadata": {}},
    }], "errors": []})

    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: _Completed(returncode=1, stdout=payload))

    rules = pathlib.Path(engine_sast.__file__).resolve().parent.parent / "rules" / "semgrep-praetor.yaml"
    assert rules.exists(), f"fixture needs the bundled ruleset; not at {rules}"
    res = engine_sast.run(str(tmp_path), str(rules), use_registry=False)

    assert res["status"] == "ok" and res["findings"], (
        f"fixture never armed -- no finding was parsed at all: {res['detail']!r}"
    )
    got = res["findings"][0].file
    assert got == ".github/workflows/ci.yml", (
        f"a WSL finding reached the report as {got!r}. Every later pass -- inline "
        "ignore markers, lexical context, taint reachability, the baseline "
        "classifier -- reopens the file by this path."
    )
    assert not got.startswith("..") and "/mnt/" not in got, (
        f"the path still carries the WSL mount prefix: {got!r}"
    )
