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

import os
import subprocess

import engine_sca
import report


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


# --------------------------------------------------------------------------- #
# THE SAST PATH -- OWED SINCE 36c00af AND NOT WRITTEN UNTIL NOW
#
# That commit added three subprocess call sites to the SAST engine (a docker
# daemon probe, a `--version` probe, a WSL `command -v`) plus the semgrep run
# itself, and added nothing here. The file's own header says "every new SCA
# backend widens this surface" -- which is narrower than the invariant, and the
# narrowness is why four new call sites arrived unguarded.
#
# 🔴 The SAST surface is a DIFFERENT shape from SCA's. SCA's danger was a tool
# BUILDING the target. SAST's dangers are: a container given write access to the
# target, and target-derived text reaching a SHELL. Both are asserted here.
# --------------------------------------------------------------------------- #

import core as _core
import engine_sast


def _capture_sast_argv(monkeypatch, mode):
    """Pin a runtime and record every argv the SAST engine would execute."""
    calls = []

    def fake_run_tool(cmd, **kwargs):
        calls.append((list(cmd), kwargs))

        class _R:
            returncode = 0
            stdout = '{"results": [], "paths": {"scanned": ["a.py"]}}'
            stderr = ""

        return _R()

    monkeypatch.setattr(engine_sast, "detect_runtime", lambda *a, **kw: {
        "mode": mode, "prefix": ["semgrep"] if mode != "docker" else ["docker"],
        "available": True, "detail": "test", "version": "test"})
    monkeypatch.setattr(_core, "run_tool", fake_run_tool)
    return calls


def test_sast_argv_carries_disable_nosem(monkeypatch, tmp_path):
    """Semgrep must report nosemgrep lines so PRAETOR can filter them with reasons."""
    calls = _capture_sast_argv(monkeypatch, "native")
    (tmp_path / "a.py").write_text("subprocess.call(cmd)\n", encoding="utf-8")
    engine_sast.run(str(tmp_path), bundled_rules="", use_registry=False,
                    extra_configs=["p/ci"], enumerated_code_files=1)
    assert calls and "--disable-nosem" in calls[-1][0]


def test_sast_retry_removes_only_rejected_nosem_flag(monkeypatch, tmp_path):
    """An old Semgrep retry must drop exactly the flag it rejected."""
    calls = []

    def fake_run_tool(cmd, **kwargs):
        calls.append(list(cmd))

        class _R:
            stderr = "unknown option --disable-nosem"
            returncode = 2
            stdout = ""

        if "--disable-nosem" not in cmd:
            _R.returncode = 0
            _R.stderr = ""
            _R.stdout = '{"results": [], "paths": {"scanned": ["a.py"]}}'
        return _R()

    monkeypatch.setattr(engine_sast, "detect_runtime", lambda *a, **kw: {
        "mode": "native", "prefix": ["semgrep"], "available": True,
        "detail": "test", "version": "test"})
    monkeypatch.setattr(_core, "run_tool", fake_run_tool)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    result = engine_sast.run(str(tmp_path), bundled_rules="", use_registry=False,
                             extra_configs=["p/ci"], enumerated_code_files=1)
    assert len(calls) == 2, calls
    assert "--disable-nosem" in calls[0]
    assert "--disable-nosem" not in calls[1]
    assert "--x-ignore-semgrepignore-files" in calls[1]
    assert "rejected --disable-nosem" in result["detail"]


def test_the_docker_runtime_mounts_the_target_read_only(tmp_path):
    """A container with write access to the target could modify what it scans.

    PRAETOR reads; it does not touch. The `:ro` suffix is the whole guarantee,
    and like `--disable-pip` it is one string in one argv list.
    """
    import pytest
    calls = []

    def fake_run_tool(cmd, **kwargs):
        calls.append(list(cmd))

        class _R:
            returncode = 0
            stdout = '{"results": [], "paths": {"scanned": ["a.py"]}}'
            stderr = ""
        return _R()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(engine_sast, "detect_runtime", lambda *a, **kw: {
            "mode": "docker", "prefix": ["docker"], "available": True,
            "detail": "test", "version": "test"})
        mp.setattr(_core, "run_tool", fake_run_tool)
        (tmp_path / "a.py").write_text("x = 1" + chr(10), encoding="utf-8")
        engine_sast.run(str(tmp_path), bundled_rules="", use_registry=False,
                        extra_configs=["p/ci"], enumerated_code_files=1)

    assert calls, "premise: the docker path must have been exercised"
    mounts = [a for argv in calls for i, a in enumerate(argv)
              if i and argv[i - 1] == "-v"]
    assert mounts, f"expected a -v mount in {calls[0]}"
    for m in mounts:
        assert m.endswith(":ro"), (
            f"every docker mount must be read-only; {m!r} is writable. A container "
            f"that can write to the target is PRAETOR modifying what it scans."
        )


def test_the_runtime_probes_never_receive_the_target_at_all(monkeypatch):
    """🔴 THE PROBE CALL SITES, which the test below CANNOT see.

    `_capture_sast_argv` monkeypatches `detect_runtime`, so the three probe
    invocations 36c00af added (docker daemon, `--version`, WSL `command -v`) never
    run under it. A test named "no SAST invocation reaches a shell" that observes
    one of four invocations is the coverage-claim defect this repo keeps hitting,
    so the probes get their own test that does NOT stub them out.

    The strongest available property is structural: `detect_runtime` is not
    given the target, so no probe argv can contain target-derived text however it
    is later edited. Asserting the signature makes that load-bearing rather than
    incidental -- adding a target parameter reddens this.
    """
    import inspect
    params = list(inspect.signature(engine_sast.detect_runtime).parameters)
    assert "target" not in params and "path" not in params, (
        f"detect_runtime must never receive the scanned path; got {params}. The "
        f"probes run a SHELL (`bash -lc`), so target text reaching them is "
        f"command injection from the tree PRAETOR was asked to read."
    )

    calls = []

    def fake_run_tool(cmd, **kwargs):
        calls.append((list(cmd), kwargs))

        class _R:
            returncode = 1
            stdout = ""
            stderr = ""
        return _R()

    # 🔴 STUB `which` TOO, or this test is HOST-DEPENDENT. Every probe sits behind
    # `shutil.which(...)`, so on a machine with no semgrep/wsl/docker -- i.e. every
    # CI runner, since the invariants job installs no tools -- detect_runtime makes
    # ZERO calls and the arming assertion below fails. Found by an independent
    # reviewer before this ever ran in CI; the suite is green locally only because
    # this box happens to have wsl.
    monkeypatch.setattr(engine_sast.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(_core, "run_tool", fake_run_tool)
    for prefer in ("native", "wsl", "docker", "auto"):
        try:
            engine_sast.detect_runtime(prefer, "Ubuntu")
        except Exception:
            pass
    assert calls, "premise: at least one probe must have been attempted"
    for argv, kwargs in calls:
        assert kwargs.get("shell") in (None, False), f"probe used a shell: {argv}"


def test_no_sast_invocation_ever_reaches_a_shell(tmp_path, monkeypatch):
    """`shell=True` would make every argv element target-influenced text.

    The WSL branch runs `bash -lc <string>`, which IS a shell -- so the rule is
    not "never name a shell" but "never let anything derived from the TARGET into
    one".

    ⚠️ SCOPE, stated because the name overreaches: this stubs
    `detect_runtime`, so it observes the semgrep RUN invocation only. The probe
    call sites are covered by the test above, which does not stub them.
    """
    (tmp_path / "a.py").write_text("x = 1" + chr(10), encoding="utf-8")
    for mode in ("native", "wsl", "docker"):
        calls = _capture_sast_argv(monkeypatch, mode)
        engine_sast.run(str(tmp_path), bundled_rules="", use_registry=False,
                        extra_configs=["p/ci"], enumerated_code_files=1)
        for argv, kwargs in calls:
            assert kwargs.get("shell") in (None, False), (
                f"{mode}: shell=True makes the target's own path a shell word: {argv}"
            )
            for i, a in enumerate(argv):
                if a == "-lc":
                    shell_word = argv[i + 1]
                    assert str(tmp_path) not in shell_word, (
                        f"{mode}: the target reached a shell string: {shell_word!r}"
                    )


def test_the_target_is_passed_as_data_never_as_a_program(tmp_path, monkeypatch):
    """The target path may appear as an ARGUMENT; it must never be argv[0].

    argv[0] is the thing that gets executed. If a path under the scanned tree
    ever became argv[0], PRAETOR would be running the code it was asked to read.
    """
    (tmp_path / "a.py").write_text("x = 1" + chr(10), encoding="utf-8")
    target = str(tmp_path)
    for mode in ("native", "wsl", "docker"):
        calls = _capture_sast_argv(monkeypatch, mode)
        engine_sast.run(target, bundled_rules="", use_registry=False,
                        extra_configs=["p/ci"], enumerated_code_files=1)
        for argv, _ in calls:
            assert argv, "empty argv"
            assert target not in argv[0], (
                f"{mode}: argv[0]={argv[0]!r} lies inside the scanned tree -- that "
                f"is executing the target, not reading it"
            )


def test_file_selection_never_follows_a_symlinked_file(tmp_path, monkeypatch):
    source = tmp_path / "linked.py"
    source.write_text("TOKEN = 'host data'\n", encoding="utf-8")
    real_islink = _core.os.path.islink
    source_abs = os.path.abspath(source)
    monkeypatch.setattr(
        _core.os.path, "islink",
        lambda path: os.path.abspath(path) == source_abs or real_islink(path),
    )
    assert _core.walk_files(str(source)) == []
    assert _core.walk_files(str(tmp_path)) == []


def test_file_selection_keeps_ordinary_files_and_nul_observation_reaches_report(tmp_path):
    source = tmp_path / "ordinary.py"
    source.write_bytes(b"TOKEN = 1\x00\n")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "other.py").write_text("value = 2\n", encoding="utf-8")
    selected = _core.walk_files(str(tmp_path))
    assert {item.relpath for item in selected} == {"ordinary.py", "nested/other.py"}
    assert next(item for item in selected if item.relpath == "ordinary.py").contains_nul
    rendered = report.render_text(
        {"active": [], "filtered": [], "summary": {}, "total_active": 0,
         "total_filtered": 0},
        {"target": "t", "timestamp": "now", "version": "x", "file_count": 2,
         "nul_text_file_count": 1, "engines": {}},
    )
    assert "NUL-bearing text files: 1" in rendered
