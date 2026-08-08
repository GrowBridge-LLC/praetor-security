"""
The SAST engine must scan what PRAETOR was pointed at.

Semgrep honours .gitignore by default. PRAETOR's own walker already decides scope
— it applies `--exclude` patterns and a size limit — so a second, invisible filter
inside semgrep made the engines disagree about what had been scanned, while the
report presented their output as one result.

🔴 Measured on the repo's own deliberately-vulnerable corpus, which is gitignored:

    --engines secrets,aisec  ->  27 findings (6 CRITICAL)
    --engines sast           ->  "ran ... scan errors=0 (0 finding(s))"

Not a skip. A *successful clean scan* of a directory full of vulnerabilities —
the exact false-clean this tool exists to prevent, and it silently broke the
README's own "Verifying it works" procedure.

Asserted at the argv level, like the never-execute invariant tests: capture the
command PRAETOR would run without running it, so the test does not depend on
semgrep being installed.
"""

import subprocess

import engine_sast


class _FakeCompleted:
    def __init__(self, stdout):
        self.returncode = 0
        self.stdout = stdout
        self.stderr = ""


def _capture_argv(monkeypatch, tmp_path):
    """
    Route semgrep through a fake exec and record every argv it is handed.

    ⚠️ The engine probes `semgrep --version` first to pick a runtime. An earlier
    version of this fixture returned scan JSON to that probe, so runtime detection
    failed, the scan was never issued, and the tests asserted against the VERSION
    argv -- failing for a reason unrelated to what they exist to check. Answer the
    probe like semgrep would, and let the caller pick out the scan invocation.
    """
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        if "--version" in cmd:
            return _FakeCompleted("1.170.0\n")
        return _FakeCompleted('{"results": [], "errors": []}')

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(engine_sast.shutil, "which",
                        lambda name: "/usr/bin/semgrep" if name == "semgrep" else None)
    return calls


def _scan_argv(calls):
    """The actual scan invocation, not the version probe."""
    scans = [c for c in calls if "--json" in c]
    assert scans, f"semgrep scan was never invoked -- only: {calls}"
    return scans[0]


def test_semgrep_is_told_not_to_apply_gitignore(tmp_path, monkeypatch):
    """THE REGRESSION. Without this, a gitignored target scans as clean."""
    (tmp_path / "t.py").write_text("import os\n", encoding="utf-8")
    rules = tmp_path / "r.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    calls = _capture_argv(monkeypatch, tmp_path)

    # A real rules path matters: run() returns early with "no rules available"
    # when it has no config, and never reaches the semgrep invocation at all.
    engine_sast.run(str(tmp_path), str(rules), use_registry=False)

    argv = _scan_argv(calls)
    assert "--no-git-ignore" in argv, (
        "FALSE-CLEAN REGRESSION: semgrep will silently skip gitignored paths, so a "
        "target PRAETOR chose to scan can report 0 findings as a successful scan "
        f"while other engines find real ones. argv was: {argv}"
    )


def test_caller_exclusions_are_still_forwarded(tmp_path, monkeypatch):
    """Scope stays the caller's decision -- disabling git's filter is not 'scan everything'."""
    (tmp_path / "t.py").write_text("import os\n", encoding="utf-8")
    rules = tmp_path / "r.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    calls = _capture_argv(monkeypatch, tmp_path)

    engine_sast.run(str(tmp_path), str(rules), use_registry=False, excludes=["node_modules"])

    argv = _scan_argv(calls)
    assert "--exclude" in argv and "node_modules" in argv, (
        f"caller exclusions must still reach semgrep: {argv}"
    )
