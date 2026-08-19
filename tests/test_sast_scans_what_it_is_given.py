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

import json
import subprocess

import engine_sast


class _FakeCompleted:
    def __init__(self, stdout):
        self.returncode = 0
        self.stdout = stdout
        self.stderr = ""


def _capture_argv(monkeypatch, tmp_path, scan_payload='{"results": [], "errors": []}'):
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
        return _FakeCompleted(scan_payload)

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


def test_caller_regex_exclusions_are_not_forwarded_as_semgrep_globs(tmp_path, monkeypatch):
    """One option cannot mean regex to PRAETOR and glob to Semgrep.

    SAST still receives the target for static analysis, then applies the caller's
    documented regex to normalized findings. Passing it to Semgrep would make a
    regex anchor a no-op and make a valid glob an invalid PRAETOR argument.
    """
    (tmp_path / "t.py").write_text("import os\n", encoding="utf-8")
    rules = tmp_path / "r.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    calls = _capture_argv(monkeypatch, tmp_path)

    exclusion = r"^generated/"
    engine_sast.run(str(tmp_path), str(rules), use_registry=False, excludes=[exclusion])

    argv = _scan_argv(calls)
    assert exclusion not in argv, (
        "caller regexes must not be handed to Semgrep's glob-only --exclude; "
        f"argv was: {argv}"
    )


def test_caller_regex_exclusions_filter_normalized_sast_findings(tmp_path, monkeypatch):
    """KEEP DIRECTION: removing Semgrep forwarding must not expose excluded findings."""
    generated = tmp_path / "generated"
    generated.mkdir()
    source = generated / "app.py"
    source.write_text("unsafe()\n", encoding="utf-8")
    rules = tmp_path / "r.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    payload = json.dumps({
        "results": [{
            "path": str(source),
            "check_id": "test.rule",
            "start": {"line": 1}, "end": {"line": 1},
            "extra": {"severity": "WARNING", "message": "test finding", "metadata": {}},
        }],
        "paths": {"scanned": ["generated/app.py"]},
    })
    _capture_argv(monkeypatch, tmp_path, payload)

    control = engine_sast.run(str(tmp_path), str(rules), use_registry=False,
                               enumerated_code_files=1)
    excluded = engine_sast.run(str(tmp_path), str(rules), use_registry=False,
                                excludes=[r"^generated/"], enumerated_code_files=1)

    assert control["findings"], "arming control: Semgrep result was not normalized"
    assert excluded["findings"] == [], (
        "the documented regex exclusion must remove the same SAST finding from "
        f"the report; got {excluded['findings']}"
    )


def test_semgrep_file_errors_are_not_certified_as_a_clean_sast_scan(tmp_path, monkeypatch):
    """A parser error is missing SAST coverage, not an ordinary zero finding."""
    source = tmp_path / "settings.py"
    source.write_bytes(b"\x00x = 1\n")
    rules = tmp_path / "r.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    payload = json.dumps({
        "results": [],
        "errors": [{"type": "ParseError", "path": str(source), "message": "invalid source"}],
        "paths": {"scanned": ["settings.py"]},
    })
    _capture_argv(monkeypatch, tmp_path, payload)

    res = engine_sast.run(str(tmp_path), str(rules), use_registry=False,
                          enumerated_code_files=1)

    assert res["findings"] == [], "fixture premise: Semgrep returned no findings"
    assert res["status"] == "error", (
        "Semgrep reported a file it could not parse, so SAST cannot claim an ok "
        f"scan; got {res['status']!r} ({res['detail']})"
    )
    assert "scan errors=1" in res["detail"], "the operator needs the error count"
