"""SAST eligibility comes from the pinned rules, never a second language list.

This is the release guard for the shell-only G1 failure: shell is source code,
but this release has no pinned shell rule. That fact must be a named gap rather
than either a pass or a broken-engine result.
"""

import json
import os
from types import SimpleNamespace

import core
import engine_sast
import praetor
import report


_RULES = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                      "rules", "semgrep-praetor.yaml")


def _file(path):
    return SimpleNamespace(relpath=path, abspath=path)


def _result(status=core.ENGINE_OK, findings=None):
    return {
        "status": status,
        "findings": findings or [],
        "detail": "test semgrep completed",
        "runtime": "test-double",
    }


def _json_run(path, capsys, *extra):
    rc = praetor.main([
        str(path), "--engines", "sast,secrets,sca,aisec",
        "--format", "json", "--quiet", *extra,
    ])
    return rc, json.loads(capsys.readouterr().out)


def test_pinned_languages_are_derived_from_every_bundled_rule():
    assert engine_sast.pinned_rule_languages(_RULES) == frozenset({
        "python", "javascript", "typescript",
    })


def test_shell_is_not_eligible_without_a_pinned_shell_rule():
    """Named mutation guard: adding shell to eligibility alone must make this RED."""
    coverage = engine_sast.language_coverage([_file("build.sh")], _RULES)
    assert coverage["detected"] == frozenset({"shell"})
    assert coverage["covered"] == frozenset()
    assert coverage["uncovered"] == frozenset({"shell"})
    assert coverage["eligible_files"] == 0


def test_extensionless_git_hooks_and_deploy_hooks_are_named_shell_gaps():
    coverage = engine_sast.language_coverage([
        _file(".githooks/pre-commit"), _file("deploy/post-release.hook"),
    ], _RULES)
    assert coverage["detected"] == frozenset({"shell"})
    assert coverage["covered"] == frozenset()
    assert coverage["uncovered"] == frozenset({"shell"})
    assert coverage["eligible_files"] == 0


def test_extensionless_executable_names_are_never_silent():
    expected = {
        "Dockerfile": "dockerfile", "Dockerfile.dev": "dockerfile",
        "Makefile": "make", "Procfile": "shell", "Jenkinsfile": "groovy",
        "Vagrantfile": "ruby", "Gemfile": "ruby", "Rakefile": "ruby",
        "Berksfile": "ruby",
    }
    for name, language in expected.items():
        coverage = engine_sast.language_coverage([_file(name)], _RULES)
        assert coverage["detected"] == frozenset({language}), name
        assert coverage["covered"] == frozenset(), name
        assert coverage["uncovered"] == frozenset({language}), name


def test_dockerfile_prefix_never_steals_a_real_source_extension():
    python = engine_sast.language_coverage([_file("dockerfile_utils.py")], _RULES)
    dockerfile = engine_sast.language_coverage([_file("api.dockerfile")], _RULES)
    assert python["covered"] == frozenset({"python"})
    assert python["eligible_files"] == 1
    assert dockerfile["uncovered"] == frozenset({"dockerfile"})
    assert dockerfile["eligible_files"] == 0


def test_typescript_module_variants_are_named_until_semgrep_opens_them():
    coverage = engine_sast.language_coverage([
        _file("module.cts"), _file("module.mts"),
    ], _RULES)
    assert coverage["covered"] == frozenset()
    assert coverage["uncovered"] == frozenset({"typescript-module"})
    assert coverage["eligible_files"] == 0


def test_shell_only_reports_named_gap_and_other_engines_still_run(
        tmp_path, monkeypatch, capsys):
    (tmp_path / "build.sh").write_text("#!/bin/sh\nprintf '%s\\n' ok\n", encoding="utf-8")
    monkeypatch.setattr(
        engine_sast, "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Semgrep must not run when no requested rules are eligible")),
    )

    rc, doc = _json_run(tmp_path, capsys, "--no-registry", "--fail-on", "HIGH")
    engines = doc["meta"]["engines"]

    assert rc == 0
    assert engines["sast"] == {
        "status": core.ENGINE_NO_COVERAGE,
        "detail": "SAST: NO COVERAGE (shell)",
    }
    assert engines["secrets"]["status"] == core.ENGINE_OK
    assert engines["sca"]["status"] == core.ENGINE_NOT_APPLICABLE
    assert engines["aisec"]["status"] == core.ENGINE_OK


def test_dockerfile_only_reports_named_gap_instead_of_ok(
        tmp_path, monkeypatch, capsys):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    monkeypatch.setattr(
        engine_sast, "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Semgrep must not run when no requested rules are eligible")),
    )
    rc = praetor.main([
        str(tmp_path), "--engines", "sast", "--no-registry",
        "--format", "json", "--quiet", "--fail-on", "HIGH",
    ])
    doc = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert doc["meta"]["engines"]["sast"] == {
        "status": core.ENGINE_NO_COVERAGE,
        "detail": "SAST: NO COVERAGE (dockerfile)",
    }


def test_python_is_scanned_under_the_pinned_rules(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(kwargs)
        return _result()

    monkeypatch.setattr(engine_sast, "run", fake_run)
    rc = praetor.main([
        str(tmp_path), "--engines", "sast", "--no-registry",
        "--format", "json", "--quiet", "--fail-on", "HIGH",
    ])
    doc = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert len(calls) == 1
    assert calls[0]["enumerated_code_files"] == 1
    assert doc["meta"]["engines"]["sast"]["status"] == core.ENGINE_OK


def test_optional_rules_may_find_shell_but_cannot_claim_pinned_coverage(
        tmp_path, monkeypatch, capsys):
    (tmp_path / "build.sh").write_text("echo ok\n", encoding="utf-8")
    finding = core.Finding(
        engine="sast", rule_id="optional-shell", title="optional shell finding",
        severity=core.Severity.HIGH, confidence=core.Confidence.HIGH,
        file="build.sh", line=1,
    )
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(kwargs)
        return _result(findings=[finding])

    monkeypatch.setattr(engine_sast, "run", fake_run)
    rc = praetor.main([
        str(tmp_path), "--engines", "sast", "--format", "json", "--quiet",
        "--fail-on", "HIGH",
    ])
    doc = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert calls[0]["enumerated_code_files"] == 0
    assert doc["meta"]["engines"]["sast"] == {
        "status": core.ENGINE_NO_COVERAGE,
        "detail": "SAST: NO COVERAGE (shell)",
    }
    assert any(item["rule_id"] == "optional-shell" for item in doc["findings"])


def test_mixed_python_and_shell_is_scanned_and_names_the_shell_gap(
        tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "build.sh").write_text("echo ok\n", encoding="utf-8")
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(kwargs)
        return _result()

    monkeypatch.setattr(engine_sast, "run", fake_run)
    rc = praetor.main([
        str(tmp_path), "--engines", "sast", "--no-registry",
        "--format", "json", "--quiet", "--fail-on", "HIGH",
    ])
    doc = json.loads(capsys.readouterr().out)
    sast = doc["meta"]["engines"]["sast"]

    assert rc == 0
    assert calls[0]["enumerated_code_files"] == 1
    assert sast["status"] == core.ENGINE_OK
    assert sast["detail"].endswith("; SAST: NO COVERAGE (shell)")

    block = report._engine_status_block({"engines": {"sast": sast}})
    assert any("[ran+GAP]" in line for line in block)


def test_mixed_python_and_extensionless_hook_names_the_shell_gap(
        tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    hooks = tmp_path / ".githooks"
    hooks.mkdir()
    (hooks / "post-merge").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    monkeypatch.setattr(engine_sast, "run", lambda *args, **kwargs: _result())

    rc = praetor.main([
        str(tmp_path), "--engines", "sast", "--no-registry",
        "--format", "text", "--quiet", "--fail-on", "HIGH",
    ])
    text = capsys.readouterr().out

    assert rc == 0
    assert "[ran+GAP]" in text
    assert "SAST: NO COVERAGE (shell)" in text


def test_mixed_python_and_makefile_names_the_make_gap(
        tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "Makefile").write_text("all:\n\t@echo ok\n", encoding="utf-8")
    monkeypatch.setattr(engine_sast, "run", lambda *args, **kwargs: _result())

    rc = praetor.main([
        str(tmp_path), "--engines", "sast", "--no-registry",
        "--format", "text", "--quiet", "--fail-on", "HIGH",
    ])
    text = capsys.readouterr().out

    assert rc == 0
    assert "[ran+GAP]" in text
    assert "SAST: NO COVERAGE (make)" in text


def test_mixed_python_and_mts_names_the_runtime_gap(
        tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "module.mts").write_text("export const x = 1;\n", encoding="utf-8")
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(kwargs)
        return _result()

    monkeypatch.setattr(engine_sast, "run", fake_run)
    rc = praetor.main([
        str(tmp_path), "--engines", "sast", "--no-registry",
        "--format", "text", "--quiet", "--fail-on", "HIGH",
    ])
    text = capsys.readouterr().out

    assert rc == 0
    assert calls[0]["enumerated_code_files"] == 1
    assert "[ran+GAP]" in text
    assert "SAST: NO COVERAGE (typescript-module)" in text


def test_shell_gap_reaches_sarif_as_a_warning_notification(tmp_path, capsys):
    (tmp_path / "build.sh").write_text("echo ok\n", encoding="utf-8")
    rc = praetor.main([
        str(tmp_path), "--engines", "sast", "--no-registry",
        "--format", "sarif", "--quiet", "--fail-on", "HIGH",
    ])
    doc = json.loads(capsys.readouterr().out)
    invocation = doc["runs"][0]["invocations"][0]
    notes = invocation.get("toolExecutionNotifications") or []

    assert rc == 0
    assert invocation["executionSuccessful"] is True
    assert any(
        note["descriptor"]["id"] == "praetor-sast-no-coverage"
        and note["message"]["text"] == "SAST: NO COVERAGE (shell)"
        for note in notes
    )


def test_adding_a_real_pinned_shell_rule_enables_shell(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n  - id: shell-rule\n    languages: [bash]\n"
        "    severity: WARNING\n    message: shell\n    pattern: echo $X\n",
        encoding="ascii",
    )
    coverage = engine_sast.language_coverage([_file("build.sh")], str(rules))
    assert coverage["covered"] == frozenset({"shell"})
    assert coverage["uncovered"] == frozenset()
    assert coverage["eligible_files"] == 1


def test_missing_or_malformed_pinned_rules_fail_closed(tmp_path):
    missing = tmp_path / "missing.yaml"
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("rules:\n  - id: missing-languages\n", encoding="ascii")

    for path in (missing, malformed):
        try:
            engine_sast.language_coverage([_file("app.py")], str(path))
        except engine_sast.RulesetEligibilityError:
            pass
        else:
            raise AssertionError(f"{path.name} did not fail closed")


def test_language_map_never_claims_files_the_walker_does_not_admit():
    assert set(engine_sast._LANGUAGE_BY_EXTENSION) <= set(core.TEXT_EXTS)


def test_every_walker_code_extension_has_a_named_language():
    assert set(core.CODE_EXTS) <= set(engine_sast._LANGUAGE_BY_EXTENSION)


def test_every_named_language_is_a_file_the_walker_admits():
    assert set(engine_sast._LANGUAGE_BY_BASENAME) <= set(core.TEXT_NAMES)


def test_every_walker_text_name_has_an_explicit_sast_decision():
    mapped = set(engine_sast._LANGUAGE_BY_BASENAME)
    hooks = set(core.GIT_HOOK_NAMES)
    excluded = set(engine_sast._NON_SAST_TEXT_NAMES)
    assert not (mapped & hooks or mapped & excluded or hooks & excluded)
    assert mapped | hooks | excluded == set(core.TEXT_NAMES)


def test_every_walker_text_extension_has_an_explicit_sast_decision():
    mapped = set(engine_sast._LANGUAGE_BY_EXTENSION)
    excluded = set(engine_sast._NON_SAST_TEXT_EXTENSIONS)
    assert not (mapped & excluded)
    assert mapped | excluded == set(core.TEXT_EXTS)
