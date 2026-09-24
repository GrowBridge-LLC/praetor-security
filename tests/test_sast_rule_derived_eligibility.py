"""SAST eligibility comes from pinned rules, never an extension allowlist."""

import builtins
import json
import os
from pathlib import Path
import re
import subprocess

import pytest
import yaml

import core
import engine_sast
import praetor
import report


_REAL_DETECT_RUNTIME = engine_sast.detect_runtime
_REAL_RESOLVE_RULE_SOURCE = engine_sast._resolve_rule_source
_REAL_FILENAME_EXTENSIONS = engine_sast._runtime_filename_extensions


@pytest.fixture(autouse=True)
def _resolve_rules_without_requiring_a_live_semgrep(monkeypatch):
    """Unit predicates stay runnable when the optional Semgrep CLI is absent.

    Parser fidelity is tested separately against captured dump output below;
    these orchestration tests need a deterministic already-resolved rule list.
    """
    monkeypatch.setattr(engine_sast, "detect_runtime", lambda *a, **kw: {
        "mode": "native", "prefix": ["semgrep"], "available": True,
        "detail": "test resolver", "version": "pinned-test-version",
    })

    # Captured from the pinned engine, not a second admission policy.
    metadata = (Path(__file__).parent / "fixtures/semgrep-1.177.0-extensions.txt").read_text()
    extensions = {line.strip().split("->")[0]: tuple(line.split("->")[1].split(", "))
                  for line in metadata.splitlines()[1:]}
    monkeypatch.setattr(engine_sast, "_runtime_filename_extensions",
                        lambda *a, **kw: extensions)

    def resolve(config, runtime, timeout=engine_sast._SEMGREP_TIMEOUT):
        del runtime, timeout
        path = Path(config)
        if path.is_dir():
            paths = sorted(path.rglob("*.yaml"))
        elif path.is_file():
            paths = [path]
        else:
            return None
        all_rules = []
        for source in paths:
            resolved = _resolved_file(source)
            if resolved is None:
                return None
            all_rules.extend(resolved)
        return all_rules

    def _resolved_file(path):
        try:
            document = yaml.safe_load(path.read_text(encoding="ascii"))
        except (OSError, UnicodeError, yaml.YAMLError):
            return None
        raw_rules = document.get("rules") if isinstance(document, dict) else None
        if not isinstance(raw_rules, list):
            return None
        resolved = []
        for rule in raw_rules:
            if not isinstance(rule, dict):
                return None
            languages = rule.get("languages")
            if not isinstance(languages, list):
                return None
            if not all(key in rule for key in ("id", "message", "severity")):
                return None
            if not any(str(key).startswith("pattern") for key in rule):
                return None
            paths = rule.get("paths") or {}
            resolved.append({
                "languages": frozenset(str(item).lower() for item in languages),
                "has_include": bool(paths.get("include")),
            })
        return resolved

    monkeypatch.setattr(engine_sast, "_resolve_rule_source", resolve)


def _run_json(target, capsys, *extra):
    rc = praetor.main([
        str(target), "--format", "json", "--quiet", "--no-registry",
        *extra,
    ])
    return rc, json.loads(capsys.readouterr().out)


def _write_rule(path, language, *, include=None):
    pattern_key = "pattern-regex" if language in {"generic", "regex", "none"} else "pattern"
    pattern = "echo ..." if language in {"bash", "sh"} else "eval(...)"
    paths = (
        "    paths:\n"
        f"      include: [{include}]\n"
        if include else ""
    )
    path.write_text(
        "rules:\n"
        "  - id: eligibility-fixture\n"
        f"    languages: [{language}]\n"
        "    severity: WARNING\n"
        "    message: fixture\n"
        f"{paths}"
        f"    {pattern_key}: {pattern}\n",
        encoding="ascii",
    )


def test_p_shell_gap_with_measured_secrets_satisfies_the_floor(
        tmp_path, monkeypatch, capsys):
    """3A guard: shell is not eligible merely because its extension is known."""
    (tmp_path / "build.sh").write_text("#!/bin/sh\necho ready\n", encoding="utf-8")

    calls = []
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run(calls))
    rc, payload = _run_json(tmp_path, capsys, "--fail-on", "HIGH")
    engines = payload["meta"]["engines"]

    assert rc == 0, "a named missing-rules gap is not a Semgrep malfunction"
    assert len(calls) == 1
    assert engines["sast"]["status"] == core.ENGINE_NO_COVERAGE
    assert "SAST: NO COVERAGE (shell)" in engines["sast"]["detail"]
    assert engines["secrets"]["status"] == core.ENGINE_OK
    assert engines["aisec"]["status"] == core.ENGINE_OK
    assert engines["sca"]["status"] == core.ENGINE_NOT_APPLICABLE


def test_python_with_a_pinned_ruleset_reaches_sast(tmp_path, monkeypatch, capsys):
    """Keep direction: rule-derived eligibility still launches SAST for Python."""
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    calls = []

    def fake_run(target, bundled_rules, **kwargs):
        calls.append((target, bundled_rules, kwargs))
        return {"findings": [], "status": core.ENGINE_OK,
                "detail": "pinned rules scanned Python", "runtime": "test-double"}

    monkeypatch.setattr(engine_sast, "run", fake_run)
    rc, payload = _run_json(tmp_path, capsys, "--engines", "sast")

    assert rc == 0
    assert len(calls) == 1, "Python must still reach the SAST engine"
    assert os.path.samefile(calls[0][1], praetor.BUNDLED_SEMGREP)
    assert calls[0][2]["enumerated_code_files"] == 1
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_OK


def test_python_shebang_hook_reaches_sast_without_filename_coverage(
        tmp_path, monkeypatch, capsys):
    """A hook's interpreter is evidence even when its name looks like shell."""
    (tmp_path / "pre-commit").write_text(
        "#!/usr/bin/env python3\neval(user_input)\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run(calls))

    rc, payload = _run_json(tmp_path, capsys, "--engines", "sast")

    sast = payload["meta"]["engines"]["sast"]
    assert rc == 0
    assert sast["status"] == core.ENGINE_OK
    assert "SAST: python covered by pinned rules" in sast["detail"]
    assert "SAST: NO COVERAGE" not in sast["detail"]
    assert calls[-1]["enumerated_code_files"] == 1
    assert calls[-1]["shebang_targets"] == (str(tmp_path / "pre-commit"),)


@pytest.mark.parametrize("name,language", [
    ("build.sh", "shell"), ("main.go", "go"),
    ("run.rb", "ruby"), ("setup.ps1", "powershell"),
])
def test_single_uncovered_language_has_named_gap_through_main(
        name, language, tmp_path, monkeypatch, capsys):
    (tmp_path / name).write_text("ordinary source\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run(calls))

    rc, payload = _run_json(tmp_path, capsys, "--engines", "sast")

    sast = payload["meta"]["engines"]["sast"]
    assert rc == 0
    assert sast["status"] == core.ENGINE_NO_COVERAGE
    assert sast["detail"] == f"SAST: NO COVERAGE ({language})"
    assert calls[-1]["enumerated_code_files"] == 0


def test_python_and_shell_report_both_coverage_states_through_main(
        tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "build.sh").write_text("echo ready\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run(calls))

    rc, payload = _run_json(tmp_path, capsys, "--engines", "sast")

    sast = payload["meta"]["engines"]["sast"]
    assert rc == 0
    assert sast["status"] == core.ENGINE_OK
    assert "SAST: python covered by pinned rules" in sast["detail"]
    assert "SAST: NO COVERAGE (shell)" in sast["detail"]
    assert calls[-1]["enumerated_code_files"] == 1


def test_mixed_target_names_each_uncovered_language_while_scanning_covered_code(
        tmp_path, monkeypatch, capsys):
    """An eligible file must not make an uncovered sibling language silent."""
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "build.sh").write_text("echo ready\n", encoding="utf-8")
    monkeypatch.setattr(
        engine_sast, "run",
        lambda *a, **kw: {"findings": [], "status": core.ENGINE_OK,
                          "detail": "pinned rules scanned Python", "runtime": "test-double"},
    )

    rc, payload = _run_json(tmp_path, capsys, "--engines", "sast")

    assert rc == 0
    sast = payload["meta"]["engines"]["sast"]
    assert sast["status"] == core.ENGINE_OK
    assert "SAST: NO COVERAGE (shell)" in sast["detail"]


def test_mixed_target_text_marks_the_run_and_the_gap():
    result = {"active": [], "filtered": [], "summary": {},
              "total_active": 0, "total_filtered": 0}
    meta = {
        "target": "fixture", "timestamp": "now", "version": "test",
        "file_count": 2, "engines": {
            "sast": {"status": core.ENGINE_OK,
                     "detail": "pinned Python rules ran; SAST: NO COVERAGE (shell)"},
        },
    }
    text = report.render_text(result, meta)
    assert "[ran+GAP]" in text
    assert "SAST: NO COVERAGE (shell)" in text


def test_pinned_rule_languages_are_read_from_the_ruleset_not_a_claim():
    """Mutation guard: adding shell eligibility without a rule makes this RED."""
    coverage = engine_sast.language_coverage(
        ["example.py", "example.js", "example.ts", "example.sh"],
        praetor.BUNDLED_SEMGREP,
    )

    assert coverage["pinned"] == frozenset({"python", "javascript", "typescript"})
    assert coverage["covered"] == frozenset({"python", "javascript", "typescript"})
    assert coverage["uncovered"] == frozenset({"shell"})


def test_every_recognized_sast_extension_is_walkable():
    assert set(engine_sast._LANGUAGE_BY_EXTENSION) <= set(core.TEXT_EXTS)


def test_every_walker_source_kind_reaches_sast_without_a_silent_gap(
        tmp_path, monkeypatch, capsys):
    """Exhaustive partition plus the real walker/coverage/status/exit pipeline.

    Only runtime resolution and the external Semgrep result are test doubles.
    In particular, an external `ok` must not certify omitted-only source.
    Historical omissions are independent expectations, not copies of the live
    classifier: removing one from the shared authority must make this test red.
    """
    omitted = {
        ".cts": "typescript-module", ".mts": "typescript-module",
        ".bat": "batch", ".cmd": "batch", ".erb": "ruby",
        ".groovy": "groovy", ".hook": "shell", ".pl": "perl",
        ".pp": "puppet", ".ps1": "powershell", ".psm1": "powershell",
        ".r": "r", ".sql": "sql", ".svelte": "svelte", ".zsh": "shell",
        ".dockerfile": "dockerfile", ".graphql": "graphql",
        ".handlebars": "handlebars", ".hbs": "handlebars",
        ".htm": "html", ".html": "html", ".proto": "protobuf",
    }
    basenames = {
        "Dockerfile": "dockerfile", "Makefile": "make", "Procfile": "shell",
        "Jenkinsfile": "groovy", "Vagrantfile": "ruby", "Gemfile": "ruby",
        "Rakefile": "ruby", "Berksfile": "ruby",
    }
    hooks = {
        "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit",
        "pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-commit",
        "pre-rebase", "post-checkout", "post-merge", "pre-push", "pre-receive",
        "update", "proc-receive", "post-receive", "post-update",
        "reference-transaction", "push-to-checkout", "pre-auto-gc",
        "post-rewrite", "sendemail-validate", "fsmonitor-watchman",
        "post-index-change",
    }
    assert hooks <= core.GIT_HOOK_NAMES
    cases = {"source" + ext: language for ext, language in omitted.items()}
    cases.update(basenames)
    cases.update({".git/hooks/" + name: "shell" for name in sorted(core.GIT_HOOK_NAMES)})
    variants = ("Dockerfile.dev", "Dockerfile.prod", "Dockerfile.test",
                "dockerfile.local", "DOCKERFILE.ci")
    cases.update(dict.fromkeys(variants, "dockerfile"))
    calls = []
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run(calls))
    for index, (name, language) in enumerate(cases.items()):
        target = tmp_path / str(index)
        path = target / name
        path.parent.mkdir(parents=True)
        path.write_text("# source fixture\n", encoding="utf-8")
        for mixed in (False, True):
            if mixed:
                (target / "covered.py").write_text("value = 1\n", encoding="utf-8")
            before = len(calls)
            rc = praetor.main([
                str(target), "--format", "json", "--quiet", "--no-registry",
                "--engines", "sast", "--fail-on", "HIGH",
            ])
            captured = capsys.readouterr()
            payload = json.loads(captured.out)
            sast = payload["meta"]["engines"]["sast"]
            assert len(calls) == before + 1, (name, mixed, sast)
            eligible = calls[-1]["enumerated_code_files"]
            assert not (sast["status"] == core.ENGINE_OK and eligible == 0
                        and "SAST: NO COVERAGE (" not in sast["detail"]), (
                f"silent SAST false-ok for {name}: eligible_files={eligible}; {sast}"
            )
            assert f"SAST: NO COVERAGE ({language})" in sast["detail"], (name, sast)
            assert eligible == int(mixed), (name, mixed, calls[-1])
            assert sast["status"] == (
                core.ENGINE_OK if mixed else core.ENGINE_NO_COVERAGE
            ), (name, mixed, sast)
            assert rc == (0 if mixed else 3), (name, mixed, captured.err)
            if not mixed:
                # Git-owned hooks remain excluded from the target-code census;
                # their earlier scope floor must not be disarmed by this fix.
                floor = ("NO CODE WAS EXAMINED" if name.startswith(".git/")
                         else "NOTHING WAS MEASURED")
                assert floor in captured.err, (name, captured.err)
            if mixed:
                assert "SAST: python covered by pinned rules" in sast["detail"]
        assert core.source_language(name) == language

    # Every finite walker kind is explicitly partitioned, including the old
    # executable population and the non-SAST text kinds. A new kind must be
    # classified at its single admission authority, never an engine-local list.
    historical_code = set("""
        .py .pyi .js .jsx .ts .tsx .mjs .cjs .cts .mts .vue .svelte .java .kt
        .kts .scala .groovy .go .rs .rb .php .c .h .cc .cpp .hpp .cs .swift .m
        .mm .dart .sh .bash .zsh .ps1 .psm1 .bat .cmd .pl .lua .r .sql .pp .erb .hook
    """.split())
    assert historical_code <= core.CODE_EXTS
    assert not (set(core.SOURCE_LANGUAGE_BY_EXTENSION) & core.NON_SAST_TEXT_EXTS)
    assert core.TEXT_EXTS == set(core.SOURCE_LANGUAGE_BY_EXTENSION) | core.NON_SAST_TEXT_EXTS
    assert not (set(core.SOURCE_LANGUAGE_BY_BASENAME) & core.NON_SAST_TEXT_NAMES)
    assert core.TEXT_NAMES == set(core.SOURCE_LANGUAGE_BY_BASENAME) | core.NON_SAST_TEXT_NAMES
    assert engine_sast._LANGUAGE_BY_EXTENSION is core.SOURCE_LANGUAGE_BY_EXTENSION
    names = ["source" + ext for ext in core.TEXT_EXTS] + sorted(core.TEXT_NAMES)
    names += [".env.staging", "Dockerfile.dev", "Dockerfile.py"]
    for name in names:
        assert core.scannable(name), name
        language = core.source_language(name)
        assert language is not None, f"unclassified walker kind: {name}"
        coverage = engine_sast.language_coverage([name], praetor.BUNDLED_SEMGREP)
        assert coverage["detected"] == ({language} if language else set()), name
        if core.is_code(name):
            assert language, f"executable kind misclassified as non-SAST: {name}"
        if language and language not in coverage["covered"]:
            assert f"SAST: NO COVERAGE ({language})" in engine_sast.coverage_detail(coverage)
        if not language:
            assert not coverage["eligible_files"], name
    # Keep the scope floor's intentionally narrower definition unchanged.
    for ext in core.OTHER_SOURCE_LANGUAGE_BY_EXTENSION.keys() | core.NON_SAST_TEXT_EXTS:
        assert not core.is_code("source" + ext), ext
    assert core.source_language("opaque.unknown-kind") is None
    print(f"partition: {len(core.TEXT_EXTS)} extensions, {len(core.TEXT_NAMES)} names; "
          f"orchestration: {len(cases)} source kinds x omitted-only/mixed = {len(calls)} runs")


def test_declaring_shell_eligible_without_a_pinned_rule_goes_red():
    """Named mutation guard for the downstream receipt adapter's compatibility API."""
    assert engine_sast.count_code_files(["build.sh"], praetor.BUNDLED_SEMGREP) == 0
    assert engine_sast.count_code_files(["app.py"], praetor.BUNDLED_SEMGREP) == 1


def test_a_missing_pinned_rules_artifact_blocks_instead_of_becoming_no_coverage(
        tmp_path, monkeypatch, capsys):
    """Missing rules are a scanner error, not an empty eligibility population."""
    missing = tmp_path / "missing-rules.yaml"
    target = tmp_path / "target"
    target.mkdir()
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    monkeypatch.setattr(praetor, "BUNDLED_SEMGREP", str(missing))

    rc, payload = _run_json(target, capsys, "--engines", "sast")

    assert rc == 3
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_ERROR
    assert "pinned SAST rules unavailable" in payload["meta"]["engines"]["sast"]["detail"]


@pytest.mark.parametrize("contents", [
    "",
    "rules:\n  - id: broken\n    message: |\n      languages: [shell]\n",
])
def test_empty_or_malformed_pinned_rules_block_through_main(
        contents, tmp_path, monkeypatch, capsys):
    rules = tmp_path / "rules.yaml"
    rules.write_text(contents, encoding="ascii")
    target = tmp_path / "target"
    target.mkdir()
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    monkeypatch.setattr(praetor, "BUNDLED_SEMGREP", str(rules))
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run([]))

    rc, payload = _run_json(target, capsys, "--engines", "sast")

    assert rc == 3
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_ERROR
    assert "malformed" in payload["meta"]["engines"]["sast"]["detail"]


def test_unreadable_pinned_rules_block_through_main(tmp_path, monkeypatch, capsys):
    rules = tmp_path / "rules.yaml"
    _write_rule(rules, "python")
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(praetor, "BUNDLED_SEMGREP", str(rules))
    real_open = builtins.open

    def deny_rules(path, *args, **kwargs):
        if os.path.abspath(os.fspath(path)) == os.path.abspath(rules):
            raise PermissionError("fixture denies pinned rules")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", deny_rules)
    rc, payload = _run_json(target, capsys, "--engines", "sast")

    assert rc == 3
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_ERROR
    assert "pinned SAST rules unavailable" in payload["meta"]["engines"]["sast"]["detail"]


def test_unresolved_pinned_rules_block_through_main(tmp_path, monkeypatch, capsys):
    rules = tmp_path / "rules.yaml"
    _write_rule(rules, "python")
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(praetor, "BUNDLED_SEMGREP", str(rules))
    monkeypatch.setattr(engine_sast, "_resolve_rule_source", lambda *a, **kw: None)

    rc, payload = _run_json(target, capsys, "--engines", "sast")

    assert rc == 3
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_ERROR
    assert "SAST rule source unresolved: pinned rules" in (
        payload["meta"]["engines"]["sast"]["detail"]
    )


def _zero_finding_run(calls):
    def fake_run(target, bundled_rules, **kwargs):
        calls.append(kwargs)
        return {"findings": [], "status": core.ENGINE_OK,
                "detail": "operator rules ran", "runtime": "test-double"}
    return fake_run


def test_operator_bash_rule_covers_shell_and_removing_it_restores_gap(
        tmp_path, monkeypatch, capsys):
    """Predicate (a): one validated bash rule is coverage; no rule is not."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    config = tmp_path / "operator.yaml"
    _write_rule(config, "bash")
    calls = []
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run(calls))

    rc, payload = _run_json(
        target, capsys, "--engines", "sast", "--semgrep-config", str(config),
    )
    detail = payload["meta"]["engines"]["sast"]["detail"]
    assert rc == 0
    assert f"SAST: shell covered by operator config {config} (1 rule)" in detail
    assert "NO COVERAGE (shell)" not in detail

    config.write_text("rules: []\n", encoding="ascii")
    rc, payload = _run_json(
        target, capsys, "--engines", "sast", "--semgrep-config", str(config),
    )
    assert rc == 0
    assert "SAST: NO COVERAGE (shell)" in payload["meta"]["engines"]["sast"]["detail"]


def test_zero_findings_do_not_remove_operator_rule_coverage(
        tmp_path, monkeypatch, capsys):
    """Predicate (b): the rule list, never findings, establishes coverage."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    config = tmp_path / "operator.yaml"
    _write_rule(config, "bash")
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run([]))

    rc, payload = _run_json(
        target, capsys, "--engines", "sast", "--semgrep-config", str(config),
    )

    assert rc == 0
    assert payload["summary"]["active"] == 0
    assert "SAST: shell covered" in payload["meta"]["engines"]["sast"]["detail"]


def test_generic_only_operator_config_does_not_cover_shell(
        tmp_path, monkeypatch, capsys):
    """Predicate (c): generic, regex, and none are not language coverage."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    config = tmp_path / "operator.yaml"
    _write_rule(config, "generic")
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run([]))

    rc, payload = _run_json(
        target, capsys, "--engines", "sast", "--semgrep-config", str(config),
    )

    assert rc == 0
    assert "SAST: NO COVERAGE (shell)" in payload["meta"]["engines"]["sast"]["detail"]


def test_paths_include_rule_does_not_cover_shell(
        tmp_path, monkeypatch, capsys):
    """Predicate (d): any paths.include makes the rule ineligible."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    config = tmp_path / "operator.yaml"
    _write_rule(config, "bash", include="scripts/**")
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run([]))

    rc, payload = _run_json(
        target, capsys, "--engines", "sast", "--semgrep-config", str(config),
    )

    assert rc == 0
    assert "SAST: NO COVERAGE (shell)" in payload["meta"]["engines"]["sast"]["detail"]


def test_operator_config_inside_scanned_target_never_counts(
        tmp_path, monkeypatch, capsys):
    """Predicate (e): target-controlled config is outside the coverage trust root."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    config = target / "operator.yaml"
    _write_rule(config, "bash")
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run([]))

    rc, payload = _run_json(
        target, capsys, "--engines", "sast", "--semgrep-config", str(config),
    )

    assert rc == 0
    detail = payload["meta"]["engines"]["sast"]["detail"]
    assert "SAST: NO COVERAGE (shell)" in detail
    assert f"operator config {config}" in detail


def test_operator_config_inside_target_still_runs_and_preserves_findings(
        tmp_path, monkeypatch, capsys):
    """The trust boundary removes coverage authority, not explicit scan rules."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    config = target / "operator.yaml"
    _write_rule(config, "bash")
    calls = []

    def matching_high(*args, **kwargs):
        calls.append(kwargs)
        return {
            "findings": [core.Finding(
                engine="sast", rule_id="eligibility-fixture", title="fixture",
                severity=core.Severity.HIGH, file="build.sh", line=1,
            )],
            "status": core.ENGINE_OK,
            "detail": "operator rule ran",
            "runtime": "test-double",
        }

    monkeypatch.setattr(engine_sast, "run", matching_high)
    rc, payload = _run_json(
        target, capsys, "--semgrep-config", str(config), "--fail-on", "HIGH",
    )

    assert rc == 1
    assert len(calls) == 1
    assert calls[0]["extra_configs"] == [str(config)]
    sast = payload["meta"]["engines"]["sast"]
    assert sast["status"] == core.ENGINE_NO_COVERAGE
    assert "SAST: NO COVERAGE (shell)" in sast["detail"]
    assert payload["summary"]["active"] >= 1


def test_operator_config_directory_ancestor_of_target_never_counts(
        tmp_path, monkeypatch, capsys):
    """A directory source must not recursively import target-owned YAML."""
    config_dir = tmp_path / "configs"
    target = config_dir / "target"
    target.mkdir(parents=True)
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    _write_rule(target / "target-owned.yaml", "bash")
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run([]))

    rc, payload = _run_json(
        target, capsys, "--engines", "sast", "--semgrep-config", str(config_dir),
    )

    assert rc == 0
    detail = payload["meta"]["engines"]["sast"]["detail"]
    assert "SAST: NO COVERAGE (shell)" in detail
    assert f"operator config {config_dir}" in detail


def test_pinned_rules_alone_do_not_cover_shell(tmp_path, monkeypatch, capsys):
    """Predicate (f): TheFact0ry's pinned-only shell case stays a named gap."""
    (tmp_path / "build.sh").write_text("echo ready\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run(calls))

    rc, payload = _run_json(tmp_path, capsys, "--engines", "sast")

    assert rc == 0
    assert len(calls) == 1
    assert payload["meta"]["engines"]["sast"]["detail"] == "SAST: NO COVERAGE (shell)"


def _hidden_pinned_finding_run(calls):
    def run(*args, **kwargs):
        calls.append(kwargs)
        return {
            "findings": [core.Finding(
                engine="sast", rule_id="hidden-pinned-finding",
                title="hidden pinned finding", severity=core.Severity.HIGH,
                file="hidden-target", line=2,
            )],
            "status": core.ENGINE_OK,
            "detail": "pinned rules scanned Semgrep-visible targets",
            "runtime": "test-double",
        }
    return run


def test_uncovered_file_cannot_skip_sast_finding_in_unclassified_shebang_target(
        tmp_path, monkeypatch, capsys):
    (tmp_path / "build.sh").write_text("echo ready\n", encoding="utf-8")
    (tmp_path / "hidden-target").write_text(
        "#!/usr/bin/env python3\neval(user_input)\n", encoding="utf-8"
    )
    calls = []
    monkeypatch.setattr(engine_sast, "run", _hidden_pinned_finding_run(calls))

    rc, payload = _run_json(tmp_path, capsys, "--fail-on", "HIGH")

    assert rc == 1
    assert len(calls) == 1
    assert payload["summary"]["active"] >= 1
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_NO_COVERAGE
    assert "SAST: NO COVERAGE (shell)" in payload["meta"]["engines"]["sast"]["detail"]


def test_uncovered_file_cannot_skip_sast_finding_in_binary_dropped_python(
        tmp_path, monkeypatch, capsys):
    (tmp_path / "build.sh").write_text("echo ready\n", encoding="utf-8")
    (tmp_path / "hidden.py").write_bytes(
        b"# " + (b"\x01" * 3000) + b"\neval(user_input)\n"
    )
    calls = []
    monkeypatch.setattr(engine_sast, "run", _hidden_pinned_finding_run(calls))

    rc, payload = _run_json(tmp_path, capsys, "--fail-on", "HIGH")

    assert rc == 1
    assert len(calls) == 1
    assert payload["summary"]["active"] >= 1
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_NO_COVERAGE
    assert "SAST: NO COVERAGE (shell)" in payload["meta"]["engines"]["sast"]["detail"]


def test_unresolved_operator_config_fails_closed_and_names_the_source(
        tmp_path, monkeypatch, capsys):
    """Predicate (g): an unresolved effective source is an eligibility error."""
    (tmp_path / "build.sh").write_text("echo ready\n", encoding="utf-8")
    pack = "p/offline-fixture"
    real_resolve = engine_sast._resolve_rule_source

    def offline_pack(config, runtime, timeout=60):
        return None if config == pack else real_resolve(config, runtime, timeout)

    monkeypatch.setattr(engine_sast, "_resolve_rule_source", offline_pack)
    monkeypatch.setattr(
        engine_sast, "run",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("SAST must not launch")),
    )
    rc, payload = _run_json(
        tmp_path, capsys, "--engines", "sast", "--semgrep-config", pack,
    )

    assert rc == 3
    detail = payload["meta"]["engines"]["sast"]["detail"]
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_ERROR
    assert "SAST: NO COVERAGE (shell)" not in detail
    assert f"operator config {pack}" in detail


def test_unresolved_enabled_registry_pack_fails_closed(
        tmp_path, monkeypatch, capsys):
    (tmp_path / "build.sh").write_text("echo ready\n", encoding="utf-8")
    pack = "p/offline-registry-fixture"
    monkeypatch.setattr(engine_sast, "DEFAULT_REGISTRY_CONFIGS", [pack])
    rc = praetor.main([
        str(tmp_path), "--format", "json", "--quiet", "--engines", "sast",
    ])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 3
    sast = payload["meta"]["engines"]["sast"]
    assert sast["status"] == core.ENGINE_ERROR
    assert f"registry config {pack}" in sast["detail"]


def _live_runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("SEMGREP_SETTINGS_FILE", str(tmp_path / "semgrep-settings.yml"))
    monkeypatch.setenv("SEMGREP_LOG_FILE", str(tmp_path / "semgrep.log"))
    monkeypatch.setenv("SEMGREP_SEND_METRICS", "off")
    monkeypatch.setenv("SEMGREP_ENABLE_VERSION_CHECK", "0")
    runtime = _REAL_DETECT_RUNTIME("auto", "Ubuntu")
    assert runtime["available"], (
        "the conformance gate requires the pinned Semgrep runtime: "
        f"{runtime['detail']}"
    )
    assert runtime["mode"] in {"native", "wsl"}, (
        "the conformance gate must query the installed CLI directly, got "
        f"{runtime['mode']}"
    )
    return runtime


def test_every_alias_is_accepted_by_the_installed_semgrep(
        tmp_path, monkeypatch):
    """Predicate (h): ask the installed Semgrep which IDs it accepts."""
    # Detection is deliberately broader: an absent alias entry means a named
    # gap, never implicit coverage. Every alias must still name a detected kind.
    assert set(engine_sast.SAST_LANGUAGE_ALIASES) <= (
        set(core.SOURCE_LANGUAGE_BY_EXTENSION.values())
        | set(core.SOURCE_LANGUAGE_BY_BASENAME.values())
    )
    assert engine_sast.SAST_LANGUAGE_ALIASES["shell"] == {"bash", "sh"}
    assert engine_sast.SAST_LANGUAGE_ALIASES["python"] == {"python", "python3", "py"}
    assert engine_sast.SAST_LANGUAGE_ALIASES["javascript"] == {"javascript", "js"}
    assert engine_sast.SAST_LANGUAGE_ALIASES["typescript"] == {"typescript", "ts"}

    runtime = _live_runtime(tmp_path, monkeypatch)
    version = core.run_tool(
        [*runtime["prefix"], "show", "version"], timeout=30,
    ).stdout.strip()
    language_output = core.run_tool(
        [*runtime["prefix"], "show", "supported-languages"], timeout=30,
    ).stdout.strip()
    prefix = "supported languages are:"
    assert language_output.startswith(prefix), (
        f"installed Semgrep {version} changed its supported-language output: "
        f"{language_output!r}"
    )
    supported = frozenset(
        item.strip() for item in language_output[len(prefix):].split(",")
        if item.strip()
    )
    aliases = frozenset().union(*engine_sast.SAST_LANGUAGE_ALIASES.values())
    root = Path(__file__).parent.parent
    project = (root / "pyproject.toml").read_text(encoding="utf-8")
    pin_match = re.search(
        r'^sast\s*=\s*\["semgrep==([0-9]+\.[0-9]+\.[0-9]+)"\]$',
        project,
        re.MULTILINE,
    )
    assert pin_match, "the sast extra must carry one exact Semgrep == pin"
    pin = pin_match.group(1)
    assert engine_sast._SEMGREP_VERSION == pin
    assert engine_sast._SEMGREP_DOCKER_IMAGE == f"semgrep/semgrep:{pin}"
    assert version == pin, (
        f"installed Semgrep is {version}, but pyproject.toml pins {pin}"
    )
    reference_path = root / f"references/semgrep-{pin}-supported-languages.txt"
    reference = frozenset(
        line.strip()
        for line in reference_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    )
    assert reference == supported, (
        f"tracked {reference_path.name} differs from installed Semgrep {version}: "
        f"missing={sorted(supported-reference)}, extra={sorted(reference-supported)}"
    )
    assert aliases <= supported, (
        f"installed Semgrep {version} does not accept aliases "
        f"{sorted(aliases - supported)}"
    )
    print(
        f"pin and alias conformance checked against installed Semgrep {version}; "
        f"reference={reference_path.name}"
    )


def test_python_and_rust_requirements_use_the_identical_coverage_predicate():
    root = Path(__file__).parent.parent
    marker = "## Binding SAST coverage predicate (Python and future Rust)"
    requirement = (root / "references/REQ-SAST-ELIGIBILITY.md").read_text(
        encoding="utf-8"
    )
    adr = (root / "references/ADR-001-engine-language.md").read_text(
        encoding="utf-8"
    )
    requirement_block = requirement[
        requirement.index(marker):requirement.index("\n## Tracked follow-up")
    ]
    adr_block = adr[adr.index(marker):]
    assert requirement_block == adr_block


def test_multiline_real_dump_fixture_resolves_every_rule():
    dump = (
        Path(__file__).parent / "fixtures" / "semgrep-dump-config-multiline-rule-id.txt"
    ).read_text(encoding="utf-8")

    rules = engine_sast._rules_from_semgrep_dump(dump)

    assert rules is not None
    assert len(rules) == 2
    assert engine_sast._source_rule_counts(rules) == {
        "python": 1, "javascript": 1, "typescript": 1,
    }


def test_real_generic_none_selector_is_preserved_without_language_coverage():
    dump = (
        Path(__file__).parent / "fixtures" / "semgrep-dump-config-generic-none.txt"
    ).read_text(encoding="utf-8")

    rules = engine_sast._rules_from_semgrep_dump(dump)

    assert rules == [{"languages": frozenset(), "has_include": False}]
    assert engine_sast._source_rule_counts(rules) == {}


def test_true_final_invalid_rules_field_defeats_quoted_metadata_spoof():
    dump = (
        Path(__file__).parent
        / "fixtures" / "semgrep-dump-config-invalid-rules-metadata-spoof.txt"
    ).read_text(encoding="utf-8")

    assert engine_sast._rules_from_semgrep_dump(dump) is None


def test_a_partially_recognized_dump_fails_closed_instead_of_using_a_subset():
    dump = (
        Path(__file__).parent / "fixtures" / "semgrep-dump-config-multiline-rule-id.txt"
    ).read_text(encoding="utf-8")
    dump = dump.replace(
        '("rules.fixture-python", _);',
        '(Rule_ID.of_string "rules.fixture-python");',
        1,
    )

    assert engine_sast._rules_from_semgrep_dump(dump) is None


def test_resolver_parses_valid_dump_and_applies_semgrep_network_discipline(
        monkeypatch):
    dump = (
        Path(__file__).parent / "fixtures" / "semgrep-dump-config-multiline-rule-id.txt"
    ).read_text(encoding="utf-8")
    observed = {}

    def completed(command, **kwargs):
        observed["command"] = command
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0, dump, "")

    monkeypatch.setattr(core, "run_tool", completed)
    rules = _REAL_RESOLVE_RULE_SOURCE(
        "/trusted/rules.yaml",
        {"mode": "native", "prefix": ["semgrep"], "available": True},
        timeout=17,
    )

    assert rules is not None and len(rules) == 2
    assert observed["timeout"] == 17
    assert observed["env"]["SEMGREP_SEND_METRICS"] == "off"
    assert observed["env"]["SEMGREP_ENABLE_VERSION_CHECK"] == "0"


def test_resolver_rejects_invalid_rule_output(monkeypatch):
    invalid = (
        'config = Valid { rules = []; invalid_rules = '
        '[{ Rule_error.message = "bad rule"; }]; }\n'
    )
    monkeypatch.setattr(
        core, "run_tool",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, invalid, ""),
    )
    assert _REAL_RESOLVE_RULE_SOURCE(
        "/trusted/invalid.yaml",
        {"mode": "native", "prefix": ["semgrep"], "available": True},
    ) is None


def test_resolver_timeout_is_unresolved(monkeypatch):
    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(core, "run_tool", timeout)
    assert _REAL_RESOLVE_RULE_SOURCE(
        "/trusted/slow.yaml",
        {"mode": "native", "prefix": ["semgrep"], "available": True},
        timeout=3,
    ) is None


@pytest.mark.parametrize("mode", ["native", "wsl", "docker"])
def test_resolution_suppression_reaches_each_runtime_mode(mode, monkeypatch):
    dump = (
        Path(__file__).parent / "fixtures" / "semgrep-dump-config-generic-none.txt"
    ).read_text(encoding="utf-8")
    observed = {}

    def completed(command, **kwargs):
        observed["command"] = command
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0, dump, "")

    monkeypatch.setattr(core, "run_tool", completed)
    prefix = ["semgrep"] if mode == "native" else (
        ["wsl", "-d", "Ubuntu", "/usr/bin/semgrep"]
        if mode == "wsl" else ["docker"]
    )
    rules = _REAL_RESOLVE_RULE_SOURCE(
        "p/fixture", {"mode": mode, "prefix": prefix, "available": True},
    )

    assert rules == [{"languages": frozenset(), "has_include": False}]
    if mode == "native":
        assert observed["env"]["SEMGREP_SEND_METRICS"] == "off"
        assert observed["env"]["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    elif mode == "wsl":
        assert observed["command"][:7] == [
            "wsl", "-d", "Ubuntu", "env", "SEMGREP_SEND_METRICS=off",
            "SEMGREP_ENABLE_VERSION_CHECK=0", "/usr/bin/semgrep",
        ]
    else:
        assert ["-e", "SEMGREP_SEND_METRICS=off"] == observed["command"][5:7]
        assert ["-e", "SEMGREP_ENABLE_VERSION_CHECK=0"] == observed["command"][7:9]


def test_rule_resolution_sources_share_one_total_timeout_budget(monkeypatch):
    observed = []
    ticks = iter((100.0, 101.0, 103.0, 106.0))
    monkeypatch.setattr(engine_sast, "_monotonic", lambda: next(ticks), raising=False)
    monkeypatch.setattr(engine_sast, "detect_runtime", lambda *a, **kw: {
        "mode": "native", "prefix": ["semgrep"], "available": True,
        "detail": "test", "version": "test",
    })

    def resolve(config, runtime, timeout):
        observed.append(timeout)
        if config == praetor.BUNDLED_SEMGREP:
            return [
                {"languages": frozenset({"python"}), "has_include": False},
                {"languages": frozenset({"javascript", "typescript"}),
                 "has_include": False},
            ]
        return []

    monkeypatch.setattr(engine_sast, "_resolve_rule_source", resolve)
    engine_sast.language_coverage(
        ["app.py"], praetor.BUNDLED_SEMGREP,
        extra_configs=["p/one", "p/two"], timeout=10,
    )

    assert observed == [9.0, 7.0, 4.0]


def test_live_semgrep_resolves_pinned_rules_and_scans_python_and_shell(
        tmp_path, monkeypatch, capsys):
    runtime = _live_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(engine_sast, "detect_runtime", _REAL_DETECT_RUNTIME)
    monkeypatch.setattr(engine_sast, "_resolve_rule_source", _REAL_RESOLVE_RULE_SOURCE)
    resolved = _REAL_RESOLVE_RULE_SOURCE(
        praetor.BUNDLED_SEMGREP, runtime, timeout=30,
    )
    assert resolved is not None and len(resolved) == 15

    generic_config = tmp_path / "generic.yaml"
    _write_rule(generic_config, "generic")
    generic_rules = _REAL_RESOLVE_RULE_SOURCE(
        str(generic_config), runtime, timeout=30,
    )
    assert generic_rules == [{"languages": frozenset(), "has_include": False}]

    python_target = tmp_path / "python-target"
    python_target.mkdir()
    (python_target / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    python_rc, python_payload = _run_json(
        python_target, capsys, "--engines", "sast", "--fail-on", "LOW",
    )
    assert python_rc == 1
    assert python_payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_OK
    assert python_payload["meta"]["semgrep_version"] == "1.177.0"

    shell_target = tmp_path / "shell-target"
    shell_target.mkdir()
    (shell_target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    shell_rc, shell_payload = _run_json(shell_target, capsys, "--engines", "sast")
    assert shell_rc == 0
    assert shell_payload["meta"]["engines"]["sast"] == {
        "status": core.ENGINE_NO_COVERAGE,
        "detail": "SAST: NO COVERAGE (shell)",
    }
    assert shell_payload["meta"]["semgrep_version"] == "1.177.0"

    generic_rc, generic_payload = _run_json(
        shell_target, capsys, "--engines", "sast",
        "--semgrep-config", str(generic_config),
    )
    assert generic_rc == 0
    assert generic_payload["meta"]["engines"]["sast"]["status"] == (
        core.ENGINE_NO_COVERAGE
    )


def test_live_known_extension_outvotes_conflicting_shebang(
        tmp_path, monkeypatch, capsys):
    """Semgrep chooses the known suffix; PRAETOR must retain that finding."""
    _live_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(engine_sast, "detect_runtime", _REAL_DETECT_RUNTIME)
    monkeypatch.setattr(engine_sast, "_resolve_rule_source", _REAL_RESOLVE_RULE_SOURCE)
    target = tmp_path / "known-extension-target"
    target.mkdir()
    (target / "app.py").write_text(
        "#!/usr/bin/env node\neval(user_input)\n", encoding="utf-8")

    rc, payload = _run_json(target, capsys, "--engines", "sast", "--fail-on", "HIGH")

    assert rc == 1
    assert "praetor-py-eval-exec" in {
        finding["rule_id"] for finding in payload["findings"]
    }
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_OK


@pytest.mark.parametrize("name,shebang,body,rule_id", [
    ("app.PY", "node", "exec(user_input)", "praetor-py-eval-exec"),
    ("app.JS", "python3", "new Function(userInput)", "praetor-js-eval"),
])
def test_live_case_divergent_suffix_keeps_semgrep_finding(
        tmp_path, monkeypatch, capsys, name, shebang, body, rule_id):
    """Unknown-to-Semgrep casing must not discard its real parser finding."""
    _live_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(engine_sast, "detect_runtime", _REAL_DETECT_RUNTIME)
    monkeypatch.setattr(engine_sast, "_resolve_rule_source", _REAL_RESOLVE_RULE_SOURCE)
    target = tmp_path / "case-divergent-target"
    target.mkdir()
    (target / name).write_text(
        f"#!/usr/bin/env {shebang}\n{body}\n", encoding="utf-8")

    rc, payload = _run_json(target, capsys, "--engines", "sast", "--fail-on", "HIGH")

    assert rc == 1
    assert rule_id in {finding["rule_id"] for finding in payload["findings"]}
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_OK


@pytest.mark.parametrize("name,shebang,body,rule_id", [
    ("app.PY", "", "exec(user_input)", "praetor-py-eval-exec"),
    ("app.Py", "", "exec(user_input)", "praetor-py-eval-exec"),
    ("app.JS", "", "new Function(userInput)", "praetor-js-eval"),
    ("app.Js", "", "new Function(userInput)", "praetor-js-eval"),
    ("app.PY", "#!/usr/bin/env deno\n", "exec(user_input)",
     "praetor-py-eval-exec"),
])
def test_live_casefolded_suffix_is_scanned_even_with_unmapped_shebang(
        tmp_path, monkeypatch, capsys, name, shebang, body, rule_id):
    _live_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(engine_sast, "detect_runtime", _REAL_DETECT_RUNTIME)
    monkeypatch.setattr(engine_sast, "_resolve_rule_source", _REAL_RESOLVE_RULE_SOURCE)
    target = tmp_path / "casefold-target"
    target.mkdir()
    sibling = "ok.py" if name.lower().endswith(".py") else "ok.js"
    (target / sibling).write_text("value = 1\n", encoding="utf-8")
    (target / name).write_text(shebang + body + "\n", encoding="utf-8")

    rc, payload = _run_json(target, capsys, "--engines", "sast", "--fail-on", "HIGH")

    assert rc == 1
    assert rule_id in {finding["rule_id"] for finding in payload["findings"]}
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_OK
    assert payload["meta"]["engines"]["sast"]["scanned_file_count"] == 2


@pytest.mark.parametrize("name,shebang,body,rule_id,sibling", [
    ("app.PY", "#!/bin/sh", "exec(user_input)", "praetor-py-eval-exec", "ok.py"),
    ("app.Js", "#!/usr/bin/env python3", "new Function(userInput)",
     "praetor-js-eval", "ok.js"),
    ("app.py", "#!/bin/sh", "exec(user_input)", "praetor-py-eval-exec", None),
])
def test_live_extension_language_survives_conflicting_shebang(
        tmp_path, monkeypatch, capsys, name, shebang, body, rule_id, sibling):
    _live_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(engine_sast, "detect_runtime", _REAL_DETECT_RUNTIME)
    monkeypatch.setattr(engine_sast, "_resolve_rule_source", _REAL_RESOLVE_RULE_SOURCE)
    target = tmp_path / "extension-first-target"
    target.mkdir()
    if sibling:
        (target / sibling).write_text("x = 1\n", encoding="utf-8")
    (target / name).write_text(shebang + "\n" + body + "\n", encoding="utf-8")

    rc, payload = _run_json(target, capsys, "--engines", "sast", "--fail-on", "HIGH")

    sast = payload["meta"]["engines"]["sast"]
    assert rc == 1
    assert rule_id in {finding["rule_id"] for finding in payload["findings"]}
    assert sast["scanned_file_count"] == (2 if sibling else 1)
    assert sast["status"] == core.ENGINE_OK
    if "sh" in shebang:
        assert "SAST: NO COVERAGE (shell)" in sast["detail"]


def test_live_known_suffix_and_other_covered_shebang_scan_both_parsers(
        tmp_path, monkeypatch, capsys):
    _live_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(engine_sast, "detect_runtime", _REAL_DETECT_RUNTIME)
    monkeypatch.setattr(engine_sast, "_resolve_rule_source", _REAL_RESOLVE_RULE_SOURCE)
    target = tmp_path / "two-parsers-target"
    target.mkdir()
    (target / "app.py").write_text(
        "#!/usr/bin/env node\nnew Function(userInput)\n",
        encoding="utf-8")

    rc, payload = _run_json(target, capsys, "--engines", "sast", "--fail-on", "HIGH")

    assert rc == 1
    assert "praetor-js-eval" in {finding["rule_id"] for finding in payload["findings"]}
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_OK


def test_semgrep_partial_file_walk_reports_high_and_error(
        tmp_path, monkeypatch, capsys):
    """A clean sibling may not certify an eligible file Semgrep did not open."""
    _live_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(engine_sast, "detect_runtime", _REAL_DETECT_RUNTIME)
    monkeypatch.setattr(engine_sast, "_resolve_rule_source", _REAL_RESOLVE_RULE_SOURCE)
    target = tmp_path / "partial-target"
    target.mkdir()
    (target / "ok.py").write_text("value = 1\n", encoding="utf-8")
    (target / "missed.PY").write_text("exec(user_input)\n", encoding="utf-8")
    real_run_tool = core.run_tool

    def omit_one_scanned_path(command, **kwargs):
        result = real_run_tool(command, **kwargs)
        if "--json" in command:
            data = json.loads(result.stdout)
            data["paths"]["scanned"] = [path for path in data["paths"]["scanned"]
                                         if not path.endswith("missed.PY")]
            result.stdout = json.dumps(data)
        return result

    monkeypatch.setattr(core, "run_tool", omit_one_scanned_path)
    rc, payload = _run_json(target, capsys, "--engines", "sast", "--fail-on", "HIGH")

    assert rc != 0
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_ERROR
    assert payload["meta"]["engines"]["sast"]["scanned_file_count"] == 1
    assert any(f["rule_id"] == "sast-file-not-scanned" and
               f["file"] == "missed.PY" and f["severity"] == "HIGH"
               for f in payload["findings"])


def test_live_shebang_filter_is_reached_for_unrelated_parser(
        tmp_path, monkeypatch, capsys):
    """The unknown-name filter must still reject a different parser's hit."""
    _live_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(engine_sast, "detect_runtime", _REAL_DETECT_RUNTIME)
    monkeypatch.setattr(engine_sast, "_resolve_rule_source", _REAL_RESOLVE_RULE_SOURCE)
    target = tmp_path / "unknown-name-target"
    target.mkdir()
    (target / "pre-commit").write_text(
        "#!/usr/bin/env python3\nnew Function(userInput)\n", encoding="utf-8")
    raw_ids = []
    real_run_tool = core.run_tool

    def capture_semgrep_result(command, **kwargs):
        result = real_run_tool(command, **kwargs)
        if "--json" in command:
            raw_ids.extend(item["check_id"].split(".")[-1]
                           for item in json.loads(result.stdout).get("results", []))
        return result

    monkeypatch.setattr(core, "run_tool", capture_semgrep_result)
    rc, payload = _run_json(target, capsys, "--engines", "sast", "--fail-on", "HIGH")

    assert "praetor-js-eval" in raw_ids, "the real Semgrep parser must find it"
    assert rc == 0
    assert "praetor-js-eval" not in {
        finding["rule_id"] for finding in payload["findings"]
    }


def test_live_in_target_operator_rule_runs_without_granting_coverage(
        tmp_path, monkeypatch, capsys):
    _live_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(engine_sast, "detect_runtime", _REAL_DETECT_RUNTIME)
    monkeypatch.setattr(engine_sast, "_resolve_rule_source", _REAL_RESOLVE_RULE_SOURCE)
    target = tmp_path / "shell-target"
    target.mkdir()
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    config = target / "operator.yaml"
    _write_rule(config, "bash")
    config.write_text(
        config.read_text(encoding="ascii").replace("severity: WARNING", "severity: ERROR"),
        encoding="ascii",
    )

    rc, payload = _run_json(
        target, capsys, "--engines", "sast", "--semgrep-config", str(config),
        "--fail-on", "HIGH",
    )

    assert rc == 1
    assert payload["summary"]["active"] == 1
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_NO_COVERAGE
    assert "SAST: NO COVERAGE (shell)" in payload["meta"]["engines"]["sast"]["detail"]


def test_live_binary_dropped_python_finding_survives_uncovered_shell_gap(
        tmp_path, monkeypatch, capsys):
    _live_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(engine_sast, "detect_runtime", _REAL_DETECT_RUNTIME)
    monkeypatch.setattr(engine_sast, "_resolve_rule_source", _REAL_RESOLVE_RULE_SOURCE)
    (tmp_path / "build.sh").write_text("echo ready\n", encoding="utf-8")
    (tmp_path / "hidden.py").write_bytes(
        b"# " + (b"\x01" * 3000) + b"\neval(user_input)\n"
    )

    rc, payload = _run_json(
        tmp_path, capsys, "--engines", "sast", "--fail-on", "HIGH",
    )

    assert rc == 1
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_NO_COVERAGE
    assert "SAST: NO COVERAGE (shell)" in payload["meta"]["engines"]["sast"]["detail"]
    assert "praetor-py-eval-exec" in {
        finding["rule_id"] for finding in payload["findings"]
    }


def _dump_rule(*, actual_language="Python", actual_paths="None;",
               early_spoof="", late_spoof=""):
    return (
        'config = Valid { rules =\n  [{ Rule.id = ("fixture", _);\n'
        f'  formula = P ("{early_spoof}", _); message = "fixture";\n'
        f'  severity = `Warning; target_selector = (Some [{actual_language}]);\n'
        f'  target_analyzer = (Analyzer.AnalyzerType.L ({actual_language}, []));\n'
        f'  options = None; fix = None; fix_regexp = None; paths = {actual_paths}\n'
        f'  metadata = Some ("{late_spoof}"); }}];\n'
        '  invalid_rules = [];\n}\n'
    )


def test_pattern_text_cannot_spoof_the_resolved_target_selector():
    dump = _dump_rule(
        actual_language="Python",
        early_spoof="target_selector = (Some [Bash]); target_analyzer =",
    )

    assert engine_sast._rules_from_semgrep_dump(dump) is None


def test_pattern_text_cannot_spoof_the_resolved_paths_field():
    dump = _dump_rule(
        actual_language="Bash",
        actual_paths="(Some { Rule.require = [\"scripts/**\"]; Rule.exclude = [] });",
        early_spoof="paths = None;",
    )

    assert engine_sast._rules_from_semgrep_dump(dump) is None


def test_late_fix_text_cannot_spoof_the_resolved_target_selector():
    dump = _dump_rule(
        actual_language="Python",
        late_spoof="target_selector = (Some [Bash]); target_analyzer =",
    )

    assert engine_sast._rules_from_semgrep_dump(dump) is None


def test_late_metadata_text_cannot_spoof_the_resolved_paths_field():
    dump = _dump_rule(
        actual_language="Bash",
        actual_paths="(Some { Rule.require = [\"scripts/**\"]; Rule.exclude = [] });",
        late_spoof="paths = None;",
    )

    assert engine_sast._rules_from_semgrep_dump(dump) is None


def test_wrapped_target_selector_with_single_line_spoof_fails_closed():
    dump = _dump_rule(
        actual_language="Python",
        late_spoof="target_selector = (Some [Bash]); target_analyzer =",
    ).replace(
        "target_selector = (Some [Python]);",
        "target_selector =\n    (Some [Python]);",
        1,
    )

    assert engine_sast._rules_from_semgrep_dump(dump) is None


def test_wrapped_paths_with_single_line_spoof_fails_closed():
    dump = _dump_rule(
        actual_language="Bash",
        actual_paths="(Some { Rule.require = [\"scripts/**\"]; Rule.exclude = [] });",
        late_spoof="paths = None;",
    ).replace(
        "paths = (Some {",
        "paths =\n    (Some {",
        1,
    )

    assert engine_sast._rules_from_semgrep_dump(dump) is None


def test_docker_operator_config_uses_same_unique_mount_for_resolution_and_scan(
        tmp_path, monkeypatch):
    bundled_dir = tmp_path / "bundled"
    operator_dir = tmp_path / "operator"
    target = tmp_path / "target"
    bundled_dir.mkdir()
    operator_dir.mkdir()
    target.mkdir()
    bundled = bundled_dir / "rules.yaml"
    operator = operator_dir / "rules.yaml"
    _write_rule(bundled, "python")
    _write_rule(operator, "bash")
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    runtime = {
        "mode": "docker", "prefix": ["docker"], "available": True,
        "detail": "test docker", "version": "test",
    }
    monkeypatch.setattr(engine_sast, "detect_runtime", lambda *a, **kw: runtime)
    observed = {}

    def completed(command, **kwargs):
        observed["scan"] = command
        body = json.dumps({
            "results": [], "errors": [], "paths": {"scanned": ["/src/build.sh"]},
        })
        return subprocess.CompletedProcess(command, 0, body, "")

    monkeypatch.setattr(core, "run_tool", completed)
    resolution = engine_sast._dump_config_command(runtime, str(operator))
    result = engine_sast.run(
        str(target), str(bundled), use_registry=False,
        extra_configs=[str(operator)], enumerated_code_files=1,
    )

    def mounted_target(command, source):
        for index, item in enumerate(command[:-1]):
            if item == "-v" and command[index + 1].startswith(f"{source}:"):
                return command[index + 1][len(source) + 1:].removesuffix(":ro")
        raise AssertionError(f"{source} was not mounted read-only: {command}")

    operator_resolution_target = mounted_target(resolution, str(operator))
    operator_scan_target = mounted_target(observed["scan"], str(operator))
    bundled_scan_target = mounted_target(observed["scan"], str(bundled))
    scan_configs = [
        observed["scan"][index + 1]
        for index, item in enumerate(observed["scan"][:-1]) if item == "--config"
    ]
    assert result["status"] == core.ENGINE_OK
    assert operator_resolution_target == operator_scan_target
    assert operator_scan_target in scan_configs
    assert bundled_scan_target in scan_configs
    assert operator_scan_target != bundled_scan_target


@pytest.mark.parametrize("mode", ["native", "wsl", "docker"])
def test_registry_id_never_becomes_an_existing_target_local_path(
        mode, tmp_path, monkeypatch):
    target = tmp_path / "target"
    attacker_pack = target / "p" / "security-audit"
    attacker_pack.mkdir(parents=True)
    (attacker_pack / "rules.yaml").write_text("rules: []\n", encoding="ascii")
    bundled = tmp_path / "bundled.yaml"
    _write_rule(bundled, "python")
    (target / "app.py").write_text("value = 1\n", encoding="utf-8")
    runtime = {
        "mode": mode,
        "prefix": (["semgrep"] if mode == "native" else
                   ["wsl", "-d", "Ubuntu", "/usr/bin/semgrep"] if mode == "wsl"
                   else ["docker"]),
        "available": True, "detail": "test", "version": "test",
    }
    monkeypatch.chdir(target)
    monkeypatch.setattr(engine_sast, "detect_runtime", lambda *a, **kw: runtime)
    observed = {}

    def completed(command, **kwargs):
        observed["scan"] = command
        return subprocess.CompletedProcess(
            command, 0,
            json.dumps({"results": [], "errors": [],
                        "paths": {"scanned": ["/src/app.py"]}}), "",
        )

    monkeypatch.setattr(core, "run_tool", completed)
    resolution = engine_sast._dump_config_command(runtime, "p/security-audit")
    result = engine_sast.run(
        str(target), str(bundled), use_registry=True,
        enumerated_code_files=1,
    )

    assert result["status"] == core.ENGINE_OK
    assert resolution[-1] == "p/security-audit"
    assert str(attacker_pack) not in resolution
    scan_configs = [
        observed["scan"][index + 1]
        for index, item in enumerate(observed["scan"][:-1]) if item == "--config"
    ]
    assert "p/security-audit" in scan_configs
    assert all(str(attacker_pack) not in item for item in observed["scan"])


@pytest.mark.parametrize("mode", ["native", "wsl", "docker"])
def test_tilde_local_config_has_one_resolution_and_scan_identity(
        mode, tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    operator = home / "rules.yaml"
    _write_rule(operator, "bash")
    target = tmp_path / "target"
    target.mkdir()
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    bundled = tmp_path / "bundled.yaml"
    _write_rule(bundled, "python")
    runtime = {
        "mode": mode,
        "prefix": (["semgrep"] if mode == "native" else
                   ["wsl", "-d", "Ubuntu", "/usr/bin/semgrep"] if mode == "wsl"
                   else ["docker"]),
        "available": True, "detail": "test", "version": "test",
    }
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(engine_sast, "detect_runtime", lambda *a, **kw: runtime)
    observed = {}

    def completed(command, **kwargs):
        observed["scan"] = command
        return subprocess.CompletedProcess(
            command, 0,
            json.dumps({"results": [], "errors": [],
                        "paths": {"scanned": ["/src/build.sh"]}}), "",
        )

    monkeypatch.setattr(core, "run_tool", completed)
    resolution = engine_sast._dump_config_command(runtime, "~/rules.yaml")
    result = engine_sast.run(
        str(target), str(bundled), use_registry=False,
        extra_configs=["~/rules.yaml"], enumerated_code_files=1,
    )

    assert result["status"] == core.ENGINE_OK
    if mode == "native":
        expected = str(operator)
    elif mode == "wsl":
        expected = engine_sast._win_to_wsl(str(operator))
    else:
        _source, expected, binding = engine_sast._docker_local_config_mount(
            str(operator)
        )
        assert binding in resolution
        assert binding in observed["scan"]
    assert resolution[-1] == expected
    scan_configs = [
        observed["scan"][index + 1]
        for index, item in enumerate(observed["scan"][:-1]) if item == "--config"
    ]
    assert expected in scan_configs
    assert "~/rules.yaml" not in scan_configs


def _fetch_record(language, rule_id):
    return _dump_rule(actual_language=language).replace(
        'config = Valid { rules =', '{ Rule_fetching.rules =', 1,
    ).replace(
        '  invalid_rules = [];\n}\n',
        f'  invalid_rules = [];\n  origin = (Rule_fetching.Local_file /tmp/{rule_id}.yaml) }}\n',
        1,
    ).replace('("fixture", _)', f'("{rule_id}", _)', 1)


def test_multi_file_dump_aggregates_only_when_every_record_is_valid():
    dump = _fetch_record("Python", "one") + _fetch_record("Bash", "two")

    assert engine_sast._rules_from_semgrep_dump(dump) == [
        {"languages": frozenset({"python"}), "has_include": False},
        {"languages": frozenset({"bash"}), "has_include": False},
    ]


def test_multi_file_dump_rejects_one_partial_invalid_record():
    valid = _fetch_record("Python", "one")
    partial_invalid = _fetch_record("Bash", "two").replace(
        'invalid_rules = [];\n  origin', 'invalid_rules = [bad];\n  origin', 1
    )

    assert engine_sast._rules_from_semgrep_dump(valid + partial_invalid) is None


def test_multi_file_dump_rejects_invalid_rules_spoof_in_one_record():
    valid = _fetch_record("Python", "one")
    partial_invalid = _fetch_record("Bash", "two").replace(
        'metadata = Some ("");',
        'metadata = Some ("metadata\n  invalid_rules = [];\nspoof");',
        1,
    ).replace('invalid_rules = [];\n  origin', 'invalid_rules = [bad];\n  origin', 1)

    assert partial_invalid.count("  invalid_rules =") == 2
    assert engine_sast._rules_from_semgrep_dump(valid + partial_invalid) is None


def test_case_insensitive_identity_blocks_target_local_config(
        tmp_path, monkeypatch):
    target = tmp_path / "CaseTarget"
    target.mkdir()
    config = target / "rules.yaml"
    _write_rule(config, "bash")
    alternate_case = str(config).replace("CaseTarget", "casetarget")
    real_exists = os.path.exists
    real_isdir = os.path.isdir

    def exists(path):
        return real_exists(str(path).replace("casetarget", "CaseTarget"))

    def isdir(path):
        return real_isdir(str(path).replace("casetarget", "CaseTarget"))

    def samefile(left, right):
        return os.path.normpath(os.fspath(left)).casefold() == os.path.normpath(
            os.fspath(right)
        ).casefold()

    monkeypatch.setattr(engine_sast.os.path, "exists", exists)
    monkeypatch.setattr(engine_sast.os.path, "isdir", isdir)
    monkeypatch.setattr(engine_sast.os.path, "samefile", samefile)

    assert engine_sast._config_crosses_target_trust_boundary(
        alternate_case, str(target)
    )


def test_config_symlink_into_target_never_counts(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    actual = target / "rules.yaml"
    _write_rule(actual, "bash")
    link = tmp_path / "outside-link.yaml"
    link.symlink_to(actual)

    assert engine_sast._config_crosses_target_trust_boundary(
        str(link), str(target)
    )


def test_config_below_symlinked_parent_into_target_never_counts(tmp_path):
    target = tmp_path / "target"
    nested = target / "nested"
    nested.mkdir(parents=True)
    actual = nested / "rules.yaml"
    _write_rule(actual, "bash")
    alias = tmp_path / "outside-parent"
    alias.symlink_to(nested, target_is_directory=True)

    assert engine_sast._config_crosses_target_trust_boundary(
        str(alias / "rules.yaml"), str(target)
    )


def test_symlinked_target_inside_config_directory_never_counts(tmp_path):
    config_dir = tmp_path / "configs"
    actual_target = config_dir / "real-target"
    actual_target.mkdir(parents=True)
    _write_rule(config_dir / "rules.yaml", "bash")
    target_link = tmp_path / "target-link"
    target_link.symlink_to(actual_target, target_is_directory=True)

    assert engine_sast._config_crosses_target_trust_boundary(
        str(config_dir), str(target_link)
    )


def test_multiline_generic_payload_cannot_forge_rule_boundaries_or_coverage():
    dump = '''config = Valid { rules =
  [{ Rule.id = ("real-generic", _);
     raw_pattern = "payload begins
     target_selector = None;
     target_analyzer = Analyzer.AnalyzerType.LSpacegrep;
     paths = None;
    { Rule.id = ("forged-bash", _);
     target_selector = (Some [Bash]);
     target_analyzer = (Analyzer.AnalyzerType.L (Bash, []));
     paths = None;
    { Rule.id = ("payload-tail", _);
payload ends";
     message = "fixture"; severity = `Warning;
     target_selector = None;
     target_analyzer = Analyzer.AnalyzerType.LSpacegrep;
     options = None; fix = None; fix_regexp = None; paths = None;
     metadata = None; }];
  invalid_rules = [];
}
'''

    rules = engine_sast._rules_from_semgrep_dump(dump)
    assert rules is None or all(not rule["languages"] for rule in rules)


def test_pinned_dump_language_drift_blocks_through_main(
        tmp_path, monkeypatch, capsys):
    """A renamed dump token cannot turn declared pinned coverage into a gap."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("value = 1\n", encoding="utf-8")
    real_resolve = engine_sast._resolve_rule_source

    def drifted(config, runtime, timeout=engine_sast._SEMGREP_TIMEOUT):
        rules = real_resolve(config, runtime, timeout)
        if os.path.abspath(os.fspath(config)) == os.path.abspath(praetor.BUNDLED_SEMGREP):
            return [{**rule, "languages": frozenset({"Language.Python"})}
                    for rule in rules]
        return rules

    monkeypatch.setattr(engine_sast, "_resolve_rule_source", drifted)
    rc, payload = _run_json(target, capsys, "--engines", "sast")

    assert rc == 3
    sast = payload["meta"]["engines"]["sast"]
    assert sast["status"] == core.ENGINE_ERROR
    assert "pinned SAST rule language resolution drift" in sast["detail"]
    assert "Language.Python" in sast["detail"]


@pytest.mark.parametrize(("gated", "expected_rc"), [(False, 0), (True, 3)])
def test_missing_semgrep_preserves_unavailable_contract(
        gated, expected_rc, tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(engine_sast, "detect_runtime", lambda *a, **kw: {
        "mode": "none", "prefix": [], "available": False,
        "detail": "semgrep not found", "version": "",
    })
    monkeypatch.setattr(
        engine_sast, "run",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("SAST must not launch")),
    )
    extra = ("--fail-on", "HIGH") if gated else ()

    rc, payload = _run_json(tmp_path, capsys, "--engines", "sast", *extra)

    assert rc == expected_rc
    assert payload["meta"]["engines"]["sast"] == {
        "status": core.ENGINE_UNAVAILABLE,
        "detail": "semgrep not found",
    }


@pytest.mark.parametrize("cli_timeout", [None, 2700])
def test_coverage_and_scan_share_the_effective_semgrep_timeout(
        cli_timeout, tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    observed = []
    real_coverage = engine_sast.language_coverage

    def coverage(*args, **kwargs):
        observed.append(("coverage", kwargs["timeout"]))
        return real_coverage(*args, **kwargs)

    def scan(*args, **kwargs):
        observed.append(("scan", kwargs["timeout"]))
        return {"findings": [], "status": core.ENGINE_OK,
                "detail": "scanned", "runtime": "test-double"}

    monkeypatch.setattr(engine_sast, "language_coverage", coverage)
    monkeypatch.setattr(engine_sast, "run", scan)
    extra = ("--semgrep-timeout", str(cli_timeout)) if cli_timeout else ()

    rc, _ = _run_json(tmp_path, capsys, "--engines", "sast", *extra)

    expected = cli_timeout or 900
    assert rc == 0
    assert observed == [("coverage", expected), ("scan", expected)]


def test_environment_semgrep_timeout_is_shared_by_coverage_and_scan(
        tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    observed = []
    real_coverage = engine_sast.language_coverage
    monkeypatch.setattr(engine_sast, "_SEMGREP_TIMEOUT", 3600)

    def coverage(*args, **kwargs):
        observed.append(("coverage", kwargs["timeout"]))
        return real_coverage(*args, **kwargs)

    def scan(*args, **kwargs):
        observed.append(("scan", kwargs["timeout"]))
        return {"findings": [], "status": core.ENGINE_OK,
                "detail": "scanned", "runtime": "test-double"}

    monkeypatch.setattr(engine_sast, "language_coverage", coverage)
    monkeypatch.setattr(engine_sast, "run", scan)

    rc, _ = _run_json(tmp_path, capsys, "--engines", "sast")

    assert rc == 0
    assert observed == [("coverage", 3600), ("scan", 3600)]


@pytest.mark.parametrize(("declared", "canonical"), [
    ("bash", "shell"), ("sh", "shell"),
    ("py", "python"), ("python", "python"),
    ("js", "javascript"), ("javascript", "javascript"),
    ("ts", "typescript"), ("typescript", "typescript"),
    ("hcl", "terraform"), ("terraform", "terraform"),
    ("c#", "csharp"), ("csharp", "csharp"),
    ("golang", "go"), ("c++", "cpp"), ("kt", "kotlin"),
    ("python3", "python"),
])
def test_pinned_rule_language_aliases_are_canonicalized(
        declared, canonical, tmp_path):
    rules = tmp_path / "rules.yaml"
    _write_rule(rules, declared)

    assert engine_sast.pinned_rule_languages(str(rules)) == frozenset({canonical})


def test_future_bash_pinned_rule_enables_shell_scanning(
        tmp_path, monkeypatch, capsys):
    rules = tmp_path / "rules.yaml"
    _write_rule(rules, "bash")
    target = tmp_path / "target"
    target.mkdir()
    (target / "build.sh").write_text("echo ready\n", encoding="utf-8")
    calls = []

    def fake_run(target, bundled_rules, **kwargs):
        calls.append(kwargs)
        return {"findings": [], "status": core.ENGINE_OK,
                "detail": "future shell rules ran", "runtime": "test-double"}

    monkeypatch.setattr(praetor, "BUNDLED_SEMGREP", str(rules))
    monkeypatch.setattr(engine_sast, "run", fake_run)
    rc, payload = _run_json(target, capsys, "--engines", "sast")

    assert rc == 0
    assert calls[0]["enumerated_code_files"] == 1
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_OK
    assert "NO COVERAGE" not in payload["meta"]["engines"]["sast"]["detail"]


def test_o_sast_only_shell_gap_does_not_satisfy_the_measurement_floor(
        tmp_path, monkeypatch, capsys):
    """A named gap is non-malfunctioning, but it did not scan source."""
    (tmp_path / "build.sh").write_text("echo ready\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run(calls))

    rc = praetor.main([
        str(tmp_path), "--format", "json", "--quiet", "--no-registry",
        "--engines", "sast", "--fail-on", "HIGH",
    ])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 3
    assert len(calls) == 1
    assert "NOTHING WAS MEASURED" in captured.err
    assert payload["meta"]["engines"]["sast"] == {
        "status": core.ENGINE_NO_COVERAGE,
        "detail": "SAST: NO COVERAGE (shell)",
    }


def test_default_rules_resolution_supports_an_installed_data_files_layout(
        tmp_path, monkeypatch):
    """The downstream compatibility API must not fail open outside a source tree."""
    installed_module = tmp_path / "site-packages" / "engine_sast.py"
    installed_module.parent.mkdir()
    installed_module.write_text("# location fixture\n", encoding="utf-8")
    installed_rules = tmp_path / "share" / "praetor" / "rules" / "semgrep-praetor.yaml"
    installed_rules.parent.mkdir(parents=True)
    installed_rules.write_text(
        "rules:\n  - id: installed-python\n    languages: [python]\n"
        "    severity: WARNING\n    message: installed\n    pattern: eval(...)\n",
        encoding="ascii",
    )
    monkeypatch.setattr(engine_sast, "__file__", str(installed_module))
    monkeypatch.setattr(engine_sast.sys, "prefix", str(tmp_path))

    assert engine_sast.count_code_files(["app.py"]) == 1
    assert engine_sast.count_code_files(["build.sh"]) == 0


@pytest.mark.parametrize("name", ["source.zsh", "source.hook", "Procfile",
    *sorted(core.GIT_HOOK_NAMES), "source.erb", "Gemfile", "Rakefile",
    "Vagrantfile", "Berksfile"])
@pytest.mark.parametrize("mixed", [False, True])
def test_alias_covered_omitted_filenames_keep_named_gap(
        name, mixed, tmp_path, monkeypatch, capsys):
    language = core.source_language(name)
    config = tmp_path / "operator.yaml"
    _write_rule(config, "bash" if language == "shell" else "ruby")
    target = tmp_path / "target"
    target.mkdir()
    (target / name).write_text("# source fixture\n")
    if mixed:
        (target / ("covered.sh" if language == "shell" else "covered.rb")).write_text(
            "# admitted sibling\n")
    calls = []
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run(calls))
    rc, payload = _run_json(target, capsys, "--engines", "sast",
                            "--semgrep-config", str(config), "--fail-on", "HIGH")
    sast = payload["meta"]["engines"]["sast"]
    assert calls[-1]["enumerated_code_files"] == int(mixed), (
        "filename admission must exclude omitted alias kinds", name, mixed, calls[-1])
    assert f"SAST: NO COVERAGE ({language})" in sast["detail"], (name, mixed, sast)
    assert sast["status"] == (core.ENGINE_OK if mixed else core.ENGINE_NO_COVERAGE)
    assert rc == (0 if mixed else 3)
    if mixed:
        assert f"SAST: {language} covered by operator config" in sast["detail"]


@pytest.mark.parametrize("name", ["Dockerfile.py", "dockerfile_utils.py"])
def test_recognized_suffix_precedes_dockerfile_prefix(name, tmp_path, monkeypatch, capsys):
    assert core.source_language(name) == "python", "recognized suffix must win"
    assert core.is_code(name)
    (tmp_path / name).write_text("value = 1\n")
    calls = []
    monkeypatch.setattr(engine_sast, "run", _zero_finding_run(calls))
    rc, payload = _run_json(tmp_path, capsys, "--engines", "sast", "--fail-on", "HIGH")
    assert calls[-1]["enumerated_code_files"] == 1
    assert rc == 0
    assert "NO COVERAGE" not in payload["meta"]["engines"]["sast"]["detail"]
    for variant in ("Dockerfile", "Dockerfile.dev", "Dockerfile.prod"):
        assert core.source_language(variant) == "dockerfile"


@pytest.mark.parametrize("mode", ["native", "wsl", "docker"])
def test_filename_metadata_uses_selected_runtime_without_target(mode, monkeypatch):
    prefix = {"native": ["/trusted/semgrep"],
              "wsl": ["wsl", "-d", "Ubuntu", "/trusted/semgrep"],
              "docker": ["docker"]}[mode]
    calls = []
    dump = (Path(__file__).parent / "fixtures/semgrep-1.177.0-extensions.txt").read_text()
    def run(command, **kwargs):
        calls.append(command)
        assert kwargs["cwd"] == os.path.dirname(os.path.abspath(engine_sast.__file__))
        return subprocess.CompletedProcess(command, 0,
            "/trusted/semgrep-core\n" if len(calls) == 1 else dump, "")
    monkeypatch.setattr(core, "run_tool", run)
    metadata = _REAL_FILENAME_EXTENSIONS({"mode": mode, "prefix": prefix})
    assert metadata["bash"] == (".bash", ".sh")
    assert metadata["ruby"] == (".rb",)
    assert calls[0][-2:] == ["scan", "--dump-engine-path"]
    assert calls[1][-2:] == ["/trusted/semgrep-core", "-dump_extensions"]
    if mode == "docker":
        assert all(command[:6] == ["docker", "run", "--rm", "--network", "none",
                                  engine_sast._SEMGREP_DOCKER_IMAGE] for command in calls)
        assert all("-v" not in command for command in calls)
    elif mode == "wsl":
        assert all(command[:3] == prefix[:-1] for command in calls)


@pytest.mark.parametrize("output", ["", "format changed", "relative/core", "/core\n/other"])
def test_unproven_filename_metadata_preserves_named_gap(output, monkeypatch):
    monkeypatch.setattr(core, "run_tool", lambda cmd, **kw:
                        subprocess.CompletedProcess(cmd, 0, output, ""))
    monkeypatch.setattr(engine_sast, "_runtime_filename_extensions", _REAL_FILENAME_EXTENSIONS)
    coverage = engine_sast.language_coverage(["app.py"], praetor.BUNDLED_SEMGREP)
    assert coverage["eligible_files"] == 0
    assert coverage["uncovered"] == {"python"}
    assert "SAST: NO COVERAGE (python)" in engine_sast.coverage_detail(coverage)


def test_live_filename_metadata_matches_pinned_engine(tmp_path, monkeypatch):
    runtime = _live_runtime(tmp_path, monkeypatch)
    assert runtime["version"] == engine_sast._SEMGREP_VERSION
    metadata = _REAL_FILENAME_EXTENSIONS(runtime)
    assert metadata == engine_sast._runtime_filename_extensions(runtime)
    assert metadata["bash"] == (".bash", ".sh")
    assert metadata["ruby"] == (".rb",)
    assert engine_sast._filename_admitted("app.py", "python", metadata)
    assert not engine_sast._filename_admitted("app.PY", "python", metadata)


@pytest.mark.parametrize("failure", ["exit", "timeout", "malformed", "empty-suffix"])
def test_filename_metadata_probe_failure_grants_no_eligibility(failure, monkeypatch):
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            return subprocess.CompletedProcess(command, 0, "/trusted/core\n", "")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        output = ("changed format" if failure == "malformed" else
                  "Language to supported file extension mappings:\npython->\n")
        return subprocess.CompletedProcess(command, int(failure == "exit"), output, "")
    monkeypatch.setattr(core, "run_tool", run)
    monkeypatch.setattr(engine_sast, "_runtime_filename_extensions", _REAL_FILENAME_EXTENSIONS)
    coverage = engine_sast.language_coverage(["app.py"], praetor.BUNDLED_SEMGREP)
    assert coverage["eligible_files"] == 0
    assert coverage["covered"] == set()
    assert "SAST: NO COVERAGE (python)" in engine_sast.coverage_detail(coverage)
