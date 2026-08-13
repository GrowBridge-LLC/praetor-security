"""
AN ENGINE THAT COULD NOT MEASURE MUST NEVER PRODUCE A PASSING EXIT CODE.

MEASURED DEFECT (2026-08-12), verified independently in `scripts/praetor.py`
before this file existed:

    if args.fail_on:
        threshold = core.Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in result["active"]):
            return 1
    return 0

The block consulted `result["active"]` and nothing else. So an engine that threw
-- a dead semgrep runtime, an unreachable Docker daemon, an unparseable tool
output -- contributed ZERO findings, and `--fail-on HIGH` returned **exit 0**,
byte-identical to a fully-measured clean scan. The exit code is what CI gates on.

🔴 The sharpest part of the defect, and the reason it is worth a dedicated file:
**PRAETOR already computed the answer.** `engine_meta` had 14 references, THIRTEEN
of them writes recording `ok`/`error`/`disabled` per engine. The fourteenth put it
in the report payload. It was never READ for any decision. The observable existed,
was correct, was populated, and was wired to the report instead of the gate.

⚠️ This is the same family as `test_sca_status_honesty.py` one layer up. That file
made each engine's STATUS honest; nothing made the DECISION read it. A scanner can
be honest in its report and still hand a gate a false clean.

WHAT IS ASSERTED, IN BOTH DIRECTIONS -- because narrowing the check and deleting
it look identical from outside:
  * an errored engine BLOCKS  (the fix)
  * a fully-measured clean scan still PASSES  (the fix did not just break the gate)
  * `disabled` and `not-applicable` do NOT block (operator choice / empty target)
  * an UNRECOGNISED status word blocks -- the guard for engines not written yet
"""

import json

import pytest

import core
import engine_aisec
import engine_sast
import engine_sca
import engine_secrets
import praetor
import report


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _clean_target(tmp_path):
    """A target with nothing to find and no dependency manifests."""
    (tmp_path / "hello.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    return str(tmp_path)


def _break_secrets(monkeypatch):
    """Make the secrets engine raise, exactly as a broken runtime would."""
    def boom(*a, **kw):
        raise RuntimeError("simulated engine failure")

    monkeypatch.setattr(engine_secrets, "scan", boom)


def _run(argv):
    return praetor.main(argv)


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #

def test_errored_engine_does_not_return_a_passing_exit_code(tmp_path, monkeypatch, capsys):
    """THE HEADLINE. A broken engine must not be reported as a clean gate result."""
    _break_secrets(monkeypatch)
    rc = _run([_clean_target(tmp_path), "--engines", "secrets", "--fail-on", "HIGH",
               "--format", "json", "--quiet"])

    out = capsys.readouterr()
    payload = json.loads(out.out)
    assert payload["meta"]["engines"]["secrets"]["status"] == core.ENGINE_ERROR, (
        "the fixture did not actually break the engine -- test is vacuous, fix the "
        f'fixture, not the assertion (status={payload["meta"]["engines"]["secrets"]["status"]!r})'
    )
    assert payload["findings"] == [], "fixture assumption: the target is clean"

    assert rc != 0, (
        "FALSE CLEAN AT THE GATE: the only engine selected THREW, produced zero "
        "findings for that reason alone, and --fail-on HIGH still returned exit 0. "
        "CI cannot distinguish this from a scan that ran and found nothing."
    )
    assert rc == 3, f"expected exit 3 (scan degraded), got {rc}"


def test_fully_measured_clean_scan_still_exits_zero(tmp_path):
    """THE KEEP DIRECTION. Without this, the fix and a broken gate look the same."""
    rc = _run([_clean_target(tmp_path), "--engines", "secrets", "--fail-on", "HIGH",
               "--format", "json", "--quiet"])
    assert rc == 0, (
        f"a clean, fully-measured scan must still pass its gate, got exit {rc}. "
        "A gate that fails on everything gets switched off, which is the same "
        "outcome as no gate at all."
    )


def test_real_findings_outrank_degradation(tmp_path, monkeypatch, capsys):
    """1 beats 3: the actionable signal wins when both are true."""
    (tmp_path / "leak.py").write_text(
        # assembled from parts so this file does not trip the engine it tests
        'KEY = "' + "sk-" + "ant-" + "api03-" + "A" * 80 + '"\n',
        encoding="utf-8",
    )

    def half_broken(*a, **kw):
        raise RuntimeError("simulated sast failure")

    monkeypatch.setattr(engine_sast, "run", half_broken)
    rc = _run([str(tmp_path), "--engines", "secrets,sast", "--fail-on", "HIGH",
               "--format", "json", "--quiet"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["meta"]["engines"]["sast"]["status"] == core.ENGINE_ERROR, (
        "fixture did not break sast -- test is vacuous"
    )
    assert payload["findings"], (
        "fixture produced no active finding, so this asserts nothing about ordering"
    )
    assert rc == 1, (
        f"a real finding at/above the threshold must report as a finding (1), not as "
        f"degradation (3); got {rc}"
    )


def test_allow_degraded_is_the_only_way_past(tmp_path, monkeypatch):
    """The opt-out is explicit, per-run, and cannot be reached by accident."""
    _break_secrets(monkeypatch)
    rc = _run([_clean_target(tmp_path), "--engines", "secrets", "--fail-on", "HIGH",
               "--allow-degraded", "--format", "json", "--quiet"])
    assert rc == 0, (
        f"--allow-degraded is the documented way to gate on findings alone; got {rc}"
    )


def test_min_severity_is_a_display_filter_and_must_not_narrow_the_gate(tmp_path):
    """A SECOND fail-open, same class, found by re-reading the exit path.

    `--min-severity` moved below-threshold findings out of result["active"], and
    the gate judged that same mutated list. So `--min-severity CRITICAL
    --fail-on HIGH` on a target with a live HIGH-severity credential returned
    EXIT 0 -- both flags doing exactly what their help text says, combining into
    a pass. No broken environment required, unlike the errored-engine case above.

    Measured before the fix: exit 1 without --min-severity, exit 0 with it, same
    target and the same real finding.
    """
    (tmp_path / "leak.py").write_text(
        'KEY = "' + "sk-" + "ant-" + "api03-" + "A" * 80 + '"\n', encoding="utf-8"
    )

    baseline = _run([str(tmp_path), "--engines", "secrets", "--fail-on", "HIGH",
                     "--format", "json", "--quiet"])
    assert baseline == 1, (
        f"fixture assumption: this target must produce a HIGH finding, got exit {baseline}"
    )

    rc = _run([str(tmp_path), "--engines", "secrets", "--min-severity", "CRITICAL",
               "--fail-on", "HIGH", "--format", "json", "--quiet"])
    assert rc == 1, (
        "FALSE CLEAN AT THE GATE: a display filter silently narrowed it. The "
        f"operator asked to fail on HIGH, a HIGH-severity credential is present, and "
        f"the run returned exit {rc} because --min-severity CRITICAL emptied the list "
        "the gate reads. --fail-on means 'fail if a HIGH exists', not 'fail if a HIGH "
        "survived the reporting threshold'."
    )


def test_min_severity_still_filters_the_report(tmp_path, capsys):
    """THE KEEP DIRECTION: the display filter must still do its own job."""
    (tmp_path / "leak.py").write_text(
        'KEY = "' + "sk-" + "ant-" + "api03-" + "A" * 80 + '"\n', encoding="utf-8"
    )
    _run([str(tmp_path), "--engines", "secrets", "--min-severity", "CRITICAL",
          "--format", "json", "--quiet"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == [], (
        "--min-severity CRITICAL must still hide the HIGH finding from the REPORT; "
        "the fix was to stop it reaching the gate, not to disable it"
    )


def test_operator_disabled_engines_do_not_block_the_gate(tmp_path):
    """`disabled` is a choice the operator made knowingly -- not a surprise blind spot.

    Without this, `--engines secrets` could never return 0, and the gate would be
    unusable for anyone scanning with a subset.
    """
    rc = _run([_clean_target(tmp_path), "--engines", "secrets", "--fail-on", "INFO",
               "--format", "json", "--quiet"])
    assert rc == 0, f"three engines were 'disabled' by the operator's own flag; got {rc}"


# --------------------------------------------------------------------------- #
# The classification itself -- the part that has to survive future engines
# --------------------------------------------------------------------------- #

def test_unrecognised_status_is_treated_as_a_blind_spot():
    """🔴 The guard for code nobody has written yet.

    Every previous narrowing defect in this repo took the same shape: a check that
    enumerated what its author had seen. A status word added by a future engine and
    never considered here MUST fail toward "unmeasured" -- the same way an unproven
    finding is KEPT rather than suppressed.
    """
    blind = core.engine_blind_spots({"future": {"status": "partial", "detail": "half a scan"}})
    assert blind == [("future", "partial", "half a scan")], (
        "an unknown status word was treated as trustworthy. The allowlist in "
        "core.GATE_TRUSTED_STATUSES must stay an ALLOWLIST -- if this ever becomes a "
        "denylist of known-bad statuses, every engine added later is silently trusted."
    )


@pytest.mark.parametrize("status", sorted(core.GATE_TRUSTED_STATUSES))
def test_trusted_statuses_are_exactly_the_three_defensible_ones(status):
    assert status in (core.ENGINE_OK, core.ENGINE_NOT_APPLICABLE, core.ENGINE_DISABLED), (
        f"{status!r} was added to the gate's trusted set. Only three states justify "
        "reading an engine's silence as meaningful: it ran (ok), there was nothing of "
        "its kind in the target (not-applicable), or the operator switched it off "
        "(disabled). Anything else means PRAETOR did not look."
    )


@pytest.mark.parametrize("status", [core.ENGINE_ERROR, core.ENGINE_UNAVAILABLE])
def test_both_failure_states_block(status):
    assert core.engine_blind_spots({"e": {"status": status, "detail": ""}}), (
        f"{status!r} must block a gate: the engine did not measure the target"
    )


# --------------------------------------------------------------------------- #
# The report -- the human reading path, same defect
# --------------------------------------------------------------------------- #

def test_empty_report_says_it_was_not_fully_measured():
    """"No active findings" is the line most likely to be misread as a clean bill."""
    result = {"active": [], "filtered": [], "summary": {}, "total_active": 0, "total_filtered": 0}
    meta = {"target": "t", "timestamp": "now", "version": "x", "file_count": 1,
            "engines": {"sast": {"status": core.ENGINE_ERROR, "detail": "semgrep died"}}}

    text = report.render_text(result, meta)
    assert "No active findings" in text, "fixture assumption changed"
    assert "NOT fully measured" in text, (
        "a reader who skips to 'No active findings' gets a clean bill of health from "
        "a scan whose engine died. The caveat must appear at that line, not only in "
        "the engine-status block above it."
    )


def test_unavailable_no_longer_renders_as_skipped():
    """`[skipped]` reads as 'nothing to do here'. It meant 'could not look'."""
    result = {"active": [], "filtered": [], "summary": {}, "total_active": 0, "total_filtered": 0}
    meta = {"target": "t", "timestamp": "now", "version": "x", "file_count": 1,
            "engines": {"sast": {"status": core.ENGINE_UNAVAILABLE,
                                 "detail": "no semgrep runtime found"}}}

    text = report.render_text(result, meta)
    assert "[skipped]" not in text, (
        "an engine that could not run was marked [skipped], the same word a reader "
        "applies to a step that was legitimately unnecessary"
    )
    assert "[BLIND]" in text


# --------------------------------------------------------------------------- #
# 🔴 EVERY ENGINE TRUSTED, NONE OF THEM MEASURED (found by independent audit,
# re-derived here before fixing)
#
# GATE_TRUSTED_STATUSES answers a PER-ENGINE question -- "can I trust this
# engine's silence?" -- and answers it correctly. Nothing asked the WHOLE-SCAN
# question: "did anything actually look?" So a scan in which every engine was
# individually trustworthy and none of them ran was a clean bill of health.
#
# Measured before the fix: `--engines "" --fail-on INFO` on a tree containing a
# live credential parsed to [], left all four engines `disabled`, and exited 0.
# An INVALID engine name was correctly rejected with exit 2 -- so the typo was
# caught and the empty string was not, which is how it would reach CI as
# `--engines "$ENGINES"` with the variable unset.
# --------------------------------------------------------------------------- #

def test_an_empty_engine_selection_is_rejected_rather_than_scanned(tmp_path):
    """`--engines ""` is a usage error, not a scan that found nothing."""
    for spelling in ("", "   ", ",", " , ,"):
        rc = _run([_clean_target(tmp_path), "--engines", spelling, "--fail-on", "INFO",
                   "--format", "json", "--quiet"])
        assert rc == 2, (
            f"--engines {spelling!r} selected no engines and returned {rc}. "
            f"An empty selection scans nothing; 0 would be a false clean."
        )


def test_a_scan_of_only_trusted_silences_cannot_pass_the_gate(tmp_path):
    """🔴 The guarantee, keyed on the property rather than the spelling.

    `--engines sca` against a target with no dependency manifests leaves sca
    `not-applicable` and the other three `disabled` -- four individually trusted
    statuses, zero engines that looked at anything. This route does not involve
    the empty string at all, which is the point: fixing only `--engines ""`
    would close the instance the audit demonstrated and leave the class open.
    """
    rc = _run([_clean_target(tmp_path), "--engines", "sca", "--fail-on", "INFO",
               "--format", "json", "--quiet"])
    assert rc == 3, (
        f"no engine measured this target and the gate returned {rc}. Every status "
        f"was trusted; none of them was a measurement."
    )


def test_allow_degraded_is_still_the_only_way_past_the_floor(tmp_path):
    """The operator can knowingly accept it -- but must say so."""
    rc = _run([_clean_target(tmp_path), "--engines", "sca", "--fail-on", "INFO",
               "--allow-degraded", "--format", "json", "--quiet"])
    assert rc == 0, f"--allow-degraded must opt out of the floor; got {rc}"


def test_measuring_is_strictly_narrower_than_being_trusted():
    """The set relationship IS the defect, so assert it directly.

    If these two sets ever become equal, the whole-scan floor silently stops
    meaning anything -- it would fire only when the degraded path already had.
    """
    assert core.ENGINE_MEASURED_STATUSES < core.GATE_TRUSTED_STATUSES, (
        "measured statuses must be a PROPER subset of trusted ones; an engine "
        "can be trustworthy without having measured anything"
    )
    all_silent = {name: {"status": core.ENGINE_DISABLED, "detail": "not selected"}
                  for name in ("sast", "secrets", "sca", "aisec")}
    assert core.engine_blind_spots(all_silent) == [], "premise: every status is trusted"
    assert core.engines_that_measured(all_silent) == [], (
        "four trusted silences are not a measured scan"
    )


def test_the_degraded_path_keeps_its_own_diagnosis(tmp_path, monkeypatch, capsys):
    """Ordering matters: a broken engine is a different fault from an empty scan.

    Both exit 3, so the exit code alone cannot distinguish them -- the operator
    needs the message that names which one happened.
    """
    _break_secrets(monkeypatch)
    rc = _run([_clean_target(tmp_path), "--fail-on", "INFO", "--format", "json", "--quiet"])
    err = capsys.readouterr().err
    assert rc == 3
    assert "SCAN DEGRADED" in err, "a broken engine must still be diagnosed as degraded"
    assert "NOTHING WAS MEASURED" not in err, (
        "the whole-scan floor must not swallow the degraded path's diagnosis; "
        "other engines did measure here"
    )


def test_when_both_faults_hold_the_more_specific_diagnosis_wins(tmp_path, monkeypatch, capsys):
    """🔴 ORDERING. Only testable when BOTH conditions are true at once.

    The test above breaks a single engine, so the others still measure and the
    whole-scan floor never competes -- it therefore proves nothing about order,
    and a mutation swapping the two blocks left it green. This is the case that
    actually distinguishes them: every engine dead means every engine blind AND
    nothing measured, so both blocks would fire and only the first one speaks.

    `SCAN DEGRADED` must win, because it names WHICH engines failed and why.
    `NOTHING WAS MEASURED` is true here too and strictly less actionable.
    """
    def boom(*a, **kw):
        raise RuntimeError("simulated engine failure")

    for mod in (engine_secrets, engine_sast, engine_sca, engine_aisec):
        monkeypatch.setattr(mod, "scan", boom, raising=False)
        monkeypatch.setattr(mod, "run", boom, raising=False)

    rc = _run([_clean_target(tmp_path), "--fail-on", "INFO", "--format", "json", "--quiet"])
    err = capsys.readouterr().err

    assert rc == 3, f"every engine failed and the gate returned {rc}"
    assert "SCAN DEGRADED" in err, (
        "with every engine dead, both blocks are true -- the degraded path must "
        "answer, because it names the engines and the floor does not"
    )
    assert "NOTHING WAS MEASURED" not in err, (
        "the floor answered a question the degraded path answers better; the two "
        "blocks are in the wrong order"
    )


# --------------------------------------------------------------------------- #
# THE FLOOR MUST BE A MEASUREMENT, NOT A STATUS WORD
#
# Added 2026-08-13, after an independent reader falsified the claim that the
# measured-engine floor above closed the "trusted but never looked" class.
# It did not. It reads `engine_meta[...]["status"]`, and an engine handed an
# EMPTY FILE LIST returns without raising and is recorded `ok`. So the floor
# said "an engine measured" about an engine that had opened nothing, and
# `--exclude ""` -- one flag over from the `--engines ""` that motivated it --
# exited 0 on a tree containing a live-shaped credential.
#
# The repair is a term no silence can satisfy: `len(scan_files)`, the count of
# files actually opened. These tests assert the COUNT-based property, and one of
# them deliberately uses a route the fix was NOT written against.
# --------------------------------------------------------------------------- #

# Assembled from fragments so this file does not itself trip the secrets engine
# it exercises -- the repo rule is "fix the fixture, not the rules".
_LIVE_SHAPED_KEY = "sk-" + "ant-" + "api03-" + ("A" * 80)


def _target_with_a_real_finding(tmp_path):
    """A target that provably HAS something to find.

    🔴 The arming half. `exit 3 because 0 files were scanned` is indistinguishable
    from `exit 3 because the tree was empty anyway` unless the control proves the
    finding was there to be missed.
    """
    (tmp_path / "settings.py").write_text(
        f'ANTHROPIC_API_KEY = "{_LIVE_SHAPED_KEY}"\n', encoding="utf-8"
    )
    return str(tmp_path)


def test_the_control_actually_finds_the_key(tmp_path):
    """ARMING CHECK -- every test below is void if this one does not fail loudly."""
    rc = _run([_target_with_a_real_finding(tmp_path), "--engines", "secrets",
               "--fail-on", "INFO", "--format", "json", "--quiet"])
    assert rc == 1, (
        f"premise broken: the control scan must FIND the planted key and exit 1, "
        f"got {rc}. Every zero-file assertion below is meaningless without this."
    )


def test_an_empty_exclude_pattern_cannot_produce_a_clean_bill_of_health(tmp_path):
    """THE HEADLINE OF THIS BLOCK. `--exclude ""` matches every path.

    Measured before the fix: `Files (text): 0`, `Findings (active): 0`, exit 0 --
    on the same tree the control above exits 1 for.
    """
    rc = _run([_target_with_a_real_finding(tmp_path), "--engines", "secrets",
               "--fail-on", "INFO", "--exclude", "", "--format", "json", "--quiet"])
    assert rc == 2, (
        f"an empty --exclude excludes the whole tree and must be rejected, got {rc}"
    )


def test_the_floor_catches_a_route_it_was_not_written_against(tmp_path):
    """🔴 THE POINT OF KEYING ON A COUNT.

    No code anywhere special-cases `--max-file-size`. This route empties the tree
    by a completely different mechanism than the empty exclude regex, and it must
    fail identically -- because the floor asks how many files were opened, not
    how any engine described itself.

    If this test ever needs its own carve-out to pass, the floor has stopped
    being a measurement and gone back to being an enumeration of known routes.
    """
    rc = _run([_target_with_a_real_finding(tmp_path), "--engines", "secrets",
               "--fail-on", "INFO", "--max-file-size", "1", "--format", "json",
               "--quiet"])
    assert rc == 3, (
        f"a byte cap that excludes every file must hit the NOTHING WAS EXAMINED "
        f"floor, got {rc}"
    )


def test_a_prefix_of_the_bypass_flag_does_not_reach_it(tmp_path):
    """argparse abbreviates long options BY DEFAULT.

    `--allow` was an unambiguous prefix of `--allow-degraded`, so seven characters
    turned exit 3 into exit 0. An exit code is this tool's whole contract with CI;
    no prefix of a bypass flag may be spelled by accident.
    """
    with pytest.raises(SystemExit) as exc:
        _run([_clean_target(tmp_path), "--engines", "sca", "--fail-on", "INFO",
              "--allow", "--format", "json", "--quiet"])
    assert exc.value.code == 2, (
        f"--allow must be an argparse error, not a silent bypass; got exit "
        f"{exc.value.code}"
    )


def test_the_full_spelling_of_the_bypass_still_works(tmp_path):
    """KEEP DIRECTION. Closing the abbreviation must not break the real flag."""
    rc = _run([_clean_target(tmp_path), "--engines", "sca", "--fail-on", "INFO",
               "--allow-degraded", "--format", "json", "--quiet"])
    assert rc == 0, f"--allow-degraded must still opt out of the floor; got {rc}"


def test_a_genuinely_measured_clean_tree_still_passes(tmp_path):
    """KEEP DIRECTION. The floor must not make every clean scan exit 3.

    This is the assertion that distinguishes 'narrowed the gate' from 'jammed the
    gate shut', which look identical from the outside.
    """
    rc = _run([_clean_target(tmp_path), "--engines", "secrets", "--fail-on", "INFO",
               "--format", "json", "--quiet"])
    assert rc == 0, f"a real scan of a real clean tree must still pass; got {rc}"


def test_the_floor_is_not_suppressed_by_an_unselected_engines_walk(tmp_path):
    """🔴 A REGRESSION THIS SUITE DID NOT CATCH, found by adversarial audit.

    The secrets engine walks wider than the others (it must: a credential in
    `vendor/` is disclosed). The floor was briefly written as
    `not scan_files and not secret_files` -- and since `secret_files` is a strict
    SUPERSET of `scan_files`, that collapses to `not secret_files`, so the floor
    stopped protecting the narrow walk entirely.

    Measured: a tree whose only content was an os.system concat under `vendor/`
    went from exit 3 to exit 0, and with `--engines sast` the floor was suppressed
    by a walk belonging to an engine the operator had switched OFF.

    ⇒ A floor may only be satisfied by work a SELECTED engine actually did.
    """
    v = tmp_path / "vendor"
    v.mkdir()
    (v / "app.py").write_text(
        "import os" + chr(10) + "def h(e):" + chr(10) + "    os.system('ls ' + e)" + chr(10),
        encoding="utf-8")
    rc = _run([str(tmp_path), "--engines", "sast", "--fail-on", "INFO",
               "--format", "json", "--quiet"])
    assert rc == 3, (
        f"nothing SAST can read was enumerated, so this is not a clean result; got {rc}"
    )


def test_the_report_carries_both_file_counts(tmp_path):
    """schema_version 3.0: `file_count` no longer covers every finding.

    The secrets engine walks wider than the others, so a finding can be reported
    in a file `file_count` never counted. A consumer treating `file_count == 0` as
    "nothing was scanned" is wrong, and needs `secret_file_count` to know it.

    Behavioural, not a config check: asserting SCHEMA_VERSION == "3.0" would pass
    happily while the field it describes was deleted.
    """
    v = tmp_path / "vendor"
    v.mkdir()
    (v / "creds.py").write_text(
        'API_KEY = "' + "sk-" + "ant-" + "api03-" + ("E" * 80) + '"' + chr(10),
        encoding="utf-8")
    out = tmp_path / "out"
    _run([str(tmp_path), "--engines", "secrets", "--format", "json",
          "--out", str(out), "--quiet"])
    data = json.loads((out / "praetor-report.json").read_text(encoding="utf-8"))
    meta = data["meta"]
    assert "secret_file_count" in meta, (
        "schema 3.0 promises meta.secret_file_count; consumers cannot otherwise "
        "tell that a finding came from a file file_count never counted"
    )
    assert meta["secret_file_count"] > meta["file_count"], (
        f"the secrets walk must be wider here; got {meta['secret_file_count']} "
        f"vs {meta['file_count']}"
    )
    assert data["findings"], "premise: the vendored credential must be found"
