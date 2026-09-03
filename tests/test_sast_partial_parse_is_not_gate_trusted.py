"""
SAST's error classification must distinguish PartialParsing from every other
semgrep error_type -- and must do it by TYPE, never by LEVEL.

MEASURED DEFECT, found by independent adversarial audit and never shipped: an
earlier attempt at this exact classification filtered on semgrep's `level`
field (only `level: "warn"` items were treated as non-fatal). That is provably
unsafe -- Timeout, OutOfMemory, StackOverflow and FixpointTimeout all share
`level: "warn"` with PartialParsing. ⚠️ That's an EMPIRICAL fact about running
semgrep, confirmed by two independent audits invoking real semgrep 1.175.0 and
reading its actual JSON output -- NOT something semgrep_output_v1.py states.
That file's ErrorType class only names the type CONSTRUCTORS (Timeout,
PartialParsing, ...); which ones semgrep assigns which severity is decided by
semgrep-core's own error-classification logic, not declared anywhere in this
Python interface. A real exploit was demonstrated on top of this: deleting one
bracket character from a vulnerable file made PartialParsing's own span
swallow a block containing `eval $PAYLOAD`, flipping the scan from
correctly-blocked to a silent pass.

This file asserts the fix in both directions:
  * a PartialParsing-only errors list downgrades to core.ENGINE_PARTIAL_PARSE
  * ANY other error_type present -- alone or mixed with PartialParsing --
    stays core.ENGINE_ERROR, the harsher classification
  * core.ENGINE_PARTIAL_PARSE is NOT in core.GATE_TRUSTED_STATUSES, so a
    --fail-on run still refuses to certify it clean (see
    test_exit_code_never_hides_a_blind_spot.py for the CLI-level proof)
"""

import subprocess

import core
import engine_sast


def test_no_errors_is_ok():
    assert engine_sast._classify_scan_errors([]) == core.ENGINE_OK


def test_partial_parsing_only_downgrades():
    errors = [{"level": "warn", "type": ["PartialParsing", [{"path": "a.py"}]]}]
    assert engine_sast._classify_scan_errors(errors) == core.ENGINE_PARTIAL_PARSE


def test_multiple_partial_parsing_entries_still_downgrade():
    errors = [
        {"level": "warn", "type": ["PartialParsing", []]},
        {"level": "warn", "type": ["PartialParsing", []]},
    ]
    assert engine_sast._classify_scan_errors(errors) == core.ENGINE_PARTIAL_PARSE


def test_timeout_alone_is_a_hard_error():
    errors = [{"level": "warn", "type": "Timeout"}]
    assert engine_sast._classify_scan_errors(errors) == core.ENGINE_ERROR


def test_out_of_memory_alone_is_a_hard_error():
    errors = [{"level": "warn", "type": "OutOfMemory"}]
    assert engine_sast._classify_scan_errors(errors) == core.ENGINE_ERROR


def test_stack_overflow_alone_is_a_hard_error():
    errors = [{"level": "warn", "type": "StackOverflow"}]
    assert engine_sast._classify_scan_errors(errors) == core.ENGINE_ERROR


def test_fixpoint_timeout_alone_is_a_hard_error():
    errors = [{"level": "warn", "type": "FixpointTimeout"}]
    assert engine_sast._classify_scan_errors(errors) == core.ENGINE_ERROR


def test_the_exploit_scenario_mixed_partial_parsing_and_timeout_is_a_hard_error():
    """🔴 THE ACTUAL EXPLOIT SCENARIO. A Timeout riding alongside PartialParsing
    entries -- e.g. one file that partially parsed, another that timed out --
    must not be laundered into the softer status just because PartialParsing
    is also present. Same `level: "warn"` on both; different `type`."""
    errors = [
        {"level": "warn", "type": ["PartialParsing", []]},
        {"level": "warn", "type": "Timeout"},
    ]
    assert engine_sast._classify_scan_errors(errors) == core.ENGINE_ERROR, (
        "a real Timeout must not be hidden behind a PartialParsing entry in the "
        "same errors list -- this is the exact shape the demonstrated exploit used"
    )


def test_unrecognised_future_error_type_fails_toward_hard_error():
    """A semgrep release adding a new error_type variant must fail toward
    ENGINE_ERROR, the same fail-safe direction every allowlist in this repo
    takes on an unrecognised value."""
    errors = [{"level": "warn", "type": "SomeFutureErrorType"}]
    assert engine_sast._classify_scan_errors(errors) == core.ENGINE_ERROR


def test_error_type_name_handles_both_serialization_shapes():
    """Unit variants (Timeout) serialize as a bare string; variants carrying
    data (PartialParsing) serialize as a [name, payload] pair. Both must
    resolve to the same type name."""
    assert engine_sast._error_type_name({"type": "Timeout"}) == "Timeout"
    assert engine_sast._error_type_name({"type": ["PartialParsing", []]}) == "PartialParsing"
    assert engine_sast._error_type_name({"type": None}) == ""
    assert engine_sast._error_type_name({}) == ""


def test_error_type_name_discriminates_among_list_shaped_variants():
    """🔴 semgrep's error_type union has FOUR list-shaped (payload-carrying)
    variants, not just PartialParsing: PatternParseError, IncompatibleRule,
    and DependencyResolutionError also serialize as [name, payload]. A
    classifier that returned "PartialParsing" for any list-shaped type would
    pass every other test in this file (they only ever construct
    PartialParsing lists) while silently misclassifying a rule that never
    parsed -- a different, real malfunction -- as the soft status. This test
    exists specifically to catch that shape of bug, which a mutation testing
    pass found nothing else here catches."""
    assert engine_sast._error_type_name({"type": ["PatternParseError", {}]}) == "PatternParseError"
    assert engine_sast._error_type_name({"type": ["IncompatibleRule", {}]}) == "IncompatibleRule"
    assert engine_sast._error_type_name(
        {"type": ["DependencyResolutionError", {}]}) == "DependencyResolutionError"


def test_pattern_parse_error_alone_is_a_hard_error():
    """A RULE that never parsed is a different malfunction from source that
    didn't parse -- whole categories of checks silently never ran. Must not
    be classified as PartialParsing."""
    errors = [{"level": "warn", "type": ["PatternParseError", {}]}]
    assert engine_sast._classify_scan_errors(errors) == core.ENGINE_ERROR


def test_partial_parse_status_is_a_full_malfunction_in_report_only_mode():
    """🔴 THE CORRECTED SAFETY PROPERTY, per an independent adversarial audit
    that reproduced a live exploit against an earlier version of this fix.

    ENGINE_UNAVAILABLE is excused from NON_MALFUNCTION_STATUSES because the
    ENVIRONMENT chooses it -- a scanned tree cannot make semgrep absent from
    the host. ENGINE_PARTIAL_PARSE is chosen BY the scanned tree: a file
    crafted so one bracket is missing decides, on its own, whether SAST
    reports itself degraded. Treating it as a non-malfunction let a
    report-only run (no --fail-on) exit 0 on exactly the adversarial file
    this whole fix exists to catch. It must be a full malfunction, same as
    ENGINE_ERROR, in every mode -- only the JSON status word and detail
    message are more specific than 'error'."""
    assert core.ENGINE_PARTIAL_PARSE not in core.NON_MALFUNCTION_STATUSES, (
        "ENGINE_PARTIAL_PARSE must not be treated as a non-malfunction -- the "
        "scanned tree chooses this status, unlike ENGINE_UNAVAILABLE, so a "
        "report-only run must still refuse it (see engine_malfunctions)"
    )


def test_partial_parse_is_not_gate_trusted():
    """The load-bearing safety property: --fail-on must still refuse this
    status. If this ever goes green after someone adds ENGINE_PARTIAL_PARSE
    to GATE_TRUSTED_STATUSES, the exploit is back."""
    assert core.ENGINE_PARTIAL_PARSE not in core.GATE_TRUSTED_STATUSES


# --------------------------------------------------------------------------- #
# Engine-level: engine_sast.run() actually returns the classified status
# --------------------------------------------------------------------------- #

class _FakeCompleted:
    def __init__(self, stdout):
        self.returncode = 0
        self.stdout = stdout
        self.stderr = ""


def _mock_semgrep(monkeypatch, scan_json):
    def fake_run(cmd, **kwargs):
        if "--version" in cmd:
            return _FakeCompleted("1.170.0\n")
        return _FakeCompleted(scan_json)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(engine_sast.shutil, "which",
                        lambda name: "/usr/bin/semgrep" if name == "semgrep" else None)


def test_run_reports_partial_parse_status_for_partial_parsing_only(tmp_path, monkeypatch):
    (tmp_path / "t.py").write_text("import os\n", encoding="utf-8")
    rules = tmp_path / "r.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    _mock_semgrep(
        monkeypatch,
        '{"results": [], "errors": [{"level": "warn", "type": ["PartialParsing", []]}]}',
    )

    result = engine_sast.run(str(tmp_path), str(rules), use_registry=False)

    assert result["status"] == core.ENGINE_PARTIAL_PARSE, (
        f"expected partial-parse status, got {result['status']!r} / detail: {result['detail']!r}"
    )
    assert "PartialParsing" in result["detail"] or "partial" in result["detail"].lower()


def test_run_reports_hard_error_for_mixed_errors(tmp_path, monkeypatch):
    (tmp_path / "t.py").write_text("import os\n", encoding="utf-8")
    rules = tmp_path / "r.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    _mock_semgrep(
        monkeypatch,
        '{"results": [], "errors": ['
        '{"level": "warn", "type": ["PartialParsing", []]}, '
        '{"level": "warn", "type": "Timeout"}'
        ']}',
    )

    result = engine_sast.run(str(tmp_path), str(rules), use_registry=False)

    assert result["status"] == core.ENGINE_ERROR, (
        f"a Timeout riding with PartialParsing must stay a hard error, got {result['status']!r}"
    )
