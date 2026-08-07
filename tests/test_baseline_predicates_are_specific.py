"""
The suppression predicates must be SPECIFIC, not merely convenient.

A classifier that suppresses everything is exactly as useless as a scanner that
flags everything -- and it fails silently, which is worse. These tests exist
because the first version of P1-DETECTOR-SELF-MATCH did the wrong thing:

    P1 originally matched on DIRECTORY alone ("the finding is under scripts/").
    A planted CRITICAL hardcoded AWS secret in live executable code at
    scripts/_probe_inside.py was classified P1 and SUPPRESSED.

That would have shipped a rule hiding real credentials anywhere in PRAETOR's own
engine directory. It was found by PLANTING A PROBE, not by reading the code --
reasoning about the predicate had already concluded it was fine.

So both directions are asserted here, and both are load-bearing:
  * a real secret in live code under scripts/ must be KEPT   (the regression)
  * a pattern string in a rule table under scripts/ must be SUPPRESSED
    (proves the fix narrowed P1 rather than disabling it)
"""

import classify_baseline


def _finding(file, line, engine="secrets", severity="CRITICAL"):
    return {"file": file, "line": line, "engine": engine, "severity": severity,
            "rule_id": "aws-secret-access-key"}


def _write(tmp_path, monkeypatch, rel, body):
    """Materialise a source file and point the classifier's repo root at it."""
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    monkeypatch.setattr(classify_baseline, "REPO", str(tmp_path))
    return path


# Assembled from parts so this FILE never carries a full credential-shaped token.
# Written out whole it is a real 40-char high-entropy string, and PRAETOR flagged
# this very fixture at CRITICAL on its own self-scan -- correctly, and per the
# policy in test_lexctx_and_suppression_policy.py it must not be suppressed.
# Same idiom as engine_secrets.py:170, which splits its KNOWN_EXAMPLES entries.
_FAKE_KEY = "kQ7bN2xVfR9pLmT4" + "wZ8cJ6yH3dG5sA1e" + "U0iOpXqW"


def test_real_secret_in_live_code_under_scripts_is_kept(tmp_path, monkeypatch):
    """THE REGRESSION. A scalar assignment is live code, not a pattern table."""
    _write(tmp_path, monkeypatch, "scripts/engine_thing.py",
           'import boto3\n'
           f'AWS_SECRET_ACCESS_KEY = "{_FAKE_KEY}"\n'
           'client = boto3.client("s3")\n')

    predicate, _why = classify_baseline.classify(_finding("scripts/engine_thing.py", 2))

    assert predicate == "P7-REVIEW", (
        "SUPPRESSION REGRESSION: a hardcoded credential in live code under scripts/ was "
        f"classified {predicate} instead of P7-REVIEW. P1 must require the match to sit "
        "inside a pattern collection or Finding(...) template -- never directory alone."
    )
    assert classify_baseline.PREDICATES[predicate] == "KEEP"


def test_pattern_string_in_a_rule_table_is_still_suppressed(tmp_path, monkeypatch):
    """The other direction: narrowing P1 must not have disabled it."""
    _write(tmp_path, monkeypatch, "scripts/engine_secrets.py",
           'PLACEHOLDER_TOKENS = (\n'
           '    "changeme",\n'
           '    "AWS_SECRET_ACCESS_KEY",\n'
           ')\n')

    predicate, _why = classify_baseline.classify(_finding("scripts/engine_secrets.py", 3))

    assert predicate == "P1-DETECTOR-SELF-MATCH", (
        f"P1 no longer recognises a genuine pattern table (got {predicate}); the fix "
        "disabled the predicate instead of narrowing it."
    )
    assert classify_baseline.PREDICATES[predicate] == "SUPPRESS"


def test_every_predicate_has_a_declared_disposition():
    """A predicate the classifier can emit but the table cannot dispose of is a crash."""
    emitted = {
        "P1-DETECTOR-SELF-MATCH", "P2-COMMENT", "P3-DOCSTRING",
        "P4-FIXTURE-CORPUS", "P5-DOC-PROSE", "P6-TAXONOMY-LABEL", "P7-REVIEW",
    }
    assert emitted == set(classify_baseline.PREDICATES), (
        "classify() and PREDICATES have drifted apart: "
        f"{emitted ^ set(classify_baseline.PREDICATES)}"
    )
