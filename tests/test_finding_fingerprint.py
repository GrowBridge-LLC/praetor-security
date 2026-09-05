"""
A finding needs TWO identities, and confusing them breaks every consumer that
compares one scan to another.

`dedup_key` answers "are these the same finding IN THIS SCAN?" It includes the
LINE, correctly: two hits on different lines of one file are two findings.

`fingerprint` answers "is this the same finding as one in a PREVIOUS scan?" It
must NOT include the line.

🔴 WHY. Measured on the real CLI: the identical credential at line 1 and then at
line 3, after two lines were added above it, produced two different `dedup_key`
values. Anything keyed on that -- a dashboard, a CI job gating only on NEW
findings, a triage note attached to a finding -- reports a wall of false "new
findings" on any commit that adds an import.

This is the same class as the KB-anchor defect this repository hit the same week:
a prepend invalidates every anchor below it.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from core import Finding, Severity, Confidence  # noqa: E402

_PRAETOR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "praetor.py")

# Assembled from parts: written whole, this file's own self-scan would flag it.
_KEY = "AKIA" + "QWERTYUIOPASDFGH"


def _f(line, snippet="the same code", file="a/b.py", rule_id="r"):
    f = Finding(
        engine="aisec", rule_id=rule_id, title="t", severity=Severity.HIGH,
        confidence=Confidence.HIGH, file=file, line=line,
        category="PROMPT_INJECTION", description="d", snippet=snippet,
        fix="f", cwe="CWE-77",
    )
    f.compute_dedup_key()
    f.compute_fingerprint()
    return f


def _scan(tmp_path, body):
    (tmp_path / "a.py").write_text(body, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, _PRAETOR, str(tmp_path), "--engines", "secrets",
         "--no-registry", "--format", "json", "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    return json.loads(proc.stdout)


# --------------------------------------------------------------------------- #
# The property the SaaS layer depends on
# --------------------------------------------------------------------------- #

def test_a_fingerprint_survives_the_finding_moving_down_a_file(tmp_path):
    """🔴 THE WHOLE POINT. Adding an import must not make every finding below it
    look new."""
    before = _scan(tmp_path, f'KEY = "{_KEY}"\n')
    after = _scan(tmp_path, f'import os\n# a new line\nKEY = "{_KEY}"\n')

    a, b = before["findings"][0], after["findings"][0]
    assert a["line"] != b["line"], "the fixture must actually move the finding"
    assert a["fingerprint"] == b["fingerprint"], \
        "a finding that only MOVED must keep its cross-scan identity"


def test_the_dedup_key_still_distinguishes_lines(tmp_path):
    """🔴 THE KEEP DIRECTION. Making the fingerprint line-independent must not
    have blunted the WITHIN-scan key -- two hits on different lines of one file
    really are two findings, and merging them would lose one."""
    before = _scan(tmp_path, f'KEY = "{_KEY}"\n')
    after = _scan(tmp_path, f'import os\n# a new line\nKEY = "{_KEY}"\n')
    assert before["findings"][0]["dedup_key"] != after["findings"][0]["dedup_key"]


def test_two_findings_on_different_lines_do_not_merge(tmp_path):
    """The same keep direction, stated as the behaviour a user would notice."""
    data = _scan(tmp_path, f'A = "{_KEY}"\nB = "{_KEY}"\n')
    keys = {f["dedup_key"] for f in data["findings"]}
    assert len(data["findings"]) == 2 and len(keys) == 2


# --------------------------------------------------------------------------- #
# What the fingerprint must and must not depend on
# --------------------------------------------------------------------------- #

def test_the_fingerprint_changes_when_the_code_changes():
    """It is an identity, not a label. Different code is a different finding."""
    assert _f(10).fingerprint != _f(10, snippet="different code").fingerprint


def test_the_fingerprint_changes_with_the_rule_and_the_file():
    assert _f(10).fingerprint != _f(10, rule_id="other").fingerprint
    assert _f(10).fingerprint != _f(10, file="c/d.py").fingerprint


def test_the_fingerprint_ignores_severity_and_confidence():
    """A rule re-rating must not orphan an existing triage record. The issue did
    not change; the tool's opinion of it did."""
    a = _f(10)
    b = _f(10)
    b.severity, b.confidence = Severity.LOW, Confidence.LOW
    b.compute_fingerprint()
    assert a.fingerprint == b.fingerprint


def test_the_fingerprint_normalises_whitespace():
    """Reformatting is not a new finding."""
    a = _f(10, snippet="x  =   1")
    b = _f(10, snippet="x = 1")
    assert a.fingerprint == b.fingerprint


def test_two_identical_lines_share_a_fingerprint_and_that_is_accepted():
    """🔴 THE STATED LIMIT, asserted so it is a decision rather than a surprise.

    Without a line number there is nothing to tell two identical lines apart. A
    consumer that needs to should group by fingerprint and count. SARIF's own
    `partialFingerprints` has the same property for the same reason.
    """
    assert _f(10).fingerprint == _f(99).fingerprint


# --------------------------------------------------------------------------- #
# It must not leak
# --------------------------------------------------------------------------- #

def test_a_fingerprint_cannot_carry_a_credential(tmp_path):
    """The basis includes the snippet, and the snippet is REDACTED at the Finding
    boundary before this can run. A fingerprint is stored and transmitted by
    whatever consumes it, so this is a disclosure boundary, not a detail."""
    data = _scan(tmp_path, f'KEY = "{_KEY}"\n')
    f = data["findings"][0]
    assert _KEY not in f["snippet"], "the snippet must already be redacted"
    assert _KEY not in f["fingerprint"]
    assert len(f["fingerprint"]) == 16 and all(
        c in "0123456789abcdef" for c in f["fingerprint"])


def test_every_finding_in_the_report_carries_one(tmp_path):
    """A consumer must never meet a finding without an identity -- including a
    FILTERED one, which a dashboard still shows and a reviewer still triages."""
    data = _scan(tmp_path, f'KEY = "{_KEY}"\n# pad\n')
    for f in data["findings"] + data["filtered"]:
        assert f.get("fingerprint"), f"missing fingerprint: {f['rule_id']}"
