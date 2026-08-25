import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import engine_aisec
import praetor
from core import Finding, ScanFile


def test_long_line_emits_exactly_one_coverage_finding_per_file():
    payload = "x" * 6001
    sf = ScanFile("fixture.txt", "fixture.txt", len(payload))
    findings = engine_aisec.scan([sf], lambda _path: payload)
    coverage = [f for f in findings if f.category == "COVERAGE"]
    assert len(coverage) == 1
    assert coverage[0].file == "fixture.txt"


def _coverage_finding():
    return Finding(
        engine="aisec", rule_id="aisec-long-line-skip",
        title="coverage", severity="INFO", confidence="HIGH",
        file="fixture.py", line=1, category="COVERAGE",
        description="oversized line skipped", snippet="skipped_lines=1",
        fix="split line",
    )


def test_coverage_survives_lexical_suppression():
    finding = _coverage_finding()
    source = "# " + ("x" * 6001) + "\n"
    praetor._apply_lexical_context([finding], "/t", lambda _path: source)
    assert not getattr(finding, "filtered", False)


def test_coverage_survives_reachability_suppression():
    finding = _coverage_finding()
    finding.file = "fixture.py"
    source = "SECRET=" + ("'" + ("x" * 12) + "'" ) + "\n"
    praetor._apply_reachability([finding], "/t", lambda _path: source)
    assert not getattr(finding, "filtered", False)


def test_coverage_survives_both_suppression_passes():
    finding = _coverage_finding()
    source = "# " + ("x" * 6001) + "\n"
    reader = lambda _path: source
    praetor._apply_lexical_context([finding], "/t", reader)
    praetor._apply_reachability([finding], "/t", reader)
    assert not getattr(finding, "filtered", False)
