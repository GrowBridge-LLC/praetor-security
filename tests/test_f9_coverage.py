import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import engine_secrets
import praetor
from core import Finding, ScanFile


def test_secrets_long_line_emits_one_coverage_finding():
    payload = "a" * 4001
    sf = ScanFile("fixture.txt", "fixture.txt", len(payload))
    findings = engine_secrets.scan([sf], lambda _path: payload)
    coverage = [f for f in findings if f.category == "COVERAGE"]
    assert len(coverage) == 1


def test_secrets_coverage_survives_inline_ignore():
    finding = Finding(
        engine="secrets", rule_id="secrets-long-line-skip", title="coverage",
        severity="INFO", confidence="HIGH", file="fixture.py", line=1,
        category="COVERAGE", description="coverage", snippet="coverage",
        fix="split line",
    )
    source = "# praetor: ignore " + ("x" * 4001) + "\n"
    praetor._apply_inline_ignores([finding], "/t", lambda _path: source)
    assert not getattr(finding, "filtered", False)
