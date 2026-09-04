"""
Agent capability profile (scripts/capability.py).

The property that matters most here is the honesty of the vocabulary: a
capability is reported PRESENT or `none`, never SAFE. `none` means no rule
matched it -- the same claim PRAETOR always makes -- and the tests below hold
that line, because a summariser that quietly upgrades "nothing matched" into
"nothing there" is exactly the false-clean this tool exists to prevent.
"""

import capability
from core import Finding, Severity, Confidence
from interpret import interpret


def _f(engine, rule_id, category, file="x", line=1, severity=Severity.MEDIUM):
    return Finding(
        engine=engine, rule_id=rule_id, title=f"{rule_id} title",
        severity=severity, confidence=Confidence.MEDIUM,
        file=file, line=line, category=category,
        description="d", snippet="s", fix="f",
    )


def test_autorun_finding_raises_the_executes_on_load_capability():
    prof = capability.profile([
        _f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", ".claude/settings.json"),
    ])
    assert prof["executes_on_load"]["status"] == "present"
    assert prof["executes_on_load"]["evidence_count"] == 1
    assert prof["executes_on_load"]["examples"][0]["rule_id"] == "agent-hook-autorun"


def test_credentials_capability_covers_both_shapes():
    """A credential sitting in the tree and one handed to a third-party
    process are different problems that raise the same capability."""
    in_tree = capability.profile([
        _f("secrets", "aws-access-key-id", "SECRET", "config/aws.env"),
    ])
    handed_over = capability.profile([
        _f("aisec", "mcp-server-credential-env", "EXFIL", ".mcp.json"),
    ])
    assert in_tree["holds_credentials"]["status"] == "present"
    assert handed_over["holds_credentials"]["status"] == "present"


def test_absent_capability_reads_none_and_the_summary_refuses_to_say_safe():
    """🔴 THE HONESTY PROPERTY. Nothing matched must never render as a clean
    bill of health."""
    prof = capability.profile([])
    assert all(d["status"] == "none" for d in prof.values())

    line = capability.summary_line(prof)
    lowered = line.lower()
    assert "safe" not in lowered, "an empty profile must never claim safety"
    assert "no rule matched" in lowered, \
        "the empty case must state WHY it is empty, not just that it is"


def test_summary_line_names_the_present_capabilities():
    prof = capability.profile([
        _f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", ".claude/settings.json"),
        _f("secrets", "aws-access-key-id", "SECRET", "config/aws.env"),
    ])
    line = capability.summary_line(prof)
    assert "executes on load" in line
    assert "holds credentials" in line


def test_profile_never_mutates_a_finding():
    findings = [_f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", ".claude/settings.json")]
    before = [(f.severity, f.filtered, f.filter_reason, f.category) for f in findings]
    capability.profile(findings)
    after = [(f.severity, f.filtered, f.filter_reason, f.category) for f in findings]
    assert before == after, "profile() mutated a finding -- it must only read"


def test_filtered_findings_do_not_raise_a_capability_through_the_pipeline():
    """Same reasoning as chains: a filtered finding was assessed inert with a
    written rationale, and raising a capability off it would re-admit it
    invisibly to whoever reads that rationale."""
    suppressed = _f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", "docs/example.md")
    suppressed.filtered = True
    suppressed.filter_reason = "documentation prose"

    result = interpret([suppressed])
    assert result["capability_profile"]["executes_on_load"]["status"] == "none"


def test_interpret_always_emits_the_profile_key():
    result = interpret([])
    assert "capability_profile" in result
    assert set(result["capability_profile"]) == {k for k, _q, _p, _n in capability.DIMENSIONS}
