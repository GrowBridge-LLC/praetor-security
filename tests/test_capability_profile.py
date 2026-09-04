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


def test_an_npm_lifecycle_script_raises_executes_on_load():
    """🔴 REGRESSION TEST FOR A FOUND GAP. An audit ran PRAETOR on a fixture
    repository whose npm `postinstall` piped a remote script into a shell. The
    capability profile reported `executes_on_load` present -- listing an MCP
    autostart and an agent hook -- and left the postinstall out entirely.

    It is the most unconditional auto-run primitive in the whole rule set: no
    config gate, no matching event, it runs on every `npm install`. It was
    invisible because the predicate keyed only on `category ==
    "DANGEROUS_HOOK"`, and the engine files this rule under SUPPLY_CHAIN.
    """
    prof = capability.profile([
        _f("aisec", "npm-lifecycle-exec", "SUPPLY_CHAIN", "package.json", severity=Severity.HIGH),
    ])
    assert prof["executes_on_load"]["status"] == "present"


def test_a_vulnerable_dependency_does_not_raise_executes_on_load():
    """THE KEEP DIRECTION for the fix above, and the reason it enumerates rule
    ids instead of widening to the category. SUPPLY_CHAIN also holds
    vulnerable-dependency findings, which do not execute on load. Widening the
    category would have been the shorter edit and would have made this
    capability mean something else."""
    prof = capability.profile([
        _f("sca", "vulnerable-dependency", "SUPPLY_CHAIN", "requirements.txt", severity=Severity.HIGH),
    ])
    assert prof["executes_on_load"]["status"] == "none"


def test_evidence_splits_between_shipping_code_and_fixtures():
    """Twelve production configs and one test fixture used to render
    identically as `present`, which is not a decision anyone can make."""
    prof = capability.profile([
        _f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", ".claude/settings.json"),
        _f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", "tests/fixtures/settings.json"),
    ])
    dim = prof["executes_on_load"]
    assert dim["evidence_count"] == 2
    assert dim["production_evidence_count"] == 1
    assert dim["test_or_example_evidence_count"] == 1


def test_a_fixture_only_capability_is_marked_but_never_dropped():
    """🔴 THE FAIL-SAFE DIRECTION. A fixture is still a file an agent can read.
    Suppressing a capability because its evidence sits on a test path would be
    suppression on PATH ALONE, which this project's rules forbid and which has
    already disarmed this scanner once by renaming a file."""
    prof = capability.profile([
        _f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", "tests/fixtures/settings.json"),
    ])
    assert prof["executes_on_load"]["status"] == "present",         "a fixture-only capability must still be reported"
    line = capability.summary_line(prof)
    assert "test/example data only" in line, "it must be MARKED, not silently equal"


def test_the_summary_line_leads_with_the_worst_capability():
    """A flat alphabetical list read identically whether a dimension rested on
    one LOW hit or ten CRITICAL ones.

    ⚠️ The original fixture paired "executes_on_load" (CRITICAL) with
    "holds_credentials" (LOW) -- but `executes_on_load` sorts FIRST both
    alphabetically AND by DIMENSIONS declaration order, independent of any
    severity sort at all. Deleting `present.sort(...)` outright (verified by
    mutation: `# sort call deleted` in capability.py) left this test green,
    because the two dimensions were already in the "right" order before any
    sorting logic ran. It could not tell "sorted by severity" from "sorted by
    dimension key" from "not sorted, just declaration order".

    This fixture picks two dimensions where declaration order AND alphabetical
    order both put the LOW-severity one first ("executes_on_load" before
    "runs_unpinned_code" both ways) -- so only an actual severity-descending
    sort produces the required order.
    """
    prof = capability.profile([
        _f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", ".claude/settings.json",
           severity=Severity.LOW),
        _f("aisec", "remote-code-pipe", "SUPPLY_CHAIN", "install.sh",
           severity=Severity.CRITICAL),
    ])
    assert prof["executes_on_load"]["status"] == "present", "fixture premise: both dimensions must fire"
    assert prof["runs_unpinned_code"]["status"] == "present", "fixture premise: both dimensions must fire"
    line = capability.summary_line(prof)
    assert line.index("runs unpinned code") < line.index("executes on load"),         (
        "the CRITICAL capability must lead the LOW one, even though "
        "'executes_on_load' sorts first both alphabetically and in "
        "DIMENSIONS declaration order -- only severity may decide this"
    )
    assert "[CRITICAL]" in line and "[LOW]" in line,         "each capability must state the worst severity behind it"
