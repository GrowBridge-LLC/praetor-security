"""
Attack-chain correlation (scripts/chains.py): findings that COMPOSE.

The safety properties asserted here are the ones that make this layer safe to
add at all -- it may only ADD a chains section, and must never suppress,
downgrade, re-bucket, or otherwise touch a finding. A correlation pass that
could downgrade would be a suppression mechanism wearing a different name.
"""

import chains
from core import Finding, Severity, Confidence
from interpret import interpret


def _f(engine, rule_id, category, file, line=1, severity=Severity.MEDIUM):
    return Finding(
        engine=engine, rule_id=rule_id, title=f"{rule_id} title",
        severity=severity, confidence=Confidence.MEDIUM,
        file=file, line=line, category=category,
        description="d", snippet="s", fix="f",
    )


def _chain_ids(hits):
    return {c["chain_id"] for c in hits}


def test_injection_plus_autorun_composes_into_a_critical_chain():
    hits = chains.correlate([
        _f("aisec", "prompt-injection-override", "PROMPT_INJECTION", "README.md"),
        _f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", ".claude/settings.json"),
    ])
    assert "chain-injection-to-autorun" in _chain_ids(hits)
    chain = next(c for c in hits if c["chain_id"] == "chain-injection-to-autorun")
    assert chain["severity"] == "CRITICAL", "a chain may exceed its links' severity -- that IS the finding"
    assert len(chain["links"]) == 2


def test_a_lone_finding_forms_no_chain():
    """THE KEEP DIRECTION. One half of a chain is not a chain."""
    assert chains.correlate([
        _f("aisec", "prompt-injection-override", "PROMPT_INJECTION", "README.md"),
    ]) == []
    assert chains.correlate([
        _f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", ".claude/settings.json"),
    ]) == []


def test_one_finding_satisfying_both_links_is_not_a_chain():
    """THE KEEP DIRECTION, and the subtle one: one problem counted twice is not
    a composition of two problems.

    ⚠️ This test's FIRST draft was vacuous and a mutation caught it. It used a
    single `mcp-server-autostart` finding, reasoning that an MCP autostart is
    also categorised DANGEROUS_HOOK so the predicates overlap. They do -- but
    no chain pairs those two predicates, so that input failed every chain at
    its FIRST link and returned [] whether or not the distinct-findings check
    existed at all. Disabling the check left the test green.

    The construction below is the one that actually reaches the check: a
    secrets-engine finding whose category is EXFIL satisfies BOTH links of
    chain-credential-plus-exfil-path by itself (`engine == "secrets"` and
    `category == "EXFIL"` can genuinely coexist on one finding, unlike the
    two-different-rule_ids and two-different-categories pairings every other
    chain uses -- those are structurally impossible for one finding and so
    could never have tested this)."""
    single = _f("secrets", "env-file-credential", "EXFIL", "config/.env", severity=Severity.HIGH)
    assert chains.correlate([single]) == [], \
        "one finding satisfying both links must not be reported as a chain"


def test_remote_mcp_with_credentials_is_the_sharper_critical_chain():
    hits = chains.correlate([
        _f("aisec", "mcp-server-autostart-remote", "DANGEROUS_HOOK", ".mcp.json", 3),
        _f("aisec", "mcp-server-credential-env", "EXFIL", ".mcp.json", 3, Severity.HIGH),
    ])
    ids = _chain_ids(hits)
    assert "chain-remote-mcp-with-credentials" in ids
    assert "chain-mcp-autostart-with-credentials" in ids, \
        "the remote variant also satisfies the general autostart chain; both are true"
    remote = next(c for c in hits if c["chain_id"] == "chain-remote-mcp-with-credentials")
    assert remote["severity"] == "CRITICAL"


def test_chains_are_ordered_most_dangerous_first():
    hits = chains.correlate([
        _f("aisec", "mcp-server-autostart-remote", "DANGEROUS_HOOK", ".mcp.json", 3),
        _f("aisec", "mcp-server-credential-env", "EXFIL", ".mcp.json", 3),
        _f("aisec", "prompt-injection-override", "PROMPT_INJECTION", "README.md"),
    ])
    severities = [c["severity"] for c in hits]
    assert severities == sorted(
        severities, key=lambda s: -{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[s]
    ), "Severity is an IntEnum where higher is worse -- CRITICAL must lead, not trail"


def test_credential_plus_exfil_keys_on_the_secrets_ENGINE_not_a_rule_name():
    """The credential link asks the secrets engine, because that engine exists
    to answer exactly this question -- a name-substring guess would drift the
    moment a rule is renamed."""
    hits = chains.correlate([
        _f("secrets", "aws-access-key-id", "SECRET", "config/aws.env", severity=Severity.HIGH),
        _f("aisec", "env-exfil", "EXFIL", "scripts/deploy.sh"),
    ])
    assert "chain-credential-plus-exfil-path" in _chain_ids(hits)


def test_correlation_never_mutates_or_suppresses_a_finding():
    """🔴 THE SAFETY PROPERTY. This layer may only ADD. If it could downgrade
    or re-bucket, it would be a suppression mechanism needing the whole
    carve-out discipline CLAUDE.md demands of suppression."""
    findings = [
        _f("aisec", "prompt-injection-override", "PROMPT_INJECTION", "README.md"),
        _f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", ".claude/settings.json"),
    ]
    before = [(f.severity, f.filtered, f.filter_reason, f.category) for f in findings]
    chains.correlate(findings)
    after = [(f.severity, f.filtered, f.filter_reason, f.category) for f in findings]
    assert before == after, "correlate() mutated a finding -- it must only read"


def test_filtered_findings_cannot_form_a_chain_through_the_pipeline():
    """A filtered finding was assessed inert WITH A STATED REASON. Letting it
    form a link would re-admit through the side door exactly what the filter
    just excluded, invisibly to whoever reads filter_reason."""
    planted = _f("aisec", "prompt-injection-override", "PROMPT_INJECTION", "README.md")
    planted.filtered = True
    planted.filter_reason = "documentation prose"
    autorun = _f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", ".claude/settings.json")

    result = interpret([planted, autorun])
    assert result["chains"] == [], "a filtered finding must not form a chain link"


def test_interpret_always_emits_a_chains_key_even_when_empty():
    """An empty chains list is not the same as a missing key -- a consumer must
    be able to tell 'no chain matched' from 'this report predates chains'."""
    result = interpret([_f("aisec", "prompt-injection-override", "PROMPT_INJECTION", "README.md")])
    assert "chains" in result
    assert result["chains"] == []
