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


def test_injection_plus_autorun_is_reported_but_only_as_co_occurrence():
    """A planted instruction and an auto-run mechanism genuinely live in
    different files -- that separation IS the attack shape, so this chain is
    SAME_TREE and fires.

    🔴 It is capped at MEDIUM, and this assertion is the point of the test. An
    earlier version rated it CRITICAL. "Both categories appear somewhere in
    this repository" is close to certain in any real tree, so that rating
    escalated a coincidence into the report's top line. Co-occurrence earns a
    prompt to look, never an escalation.
    """
    hits = chains.correlate([
        _f("aisec", "prompt-injection-override", "PROMPT_INJECTION", "README.md"),
        _f("aisec", "agent-hook-autorun", "DANGEROUS_HOOK", ".claude/settings.json"),
    ])
    assert "chain-injection-to-autorun" in _chain_ids(hits)
    chain = next(c for c in hits if c["chain_id"] == "chain-injection-to-autorun")
    assert chain["severity"] == "MEDIUM",         "a cross-file co-occurrence must not outrank its own links"
    assert chain["proximity"] == chains.SAME_TREE
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
        _f("aisec", "env-exfil", "EXFIL", "config/aws.env", line=9),
    ])
    assert "chain-credential-plus-exfil-path" in _chain_ids(hits)


def test_a_credential_and_an_exfil_path_in_DIFFERENT_files_form_no_chain():
    """🔴 THE REGRESSION TEST FOR A DEMONSTRATED FALSE POSITIVE.

    This chain once required only that both links matched SOMEWHERE in the
    tree. Run against PRAETOR's own repository, it composed the secrets
    engine's own redaction TEMPLATE STRING (not a credential at all) with this
    project's teaching example of an INERT comment, and narrated the pair as
    "A real credential in the tree... Rotate the credential regardless."

    Every word of that was false, and it came out of a well-tested, add-only
    mechanism working exactly as written -- because nothing asked whether the
    two links had anything to do with each other. Same-file is the scope that
    fixed it, and this test is what keeps it.
    """
    hits = chains.correlate([
        _f("secrets", "aws-access-key-id", "SECRET", "config/aws.env", severity=Severity.HIGH),
        _f("aisec", "env-exfil", "EXFIL", "scripts/deploy.sh"),
    ])
    assert "chain-credential-plus-exfil-path" not in _chain_ids(hits),         "two findings in unrelated files are co-occurrence, not composition"


def test_a_same_file_chain_names_the_file_it_rests_on():
    """A SAME_FILE chain's whole claim is co-location, so the report has to say
    WHICH file -- otherwise the reader cannot check the claim that justifies
    the severity."""
    hits = chains.correlate([
        _f("aisec", "mcp-server-autostart", "DANGEROUS_HOOK", ".mcp.json", 3),
        _f("aisec", "mcp-server-credential-env", "EXFIL", ".mcp.json", 5, Severity.HIGH),
    ])
    chain = next(c for c in hits if c["chain_id"] == "chain-mcp-autostart-with-credentials")
    assert chain["proximity"] == chains.SAME_FILE
    assert chain["scope"] == ".mcp.json"


def test_one_same_file_chain_is_reported_per_file():
    """Two separate manifests are two separate problems. Merging them into one
    chain would imply a relationship across files that this chain type
    specifically declines to claim."""
    hits = chains.correlate([
        _f("aisec", "mcp-server-autostart", "DANGEROUS_HOOK", "a/.mcp.json", 3),
        _f("aisec", "mcp-server-credential-env", "EXFIL", "a/.mcp.json", 5),
        _f("aisec", "mcp-server-autostart", "DANGEROUS_HOOK", "b/.mcp.json", 3),
        _f("aisec", "mcp-server-credential-env", "EXFIL", "b/.mcp.json", 5),
    ])
    scopes = sorted(
        c["scope"] for c in hits
        if c["chain_id"] == "chain-mcp-autostart-with-credentials"
    )
    assert scopes == ["a/.mcp.json", "b/.mcp.json"]


def test_a_same_file_chain_does_not_form_across_two_manifests():
    """The halves are each in a DIFFERENT manifest. Tree-wide matching would
    have called that one chain; same-file matching must not."""
    hits = chains.correlate([
        _f("aisec", "mcp-server-autostart", "DANGEROUS_HOOK", "a/.mcp.json", 3),
        _f("aisec", "mcp-server-credential-env", "EXFIL", "b/.mcp.json", 5),
    ])
    assert "chain-mcp-autostart-with-credentials" not in _chain_ids(hits)


def test_chain_links_carry_the_confidence_of_their_findings():
    """The one section that computes a NEW severity is the last place that may
    hide its inputs' confidence. Without it a LOW-confidence match anchoring a
    CRITICAL chain reads identically to a HIGH-confidence one."""
    hits = chains.correlate([
        _f("aisec", "mcp-server-autostart-remote", "DANGEROUS_HOOK", ".mcp.json", 3),
        _f("aisec", "mcp-server-credential-env", "EXFIL", ".mcp.json", 5),
    ])
    assert hits, "fixture must produce a chain or this test asserts nothing"
    for chain in hits:
        for link in chain["links"]:
            for finding in link["findings"]:
                assert finding["confidence"] == "MEDIUM"


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
