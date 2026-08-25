"""Every provider rule must be REACHABLE and must WIN its own token.

🔴 Why this file exists.

`openai-key` matches `sk-` + 20 token characters. `anthropic-key` matches
`sk-ant-` + 24. An Anthropic key satisfies both. Both findings land on the same
line with the same redacted snippet, so `Finding.compute_dedup_key()` gives them
the IDENTICAL key and `interpret.dedup()` collapses them to one. Every term in
`_sort_key` tied, Python's sort is stable, and so the survivor was decided by
the order of the `PROVIDERS` list.

The result: a live Anthropic key was reported, at HIGH severity and HIGH
confidence, as `OpenAI API Key`, with the remediation "Revoke the key in the
OpenAI dashboard and rotate." The operator goes to the wrong vendor, finds
nothing, and the real key is never rotated. The discarded `anthropic-key`
finding did not appear in `active`, did not appear in `filtered`, and carried no
`filter_reason` -- it was gone without a trace.

⚠️ THE TEST SHAPE IS THE POINT. A test that asserts "a secret was found" passes
before AND after this bug, which is exactly how it survived. These tests assert
the surviving finding's **rule_id** -- the discriminator, not the match.

⚠️ AND THE SWEEP IS THE POINT. The question asked was "is the shadowing an
INSTANCE or a CLASS?" A hand-check of four prefixes answers it for four
prefixes. `test_every_provider_rule_wins_its_own_token` runs EVERY rule in
`PROVIDERS` through the whole pipeline, so it answers the question for the ones
nobody thought of, and keeps answering it for rules added later.
"""

import base64
import hashlib
import os

import pytest

import engine_secrets
import interpret
from core import ScanFile


# --------------------------------------------------------------------------- #
# Canonical example tokens -- one per provider rule.
#
# Assembled from fragments, per the repo's standing rule: a test file containing
# a literal credential-shaped token becomes a finding in the next self-scan, and
# exempting tests/ is the wrong fix (a real key committed to a test file is one
# of the commonest leaks there is).
#
# These must also survive `is_dummy()`: no "xxxx", no "example", no "your_", no
# token with <= 3 distinct characters.
# --------------------------------------------------------------------------- #
# ⚠️ EVERY quoted literal below is kept UNDER 24 characters, and the real tokens
# are built by concatenation at runtime. That is not stylistic. The standalone
# high-entropy rule fires on any quoted run of 24+ token characters, so the first
# version of this file added FIVE findings to PRAETOR's own self-scan -- a test
# for a detector becoming noise in that detector.
#
# 🔴 The tempting fix is a `tests/` exemption. It is the WRONG fix: it would also
# exempt a real credential committed to a test file, which is one of the commonest
# leaks there is. Fix the fixture, never the rule. (Same discipline as
# engine_secrets.KNOWN_EXAMPLES.)
_SK = "sk-"
_HEX32 = "9f8e7d6c5b4a3928" + "1706f5e4d3c2b1a0"
_B62 = "QRSTUVWXyz234567" + "89ABCDEFGHJKLMNP"     # 32 chars, high variety

# Several provider patterns pin an EXACT token length ({36}, {82}). Hand-counting
# those is how the first draft of this file produced three "shadowed!" failures
# that were really just miscounted fixtures -- a fixture bug wearing the costume
# of the defect under test. Generate them instead.
_ALPHABET = ("Qr7TzWmK9Le2Vd4N" + "b8XcJf5Hp3Rt6Yw2"
             + "Sg8BnKd4MzPv7Jh")                  # 47 chars, no 'x' runs


def _run(n: int) -> str:
    """Exactly n alphanumeric characters, deterministic and placeholder-safe."""
    return (_ALPHABET * (n // len(_ALPHABET) + 1))[:n]


def _azure_key() -> str:
    """Deterministic high-entropy Azure-shaped material, never a word/example."""
    return base64.b64encode(hashlib.sha256(b"praetor-f18-azure").digest()).decode()

EXAMPLES = {
    "aws-access-key-id":            "AKIA" + "QRSTUVWX23456789",
    "aws-secret-access-key":        'aws_secret_access_key = "' + "Qr7Tz" + _B62 + "wLm9Ke2Vd" + '"',
    "gcp-api-key":                  "AIza" + "SyQ9r7Tz" + _B62[:27],
    "gcp-oauth-client-secret":      "GOCSPX-" + "Qr7TzWmK9Le2Vd4Nb8Xc",
    "google-oauth-refresh-token":   "1//0" + "gQr7TzWmK9Le2Vd4Nb8XcJf5Hp3Rt6",
    "github-token":                 "ghp_" + _run(36),
    "github-fine-grained-pat":      "github_pat_" + _run(82),
    "slack-token":                  "xoxb-" + "2468013579-" + "1357902468-" + "Qr7TzWmK9Le2Vd4Nb8Xc",
    "slack-webhook":                "https://hooks.slack.com/services/T" + "Q7RTZWMK9" + "/B" + "L2VD4NB8X" + "/" + "Qr7TzWmK9Le2Vd4Nb8XcJf5H",
    "stripe-secret-key":            _SK.replace("-", "_") + "live_" + "Qr7TzWmK9Le2Vd4Nb8XcJf5H",
    "openai-key":                   _SK + "proj-" + "Qr7TzWmK9Le2Vd4Nb8XcJf5Hp3Rt6",
    "anthropic-key":                _SK + "ant-" + "api03-Qr7TzWmK9Le2" + "Vd4Nb8XcJf5Hp3Rt6Yw",
    "twilio-account-sid-authtoken": 'twilio_auth_token = "' + _HEX32 + '"',
    "sendgrid-key":                 "SG." + "Qr7TzWmK9Le2Vd4Nb8XcJf" + "." + "Qr7TzWmK9Le2Vd4Nb8Xc" + "Jf5Hp3Rt6Yw2Sg8BnKd4Mz7",
    "npm-token":                    "npm_" + _run(36),
    "jwt":                          "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiJRcjdUeldtSzlMZTIifQ" + "." + "Qr7TzWmK9Le2Vd4Nb8XcJf5Hp3Rt6Yw",
    "azure-storage-account-key":    "DefaultEndpointsProtocol=https;AccountName=fixture;AccountKey=" + _azure_key() + ";EndpointSuffix=core.windows.net",
}


def _survivors(tmp_path, content, name="conf.py"):
    """Run one file through the REAL pipeline: engine scan -> interpret."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    sf = ScanFile(abspath=str(p), relpath=name, size=os.path.getsize(p))
    raw = engine_secrets.scan([sf], lambda x: open(x, encoding="utf-8").read())
    res = interpret.interpret(raw)
    return res["active"] + res["filtered"]


# --------------------------------------------------------------------------- #
# The sweep -- this is the answer to "instance or class?"
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("rule_id", sorted(EXAMPLES))
def test_every_provider_rule_wins_its_own_token(tmp_path, rule_id):
    """A rule's own canonical token must SURVIVE the pipeline labelled as that rule.

    Not "a finding was produced" -- the surviving finding's rule_id. A broader
    rule that eats this one turns this red and names which rule was reported
    instead, which is the whole diagnostic.
    """
    findings = _survivors(tmp_path, EXAMPLES[rule_id] + "\n")
    assert findings, f"{rule_id}: its own canonical token produced NO finding at all"
    ids = [f.rule_id for f in findings]
    assert rule_id in ids, (
        f"{rule_id} was SHADOWED: its own token survived as {ids} instead. "
        f"A broader rule is eating it, and the operator gets that rule's "
        f"remediation -- possibly pointing at the wrong vendor entirely."
    )


def test_every_provider_rule_has_an_example():
    """Anti-vacuity: a rule with no example is a rule this sweep never tested.

    Without this, adding a provider rule silently shrinks the sweep's coverage
    while every test stays green -- the exact 'hand-maintained list presented as
    automatic coverage' failure this repo has now hit four times.
    """
    defined = {rule_id for rule_id, *_ in engine_secrets.PROVIDERS}
    missing = defined - set(EXAMPLES)
    assert not missing, (
        f"provider rules with no canonical example, so untested by the sweep: "
        f"{sorted(missing)}. Add one to EXAMPLES."
    )
    stale = set(EXAMPLES) - defined
    assert not stale, f"EXAMPLES names rules that no longer exist: {sorted(stale)}"


# --------------------------------------------------------------------------- #
# The specific regression, both directions
# --------------------------------------------------------------------------- #

def test_anthropic_key_is_not_reported_as_openai(tmp_path):
    """The live defect: an Anthropic key must not route the operator to OpenAI."""
    findings = _survivors(tmp_path, 'KEY = "' + EXAMPLES["anthropic-key"] + '"\n')
    active = [f for f in findings if not f.filtered]
    assert active, "an Anthropic key produced no active finding"
    primary = active[0]
    assert primary.rule_id == "anthropic-key", (
        f"reported as {primary.rule_id!r} -- the operator is sent to the wrong vendor"
    )
    assert "openai" not in primary.fix.lower(), (
        f"remediation names the wrong vendor: {primary.fix!r}"
    )
    assert "anthropic" in primary.fix.lower()


def test_openai_key_still_reported_as_openai(tmp_path):
    """The opposite direction. Narrowing and disabling look identical from outside.

    If the fix had been "make openai-key stop matching", this stays red.
    """
    findings = _survivors(tmp_path, 'KEY = "' + EXAMPLES["openai-key"] + '"\n')
    active = [f for f in findings if not f.filtered]
    assert active, "an OpenAI key produced no active finding"
    assert active[0].rule_id == "openai-key", (
        f"reported as {active[0].rule_id!r}; the OpenAI rule must still win its own token"
    )


def test_azure_storage_key_inside_connection_string_gates(tmp_path):
    """The named Azure envelope must be detected at provider severity."""
    findings = _survivors(tmp_path, EXAMPLES["azure-storage-account-key"] + "\n")
    active = [f for f in findings if not f.filtered]
    assert active, "wrapped Azure storage key produced no active finding"
    azure = [f for f in active if f.rule_id == "azure-storage-account-key"]
    assert azure, f"wrapped Azure key was not reported by its provider rule: {[f.rule_id for f in active]}"
    assert azure[0].severity >= engine_secrets.Severity.MEDIUM


def test_covered_aws_key_still_gates_inside_an_envelope(tmp_path):
    """Positive control: a covered provider remains visible when embedded."""
    wrapped = "DefaultEndpointsProtocol=https;AccessKey=" + EXAMPLES["aws-access-key-id"] + ";EndpointSuffix=amazonaws.com"
    findings = _survivors(tmp_path, wrapped + "\n")
    active = [f for f in findings if not f.filtered]
    assert any(f.rule_id == "aws-access-key-id" for f in active), "AWS provider control stopped gating inside an envelope"


def test_collapsed_rule_is_disclosed_not_silently_dropped(tmp_path):
    """A merge that discards a distinct rule_id must say which one it discarded.

    The original bug lost `anthropic-key` with no trace in active, filtered, or
    any reason field. Suppressing without a stated rationale is not triage.
    """
    findings = _survivors(tmp_path, 'KEY = "' + EXAMPLES["anthropic-key"] + '"\n')
    primary = [f for f in findings if not f.filtered][0]
    assert "openai-key" in primary.description, (
        "the collapsed openai-key match left no trace in the surviving finding"
    )


def test_specificity_is_derived_not_hand_listed(tmp_path):
    """The tie-break must come from the pattern, so new rules score automatically.

    A hand-maintained specificity table would be the same defect class in a new
    costume: correct on the day it is written, silently stale afterwards.
    """
    spec = engine_secrets.PROVIDER_SPECIFICITY
    assert set(spec) == {r for r, *_ in engine_secrets.PROVIDERS}, (
        "specificity table is not derived from PROVIDERS"
    )
    assert spec["anthropic-key"] > spec["openai-key"], (
        f"sk-ant- ({spec['anthropic-key']}) must outrank sk- ({spec['openai-key']})"
    )
