"""
THE BUNDLED RULESET MUST STAY LOADABLE. One malformed rule breaks all of them.

`rules/semgrep-praetor.yaml` is shipped as a single `--config` file, so semgrep
rejects it as a UNIT: a syntax error in rule 15 takes rules 1-14 down with it.
That is the whole offline baseline for every `--no-registry` user -- the exact
capability commit 8acf61f existed to make work.

⚠️ WHAT THIS TEST DOES *NOT* DO, stated plainly because it is easy to over-read:
it checks STRUCTURE, not semantics. It cannot tell you that a rule MATCHES what
it claims to match -- only semgrep can, by being run against a positive control.
A rule that parses and never fires is a silent no-op that looks like coverage,
and this file will happily pass on one.

📌 Semgrep does not run on this development box (native Windows unsupported,
Docker engine stopped, WSL service disabled), which is precisely why a
structure-only guard was worth writing AND why it must not be mistaken for
verification. Any rule added here still owes a positive-control run somewhere
semgrep works.
"""

import os

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML needed to parse the bundled ruleset")

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RULES = os.path.join(_ROOT, "rules", "semgrep-praetor.yaml")
_PENDING_DIR = os.path.join(_ROOT, "rules", "pending")

# Fields semgrep requires on every rule. A rule missing any of these is not a
# "slightly wrong rule", it is a config semgrep refuses to load at all.
_REQUIRED = ("id", "languages", "severity", "message")
_VALID_SEVERITIES = {"ERROR", "WARNING", "INFO"}


def _rules():
    with open(_RULES, encoding="utf-8") as fh:
        return yaml.safe_load(fh)["rules"]


def _all_rules():
    """Shipped rules PLUS anything staged in rules/pending/.

    ⚠️ The severity guard below MUST see pending rules. When the CVE-2026-53753
    rule was moved out of the shipped file, a guard reading only the shipped file
    went silently vacuous -- it kept passing by iterating over nothing, which is
    the failure mode it was written to prevent, one level up.
    """
    out = list(_rules())
    if os.path.isdir(_PENDING_DIR):
        for fn in sorted(os.listdir(_PENDING_DIR)):
            if fn.endswith((".yaml", ".yml")):
                with open(os.path.join(_PENDING_DIR, fn), encoding="utf-8") as fh:
                    out.extend(yaml.safe_load(fh).get("rules", []) or [])
    return out


def test_ruleset_parses():
    assert _rules(), "the bundled ruleset is empty or unparseable"


def test_every_rule_has_the_fields_semgrep_requires():
    for rule in _rules():
        for field in _REQUIRED:
            assert field in rule, (
                f"rule {rule.get('id', '<no id>')!r} is missing required field {field!r}; "
                "semgrep rejects the WHOLE config, so this breaks every other rule too"
            )


def test_every_rule_has_a_matching_clause():
    """A rule with no pattern clause matches nothing -- silent, and useless."""
    for rule in _rules():
        assert any(k.startswith("pattern") for k in rule), (
            f"rule {rule['id']!r} has no pattern/patterns/pattern-either clause, so it can "
            "never fire. It would sit in the ruleset looking like coverage and provide none."
        )


def test_severities_are_valid():
    for rule in _rules():
        assert rule["severity"] in _VALID_SEVERITIES, (
            f"rule {rule['id']!r} has severity {rule['severity']!r}; semgrep accepts only "
            f"{sorted(_VALID_SEVERITIES)}"
        )


def test_rule_ids_are_unique():
    ids = [r["id"] for r in _rules()]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate rule id(s) {sorted(dupes)} -- findings would be ambiguous"


def test_undecidable_rules_are_not_shipped_as_ERROR():
    """A confident verdict on an undecidable property is a false negative with a badge.

    Sandbox soundness cannot be decided by pattern matching. The CVE-2026-53753
    rule matches ONE known-bad shape, so it ships at WARNING and its message says
    so. If someone promotes it to ERROR, this fails on purpose.
    """
    candidates = [r for r in _all_rules() if "denylist" in r["id"] or "sandbox" in r["id"]]
    assert candidates, (
        "VACUOUS: no undecidable-property rule was found in either the shipped ruleset or "
        "rules/pending/, so this guard asserted nothing. If the rule was deleted on purpose, "
        "delete this test with it -- do not leave it passing over an empty set."
    )
    for rule in candidates:
        if True:
            assert rule["severity"] != "ERROR", (
                f"{rule['id']!r} asserts an undecidable property (sandbox soundness) at ERROR. "
                "Absence of such a finding is not evidence of safety and the severity must "
                "not imply otherwise."
            )
            assert "not evidence of safety" in rule["message"] or "does not mean" in rule["message"], (
                f"{rule['id']!r} must state its failure mode in its own message -- a reader "
                "will over-read a clean result otherwise."
            )
