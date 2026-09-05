"""
Findings must carry the CWE the ecosystem expects.

🔴 WHY THIS FILE EXISTS. Every PROMPT_INJECTION rule carried **CWE-77** --
"Improper Neutralization of Special Elements used in a Command", i.e. command
injection. That is a different weakness with a different remedy.

MITRE added **CWE-1427**, "Improper Neutralization of Input Used for LLM
Prompting", for exactly this class, and it is the entry OWASP LLM01 maps to. The
`owasp` field beside each rule had said LLM01 all along -- so the two fields in
one tuple were describing different weaknesses, and nothing noticed because no
test asserted either.

That matters beyond tidiness: consumers deduplicate and roll up on CWE. A
downstream tool would have grouped prompt injections with shell-command
injections.
"""

import sys
import os

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import engine_aisec  # noqa: E402


def _rows():
    for row in engine_aisec.INJECTION:
        strs = [x for x in row if isinstance(x, str)]
        cwe = next((x for x in strs if x.startswith("CWE-")), None)
        cat = next((x for x in strs if x.isupper() and "_" in x), None)
        yield strs[0], cat, cwe


def test_every_prompt_injection_rule_maps_to_CWE_1427():
    """The MITRE entry for LLM prompt injection, which is what OWASP LLM01 maps
    to and what a consumer will roll up on."""
    for rule_id, category, cwe in _rows():
        if category == "PROMPT_INJECTION":
            assert cwe == "CWE-1427", f"{rule_id} carries {cwe}"


def test_no_prompt_injection_rule_still_claims_command_injection():
    """The specific wrong value, named, so re-introducing it is a red test rather
    than a quiet edit."""
    for rule_id, category, cwe in _rows():
        if category == "PROMPT_INJECTION":
            assert cwe != "CWE-77", f"{rule_id} is back on the command-injection CWE"


def test_hidden_content_rules_keep_CWE_1007():
    """🔴 THE KEEP DIRECTION, and the reason the fix was applied rule by rule
    rather than as a wholesale replace. Invisible Unicode and bidi overrides
    really ARE a visual-distinction weakness; CWE-1007 is correct for them and
    only the PROMPT_INJECTION rows were wrong."""
    import pathlib
    src = pathlib.Path(engine_aisec.__file__).read_text(encoding="utf-8")
    assert src.count('cwe="CWE-1007"') >= 4, \
        "the hidden-content rules must keep the homoglyph CWE"


def test_every_rule_carries_some_cwe():
    """A finding with no CWE cannot be rolled up at all."""
    for rule_id, _category, cwe in _rows():
        assert cwe and cwe.startswith("CWE-"), f"{rule_id} has no CWE"


def test_owasp_and_cwe_do_not_contradict_each_other():
    """The defect was two fields in one tuple describing different weaknesses.
    Anything tagged LLM01 must carry the CWE that LLM01 maps to."""
    for row in engine_aisec.INJECTION:
        strs = [x for x in row if isinstance(x, str)]
        owasp = next((x for x in strs if x.startswith("LLM01")), None)
        cwe = next((x for x in strs if x.startswith("CWE-")), None)
        cat = next((x for x in strs if x.isupper() and "_" in x), None)
        if owasp and cat == "PROMPT_INJECTION":
            assert cwe == "CWE-1427", f"{strs[0]}: {owasp} beside {cwe}"
