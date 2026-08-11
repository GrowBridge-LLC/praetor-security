"""
HOMOGLYPHS: fire on a MIXED-SCRIPT TOKEN, never on the presence of non-Latin text.

Cyrillic U+0430 renders identically to Latin "a". `paypal` spelled with one is
indistinguishable to a human and a different string to every machine.

🔴 THE SCOPE DECISION IS THE DETECTOR. The tempting predicate -- "contains
non-ASCII" -- would flag every non-English document in existence. A detector that
fires on ordinary Russian prose gets switched off, and a switched-off detector
catches nothing at all. So the negative tests below are not politeness; they are
the half that decides whether this ships.

⚠️ THE CONFUSABLES BELOW ARE BUILT WITH `chr()`, NOT PASTED. A literal lookalike
here would be invisible to anyone reviewing this file -- which is the exact
property the detector exists to expose, so pasting one makes the test itself
unreviewable. `chr(0x0430)` states which code point is meant; the character it
denotes states nothing.

📌 The obviously-foreign prose in the negative tests IS written literally, and
that is a deliberate distinction rather than an inconsistency: Cyrillic prose is
plainly Cyrillic to any reader, so it deceives nobody. Only the Latin-lookalikes
need spelling out.
"""

import engine_aisec

_CYR_A = chr(0x0430)   # CYRILLIC SMALL LETTER A    -- renders exactly like "a"
_CYR_O = chr(0x043E)   # CYRILLIC SMALL LETTER O    -- renders exactly like "o"
_GRK_O = chr(0x03BF)   # GREEK SMALL LETTER OMICRON -- renders exactly like "o"


def _ids(text, rel="sample.md"):
    return [f.rule_id for f in engine_aisec._scan_homoglyphs(text, rel)]


# --------------------------------------------------------------------------- #
# MUST FIRE
# --------------------------------------------------------------------------- #

def test_latin_token_with_cyrillic_lookalike_is_flagged():
    spoofed = "p" + _CYR_A + "ypal"          # renders as "paypal"
    findings = engine_aisec._scan_homoglyphs(f"Send payment via {spoofed}.com\n", "doc.md")

    assert findings, (
        "MISS: a token mixing Latin with a Cyrillic lookalike was not flagged. This is "
        "the entire attack -- it is invisible to a human reviewer by construction."
    )
    assert findings[0].rule_id == "homoglyph-mixed-script"
    assert "U+0430" in findings[0].description, (
        "the finding must NAME the offending code point -- the reviewer cannot see it, "
        f"so a description without it is unactionable. Got: {findings[0].description}"
    )


def test_greek_lookalike_is_flagged():
    spoofed = "g" + _GRK_O + "ogle"
    assert _ids(f"visit {spoofed}.com\n"), "Greek confusables must be caught too"


def test_line_number_is_reported():
    spoofed = "micr" + _CYR_O + "soft"
    findings = engine_aisec._scan_homoglyphs(f"line one\nline two\n{spoofed}\n", "d.md")
    assert findings and findings[0].line == 3, (
        f"wrong line: a reviewer needs to find the token, got {[f.line for f in findings]}"
    )


# --------------------------------------------------------------------------- #
# MUST NOT FIRE -- the half that decides whether this is usable
# --------------------------------------------------------------------------- #

def test_wholly_cyrillic_text_is_not_flagged():
    """A Russian README is not an attack.

    If this ever fails, the detector has become "contains non-ASCII" and must not
    ship: it would fire on every non-English document in every repository.
    """
    russian = "Привет мир\n"   # "Привет мир"
    assert not _ids(russian), (
        "FALSE POSITIVE: ordinary Cyrillic prose was flagged as a homoglyph attack. "
        "The predicate must require Latin AND a confusable script in the SAME token."
    )


def test_wholly_greek_text_is_not_flagged():
    greek = "αλφα βητα\n"           # "αλφα βητα"
    assert not _ids(greek), "ordinary Greek prose is not an attack"


def test_pure_ascii_is_not_flagged():
    assert not _ids("just a normal line of code = 42\n")


def test_accented_latin_is_not_flagged():
    """Latin-with-diacritics is one script. `café` and `naïve` are not attacks."""
    assert not _ids("café naïve résumé Mañana\n"), (
        "FALSE POSITIVE: accented Latin was flagged. Accents do not make a second "
        "script, and flagging them would fire on most European-language text."
    )


def test_latin_mixed_with_non_confusable_script_is_not_flagged():
    """CJK does not resemble Latin, so Latin+CJK is not a lookalike attack.

    Bilingual documentation mixes these constantly. Only scripts with genuine
    Latin lookalikes belong in _CONFUSABLE_SCRIPTS.
    """
    assert not _ids("README 文件 setup\n"), (
        "FALSE POSITIVE: Latin+CJK flagged. CJK characters have no Latin lookalikes; "
        "including them would fire on ordinary bilingual documentation."
    )


def test_adjacent_words_in_different_scripts_are_not_flagged():
    """The mixture must be WITHIN a token, not across a line.

    `Привет world` is two words in two scripts -- completely ordinary. Only
    "w<U+041E>rld" is suspicious.
    """
    assert not _ids("Привет world\n"), (
        "FALSE POSITIVE: two separate words in two scripts were flagged. Tokenisation "
        "is load-bearing here -- the signature is mixture inside ONE word."
    )
