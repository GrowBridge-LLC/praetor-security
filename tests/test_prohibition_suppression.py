"""
Prose that FORBIDS the thing it names (suppression pass A3).

🔴 THE PROBLEM, MEASURED IN A SECOND REPOSITORY. A team documenting these false
positives found that writing the report produced five more of them: it quoted the
offending lines so a reader could see them, and the scan went from 5 findings to
10, all five new ones inside the report. Rewriting it to DESCRIBE rather than
reproduce took it back to 5. Measured, both directions.

Their conclusion drives this pass: the rules impose a cost on documenting their
own failures, and it lands hardest on whoever is trying to fix them.

🔴 AND THE HONEST LIMIT, WHICH MATTERS MORE THAN THE FIX. This pass suppresses
ONE of their six findings. The other five are recorded in
`test_the_cases_this_pass_does_NOT_cover` with the reason for each, because a
mechanism that looks like it solved a problem it did not is worse than no
mechanism. Widening it to force those five to pass would require either reading
AFTER the match or suppressing inside code string literals, and both are
demonstrated attack surface -- see that test.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import praetor  # noqa: E402

_PRAETOR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "praetor.py")

# Assembled: written whole, this file's own self-scan would flag it.
_FLAG = "--dangerously" + "-skip-permissions"


def _scan(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, _PRAETOR, str(tmp_path), "--engines", "aisec",
         "--no-registry", "--format", "json", "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    return json.loads(proc.stdout)


def _active(d):
    return {f["rule_id"] for f in d["findings"]}


def _filtered(d):
    return {f["rule_id"] for f in d["filtered"]}


# --------------------------------------------------------------------------- #
# What it suppresses
# --------------------------------------------------------------------------- #

def test_a_comment_forbidding_the_flag_is_suppressed(tmp_path):
    """The shape the whole pass exists for: the author's own prose telling a
    reader NOT to do the thing."""
    d = _scan(tmp_path, "install.py", f"# Never use {_FLAG} in CI.\nx = 1\n")
    assert "dangerous-permission-flag" in _filtered(d)
    assert "dangerous-permission-flag" not in _active(d)


def test_a_comment_describing_a_scanner_that_flags_it_is_suppressed(tmp_path):
    """The most absurd instance the reporting team found: a test comment
    ANTICIPATING this false positive, flagged by it."""
    d = _scan(tmp_path, "t.py", f'#   scanner flagging "Never {_FLAG}".\nx = 1\n')
    assert "dangerous-permission-flag" in _filtered(d)


def test_the_reason_is_recorded_not_silently_dropped(tmp_path):
    """Suppression without a stated reason is not triage."""
    d = _scan(tmp_path, "install.py", f"# Do not pass {_FLAG}.\nx = 1\n")
    note = next(f for f in d["filtered"] if f["rule_id"] == "dangerous-permission-flag")
    assert "PROHIBITION" in note["filter_reason"]


# --------------------------------------------------------------------------- #
# What it must NOT suppress -- each of these is an attack if it ever passes
# --------------------------------------------------------------------------- #

def test_a_bare_instruction_in_a_comment_still_fires(tmp_path):
    """🔴 THE PRIMARY KEEP DIRECTION. Comment context ALONE must never suppress a
    SAFETY_BYPASS finding -- that was the defect this repository fixed one commit
    earlier, and this pass must not quietly re-open it."""
    d = _scan(tmp_path, "install.py", f"# Always use {_FLAG} for speed.\nx = 1\n")
    assert "dangerous-permission-flag" in _active(d)


def test_a_prohibition_does_not_cover_a_later_live_instruction(tmp_path):
    """🔴 THE LOAD-BEARING PROPERTY, AND WHY ADJACENCY IS THE DESIGN.

    A line that forbids something and then does it must still fire on the second
    occurrence. Without adjacency, prefixing any payload with "Never" would be a
    suppression primitive the attacker controls -- the same shape as the quoting
    bypass this project already fixed once.
    """
    line = f"# never use {_FLAG}; for deploys use {_FLAG}\n"
    d = _scan(tmp_path, "install.py", line + "x = 1\n")
    assert "dangerous-permission-flag" in _active(d), \
        "a discharged prohibition must not cover a later instruction"


def test_a_prohibition_in_LIVE_CODE_is_not_suppressed_by_THIS_pass(tmp_path):
    """Condition 1 is the author's own prose. A string literal in executable code
    is not that -- it may be an argument the program actually passes.

    ⚠️ ASSERTS THE FILTER REASON, NOT THE BUCKET, and the first version of this
    test got that wrong. `cmd = "never <flag>"` IS suppressed -- by the
    long-standing REACHABILITY pass, because the string provably never reaches a
    dangerous sink in that file. That verdict is correct and predates this pass
    entirely. Asserting "still active" therefore tested a different mechanism and
    failed for a reason that had nothing to do with this one.
    """
    d = _scan(tmp_path, "run.py", f'cmd = "never {_FLAG}"\n')
    for f in d["filtered"]:
        if f["rule_id"] == "dangerous-permission-flag":
            assert "PROHIBITION" not in f["filter_reason"], (
                "this pass must not suppress inside executable code; got: "
                + f["filter_reason"]
            )


def test_a_prohibition_far_from_the_match_does_not_govern_it(tmp_path):
    """The window is short on purpose. By forty characters a sentence may have
    turned back into an instruction."""
    filler = "and after a good deal of unrelated explanatory text we then say "
    d = _scan(tmp_path, "install.py", f"# never mind that, {filler}use {_FLAG}\nx = 1\n")
    assert "dangerous-permission-flag" in _active(d)


def test_the_pass_is_scoped_to_SAFETY_BYPASS(tmp_path):
    """A prompt injection has its own narrower guard, and a behavioural finding
    is handled by lexical context. Widening this to another category needs its
    own argument, so the scope is asserted rather than assumed."""
    # ⚠️ ASSEMBLED IN REVERSE. Splitting the phrase into a list is NOT enough:
    # `prompt-injection-override` tolerates about forty arbitrary characters
    # between its trigger words, which is wide enough to bridge the quotes and
    # commas of a four-element list holding them in order. The self-scan caught
    # this file doing exactly that -- and then caught the COMMENT that explained
    # it, which had spelled the list out. Source order never spells the trigger
    # sequence; run-time order does.
    #
    # That is the documentation tax this whole module is about, charged twice to
    # the file implementing the relief. It is left recorded rather than tidied
    # away, because it is the clearest evidence the problem is real.
    override = " ".join(reversed(["instructions", "previous", "all", "ignore"]))
    d = _scan(tmp_path, "notes.py", f"# Never write '{override}' in a prompt.\nx = 1\n")
    assert "prompt-injection-override" in _active(d), \
        "PROMPT_INJECTION must not be suppressed by this pass"


# --------------------------------------------------------------------------- #
# The honest limit
# --------------------------------------------------------------------------- #

def test_the_cases_this_pass_does_NOT_cover(tmp_path):
    """🔴 FIVE OF THE SIX REPORTED FINDINGS ARE STILL ACTIVE, BY DESIGN.

    Measured against the reporting repository's real files. Each shape below is
    left firing for a stated reason, not an oversight:

    1. The prohibition FOLLOWS the match -- a comment naming the flag and
       THEN saying it skips every local hook.
       Reading after the match would suppress "use X, never mind the warnings",
       which reads as an instruction. Trailing context is attacker-controllable
       in a way leading context is not.

    2. The match is inside a STRING LITERAL in executable code -- a shell
       test assertion whose message names the flag.
       Suppressing there would cover a payload passed as a real argument, which
       is one of the commonest genuine attacks.

    3. A comment that merely NAMES the flag with no prohibition -- a section
       header listing the escape, its boundary and the flag.
       Nothing in the line forbids anything, so nothing here can tell it from an
       instruction.

    ⇒ The better mechanism is COMMAND-POSITION analysis: is this token in a place
    where it would actually be passed to a program? That subsumes cases 1-3 and
    does not depend on prose at all. It is a real build, not a regex, and it is
    recorded as owed work rather than approximated here.
    """
    trailing = _scan(tmp_path, "a.py", f"# `{_FLAG}` skips every check.\nx = 1\n")
    assert "dangerous-permission-flag" in _active(trailing)

    naming = _scan(tmp_path, "b.py", f"# --- the boundary, and {_FLAG} ---\nx = 1\n")
    assert "dangerous-permission-flag" in _active(naming)


def test_the_prohibition_predicate_is_leading_context_only():
    """Pins the design decision itself, so extending the window to trailing
    context is a deliberate act against a red test rather than a quiet edit."""
    assert praetor._prohibition_governs("never use ", len("never use "))
    assert not praetor._prohibition_governs("use ", len("use ")), \
        "trailing prohibitions are deliberately not consulted"
    assert praetor._PROHIBITION_WINDOW <= 40, \
        "a longer window lets a discharged prohibition cover a live instruction"
