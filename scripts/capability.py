"""
PRAETOR agent-capability profile -- a different KIND of answer, not another rule.

Every scanner surveyed in `references/audits/2026-08-24-*` and `2026-09-02-*`
answers the same question: "what is wrong in this tree?" Nobody answers the
one a developer actually faces before opening an unfamiliar repository in an
agent:

    If I open this repo in Claude Code / Cursor / Windsurf right now,
    WHAT HAVE I JUST AUTHORISED?

That is not a findings list. A findings list says "here are 34 problems." A
capability profile says "this repository can execute on load, reaches the
network, and holds a credential" -- three sentences a human can act on
without triaging anything. The two are complementary: the findings are the
evidence, the profile is the summary that tells you whether to read them.

🔴 SAME ADD-ONLY SAFETY PROPERTY AS scripts/chains.py, for the same reason.
This module reads findings and emits a separate section. It never suppresses,
downgrades, re-buckets, or mutates a finding. A summariser that could quiet a
finding would be a suppression mechanism wearing a friendlier name.

⚠️ A capability is reported as PRESENT, never as SAFE. "No auto-execution
found" means no rule matched one, exactly as an empty findings list means no
rule matched anything -- `references/LIMITS.md` already says why that is not a
clean bill of health, and this profile inherits that limit rather than
laundering it into reassurance. A profile with every dimension at `none` is
the same claim PRAETOR always makes: nothing matched these rules.

⚠️ Computed over ACTIVE findings only, for the reason chains.py states: a
filtered finding was assessed inert with a written rationale, and letting it
raise a capability here would re-admit it invisibly to whoever reads that
rationale.
"""

from __future__ import annotations

# Each dimension: (key, question it answers, [predicate over a finding], note)
#
# Predicates are deliberately expressed over CATEGORY and ENGINE rather than
# rule-name substrings: categories are the engines' own stable vocabulary, and
# a substring guess drifts silently the moment a rule is renamed -- a failure
# this repo has already recorded elsewhere.


def _cat(f) -> str:
    return (getattr(f, "category", "") or "").upper()


def _rule(f) -> str:
    return getattr(f, "rule_id", "") or ""


def _engine(f) -> str:
    return getattr(f, "engine", "") or ""


def _executes_on_load(f) -> bool:
    return _cat(f) == "DANGEROUS_HOOK"


def _holds_credentials(f) -> bool:
    # Two distinct shapes: a credential sitting in the tree (secrets engine's
    # whole job), and a credential deliberately handed to a third-party process.
    return _engine(f) == "secrets" or _rule(f) == "mcp-server-credential-env"


def _reaches_network(f) -> bool:
    return _cat(f) == "EXFIL" or _rule(f) in (
        "mcp-server-autostart-remote", "git-hook-network-exec",
    )


def _carries_agent_instructions(f) -> bool:
    return _cat(f) in ("PROMPT_INJECTION", "SAFETY_BYPASS")


def _hides_content_from_review(f) -> bool:
    return _cat(f) == "HIDDEN_CONTENT"


def _runs_unpinned_code(f) -> bool:
    return _rule(f) in ("mcp-server-autostart-remote", "remote-code-pipe")


DIMENSIONS = [
    (
        "executes_on_load",
        "Does anything in this repository run without being asked?",
        _executes_on_load,
        "Agent hooks, git hooks, and auto-started MCP servers all execute when "
        "the repository is opened or a routine git operation happens -- before "
        "anyone has decided to trust it.",
    ),
    (
        "holds_credentials",
        "Are there credentials here, or credentials handed to something else?",
        _holds_credentials,
        "A credential in the tree is disclosed by existing. One passed into a "
        "third-party server process is held by that process for the session, "
        "outside this repository entirely.",
    ),
    (
        "reaches_network",
        "Can anything here move data outward?",
        _reaches_network,
        "Egress is what turns local access into a leak. It is reported "
        "separately from credentials on purpose -- either alone is a fact, "
        "together they are a path.",
    ),
    (
        "carries_agent_instructions",
        "Does any content here try to steer an agent that reads it?",
        _carries_agent_instructions,
        "The core prompt-injection premise: content an agent reads becomes "
        "instructions it may follow. Common and often benign in a repository "
        "that documents prompt injection -- which is exactly why this is a "
        "capability to weigh, not a verdict.",
    ),
    (
        "hides_content_from_review",
        "Is there content a human reviewer cannot see on screen?",
        _hides_content_from_review,
        "Invisible Unicode, bidirectional overrides, terminal escapes and "
        "instruction-bearing HTML comments mean the reviewer approving this "
        "repository and the agent loading it are not reading the same file.",
    ),
    (
        "runs_unpinned_code",
        "Does anything fetch code at load time from a source that can change?",
        _runs_unpinned_code,
        "An unpinned remote source means what runs can change without this "
        "repository changing -- the supply-chain shape, where reviewing the "
        "commit does not tell you what will execute.",
    ),
]


def profile(active: list) -> dict:
    """Build the capability profile from ACTIVE findings. Never mutates them.

    Returns a dict with one entry per dimension: whether the capability is
    present, how many findings evidence it, and up to three example locations.
    """
    out = {}
    for key, question, predicate, note in DIMENSIONS:
        hits = [f for f in active if predicate(f)]
        out[key] = {
            "question": question,
            # "present"/"none" -- never "safe". See this module's header.
            "status": "present" if hits else "none",
            "evidence_count": len(hits),
            "note": note,
            "examples": [
                {
                    "rule_id": _rule(f),
                    "file": getattr(f, "file", ""),
                    "line": getattr(f, "line", 0),
                    "severity": f.severity.label,
                }
                for f in hits[:3]
            ],
        }
    return out


def summary_line(prof: dict) -> str:
    """One sentence a human can read without opening the findings list."""
    present = [k for k, v in prof.items() if v["status"] == "present"]
    if not present:
        # Deliberately not "this repository is safe". Nothing matched; that is
        # all this can honestly say.
        return ("No capability in the profiled set matched. That means no rule "
                "matched one, not that the repository grants nothing.")
    return "This repository: " + ", ".join(k.replace("_", " ") for k in present) + "."
