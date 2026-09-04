"""
PRAETOR attack-chain correlation -- the layer that reads findings as a graph
instead of a list.

Every scanner in the surveys behind `references/audits/2026-08-24-*` and
`2026-09-02-*` is per-file pattern matching, PRAETOR included. It reports N
findings and leaves the reader to notice that three of them COMPOSE. But an
attack on an agent is a chain, not a point:

    a README carries an instruction-override phrase        (MEDIUM alone)
  + a .mcp.json auto-starts a server holding a credential  (MEDIUM alone)
  + .claude/settings.json auto-runs a hook on load         (MEDIUM alone)
  ------------------------------------------------------------------------
  = content that steers the agent, and a mechanism that executes with
    credentials, in the same tree the agent is about to open.

PRAETOR is unusually placed to see this: fusing four engines into one report
is already its whole design premise, so the correlation input is sitting in
one list by the time this module runs.

🔴 WHAT A CHAIN IS, AND IS NOT.
A chain is a HYPOTHESIS about composability, not proof of exploitability. It
says "these findings could compose into this path; go verify," in exactly the
register `references/LIMITS.md` already demands of every finding ("a lead to
verify, never proof"). It does NOT assert that the path is reachable, that
the injected text will actually be read, or that the hook will actually fire.
Naming it a chain and then describing it as a confirmed exploit would be the
overclaim this repo's own audit history keeps catching.

🔴 THIS LAYER ONLY ADDS. It never suppresses, never downgrades, never
re-buckets a finding, and never changes a finding's severity. That is a
deliberate safety property, not an accident of the current implementation: a
correlation pass that could DOWNGRADE would be a suppression mechanism wearing
a different name, and would need the whole carve-out discipline CLAUDE.md
demands of suppression. Because it can only add a separate `chains` section,
it is structurally incapable of causing a false clean -- the failure mode this
tool exists to prevent.

⚠️ Chains are computed over ACTIVE findings only. A filtered finding has been
assessed as inert with a stated reason; letting it form a link would
re-admit through the side door exactly what the filter just excluded, and the
reviewer reading `filter_reason` would have no idea it had been counted
anyway. If a filtered finding should be able to form a chain, the correct fix
is to stop filtering it, not to special-case it here.
"""

from __future__ import annotations

from core import Severity


def _cat(f) -> str:
    return (getattr(f, "category", "") or "").upper()


def _rule(f) -> str:
    return getattr(f, "rule_id", "") or ""


def _engine(f) -> str:
    return getattr(f, "engine", "") or ""


# --------------------------------------------------------------------------- #
# Link predicates -- each names ONE capability an attacker needs
# --------------------------------------------------------------------------- #
#
# Kept as small named predicates rather than inlined lambdas so a chain
# definition reads as the sentence it is meant to be, and so a predicate that
# turns out to be wrong is fixed in one place for every chain that uses it.

def _is_planted_instruction(f) -> bool:
    """Content that tries to steer an agent: injection or safety-bypass text."""
    return _cat(f) in ("PROMPT_INJECTION", "SAFETY_BYPASS")


def _is_autorun(f) -> bool:
    """A mechanism that executes without a human asking it to, on load."""
    return _cat(f) == "DANGEROUS_HOOK"


def _is_hidden_content(f) -> bool:
    """Content a human reviewer cannot see on screen: invisible Unicode,
    bidi overrides, ANSI escapes, instruction-bearing HTML comments."""
    return _cat(f) == "HIDDEN_CONTENT"


def _is_exfil_path(f) -> bool:
    """A mechanism that moves data out of the machine."""
    return _cat(f) == "EXFIL"


def _is_real_credential(f) -> bool:
    """An actual credential in the tree -- the secrets engine's own findings.

    Deliberately keyed on the ENGINE, not on a category or a rule-name
    substring: `secrets` exists to answer exactly this question, and its
    membership is the authoritative answer. A category/name-based guess here
    would drift the moment a rule is renamed.
    """
    return _engine(f) == "secrets"


def _is_mcp_autostart(f) -> bool:
    return _rule(f) in ("mcp-server-autostart", "mcp-server-autostart-remote")


def _is_mcp_remote_autostart(f) -> bool:
    return _rule(f) == "mcp-server-autostart-remote"


def _is_mcp_credential(f) -> bool:
    return _rule(f) == "mcp-server-credential-env"


# --------------------------------------------------------------------------- #
# Chain definitions
# --------------------------------------------------------------------------- #
#
# Each entry: (chain_id, title, severity, [(link_label, predicate), ...],
#              why_it_composes, what_to_verify)
#
# `severity` is the chain's own, and is deliberately allowed to exceed its
# links' -- that IS the finding: two MEDIUMs that compose into a working path
# are not a MEDIUM situation. It is never allowed to LOWER anything, because
# this layer never touches the underlying findings at all.

CHAINS = [
    (
        "chain-injection-to-autorun",
        "Planted instruction + an auto-run execution path in the same tree",
        Severity.CRITICAL,
        [
            ("planted instruction", _is_planted_instruction),
            ("auto-run mechanism", _is_autorun),
        ],
        "An agent opening this repository reads the instruction-bearing content as "
        "part of its context, and separately the repository carries a mechanism that "
        "executes without anyone asking it to. The first supplies the intent, the "
        "second supplies the execution.",
        "Confirm whether the auto-run mechanism is reachable from the agent's normal "
        "load path, and whether the instruction-bearing file is one the agent actually "
        "reads (a README or skill file usually is; a fixture in a test directory "
        "usually is not).",
    ),
    (
        "chain-hidden-instruction-to-autorun",
        "Reviewer-invisible content + an auto-run execution path in the same tree",
        Severity.CRITICAL,
        [
            ("reviewer-invisible content", _is_hidden_content),
            ("auto-run mechanism", _is_autorun),
        ],
        "The content link here is one a human reviewer cannot see on screen at all -- "
        "invisible Unicode, a bidirectional override, a terminal escape, or an HTML "
        "comment. Pairing that with something that auto-executes means the reviewer "
        "who approves this repository and the agent that loads it are not reading the "
        "same file.",
        "Render the hidden-content file with a tool that shows control characters, and "
        "confirm what the auto-run mechanism actually does.",
    ),
    (
        "chain-mcp-autostart-with-credentials",
        "Auto-started MCP server is handed a credential",
        Severity.HIGH,
        [
            ("MCP server auto-starts", _is_mcp_autostart),
            ("credential passed to an MCP server", _is_mcp_credential),
        ],
        "A server that starts automatically when the agent loads this config is also "
        "given credential-shaped environment variables. Whatever that server does with "
        "them happens outside this repository, and it holds them for the whole session.",
        "Confirm the server is one you have audited, and scope the credential to the "
        "minimum it needs -- a short-lived token rather than a standing one.",
    ),
    (
        "chain-remote-mcp-with-credentials",
        "MCP server fetched from a remote/unpinned source is handed a credential",
        Severity.CRITICAL,
        [
            ("MCP server auto-starts from a remote/unpinned source", _is_mcp_remote_autostart),
            ("credential passed to an MCP server", _is_mcp_credential),
        ],
        "This is the previous chain's sharper form: the code that receives the "
        "credential is not pinned, so what runs can change without this config "
        "changing. A credential handed to an unpinned remote source is a "
        "supply-chain credential disclosure waiting on someone else's release.",
        "Pin the server to an exact version from a source you control before it "
        "receives any credential at all.",
    ),
    (
        "chain-credential-plus-exfil-path",
        "A real credential in the tree + a mechanism that moves data out",
        Severity.HIGH,
        [
            ("credential present in the tree", _is_real_credential),
            ("data-egress mechanism", _is_exfil_path),
        ],
        "The secrets engine found an actual credential in this tree, and separately "
        "there is a mechanism here that sends data outward. Neither on its own says "
        "the credential leaves; together they are the two halves of one.",
        "Rotate the credential regardless (it is in the tree, which is disclosure on "
        "its own), then confirm whether the egress path can actually read it.",
    ),
]


def _identity(f) -> str:
    return f"{_engine(f)}|{_rule(f)}|{getattr(f, 'file', '')}|{getattr(f, 'line', '')}"


def correlate(active: list) -> list:
    """Find attack chains across ACTIVE findings. Never mutates them.

    Returns a list of chain dicts, highest severity first. An empty list means
    no chain matched -- which is NOT a statement that the tree is safe, exactly
    as an empty findings list isn't.
    """
    out = []
    for chain_id, title, severity, links, why, verify in CHAINS:
        matched_links = []
        for link_label, predicate in links:
            hits = [f for f in active if predicate(f)]
            if not hits:
                matched_links = []
                break
            matched_links.append((link_label, hits))

        if not matched_links:
            continue

        # A chain whose links are all satisfied by the SAME single finding is
        # not a chain -- it is one finding counted twice. Two predicates can
        # legitimately overlap (an MCP autostart is also a DANGEROUS_HOOK), so
        # require the links to be satisfiable by distinct findings before this
        # is reported as a composition of separate problems.
        distinct = set()
        for _label, hits in matched_links:
            distinct.update(_identity(f) for f in hits)
        if len(distinct) < len(matched_links):
            continue

        out.append({
            "chain_id": chain_id,
            "title": title,
            "severity": severity.label,
            "why_it_composes": why,
            "what_to_verify": verify,
            "links": [
                {
                    "link": label,
                    "findings": [
                        {
                            "engine": _engine(f),
                            "rule_id": _rule(f),
                            "file": getattr(f, "file", ""),
                            "line": getattr(f, "line", 0),
                            "severity": f.severity.label,
                        }
                        # Cap per link: a tree with 300 injection hits should not
                        # render 300 rows under one chain. The count is reported
                        # separately so the cap is visible, never silent.
                        for f in hits[:5]
                    ],
                    "total": len(hits),
                    "shown": min(len(hits), 5),
                }
                for label, hits in matched_links
            ],
        })

    # Severity is an IntEnum where HIGHER means more dangerous, so this sorts
    # descending on the enum's own value -- not on enumerate() order, which
    # runs INFO->CRITICAL and would have listed the least dangerous chain first.
    by_label = {s.label: int(s) for s in Severity}
    out.sort(key=lambda c: -by_label.get(c["severity"], -1))
    return out
