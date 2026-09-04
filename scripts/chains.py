"""
PRAETOR attack-chain correlation -- the layer that reads findings as a graph
instead of a list.

Every scanner in the surveys behind `references/audits/2026-08-24-*` and
`2026-09-02-*` is per-file pattern matching, PRAETOR included. It reports N
findings and leaves the reader to notice that three of them COMPOSE. But an
attack on an agent is a chain, not a point:

    a .mcp.json auto-starts a server                       (MEDIUM alone)
  + the SAME .mcp.json hands it a credential               (MEDIUM alone)
  ------------------------------------------------------------------------
  = one config that starts a third-party process and gives it a credential,
    before anyone has decided to trust it.

⚠️ WHAT THIS TABLE DOES NOT YET DO. `correlate()` walks a chain's link list
generically, so an N-link chain needs only a table entry -- but every entry
today has exactly TWO links. A three-way composition (planted instruction +
credentialed MCP autostart + auto-run hook) is therefore reported as its
separate two-link parts, never as one finding. An audit caught the previous
version of this docstring using exactly that three-way example to motivate the
module, which promised a shape the code has never produced. The gap is real and
is recorded in `references/LIMITS.md`; the docstring now describes what runs.

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

def _is_coverage(f) -> bool:
    """A finding ABOUT THE SCAN, not about the target.

    Every engine can emit one -- a skipped long line, a file too large, a
    binary the sniff refused. None of them is evidence of anything in the tree,
    so none may satisfy a chain link. Applied inside every predicate below
    rather than filtered once in `correlate()`, so a predicate added later
    inherits it by using these helpers instead of remembering a rule.
    """
    return _cat(f) == "COVERAGE"


def _is_planted_instruction(f) -> bool:
    """Content that tries to steer an agent: injection or safety-bypass text."""
    return _cat(f) in ("PROMPT_INJECTION", "SAFETY_BYPASS") and not _is_coverage(f)


#: Rules that execute without being asked but are NOT categorised
#: DANGEROUS_HOOK. An audit found `npm-lifecycle-exec` forming no chain at all:
#: an npm `postinstall` is the most unconditional auto-run primitive in the
#: rule set -- no config gate, no matching event, it runs on every
#: `npm install` -- and it was invisible here because the engine files it under
#: SUPPLY_CHAIN.
#:
#: ⚠️ Enumerated by RULE ID rather than widening to `category ==
#: "SUPPLY_CHAIN"`. That category also holds vulnerable-dependency findings and
#: (once the model engine lands) unsafe-pickle findings, neither of which
#: executes on load. The category widening was the shorter edit and would have
#: made this predicate mean something else.
#:
#: 🔴 STATED GAP: any FUTURE rule describing install-time or load-time
#: execution must be added here by hand. Nothing enforces that. The same list
#: exists in scripts/capability.py for the same reason -- they are separate
#: because the two modules ask different questions, and both are hand-kept.
_AUTORUN_RULE_IDS = frozenset({
    "npm-lifecycle-exec",
})


def _is_autorun(f) -> bool:
    """A mechanism that executes without a human asking it to, on load."""
    return (
        (_cat(f) == "DANGEROUS_HOOK" or _rule(f) in _AUTORUN_RULE_IDS)
        and not _is_coverage(f)
    )


def _is_hidden_content(f) -> bool:
    """Content a human reviewer cannot see on screen: invisible Unicode,
    bidi overrides, ANSI escapes, instruction-bearing HTML comments."""
    return _cat(f) == "HIDDEN_CONTENT" and not _is_coverage(f)


def _is_exfil_path(f) -> bool:
    """A mechanism that moves data out of the machine."""
    return _cat(f) == "EXFIL" and not _is_coverage(f)


def _is_real_credential(f) -> bool:
    """An actual credential in the tree -- the secrets engine's own findings.

    Keyed on the ENGINE, not on a rule-name substring: `secrets` exists to
    answer exactly this question, and a name-based guess would drift the moment
    a rule is renamed.

    🔴 BUT ENGINE MEMBERSHIP ALONE WAS NOT THE ANSWER, AND THE DOCSTRING THAT
    SAID IT WAS IS THE REASON THIS TOOK A SECOND AUDIT TO FIND. The secrets
    engine also emits `secrets-long-line-skip` -- an INFO COVERAGE note saying
    "some passes did not run on this line." It carries `engine == "secrets"`, so
    it satisfied this predicate, and a minified `.mcp.json` produced:

        chain   : chain-credential-plus-exfil-path      [HIGH]
        basis   : same-file -- .mcp.json
        verify  : Rotate the credential (it is in the tree, ...)
        link    : credential present
                   - INFO/HIGH secrets-long-line-skip @ .mcp.json:1

    There was no credential in that tree. A note reporting REDUCED COVERAGE was
    rendered as evidence of a leak -- the strongest possible inversion, since the
    note exists to say the scanner looked LESS hard there.

    ⇒ A COVERAGE finding is a statement ABOUT THE SCAN, never about the target.
    Excluded here and, deliberately, from every link predicate below, because
    every engine can emit one.
    """
    return _engine(f) == "secrets" and not _is_coverage(f)


def _is_mcp_autostart(f) -> bool:
    return _rule(f) in ("mcp-server-autostart", "mcp-server-autostart-remote")


def _is_mcp_remote_autostart(f) -> bool:
    return _rule(f) == "mcp-server-autostart-remote"


def _is_mcp_credential(f) -> bool:
    return _rule(f) == "mcp-server-credential-env"


# --------------------------------------------------------------------------- #
# Proximity -- how RELATED two links must be before this is called a chain
# --------------------------------------------------------------------------- #
#
# 🔴 THIS EXISTS BECAUSE THE FIRST VERSION WAS WRONG, AND AN AUDIT PROVED IT
# ON THIS REPOSITORY'S OWN TREE. That version required only that both links
# match SOMEWHERE in the scanned tree. In a repository of any size, two
# unrelated findings of two given categories co-occurring is close to certain,
# so the "chain" proved co-occurrence and then narrated it as composition.
#
# The demonstration, run against PRAETOR itself: it composed
#   - `scripts/engine_secrets.py:379` -- the detector's OWN template string,
#     not a credential at all, and
#   - `CLAUDE.md:42` -- this project's own teaching example of an INERT
#     comment, the literal line used to explain why a behavioural pattern in a
#     comment cannot execute
# into a HIGH chain narrated "A real credential in the tree... Rotate the
# credential regardless." Every word of that was false for that instance, and
# it was produced by a well-tested, add-only mechanism working exactly as
# designed -- because nothing in it asked whether the two links had anything
# to do with each other.
#
# ⇒ The lesson is this repository's own, one layer up from where it was
# learned: a mechanism's safety is a scope decision made next to it. "Both
# present in the tree" is not a scope; it is the absence of one.
#
#   SAME_FILE -- both links must come from the SAME file. For an MCP manifest
#                this is the real thing: one config, one server entry,
#                autostart AND the credential handed to it. Strong evidence,
#                and severity may exceed the links' own.
#   SAME_TREE -- the links are genuinely expected to live in different files
#                (an instruction planted in a README, a hook in
#                .claude/settings.json -- that IS the attack shape). But
#                co-occurrence across a tree is weak evidence, so a SAME_TREE
#                chain is capped at MEDIUM and worded as what it is: a prompt
#                to look, not an escalation.
SAME_FILE = "same-file"
SAME_TREE = "same-tree"

# --------------------------------------------------------------------------- #
# Chain definitions
# --------------------------------------------------------------------------- #
#
# Each entry: (chain_id, title, severity, proximity,
#              [(link_label, predicate), ...], why_it_composes, what_to_verify)
#
# A SAME_FILE chain's severity may exceed its links' -- co-location in one
# config is real evidence of composition. A SAME_TREE chain's may NOT: it is
# capped at MEDIUM, because "both somewhere in this repository" does not earn
# more. Neither ever LOWERS anything; this layer never touches the underlying
# findings at all.

CHAINS = [
    (
        "chain-injection-to-autorun",
        "Planted instruction co-occurs with an auto-run execution path",
        Severity.MEDIUM,
        SAME_TREE,
        [
            ("planted instruction", _is_planted_instruction),
            ("auto-run mechanism", _is_autorun),
        ],
        "An agent opening this repository reads instruction-bearing content as part "
        "of its context, and separately the repository carries a mechanism that "
        "executes without anyone asking it to. ⚠️ These two were found in DIFFERENT "
        "files and nothing here demonstrates a path between them -- that separation "
        "is the real attack shape, which is why this chain is reported at all, and it "
        "is also why it is only a prompt to look.",
        "Check whether the instruction-bearing file is one an agent actually loads (a "
        "README or skill file usually is; a fixture under tests/ usually is not), and "
        "whether the auto-run mechanism is reachable on that same load path. If both "
        "are test data, this chain is noise -- say so and move on.",
    ),
    (
        "chain-hidden-instruction-to-autorun",
        "Reviewer-invisible content co-occurs with an auto-run execution path",
        Severity.MEDIUM,
        SAME_TREE,
        [
            ("reviewer-invisible content", _is_hidden_content),
            ("auto-run mechanism", _is_autorun),
        ],
        "The content link is one a human reviewer cannot see on screen -- invisible "
        "Unicode, a bidirectional override, a terminal escape, an HTML comment. "
        "Paired with something that auto-executes, the reviewer approving this "
        "repository and the agent loading it are not reading the same file. ⚠️ Again: "
        "different files, no demonstrated path between them.",
        "Render the hidden-content file with a tool that shows control characters, and "
        "confirm what the auto-run mechanism actually does.",
    ),
    (
        "chain-mcp-autostart-with-credentials",
        "One MCP manifest both auto-starts a server and hands it a credential",
        Severity.HIGH,
        SAME_FILE,
        [
            ("MCP server auto-starts", _is_mcp_autostart),
            ("credential passed to an MCP server", _is_mcp_credential),
        ],
        "Both halves are in the SAME manifest: a server that starts automatically when "
        "the agent loads this config, and credential-shaped environment variables "
        "handed to a server in that same file. Whatever it does with them happens "
        "outside this repository, and it holds them for the whole session.",
        "Confirm the server is one you have audited, and scope the credential to the "
        "minimum it needs -- a short-lived token rather than a standing one. ⚠️ This "
        "chain proves same-FILE co-location, not that the credential goes to that "
        "specific server; a manifest with several servers may pair them differently.",
    ),
    (
        "chain-remote-mcp-with-credentials",
        "One MCP manifest fetches a server from an unpinned source and hands it a credential",
        Severity.CRITICAL,
        SAME_FILE,
        [
            ("MCP server auto-starts from a remote/unpinned source", _is_mcp_remote_autostart),
            ("credential passed to an MCP server", _is_mcp_credential),
        ],
        "The previous chain's sharper form, and in the same file: the code receiving "
        "the credential is not pinned, so what runs can change without this config "
        "changing. A credential handed to an unpinned remote source is a supply-chain "
        "credential disclosure waiting on someone else's release.",
        "Pin the server to an exact version from a source you control before it "
        "receives any credential at all.",
    ),
    (
        "chain-credential-plus-exfil-path",
        "A credential and a data-egress mechanism in the same file",
        Severity.HIGH,
        SAME_FILE,
        [
            ("credential present", _is_real_credential),
            ("data-egress mechanism", _is_exfil_path),
        ],
        "A credential and a mechanism that sends data outward are in the SAME file. "
        "Neither alone says the credential leaves; in one file they are close enough "
        "to be worth reading together. 🔴 This chain previously required only that both "
        "existed anywhere in the tree, and an audit proved that composed a detector's "
        "own template string with an unrelated documentation example into a confident, "
        "entirely false claim. Same-file is the narrower scope that fixed it.",
        "Rotate the credential (it is in the tree, which is disclosure on its own), "
        "then read the file and confirm whether the egress path can actually reach it.",
    ),
]


def _identity(f) -> str:
    return f"{_engine(f)}|{_rule(f)}|{getattr(f, 'file', '')}|{getattr(f, 'line', '')}"


def _matches_in_file(active, predicate, path):
    return [f for f in active if predicate(f) and getattr(f, "file", "") == path]


def _correlate_same_file(chain_id, title, severity, links, why, verify, active):
    """A SAME_FILE chain fires once per FILE that satisfies every link inside
    that one file. Reported per-file so the reader sees which config is the
    problem, rather than one merged blob implying a relationship across files
    that this chain specifically declines to claim."""
    out = []
    candidate_files = sorted({
        getattr(f, "file", "") for f in active
        if any(predicate(f) for _label, predicate in links)
    })
    for path in candidate_files:
        if not path:
            continue
        matched = []
        for label, predicate in links:
            hits = _matches_in_file(active, predicate, path)
            if not hits:
                matched = []
                break
            matched.append((label, hits))
        if not matched:
            continue
        if not _links_are_distinct(matched):
            continue
        out.append(_render(chain_id, title, severity, SAME_FILE, matched, why, verify, scope=path))
    return out


def _links_are_distinct(matched_links) -> bool:
    """True when every link can be satisfied by a DIFFERENT finding.

    A chain whose links are all satisfied by the same single finding is not a
    chain -- it is one finding counted twice. Predicates legitimately overlap
    (an MCP autostart finding is also categorised DANGEROUS_HOOK), so this must
    ask whether a one-to-one assignment exists, not merely count.

    🔴 IT USED TO COUNT THE UNION, and that is correct for two links by Hall's
    theorem and WRONG for three or more. An audit demonstrated a three-link
    chain firing where two of its links were satisfiable only by the same single
    finding: the union held three identities, so the count passed, while no
    assignment existed. No three-link chain is defined today -- but this
    module's own header advertises that one needs only a table entry, and this
    check's docstring already records that it was vacuous once.

    Kata-style augmenting-path matching. The link count is single digits, so the
    cost is irrelevant and the correctness is not.
    """
    links = [sorted({_identity(f) for f in hits}) for _label, hits in matched_links]
    assigned: dict = {}

    def augment(i, seen):
        for ident in links[i]:
            if ident in seen:
                continue
            seen.add(ident)
            if ident not in assigned or augment(assigned[ident], seen):
                assigned[ident] = i
                return True
        return False

    return all(augment(i, set()) for i in range(len(links)))


#: A SAME_TREE chain may not exceed this, whatever its table entry says.
#:
#: 🔴 THE CAP WAS A SENTENCE IN A COMMENT AND NOTHING CHECKED IT. An audit added
#: a SAME_TREE entry at CRITICAL on a copy of this file; `correlate()` returned
#: it as CRITICAL and the ENTIRE test suite stayed green, because the only
#: assertion pinned one existing entry's literal value rather than the
#: invariant. "Both categories appear somewhere in this repository" is close to
#: certain in any real tree, so a SAME_TREE chain outranking its own links is
#: exactly the false escalation the proximity model was added to stop.
#:
#: ⇒ Clamped here, where a new table row cannot get around it.
_SAME_TREE_MAX = Severity.MEDIUM


def _capped(severity, proximity):
    """Return the severity a chain may actually report."""
    if proximity == SAME_TREE and severity > _SAME_TREE_MAX:
        return _SAME_TREE_MAX
    return severity


def _render(chain_id, title, severity, proximity, matched_links, why, verify, scope):
    severity = _capped(severity, proximity)
    return {
        "chain_id": chain_id,
        "title": title,
        "severity": severity.label,
        # Stated in the output, not just in this module's source: a reader can
        # see whether the claim rests on same-file co-location (real evidence)
        # or mere co-occurrence in the tree (a prompt to look).
        "proximity": proximity,
        "scope": scope,
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
                        # Carried through deliberately: every other line in the
                        # report shows SEVERITY/CONFIDENCE so a reader can weigh
                        # the claim. The one section computing a NEW severity is
                        # the last place that should hide its inputs' confidence
                        # -- a LOW-confidence finding must not silently anchor a
                        # CRITICAL chain and read identically to a HIGH one.
                        "confidence": f.confidence.label,
                    }
                    # Cap per link: a tree with 300 injection hits should not
                    # render 300 rows. The total is reported so the cap is
                    # visible, never silent.
                    for f in hits[:5]
                ],
                "total": len(hits),
                "shown": min(len(hits), 5),
            }
            for label, hits in matched_links
        ],
    }


def correlate(active: list) -> list:
    """Find attack chains across ACTIVE findings. Never mutates them.

    Returns a list of chain dicts, highest severity first. An empty list means
    no chain matched -- which is NOT a statement that the tree is safe, exactly
    as an empty findings list isn't.
    """
    out = []
    for chain_id, title, severity, proximity, links, why, verify in CHAINS:
        if proximity == SAME_FILE:
            out.extend(
                _correlate_same_file(chain_id, title, severity, links, why, verify, active)
            )
            continue

        # SAME_TREE: the links are expected in different files, so co-location
        # cannot be required -- but co-occurrence across a tree is weak, which
        # is why these chains are capped at MEDIUM in the table above rather
        # than being allowed to escalate on evidence they do not have.
        matched = []
        for label, predicate in links:
            hits = [f for f in active if predicate(f)]
            if not hits:
                matched = []
                break
            matched.append((label, hits))
        if not matched or not _links_are_distinct(matched):
            continue
        out.append(_render(chain_id, title, severity, SAME_TREE, matched, why, verify,
                           scope="(across the scanned tree)"))

    by_label = {s.label: int(s) for s in Severity}
    out.sort(key=lambda c: -by_label.get(c["severity"], -1))
    return out
