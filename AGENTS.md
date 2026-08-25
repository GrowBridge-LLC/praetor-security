# AGENTS.md

Onboarding for any AI coding agent working in this repository — written with
[Codex](https://openai.com/codex) specifically in mind, alongside
[Claude Code](https://docs.claude.com/en/docs/claude-code), which this project
already uses as a build tool (see `CLAUDE.md`).

## Read `CLAUDE.md` first — it is the canonical rule set

`CLAUDE.md` is not Claude-specific. It states the actual engineering rules for
this codebase: the invariant, the suppression carve-out, the testing
discipline. Nothing in this file overrides it. If this file and `CLAUDE.md`
ever disagree, `CLAUDE.md` wins — treat the disagreement itself as a bug and
fix it, don't quietly pick a side.

This file exists for what `CLAUDE.md` doesn't cover: fast orientation for an
agent new to the repo, and how two different agents work the same codebase
without either one grading its own homework.

## What PRAETOR is, in three sentences

PRAETOR is a static, multi-engine security scanner: four engines (`sast`,
`secrets`, `sca`, `aisec`) plus an interpretation layer that dedups, ranks, and
false-positive-filters their combined output into one report. It reads files;
it never executes, imports, installs, builds, or evaluates anything it scans —
that guarantee is the whole product. It ships as both a standalone Python CLI
(`scripts/praetor.py`) and a Claude Code skill, with a Rust port in progress
(`references/ADR-001-engine-language.md`).

## The rule that outranks everything

**PRAETOR NEVER EXECUTES, IMPORTS, INSTALLS OR BUILDS THE CODE IT SCANS.** It
has been false once — the SCA path let `pip-audit` resolve a target's
`requirements.txt`, which builds source distributions and runs arbitrary
`setup.py` / PEP 517 code from an attacker-controlled tree. The fix is
`--disable-pip` in `scripts/engine_sca.py`, one flag, and it is the whole
guarantee. Every new engine or backend widens this surface; every one needs a
behavioural test in `tests/test_invariant_never_executes_target.py` — it
captures the argv PRAETOR would hand to a subprocess without running
anything, so it fails when the flag stops reaching the command line, not
merely when a comment changes.

## The other two rules that matter most

Full reasoning lives in `CLAUDE.md` and `CONTRIBUTING.md`. Compressed:

1. **Suppression must fail safe and carry a reason.** Unproven ⇒ keep the
   finding. Never suppress on file path alone — that exact mistake once hid a
   real hardcoded credential in live code. `secrets` is deliberately excluded
   from both context-based suppression passes (`lexctx`, `taint`): a secret is
   dangerous because it *exists*, not because it *executes*, so "this string
   can't reach a sink" is not a reason to hide it. If you find yourself arguing
   a suppression technique is safe "by its nature," that is the moment a
   carve-out is about to be omitted — state what would make it unsafe and check
   that case is handled.
2. **Prove a test can fail before trusting it.** After adding a guard, change
   the real code it protects and confirm the named test goes red, then
   restore. Mutate in both directions: the thing that must be suppressed, and
   the thing that must survive. A green suite proves nothing until it has been
   seen red.

## Testing discipline

```bash
bash tests/precommit.sh
```

Nine gates. It exits non-zero on the first failure. **Read the exit code, not
the output** — this repo has been committed over a red gate at least three
times because a piped `grep` matched the word `FAIL` and returned 0 anyway.
Capture `$?` and branch on it; never `precommit.sh | grep ... && git commit`.

Fast inner loop:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/ -q
```

The env var is required, not optional — a globally installed pytest plugin on
some machines autoloads and dies on import before collection. That looks like
a broken repo. It isn't one.

Semgrep, osv-scanner, pip-audit, and npm are all optional — the test suite
captures subprocess argv rather than executing anything, so none of them are
needed to run `pytest`. Semgrep itself runs native, via WSL, or via a
read-only Docker mount, in that detection order (`engine_sast.py`); if none
are present the engine reports itself `unavailable` and the scan degrades
rather than silently lying about coverage.

## Layout

| Path | Role |
|---|---|
| `scripts/praetor.py` | CLI, engine orchestration, suppression wiring |
| `scripts/engine_*.py` | the four engines: `sast`, `secrets`, `sca`, `aisec` |
| `scripts/interpret.py` | dedup, rank, false-positive filtering |
| `scripts/lexctx.py` | lexical context: comment / docstring / code |
| `scripts/taint.py` | reachability: does a string reach a dangerous sink? |
| `scripts/report.py` | text + JSON output |
| `tools/classify_baseline.py` | assigns a predicate to each self-scan finding |
| `rules/` | bundled offline Semgrep rules |
| `references/` | architecture, limits, ADRs, design docs, audits, self-scan baseline, test corpus |
| `rust/` | the in-progress Rust port (`references/ADR-001-engine-language.md`); Python stays the reference implementation until the Rust one matches it exactly |

## Where the project actually stands — check, don't take anyone's word for it

A claim made in conversation — including by the repo owner, including in
another agent's handoff — is a claim, not a fact, until it matches what is
committed. This repo's own history has several "fixed" claims a second reader
later disproved.

Before changing anything:

- Read `CHANGELOG.md`'s `Unreleased` section. It states, per change, what the
  change means for *detection*, and which findings are fixed versus still
  open.
- Read the most recent file in `references/audits/`. Independent audits land
  there, dated, with a scope line stating exactly which commit range they
  cover.
- Run `git log --oneline -20` and compare it against whatever a handoff or
  audit claims as HEAD. A stale claim treated as current is how a fixed
  regression ships a second time.
- As of commit `8f46d3b`, two findings from an external review
  (`references/audits/2026-08-13-scope-and-cost-research.md`, labeled CR-1
  and CR-2) were recorded open and unresolved in the code that ships — a
  regex/glob mismatch in how `--exclude` reaches Semgrep, and an `ok` status
  that survives a scope-narrowing fallback. If you're told they're closed,
  verify directly against `scripts/core.py` (`re.compile` at line ~538) and
  `scripts/engine_sast.py` before relying on it.

## No AI-tool branding in anything that ships

Gate 6 of `tests/precommit.sh` blocks a `Co-Authored-By` trailer naming this
assistant, a "Generated with" credit naming its coding tool, and the robot
emoji, in any shipped file or the last commit message. The underlying rule is
broader than what's implemented today: **no AI-tool attribution of any kind**
— including Codex's own — belongs in a commit, PR, tag, or release in this
repo. Today's pattern only matches the one vendor name; that's a known gap in
the gate, not a statement that other tools are exempt from the rule. If you
notice AI-tool-branded output about to ship under a name the gate doesn't
check for, that's worth fixing in the gate itself, not just in your own
commit. (This paragraph is deliberately worded to avoid the exact strings the
gate matches — reproducing them here would trip gate 6 on this file. See
`tests/precommit.sh`'s own gate-6 block for the literal patterns.)

## The collaboration model — why two agents, and what each owes the other

This repo has direct, measured evidence for a specific claim: **an agent
reviewing its own fix is the weakest reviewer available.** Three consecutive
rounds of independent adversarial audit ran over the same range of commits
here, and each round's fix introduced a new defect the round before had not
caught. Then an outside, differently-built reviewer's *first* pass found two
more defects that all three rounds — six independent passes total — had
missed, one of which would have broken CI on the next push. That result is
recorded in `CHANGELOG.md` and
`references/audits/2026-08-13-scope-and-cost-research.md` because it is a
load-bearing lesson from this project's own history, not a one-off anecdote.

The likely reason isn't carelessness. It's structural: a reviewer built the
same way, trained the same way, holding the same context as the author, tends
to share the author's blind spot. Two agents built by different teams, on
different training, are more likely to fail *differently* — and failing
differently is the only property that makes a second review worth anything.

That's what "symbiotic" means here, in concrete terms:

- **Neither agent's self-review counts as the review**, for any change
  touching the invariant, suppression logic, or gate/exit-code logic (the
  sections marked 🔴 in `CLAUDE.md`). If Claude Code writes the fix, Codex is
  the outside reader before it's trusted, and the reverse holds too — not a
  courtesy pass, a real attempt to break it.
- **Both agents are bound by the same rules**, because the rules bind the
  codebase, not whichever tool happens to be editing it right now. `CLAUDE.md`
  applies to Codex in full; nothing here loosens it.
- **A handoff must be readable cold.** State what was verified, what was
  assumed, and what failed — exact commands, exact `file:line` — not "should
  work now." Whoever picks it up next, human or agent, needs to act on it
  without re-deriving your context first.
- **An external reviewer is a third, still-more-independent pass**, and
  neither agent reviewing the other replaces it. Fast Claude ↔ Codex
  cross-review is the inner loop; an outside review before anything ships to
  `main` is the outer gate — see
  `references/audits/2026-08-13-scope-and-cost-research.md` §1 for exactly
  what it caught that six agent passes did not.
- **This document is itself subject to the same rule.** If this framing turns
  out wrong, incomplete, or stale, that's exactly the kind of thing the other
  agent should catch — fix it in place instead of quietly working around it.

## If you are `codex-f`, your standing goal is a separate file

Read `inbox/GOAL-codex-f-2026-08-22.md` before you accept any task. It carries the operator's
own words and the two resolutions that settle where those words pull against themselves.

It is a pointer on purpose. A goal changes and a pasted copy rots, so this file names the goal
rather than repeating it.

Your build worktree is `.codex/PRAETOR-codex` on branch `codex-f/build`. Your pair channel is
`C:\projects\PRAETOR\.local\PAIR-CHANNEL.md`, append-only and NOT tracked -- the
absolute path is deliberate, since that directory is absent from your worktree. Your own handoff
file is `inbox/HANDOFF-codex-f.md`
on your own branch. Do not write to the auditor's handoff.

## Designed but not built — reasonable places to pick up work

Not exhaustive; `references/audits/` has the full record. These are named,
authorized-or-open design decisions with no code behind them yet:

- `references/DESIGN-LF2-malfunction-vs-unavailable.md` — a scanner exit-code
  gap: `praetor .` with no `--fail-on` and a dead engine currently exits 0,
  so a caller can't distinguish "scanned, clean" from "didn't run."
- Git-tracked file selection for the wide-walk engines — measured 56× fewer
  files scanned on a real repository, same coverage, and it closes the
  directory-name-evasion hole a hardcoded skip-list can't.
- Restoring Semgrep's real default-ignore set — measured at ten directories,
  not the thirty currently hardcoded in this repo.

## Where working notes go, and what must never ship

This repo is public. Routine build traffic, drafts, assignments, and working
state stay under .local/. That directory is intentionally ignored and pre-commit
gate 9 asserts that no .local artifact is tracked.

Pair traffic goes to C:\\projects\\PRAETOR\\.local\\PAIR-CHANNEL.md, which is
tracked and absent from worktrees -- hence the absolute path. Append to it with
the shared channel-append.sh and an absolute CHANNEL_FILE, never with Write or
Edit. Read its tail at the start of every session.

lane-pair.md (the same directory) is frozen as the record from before
2026-08-22 -- read it for history, post nothing new to it. The earlier rule
sent traffic there directly and forbade a channel wrapper, because a helper
aimed at an ignored path could append while its attribution check was
inoperative; that reason no longer applies now that the channel is tracked.

Findings for another project, blockers owned elsewhere, and contract corrections
belong in the shared coordination channel; otherwise keep routine traffic local.

The .local directory is machine-local and must never enter this public repository.

## One line, if you read nothing else above

This is a security scanner. A bug here is not a broken feature — it's a
scanner that says "clean" while something is there. When in doubt between a
change that might suppress a real finding and one that might report a false
one, keep the finding and take the false positive. Every rule above is a
specific case of that one sentence.
