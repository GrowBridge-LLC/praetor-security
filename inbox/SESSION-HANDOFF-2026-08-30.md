# PRAETOR — historical session handoff, 2026-08-30 (fully superseded)

> **OWNER OVERRIDE — 2026-08-31:** This entire dated handoff is historical
> evidence. Every current-state label, path, count, assignment, next action,
> wait, merge, push, and coordination instruction below is non-operational.

The companion restart/masterplan documents and former local verdict ledger are
also dated historical evidence. Current authority comes only from canonical
operating guidance, live local measurements, and owner-designated private receipts.

## 1. Identity and environment

| | |
|---|---|
| working dir | `C:\projects\PRAETOR` |
| builder worktree | `C:\projects\PRAETOR\.codex\PRAETOR-codex` (branch `codex-f/build`) |
| GitHub account | `GrowDev1` — verify with `gh auth status` before every write |
| remote | SSH alias form, `git@github.com-<alias>:...` — never HTTPS |
| interpreter | **`py -3.14`**. A bare `python` is 3.13 here and lacks pytest |
| test command | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 py -3.14 -m pytest tests/ -q` — the env var is required, not optional |

**Machine boot: 2026-08-30 05:01:13.** Session ran to ~23:50. **No reboot
during the session**, so nothing in flight was lost to one.

### 🔴 UNRESOLVED — which Claude profile this session ran under

The opening instruction said to **derive** the account rather than assume it.
Deriving it produced a contradiction that was never settled, and it is recorded
here because it was missing from every close-out document until the transcript
audit found the gap:

Two signals name **different profiles**, and neither was proven wrong:

1. `CLAUDE_CONFIG_DIR` is unset, which points at the default profile.
2. This session's own user-identity context field names the **other** profile.

**The two disagree.** This is the Claude profile, not the GitHub account — the
GitHub account was verified repeatedly and is correct. It matters because the
profile decides which settings and registry a command edits, and because one of
the two profiles was described as being retired.

⚠️ **The values are deliberately not printed here. This repo is public** — the
pre-commit hygiene gate rejected an earlier draft of this very paragraph for
naming them, which is the gate working. Re-derive both yourself; each is one
command, and neither needs to be written down.

⇒ **Do not assume either answer. Re-derive it, and say which signal you used.**

## 2. Repo state — verified live at close

```
HEAD / origin/main   ea9b82b + THIS commit   see the caveat below
working tree         0 dirty, excluding this file as it was written
suite                345 passed
gate                 13/13, rc read from $?, not from output
CI  run 33349135519  7374ccd  success  16 steps  semgrep-live + invariants
wiki                 LIVE at e326efa (separate repo, PUBLIC)
backup ref           1 on remote, under backup/praetor/
builder branch       0 unlanded (main 18 ahead, builder has nothing outstanding)
```

⚠️ **A handoff cannot state the hash of the commit that contains it.** `ea9b82b`
was HEAD when this block was measured; committing this correction moved it. The
same applies to "0 dirty" — it was 0 apart from this file. **Do not treat either
as current. Re-derive both, which is one command each:**

```bash
git rev-parse --short HEAD; git status --porcelain -uall | wc -l
```

The CI run is pinned to `7374ccd` on purpose: that is the commit it actually
ran on, and it is the last one whose CI result was read. **The commits after it
carry documentation only** — no scanner code changed — but their CI has not been
checked, so do not report them as green without looking.

### 🔴 READ THIS BEFORE QUOTING THE "13/13" ABOVE

**WSL was removed from this machine during the session**, so `sast` cannot run.
Verified directly: `wsl --list --verbose` reports it is not installed and the
`LxssManager` service does not exist.

**Every gate run this session was green with `sast` BLIND**, including the runs
that authorised the pushes. The gate's self-scan check reads only the exit code
and two counts; PRAETOR returns 0 on a degraded scan when no `--fail-on` is
given, and the `SCAN DEGRADED` banner it prints is captured and discarded on the
success path. Filed as **F41** in the restart plan, with the trade-off written
out. **The gate is not lying — it is answering a narrower question than it
appears to.**

⚠️ **The builder worktree has 14 dirty rows** — 3 modified plus 11 untracked.
They are codex-f's own evidence and manifest files plus three source rows that
now duplicate `main`. **That is deliberate and it is codex-f's tree, not a loose
end of mine.** It was told the three duplicates vanish on a sync with no
deletion, and that its evidence files are its own to keep or commit.

⚠️ *This line said **11** until an independent auditor re-counted it as 14. I
had counted the untracked rows and not the modified ones. The count is now
`git -C .codex/PRAETOR-codex status --porcelain | wc -l`, measured at close.*

## 3. DONE — chronological, with the reasoning

**Five defects found, fixed and landed.** All were in PRAETOR itself.

| id | defect | why it mattered |
|---|---|---|
| F35 | all four suppression passes were silent no-ops when the scan target was a single FILE — they joined the finding path onto the target, building `file.py/file.py` | no error, no `filter_reason`; it read as a clean scan. Fails safe (keeps findings) but a single-file FILTERED count could not be trusted |
| F36 | the regression test for F35 could pass while F35 was broken | its detection depended on path arithmetic between the cwd and the fixture. Fixed by controlling cwd depth and asserting the pass **opened the path it was asked to open** |
| F37 | an uncaught exception exited **1** — the same code as "found findings" — and wrote no report | a crash was indistinguishable from a healthy gate failure. Handler now at the entry point, traceback preserved, exits 2 |
| F38 | a test permitted a POSIX write to succeed, then asserted the file unchanged | passed on Windows, failed on Linux CI. **CI was the first Linux execution it ever had** |
| F39 | `lexctx.context_of` called `classify_lines` on every invocation and `lexctx` cached nothing, so the suppression pass re-classified the whole file **once per finding** | ~0.28 s per finding; one 1.2 MB file with 787 findings ≈ **244 s**, presenting as a hang with no artifact and no exit code. Now 0.988 s |

**Also this session:** the branch merged (48 commits, one conflict in a
generated file resolved by regeneration), the wiki given a real landing page,
the masterplan assessment and restart plan written and committed, and nine plus
four findings ruled for a consumer lane.

### Decisions worth not undoing

- **The merge conflict in `references/kb/records.jsonl` was resolved by
  REGENERATION, never by hand.** Its generator's own docstring says nobody edits
  it. ⚠️ The generator READS the existing file to grandfather empty fields, so it
  cannot run against conflict markers — seed with `git checkout --ours` first.
- ⚠️ **`tests/kb-drift.py` cannot vouch for such a resolution.** It recomputes
  hashes from the tree it is checking, so it passes by construction. It was
  checked against both parents instead: 0 records in neither parent, 0 whose
  `source_sha` matched neither.
- **The self-scan pin moved 13/52 → 31/47 and that is the gate getting
  STRICTER** — active rose while filtered fell. Verified by measuring the merged
  tree, not by trusting the incoming pin.

## 4. OPEN

### Blocked on Mike — nothing else can move these

- 🔴 **`git -C ~/.claude/skills/praetor pull`.** The installed skill is behind
  and missing F35 and F37. **Demonstrated, not inferred:** on a single-file scan
  with an authored `# nosec`, the installed copy returns 1 active / 0 filtered
  while the current build returns 0 active / 1 filtered with a stated reason.
  `~/.claude/skills/` is outside every project folder, so no lane can do it.
- **Two questions asked and never answered.** Neither blocks anything now, but
  both were acted around and a fresh session should not assume either:
  1. *Does the build hold bar committing documentation?* Commits and pushes went
     ahead on Mike's later "merge you damn trees / get a clean tree".
  2. *Does "the KB is superseded by the wiki" mean PRAETOR's `references/kb/`?*
     **Nothing was changed.** Ours is machine-readable by design and **three of
     thirteen gate checks depend on it**.

### Not started, specified

- 🔴 **F41 — the most serious open defect, and it has a LIVE trigger.** Without
  `--fail-on`, the whole engine-status gate is skipped and a degraded scan
  returns **0**, which means clean. WSL is gone from this box, so `sast` is blind
  right now, and our own `tests/precommit.sh` passed on that exit code all
  evening. Worse than F40, which at least returns 1. **Not fixed on purpose** —
  the repair reddens the gate estate-wide until WSL returns, which is Mike's
  call. Full detail and the trade in the restart plan, §1a-bis.
- 🔴 **F40 — a FALSE CLEAN, and the second most serious open defect.**
  `scripts/praetor.py:785-790` orders the blind-spot test AFTER the findings
  gate, so a scan with findings returns 1 and never reports that an engine was
  blind. Reproduced with `PRAETOR_SEMGREP_TIMEOUT=1`. Full detail and the
  how-not-to-rush-it in the restart plan.
- **A scan timeout that FAILS LOUDLY** rather than silently producing no
  artifact. Deferred deliberately from F39.
- **The false-positive class** — the detector fires on the prohibition. Nine
  rulings' worth of evidence, recorded with a how-NOT-to-fix-it list.
- **PRAETOR as a GitHub App**, Mike's direct instruction. Spec'd in the restart
  plan with two acceptance gates: it must prove no metered credential is
  reachable, and it must not hang.
- **This project's `CLAUDE.md` is 220 lines, over the 200-line cap.** It was
  already 218 before this session touched it, so the breach is not new, but it
  is real and nothing trims it automatically. The `lean-claude-md` skill has the
  playbook.
- **No check asserts the gate's own check count.** `CLAUDE.md` said "9 checks"
  while `tests/precommit.sh` had grown to 13. Corrected, and the line now tells
  the reader to count them instead of trusting it — but the class is open: a
  number in prose that nothing verifies.

## 4.5 Two red results that were NOT regressions — read this before you panic

Four independent audits ran at close. Two of them reported intermittent failures
on "an unchanged tree". **Both were explained, and neither is a defect.** They
had the same root cause: **a second actor was writing to the tree while the
auditor measured it.**

**1. The F39 regression test failed in 1 of 4 suite runs.** Not a flake. The
slop-audit agent had removed the F39 cache from `scripts/praetor.py` for its own
mutation test, and the fact-verification agent's concurrent suite run imported
the mutated file. Confirmed by positive control: disabling the cache reproduces
the reported signature exactly — six identical `(source, "subject.py")` tuples.
**F39 then passed 11 further runs: 5 serial and 6 concurrent, 345 each.**

**2. The KB-drift check failed in 1 of 3 gate runs.** Not a flake either. That
one was **mine** — I was editing `CHANGELOG.md` while the auditor was gating.
Mechanism in the next paragraph, because it will happen again to anyone who
edits that file.

🔴 **Editing `CHANGELOG.md` breaks the KB gate, by design, every time.**
`references/kb/claims-*.jsonl` anchors each quote to a `source_line`, and
`tests/kb-content-anchor.py` searches a **20-line window** from it. The
CHANGELOG is most-recent-first, so **any new entry shifts all 69 CHANGELOG
claims out of their windows.** Regenerating to silence it would re-anchor every
quote to whatever text now sits at those numbers — the gate warns against
exactly that. **The repair is to shift `source_line` by the measured insertion
delta, then let the content-anchor gate re-resolve every quote against the real
file.** That gate IS the verification: it re-read all 517 claims and returned
the pinned 30 unresolved. This session's delta was +63 below old line 22, +61
for old lines 15–21.

⇒ **The transferable rule: do not run an audit over a tree you are still
editing.** An auditor's "unchanged tree" premise is not something the auditor
can check, and both false alarms above cost real time to disprove.

## 4.6 Two things about the machine, not about PRAETOR

*Named in project `memory/`, not here: this repo is public and the hygiene gate
refuses a shipping file that names a sibling project. It rejected an earlier
draft of this very section, which is the gate working.*

- ⚠️ **The machine-level identity guard is INERT on this box.** Every `git`
  command this session ran printed that it found no identity config, so no
  project map was loaded. The plugin is installed and its hooks fire; the guard
  has nothing to check against. **The account and remote check before each push
  was therefore manual, not enforced.** Do it by hand — `gh auth status` and
  `git remote -v` — and do not assume a guard covered you.
- **This session's one rule candidate was KILLED on the coverage check, and that
  is the useful result.** A machine-level skill already carries it, better
  stated, bought 2026-08-11: *a mutating pass and a reading pass must not run
  concurrently on the same tree, and dispatching a mutator counts as editing.*
  🔴 **The rule did not fail — the trigger did.** I dispatched four
  content-valued audit agents, which is that skill's exact stated trigger, and
  never loaded it. Filed upstream as a delivery finding, not a new rule.

## 5. MUST NOT LOSE

- **Never suppress on PATH alone.** A proposal to exempt a consumer's ruling file
  structurally was **rejected** for this reason; we shipped that defect once when
  a directory predicate suppressed a real credential.
- **Do not narrow a detector while a lane is blocked by it.** Refused twice today
  under time pressure.
- **A clean scan is `NO FINDING`, never `SAFE`.**
- **Secrets are never suppressed by context or reachability.** A pattern in a
  comment is inert; a credential in a comment is still disclosed.
- **Read the gate's EXIT CODE, never its printed output**, and never through a
  pipe — a pipe makes `$?` the pipe's.
- **Do not ask for the machine-global push guard to be narrowed.** The candidate
  narrowing was measured WEAKER than what it replaces.
- **A backup ref name must not contain `-f` at a word boundary**, or the guard
  refuses the push. `backup/praetor/...` works; the branch name embedded does not.

## 6. Where things live

| what | where |
|---|---|
| forward plan | `inbox/RESTART-PLAN-2026-08-30.md` |
| where the project stands | `inbox/MASTERPLAN-ASSESSMENT-2026-08-30.md` |
| live verdict ledger | `.local/AUDIT-STATE.md` — **overwritten, never appended** |
| pair channel (log) | `C:\projects\PRAETOR\.local\PAIR-CHANNEL.md` — append only via the shared `channel-append.sh` |
| builder's standing goal | `inbox/GOAL-codex-f-2026-08-22.md` — permanent, does not expire |
| superseded | `inbox/NEXT-SESSION-2026-08-30.md` — bannered as history |
| durable lessons | project `memory/` in the profile store, with `MEMORY.md` index |

## 7. First moves

1. **Re-derive before trusting anything here.** `git status`, `git log -1`, the
   suite, and `.local/AUDIT-STATE.md`.
2. **Read the pair channel tail** — but grep forward for `claude-f -> codex-f`
   from your last known line rather than tailing. Tailing shows your own post.
3. ⚠️ **The channel Monitor was STOPPED at close. Re-arm it** if you want to be
   woken on codex-f posts.
4. Pick up from the restart plan, in its order.

## 8. What was NOT verified

- That the builder's 11 dirty rows contain nothing that should have been
  committed. **It is codex-f's tree and its call**, and it was told so.
- Any CI result whose step count was not read.
- Whether the two questions in §4 have since been answered elsewhere.
- The exact drift of the installed skill — **"54 or more"** is a lower bound. The
  ref two parties read had been written by one of them, so two readings of it are
  not two measurements.
