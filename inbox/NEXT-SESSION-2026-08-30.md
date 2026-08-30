# PRAETOR — next-session plan, written 2026-08-30

Written for a session with zero memory of this one. Every number below has the
command that produced it. Re-run them; do not cite them as current.

⚠️ **This repository is public.** Coordination detail — branch topology, review
ownership, proposed ref names, and anything naming another repository on this
machine — is deliberately NOT in this file. It is at
`C:\projects\PRAETOR\.local\NEXT-SESSION-COORDINATION-2026-08-30.md`, which is
gitignored and absent from worktrees, hence the absolute path. **Read that file
too; this one alone is not the whole plan.**

🔴 **Two working files, and they answer different questions.** The pair
channel is **append-only**, so every verdict in it is a LOG ENTRY: reading the
tail tells you what was true when that line was written, never what is true now,
and nothing in the format distinguishes the two. A superseded verdict still
reads as authoritative at its own line. That produced three stale-state
collisions in one day, in three different directions, between careful readers.

- `.local\PAIR-CHANNEL.md` — append-only LOG. Reasoning and history.
- `.local\AUDIT-STATE.md` — **overwritten, never appended.** One writer.
  Current verdicts, open items, standing constraints.

**Read AUDIT-STATE.md for STATE. Read the channel for REASONING.** No collision
has occurred since the split.

The split is not tidiness. Pre-commit gate 8 (`public-hygiene`) rejected the
combined file, correctly, for naming a sibling repository and using lane
framing. The finding was right and the file was in the wrong place.

## 0. What happened after this file was first written

Read this section first. The rest of the file was accurate when written and
parts of it have been overtaken.

### A real behavioural defect in this scanner, found and fixed but NOT MERGED

**All four suppression passes were silent no-ops when the scan target was a
single FILE rather than a directory.** They resolved a finding's source path by
joining it onto the target; when the target is already a file, that builds
`file.py/file.py`, the read fails, the bounds check fails, and the pass returns
having done nothing. No error, no warning, no `filter_reason`. It reported as a
clean scan.

Same file, two invocations, before the fix:

```bash
python scripts/praetor.py DIR/subject.py --engines aisec   # -> active 1, filtered 0
python scripts/praetor.py DIR            --engines aisec   # -> active 0, filtered 1
```

**Direction of failure is SAFE** — it keeps findings rather than dropping them,
so it is not a false-negative hole. Two consequences that matter anyway:

- The documented false-positive suppression does not work for the single-file
  invocation, which is the invocation `SKILL.md` teaches.
- **A single-file scan's FILTERED count is not trustworthy** in any build that
  does not carry the fix. If you are triaging findings, scan the directory.

The fix is one shared path resolver used by all four passes. It is **accepted
and unmerged** — it lives on the builder branch, not on `main`. Until the merge
happens, `main` still has the defect.

### The regression test for it is guarded against a coincidence

The end-to-end test for that fix can pass while the fix is broken, depending on
where you run it from. Derived predicate, verified:

> **The false green occurs if and only if N == T**, where N is the number of
> `..` in the finding's reported path and T is the subject file's depth below
> the prefix it shares with the current working directory.

Windows cancels `subject.py\..` textually, without checking that `subject.py`
is a directory, so when N == T the broken join lands back on the real file. Two
people ran the identical mutation and got opposite results for this reason
alone.

**Root cause is `scripts/core.py`:** a finding's `file` field is
**cwd-relative** for a single-file target (`core.py:732`) and **target-relative**
for a directory (`core.py:772`). Every consumer of `f.file` has to know which
mode produced it and none of them are told. That dual contract is unfixed and
deliberately out of scope for the test repair — changing it touches every
engine.

### Two corrections to the measurements in section 1

- **The file-count instrument changed.** `find | wc -l` is withdrawn. Use
  `git ls-files | wc -l`. Measured here: **92-96% of the old population was
  gitignored churn** — canonical 1124 ignored against 100 tracked, builder 2446
  against 109. A one-file loss among ~100 real deliverables cannot register
  against ~2400 churning bytecode and cache files, and running the test suite
  moves the number.

  🔴 **But `git ls-files` is only half the answer, and the missing half is
  the point of the check.** It reads the INDEX, so it cannot see an untracked
  file at all — and the work a careless cleanup destroys is exactly the
  untracked work. A tracked file that disappears shows in `git status`; an
  untracked one leaves no trace, and `git ls-files` returns the same number
  before and after. Measured here: 100 before adding an untracked file, 100
  after.

  **Three instruments, three different blindnesses, all aimed at the same
  population:**

  | instrument | misses |
  |---|---|
  | `find . -type f` | 92-96% churn drowns any real loss |
  | `git ls-files` | every untracked file |
  | `git ls-files --others --exclude-standard` | every **ignored** file |

  The third one matters most here. `.local/` is gitignored by design — it must
  never enter this public repo — and it holds **67 files**, including the audit
  state, the pair channel, and the coordination half of this very plan. All of
  them are **invisible to both** proposed counts.

  ⇒ **Do not try to protect unversioned work with a count.** For tracked work
  use `git ls-files | wc -l` (floors here: 100 canonical, 109 builder). For
  anything ignored-but-precious, **enumerate the paths by name** and check the
  names, not a total. A population you cannot enumerate is one you cannot
  notice losing.
- **The two branches disagree about what a clean scan is.** `tests/precommit.sh`
  pins `EXPECT_ACTIVE=13` on `main` and `31` on the builder branch. Both gates
  pass, each against its own tree. **At merge time one pin wins, and if the
  higher one does, the gate silently loosens with no red anywhere.** Account for
  the delta before merging; do not regenerate the baseline to make it disappear.

### 🔴 Exit code 1 means two opposite things (open, assigned)

The documented contract at `scripts/praetor.py:28-45` says:

```
0  no active findings at/above --fail-on
1  active findings at/above --fail-on
2  usage / internal error
3  THE SCAN DID NOT COMPLETE safely enough to pass
```

The entry point handles exactly one exception:

```python
if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
```

**Everything else propagates, and Python exits 1** — the code we document as the
ordinary "we found something" result. Proved by injecting a crash immediately
before the report write:

```
PRAETOR rc=1
report written? -> 0 file(s)
```

**Exit 1, no report, externally byte-identical to a healthy scan that found a
HIGH finding.** Our own comment at line 122 says an exit code is this tool's
entire contract with CI — and code 1 currently carries "I worked and found
things" and "I crashed" at once. Separating those is the only thing an exit code
exists to do.

The requirement is **never 1**; whether the right answer is 2 (internal error)
or 3 (scan did not complete) is open. ⚠️ **The wrong fix is catching `Exception`
inside `main()`** — that converts a crash into a *quiet* result and loses the
traceback. A silent 2 is worse than a noisy 1. The handler belongs at the entry
point. Writing no report on that path is correct: a partial report is worse than
none, and a consumer checking freshness will refuse.

⚠️ **This defect is real and proved. Do not attach it to any particular
incident** — a causal claim of that kind was made and retracted the same day.
A mechanism that explains every observation is not thereby the mechanism that
produced them.

### A standing risk that is not ours to solve

**The unlanded commits on the builder branch have no off-disk copy.** A
machine-global guard blocks `git push` for any ref whose name matches a
force-push pattern, and the builder branch name matches it. A backup ref can
therefore only ever be **local** — it protects against a bad history operation
and **not against disk loss**. Do not route around the guard; it is firing as
written and another owner maintains it.

## 1. Where things stand

```bash
git rev-list --left-right --count main...codex-f/build     # -> 3    45
git rev-list --left-right --count origin/main...main       # -> 0    1
git status --porcelain | wc -l                             # -> canonical
git -C .codex/PRAETOR-codex status --porcelain             # -> builder
```

- Canonical checkout `C:\projects\PRAETOR`, branch `main`, tip `681f844`.
- Builder worktree `C:\projects\PRAETOR\.codex\PRAETOR-codex`, branch
  `codex-f/build`, tip `a62a977`.
- **The integration tip is local `main` at `681f844`.** `origin/main` at
  `b80f7f8` is one commit stale. An earlier note stated this backwards; it is
  corrected here.
- The machine rebooted 2026-08-30 05:01:13. Treat anything measured before that
  as unconfirmed.

### 🔴 The on-disk file count command is wrong in a worktree

On-disk counts recorded before any cleanup: canonical **3769**, builder
**2547**. These must not fall. Measure them with the corrected form:

```bash
# WRONG in a linked worktree -- returns 2548, one too many:
find . -type f -not -path './.git/*' | wc -l
# CORRECT -- returns 2547:
find . -type f -not -path './.git/*' -not -name '.git' | wc -l
```

In a normal checkout `.git` is a DIRECTORY, so `-not -path './.git/*'` excludes
it. In a linked worktree `.git` is a 57-byte FILE holding a gitdir pointer, and
that glob does not exclude a file at that path — so the worktree count is
inflated by exactly one. Two independent measurements of the same unchanged
tree disagreed by one, and this was the entire cause.

**Why it matters:** the acceptance test for a cleanup is "the count did not
fall." A count recorded with the inflated command and re-checked with a correct
one shows a phantom loss of one file, sending the next session hunting for
something never lost. The inverse is worse — a genuine loss of one file is
masked, and the check passes.

## 2. The exact next action — resolve the one merge conflict by REGENERATING

`main` and `codex-f/build` produce exactly one conflict block, in
`references/kb/records.jsonl`.

```bash
# after merging the SOURCES cleanly:
python scripts/kb-build.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python tests/kb-drift.py ; echo "rc=$?"
```

🔴 `references/kb/records.jsonl` is a **generated** file. Its generator's own
docstring says nobody hand-edits it. All four `claims-*.jsonl` source files
merge cleanly, as do `kb-build.py` and `tests/kb-drift.py`; the whole merge
produces one conflict block and it is in the derived file alone. Hand-editing
the markers would produce a state no run of the generator can reproduce — the
exact state the drift gate exists to prevent.

🔴 **The trap in that fix.** `kb-drift.py` recomputes each hash from the current
tree. After a regeneration those match **by construction**. A green drift gate
straight after regenerating is not evidence about the merge; it only resumes
gating on the next change. The audit it cannot supply: diff the regenerated
records against both parents and confirm every moved `source_sha` or `verbatim`
moved because the cited source line genuinely moved.

⚠️ This is **not** the `references/differential/*.expected` case. That file is a
contract precisely because regenerating it makes it agree with whatever produced
it. The distinguishing property here is the independent recomputation.

**Merge, not rebase.** A rebase rewrites commit identity, and an accepted audit
is bound to an existing commit SHA — rewriting it would silently void a cleared
audit. That reason outranks the conflict-replay one.

## 3. Reading the gate

```bash
bash tests/precommit.sh ; rc=$?   # read $?, never the printed output
```

A run on 2026-08-30 returned `rc=1` on two gates at once: a self-scan pin drift
(15 active vs 13 expected) and public-hygiene. Both were caused by this very
file in its original combined form. The two new findings were the proposed ref
name read as a 49-character high-entropy string. Neither gate was weakened; the
file was split instead.

## 4. What is gated on a human decision

**WHAT** — name the backup ref before any history operation.
**HOW** — the proposal is recorded in the `.local` coordination file, not here;
it embeds lane framing that this repo's own hygiene gate rejects, so the
spelling needs revising before it is used.
**PASS** — a name given. **FAIL** — no name; nothing proceeds, correctly.
**WHY A HUMAN** — backup-ref and remote-write policy is not the lane's to set.
**WHERE** — machine **BlueIris** (Windows); `CLAUDE_CONFIG_DIR` unset, so
**Profile A** (`~/.claude`).

**WHAT** — approve, per page, anything written to this repo's GitHub wiki.
**HOW** — `gh api repos/GrowBridge-LLC/praetor-security --jq '{private,has_wiki}'`
returns `{"has_wiki":true,"private":false}`. **Writing there publishes.**
**PASS** — explicit per-page go. **FAIL** — anything published without it, which
is irreversible.
**WHY A HUMAN** — publication is irreversible.
**WHERE** — same machine and profile.

## 5. What was NOT verified

- **The account this session runs under.** `CLAUDE_CONFIG_DIR` is unset
  (Profile A), but the session's own `userEmail` reads the account being
  retired. The two disagree and were not reconciled.
- **That the regeneration in §2 produces a correct `records.jsonl`.** Nobody has
  run it.
- **That the accepted single-file suppression fix behaves correctly once merged.**
  It is accepted against one commit hash only, on a branch that has not been
  merged. Acceptance of a commit is not a claim about the merged tree.
- **That the repaired regression test is location-independent in general.** The
  predicate above is derived and reproducible; a repair for it was assigned and
  has not been delivered or audited.
- **The exact depth arithmetic in every layout.** N == T is verified in five
  measured cases, not proven for all.
- **The exact read ceiling on the memory index.** Its current size is measured;
  that it is under the ceiling is not established.
- **That any push of the builder branch would succeed.** It was never attempted.
  See the `.local` coordination file for a reported guard interaction.

## 6. Hygiene measurements

```bash
ls ~/.claude/projects/C--projects-PRAETOR/memory/*.md | wc -l   # -> 58
wc -c ~/.claude/projects/C--projects-PRAETOR/memory/MEMORY.md   # -> 13722
wc -l ~/.claude/projects/C--projects-PRAETOR/memory/MEMORY.md   # -> 85
```

- **Orphaned memory: zero.** All 58 files have a pointer line in the index,
  checked by matching each filename against it.
- ⚠️ This project's memory lives in the **profile store** at the path above, not
  in this repository. A reader who looks only in the repo concludes there is no
  memory, and a session acting on that would start a second, forked store.
- Remote matches the identity map. Verify it without printing the org name,
  which this repo's own hygiene gate denies in a shipping file:

  ```bash
  git remote get-url origin | grep -q '^git@github\.com-' && echo "SSH alias OK"
  ```

  The git-root leaf is `PRAETOR`, not a generic name.
