# PRAETOR — next-session plan, written 2026-08-30

Written for a session with zero memory of this one. Every number below has the
command that produced it. Re-run them; do not cite them as current.

⚠️ **This repository is public.** Coordination detail — branch topology, review
ownership, proposed ref names, and anything naming another repository on this
machine — is deliberately NOT in this file. It is at
`C:\projects\PRAETOR\.local\NEXT-SESSION-COORDINATION-2026-08-30.md`, which is
gitignored and absent from worktrees, hence the absolute path. **Read that file
too; this one alone is not the whole plan.**

The split is not tidiness. Pre-commit gate 8 (`public-hygiene`) rejected the
combined file, correctly, for naming a sibling repository and using lane
framing. The finding was right and the file was in the wrong place.

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
