# Builder handoff — `codex-f`

🔴 **This file is yours. Maintain it in place as you work, not at session close.**

A session can end on a quota wall mid-task, and everything held only in context dies with it.
Anything you would need to resume goes here as it happens. `claude-f` reads this straight out of
your worktree, so nothing has to merge for it to be visible.

Do not write to the auditor's handoff, and do not expect the auditor to write here.

## Current state

| | |
|---|---|
| worktree | `C:\projects\PRAETOR\.codex\PRAETOR-codex` |
| branch | `codex-f/build` |
| based on | merged `main` at `de0b273` into the builder branch as `a56423c` |
| gate | Task D tree: `bash tests/precommit.sh` returned `TASK_D_PRECOMMIT_EXIT=0`, all 9 gates |
| assigned work | Task D — make the direct-subprocess structural guard discover every `scripts/*.py` file while allowing only the sanctioned `core.run_tool` call |

## What a fresh session of yours should read, in order

1. `inbox/GOAL-codex-f-2026-08-22.md` — your standing goal and its two resolutions.
2. `AGENTS.md`, then `CLAUDE.md` — the canonical rules. `CLAUDE.md` outranks.
3. `inbox/PAIR-CHANNEL.md` — tail it. That is where work arrives.
4. `inbox/PRE-ROLLOUT-BACKLOG-2026-08-22.md` — the queue that survived the rollout setup.

## Log

Append dated entries below as work happens. Newest last.

### 2026-08-22 — worktree created, nothing built yet

Set up by `claude-f`. The branch was advanced to `main` twice while it held no work of yours. Once
you have commits here, that stops: `claude-f` will check your `git status` and tell you before
advancing anything.

### 2026-08-22 — Task D accepted

- Armed the one `codex-f` watcher on the pair channel; the discriminating process query found one
  three-process watcher tree and no pre-existing match.
- Re-ran the full precommit gate from this worktree through full-path Git Bash and captured exit 0
  with all nine gates passing (240 Python tests, 8 Rust tests, self-scan 13 active / 52 filtered).
- Appended the required acknowledgement to the canonical pair channel. The append integrity check
  passed and an exact fixed-string check found one copy in the main checkout. The channel change is
  intentionally not committed here because this branch never commits to `main`.
- Read the standing goal, `AGENTS.md`, canonical `CLAUDE.md`, comms topology, backlog, current
  changelog, latest audit, and current 20-commit history before touching the Task D test.
- Next: capture Task D acceptance A against the existing guard, implement the test-only discovery
  fix, mutation-prove A and B, then run the clean true case and full gate.
- Blocker found before that next step: live refs contradict the launch claim that this branch is one
  commit above current `main`. `codex-f/build` is `6ef8106`, `main` is `d8a77b3`, and their merge
  base is `5bcd9c7`; this branch lacks main's Task D channel commit and narrowed self-scan exclusion.
  The local gate therefore passed with the superseded broad `.codex/` exclusion. Posted an exact
  branch-base question to the pair channel and am waiting for `claude-f` to direct reconciliation.
  Do not edit the Task D test until that answer arrives.

### 2026-08-22 — branch reconciled under explicit direction

- `claude-f` directed: commit this handoff, merge `main` (not rebase), assert the narrowed
  worktree exclusion, rerun the gate, then execute Task D unchanged.
- Committed the handoff alone as `acaeea0`; merged `main` into `codex-f/build` as `a56423c`.
- The required exclusion literal `^\.codex/PRAETOR-codex/` occurs exactly once in
  `tests/precommit.sh`. It is at line 160, not the assigned line 149; reported the stale line number.
- The machine-wide portable precommit check could not recognize this valid linked worktree and
  returned exit 2 with `CANNOT RUN: not inside a git repository`. Reported it rather than masking it.
- The reconciliation status post appended successfully but returned exit 3 because a peer post was
  already uncommitted. Per the appender contract, do not append it again and do not commit `main`.
- Post-merge baseline: `bash tests/precommit.sh` completed all nine gates and returned
  `POST_MERGE_PRECOMMIT_EXIT=0` (240 Python, 8 Rust, self-scan 13/52, 81 shipping files).
- Task D acceptance A control: with a one-line `scripts/engine_probe.py`, the old guard returned
  `A_EXISTING_GUARD_EXIT=0` and `1 passed`, reproducing the blind spot.
- Implemented AST-based discovery across every `scripts/*.py`, with a floor, the five required
  engine-entry files asserted as a subset, and only `scripts/core.py:152` allowed.
- Acceptance A red proof: the fixed guard returned test exit 1 and named
  `scripts/engine_probe.py:1`; the exact-name assertion passed. The probe has been deleted.
- Acceptance B allowance mutation: a temporary second call inside `scripts/core.py` made the guard
  return test exit 1 and name `scripts/core.py:164`; the exact file-name assertion passed. The
  mutation was removed with `git diff scripts/core.py` empty.
- Acceptance C clean tree: the named guard returned `C_CLEAN_GUARD_EXIT=0` and `1 passed` after both
  mutations were removed. The sanctioned call at `core.py:152` and its docstring mention remain.
- The complete targeted module returned `TARGET_MODULE_EXIT=0` with `3 passed`.
- Acceptance D: the final `bash tests/precommit.sh` run returned `TASK_D_PRECOMMIT_EXIT=0`; all nine
  gates passed (240 Python, 8 Rust, self-scan 13/52, public-hygiene sweep 81 files).
- `scripts/core.py` has no content diff after mutation restoration; a refresh cleared its
  timestamp-only modified status. Only this handoff and the Task D test remain intentionally dirty.
