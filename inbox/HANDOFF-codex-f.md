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

### 2026-08-22 — Task D independent audit follow-up

- `claude-f` independently accepted the AST walk, docstring/comment behavior, required-set
  anti-vacuity check, and exact `(file, line)` allowance in commit `4dfae00`.
- Audit measured two live evasions without moving the tree: `import subprocess as sp; sp.run(...)`
  and `from subprocess import run; run(...)` are not caught by the committed predicate.
- Assigned follow-up: resolve per-file `ast.Import` and `ast.ImportFrom` bindings for the module and
  `run` function; disclose any remaining unreachable spellings; prove both aliases red, prove
  comment/docstring mentions remain green, prove the clean tree green, then run the full gate.
- The audit also noted the line-number allowance can rot and top-level `glob("*.py")` is not
  recursive. Those were observations, not part of the numbered follow-up. The allowance must not
  be widened; do not expand scope without a further instruction.
- Red-first reproduction against `4dfae00`: module-alias and from-import probes each returned exit
  0 with `1 passed` (`FOLLOWUP_OLD_MODULE_ALIAS_EXIT=0`, `FOLLOWUP_OLD_FROM_IMPORT_EXIT=0`).
- Added per-file import binding collection for direct module imports, module aliases, direct
  `run` imports, function aliases, and star imports. Call matching uses those bound names.
- Fixed-guard mutation outputs returned exit 1 and named the exact probe call for all four tested
  spellings: `sp.run`, direct imported `run`, imported `runner`, and star-imported `run`.
- A probe with both import bindings but only docstring/comment call text returned
  `FOLLOWUP_DOCSTRING_COMMENT_EXIT=0` and `1 passed`.
- The safety claim in the test docstring now scopes the mechanism to covered static spellings and
  discloses dynamic imports, `getattr`, assignment aliases, top-level-only discovery, and the
  fail-closed positional allowance. Each spelling it positively claims was mutation-proven.
- Probe deleted; the clean named guard returned `FOLLOWUP_CLEAN_GUARD_EXIT=0` and `1 passed`.
- Complete targeted module: `FOLLOWUP_TARGET_MODULE_EXIT=0`, `3 passed`.
- Exact follow-up tree gate: `FOLLOWUP_FINAL_TREE_PRECOMMIT_EXIT=0`, all nine gates
  (240 Python, 8 Rust, self-scan 13/52, public-hygiene sweep 81 shipping files).

### 2026-08-22 — Task D dangerous-function surface follow-up

- `claude-f` independently re-ran and accepted every claim in `3388db6`, including module aliases,
  direct/from-import aliases, star imports, relative-import exclusion, and inert docstring behavior.
- The audit found the disclosure still incomplete at the function-set level: the guard does not
  catch `subprocess.check_output`, `subprocess.Popen`, `subprocess.call`,
  `subprocess.check_call`, `os.system`, or `os.popen`. No current `scripts/` file uses them, so the
  gap is latent rather than live.
- Assigned follow-up: cover the four additional `subprocess` functions; either cover or disclose
  the two `os` functions; state the covered function surface; mutation-prove each, inert text, clean
  tree, and the full gate.
- Builder choice: cover both `os` functions in the fail-safe direction rather than leave an
  alternate process-launch surface out of the structural guard. Preserve the exact core allowance.
- Red-first combined alias/from-import probe called all six new primitives and the committed guard
  returned `SURFACE_OLD_GUARD_EXIT=0` with `1 passed`.
- Generalized the binding table to the explicit function surface: `subprocess.run`,
  `check_output`, `Popen`, `call`, `check_call`, plus `os.system` and `os.popen`. The docstring names
  that surface and retains the previously audited dynamic/discovery limitations.
- The fixed guard returned test exit 1 and reported all six exact probe lines; the wrapper asserted
  `SURFACE_OFFENDER_ASSERT_COUNT=6` and `SURFACE_OFFENDER_ASSERT=PASS`.
- A probe with the same imports but only docstring/comment names returned
  `SURFACE_DOCSTRING_COMMENT_EXIT=0` and `1 passed`; the probe was deleted.
- Re-proved the allowance boundary with a second `subprocess.check_output` in `core.py`: test exit 1
  named `scripts/core.py:164`, then the mutation was removed and `git diff scripts/core.py` returned
  no content difference. Clean guard returned `SURFACE_POST_ALLOWANCE_CLEAN_EXIT=0`.
- Safety-claim check: fixed-string probes found every named function in the guarded set and found
  explicit UTF-8, replacement-error, timeout, and cwd handling in the real `core.run_tool` body.
- Complete targeted module returned `SURFACE_TARGET_MODULE_EXIT=0` with `3 passed`.
- Pre-final-handoff repository gate returned `SURFACE_PRECOMMIT_EXIT=0`, all nine gates
  (240 Python, 8 Rust, self-scan 13/52, public-hygiene sweep 81 shipping files).
