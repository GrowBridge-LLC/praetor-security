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
3. `C:\projects\PRAETOR\.local\PAIR-CHANNEL.md` — tail it. That is where work arrives.
   Absolute on purpose: it is ignored by git and absent from this worktree.
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

### 2026-08-22 — Task D structural inversion follow-up

- `claude-f` independently verified `35dc426`: requested subprocess/os catches, alias behavior,
  inert docstrings, and the real-tree guard all passed.
- Audit found the enumeration class persists: `subprocess.getoutput`, `getstatusoutput`, and the
  `os` exec/spawn families are not caught. None is used by current `scripts/`, so the gap is latent.
- Assigned terminating shape: deny every statically resolved call through the `subprocess` module
  or a name imported from it unless exactly allowed; keep `os` as an enumeration matching exact
  `system`/`popen` plus `exec`, `spawn`, and `posix_spawn` families by prefix.
- Acceptance requires old catches plus the two unenumerated subprocess functions; dangerous and
  harmless `os` directions (`spawnv`/`execv`/`posix_spawn` versus `path.join`/`getcwd`); inert text;
  clean tree; full gate; and an explicit asymmetry/remaining-limits disclosure.
- Red-first probe against `35dc426`: aliased `subprocess.getoutput` and from-imported
  `getstatusoutput` returned `INVERT_OLD_GUARD_EXIT=0` with `1 passed`.
- Replaced the subprocess function-name set with deny-by-default module/from-import binding logic;
  no `getoutput` or `getstatusoutput` name was added. The fixed guard returned exit 1 and reported
  both exact lines (`INVERT_SUBPROCESS_ASSERT_COUNT=2`, assertion pass).
- Regression probe rechecked all seven earlier process functions through aliases/imports: fixed
  guard exit 1, seven exact offenders, `INVERT_REGRESSION_ASSERT=PASS`.
- `os.spawnv`, from-imported/aliased `execv`, and `os.posix_spawn` produced three exact offenders;
  `os.path.join` plus `os.getcwd` returned `INVERT_OS_HARMLESS_EXIT=0` and `1 passed`.
- A star-import probe proved the disclosed fail-safe: an otherwise ordinary bare `print` call was
  reported because its binding could not be proved. Docstring/comment-only names stayed green.
- Probe deleted; clean named guard returned `INVERT_CLEAN_GUARD_EXIT=0`.
- Re-proved the exact allowance after inversion: a second `subprocess.getoutput` in `core.py` was
  reported at line 164, then removed; core has no content diff and the clean guard passed again.
- Safety-claim fixed-string checks found the deny-by-default module/from-import branches, star-import
  branch, `os` exact/prefix predicate, and both dangerous/harmless mutation directions.
- Complete targeted module returned `INVERT_TARGET_MODULE_EXIT=0` with `3 passed`.
- Pre-final-handoff repository gate returned `INVERT_PRECOMMIT_EXIT=0`, all nine gates
  (240 Python, 8 Rust, self-scan 13/52, public-hygiene sweep 81 shipping files).

### 2026-08-22 — Task D clearance and Task H assignment

- `claude-f` independently verified the structural inversion and cleared Task D after four audit
  rounds. The requested final disclosure is that deny-by-default also catches non-executing uses
  such as constructing a `subprocess` exception; those require an exact, reasoned allowance rather
  than an implicit predicate carve-out.
- Rebased the clean, unpushed builder branch onto current `main` at `2f881a6`; the Task D tip is now
  `deb839d` with unchanged content from pre-rebase `da915b7`.
- Task H assignment: port `scripts/engine_secrets.py` into `rust/praetor-core/src/`, extend the
  existing blocking differential runner rather than replacing it, assemble credential-shaped
  fixtures from fragments, include the known wide-scope path shapes, prove deliberate divergence
  in both Python and Rust directions, re-run the pinned self-scan, then run the full gate by exit
  code.
- Re-read `CLAUDE.md` detector-test discipline: mutate real implementations in both directions,
  keep fixtures from becoming detector noise, never exempt `tests/`, and re-run the self-scan.
- Re-derived the Rust dependency decision from ADR-001 Amendment 1: the `regex` crate is explicitly
  approved for the regex-driven engine port because a bespoke matcher would increase security risk;
  the manifest change is intended to land with the first code that uses it.
- Found and reported a binding conflict before committing: the initial Task H assignment named the
  secrets detector, while ADR-001 condition 1 requires the aisec detector to port first. `claude-f`
  independently checked the ADR, ruled the assignment wrong, corrected the backlog, and restated Task
  H as the aisec port. The ADR was not amended.
- Preserved the uncommitted early secrets prototype exactly as directed on local-only branch
  `codex-f/secrets-port-parked` at `2b27857` with commit subject
  `wip: park secrets port ahead of ADR order`. The commit message states that it is not Task H
  completion. Nothing was pushed.
- Preservation evidence: the portable precommit skill gate returned exit 2 because its `.git`
  directory assumption cannot run in a linked worktree; the repository-prescribed
  `bash tests/precommit.sh` returned exit 0 with all nine gates before the parked commit. After
  switching back, `git show --no-patch codex-f/secrets-port-parked` resolves the parked commit and
  `rust/praetor-core/src/secrets.rs` is absent from `codex-f/build`; only this handoff and the Task D
  disclosure remain uncommitted here.

### 2026-08-22 — Task H Amendment 2 ruling and unpark

- Operator ruling is persisted on `main` in ADR-001 Amendment 2: `base64` is authorised for
  `praetor-core`; the port order changes to secrets first; aisec is deferred until a separate JSON
  dependency decision. The base64 decision is recorded as marginal and does not create precedent
  for another crate.
- Re-armed the required channel watcher after it exited on the ruling. Rebasing the clean builder
  branch onto current `main` completed without conflict, then local-only parked commit `2b27857` was
  applied to `codex-f/build` as `7ab13ab`.
- Initial re-derived state after unpark: the existing differential runner returned exit 0 with both
  line and secrets contracts equal; `cargo test --manifest-path rust/Cargo.toml -p praetor-core`
  returned exit 0 with 11 Rust tests and no ignored tests. This is prototype evidence, not Task H
  acceptance: the code still contains a bespoke base64 decoder, lacks the newly authorised pinned
  crate, and carries stale parked/no-detector status prose.
- Required next work: replace the bespoke decoder with pinned `base64`, enumerate its resolved
  dependency/build-script tree, re-read every ported behavior against the Python reference, update
  all current status surfaces, mutation-prove direct Python/Rust divergence, run the pinned self-scan
  and full repository gate, then commit and hand off for independent audit. Nothing pushed.

### 2026-08-22 — Task H implementation handoff

**TARGET:** independently audit commits `7ab13ab` and `d5943fb` on `codex-f/build`. The first restores
the parked detector, fragmented corpus, and existing-runner extension; the second replaces the
prototype decoder with the authorised dependency, strengthens anti-vacuity, and corrects current
status surfaces.

**SCOPE:** Rust parity for `scripts/engine_secrets.py` inside `praetor-core`, plus its differential
contract. The provider and special-rule scan logic, in-memory fragment assembly, and three-way
Python/Rust/committed-contract comparison survived prototype review. Changed: handwritten base64
decoding became exact `base64` 0.23.1 with defaults disabled and only `std` enabled; the runner now
derives the Python rule surface and requires three named negative paths. CLI engine wiring, aisec,
and any further dependency are explicitly out of scope.

**ACCEPTANCE:** at the `d5943fb` task tree, `py -3.14 tests/differential/run_differential.py` returned
0 for 23 line cases and 25 fragmented secrets cases. Mutating the Python AWS rule identity returned
runner exit 1 with `Python and Rust secrets engines disagree WITH EACH OTHER`; restoring it and
mutating the Rust identity returned the same exit and marker in the opposite direction. Both sources
were restored and the runner returned 0 again. `cargo test -p praetor-core` returned 0 with 11 passed
and none ignored; focused Python tests returned 0 with 28 passed. The exact-source formatter checks
returned 0. Workspace-wide formatter check remains red on pre-existing `sca.rs`, `text.rs`, and
generated Unicode-table formatting; those unrelated files were not rewritten. `rg` found the
`pub fn scan` positive control and returned 1 for forbidden process/filesystem surfaces in
`secrets.rs`. `cargo tree` resolved base64 with only `std` and `alloc`, no `simd-unsafe`, no
transitives, and no build script. `bash tests/precommit.sh` returned 0 with all nine gates, including
the stamped 13 active / 52 filtered self-scan. Failure is any independent Python/Rust identity
divergence, a changed self-scan pin, a process/filesystem capability in the detector, or a non-zero
repository gate.

**PERSISTENCE:** implementation and status changes are committed at `d5943fb` on
`codex-f/build`; this handoff is the sole follow-up change prepared for an explicit-path commit.
Any reader seeing this paragraph in Git has the persistent handoff; if it exists only in a working
tree, persistence is not yet met. Nothing pushed. The portable skill gate returned exit 2 with
`CANNOT RUN: not inside a git repository` because it rejects this managed linked worktree's `.git`
file; the prescribed repository gate above is the authorised worktree path. Independent audit
remains required before landing.

### 2026-08-22 — Task H independently CLEAR; remote landing still pending

- `claude-f` audited `7ab13ab`, `d5943fb`, and `3e1ea71` from BLOCK and issued **CLEAR**. The audit
  independently reproduced baseline differential exit 0, an armed Rust-rule divergence that emitted
  both the contract failure and `Python and Rust secrets engines disagree WITH EACH OTHER` at exit 1,
  and restored exit 0. It separately armed the rule-surface guard by proving the Python provider
  population moved before trusting its exit 1, then restored the provider population and exit 0.
- Dependency/invariant audit also cleared: exact base64 0.23.1 with defaults disabled and `std` only,
  no process-spawn surface in the detector, and 11 Rust tests passed with none ignored. This supersedes
  the preceding section's statement that independent audit remains required; the earlier paragraph is
  retained as the state at its commit boundary.
- Landing state is split and must not be collapsed into “pushed.” Local main is `0d24b27` and contains
  merge commit `Merge the Rust secrets port from codex-f/build`. The live command
  `git -C C:\projects\PRAETOR ls-remote origin refs/heads/main` still returned `fa8b56e` for the remote
  branch after the authority stated an intent to push. The same mismatch was posted to the pair channel.
- The builder must not perform that remote write. Next action is to keep exactly one watcher armed and
  wait for `claude-f` to confirm the authority-owned push or assign the next build task. The builder
  worktree was clean before this handoff-only update; no code mutation is pending and nothing was pushed.

### 2026-08-22 — Task H delivered; close state and channel migration

- Re-derived after the close artifact: local `main` and the live remote both resolve to `83a45e9`, and
  `git -C C:\projects\PRAETOR status --short --branch` reports `main...origin/main` with no ahead/behind
  delta. Task H is delivered; this builder branch remains clean and is not being rebased or pushed.
- Pair traffic moved from tracked `inbox/PAIR-CHANNEL.md` to the ignored absolute channel
  `C:\projects\PRAETOR\.local\PAIR-CHANNEL.md`. The tracked file is now a pointer explaining the
  security rationale. Current main `CLAUDE.md` names the absolute path and requires the shared appender;
  the old tracked-path watcher must not be reused.
- Exactly one watcher is now armed against `/c/projects/PRAETOR/.local/PAIR-CHANNEL.md` with identity
  `codex-f`; its initial output reported 1463 lines and the required session identity. No watcher is
  armed against the obsolete tracked pointer.
- The close channel says the next work is a properly assigned, independently audited proposal for
  backup-recovery Cluster A (NUL handling and symlink refusal). Do not start it from the old 13 REAL /
  4 STALE / 0 UNCLEAR classification alone. Do not start the separately described supply-chain scan;
  the close instruction says it requires an orchestrator because fetching package artifacts is itself
  unsafe for this scanner's never-execute invariant. Await a fresh acceptance-bearing assignment.

### 2026-08-24 — Cluster A implementation delivered for independent audit

**TARGET:** `scripts/core.py`, `scripts/praetor.py`, `scripts/report.py`, and
`tests/test_invariant_never_executes_target.py`, committed as `0e3083f` on
`codex-f/build` after merging `origin/main` at `4936b01`.

**SCOPE:** retain NUL-bearing source-named text as an explicit observation through
`ScanFile.contains_nul`, metadata, and text reporting; refuse symlinked direct targets
and symlinked directory entries before any size/read operation; add behavioral coverage.
Out of scope: supply-chain scanning, main, push, and wholesale backup merge.

**ACCEPTANCE:** each symlink boundary was independently mutated and the named test
`test_file_selection_never_follows_a_symlinked_file` went RED with exit 1, then was
restored. Ordinary files and nested ordinary files remain selected. A NUL-bearing
source is retained with `contains_nul=True` and reaches `report.render_text`, covered
by the targeted test suite (`9 passed`). `bash tests/precommit.sh` returned exit 0:
263 Python tests, 11 Rust tests, self-scan 13 active / 52 filtered, all gates passed.
The portable auxiliary fast gate returned exit 0. Failure is any symlink traversal, lost NUL
observation/report, targeted regression, or non-zero repository gate.

**PERSISTENCE:** this handoff update and implementation are committed on
`codex-f/build`; nothing was pushed. Claude must independently audit before landing.

### 2026-08-25 — pre-close state

The operator requested a pre-close audit and asked that the counterpart be informed. This is a
closeout preparation point, not a claim that the long-running communication goal is complete.

**LIVE STATE (re-derived):** worktree is `C:\projects\PRAETOR\.codex\PRAETOR-codex`; branch is
`codex-f/build`; `HEAD` is `1ccf9d10dcd1f4000561b85d9c53feb2c67a0578` (`Add live nosemgrep outcome
coverage`). `git status --short` produced no entries. `git rev-list --left-right --count
origin/main...HEAD` returned `1 43` (local branch is one commit ahead and 43 commits behind the
remote main tip); nothing was pushed.

**CURRENT ASSIGNMENT:** F22 remains the bounded assignment recorded in the live lane; no new
counterpart assignment was present in the latest own-lane read. The durable Zulip inbox continues
to report a limit-hit floor; the latest cycle reported 190 unread in 38 conversations, with
`INBOX_RC=0`. Own-lane read returned `OWN_LANE_RC=0`; heartbeat `who --json` returned `WHO_RC=0`,
`fresh_seconds=300`, slug `codex-f`. No messages were marked read in that cycle.

**VERIFICATION NOTE:** Two prescribed `bash tests/precommit.sh` attempts were started during this
closeout but produced only the initial banner within the bounded tool window and did not yield a
usable exit code. They were explicitly terminated, and a process sweep found no surviving
precommit process attributable to those attempts. Therefore do not claim a fresh precommit pass
from this closeout; the last recorded successful repository gate remains the earlier F22 evidence
in this file. The portable skill gate's linked-worktree `.git` limitation remains known and is not
a reason to reinterpret the repository gate.

**MUST NOT LOSE:** do not push, merge, deploy, cross repositories, take floor action, or manage
watchers. The active user override prohibits watcher creation, inspection, or alteration. Keep
the ignored absolute pair channel at `C:\projects\PRAETOR\.local\PAIR-CHANNEL.md`; do not revive the
obsolete tracked channel. The next session must re-read the standing goal, `AGENTS.md`,
`CLAUDE.md`, this handoff, and the live pair channel before acting.

**OPEN:** counterpart acknowledgement of this closeout notice is still required; the persistent
communication goal remains active until the operator ends it. No independent subagent audit was
dispatched in this closeout because the user asked to inform the counterpart and the current
watcher prohibition and no-push boundary remain controlling.

### 2026-08-25 — final pre-close gate attempt

Ran the prescribed bounded command with a 300-second allowance, capturing the gate output to
`C:\Users\Admin\AppData\Local\Temp\codex-f-preclose-gate-final.txt` and capturing the exit code
immediately in the Git Bash command. The captured output reached only:

```text
== PRAETOR pre-commit gate ==
  OK    python suite (322 passed, 0 skipped)
  OK    rust suite (11 passed, 0 ignored)
  OK    unicode tables current
  OK    self-scan unchanged (22 active / 56 filtered)
  OK    public-hygiene sweep (107 shipping files, tracked+untracked)
```

No `PRECOMMIT_RC` marker was produced, so the final gate result is `CANNOT-DERIVE`; this is not a
green claim. The current process sweep found no surviving precommit process attributable to the
attempt. Git state remains `1ccf9d1`, branch `codex-f/build`, `git status --short` shows only this
handoff update, and `git rev-list --left-right --count origin/main...HEAD` remains `1 43`.

The requested task archive operation is not available through the currently exposed Codex tools.
The handoff is therefore ready for a fresh session, but task archival itself remains an external UI
operation and must not be claimed as completed here.

### 2026-08-28 — Mike-directed reorientation correction (supersedes only stale current-state prose above)

**METHOD / READ SET:** Re-read the current task's five most recent transcript entries through the
Codex task reader, the PRAETOR memory registry and its two available PRAETOR rollout summaries, this
handoff, the standing goal, and the live ignored channel. The durable PRAETOR transcript summaries
available locally cover 2026-08-22 and 2026-08-27; no additional historical PRAETOR rollout summaries
were present, so claims below are derived from live Git and the current channel rather than invented
from absent transcript content.

**LIVE BRANCH / DIRTY OWNERSHIP:** `codex-f/build` is at
`a62a97715a42a595c022351e7ded5e5017bf0805`; local `main` is
`681f844d95374771c8d0756193029a7381ed6626`; `origin/main` is
`b80f7f8e75c87758e1630eabfa424f19ee74e2e9`; merge base is
`513880de269c05520d01970208c7f2d8c1989336`. Against the current tracking ref, the builder branch
is 45 commits ahead and 2 behind (`origin/main..HEAD` / `HEAD..origin/main`). At reorientation start
`git status --porcelain=v1` named only this handoff as modified; its pre-existing diff was 60 added
lines. Preserve that work and this append; do not stage broadly, clean, reset, rebase, merge, or push.

**AUDIT / CANDIDATE LEDGER:** `d8ffacfb48273ef0d82b5fe140e44f949f626871` (F29/F33) has a detached
`claude-f` ACCEPT, including independent red-source mutations. `a62a977` (F34) remains BLOCKED:
the OSV regex translator silently fails the real downstream separator-class pattern
`(^|[\\/])\\.codex[\\/]`; F34 needs a named red-first control for that pattern as well as the existing
PRAETOR-relative form. F30's exact-content identity predicate is accepted for build only if hashes are
derived from actual shipped detector files at runtime/build time and the implementation explicitly starts
with `engine_secrets.py` rather than claiming the whole detector class is solved. F31/F32 remain
report-visible, gate-only category work, not ordinary suppression.

The range remains branch-wide BLOCK, not mergeable clearance: A2 (KB rebuild self-dependency), A4
(Rust Azure-padding parity), A5 (homoglyph cap), and A7 (LIMITS.md contradicts `TEXT_EXTS`) were
re-verified at this tip. A3 is also OPEN: the correct read-only command
`git merge-tree --trivial-merge $(git merge-base main codex-f/build) main codex-f/build` produced
`+<<<<<<< .our` / `+>>>>>>> .their` for `references/kb/records.jsonl`. The earlier unflagged
`git merge-tree` invocation was unsupported by this Git version and is not evidence of a clean merge.

**NEXT TARGET / OWNER / ACCEPTANCE:** `claude-f` assigns A2/A4/A5/A7 ahead of F30/F31/F32 and suggests
A7 first (correct the public extension-coverage statement in `references/LIMITS.md` to match current
`core.TEXT_EXTS`). `codex-f` is builder; `claude-f` is detached auditor/integrator. The current message
does not state a separate A7 red-first test, exact persistence commit, or explicit failure predicate;
therefore an A7 implementation is not yet started. Obtain that acceptance-bearing detail before mutation.
A2 requires a design proposal before building; A3 has no assigned resolution mechanism. Any future
acceptance must include a direct exit-status gate and fail if the stated code/doc discrepancy, parity
gap, cap bypass, KB self-dependency, F34 real-regex miss, or unresolved merge conflict remains.

**NO-GO:** Do not claim a fresh gate from historical output; do not execute, import, install, or build a
scanned target; do not push, merge, deploy, run live OSV against an unbounded target, resolve A3, alter
baseline/rulings to green a result, or broaden into F30/F31/F32 until their assigned slice is accepted.
Green builder checks are not detached audit or shipment clearance.

### 2026-08-28 — official Claude-F hold-status receipt

Reorientation status was sent through the official Zulip wrapper as `codex-f` to the known `claude-f`
seat, topic `PRAETOR reorientation hold`. Wrapper receipt: `sent id=5158`; the server confirmed both
direct-message recipients (`claude-f-bot@zulip.localdomain` and `codex-f-bot@zulip.localdomain`). The
post reported only the existing owner, A7 contract gap, A2/A3/A4/A5/A7 and F34 holds, and no-go scope.
It did not authorize or perform a source, staging, commit, merge, push, deployment, or lifecycle action.

### 2026-08-28 — fresh held-range packet for Factory coordination

**BUILDER TIP / PERSISTENCE:** `codex-f/build` remains at
`a62a97715a42a595c022351e7ded5e5017bf0805`; the only dirty path is this durable builder handoff.
`origin/main...HEAD` remains `2 45`. This packet is status coordination only and is persisted here,
uncommitted, to preserve all existing dirty work.

**VERDICTS / PREREQUISITES:** F29/F33 are detached-ACCEPT at
`d8ffacfb48273ef0d82b5fe140e44f949f626871`. F34 is BLOCK at `a62a977`: the actual downstream
`(^|[\\/])\\.codex[\\/]` exclude pattern is translated into a nonmatching expression. F30's
exact-content predicate is conditionally accepted only if hashes are derived from shipped files and
the initial scope is explicitly `engine_secrets.py`; F31/F32 remain report-visible, gate-only work.
The branch-wide independent audit is still BLOCK: A2/A3/A4/A5/A7 remain open, and A3's read-only
`git merge-tree --trivial-merge $(git merge-base main codex-f/build) main codex-f/build` emits
`+<<<<<<< .our` and `+>>>>>>> .their` for `references/kb/records.jsonl`.

**NEXT SLICE / ACCEPTANCE:** Preserve the agreed A2/A4/A5/A7 before F30/F31/F32 order. A7 is the
first suggested bounded slice (`references/LIMITS.md` must agree with `core.TEXT_EXTS`) but is NOT
assigned for mutation: an exact red-first acceptance command, persistence commit target, and explicit
failure predicate are CANNOT-DERIVE from the current Claude-F assignment. Until supplied, attempted
acceptance fails because the four-field builder contract is incomplete. Any supplied check must fail
if the stated LIMITS/TEXT_EXTS discrepancy remains.

**AUDIT ROUTE / NO-GO:** `claude-f` is the required detached BLOCK-first auditor and integration route;
`codex-f` does not send work sideways outside its designated counterpart route. I am available to independently audit a future,
separately delivered exact-hash Hermes or rotation candidate only after its builder supplies a bounded
artifact, scope/exclusions, red-first acceptance command and failure condition, and persistence
revision. No such audit has begun, and no code, credential, host, service, lifecycle, merge, push, or
deployment action is authorized or performed.

### 2026-08-28 — overnight single-slice receipt: A7 contract pending

**READ SET / STATE LIMIT:** Re-read the five newest completed PRAETOR task turns, the PRAETOR memory
registry, this handoff, the standing goal, live ignored Claude-F lane record, and live worktree state.
The official Zulip wrapper reported `199 unread for codex-f, in 57 conversation(s)` but also reported
its fetch cap of 200; that number is a floor and is NOT an inbox-clearance claim. The only relevant
current assignment source remains the Claude-F lane record below; no new acceptance-bearing A7 contract
was derived from a capped inbox listing.

**ONE ORDERED NEXT SLICE — A7 ONLY:** Correct the false extension-coverage sentence in
`references/LIMITS.md` so it agrees with the current `scripts/core.py` `TEXT_EXTS` treatment of
`.csv`, `.log`, `.jsonl`, `.ndjson`, `.har`, and `.out`. `codex-f` is the builder only after Claude-F
supplies the bounded contract; `claude-f` owns contract issuance, detached BLOCK-first audit, and
integration.

**EXCLUSIONS:** No A2, A3, A4, A5, F34, F30, F31, or F32 work; no source outside the named A7 document
slice; no baseline/ruling edits, test or CI alteration, staging, commit, merge, push, deploy, credential,
host/service, or lifecycle action. F29/F33's detached ACCEPT and F34's separate BLOCK stay distinct.

**RED-FIRST ACCEPTANCE / FAILURE:** The required exact A7 red-first acceptance command is
`CANNOT-DERIVE`: Claude-F has not provided a command, precise test artifact, or explicit exit-status
predicate. The acceptance contract must fail before correction while the LIMITS sentence says those six
extensions are skipped despite their membership in `TEXT_EXTS`, and pass only after the named mismatch is
removed without widening scope. Until an exact command and expected failure are supplied, any builder
claim or mutation fails this receipt's contract.

**AUDIT / PERSISTENCE:** A future A7 result must be persisted as an exact named revision on
`codex-f/build`, with the command, exit status, and red-first evidence recorded in this handoff; then
Claude-F must independently audit that exact revision from BLOCK before any acceptance or integration
claim. No such revision or verdict exists.

**CURRENT BLOCKERS:** missing four-field A7 contract; branch-wide A2/A3/A4/A5 hold; A3 conflict in
`references/kb/records.jsonl`; and F34's unresolved real-pattern translator defect. Builder tip remains
`a62a97715a42a595c022351e7ded5e5017bf0805`; this handoff remains the only dirty path.

### 2026-08-28 — durable reorientation refresh: A7 remains contract-pending

**EVIDENCE READ:** Reviewed the five newest completed PRAETOR task turns, PRAETOR memory records, this
handoff, the standing goal, the live Claude-F pair record, current Git state, and official Zulip inbox.
The wrapper again reports `199 unread for codex-f, in 57 conversation(s)` and its 200-message fetch cap;
the count is a floor, so neither an empty inbox nor a new contract can be inferred from it.

**EXACT TARGET / ALLOWED SCOPE:** The sole ordered next slice is A7: correct only the false
`references/LIMITS.md` extension-coverage claim so it matches `scripts/core.py` `TEXT_EXTS` for `.csv`,
`.log`, `.jsonl`, `.ndjson`, `.har`, and `.out`. No mutation is currently allowed because the necessary
acceptance-bearing contract is absent.

**OWNER / DEPENDENCIES:** `codex-f` is builder only after a contract; `claude-f` owns the four-field
assignment, detached BLOCK-first audit, and integration. Dependencies are the exact A7 red-first command,
expected failure, allowed file set, and persistence revision. They are all CANNOT_DERIVE except the
already-named A7 document target.

**ACCEPTANCE / EXPECTED FAILURE:** Exact command: CANNOT_DERIVE. Required failure: before correction,
the named command must fail because LIMITS calls those `TEXT_EXTS` members skipped; it can pass only when
that mismatch is removed without changing the code allowlist or expanding scope. No builder may treat this
descriptive failure condition as an authorized substitute for the missing command.

**EXCLUSIONS:** A2/A3/A4/A5, F34, F30/F31/F32, fan/Hermes/rotation or other externally supplied candidate work,
all source other than the named A7 document, baselines/rulings, CI/test changes, staging, commits, merge,
push, deployment, credentials, live/host/network actions, and lifecycle changes. F29/F33 ACCEPT and F34
BLOCK remain separate verdicts.

**DIRTY / PERSISTENCE:** `codex-f/build` is at `a62a97715a42a595c022351e7ded5e5017bf0805`, with local
`main` `681f844d95374771c8d0756193029a7381ed6626` and `origin/main`
`b80f7f8e75c87758e1630eabfa424f19ee74e2e9`; `origin/main...HEAD` is `2 45`. `git status --porcelain=v1`
shows only this handoff modified (unstaged); no staged or untracked path was reported. This record itself
is the persistence location and remains uncommitted to preserve existing dirty work. A future result must
be a named builder revision plus command/exits/red-first evidence here, followed by Claude-F's detached
audit of that exact revision.

**BLOCKERS / DECISION OWNERS:** Claude-F must decide/provide the A7 contract. Separate blockers remain
A2 (KB self-dependency), A3 (read-only merge-tree still emits `+<<<<<<< .our` / `+>>>>>>> .their` for
`references/kb/records.jsonl`), A4 (Rust Azure-padding parity), A5 (homoglyph cap), and F34 (real
separator-class pattern translation). No audit verdict, live/account/deploy, or cross-lane authority is
derived from this reorientation request.

### 2026-08-29 — Light-tier pre-close: CPU shutdown-ready

**TIER / METHOD:** Light tier under `pre-close-audit`: this session only re-derived and persisted
PRAETOR held-range/coordinator status. It made no source, test, CI, configuration, service, lifecycle,
or commit change. Therefore no independent audit was dispatched and no memory/CHANGELOG update is owed.

**LOCAL SURVIVAL / PROFILE CONTINUITY:** Local Windows boot time was measured as
`2026-08-27 00:15:38 -05:00` (about 60.23 hours uptime). PRAETOR's current scope has no remote machine
or service dependency, so no remote boot probe is applicable. `C:\Users\Admin\.Codex-b` was absent;
profile-store sharing is CANNOT_DERIVE rather than assumed. The durable worktree handoff remains the
resume artifact; it is not committed and should be treated as local-machine persistence only until an
authorized owner decides otherwise.

**REPO / DIRTY OWNERSHIP:** Worktree
`C:\projects\PRAETOR\.codex\PRAETOR-codex`, branch `codex-f/build`, is at
`a62a97715a42a595c022351e7ded5e5017bf0805`; local `main` is
`681f844d95374771c8d0756193029a7381ed6626`; `origin/main` is
`b80f7f8e75c87758e1630eabfa424f19ee74e2e9`; remote is
the configured SSH-alias remote (derive with `git remote get-url origin`). `git status --porcelain=v1` reports
only this handoff modified and unstaged; cached paths are empty. `git diff --check` passes. No fresh test
or precommit result exists this session, so current gate status is CANNOT_DERIVE—not green.

**DONE THIS SESSION:** Read the newest completed PRAETOR task turns, memory/handoff/lane status, live
Git state, and official Zulip inbox; retained the A7-only contract-pending order; persisted its owner,
scope, exclusions, evidence gap, and no-go rules. Declined the external fan-candidate audit because the
standing PRAETOR order and Claude-F-only routing do not admit cross-lane work. No message, runner,
watcher, service, or detached audit remains owned by this session.

**OPEN / DELIBERATE HOLDS:** A7 is first but cannot start until Claude-F supplies the exact red-first
acceptance command, expected failure, allowed files, and persistence revision. A2/A3/A4/A5 remain held;
A3's read-only merge probe still contains markers for `references/kb/records.jsonl`; F34 remains BLOCK
on the real separator-class pattern; F30/F31/F32 remain later and distinct. Zulip returned a 200-message
cap with 199 unread in 57 conversations, so its count is a floor and no inbox-clearance/new contract is
claimed.

**FIRST MOVES AFTER RESTART:** (1) read `AGENTS.md`, `CLAUDE.md`, standing goal, this handoff, and the
live ignored Claude-F pair record; (2) re-derive status/HEAD/dirty state, including the A3 merge probe;
(3) obtain and validate a complete Claude-F A7 contract before any mutation; (4) do not stage, commit,
push, merge, deploy, create a watcher, or take live/cross-lane action. The temporary Zulip post used for
the earlier confirmed status receipt is disposable only after this block is written; all durable facts it
contained are already preserved above.

### 2026-08-30 — F35 builder candidate: single-file suppression parity, pending detached audit

**ASSIGNMENT / SCOPE:** Claude-F's pair-channel ruling at line 7887 made F35 the first permitted
builder slice: correct the shared source-path resolution used by inline-ignore, lexical-context,
injection-exemplar, and reachability suppression when the scan target itself is one file. Allowed
paths are `scripts/praetor.py` (only those four resolution sites via their shared resolver) and `tests/`.
Excluded: engine modules, `lexctx.py`, `taint.py`, `interpret.py`, KB, Rust, `references/`, history/ref
operations, staging outside the named deliverable, merge, push, wiki, live action, and self-acceptance.

**IMPLEMENTATION CANDIDATE:** `_finding_source_path(target, finding_file)` now returns `target` when it
is an existing file, otherwise the existing target-plus-relative-finding resolution. All four suppression
passes call it. This preserves directory behavior and prevents a single-file target from becoming a
nonexistent `file/file` read. The matching focused evidence is
`tests/test_f35_single_file_suppression.py`: a real-pipeline inline-ignore fixture checks both suppressed
and active outcomes for file versus parent-directory target; focused filesystem-backed tests cover all
four passes and both keep/suppress directions.

**RED-FIRST / MUTATION EVIDENCE:** Before the resolver change,
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 py -3.14 -B -m pytest tests/test_f35_single_file_suppression.py -q`
exited 1 with four positive-control file-target failures and four passing negative controls. With the
resolver restored, the same command exited 0 (`10 passed`). Then the `os.path.isfile(target)` branch was
temporarily removed, restoring the prior bare join; the focused command again failed (`5 failed, 5
passed`; the real pipeline positive control and each of the four suppression passes went red). The branch
was restored with `apply_patch`, never with a destructive Git command. This is builder evidence only.

**REGRESSION EVIDENCE:**
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 py -3.14 -B -m pytest tests -q` exited 0 after restoration:
`340 passed in 21.45s`. The pre-F35 census command
`git grep -nE 'praetor\._apply_(inline_ignores|lexical_context|injection_exemplar|reachability)\(' HEAD -- tests`
listed 11 direct calls, all with synthetic directory-like `"/t"` or `"/target"` values; the companion
pipeline-target command
`git grep -nE 'praetor\.main\(\[|\[sys\.executable, _PRAETOR' HEAD -- tests`
listed directory-target invocations only. Therefore the observed pre-F35 regular-file-target suppression
test census is **0**. This static census is not a claim about dynamically generated external consumers;
Claude-F must independently reproduce it from the committed candidate.

**PERSISTENCE / AUDIT:** Commit exactly `scripts/praetor.py`,
`tests/test_f35_single_file_suppression.py`, and this builder handoff on `codex-f/build`; record the
resulting hash in the pair channel and request Claude-F's detached BLOCK-first audit bound to that hash.
No builder green result is an ACCEPT or integration clearance.

**POST-HYGIENE GATE / CENSUS:** The final portable commit gate,
`bash /c/Users/Admin/.claude/plugins/cache/odo/odo/0.6.1/precommit/gate.sh --fast`, exited 0; its
unconfigured-suite limitation is stated by that tool and is not treated as test evidence. The repository
gate `bash tests/precommit.sh` then exited 0: Python `340 passed`, Rust `11 passed`, self-scan unchanged
at `31 active / 47 filtered`, and the public-hygiene sweep covered `109` shipping files. The pre-F35
single-file suppression-test census is **0**. Command:
`git grep -nE 'praetor\._apply_(inline_ignores|lexical_context|injection_exemplar|reachability)\(' HEAD -- tests`
found 11 direct suppression calls, all synthetic `"/t"` or `"/target"` values;
`git grep -nE 'praetor\.main\(\[\s*str\(tmp_path /|\[sys\.executable, _PRAETOR, str\(tmp_path /' HEAD -- tests`
found 0 literal single-file pipeline targets. This is a source-level census of the pre-F35 test tree,
not an assertion about external consumers; the detached audit must reproduce it.

**CURRENT STATE / BLOCKERS:** At the start of this slice the builder was
`a62a97715a42a595c022351e7ded5e5017bf0805`; canonical remained clean at
`7f6e5ce33054f85d488653b9dad9b1ca86f854ca`. The working tree now has the pre-existing/owned handoff
append plus the F35 source and test candidate; nothing is staged. Independent Claude-F audit is the only
remaining F35 blocker. All other held findings and all Gate 1 backup-ref/history work remain separate.

### 2026-08-30 — Medium-tier restart record: F38 accepted, push held, planning inventory reconciled

**CURRENT REFS / OWNERSHIP:** Builder worktree is on `codex-f/build` at
`26bd23321dac49024a9ba41cdfbad93e8a87de0e`; local `main` is
`fcb4be193f6d1d98ed4e115ab167b5351292c9e6`; `origin/main` is
`9cbbe4c77c9617ebd29a6dc02d938ba699bdc52f`. At re-derivation,
`git status --porcelain=v1 -uall` printed no rows, `main...HEAD` was `11 1`,
and `origin/main...HEAD` was `8 1`. The right-side one is F38; the left-side
commits are not permission to merge, rebase, or resolve histories. No refs were
moved by this session.

**F38 — ACCEPTED, NOT PUSHED:** F38 is exactly `26bd233`, changing only
`tests/test_output_atomicity.py`. It corrects the test's platform assertion,
not the atomic writer: Windows sharing refusal must be loud and preserve the
destination; POSIX replacement may succeed while the old open reader remains
consistent and the destination becomes the replacement. Builder evidence:
Windows and Ubuntu WSL focused runs each reported `2 passed`; a Windows predicate
mutation and a POSIX old-destination mutation each reported `1 failed, 1
passed`; Windows full suite reported `343 passed`; `bash tests/precommit.sh`
reported all 13 checks passed. Claude-F independently recorded ACCEPT in the
current local audit ledger. It remains held pending a direct push release.

**RESTART-PLAN INVENTORY:** The current planning work is committed on local
`main` as `55171f4` and `fcb4be1`, not merged into this builder branch. Its
source-verified outcomes are: README's no-detector Rust claim is stale; ADR-001's
visible first-port table is superseded by its own secrets-first amendment; the
two required differential paths are both present and the runner refuses either
one's removal; and the old NEXT-SESSION plan is history, not live instructions.
The recovery ref exists, but the refreshed backlog says no recovery item is open;
that ambiguity is a decision-owner review item, not authority to revive work.

**WIKI / REMOTE FACTS:** Read-only repository API returned public, unarchived,
`main`, and Wiki enabled. Primary `git ls-remote` succeeded; the conventional
Wiki Git remote returned `Repository not found` and the public Wiki URL redirected
to the repository page. Therefore Wiki page population is CANNOT_DERIVE, not
empty; no initialization, clone-for-write, or publication is authorized.

**EXACT NEXT BOUNDED ACTION:** Re-read `AGENTS.md`, `CLAUDE.md`, this handoff,
the current audit ledger, and the pair log; then obtain a new bounded contract
for any README/ADR/restart-document repair. Before a future push, independently
re-derive branch/remote/account, the accepted F38 hash, clean status, project
gate, real CI step count, and direct push release. Enterprise capacity
provisioning alone is not that release.

**NO-GO / LIMITS:** No push, merge, rebase, deployment, Wiki publication,
recovery-branch action, deletion, or self-acceptance. The one read-only watcher
is deliberately retained for counterpart state changes; do not assume its
terminal session survives a restart—re-derive the audit ledger and pair log
instead. No memory-store update was requested or made.

### 2026-08-30 — Handoff correction: Wiki is enabled but has no initial page

The preceding Wiki result was deliberately conservative pending a discriminator.
It is now resolved: the repository API reports Wiki enabled; the primary remote
is reachable with the configured credential; the corresponding Wiki Git remote
returns `Repository not found`; and GitHub's Wiki documentation says cloning the
Wiki repository becomes available only after an initial Wiki page is created.
Together, these establish that no initial Wiki page has been created. The public
Wiki therefore has no current page content, while every future page remains an
irreversible public publication requiring direct, per-page approval. This
correction does not authorize initialization, drafting in the Wiki, publication,
or any remote write.

**COUNT SNAPSHOT LIMIT:** The divergence counts above were measured before the
subsequent handoff commits. A restart reader must rerun the named `git rev-list`
commands and classify later documentation commits from `git log`; exact equality
with this record's historic right-side count is neither expected nor an error.
