# PRAETOR — open backlog recorded before the Codex worktree/comms rollout

## ↩️ REFRESHED 2026-08-24 (evening) — re-derived by execution, not carried forward

**Everything the "Build queue" section below lists as open or in-progress is DONE and on `main`,
re-verified by running the actual checks rather than trusting the prior text:**

- **Cluster A** — merged `3f27c6e`. `codex-f/build` and `main` had genuinely diverged (both rewrote
  the same lines of `core.py::walk_files()`); hand-resolved keeping both sides. Full suite +
  precommit green after.
- **Task D** — already landed on `main` before this refresh (`git merge-base --is-ancestor` on its
  landing commits returns 0). `codex-f` independently re-derived this from `tests/test_tool_output_
  is_not_target_controlled.py`'s AST-based subprocess-discovery guard and confirmed it live.
- **Task H** — already landed on `main` before this refresh (`d5943fb`, `0d24b27`, `3a34b16` are all
  ancestors of current `main`). `codex-f/secrets-port-parked` is a superseded dead end -- its tip is
  NOT an ancestor of `main`; do not build on it.
- **SAST fail-safe status gap** — `88affb0`. `n_errors > 0` (Semgrep reporting file/analysis errors)
  used to sit in `detail` next to an unconditional `status: "ok"`. Re-derived from the 2026-08-18
  recovery backup below, narrowed: that backup's version of the same function also reverts the
  operator-controlled Semgrep timeout (`e09dcf3`) and a *deliberate* prior fix (`.semgrepignore`
  degradation staying `"ok"` rather than breaking every scan on an older Semgrep -- see
  `test_a_semgrep_that_rejects_the_flag_does_not_break_every_scan`'s own docstring). Only the
  `n_errors` half was taken; the rest of that backup is NOT safe to apply wholesale.

**Genuinely still open, from the same recovery backup (`wip/task-d-backup-2026-08-18`), deliberately
not touched today because both need real design reconciliation, not extraction:**

- `SEMGREP_DEFAULT_IGNORE_DIRS` (the backup's Semgrep-measured default-ignore set) vs. `main`'s
  current caller-supplied `skip_dirs` parameter (which exists to fix a *different*, already-shipped
  bug: the `--no-default-skips` desync between PRAETOR's walker and Semgrep's own exclusions). The
  backup predates the `skip_dirs` fix and would regress it if applied as-is; reconciling the two
  needs someone to decide whether Semgrep's default-ignore restoration should be keyed off PRAETOR's
  walker policy or off Semgrep's own measured defaults, not just picked.
- `scripts/engine_sast.py` currently forwards PRAETOR's `--exclude` (documented as REGEX) straight
  to Semgrep's own `--exclude` flag (which is GLOB syntax) — a real, live language mismatch, same
  shape as the already-fixed `.gitignore`/`.semgrepignore` scope-disagreement bugs above it in the
  same file. Not fixed here because it needs verification against a live Semgrep
  (`tests/semgrep_live_check.py` exists for exactly this) before trusting a behavioural claim about
  it, not because it's low-value.


Written 2026-08-22, before the rollout's first step, because that rollout is an interruption and
not a replacement. Every item carries an owner and a next action, so none of it depends on a
session surviving.

## ↩️ REFRESHED 2026-08-24 — the rollout returned a second time; the section below is CURRENT state

The worktree, `.gitignore` rules, goal file and handoff file described below were already built and
committed on 2026-08-22 (`090bf28`, `b78cf1c`/`59249d8`) — re-verified today, all still correct
(`.gitignore` gate passes, worktree `git-common-dir` links to the main checkout, precommit gate runs
clean from both the main checkout and the worktree). The pair channel moved to `.local/PAIR-CHANNEL.md`
(gitignored) after `inbox/PAIR-CHANNEL.md` tripped two of this repo's own gates on 2026-08-22 —
`inbox/PAIR-CHANNEL.md` is now a 36-line pointer explaining that, not the live channel.

**Since this file was written, both this session and codex-f have been active. Current state:**

- **Four PRAETOR defects found and fixed by this session, all committed and pushed to `main`**
  (`66d0dd9`, `0d3d184`, `4936b01`, `e09dcf3`): a scan that read zero code files exiting clean, one
  undecodable file blinding a whole engine, an extension allowlist missing deployment/build-recipe
  code, and a hard-coded Semgrep timeout with no operator override.
- **`codex-f/build` is 5 ahead of `main`** (tip `16f0797`), carrying Cluster A: symlink-refusal +
  NUL-retention in `scripts/core.py`. Independently audited by this session tonight — **CLEAR on the
  code** (mutation-reproduced the claimed test failures myself), **BLOCK on landing**: the branch's
  own last commit leaked a sibling lane's tool name into `inbox/HANDOFF-codex-f.md:323`, failing the
  public-hygiene gate. Fix is narrow (reword that line, re-run the gate) and is codex-f's to make,
  per Rule 1. Full verdict posted to `.local/PAIR-CHANNEL.md`.
- **`codex-f/secrets-port-parked` is 7 ahead of `main`** — this is Task H below (the Rust secrets
  port), parked, not abandoned. Still needs the differential/mutation acceptance pass and independent
  audit named in that entry.
- **Zulip comms are live for this session** (`claude-f` / Dorothy, onboarded, LIVE). `codex-f` /
  Whitfield has NOT onboarded — still `never` in `zulip who` as of this refresh — so
  `.local/PAIR-CHANNEL.md` remains the only channel to reach it. **Whoever next opens a Codex session
  in the worktree should onboard it to Zulip using its already-provisioned
  `C:\Users\Admin\zulip-agents\codex-f.zuliprc`, not the git-channel-based prompt in
  `ROLLOUT-WORKTREE-AND-COMMS.md` §3** — Mike ruled 2026-08-24 that the git channel files and their
  watchers are retired, no dual-write.
- **The enforcement plugin's cache content-check FAILs today**, one file (`generic-git-root-basename.sh`,
  installed `0.6.1` vs repo). Not this project's to fix — the owning lane's repo is deliberately ahead
  of origin pending its own held audit, so the cache legitimately can't match it yet. Reported, not
  acted on.

Everything below this point is the original 2026-08-22 backlog, left as written except where a line
above it already updated an item (Cluster A above is separate from, and does not change, Task D
below).

**How this was established:** read this project's live session handoff in the Claude memory store,
the tail of the machine-local pair record under `.local/`, `git log`, `git status`, and the
contents of `.local/`. State at the time of writing: `main` at `090bf28`, clean, one checkout.

## Build queue — ordered, owned by this project

1. **Task D — DELIVERED on `codex-f/build`, four audited rounds. Awaiting a merge decision.**
   The guard hard-coded five filenames, so a planted new-engine file went undetected. It now
   discovers every `scripts/*.py` by AST, treats `subprocess` as deny-by-default, matches the `os`
   process family by prefix, and allows exactly one sanctioned call by `(file, line)`.
   Owner: this project. Next action: **the merge to `main` needs the operator's word.** Nothing on
   that branch is pushed.
2. ~~**Task I — exit-code priority.**~~ ✅ **ALREADY DONE — this entry was wrong when written.**
   It landed in `0930947`, and six tests in `tests/test_exit_code_never_hides_a_blind_spot.py` hold
   the behaviour, including the carve-out that an *unavailable* runtime must not fail a report-only
   run.
   ⚠️ **How the error happened, because it will happen again:** this entry was copied from a handoff
   written before the implementation landed, and the design document carried a "NOT IMPLEMENTED"
   header of its own, so two sources agreed and neither had been re-derived. A second near-miss
   followed: searching `tests/` for the implementation's identifiers found nothing, because those
   tests assert **exit codes**, not function names — which is exactly the discipline this repository
   asks for. **Re-derive a "not started" claim against the code before assigning it to anyone.**
3. **Task H — IN PROGRESS, re-derived 2026-08-22.** The differential harness exists at
   `tests/differential/run_differential.py`, and pre-commit gate 8 enforces it. The Rust secrets
   detector now exists at `rust/praetor-core/src/secrets.rs`; it is not wired into the CLI.
   Next action: finish differential/mutation acceptance and independent audit. **Do not rebuild the
   harness — it is already there.**
   🔴 **The engine order is NOT free choice, and it CHANGED on 2026-08-22.** See ADR-001 Amendment 2:
   `secrets` ports first and `aisec` is deferred, because condition 1's premise that `aisec` is
   "pure pattern matching, zero external tool dependencies" is false — it imports `json` and parses
   MCP manifests structurally. `base64` is authorised for `secrets`; **a JSON crate is NOT, and
   `aisec` cannot proceed until that separate decision is made.** Condition 2 is unchanged and still
   binding: no Rust backend merges before its never-execute invariant test does, which is why
   `sca.rs` exists as argv construction only.
   ↩️ **This entry has now been wrong twice** — first naming `engine_secrets` against the then-current
   ADR, then naming `engine_aisec` against an ADR whose own premise had rotted. The builder caught
   both by trying to execute them.
4. **Tasks F, E and B.** Owner: this project. Next action: re-read the assignment file under
   `.local/` for their specifications once H clears. The handoff supersedes that file's ordering,
   not its content.

## Recovery work — owned by this project

5. 🔴 **`wip/task-d-backup-2026-08-18` (`2689ade`) — CLASSIFIED 2026-08-22. It is far bigger than
   this entry claimed, and it holds unlanded SCANNER BEHAVIOUR, not stale prose.**

   **Measured: 13 REAL, 4 STALE, 0 UNCLEAR** against `main`, with a positive control proving the
   search method reached the tree. ↩️ **The inherited description — "only `engine_sast.py` and
   `test_tool_output_is_not_target_controlled.py` are real, the other fifteen are a stale duplicate"
   — is FALSE.** It was a guess carried across three handoffs and never measured.

   Independently spot-checked: `main:scripts/core.py` is byte-identical to the merge-base blob, so
   `main` never received this work at all; `SEMGREP_DEFAULT_IGNORE_DIRS` appears in 0 files on `main`
   and 3 on the backup; symlink-refusal tests appear 0 times on `main` and 6 on the backup.

   **STALE (4):** `.gitignore`, `AGENTS.md`, `CLAUDE.md`, `tests/precommit.sh` — superseded.

   **REAL (13)**, in two coupled clusters plus three singles:
   - **NUL handling** — `scripts/core.py` (NUL observation/retention, refuses direct and walked file
     symlinks), `scripts/praetor.py`, `scripts/report.py`, and their tests.
   - **SAST scope and error handling** — `scripts/engine_sast.py` (measured Semgrep default-ignore
     set, fail-safe analysis-error status, fail-safe ignore-flag fallback), `tests/semgrep_live_check.py`,
     CLI exclude-regex validation, several tests, and the `CHANGELOG.md` entries recording them.
   - Singles: `CONTRIBUTING.md` (publishes the bare pytest command that fails on this machine),
     `tests/test_mcp_manifest_scanning.py`, `tests/test_tool_output_is_not_target_controlled.py`.

   ⚠️ **The clusters are COUPLED — recovering isolated rows splits behaviour from its evidence.**
   ⚠️ **`REAL` means "absent from `main`", NOT "safe to cherry-pick".** The commit is unaudited.
   ⚠️ For `test_tool_output_is_not_target_controlled.py`, a stronger audited descendant exists on
   `codex-f/build`; prefer that lineage over this raw earlier hunk.

   Owner: this project. Next action: decide recovery cluster by cluster, not file by file, and audit
   each before it lands. **`scripts/core.py`'s symlink refusal touches the never-execute invariant,
   so it is the highest-value and highest-risk item in the set.**

## Blocked on someone else — do not guess

6. **Mike said "when the prd work is done ask df for clarification" and the previous session could
   not identify which PRD he meant.** Owner: Mike and the coordination project.
   Next action: ask directly which PRD is meant before acting. The sibling repository's PRD is the
   likely candidate, but that is inference, and that repository is a separate session's.
7. **The estate-wide stop-work hold is not this project's to resolve.** Mike: "the hold is df
   choice." Owner: the coordination project. Next action: none here — ask Mike or that project
   directly if build authorization is needed. Do not re-derive it by grepping the channel.
8. **Two cross-project findings are posted and awaiting a reply** — a possibly-lost 34.8 MB
   preservation archive, and a conflation risk between capability and decision in the memory
   substrate. Owner: the projects they were addressed to. Next action: none here; await their
   replies in the shared coordination channel.
9. **The builder session's responsiveness is unknown.** Its last posts were administrative, and its
   Codex thread was reported as "thread not found". Owner: this project and Mike.
   Next action: confirm the builder actually reads its channel before assigning it Task D. The
   rollout's fresh worktree may itself resolve this.

## Residual, low stakes

10. **An empty worktree parent folder under the Codex state directory resists `rmdir`** with
    "device or resource busy", most likely held open by the Codex application. Owner: this project.
    Next action: retry `rmdir` once the Codex application closes that task. Do not force it.
11. **`wip/main-dirty-backup-2026-08-19` is a spent safety net.** Owner: Mike. Next action: leave it
    alone. Claude Code cannot delete branches, so removing it would be Mike's own hand.
