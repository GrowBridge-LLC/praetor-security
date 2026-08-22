# PRAETOR — open backlog recorded before the Codex worktree/comms rollout

Written 2026-08-22, before the rollout's first step, because that rollout is an interruption and
not a replacement. Every item carries an owner and a next action, so none of it depends on a
session surviving.

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
3. **Task H — PARTIALLY DONE, re-derived 2026-08-22.** The differential harness **exists**, at
   `tests/differential/run_differential.py`, and pre-commit gate 8 enforces it. The Rust
   `engine_secrets` port **does not**: `rust/praetor-core/src/` holds `sca.rs`, `text.rs` and
   `unicode_tables.rs`, and no secrets module. Owner: this project.
   Next action: port `engine_secrets` into `rust/praetor-core/src/`, then extend the existing
   differential runner to cover it. **Do not rebuild the harness — it is already there.**
4. **Tasks F, E and B.** Owner: this project. Next action: re-read the assignment file under
   `.local/` for their specifications once H clears. The handoff supersedes that file's ordering,
   not its content.

## Recovery work — owned by this project

5. **`wip/task-d-backup-2026-08-18` (pushed, `2689ade`) still needs a real-versus-stale sorting
   pass.** It holds 17 files, of which only `scripts/engine_sast.py` and
   `tests/test_tool_output_is_not_target_controlled.py` look like genuine undescribed work; the
   other fifteen look like a stale duplicate of a reconciliation already merged into `main`.
   Owner: this project. Next action: run `git show wip/task-d-backup-2026-08-18`, classify every
   file as real or stale, then cherry-pick only the real portion. Nobody has done this sort yet.

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
