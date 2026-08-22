# PRAETOR — open backlog recorded before the Codex worktree/comms rollout

Written 2026-08-22, before the rollout's first step, because that rollout is an interruption and
not a replacement. Every item carries an owner and a next action, so none of it depends on a
session surviving.

**How this was established:** read this project's live session handoff in the Claude memory store,
the tail of the machine-local pair record under `.local/`, `git log`, `git status`, and the
contents of `.local/`. State at the time of writing: `main` at `090bf28`, clean, one checkout.

## Build queue — ordered, owned by this project

1. **Task D — the subprocess-discovery guard hard-codes five filenames.** A planted new-engine file
   goes undetected, and a fifth engine is inbound, so this is a live security gap rather than
   cleanup. Owner: the builder session, or the auditor session if no builder is running.
   Next action: prove the existing probe RED first, then glob `scripts/*.py`, allow `core.py`'s one
   legitimate call by line number rather than by excluding its filename, and replace the `== 5`
   count pin.
2. **Task I — exit-code priority.** Findings plus a blind engine must return 3, not 1.
   Owner: this project. Next action: start after Task D lands with a green gate.
3. **Task H — the Rust differential harness and the `engine_secrets` port.** Its "wait for Task G to
   merge" precondition is now satisfied. Owner: this project. Next action: start after D and I.
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
