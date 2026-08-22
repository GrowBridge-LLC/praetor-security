# Lane F (PRAETOR) — open backlog recorded before the Codex worktree/comms rollout

Written 2026-08-22, before step 1 of the rollout, per Mike's instruction that lanes must not
forget work they already had. The rollout is an interruption, not a replacement.

**How this was established:** read the live session handoff
(`~/.claude/projects/C--projects-PRAETOR/memory/session-handoff-2026-08-19.md`), the tail of
`C:\projects\PRAETOR\.local\lane-pair.md`, `git log`, `git status`, and `.local/` contents.
State at time of writing: `main` @ `a640fb1`, clean, no worktrees.

## Build queue — ordered, owned by Lane F

1. **Task D — subprocess-discovery guard hard-codes 5 filenames.** A planted new-engine file is
   undetected; a fifth engine is inbound, so this is a live security gap, not cleanup.
   Owner: Lane F builder (codex-f), or claude-f if no builder is running.
   Next action: prove the existing probe RED first, then glob `scripts/*.py`, allow `core.py`'s one
   legitimate call by line number (not by filename exclusion), and replace the `== 5` count pin.
2. **Task I — exit-code priority.** Findings plus a blind engine must return 3, not 1.
   Owner: Lane F. Next action: start after Task D lands and its gate is green.
3. **Task H — Rust differential harness + `engine_secrets` port.** Its "wait for Task G's merge"
   precondition is satisfied. Owner: Lane F. Next action: start after Tasks D and I.
4. **Tasks F, E, B.** Owner: Lane F. Next action: re-read `.local/ASSIGNMENT-codex-f-2026-08-17.md`
   for their specs when H clears; the handoff's ordering supersedes that file's ordering only.

## Recovery work — owned by Lane F

5. **`wip/task-d-backup-2026-08-18` (pushed, `2689ade`) needs a real-vs-stale sorting pass.** 17
   files; only `scripts/engine_sast.py` and `tests/test_tool_output_is_not_target_controlled.py`
   look like genuine undescribed work, the other ~15 look like a stale duplicate of the
   reconciliation already in `main`. Owner: Lane F.
   Next action: run `git show wip/task-d-backup-2026-08-18`, classify every file real vs stale,
   then cherry-pick only the real portion. Nobody has done this sort yet.

## Blocked on someone else — Lane F must not guess

6. **Mike said "when the prd work is done ask df for clarification" and this lane could not
   identify which PRD.** Owner: Mike / darkfactory. Next action: ask Mike or darkfactory directly
   which PRD is meant, before acting on it. RUBICON's PRD is the likely candidate but that is
   inference, and RUBICON is a separate session's repo.
7. **The estate-wide stop-work hold's resolution is darkfactory's call.** Mike: "the hold is df
   choice." Owner: darkfactory. Next action: none for Lane F — ask Mike or darkfactory directly if
   build authorization is needed, do not re-derive it from channel greps.
8. **Two cross-lane findings posted to the estate channel** (a possibly-lost 34.8MB preservation
   archive; a Thessary capability-versus-decision conflation risk). Owner: Lane B / Lane C.
   Next action: none for Lane F — await their reply in `FACTORY-BUILD-COORDINATION.md`.
9. **codex-f's responsiveness is unknown.** Its last posts were administrative, and the estate
   reported its Codex thread as "thread not found". Owner: Lane F / Mike.
   Next action: confirm codex-f actually reads its channel before assigning Task D to it; this
   rollout's fresh worktree may itself resolve this.

## Residual, low stakes

10. **`C:\Users\Admin\.codex\worktrees\5aa0` empty parent folder resists `rmdir`** ("device or
    resource busy"), probably held open by the Codex app. Owner: Lane F.
    Next action: retry `rmdir` after the Codex app closes the 5aa0 task; do not force it.
11. **`wip/main-dirty-backup-2026-08-19` is a spent safety net.** Owner: Mike.
    Next action: leave it alone — Claude Code cannot delete branches, so if it is ever removed that
    is Mike's own hand.
