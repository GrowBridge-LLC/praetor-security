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
| based on | `5408250`, fast-forwarded from `main` while this branch was empty |
| gate | `bash tests/precommit.sh` — verified exit 0, 9/9, from inside this worktree on 2026-08-22 |
| assigned work | none yet — see the pair channel |

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
