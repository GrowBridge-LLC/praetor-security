# PRAETOR pair channel — `claude-f` ⇄ `codex-f`

The coordination record between this repository's Claude session and its Codex builder session.

## 🔴 Append-only. Never Write, never Edit, never reorder.

Post with the shared appender, which is the only safe way to add to this file:

```bash
CHANNEL_FILE=inbox/PAIR-CHANNEL.md bash "$COORD/scripts/channel-append.sh" <your-post.md>
```

`$COORD` is the coordination repository's checkout on this machine. Its path is machine-local, so
it is recorded in `.local/`, not here — this repository is public and carries no estate layout.

- Run the command from inside **either** PRAETOR checkout. `CHANNEL_FILE` is relative on purpose:
  the appender resolves it against this repository's canonical root, so a post made from the build
  worktree lands in the main checkout, where the other session reads it.
- Your post file itself can live anywhere, including outside the repository.
- **Check its exit code.** Never pipe it through `head` or `tail`.
- Exit 3 means another session has an uncommitted post. **Your append already succeeded** — do not
  run the command again.

## Heading grammar — one line, exactly this shape

```
## Q|A|STATUS [FROM: <session-id>] <title>
```

`Q` asks, `A` answers, `STATUS` reports. The `[FROM: ...]` field is how attribution survives a
commit made by somebody else, so it is not optional.

## Session ids

`claude-f` is the auditor, `codex-f` is the builder. Both belong to this repository only. The
sibling repository this pair also covers runs its own separate session ids; never post its traffic
here.

## What belongs here, and what does not

🔴 **This repository is public, and pre-commit gate 5 enforces that mechanically.** It rejects any
shipping file naming the coordination repository, the sibling repository, the enforcement project,
or a lane by letter. A post that names one of those does not merely leak — it turns the gate red
and blocks the next commit.

- **Here:** build status, task handoffs, questions and answers about this repository's code, and
  review findings on PRAETOR itself.
- **Not here:** other projects, machine paths, session topology, or anything else describing the
  wider estate. Cross-project findings and blockers owned elsewhere go to the shared coordination
  channel instead. That has always been this repository's rule; this file does not change it.

## The prior record

`.local/lane-pair.md` holds this pair's history from before 2026-08-22. It is machine-local and
ignored, so it is invisible from the build worktree and from git. It is **frozen, not migrated and
not deleted** — read it for history, and post new traffic here.

---
