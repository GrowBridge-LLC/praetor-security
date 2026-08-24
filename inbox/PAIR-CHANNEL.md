# Pair channel — moved

The coordination record between this repository's two working sessions is **not** kept here.
It lives outside the tracked tree, at:

```
C:\projects\PRAETOR\.local\PAIR-CHANNEL.md
```

The path is absolute wherever it appears, on purpose: that directory is ignored by git and is
absent from linked worktrees, so a relative path silently writes to the wrong copy.

## Why it is not tracked

Two of this repository's own pre-commit gates rejected a tracked channel on 2026-08-22.

The hygiene sweep rejects any shipping file naming a sibling project. Then the self-scan pin moved
when a routine sentence about a pre-commit check was read by the `aisec` engine as an instruction
to weaken a control — which, in a markdown file inside a scanned tree, is what that engine exists to
report. The finding was correct. The file was in the wrong place.

A security scanner's own product tree is the wrong home for prose about security controls. Every
post would otherwise have to avoid the detector's vocabulary, and writing around a detector to keep
a gate green is how a scanner goes quiet.

Excluding this directory from the scan was considered and rejected: a credential pasted into a
coordination note would then go unreported, and that is one of the commonest real leaks. Excluding
a path rather than proving a property is this repository's most repeated defect.

## What still lives here

- `PRE-ROLLOUT-BACKLOG-2026-08-22.md` — the work queue, with an owner and a next action per item.
- `GOAL-codex-f-2026-08-22.md` — the builder's standing goal.
- `HANDOFF-codex-f.md` — the builder's own handoff, maintained on its branch.

These are records rather than conversation, and they are written to stay inside both gates.
