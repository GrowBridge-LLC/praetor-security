# Pair channel — historical and retired

This file is a historical pointer, not an operational coordination record.
The former channel and its transport are permanently retired.

No operational path is published here.
Current coordination uses an owner-designated private local mechanism
and durable receipts outside the tracked tree.

The former absolute-path rule is preserved in Git history and verified
recovery archives; it must not be followed or reconstructed from this file.


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

## Historical records

- `PRE-ROLLOUT-BACKLOG-2026-08-22.md` — the retired rollout-era queue.
- `GOAL-codex-f-2026-08-22.md` — the historical vendor-specific goal.
- `HANDOFF-codex-f.md` — the historical builder handoff.

These are preserved records, not active assignments or conversation.
