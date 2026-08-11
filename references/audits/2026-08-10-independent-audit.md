# Independent audit — 2026-08-10

**Scope:** commits `3b6008b..51657ef` (6 commits).
**Method:** four independent auditors with **zero prior context**, each instructed to verify against
ground truth — real `git`, real test runs, real mutations — and explicitly *not* against the prose of
the work under review.
**Outcome:** 3 real defects, all of the same class, all fixed in `f0b3ad2`.

> Recorded here rather than summarised in a commit message, because a finding that lives only in a
> summary cannot be re-checked. This file is the artifact; the fixes cite it.

## Why this exists at all

Every guard in the audited commits had already been mutation-tested by its author. All three defects
below survived that. The distinction the audit exposed:

> **Mutation testing proves a guard catches the case in front of it today. It says nothing about the
> sentence claiming the guard will catch tomorrow's case** — and that sentence is the one every future
> reader trusts, because verifying it means constructing a case that does not exist yet.

That is the class this repo's own `CLAUDE.md` names as the killer: **a safety property asserted in a
header that the code does not implement.** Three instances shipped in six commits, written by an author
who had just cited that rule.

## Findings

### F1 — A cited test did not exist (`unicode_tables.rs`, `gen_unicode_tables.py`)

Three comments asserted that `tests/test_rust_unicode_tables_parity.py` fails if the generated Unicode
table stops matching its generator. **No such file existed.** The only check was a manual CLI flag that
nothing invoked.

*Impact:* the table is generated from Python's `unicodedata`. When that database advances, the Rust
port's notion of "what is a letter" silently diverges from the Python engine's, moving token boundaries
so a mixed-script finding can fire in one implementation and not the other — while both suites stay
green, because each remains consistent with itself.

*Fix:* the test was **written**, not the claim struck — 4 tests including an anti-vacuity check (empty
tables would satisfy a naive parity assertion perfectly) and a spot-check of the confusable code points
the homoglyph detector is built around. Mutation-proven by aging the recorded Unicode version.

### F2 — 🔴 An invariant sweep that did not sweep (`rust/praetor-core/src/sca.rs`)

The test `no_sca_argv_can_resolve_build_or_install` carried the comment: *"Covers EVERY backend at once,
so a newly added one is caught by an existing test rather than by remembering to write a new one."*

**False.** The list was hand-written. The auditor added an `npm_audit_argv` returning `["install"]` —
a flag that lets a package manager resolve and build from the scanned tree — and **all three tests
stayed green.**

*Impact:* this is the never-execute invariant, the one that outranks everything in this codebase. An
SCA backend whose argv nobody checks is precisely how the original `pip-audit` RCE got in. The comment
actively discouraged the reader from adding a guard, by telling them one already existed.

*Fix:* `every_argv_builder_in_this_file_is_swept` counts the `pub fn *_argv` definitions the module
declares and fails when the swept list falls behind. Verified against the auditor's exact mutation:
3 defined vs 2 swept → red, with the backend named in the failure message.

### F3 — A guard that exempted the file it was guarding (`test_line_numbering_consistency.py`)

The call-site guard skipped **all of `scripts/core.py`** on the grounds that its docstring legitimately
mentions `str.splitlines()`. `core.py` is the file that *owns* line semantics, making it the highest-risk
file, not the lowest. The auditor added a real `.splitlines()` call to `redact_line`; the guard stayed
green.

*Fix:* narrowed to skip only the prose. The two are distinguishable: documentation writes
`str.splitlines()` (the thing warned about), an accidental call reads `text.splitlines()`. Verified
against the auditor's exact probe.

## Claims corrected (not defects, but misleading)

- `lib.rs` described itself as *"scaffold only"* when `text.rs`, `sca.rs` and `unicode_tables.rs` are
  real, tested, load-bearing code. What is absent is any `scan()` entry point. A reader skimming the
  summary would have taken the crate for inert.
- A doc comment cited *"64 passing tests"*. That was the working tree's count at the moment of
  discovery, but the work was split into separate commits afterwards, so **no commit in history shows
  64** — a reader re-deriving it would find a different number and reasonably conclude the figure was
  invented. Dropped rather than corrected: it was never the point, and a number that cannot be
  reconciled against the repo is worse than no number.

## A recommendation that was rejected

One auditor advised changing "64" to "58" — the count at commit `f5107de`. **58 was never observed**;
adopting it would have replaced a confusing truth with a confident falsehood that *looked* better
sourced. Recorded because the reasoning generalises: **an independent finding is evidence to re-derive,
never a verdict to apply.**

## What verified clean

Independently re-derived and confirmed: commit count and hashes; test counts; the self-scan at 12
active / 45 filtered; that `references/SELF-SCAN-BASELINE.json` was **not** modified by any commit
(it is a frozen "before" and regenerating it would destroy the only thing making any false-positive
reduction checkable); the `secrets` carve-out from both suppression passes still intact
(`_LEXCTX_ENGINES` and `_REACHABILITY_ENGINES` are `("aisec",)` only); `--disable-pip --no-deps` present
in the pip-audit argv; the `split_lines` migration complete across every line-number site; the
cross-language differential contract genuinely unfalsifiable on its 23 covered cases; and no
identifying or personal content in the diff or commit messages.

## Standing limitations, stated rather than left to be found

- The differential corpus covers 23 cases. Two implementations can still share a bug on an input shape
  the corpus does not contain. This is inherent to differential testing; the corpus is the only place
  truth enters, which is why it must keep including cases the implementations get *wrong*.
- The harness compares `(engine, rule_id, file, line)` and therefore **cannot detect description
  drift** between the two implementations.
- Measurements taken against a developer machine's local tree (a real `~/.cursor/` hook config) are not
  reproducible by a third party. They are cited as the origin of a fix, never as a test assertion.
