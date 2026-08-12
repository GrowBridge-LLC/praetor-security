# Pre-close audit — 2026-08-12 (second round of the 2026-08-11/12 session)

**Scope:** commits `b5670e2..aded477` — five commits adding two false-positive fixes, the differential
Python↔Rust gate, and the pre-commit gate's repairs — plus the session's authored prose, the project
memory store, and the conversation transcript.
**Method:** four independent auditors with **zero prior context**, dispatched in parallel, each told to
verify against ground truth — real `git`, real test runs, real mutations — and explicitly *not* against
the prose of the work under review.

> 🔴 **Provenance, stated because it is itself a finding (F14).** Unlike
> `2026-08-11-preclose-audit.md`, this file was **not** written while the round ran. The four subagent
> reports lived only in the session-scoped temp directory, and by the time this file was started every one
> of them was **0 bytes**. What follows is reconstructed from the session record and then **re-verified
> against the tree** — every fix below was confirmed present in code before being written down here. It is
> an honest reconstruction, not a transcription, and the distinction is the point: *a summary is not the
> artifact.*

## F8 — 🔴 The argv sweep enumerated one directory. Fourth spelling of the same class.

`tests/test_rust_sca_argv_sweep.py` — the Python guard that F7 introduced *because* the Rust-side check
could only see one file — walked `rust/praetor-core/src` and nothing else. A second crate anywhere in the
workspace was invisible to it, and would have shipped an unswept argv builder with every gate green.

This is the **fourth** consecutive spelling of one class in two sessions:

| | the enumeration that was too narrow | found by |
|---|---|---|
| F2 | a hand-written list of SCA backends, described as covering all of them | audit 1 |
| F4 | the repair for F2: filtered on the literal prefix `pub fn ` | audit 2 |
| F7 | the repair for F4: keyed on function *name*, read one file via `include_str!` | audit 3 |
| **F8** | the repair for F7: read one *directory* | **audit 4** |

⇒ **Each repair was written by someone who had just read the previous finding.** The scope shrank by one
level of nesting each time — backend list → line prefix → single file → single directory — and at every
step the author believed they had generalised. *The fix for an enumeration bug is reliably another
enumeration bug one scope wider.*

*Fix* (`aded477`): the population is now the **workspace**, not a crate —

```python
RUST_ROOT = REPO / "rust"
files = sorted(p for p in RUST_ROOT.rglob("*.rs")
               if "target" not in p.relative_to(RUST_ROOT).parts)
```

`rglob`, not `glob`. `CRATE_SRC` survives **only** to locate `sca.rs` for the tests that are genuinely
about that one file. A new test, `test_the_sweep_reaches_every_crate_not_just_praetor_core`, asserts the
population is not confined to `praetor-core` — so the next narrowing fails a **named** test rather than
being discovered by a fifth audit. The enumeration also raises if it finds **zero** `.rs` files, because a
guard whose population is empty passes vacuously.

## F9 — 🔴 Two gates passed on suites that never ran

`tests/precommit.sh` gates 1 (Python) and 2 (Rust) tested for the **absence of failure**. Both therefore
passed when the suite did not run at all: a collection error that produced no summary line, a suite
reduced to zero tests, or — on the Rust side — every test marked `#[ignore]`, which prints `ok` and exits
0. The differential work in this same session had *just* demonstrated that last one empirically:
`cargo test` reported **"ok. 6 passed; 2 ignored"** over a deliberately diverged implementation.

**Second recurrence of `a-check-that-reports-does-not-gate`**, and the first was in this same file.

*Fix* (`aded477`): both gates now require **positive evidence of a run**, and reject the two ways it can
be faked —

```
MIN_PY=120   # floors, not exact pins: a floor blocks disappearance
MIN_RS=8     # without failing on every honest addition
```

- **no pass count parsed** ⇒ fail, *"A suite that never ran is not a suite that passed."*
- **below the floor** ⇒ fail, with the instruction to raise the floor *deliberately* if tests were
  removed on purpose.
- **any skipped / deselected / xfailed / `#[ignore]`d test** ⇒ fail, *"An ignored test still reports
  'ok' — that is the documented bypass, not an exemption."*

Floors rather than exact pins is a deliberate trade: an exact pin fails on every added test and gets
raised reflexively until nobody reads it, which is how a gate becomes a formality.

## F10 — The failure reporter crashed in the one case its floors exist for

`_report()` in `tests/differential/run_differential.py` raised `IndexError` on an **empty corpus** —
before the anti-vacuity summary printed. The run still failed, so there was no false pass; but the reader
saw a traceback instead of the carefully-worded explanation of *why*, in **exactly the gutted-corpus
scenario** the `_MIN_CASES` / `_MIN_DISCRIMINATING_CASES` floors were written to catch.

*A diagnostic that crashes in its own headline case is not a diagnostic.* Fixed, and the reason is now in
the docstring so it is not re-simplified away.

## F11 — A corpus index off by one, in the file that defines what an index means

A docstring cited corpus case **20** as the one containing a space (the case that motivated `_locate()`).
It is case **19**: the docstring was 1-based while `_report` prints `enumerate` output, which is 0-based —
in a file whose entire subject is that **two defensible definitions of the same coordinate silently
disagree**. Corrected, with the 0-based convention now stated explicitly next to the number.

## F12 — "NEVER mutates the tree" was false

`tests/precommit.sh`'s header claimed the gate *"NEVER regenerates a baseline and **NEVER mutates the
tree** — it only reads."* The first half is true and load-bearing. The second was not: the gate invokes
`cargo`, which writes to `rust/target/`.

The correction narrows the claim to what is actually guaranteed — *"never edits a tracked file"* — rather
than deleting it, because the guarantee people rely on is the baseline one and it survives intact.

⚠️ **Related, disclosed rather than fixed:** `rust/target/` currently holds `libregex_automata-*.rlib`
build residue from the measurement recorded in ADR-001 Amendment 1. Re-verified at this commit:
`praetor-core`'s `[dependencies]` is **empty** and `rust/Cargo.lock` contains **zero** `regex` entries —
the dependency is not taken. The residue is only visible to a search that ignores `.gitignore`, and is
noted here so a future reader who runs one does not mistake it for a live dependency.

## F13 — Gate 8 named every failure "DIVERGED"

The differential gate reported any non-zero exit from the runner as a Python↔Rust divergence. But the
runner also exits non-zero when the corpus is too thin to discriminate, when the Rust toolchain is
unreachable, and when the interpreter is missing. **Gating on all of those is correct** — the fix is not
to soften the gate. Naming them all "DIVERGED" sends the reader to the wrong file.

*Fix:* the failure now prints the runner's own output and says how to reproduce it, leaving the runner —
which knows which condition fired — to name the cause.

## F14 — 🔴 This round's own reports were lost, one round after the rule was written

`2026-08-11-preclose-audit.md` opens by explaining that a subagent report dies with the session, and says
that is *why* it was written while the round was still running. **One round later, that was not done.**
All four `.output` files for this round measured **0 bytes** when checked.

The findings themselves survived only because they were acted on immediately and the fixes are in
committed code — which is luck, not process: any finding that had been *rejected*, or deferred, or judged
not worth fixing, would be gone with no trace that it was ever raised. **A rejected finding is the one
most worth keeping**, because it is the one a future round will re-derive from scratch.

⇒ The rule is not "write the audit file." It is **write it as results arrive**, and the failure mode is
that the instruction to do so is itself sitting in a file nobody re-reads mid-round.

## Verified clean (re-derived at `aded477`, not read)

Full gate, run immediately before this file was written:

```
python suite (121 passed, 0 skipped)        self-scan unchanged (12 active / 45 filtered)
rust suite (8 passed, 0 ignored)            public-hygiene sweep (64 shipping files, tracked+untracked)
unicode tables current                      no Claude branding
differential Python<->Rust contract holds   account / SSH-alias remote / branch
```

Tree clean, nothing unpushed. The differential gate's three-way requirement was confirmed by mutation
during construction, not merely asserted: python==contract **and** rust==contract **and** python==rust
directly, because the first two holding while the third fails is precisely the conformance-without-parity
hole that `#[ignore]` was hiding.

## Standing limitations

- **F8's class is not closed, only widened.** The sweep now reads the workspace, but it remains a
  **textual** check over `.rs` files, and `#[cfg(test)]` items and macro-generated builders are still
  invisible to it. Given four consecutive narrowings, the correct prior is that a fifth exists.
- The differential corpus is 23 cases; two implementations can share a bug on a shape it does not contain.
- `MIN_PY`/`MIN_RS` are floors. They catch tests **disappearing**; they cannot catch a test that stays
  present and stops asserting anything.
- Three further findings from this round landed outside this repo — in a private workspace's README, in
  the project memory store, and in process — and are recorded there rather than here.
