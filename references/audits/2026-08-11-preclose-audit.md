# Pre-close audit — 2026-08-11

**Scope:** the session's *closing* delta — commits `5a82e93..3b19d3b` (`cd2ab19`, `3b19d3b`), the
session's authored prose across all 10 commits, the project memory store, and the conversation
transcript.
**Method:** four independent auditors with **zero prior context**, dispatched in parallel, each told to
verify against ground truth — real `git`, real test runs, real mutations — and explicitly *not* against
the prose of the work under review.

> **This file is written as results arrive, not afterwards.** A subagent's report lives in a
> session-scoped temp directory and dies with the session; a finding that exists only in a summary
> cannot be re-checked. One of the auditors below raised exactly this risk, which is why this file
> exists before the round finished.

## F5 — 🔴 The correction outran the artifact, in the post reporting on that class

Two false claims in a status post this session made to a private coordination channel outside this repo, found by the
slop audit and confirmed against ground truth:

1. **"One dependency was taken — the `regex` crate."** It was not.
   `rust/praetor-core/Cargo.toml` has an **empty** `[dependencies]`, and `rust/Cargo.lock` has zero
   `regex` entries. This repo's own `ADR-001-engine-language.md` Amendment 1 says so explicitly: *"The
   dependency is **not yet in `Cargo.toml`**. It was added to measure the above, then reverted."*
   **Decided is not taken**, and the post asserted the stronger one to an external audience.
2. **"64 tests, the self-scan and code review all passed over it."** That figure had been retracted from
   every in-repo artifact in commit `f0b3ad2` — because **no commit in history shows 64** — and the post
   republished it **13 minutes later**, to readers who will never see the retraction.

*Fix:* that channel is append-only, so a correction was appended there rather than
the original edited. Nothing in this repo required changing: the in-repo artifacts were already correct,
which is precisely why the error was invisible — **the divergence was between the repo and the story
told about it.**

*Half the finding was rejected.* The auditor also read *"on Mike's word"* as unsupported, because ADR-001
does not attribute Amendment 1 to the decision-maker. Ground truth says otherwise — the authorization was
given directly — so the **ADR is what is incomplete**, not the post. Recorded because the discipline
generalises: **a subagent finding is evidence to re-derive, never a verdict to apply**, and that must cut
in both directions or it is just deference with extra steps.

### Why F5 matters more than its content

It is the **third recurrence of one class in a single session**, each one hop further from where the
class was learned:

| | where the claim outran the artifact | found by |
|---|---|---|
| F1–F3 | in the **code** — three guards | audit 1 |
| F4 | in the **fix** for one of those guards | audit 2 |
| F5 | in the **post reporting the fixes** | audit 3 |

⇒ **The artifact you are least likely to audit is the one describing your audit.** Each round was written
by an author who had just read the previous finding, understood the class, and was actively trying not to
repeat it.

## F6 — A commit count asserted three times, wrong in all three

The memory audit re-derived `git rev-list --count 3b6008b..HEAD` and got **10**. The session's handoff
and its index both said **11**, in three places. Off by one, in the direction that flatters — and stated
as a verified fact in the artifact a fresh session reads first.

*Fix:* corrected in all three sites, with the replacement performed by a script that **fails loudly on a
non-match** rather than a silent string substitution (a class this project has hit four times). An
intermediate figure of "9 commits" was left in place but relabelled *"9 commits at that point (10 by
close)"* — it was accurate when written, and the handoff now carries a banner telling readers the
narrative is chronological and only the final block is current.

📌 **Not fixable, so disclosed instead:** commit `51657ef`'s subject reads *"praetor-core **takes** the
regex crate."* Its body is accurate — it says plainly the dependency is not in `Cargo.toml` — but the
subject line is the same overstatement as F5, and subjects are what people read. It is pushed to a public
repo and **this project does not rewrite history**, so it stands as written.

## F7 — 🔴 The same guard, defeated three more ways, and its disclosure was the problem

The fact-verification pass attacked `cd2ab19`'s repaired sweep counter (itself the fix for F2, which was
the fix for the original comment). **Three further evasions, every one confirmed by mutation, every one
leaving the Rust suite 8/8 green with a builder containing the literal `"install"`:**

| evasion | why it works | plausible by accident? |
|---|---|---|
| builder **not named** `*_argv` (`npm_command`) | the guard matched the *name* | yes — a name is a promise you can forget to make |
| builder in a **different file** (`npm.rs`) | `include_str!("sca.rs")` reads exactly one file | yes — a new backend is a natural new module |
| **attribute on the same line** (`#[allow(dead_code)] pub fn x_argv(`) | first-token logic | yes |

The auditor also observed, correctly, that the check compared **counts** rather than asserting **set
membership** — a proxy that two cancelling errors would satisfy.

**The finding is the disclosure, not the holes.** The comment named *macro-generation* as its known gap —
the rarest of the four, and the only one a contributor would have to go out of their way to hit — which
made the enumeration read as exhaustive while omitting the three easy ones. **An incomplete "known gaps"
list is worse than none**, because it converts an unexamined mechanism into an apparently examined one.

*Fix:* the cross-file hole is **unfixable in Rust** — `include_str!` needs a literal path and enumerating
the directory at compile time requires a `build.rs`, which this crate refuses on the never-execute
principle. So the enforcement moved to `tests/test_rust_sca_argv_sweep.py`, which reads the crate
directory, keys on the **`-> Vec<String>` signature** rather than a name, and asserts **set membership**
in `all_argvs()`. The Rust test is retained as a fast in-language check and its comment now says plainly
that it is not the guarantee.

*Mutation-proven, both directions:* a builder in `npm.rs` → red, naming file and function; `npm_command`
+ `#[allow(dead_code)] pub fn npm_attr_argv` → red, naming both; the Rust suite **stayed green under the
same mutation**, which is the evidence that the two checks are complementary rather than redundant. Clean
tree → 80 Python + 8 Rust, green.

*A carve-out was introduced and is stated rather than silent:* `#[cfg(test)]` modules are excluded,
because a test-only item is never compiled into the shipped binary and so cannot construct an argv
PRAETOR runs. That is a structural property of the build, not a path heuristic — but it **is** a
carve-out, and a builder hidden inside a test module is invisible to the guard.

⚠️ **Two implementation traps hit while writing this guard, both previously recorded in this repo:**
brace-matching to find the test module silently failed (`text.rs` contains `\u{2028}` escapes inside
string literals, so its raw brace counts are 36 vs 34 and never balance) — replaced with a line-structural
match; and the docstring describing that needed `r"""`, or Python reads `\u{2028}` as a broken escape.

## Verified clean (independently re-derived, not read)

The slop audit re-derived and confirmed, at the time it ran: Python **77** tests, Rust **8** tests,
self-scan **12 active / 45 filtered**. (Python is **80** after F7's guard was added; the self-scan is
unchanged.) all four of F1–F4 genuinely fixed in code, including that
`every_argv_builder_in_this_file_is_swept` strips visibility modifiers and matches on function name
rather than a line prefix; `lib.rs`'s corrected status claim; ADR-001's measured figures (**22**
`re.compile` in `aisec` + **25** in `secrets` = 47, counted directly); the differential corpus at **23**
cases; the CVE-2026-53753 rule present in the *shipped* ruleset; the osv-scanner status-honesty branch;
the vendor-neutral hook-event regex; the homoglyph detector's scope; and that README / ARCHITECTURE /
LIMITS / CHANGELOG agree with each other, with the ADR, and with the actual `rust/` tree.

The transcript audit confirmed every user instruction in the session was answered, and that the
handoff and memory store accurately capture the four rulings, both measurements, the Rust
authorization (including that it arrived **relayed through the channel**, not typed directly), the
regex decision with its measured cost, and the "unanswered ≠ unauthorized" self-correction.

⚠️ **One transcript finding was a timing artifact and is recorded as rejected**, so it is not
rediscovered later: it reported that this audit round was "dispatched but never read." It read the
transcript *while the auditors were still running*, so the transcript necessarily ended at the
dispatch. The findings were read and acted on — this file is the evidence. **Its underlying warning was
adopted anyway**, and is why this file was written during the round rather than after it.

## Standing limitations

- The differential corpus covers 23 cases; two implementations can still share a bug on a shape it does
  not contain, and the comparison keys on location so it cannot detect description drift.
- `every_argv_builder_in_this_file_is_swept` is a **textual** check. It now catches every visibility
  modifier and split signatures, and it states that macro-generated builders remain invisible to it —
  but an incomplete "known gaps" list reads as exhaustive, so treat that disclosure as a starting point,
  not a guarantee.
