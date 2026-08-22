# ADR-001 — PRAETOR's engine is ported to Rust

**Status:** ACCEPTED, 2026-08-10. Port authorised; not yet started.
**Supersedes:** nothing. **Superseded by:** nothing.

## Decision

PRAETOR's engine is ported from Python to Rust, incrementally, under four binding
conditions (below). The Python implementation stays shipped and stays the
reference until the Rust one reproduces its output exactly.

## Context

A project-wide ruling made Rust the default language. "Default" flips the burden
of proof: the question is no longer *"why Rust here?"* but **"why NOT Rust
here?"**, and the answer must be **named**, not assumed.

That ruling explicitly did **not** mandate rewriting working code — rewriting
working code is a recognised failure mode, and a port is a build: it gets a row,
an owner, an acceptance test, and a reason. This document is that reason.

## 🔴 The counter-argument, which lost — recorded because it is what makes this reversible

**This section is not a dissent to be tidied away.** *Every durable rule carries
the failure that bought it* is a **retirement precondition**: a decision with no
recorded counter-argument becomes immortal, because no future session can
re-test what it was never told the decision was weighed against.

The case for an exception was:

1. **The port buys nothing on the dependency story that motivated the default.**
   PRAETOR's value is orchestration: `sast` shells out to Semgrep (Python), `sca`
   to `pip-audit` (Python) and `osv-scanner` (Go). **A Rust PRAETOR still shells
   out to a Python Semgrep.** The subprocess boundary — and therefore the
   dependency burden on the user — is unchanged by the host language.
2. **The measured failures Rust was reasoned about did not include the ones
   actually occurring.** The dominant defect classes were enumeration errors and
   correction-propagation failures. Rust addresses neither.
3. **Cost:** ~2,900 working lines, a green suite, a committed regression
   baseline, and a packaged distribution — plus a long window in
   which PRAETOR exists as **two implementations**, which is the
   "two copies with no propagation path" defect in the one repository where a
   divergence means *a scanner that reports differently depending on which binary
   you ran*.

**This was put to the decision-maker and the ruling was Rust regardless.** The
objection did not prevail; it is preserved so that a future session with new
evidence can reopen the question honestly rather than rediscover it.

📌 **Condition 3 below is the direct answer to objection 3** — see the note there.

## The four conditions — binding, not advisory

| # | Condition | Why |
|---|---|---|
| 1 | **`aisec` ports first** | Pure pattern matching, zero external tool dependencies, and it is the engine with no equivalent elsewhere. `sast`/`sca` stay orchestration wrappers and move last. |
| 2 | 🔴 **The never-execute invariant test ports FIRST — before the backend it guards** | `tests/test_invariant_never_executes_target.py` asserts PRAETOR's foundational property behaviourally. **No Rust backend merges before its invariant test does.** A Rust `sca` backend whose argv omits `--disable-pip` reintroduces arbitrary code execution from an attacker-controlled tree; *every new backend widens that surface*, and a Rust backend is a new backend. |
| 3 | **Acceptance is DIFFERENTIAL, not "the tests pass"** | Both implementations run the same corpus and must emit **identical `(engine, rule_id, file, line)` sets.** ⚠️ **This is what dissolves objection 3:** a differential harness *is* a propagation path, so two implementations under continuous reconciliation are a pair, not a fork. ⇒ **The two-implementation window is acceptable ONLY while that harness is green and blocking. If it is ever skipped, the fork becomes real that day.** |
| 4 | **`references/SELF-SCAN-BASELINE.json` is the regression floor for both** | 🔴 Never regenerate it to reflect an improvement; it is the committed "before". |

### ⚠️ The corpus condition — subtle, and easy to satisfy vacuously

The differential corpus **must include the cases the Python engine currently
MISSES** — at minimum `.cursor/hooks.json`-shaped agent hook configs and
extensionless instruction dotfiles.

**Otherwise "identical output" is satisfied by two engines that are identically
blind, and the port certifies the existing hole into a second language.** A
differential harness compares implementations against each other, never against
the truth; its corpus is the only place truth enters.

## Consequences

- Python remains the reference implementation until parity, and remains the only
  implementation a user can run. Installation from source must keep working
  throughout.
  📌 Nothing is published to PyPI; the packaging metadata exists but no release has
  been made. Any statement here about an install channel means installing from the
  repository.
- The JSON contract (`schema_version`) is the interface both implementations
  satisfy; it is what the differential harness compares.
- **Toolchain (verified 2026-08-10):** `rustc` / `cargo` 1.97.1, host
  `x86_64-pc-windows-msvc`, with MSVC Build Tools already installed. **Windows is
  therefore the native build target from day one**, which matters more than it
  looks: PRAETOR is public and cross-platform, and a port developed only under
  WSL would risk an engine that does not build for Windows users — precisely the
  platform where PRAETOR's Semgrep dependency already fails.

  ⚠️ **`cargo` is NOT on Git Bash's `PATH` on this machine** even though it is
  installed and on the Windows `PATH`. An earlier check concluded "no toolchain"
  from a bare `cargo --version` in Git Bash and was wrong. Prepend
  `$HOME/.cargo/bin` (or verify with `where.exe cargo`) before concluding a
  Windows tool is absent.

## Amendment 1 (2026-08-10): `praetor-core` takes the `regex` crate

**Superseding the "zero dependencies" property of `praetor-core`, with the bar it
must clear stated first**, because a dependency budget nobody wrote down is a
budget that only ever loosens.

> **The bar:** a dependency is justified only when writing it ourselves would be
> *worse for security*, not merely slower to build. Convenience is not a reason.

**Why this one clears it.** The remaining engines are regex-driven — `aisec`
carries 22 compiled patterns and `secrets` 25 — and Rust's standard library has
no regex. The alternatives were:

| Option | Verdict |
|---|---|
| Hand-write a matcher | **Worse for security.** A bespoke regex engine inside a scanner is new, unaudited parsing code running against attacker-controlled input. This is exactly the case the bar exists to catch. |
| Restructure 47 patterns into non-regex matching | Changes matching behaviour, so it breaks differential parity **by construction** — the one property that makes the port checkable. |
| Take `regex` | Adopted. |

**Measured cost, not asserted (2026-08-10):**

- **5 crates total**: `regex`, `regex-automata`, `regex-syntax`, `aho-corasick`,
  `memchr`. All from the same maintainer lineage as `ripgrep`, and among the most
  widely deployed Rust code in existence.
- 🔴 **No `build.rs` anywhere in the tree** — nothing executes at build time. For
  a tool whose central invariant is *never execute the code it scans*, a
  dependency that runs arbitrary build scripts would be a contradiction, so this
  was checked rather than assumed.
- No C/system libraries, no network, no transitive tree beyond those five.
- Workspace builds clean and the existing tests stay green with it present.

**Compatibility, checked before committing to it:** Rust's `regex` is a
finite-automata engine and does **not** support backreferences or lookaround.
All 47 Python patterns were swept for `(?=`, `(?!`, `(?<=`, `(?<!` and `\1`-`\9`:
**none use any of them.** Every pattern is therefore truly regular and expressible
without rewriting its semantics.

⚠️ **A benefit worth naming, and a claim deliberately NOT made.** Rust's engine
guarantees linear-time matching; Python's `re` backtracks and can blow up on
hostile input, which matters because PRAETOR runs these patterns over
attacker-controlled files. **This has not been tested against PRAETOR's actual
patterns, so no live ReDoS is claimed here** — it is a property of the engine,
recorded as a reason the port may end up *safer* than the reference, and left as
an open question against the Python side.

📌 The dependency is **not yet in `Cargo.toml`**. It was added to measure the
above, then reverted, so it lands in the same change as the code that uses it
rather than sitting unused in the manifest.

## What this decision does NOT authorise

It authorises the **port**. Nothing else. In particular it says nothing about any
other project's language choice, and it is not a licence to rewrite working code
elsewhere to match a preference.

## Amendment 2 (2026-08-22): `praetor-core` takes `base64`, and `secrets` ports before `aisec`

**One decision with two parts, recorded together on purpose.** Ruling them separately is how the
premise below went stale in the first place.

### Part A — the `base64` crate is authorised

`scripts/engine_secrets.py` calls `base64.b64decode(blob, validate=True)` and inspects the decoded
bytes for markers. Rust's standard library has no base64 decoder.

Applying Amendment 1's bar — *a dependency is justified only when writing it ourselves would be
worse for security, not merely slower to build*:

| Option | Verdict |
|---|---|
| Hand-write a decoder | **Genuinely borderline, and this record says so rather than pretending otherwise.** Base64 is a fixed alphabet with no recursion and no state machine, so it is far less dangerous to write than a regex or JSON parser, and in Rust its failure mode is mis-decoding rather than memory corruption. It is still bespoke parsing of attacker-controlled input. |
| Take `base64` | **Adopted, by the operator's own decision 2026-08-22.** |

⚠️ **The bar did not decide this one on its own, and the honest record of a marginal call is more
useful than a manufactured justification.** Amendment 1's regex case was clear-cut; this one was not,
and it was escalated rather than absorbed. **A future crate does not inherit this outcome — it gets
its own decision, exactly as Amendment 1 requires.**

### Part B — the port order changes: `secrets` first, `aisec` deferred

🔴 **Condition 1's stated premise is FALSE and has been for some time.** It orders `aisec` first
because it is *"pure pattern matching, zero external tool dependencies."* It is not:
`scripts/engine_aisec.py:28` imports `json`, and `_scan_mcp` at :552 calls `json.loads`, then
`isinstance(data, dict)`, then `data.get("mcpServers")` — structural parsing of attacker-controlled
MCP manifests.

`secrets` is 25 regex patterns plus base64, so it now fits condition 1's *rationale* better than
`aisec` fits its own *name*. The ordering follows the reason, not the label.

**`aisec` is DEFERRED, not cancelled.** Porting it requires a JSON parser, which is a separate
dependency decision that has NOT been made and must not be assumed to follow from Part A. A bespoke
JSON parser inside a scanner is new, unaudited parsing code running against attacker-controlled
input — the case Amendment 1's table exists to catch — so that decision genuinely matters.

**Condition 2 is unchanged and still binding:** no Rust backend merges before its never-execute
invariant test does. `rust/praetor-core/src/sca.rs` exists for exactly that reason and is argv
construction only, never execution.

### How the stale premise was found

The builder was assigned the port and refused it, twice: first because the assignment named the wrong
engine against condition 1, then because condition 1's own premise did not survive contact with the
code. Neither was caught by review of the ADR — both were caught by someone trying to execute it.
⇒ **An ADR's premises rot exactly like any other measured claim, and the ordering it derives from
them rots with them. Re-derive a condition's REASON, not just its instruction.**
