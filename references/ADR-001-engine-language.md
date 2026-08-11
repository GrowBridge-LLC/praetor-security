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
   baseline, and a live `pip install praetor-security` — plus a long window in
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

- Python remains shipped and remains the reference implementation until parity.
  `pip install praetor-security` must keep working throughout.
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

## What this decision does NOT authorise

It authorises the **port**. Nothing else. In particular it says nothing about any
other project's language choice, and it is not a licence to rewrite working code
elsewhere to match a preference.
