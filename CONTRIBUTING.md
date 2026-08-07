# Contributing to PRAETOR

Contributions welcome. PRAETOR is a security scanner, so the bar for a change is
a little different from an ordinary tool: **the failure mode here is a scanner
that reports "nothing found" while something is there**, and that failure is
silent.

Read [`CLAUDE.md`](CLAUDE.md) before changing detection or suppression logic. It
is written for both humans and AI agents and covers the reasoning that is easy to
get wrong — particularly why secrets are exempt from context-based suppression.

## Setup

```bash
git clone https://github.com/GrowDev1/praetor-security
cd praetor-security
pip install -e ".[dev]"
python -m pytest tests/ -q
```

Optional engines (`semgrep`, `osv-scanner` / `pip-audit` / `npm`) are not needed
to run the test suite — the tests capture subprocess arguments rather than
executing anything.

## The three rules that matter most

**1. Never execute, import, install or build the scanned target.** This is the
whole promise of the tool and it has been broken once. If you add an engine or a
backend, add a test to `tests/test_invariant_never_executes_target.py` that
asserts its argv, and never invoke a package manager in a mode that resolves or
builds from the target tree.

**2. Suppression must fail safe and carry a reason.** Anything not *proven* inert
is kept. Findings are moved to a FILTERED bucket with a stated `filter_reason`,
never dropped. And never suppress on file path alone — an earlier predicate did
that and hid a real credential.

**3. Prove your test can fail.** After adding a guard, change the real code it
protects and confirm the *named* test goes red, then restore. A green suite proves
nothing until you have seen it red. Assert both directions: what must be
suppressed, and what must be kept.

## Adding a detection rule

- Put a fixture in `references/test-corpus/_generate_corpus.py` rather than
  committing a real payload.
- **Assemble attack strings and credential-shaped tokens from parts** (`"curl x | "
  + "sh"`), or your own test file becomes a finding in the next self-scan. This
  happens reliably; it is not a hypothetical.
- Re-run the self-scan afterwards:
  ```bash
  python scripts/praetor.py . --no-registry
  ```

## Reporting a false positive

Open an issue with the smallest snippet that reproduces it, the rule ID, and
whether the match was in live code, a comment, a docstring, or documentation.
That last detail decides which pass should have caught it.

## Reporting a vulnerability

Please report security issues affecting PRAETOR itself privately through GitHub's
security advisory flow rather than a public issue.

## Pull requests

Keep them focused, include tests, and say in the description what you mutated to
prove the tests fail. If a change alters what gets suppressed, say how you
verified it does not suppress anything real — and do not regenerate
`references/SELF-SCAN-BASELINE.json`, which is the committed "before" that makes
such a claim checkable.

Licensed under MIT; contributions are accepted under the same terms.
