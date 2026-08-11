# Pending rules — written, NOT yet verified against a positive control

Rules here are **not shipped**. `scripts/engine_sast.py` loads
`rules/semgrep-praetor.yaml` only; nothing in this directory reaches a scan.

## Why this directory exists

Semgrep validates a `--config` file **as a unit**. A single rule with invalid
pattern syntax makes semgrep reject the *entire* file — so one unverified rule
would take the other fourteen down with it, for exactly the `--no-registry`
users that commit `8acf61f` exists to serve.

`tests/test_bundled_ruleset_is_wellformed.py` checks **structure** and cannot
substitute: it will pass a rule that parses cleanly and matches nothing. A rule
that has never fired against a positive control is not coverage — it is a silent
no-op that looks like coverage.

## Promotion criteria

A rule leaves this directory when **both** controls have been run:

```bash
# 1. POSITIVE control — must produce a finding
semgrep --config rules/pending/<rule>.yaml path/to/vulnerable_fixture.py

# 2. NEGATIVE control — must be silent
semgrep --config rules/pending/<rule>.yaml path/to/safe_fixture.py

# 3. and the shipped ruleset must still LOAD with the rule appended
semgrep --config rules/semgrep-praetor.yaml --validate
```

Then move the rule into `rules/semgrep-praetor.yaml` and commit the fixtures.

## Current contents

**Empty.** That is the intended steady state — a rule should sit here only while
it is waiting on verification.

## Worked example (2026-08-10)

The CVE-2026-53753 rule (Crawl4AI, CVSS 9.8 — an AST sandbox whose attribute
denylist blocked only leading-underscore names, so `gi_frame` / `f_back` /
`cr_frame` walked out to `f_globals`) was staged here rather than shipped,
because semgrep would not run on the authoring machine.

It was later verified on WSL with semgrep 1.172.0 and promoted into
`rules/semgrep-praetor.yaml`:

```
positive control -> 1 finding
negative control -> 0 findings
semgrep --validate on the full shipped file -> valid, 15 rules, 0 errors
```

📌 **The third line is why the staging was worth it, and the result does not make
it unnecessary.** The pattern turned out to be valid — but that was not knowable
in advance, and an invalid one would have broken all fourteen other rules for
every `--no-registry` user. The cost of staging was a few minutes; the cost of
being wrong was the whole offline baseline.
