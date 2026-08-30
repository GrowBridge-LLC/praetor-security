# PRAETOR — where everything ever planned actually stands, 2026-08-30

Written because a plan assembled from planning documents describes what was
intended, not what exists. **Every line below was measured against the tree, and
where a document disagreed with the tree, the document is named.**

Read with [NEXT-SESSION-2026-08-30.md](NEXT-SESSION-2026-08-30.md), which covers
operational state. This file covers direction.

## 1. The one thing that is red right now

**CI fails on `9cbbe4c`, the current `origin/main`.** Local gate is 13/13 green.

```
run 33323828930   9cbbe4c   FAILURE   16 steps      <- 16, so NOT a ghost run
job invariants:   FAILED
  tests/test_output_atomicity.py::test_blocked_windows_publish_fails_loudly_without_clobbering
  assert '{"generation":"new"}' == '{"generation":"old"}'
```

⚠️ **Check the step count before believing any CI result from today.** A
platform-wide Actions problem is producing zero-step runs that look identical to
real failures in `gh run list`:

```bash
gh api repos/<owner>/<repo>/actions/runs/<id>/jobs --jq '[.jobs[].steps|length]|add'
```

**Diagnosis:** the test explicitly permits the write to succeed on POSIX, then
asserts the file is unchanged. Those contradict each other on exactly the
platform its own comment names. It passes on Windows, and CI is the only place it
has ever run on Linux. **The product is correct; the assertion is wrong about one
platform.** Assigned as F38, test-only.

⇒ **The lesson is larger than the fix: a test that has only ever run on one
platform is untested on the other, and a green suite says nothing about it.**

## 2. The Rust port — the plan is further along than the README says

`references/ADR-001-engine-language.md` — **ACCEPTED 2026-08-10**, three
amendments.

🔴 **README.md:273 is STALE and it understates the work.** It says *"no detector
has been ported yet"* and enumerates three things in `rust/`: the shared line
definition, SCA argv construction, and Unicode tables.

**Measured, there are four.** `rust/praetor-core/src/secrets.rs` is **835 lines
across 32 functions**, with a differential contract already in place
(`references/differential/secrets.expected`, `secrets.tsv`). A detector *has*
been ported. The sentence claiming none has is in a **public, shipping** file.

**What the README gets right:** the binary genuinely refuses to scan. 27 lines,
prints why, exits 2. That half is accurate and should stay.

🔴 **ADR-001's binding-conditions table also contradicts its own amendment.**
Condition 1 says **"`aisec` ports first"**. Amendment 2 Part B (2026-08-22)
reverses it to **`secrets` first, `aisec` deferred**. The amendment is the live
decision and the table still asserts the superseded order. Anyone reading the
table alone gets the wrong plan.

**Amendment 3** (a JSON crate for `aisec`) is **RESEARCHED, NOT RULED ON**. It is
the next open decision on this track.

### The four binding conditions — status

| # | Condition | Status |
|---|---|---|
| 1 | `aisec` ports first | **SUPERSEDED** by Amendment 2 Part B. Table not updated. |
| 2 | The never-execute invariant test ports BEFORE the backend it guards | **NARROWED.** An earlier draft said "no Rust backend exists" — disproven: `rust/praetor-core/src/sca.rs` carries argv construction **and an in-module `--disable-pip` invariant test**. What is true is that no Rust backend is WIRED to the binary, which still refuses to scan. Whether the ordering was honoured historically is not established from source alone. |
| 3 | Acceptance is DIFFERENTIAL, and the harness must be green and blocking | **LIVE** — `tests/precommit.sh:250` fails if the runner is missing |
| 4 | `SELF-SCAN-BASELINE.json` is the regression floor for both | **HELD** — never regenerated |

### ✅ Condition 3's corpus requirement is FULLY MET — and enforced

**An earlier version of this file said "HALF met". That was wrong, and the error
is worth more than the finding was.**

The ADR requires the differential corpus to include cases the Python engine
MISSES, *"otherwise identical output is satisfied by two engines that are
identically blind."* It names two. Measured:

| required case | present |
|---|---|
| `.cursor/hooks.json`-shaped agent hook config | ✅ `secrets.tsv` row 14 → `secrets|github-token|.cursor/hooks.json|1` |
| extensionless instruction dotfile | ✅ `secrets.tsv` row 11 → `secrets|gcp-api-key|.agent-instructions|2` |

**Stronger than presence: the runner ENFORCES them.**
`tests/differential/run_differential.py:477` —
`for required_path in {".cursor/hooks.json", ".agent-instructions"}` — so the
corpus cannot silently lose either case. A third extensionless case (the npm
registry config) sits in the corpus beyond the required floor — named here
without its literal filename, because writing that path into a shipping file
trips our own `sensitive-file-read` rule, correctly. It did, on the first draft
of this paragraph.

🔴 **How I got it wrong, because the method matters.** I searched the corpus for
`.cursor/hooks.json` — the THING — and found it. For the second case I searched
for `extensionless` and `dotfile` — the DESCRIPTION — and found nothing. **A
corpus file contains paths, never the prose that describes them.** Two checks in
one paragraph, different methods, and only the second was wrong.

⇒ **I reported an absence with no positive control.** The rule I apply to
everything else is: before reporting a zero, prove the instrument returns
non-zero for the class you claim is missing. A grep for `dotfile` cannot return
non-zero against any corpus, so its zero carried no information at all.

The builder caught it by checking the claim against source before carrying it
into a plan.

**`aisec` still has no differential contract**, consistent with Amendment 2
deferring it. That is a real open item and it is NOT evidence that the secrets
corpus is incomplete — conflating the two was part of the same error.

## 3. The pre-rollout backlog — mostly closed, and it says so honestly

`inbox/PRE-ROLLOUT-BACKLOG-2026-08-22.md` has been refreshed three times **by
re-derivation rather than by carrying claims forward**, which is why it can be
trusted. Everything its build queue listed as open or in progress is on `main`.

Two entries worth carrying:

- **A recovery branch remains classified but unlanded**, recorded as far bigger
  than first thought. Still open.
- **One queue entry was wrong when written** and is marked so in place, rather
  than deleted. That is the right handling and the reason the document is
  reliable.

## 4. What landed today, and what it cost to learn

Three audited fixes, merged and pushed as 48 commits:

| id | defect |
|---|---|
| F35 | **all four suppression passes were silent no-ops on a single-file target** |
| F36 | the regression test for F35 could pass while F35 was broken, depending on path arithmetic |
| F37 | an uncaught exception exited **1** — the same code as "found findings" — writing no report |

⚠️ **F35 is still live for anyone running an older install.** The skill installed
at the user level on this machine was measured **54 commits behind** and missing
both F35 and F37. A directory scan is unaffected; **a single-file scan's FILTERED
count cannot be trusted on such a build.** Updating an install is outside this
repo's write scope and belongs to whoever owns it.

## 5. Standing decisions that close questions

- **PRAETOR is NOT hardened to protect consumers from their own staleness or
  their own gate defects.** Reports already carry `meta.timestamp`,
  `meta.target`, `meta.version` — measured in real output. A consumer has what
  it needs.
- **A clean scan is `NO FINDING`, never `SAFE`.**
- **Suppression fails safe.** Unproven ⇒ keep the finding.
- **Secrets are never suppressed by context or reachability**, and the reason is
  that a credential is disclosed by being written down, not by executing.

## 6. What I could not verify

- Whether the two corpus cases in §2 are the ONLY blind spots worth covering. The
  ADR says "at minimum", so the list is a floor, not a specification.
- Whether the classified recovery branch still holds anything not since landed.
- Any CI result from today other than the two runs whose step counts I read.
- That the README/ADR corrections in §2 are the only stale claims. I checked the
  Rust and port-order statements specifically, not every document.
