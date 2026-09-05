# PRAETOR — product requirements

The structured specification: who it is for, what it must do, what it must never
do, and how each requirement is verified. Every requirement has an ID so it can
be cited, tested against, and argued with.

**Version 1.1.0.** Status keys: ✅ met · 🔨 committed, not built · 🔬 researched,
undecided · ❌ out of scope with a reason.

---

## 1. Who this is for

| | |
|---|---|
| **Primary** | a developer or security engineer vetting code they did not write — a dependency, a contributor's PR, a plugin, an agent-generated skill, a model checkpoint — **before** running it or granting it access |
| **Secondary** | a CI pipeline that must fail a build on a real finding and, crucially, must **also** fail when the scan could not be trusted |
| **Tertiary** | a hosted dashboard consuming scan output over time |

**Explicitly not for:** proving a codebase secure; replacing review, threat
modelling or penetration testing; finding runtime, logic or authorization flaws.

---

## 2. The invariants — these outrank every other requirement

### INV-1 · PRAETOR never executes, imports, installs or builds the target ✅
No engine, and no external tool it invokes, may run in a mode that evaluates
target code.

> **Verified by** `tests/test_invariant_never_executes_target.py`, which captures
> the argv PRAETOR would hand a subprocess without running it, plus
> `test_it_never_consults_the_import_system` and
> `test_the_reader_touches_no_subprocess`, which poison the relevant modules and
> assert the code path survives.

⚠️ **Violated once.** The SCA path let `pip` resolve requirements, which builds
source distributions and runs `setup.py` from an attacker-controlled tree.
⚠️ **Nearly violated twice more, both caught before shipping:**
`importlib.util.find_spec` executes the parent package; invoking `git` in a
target evaluates that target's config, which can name commands.

**Every new engine or backend widens this surface and must add its own test.**

### INV-2 · A clean scan is `NO FINDING`, never `SAFE` ✅
No output may state or imply that a scanned target is secure.

> **Verified by** the vocabulary itself: a capability reads `present` or `none`;
> `test_absent_capability_reads_none_and_the_summary_refuses_to_say_safe`.

### INV-3 · Suppression fails safe and is always auditable ✅
Unproven means KEEP. A suppressed finding moves to a separate bucket carrying a
written reason; it is never deleted.

> **Verified by** every suppression pass having a mutation-proven keep-direction
> test, and `_lexctx_may_suppress` returning False for any unlisted category.

⚠️ **Never suppress on PATH alone.** Renaming a file must not disarm the scanner.

### INV-4 · Every coverage cap discloses itself ✅
A file PRAETOR did not read says so, in the findings list and in the JSON.

> **Verified by** `tests/test_oversize_files_are_disclosed.py` and
> `tests/test_floors_are_not_disarmed.py`.

⚠️ The one cap that did **not** disclose became a clean scan over a live-shaped
credential.

### INV-5 · Nothing phones home ✅
No telemetry, no licence check, no usage counting, ever — including as a trial
condition. The CLI is uncapped. Commercial value lives in the hosted product.

### INV-6 · A report can never leak a credential ✅
Secrets are redacted at the `Finding` boundary, before anything downstream —
snippet, fingerprint, SARIF — can see them.

> **Verified by** `test_a_fingerprint_cannot_carry_a_credential`,
> `test_a_snippet_in_sarif_is_redacted`.

---

## 3. Detection requirements

| ID | Requirement | Status |
|---|---|---|
| **DET-1** | Credentials: ≥17 anchored provider patterns, connection strings, generic keyword-and-entropy, base64 unwrapping via the provider table itself | ✅ |
| **DET-2** | Prompt injection, including ≥9 languages, role hijack, system-role forgery | ✅ |
| **DET-3** | Hidden content: invisible Unicode, Unicode-Tags smuggling, bidi Trojan Source, ANSI escapes, instruction-bearing HTML comments, homoglyphs | ✅ |
| **DET-4** | Exfiltration: remote-exec pipes, env dumps, DNS, sensitive-file reads, markdown-image beacons | ✅ |
| **DET-5** | Auto-run: agent hooks across ≥7 vendors, git hooks, npm lifecycle | ✅ |
| **DET-6** | MCP manifests: autostart, unpinned source, credentials handed over — by name **and** by content | ✅ |
| **DET-7** | Serialized models: pickle opcodes disassembled, never loaded | ✅ |
| **DET-8** | Known-vulnerable dependencies with advisory IDs and upgrade path | ✅ |
| **DET-9** | SAST across ~30 languages | ✅ |
| **DET-10** | Encoded payloads decoded one level and rescanned | ✅ |
| **DET-11** | **Cross-file**: a payload defined in one file, used dangerously in another | ✅ |
| **DET-12** | Cross-file through a function parameter and an aliased call | 🔨 |
| **DET-13** | Strings assembled from fragments across a chain | 🔨 |
| **DET-14** | `.pth` and `.pyc` admission — files that execute at interpreter startup and are parsed by no SAST or SCA tool today | 🔨 |
| **DET-15** | Command-position analysis: is a token where it would be passed to a program, or is it prose about it? | 🔨 |

🔴 **DET-11 through DET-15 are the "spatial awareness" thread.** Each must obey
INV-1 and be **add-only**. Each must state what it still misses.

⚠️ **Coverage is not the competitive axis.** On the public
`MaliciousSkillBench` held-out split, the largest incumbent ships 71 patterns and
scores **0% malicious recall**. Adding rules is not what is missing from this
field.

---

## 4. Accuracy requirements

| ID | Requirement | Status |
|---|---|---|
| **ACC-1** | Every suppression carries a written, auditable reason | ✅ |
| **ACC-2** | The self-scan is pinned as a **pair** (active *and* filtered), so suppression eating real findings is visible | ✅ |
| **ACC-3** | Every pin move classifies each moved finding by name | ✅ |
| **ACC-4** | **Publish a measured false-positive rate on a public corpus, beside the incumbents' published numbers** | 🔨 |
| **ACC-5** | Report "needs review" alongside any false-positive count | 🔨 |

🔴 **ACC-4 is the highest-value unbuilt requirement.** Practitioners abandon
scanners over false positives — *"the best SAST tool is whichever one your
developers don't turn off"*. The incumbents in this niche publish no accuracy
numbers, and the one independent audit measured a leading MCP scanner at ~78%
false positives. **Publish the number even if it is bad.**

⚠️ **ACC-5 is the control on ACC-4.** If false positives fall while needs-review
rises, suppression has started eating real findings — and the FP number alone
would look like a triumph at exactly that moment.

---

## 5. Output and integration

| ID | Requirement | Status |
|---|---|---|
| **OUT-1** | Human-readable text report, engine status first | ✅ |
| **OUT-2** | Versioned JSON, additive-only within a major | ✅ |
| **OUT-3** | Exit codes distinguishing clean · findings · usage error · **not measured** | ✅ |
| **OUT-4** | `fingerprint` — cross-scan identity surviving a finding moving in its file | ✅ |
| **OUT-5** | Scan provenance: commit, branch, repo, **and the source of that provenance** | ✅ |
| **OUT-6** | SARIF 2.1.0 with `partialFingerprints` | ✅ |
| **OUT-7** | Machine-readable coverage: what the walker refused, and why | ✅ |
| **OUT-8** | SBOM (SPDX / CycloneDX) | 🔬 |

🔴 **OUT-3 is the requirement most often got wrong by consumers.** A consumer
reading only the exit code cannot tell "clean" from "half the engines never ran".
`meta.engines[].status` is the answer, and an unrecognised status word must be
treated as a blind spot, never as a pass.

---

## 6. Distribution

| ID | Requirement | Status | Blocking |
|---|---|---|---|
| **DIS-1** | Install from source | ✅ | |
| **DIS-2** | GitHub Action | ✅ | *(shipped broken; repaired)* |
| **DIS-3** | pre-commit hook | 🔨 | **needs a tag** |
| **DIS-4** | PyPI release via OIDC trusted publishing | 🔨 | **needs the owner's login** |
| **DIS-5** | GitHub Marketplace listing | 🔨 | needs DIS-4 |
| **DIS-6** | OWASP GenAI Solutions Landscape listing | 🔨 | free, self-serve |
| **DIS-7** | Editor / IDE integration | 🔬 | |

⚠️ **DIS-2 and DIS-3 were marked done for a day while both were inert** — the
Action installed a package that 404s, the hook needed a tag that did not exist.
Both were ticked because the FILE EXISTED.
**A requirement is met when a command runs, never when a file is present.**

---

## 7. Non-functional

| ID | Requirement | Status |
|---|---|---|
| **NFR-1** | Zero required runtime dependencies | ✅ |
| **NFR-2** | Every unbounded loop has a disclosed ceiling | ✅ |
| **NFR-3** | No pass may cost more than ~30s per 5,000 files | ✅ |
| **NFR-4** | Reports published atomically — never a torn read | ✅ |
| **NFR-5** | Semantic versioning, enforced across every version source | ✅ |
| **NFR-6** | A CHANGELOG entry per version, leading with what may break | ✅ |

⚠️ **NFR-2 exists because an unbounded pass once hung ~244s on one file** and
produced no artifact and no exit code — so every check keyed on the exit code was
blind to it.

---

## 8. Out of scope, with reasons

| | Why |
|---|---|
| Runtime, logic and authorization flaws | static analysis cannot see them |
| Executing the target to observe it | INV-1 |
| Decoding beyond one level | attacker-chosen nesting to attacker-chosen depth is unbounded work |
| Symbolic execution | EXPTIME-complete for k≥1; state explosion is unsolved |
| Full points-to analysis | may-alias is not recursive; must-alias is not even recursively enumerable |
| Claiming a finding is "reachable" | undecidable. Only *not proven unreachable* |
| A CLI usage cap | requires phoning home — INV-5 |

---

## 9. How a requirement gets marked met

1. It has a test that goes **red** when the thing it protects is disabled —
   mutation-proven, not assumed.
2. The gate passes: `bash tests/precommit.sh`, read the **exit code**.
3. For anything user-facing: **a command was run and its output observed.**

⚠️ Point 3 is not ceremony. Two requirements were marked met for a day on file
existence alone, and both were inert.
