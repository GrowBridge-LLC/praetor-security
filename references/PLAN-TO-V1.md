# PRAETOR — the plan to finished

Every item is sized, ordered, and says what "done" means as something you can
run. Written after two research passes that measured the competitive position
rather than assuming it.

**Where we actually are: 4 of 10 roadmap items work. 2 shipped inert. 4 unbuilt.**
Percentages against the v1 bar are in §6.

---

## 0. The three findings that changed this plan

### The incumbents are loud on coverage and measurably bad at accuracy

`MaliciousSkillBench` (9,740 skills, source-disjoint held-out split) published
these, and they are the incumbents' own numbers:

| Detector | Malicious recall | Benign FPR | Macro-F1 |
|---|---|---|---|
| SkillSpector-static (NVIDIA) | **0%** | 0.6% | 0.281 |
| Cisco local behavioural | 2.5% | 1.1% | 0.308 |
| SkillFortify offline | 25.3% | **49.9%** | 0.349 |

The paper's own conclusion: *no evaluated detector achieves both high malicious
recall and low benign FPR across held-out sources.* An independent audit measured
Cisco's MCP scanner at roughly **78% false positives** on tool descriptions.
Snyk's agent-scan publishes **no accuracy numbers at all**.

⇒ **Coverage is a losing axis.** NVIDIA ships 71 patterns and scores 0% recall on
held-out malicious skills. PRAETOR cannot out-pattern NVIDIA and should stop
trying. **Accuracy is the open axis**, and it is the one PRAETOR's entire
engineering investment — `filter_reason`, `lexctx`, `taint`, the pinned
self-scan pair — already points at.

### Adoption comes from being vendored, not from being good

Every comparable tool's inflection was the same shape: **the scanner arrived
without the user choosing it.** Semgrep became GitLab's default SAST analyser.
Trivy replaced Clair as Harbor's default. GitLab's Secret Detection *is* a
Gitleaks wrapper. Docker shipped `docker sbom` on Syft to ~13M users.

Two things the evidence explicitly does **not** support: SARIF has never caused
an adoption inflection for anyone, and no benchmark win drove adoption for any
tool in the sample.

### The cross-file work is real but is not where the malware is

**80.3% of malicious npm packages used no evasion technique at all.** Genuine
cross-file payload splitting is real and rare. The literature contains **no named
algorithm** for detecting it — the research looked and reported the absence
rather than inventing one.

⇒ Build it staged, claim it precisely, and do not let it displace §1.

---

## 1. Ship a release — hours, and it unblocks three dead channels

🔴 **THE HIGHEST-LEVERAGE ITEM IS NOT A BUILD.** Two shipped artefacts are inert
for one reason: nothing to point at.

- The Action installed a package PyPI 404s on. *(Repaired to install from the
  repository, so it works today.)*
- The pre-commit hook needs an immutable `rev:`. `git tag` is empty.

| Step | Who | Blocking |
|---|---|---|
| Register the PyPI pending publisher for `praetor-security` | **owner** | needs your login |
| Tag `v1.0.0` and push | either | needs the above |
| Verify `pip install praetor-security` in a clean venv | agent | |
| Verify the Action green in a throwaway repo | agent | |
| Verify `.pre-commit-config.yaml` at `rev: v1.0.0` runs | agent | |
| List on GitHub Marketplace | owner | self-serve, no review |

⚠️ `praetor` on PyPI already belongs to an unrelated project. The name is a live
risk until registered.

**Done:** three commands run green from a clean machine.

---

## 2. Publish a measured false-positive number — 1–2 weeks

The one axis where PRAETOR can beat NVIDIA and Snyk, and the one they are
conspicuously not reporting.

1. Write an adapter for the frozen `source_disjoint` split. *(The benchmark ships
   no third-party harness — that is our work.)*
2. Publish recall, benign FPR and macro-F1 **beside the incumbents' rows, quoted
   from their source.**
3. Ship the harness so anyone can reproduce it in one command.

⚠️ **Report "needs review" alongside the FP count**, as `CLAUDE.md` already
requires. If FPs fall while needs-review rises, suppression has started eating
real findings — and the FP number alone would look like a triumph at exactly that
moment.

⚠️ **Publish the number even if it is bad.** A tool that reports its own weak
score is more credible than one that reports nothing, and the incumbents report
nothing.

⚠️ Honest caveats to state in the publication: the benchmark is weeks old, has
one GitHub star, and its authors have a tool in the space. It is an opportunity,
not a settled arena.

**Done:** a committed harness, a results table, a one-command reproduction.

---

## 3. SARIF 2.1.0 — 2–4 days

A floor, not a lever. The evidence says SARIF never drove adoption for anyone —
but one artefact reaches GitHub code scanning, GitLab, SonarQube, Azure DevOps
and DefectDojo, and upload is free and self-serve.

The hard half is already done: `fingerprint` is deliberately line-independent,
which is exactly what `partialFingerprints.primaryLocationLineHash` needs.
`Finding` already carries `cwe`, `owasp`, `end_line`, `fix` and `references`.

**Done:** `sarif-multitool validate` passes; alerts appear in a test repo's
Security tab; **a second scan of an unchanged tree opens zero new alerts.**

---

## 4. Cross-file analysis — staged, each stage shippable

The owner's ask: see hidden algorithmic things across long code chains.

**Already landed:** the cross-file *suppression bypass* is closed. A payload split
across two files is no longer reported "provably inert". That was live, and it is
independent of everything below.

| Stage | Technique | Newly catches | Still misses | Cost |
|---|---|---|---|---|
| **Weekend** | two-phase facts extraction; import resolution by **name arithmetic**; trace a sink argument back ≤4 hops to a module constant | payload split across files; import-time execution chains | parameter flow, `getattr`, aliases | ~27s / 5k files, ~140 MB |
| **Month** | bind call arguments to parameters; bounded constant folding (`+`, `.join`, `chr`) | payloads passed as arguments through aliased calls; string fragmentation | loop-built strings, runtime keys | |
| **Quarter** | module-scoped SSA via `symtable`; **`.pth` and `.pyc` admission** | files that execute at interpreter startup and are parsed by no SAST or SCA tool today | | |

🔴 **`importlib.util.find_spec` EXECUTES the parent package.** Measured: importing
`pkg.sub` runs `pkg/__init__.py`. That would break the never-execute invariant, so
**import resolution must be filesystem and name arithmetic only.** `ast.parse` and
`compile` are clean.

🔴 **Do not propagate capability over import edges.** Measured on 2,244 stdlib
modules: self-only flags 141 modules; transitive over import edges flags **1,646
(89%)**. Import edges are not use edges. This is `chains.py`'s `SAME_TREE` lesson
at graph scale. The narrow rule — cross-file payload → sink — produced **zero**
false positives on both stdlib and PRAETOR while catching the planted attacks.

🔴 **ADD-ONLY.** This pass may never suppress, exactly as `chains.py` may not.

**Do not build:** symbolic execution (EXPTIME-complete for k≥1), full IFDS
(path-dependent sanitisers are provably not distributive), points-to analysis
(may-alias is not recursive).

**Never claim "reachable".** Only *not proven unreachable*.

---

## 5. The rest

| Item | Size | Note |
|---|---|---|
| Command-position analysis | month | the right fix for the largest FP class; subsumes several regex heuristics |
| Self-authored SAST rule packs | quarter | removes the proprietary-registry dependency that blocks hosted use |
| Scan provenance in SARIF | days | already in JSON |
| OWASP GenAI Solutions Landscape listing | hours | free, self-serve, moderated |
| Rust port completion | quarter | ⚠️ **deprioritised.** The roadmap's own words: it does not change what PRAETOR can detect. Nothing in the adoption evidence rewards implementation language. |

**Explicitly not doing, with the reason:**
pre-commit.com hooks index (>500 stars required) · CNCF Landscape (300 stars) ·
Homebrew core (225 stars — use a tap instead) · OWASP project status (surrender
the repo for a badge) · OWASP Benchmark (Java; rewards pattern-matchers) ·
`awesome-devsecops` (dead since 2024-05) · **more rules**.

---

## 6. Percentage complete, three honest ways

| Measured against | Complete | What is missing |
|---|---|---|
| **Roadmap items that WORK** | **40%** (4/10) | 2 inert, 4 unbuilt |
| **The v1 bar** — *install in under a minute, point at a repo, get an actionable result* | **~85%** | one PyPI registration. The engines, interpretation and reporting are done and tested. |
| **Competitive parity on the accuracy axis** | **unknown, and that is the finding** | nobody has measured PRAETOR on a public corpus. §2 exists to replace this row with a number. |

⚠️ **The three disagree on purpose.** The v1 bar is nearly met while only 40% of
the checklist works, because the checklist counts Rust-port items its own text
says do not change detection. And the third row is the honest one: *we do not
know how good PRAETOR is*, because nobody has measured it against anything but
itself.

---

## 7. The decision that is not a build task

**AGPL-3.0 may be costing more than it protects.** Legally the position is sound:
running an unmodified CLI in CI triggers nothing in §13, and scanned code is not
a derivative work.

But Google's policy bans AGPL outright, **including workstation installs**, and
many corporate policies are cloned from it. Every widely-CI-adopted scanner
checked is permissive: Semgrep LGPL-2.1; Trivy, Syft, Grype, osv-scanner and
Bandit Apache-2.0; Gitleaks MIT. The AGPL security tools that exist are
self-hosted platforms, not CI CLIs. **Zero AGPL CLI scanners were found in
mainstream CI use.**

The protection AGPL buys is real — a competitor cannot host PRAETOR as a service
and give nothing back, which is precisely the Praetorium model. The cost is a
slice of enterprise adoption, in a plan whose top item is *get adopted*.

**This is the owner's call, and it may outrank item 3 in importance.** It is
recorded here rather than decided.

---

## 8. Order of work

1. **§1 release** — hours, unblocks three channels, needs one login.
2. **§4 weekend stage** — the owner's headline ask, and the bypass half is done.
3. **§3 SARIF** — days, and the hard half is already built.
4. **§2 the FP number** — the differentiator, and the only row in §6 that is
   currently unknown.
5. §5, in the order listed.

⚠️ §1 gates nothing technically and everything practically. Two finished
artefacts are inert until it happens.
