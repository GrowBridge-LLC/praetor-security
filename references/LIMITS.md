# PRAETOR - Limits and Residual Risk

PRAETOR is a high-signal aid, **not** a proof of security. A security tool that
oversells itself is worse than none, because it manufactures false confidence.
This document states plainly what PRAETOR cannot do. Read it before acting on a
"clean" result.

## The one rule

**A clean scan means "nothing matched these rules," never "this code is safe."**
Absence of a finding is not evidence of absence of a vulnerability. Treat every
finding as a lead to verify, and every clean result as an incomplete negative.

## Structural limits (true of the whole tool)

- **Static analysis only.** PRAETOR never runs the target. It cannot find
  runtime-only bugs, logic errors, broken business-authorization, race
  conditions, or anything that only manifests during execution.
- **No inter-file dataflow / taint tracking** in the built-in engines. They work
  line- and file-locally. Semgrep adds intra-file dataflow for its rules, but
  whole-program taint analysis is out of scope.
- **Allowlisted text/source files only.** The walker opens files whose extension or
  extensionless name is in PRAETOR's `TEXT_EXTS`/`TEXT_NAMES` allowlists. Compiled
  binaries, images, archives, and ordinary text-like formats outside those lists
  (for example `.csv`, `.log`, `.jsonl`, `.ndjson`, `.har`, or `.out`) are skipped.
  The exclusion list is not exhaustive and may change as formats are measured;
  a clean result is not evidence that an unlisted format was read. A secret or
  payload inside a binary blob will not be seen (except the specific base64-unwrap
  case).
- **Files above the size cap** (default 3 MB) are skipped; large minified bundles
  or data files may hide issues.

## Per-engine limits

### secrets
- **Denylists are never exhaustive.** New, rotated, or vendor-specific token
  formats not in the provider list will be missed unless entropy catches them.
- **Entropy trades recall for precision.** The generic/entropy detector is tuned
  to avoid drowning you in false positives, so it will miss low-entropy or
  cleverly-formatted secrets. Conversely, some high-entropy non-secrets (novel
  hash/ID formats) may still surface as LOW-confidence findings.
- It flags a secret's **presence in text**; it does not verify the credential is
  live, nor that it has not already been rotated.

### sast (Semgrep)
- **Coverage equals the active ruleset.** The bundled rules plus the default
  registry packs are good but finite. A vulnerability class with no matching rule
  is invisible.
- Registry packs require **network access** on first run (results are cached).
  Offline mode (`--no-registry`) runs only the bundled baseline - fewer rules.
- Some registry rules are Semgrep-Pro-gated; unauthenticated runs may have reduced
  depth for those specific rules.

### sca
- Sees only **declared dependencies in supported lockfiles/manifests**, checked
  against known-advisory databases (OSV / GHSA / PyPI). It cannot see vendored,
  dynamically-loaded, or system dependencies, and it cannot find **zero-days** (by
  definition unlisted).
- Advisory data changes daily; a "clean" result is only as current as the
  database at scan time. Re-scan regularly.
- Severity for advisories lacking both a label and a CVSS vector defaults to
  MEDIUM - a reasonable placeholder, not a judgment of true impact. (pip-audit's
  default output carries no severity, so its findings default to MEDIUM.)

#### SCA dependency-tool boundary (what the backends do to the target)
- The SCA engine is the only one that invokes an **external tool** as a
  subprocess. Those tools are **static** with respect to the target's code:
  osv-scanner reads lockfiles; **pip-audit runs with `--disable-pip`**, which
  forbids pip from resolving or **building** the requirements -- so no
  attacker-controlled `setup.py`/PEP517 backend is executed. `--no-deps` alone
  does NOT provide this; `--disable-pip` is what makes the scan safe against a
  hostile `requirements.txt`.
- `--disable-pip` requires **fully-pinned** requirements. If a `requirements.txt`
  is unpinned/unresolvable, PRAETOR reports SCA `status: error` (results
  incomplete) and **never** falls back to a resolving mode. Prefer **osv-scanner**
  (a pure static lockfile read) as the safest SCA backend for untrusted code.
- **npm audit** reads the lockfile with the registry pinned on the command line,
  but a target-controlled **`.npmrc`** can still influence it via scoped-registry
  (`@scope:registry=`) entries and `${ENV}` auth-token expansion. This is a
  network/exfil consideration (no code execution). For a hostile Node project,
  review its `.npmrc` first or run SCA via osv-scanner instead.
- These tools make **network** calls to advisory/registry databases; that is the
  only outbound traffic in an SCA run.

### aisec
- **Pattern-based.** A determined adversary can rephrase a prompt-injection or
  exfiltration payload to evade the regexes. This engine raises the **cost** of an
  attack and catches the common and lazy cases; it does not close the class.
- It flags **structure and phrasing**, not intent. A legitimate file that
  discusses these techniques (security docs, this very tool) can match - hence the
  false-positive filter and the FILTERED bucket. Review, do not blindly trust the
  suppression.
- New smuggling channels (novel invisible code points, steganographic encodings)
  beyond the covered set will be missed.
- **Encoded payloads are decoded ONE level and rescanned.** A payload wrapped
  twice - base64 of base64 - is not found. This is a bound, not an oversight:
  following attacker-chosen nesting to an attacker-chosen depth is how a scanner
  is made to spend an unbounded amount of time on one file. ROT13 and other
  substitution ciphers are not attempted at all.
- **Agent configs inside skipped directories are reached BY NAME.** A hostile
  `.cursor/hooks.json` under `vendor/` or `node_modules/` is found, because
  `engine_aisec.is_agent_config_path` names the shapes this engine recognises and
  a second walk admits them. ⚠️ That is an ENUMERATION - agent hook configs, MCP
  manifests, git hooks. A vendor spelling absent from those lists is still
  invisible inside a skipped directory. The **prose** rules deliberately do not
  run over vendored trees at all.

## Attack chains (the `chains` report section)

- **A chain is a hypothesis, never a demonstrated exploit.** It says these
  findings could compose into this path; go verify. It does not assert the path
  is reachable, that the injected text will be read, or that the hook will fire.
- **Read the `basis` line, because it is the evidence the severity rests on.**
  `same-file` means both links come from one file, which is real evidence of
  composition. `same-tree` means only that both appear somewhere in the scan -
  weak evidence, and those chains are capped at MEDIUM for exactly that reason.
- 🔴 **Tree-wide co-occurrence is close to certain in any large repository.** An
  earlier version required only that, and produced a confident, entirely false
  HIGH chain on this repository's own tree. If a `same-tree` chain looks
  compelling, that feeling is the thing to distrust.
- ⚠️ **Every chain today has exactly TWO links.** The correlator walks a chain's
  link list generically, so an N-link chain needs only a table entry - but none
  exists. A three-way composition is reported as its separate two-link parts,
  never as one finding.
- **Chains are computed over ACTIVE findings only** and can only ADD a section.
  Nothing here suppresses, downgrades or re-buckets a finding. A filtered finding
  cannot form a link.

## Agent capability profile (the `capability_profile` report section)

- **A capability reads PRESENT or `none`, never SAFE.** `none` means no rule
  matched it - the same claim PRAETOR makes everywhere else. A profile with every
  dimension at `none` is not a clean bill of health.
- **The profile inherits every limit of the findings it reads.** It is computed
  from active findings, so an engine that missed something reports a capability as
  absent that is present. A breaker audit demonstrated exactly that: a secrets
  miss propagated straight into `holds_credentials: none` on a tree holding a
  credential.
- **Evidence is split into production and test/example paths, and neither is
  dropped.** A capability evidenced only by fixtures is still reported, marked.
  Suppressing it would be suppression on PATH ALONE, which this project forbids.
- ⚠️ **`executes_on_load` covers `DANGEROUS_HOOK` plus a hand-kept list of rule
  ids** (today: `npm-lifecycle-exec`). A future rule describing install-time or
  load-time execution must be added by hand. Nothing enforces that.

## Coverage caps, and what each one discloses

Every cap below reports itself. That is deliberate: a cap the operator can see is
a decision, and a cap nobody records is a blind spot. A breaker audit found the
one that did not report and turned it into a clean scan over a live-shaped
credential.

| Cap | What it drops | How it discloses |
|---|---|---|
| `--max-file-size` (3 MB) | the whole file, every engine | `file-too-large-skipped` finding + `meta.scope.oversize_files` |
| 4000-char line | the UNANCHORED secrets passes only; provider and connection-string rules still run in overlapping windows | `secrets-long-line-skip` finding, naming which passes ran |
| decode depth 1 | anything wrapped more than once | stated here; no per-file finding |
| `--exclude`, skip dirs | matching paths | `meta.scope.skipped_dirs`, `excluded_by_pattern` |

⚠️ These disclosures are reported at INFO in the COVERAGE category. They do NOT
gate. A repository with a large asset has done nothing wrong, and a cap that
failed builds would be switched off - which is worse than one that reports.
Gating on reduced coverage is the operator's decision; `--allow-degraded` and
`--fail-on INFO` exist for it.

## False positives and false negatives

- **False positives** are surfaced in a separate FILTERED bucket with a reason,
  or shown as LOW confidence - not deleted. You are expected to judge them.
- **False negatives** are the dangerous ones and are invisible by nature. Do not
  infer their absence from a clean report. Combine PRAETOR with code review,
  runtime testing, and defense in depth.

## Operational notes

- Running against **untrusted code is safe**: no engine builds, runs, imports, or
  evaluates the target's code (the SCA `pip-audit` path uses `--disable-pip`
  specifically so a hostile `requirements.txt` cannot trigger a build -- see the
  SCA boundary above). The only outbound traffic is Semgrep's registry fetch and
  the osv/pip-audit/npm advisory lookups; for a fully air-gapped run use
  `--no-registry` and prefer `--sca-backend osv` (a static lockfile read). A
  hostile `.npmrc` is the one residual network/exfil consideration on the npm
  path (documented above); it cannot execute code.
- PRAETOR does not replace a human security review, a penetration test, or a
  threat model. It is a fast, repeatable first pass that catches a large fraction
  of common mistakes and frees a reviewer to focus on the rest.

## A second implementation exists, and that is itself a risk

A Rust workspace lives under `rust/`. `secrets` is the first detector port in
`praetor-core`, but no Rust engine is wired into the CLI; Python remains the only
implementation users can run. The second implementation therefore already exists
as code even though it is not yet a user-selectable scanner.

**The failure mode is two implementations that quietly disagree.** A detector
ported with a subtly different notion of what a "line" is, or of which characters
are letters, produces a finding in one implementation and silence in the other,
while both test suites stay green — because each is consistent with itself. That is
not hypothetical: a line-definition mismatch between Python's `str.splitlines()`
and the `\n` convention every other tool uses was a real, exploitable suppression
bypass in this scanner, and it was found **by porting** — the whole test suite, the
self-scan and code review all passed over it.

The controls, such as they are:

- `references/differential/` holds a shared corpus and a committed expectation both
  implementations must reproduce. 🔴 The `*.expected` files are contracts; a
  regenerated expectation agrees with whatever produced it and catches nothing.
- Acceptance is defined as identical `(engine, rule_id, file, line)` sets, not as
  "both suites pass."
- ⚠️ **Known gap, stated rather than left to be discovered:** that comparison keys
  on location, so it **cannot detect description drift** between the two
  implementations, and the corpus is finite — two implementations can still share a
  bug on an input shape it does not contain. Differential testing bounds divergence;
  it does not eliminate it.
