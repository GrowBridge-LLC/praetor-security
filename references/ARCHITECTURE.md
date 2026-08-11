# PRAETOR Architecture

PRAETOR is a small orchestrator around four engines plus an interpretation
layer. This document explains how each part works and why.

```
                 +------------------ praetor.py (CLI) ------------------+
                 |  walk_files() enumerates scannable text files once   |
                 +------------------------------------------------------+
                       |            |             |            |
                   engine_       engine_       engine_      engine_
                   secrets       aisec         sast         sca
                  (built-in)   (built-in)   (Semgrep)   (osv/pip/npm)
                       \            \             /            /
                        \            \           /            /
                         +----------- interpret.py -----------+
                         |  dedup -> rank -> FP-filter        |
                         +------------------------------------+
                                        |
                                   report.py
                                (text + JSON)
```

## Design principles

1. **Static only.** No engine executes, imports, installs, or evaluates the
   target. Secrets/aisec read files as text; Semgrep and osv-scanner are static
   analyzers; pip-audit runs with `--disable-pip` (which forbids pip from
   resolving or **building** the target's requirements, so no `setup.py`/PEP517
   backend of an attacker-controlled package is ever executed); npm audit reads
   the lockfile with a pinned registry. PRAETOR's own code opens no outbound
   sockets (the optional SCA/Semgrep subprocesses query advisory/registry
   databases over the network -- see the SCA boundary below and `LIMITS.md`).
2. **Dependency-light and auditable.** The orchestrator and the two built-in
   engines (`secrets`, `aisec`) are pure Python standard library. A security tool
   that is itself hard to audit, or that pulls a large dependency tree, is a
   liability.
3. **Graceful degradation over hard requirements.** Missing external tools
   (Semgrep, osv-scanner) never abort a scan; the affected engine reports itself
   skipped and the report says so.
4. **Honest triage.** Likely false positives are surfaced with a reason, not
   deleted. A clean result is reported as "nothing matched," never "safe."

## core.py - shared model and file walker

- `Severity` (CRITICAL..INFO) and `Confidence` (HIGH/MEDIUM/LOW), both ordered
  for ranking. `Severity.parse` normalizes external scales (Semgrep
  ERROR/WARNING/INFO, npm moderate, etc.).
- `Finding` - the single normalized record every engine emits, with a
  category-aware `compute_dedup_key()` (see interpretation, below).
- `redact()` / `redact_line()` - mask secrets so a report can never leak a live
  credential.
- `walk_files()` - enumerates scannable **text** files once (shared by the two
  built-in engines), skipping VCS/build/vendor noise dirs but deliberately **not**
  skipping `.claude/` or `hooks/` (prime AI-security targets). Binary detection
  judges on decoded code points, not raw bytes, so invisible-Unicode-heavy files
  (exactly what `aisec` hunts) are correctly treated as text.

## engine_secrets.py

Two strategies:

- **Provider patterns** - anchored regexes with a captured token group for each
  known credential type. High confidence, because the format is specific. A
  *strict* placeholder check (`is_dummy`) filters obvious dummies without
  suppressing real keys that merely contain a digit run.
- **Generic + entropy** - keyword-assignment matches and standalone high-entropy
  strings, gated by Shannon entropy and a *broad* placeholder filter, and by known
  false-positive shapes (git SHAs, UUIDs, hex colors, integrity hashes). These are
  MEDIUM/LOW confidence by design.

It also **unwraps base64 blobs** and re-checks the decoded content, catching
base64-wrapped keys and service-account JSON. Canonical documentation example
tokens are reported but marked filtered. Every matched secret is redacted before
it leaves the engine.

## engine_aisec.py - the differentiator

Five detector families, mapped to the OWASP Top 10 for LLM Applications and CWE:

- **Prompt injection** - instruction-override phrasing, role/authority hijacks,
  fake chat-role markers in data, and agent-directed imperatives.
- **Hidden content** - zero-width/invisible Unicode, the Unicode Tags block
  (U+E0000..E007F, invisible ASCII smuggling, CRITICAL), bidirectional
  Trojan-Source controls, and instruction-bearing HTML comments.
- **Data exfiltration** - `curl|sh` execution, PowerShell download-and-exec,
  reads of `~/.aws`/`~/.ssh`/`.env`, environment dumps piped to the network, and
  base64+network obfuscation.
- **Dangerous hooks** - Claude Code hooks (SessionStart/PostToolUse/...), git
  hooks, and npm lifecycle scripts that execute on load or install.
- **Safety bypass** - instructions to auto-approve, disable guards, skip review,
  use dangerous permission flags, or escalate privileges.

## engine_sast.py - Semgrep wrapper

Runtime detection in order: **native** `semgrep` on PATH, then **WSL**
(`wsl -d <distro>`), then **Docker** (`semgrep/semgrep` with a read-only mount).
Rulesets: a bundled offline baseline (`rules/semgrep-praetor.yaml`, which always
runs and adds a few agent/AI-specific code rules the public packs lack) plus, by
default, Semgrep's curated registry packs (`p/owasp-top-ten`, `p/security-audit`)
when the network is reachable (`--no-registry` to disable). Semgrep's JSON is
normalized into `Finding`s, mapping its severity, CWE, OWASP, and references. The
real source line is read locally for the snippet, because Semgrep redacts the
matched line to "requires login" for unauthenticated registry rules.

## engine_sca.py - pluggable dependency scanning

Backend preference: **osv-scanner** (language-agnostic, reads lockfiles against
the OSV.dev database) -> **pip-audit** (Python) -> **npm audit** (Node). Findings
are grouped **one per vulnerable package** (max severity, advisory count, IDs,
and the recommended upgrade), which is far more actionable than one row per CVE.
A correct CVSS v3.0/3.1 base-score calculator ranks advisories that carry a CVSS
vector but no severity label; unrated-but-known advisories default to MEDIUM
(this applies to the pip-audit path too, whose default output carries no
severity -- so its findings default to MEDIUM, never an assumed HIGH).

### The SCA subprocess boundary (what each backend actually does to the target)

The SCA backends are the only engines that shell out to an external tool, so the
trust boundary is stated precisely:

- **osv-scanner** statically **reads** the lockfiles and queries the OSV.dev
  database. It never builds or runs the target.
- **pip-audit** is invoked with **`--disable-pip`** (plus `--no-deps`). This is
  the load-bearing safety flag: `--no-deps` alone does **not** stop pip-audit from
  performing a full pip resolve of the requirements, which builds source
  distributions and executes attacker-controlled `setup.py` / PEP517 backends
  (arbitrary code execution). `--disable-pip` removes that resolve step, so
  pip-audit parses the (fully-pinned) requirements statically and queries advisory
  databases -- **no target code is built or run.** `--disable-pip` requires
  fully-pinned requirements; if a file cannot be audited that way, PRAETOR reports
  a **status `error`** for SCA and **never** retries in a resolving mode.
- **npm audit** reads the lockfile and queries the advisory endpoint with the
  **registry pinned on the command line**, so a target-controlled `.npmrc` cannot
  redirect the audit request to an attacker host.

**Residual trust:** these tools run as subprocesses and make **network** calls to
their advisory/registry databases (use `--no-registry` for Semgrep and an offline
posture for full air-gapping). A target `.npmrc` can still influence npm via
scoped-registry entries and `${ENV}` auth-token expansion (see `LIMITS.md`).

A non-zero tool exit **with** parseable output is "vulnerabilities found"; a
non-zero exit (or empty/unparseable output) **without** parseable results is a
tool **error**, surfaced as `status: error` -- never laundered into a clean
"0 findings" result.

## interpret.py - the layer that makes it coherent

- **Dedup** - a category-aware key merges findings describing the same issue:
  the same leaked token flagged by two engines at one spot merges; the same CWE
  on the same line (bundled rule vs registry vs aisec) merges and records
  corroboration; but distinct CVEs on one package stay distinct.
- **Rank** - unified severity, then confidence, then engine, then location.
  Cross-engine agreement promotes confidence to HIGH.
- **FP filter** - heuristics (example/template env files, entropy hits in
  lockfiles, low-confidence phrasing in docs) move findings into a FILTERED bucket
  **with a rationale**, never deleting them.

## report.py

Emits a plain-ASCII human report (CI/log friendly) with an engine-status table,
severity summary, ranked findings, the filtered bucket, and a LIMITS section; and
a stable JSON schema for programmatic consumers.

## rust/ — a SECOND implementation, in progress

Everything above describes the Python implementation, which is **the reference
implementation and the one you get from `pip install praetor-security`**. There is
also a Rust workspace under `rust/`, and a contributor who does not know that will
make changes in one implementation that silently diverge from the other.

**Status, stated precisely because "port in progress" is too vague to act on:**
**no detector has been ported.** `rust/praetor-core/src/` contains `text.rs` (the
shared line definition), `sca.rs` (argv construction plus the never-execute
invariant guard) and `unicode_tables.rs` (generated script tables) — real, tested,
load-bearing code. There is no `scan()` entry point, and the binary exits non-zero
rather than pretend to scan.

The decision, its conditions, and the counter-argument that lost are in
[`ADR-001-engine-language.md`](ADR-001-engine-language.md). Two of its conditions
bind anyone touching `rust/`:

- 🔴 **No backend merges before its never-execute invariant test does.** A Rust
  backend is a new backend, and every new backend widens the surface the
  `--disable-pip` guarantee covers.
- **Acceptance is DIFFERENTIAL, not "the tests pass."** Both implementations must
  emit identical `(engine, rule_id, file, line)` sets over one shared corpus. Two
  implementations that are not continuously reconciled are not a port; they are a
  fork.

### references/differential/ — 🔴 a contract, not a fixture

`line-splitting.txt` is the shared corpus; `line-splitting.expected` is the
**committed expectation both implementations must reproduce**. It encodes the line
definition that a suppression bypass turned on (see `core.split_lines`).

**Do not regenerate `*.expected` to make a test pass.** It is the only artifact
that can catch the two implementations agreeing on the *wrong* answer, and a
regenerated expectation agrees with whatever produced it — by construction. If it
fails, one of the implementations is wrong; find out which. The file repeats this
warning in its own header, because whoever regenerates it will be reading the file,
not this document.
