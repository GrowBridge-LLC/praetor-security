# PRAETOR

**Multi-engine static security analysis for code, repos, and AI agent skills.**

PRAETOR fuses five complementary security engines into a single prioritized,
deduplicated, false-positive-filtered report - human-readable and JSON. It is
built as a [Claude Code](https://docs.claude.com/en/docs/claude-code) skill but
the scanner (`scripts/praetor.py`) is a standalone Python CLI that runs anywhere.

It is **static**: it reads files and never executes, imports, installs, builds,
or evaluates the code it scans. Its own code makes no outbound network calls; the
optional SCA/Semgrep backends query advisory/registry databases (the SCA
`pip-audit` path runs with `--disable-pip` so even a hostile `requirements.txt`
is never built -- see [`references/LIMITS.md`](references/LIMITS.md)).

---

## Why PRAETOR

Most scanners do one thing. PRAETOR combines five lenses and, crucially, adds an
**interpretation layer** that turns N raw tool outputs into one coherent,
ranked answer - the part that usually separates a useful security review from a
wall of noise.

It also covers an attack surface almost no classic scanner does: the
**AI-security / agent-supply-chain** threats that a self-improving agent or an
LLM-in-the-loop pipeline actually faces - prompt injection hidden in docs,
invisible-Unicode instruction smuggling, data-exfiltration patterns, and
dangerous auto-run hooks.

## The five engines

| Engine | Finds | Backend | Requires |
|--------|-------|---------|----------|
| **sast** | OWASP Top 10, injection, unsafe deserialization, weak crypto, XSS, SSRF, disabled TLS, across ~30 languages | [Semgrep](https://semgrep.dev) (OSS) + bundled offline rules | `semgrep` (native / WSL / Docker) |
| **secrets** | Hardcoded API keys & tokens (AWS, GCP, GitHub, Slack, Stripe, OpenAI, Anthropic, Google, Twilio, SendGrid, npm, JWT), PEM private keys, DB connection-string passwords, base64-wrapped secrets, high-entropy strings | built-in (stdlib) | nothing |
| **sca** | Known-vulnerable dependencies with CVE/GHSA IDs, severity, and upgrade path | [osv-scanner](https://github.com/google/osv-scanner) -> [pip-audit](https://github.com/pypa/pip-audit) -> `npm audit` | one of those (optional) |
| **aisec** | Prompt-injection payloads, invisible-Unicode / [Trojan Source](https://trojansource.codes/) smuggling, data exfiltration, dangerous auto-run hooks (Claude Code, Cursor, Windsurf, Cline / git / npm lifecycle), safety-bypass instructions | built-in (stdlib) | nothing |
| **model** | Dangerous globals (`os.system`, `subprocess.*`, `builtins.eval`, pickle gadget-chain components, ...) referenced inside `.pt`/`.pth`/`.ckpt`/`.pkl`/`.pickle`/`.npy`/`.npz`/`.h5`/`.hdf5`/`.keras`/`.bin`/`.joblib`/`.dill` files, via pickle-**opcode disassembly** (`pickletools.genops()` -- never `pickle.load`); a bounded heuristic for Keras `Lambda`-layer RCE in HDF5; `.safetensors` recognized as safe-by-design | built-in (stdlib) | nothing |

The `secrets`, `aisec`, and `model` engines are pure Python standard library and
always run. `sast` and `sca` degrade gracefully: if their backend is missing, that
engine reports itself **skipped** and the scan continues.

## Install

⚠️ **PRAETOR is NOT on PyPI.** `pip install praetor-security` does not work and never has —
the name is unregistered. (Do not reach for `pip install praetor` either: that name belongs
to an unrelated project.) Install from source:

```bash
git clone https://github.com/GrowBridge-LLC/praetor-security
cd praetor-security
pip install .          # provides the `praetor` command
praetor --version
```

Or without installing anything at all — see below.

PRAETOR has **no runtime dependencies** — deliberately. A tool that vets other
people's dependencies should not arrive with a large dependency tree of its own.
The secrets and AI-security engines are pure standard library and work
immediately; the SAST and SCA engines shell out to external binaries *only if you
install them*, and report themselves `unavailable` rather than silently returning
zero findings if you do not.

You can also run it straight from a clone with no install at all:

```bash
python scripts/praetor.py <target>
```

### Optional engines

Only **Python 3.8+** is strictly required. Install the optional engines for full
coverage:

```bash
# SAST engine (Semgrep). Runs natively on macOS and Linux. Prefer an isolated
# environment (pipx / venv) to avoid disturbing other packages:
#
# ⚠️ WINDOWS: a native `pip install semgrep` installs a launcher that exits 1
# with no output -- semgrep-core is not built for native Windows. Use WSL or
# Docker (see below). PRAETOR reports this honestly as [error] or [skipped]
# rather than as a clean scan, but the sast engine WILL be unavailable until
# you provide one of those runtimes.
pipx install semgrep            # or:  pip install semgrep

# SCA engine (osv-scanner - preferred, language-agnostic):
winget install Google.OSVScanner        # Windows
brew install osv-scanner                # macOS
#   or download a release binary: https://github.com/google/osv-scanner/releases
# Fallbacks (auto-detected): pip-audit (Python) or npm audit (Node), no install
#   needed if you already have pip-audit or npm.
```

If Semgrep will not run natively on your platform, PRAETOR can invoke it via WSL
or Docker with `--semgrep-runtime wsl|docker`.

## Usage

```bash
# Full scan, human-readable report
python scripts/praetor.py /path/to/target

# JSON for CI or another tool, written to a directory
python scripts/praetor.py /path/to/target --format json --out ./praetor-out

# Vet an untrusted skill/plugin with just the built-in engines (no external tools)
python scripts/praetor.py /path/to/skill --engines aisec,secrets

# Fully offline (bundled Semgrep rules only, no registry fetch)
python scripts/praetor.py /path/to/target --no-registry --engines sast,secrets,aisec
# Works from a clone and from a pip install alike; set PRAETOR_RULES_DIR to
# point at a different ruleset location.

# CI gate: non-zero exit if anything HIGH or worse is found
python scripts/praetor.py /path/to/target --fail-on HIGH --format json
```

### Options

| Option | Meaning |
|--------|---------|
| `--engines` | Comma list of `sast,secrets,sca,aisec,model` (default: all) |
| `--format` | `text`, `json`, `both`, or `sarif` (default: text) |
| `--out DIR` | Write `praetor-report.txt` / `.json` / `.sarif` to DIR |
| `--min-severity` | Hide active findings below this level |
| `--fail-on` | Exit 1 if any active finding is at/above this level; exit 3 if the scan was not measured |
| `--allow-degraded` | Accept a degraded scan's blind spot instead of exit 3, with or without `--fail-on` |
| `--sca-backend` | `auto` (default), `osv`, `pip-audit`, `npm` |
| `--semgrep-runtime` | `auto` (default), `native`, `wsl`, `docker` |
| `--no-registry` | Bundled Semgrep rules only; no network fetch |
| `--semgrep-config` | Extra Semgrep `--config` (repeatable) |
| `--exclude REGEX` | Exclude matching relative paths (repeatable) |
| `--max-file-size` | Skip files larger than N bytes (default 3 MB) |

Exit codes: `0` no active findings at or above `--fail-on` — **`NO FINDING`, never `SAFE`**, `1` findings
at/above `--fail-on`, `2` usage/internal error, `3` the scan **was not measured enough to pass**. An enabled engine error or unrecognised status exits `3` even without `--fail-on`: report-only automation must not proceed after the scanner itself broke. An unavailable runtime is the deliberate report-only carve-out (it remains `[BLIND]` and exits `0` by default), but it still exits `3` under `--fail-on`. Zero files examined and PRAETOR/Semgrep scope disagreement also exit `3` under `--fail-on`. In every case the stderr names which and what to change.

🔴 **`3` exists because "no findings" and "nothing ran" are not the same result.**
An engine that dies produces zero findings for a reason that has nothing to do
with the target being clean, and until that reached the exit code a broken
semgrep runtime looked exactly like a passing scan. Pass `--allow-degraded` to
gate on findings alone when you knowingly accept the blind spot. `1` outranks
`3`, and both are non-zero, so a gate testing `if rc != 0` fails safe either way.

## Output

Every finding includes: severity x confidence, engine, location, category,
CWE/OWASP mapping, a concrete fix, and a reference. Findings are sorted
most-dangerous-first. Likely false positives are moved to a separate **FILTERED**
section with a stated reason (never dropped silently). Detected secrets are
**redacted** - PRAETOR never prints a live credential.

The JSON report is a stable schema (`schema_version`) suitable for a CI job, an
apply-gate, or another agent to consume.

### The engine-status contract — read this before trusting exit 0

`report["meta"]["engines"]` is an object keyed by engine name (`sast`, `secrets`, `sca`, `aisec`, `model`).
Each value has a `status` field, one of: `ok`, `not-applicable`, `disabled`, `unavailable`, `error`,
`partial-parse` (SAST only, `schema_version` 4.0+). Only `ok` means the engine actually ran and
looked. `unavailable`, `error`, and `partial-parse` are all blind spots — the engine did not produce
a trustworthy answer for that scan. **A consumer matching on this list by name must treat any
unrecognised word — including `partial-parse` if your integration predates 4.0 — as a blind spot,
never as a pass.**

🔴 **Without `--fail-on`, a blind engine still exits `0`.** This is the deliberate report-only
carve-out described above, and it means **a consumer that checks only the process exit code cannot
tell "clean" from "half the engines never ran."** Both look identical from the outside: exit `0`,
some findings or none. If your integration reads the report and decides anything based on it, check
`meta["engines"][name]["status"]` for every engine you care about — do not infer engine health from
the exit code or the finding count alone. (`--fail-on` closes this specific gap for you automatically,
by turning any blind spot into exit `3` — but only if you pass it.)

### schema_version 4.2 — a cross-scan identity for every finding

Every finding gains a **`fingerprint`**: a stable identity that survives the
finding MOVING within its file. Additive; a 4.1 consumer ignores it.

🔴 **`fingerprint` and `dedup_key` answer different questions and are not
interchangeable.**

| Field | Question it answers | Includes the line? |
|---|---|---|
| `dedup_key` | are these the same finding **in this scan**? | **yes**, deliberately |
| `fingerprint` | is this the same finding as one in a **previous scan**? | **no**, deliberately |

If you are building anything that compares two scans — a dashboard, a CI job
that gates only on newly-introduced findings, a triage record that must stay
attached to its finding — **key on `fingerprint`.** Keying on `dedup_key`, or on
`file:line`, reports a wall of false "new findings" on any commit that adds an
import above them.

The basis is `(rule_id, file, normalised snippet)`. It deliberately ignores
severity and confidence, so a rule re-rating does not orphan an existing triage
record: the issue did not change, the tool's opinion of it did.

⚠️ **Two identical lines in one file share a fingerprint.** Without a line number
there is nothing to tell them apart. Group by fingerprint and count. SARIF's own
`partialFingerprints` has the same property for the same reason.

⚠️ The snippet is redacted at the `Finding` boundary before the fingerprint is
computed, so a fingerprint can be stored and transmitted without carrying a
credential. `tests/test_finding_fingerprint.py` asserts that.

### schema_version 4.1 — two additive report sections

MINOR, not major, and the distinction is the point: nothing was renamed, removed
or re-typed. A 4.0 consumer keeps working and simply ignores two new top-level
keys.

- **`chains`** — an array of attack chains: findings that COMPOSE into one path.
  Always present; an empty array means no chain matched, which (like an empty
  findings list) is not a statement that the tree is safe. Each entry carries
  `chain_id`, `title`, `severity`, `proximity`, `scope`, `why_it_composes`,
  `what_to_verify`, and `links`.
  🔴 **Read `proximity` before you act on `severity`.** `same-file` means both
  links came from one file — real evidence of composition. `same-tree` means only
  that both appeared somewhere in the scan, which in a large repository is close
  to certain; those chains are capped at MEDIUM and are a prompt to look, not an
  escalation. `scope` names the file (or says the whole tree).
- **`capability_profile`** — one entry per capability dimension, answering "if I
  open this repository in an agent right now, what have I authorised?" Each
  carries `status` (`present` / `none` — **never** `safe`), `evidence_count`,
  `production_evidence_count`, `test_or_example_evidence_count`,
  `worst_severity`, and up to three `examples`.
  ⚠️ It is computed from ACTIVE findings, so it inherits every miss they have. A
  capability reported `none` means no rule matched one.

Both sections only ADD. Neither suppresses, downgrades or re-buckets a finding,
and neither changes an exit code. See `references/LIMITS.md` for what each one
does not claim.

### schema_version 4.0 — a new SAST status word

`meta.engines.sast.status` can now be `partial-parse`: semgrep ran, and every
error it reported was `PartialParsing` — some source in the target could not
be parsed. If you match engine status by an exhaustive list rather than a
"is it `ok`" check, add this value to whatever set you treat as blocking.

- **Still a blind spot, deliberately, even though most of the file measured
  cleanly.** The exit code, the `[BLIND]` report mark, and `--fail-on`'s
  refusal to certify the scan clean are all identical to a plain `error` —
  only `meta.engines.sast.detail` is more specific. An earlier version of
  this addition treated it as a lesser carve-out (like `unavailable`) and
  was reverted after an adversarial audit demonstrated a live exploit: unlike
  `unavailable`, which the *environment* chooses, `partial-parse` is chosen
  by the *scanned tree* — a file missing one bracket decides, on its own,
  whether SAST reports itself degraded, and a report-only run must refuse it
  exactly as it refuses `error`.
- **Not a new exit code, not a new report mark.** Nothing else in this
  section changes.

### schema_version 3.0 — engine statuses split, and a second file count

Two breaking changes had shipped under an unchanged `2.0`. If you consume the
JSON, check `schema_version` before these:

| what | 2.0 | 3.0 |
|---|---|---|
| an engine with nothing to scan | `unavailable` | **`not-applicable`** |
| an engine that could not scan | `unavailable` | `unavailable` (unchanged) |
| files the secrets engine read | *(not reported)* | **`meta.secret_file_count`** |

- **`unavailable` was two facts under one word.** "No dependency manifests here"
  and "the SCA backend is missing" are different, and a gate must treat them
  differently — one is a clean answer, the other is a blind spot. If you key on
  `unavailable`, you now want `not-applicable` for the benign case.
- **`meta.file_count` no longer covers every finding.** The secrets engine
  deliberately walks wider than the others (vendored and build directories are
  skipped for SAST but scanned for credentials), so a finding can be reported in a
  file `file_count` never counted. Use `meta.secret_file_count` alongside it.
  ⚠️ **Treating `file_count == 0` as "nothing was scanned" is now wrong.**

### schema_version 2.0 — breaking change to two `rule_id`s

If you match on `rule_id`, update these:

| 1.0 | 2.0 |
|---|---|
| `claude-hook-autorun` | `agent-hook-autorun` |
| `claude-hook-autorun-dangerous` | `agent-hook-autorun-dangerous` |

The auto-run hook detector is no longer Claude-specific — it recognises Cursor,
Windsurf, Cline and Roo hook configurations too, so a vendor-named id had become
misleading. Nothing else in the schema changed.

## Verifying it works

The repo ships a deliberately-vulnerable sample and a clean baseline:

```bash
python references/test-corpus/_generate_corpus.py     # materialize fixtures
python scripts/praetor.py references/test-corpus/vulnerable   # expect many findings
python scripts/praetor.py references/test-corpus/clean        # expect ~none (from code engines)
```

All "secrets" in the corpus are fake, generated from harmless parts - see
`references/test-corpus/README.md`.

### On false positives, and what gets suppressed

Scanning code that legitimately *contains* security patterns — a scanner's own
rules, security documentation, example payloads — will match on those strings.
PRAETOR reduces that noise by asking whether the matched text can actually *do*
anything:

| Pass | Suppresses when… |
|---|---|
| **inline ignore** | the flagged line carries `praetor:ignore` / `nosec` / `nosemgrep` |
| **lexical context** | the match is inside a comment or docstring — text that cannot execute |
| **reachability** | the matched string provably never reaches a dangerous sink (`exec`, shell, filesystem, network). Python, intra-file |
| **heuristics** | example/template env files, integrity hashes in lockfiles, low-confidence phrasing in docs |

Comment syntax is selected from the flagged file's type, never inferred from a
line alone: a Markdown heading and `//` within a YAML URL are content, not an
authorization to suppress. Unknown file types fail safe to code and keep the
finding.

Nothing is deleted. Suppressed findings move to the **FILTERED** bucket carrying
the reason, so you can audit every suppression rather than trust it.

**Two properties worth knowing before you rely on this:**

🔴 **Secrets are never suppressed by context or reachability.** A dangerous
*command* in a comment is inert — a comment cannot execute. A *credential* in a
comment is still leaked, because a secret is disclosed by being written down, not
by being executed. Reachability does not change that: a key declared in one module
and used in another never reaches a sink in the file that declares it. Both passes
therefore apply to the AI-security engine only, and that carve-out is enforced by
tests that call the real suppression functions — not by a convention, and not by a
test that merely inspects the config those functions read.

⚠️ **Scope of that promise, stated exactly.** It covers the two passes above. Two
older heuristics *can* still move a secret to FILTERED, in narrow cases: a secret in
an `.env.example`/`.env.template`-style file, and a low-confidence, low-entropy value
assigned to a secret-named variable. Both are visible in the FILTERED bucket with a
reason. So the accurate claim is *"context and reachability never suppress a secret"*,
not *"nothing ever does"* — **read the FILTERED bucket, do not assume it is all noise.**

🟢 **Suppression fails safe.** Anything PRAETOR cannot *prove* inert is kept —
unparseable source, an unfamiliar construct, a non-Python file, a value that
escapes single-file analysis. A classifier that failed toward suppression would be
a scanner that goes quiet under exactly the conditions an attacker creates.

PRAETOR also **does not self-exempt**: there is no rule excusing files "because
they look like detection rules", and none excusing `tests/` — such a rule would
also excuse a real credential committed in a test file, which is a common real
leak. What remains after suppression is a short list a human can actually read.

## Honest limits

PRAETOR is a high-signal aid, **not** a guarantee of security. It is static
(no runtime/logic/authorization flaws), its coverage equals its rules and
advisory databases (never exhaustive), and its pattern-based AI-security engine
raises the cost of an attack rather than closing it. Treat every finding as a
lead to verify and every clean result as "nothing matched these rules." Full
detail in [`references/LIMITS.md`](references/LIMITS.md).

## Architecture

See [`references/ARCHITECTURE.md`](references/ARCHITECTURE.md) for how each engine
and the interpretation layer (dedup, ranking, FP filtering) work, and the design
decisions behind them.

### There is a second implementation, in progress

Python is the reference implementation and is what you get from a clone or
`pip install .`. A Rust workspace also lives under [`rust/`](rust/). The
`secrets` detector has a `scan()` entry point in `praetor-core` and is held to
the Python implementation by the differential runner; shared text handling,
SCA argv construction, and generated Unicode tables also exist there. No Rust
engine is wired into the CLI yet, so the binary refuses to scan rather than
pretend to.

If you are contributing, two things bind you before you touch either tree:

- Acceptance is **differential** — both implementations must produce identical
  `(engine, rule_id, file, line)` sets over one shared corpus.
- 🔴 `references/differential/*.expected` is a **contract, not a fixture.** Never
  regenerate it to make a test pass; a regenerated expectation agrees with whatever
  produced it, which is exactly the failure it exists to catch.

Rationale, conditions and the counter-argument that lost:
[`references/ADR-001-engine-language.md`](references/ADR-001-engine-language.md).

## License

**GNU Affero General Public License, version 3** - see [`LICENSE`](LICENSE).

PRAETOR was MIT-licensed until 2026-09-04. What that means for you:

- **Using PRAETOR to scan your code changes nothing.** Running a scanner over
  your repository, in a terminal or in CI, does not make your repository a
  derivative work. Scan whatever you like, including proprietary code.
- **Modifying PRAETOR and running it as a network service** does trigger the
  AGPL's section 13: your users must be able to get your modified source.
- **A licence change is not retroactive.** Every commit published before the
  change stays available under MIT, and anyone who obtained a copy under those
  terms keeps them permanently. The MIT text and the last MIT commit are
  recorded in [`LICENSE-MIT-HISTORICAL.txt`](LICENSE-MIT-HISTORICAL.txt) so that
  is checkable rather than remembered.
- ⚠️ **Some organisations prohibit AGPL software internally.** That is a real
  cost of this choice, stated here rather than discovered later.

**The frontier capabilities are in the open-source core, not held back.**
Attack-chain correlation, the agent capability profile and serialized-model
scanning all ship here, under this licence, with no cap and nothing phoning
home. They are the reason to choose PRAETOR, and they cannot be that if you
cannot see them work.
