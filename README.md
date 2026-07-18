# PRAETOR

**Multi-engine static security analysis for code, repos, and AI agent skills.**

PRAETOR fuses four complementary security engines into a single prioritized,
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

Most scanners do one thing. PRAETOR combines four lenses and, crucially, adds an
**interpretation layer** that turns N raw tool outputs into one coherent,
ranked answer - the part that usually separates a useful security review from a
wall of noise.

It also covers an attack surface almost no classic scanner does: the
**AI-security / agent-supply-chain** threats that a self-improving agent or an
LLM-in-the-loop pipeline actually faces - prompt injection hidden in docs,
invisible-Unicode instruction smuggling, data-exfiltration patterns, and
dangerous auto-run hooks.

## The four engines

| Engine | Finds | Backend | Requires |
|--------|-------|---------|----------|
| **sast** | OWASP Top 10, injection, unsafe deserialization, weak crypto, XSS, SSRF, disabled TLS, across ~30 languages | [Semgrep](https://semgrep.dev) (OSS) + bundled offline rules | `semgrep` (native / WSL / Docker) |
| **secrets** | Hardcoded API keys & tokens (AWS, GCP, GitHub, Slack, Stripe, OpenAI, Anthropic, Google, Twilio, SendGrid, npm, JWT), PEM private keys, DB connection-string passwords, base64-wrapped secrets, high-entropy strings | built-in (stdlib) | nothing |
| **sca** | Known-vulnerable dependencies with CVE/GHSA IDs, severity, and upgrade path | [osv-scanner](https://github.com/google/osv-scanner) -> [pip-audit](https://github.com/pypa/pip-audit) -> `npm audit` | one of those (optional) |
| **aisec** | Prompt-injection payloads, invisible-Unicode / [Trojan Source](https://trojansource.codes/) smuggling, data exfiltration, dangerous auto-run hooks (Claude Code / git / npm lifecycle), safety-bypass instructions | built-in (stdlib) | nothing |

The `secrets` and `aisec` engines are pure Python standard library and always
run. `sast` and `sca` degrade gracefully: if their backend is missing, that
engine reports itself **skipped** and the scan continues.

## Install

Only **Python 3.8+** is strictly required. Install the optional engines for full
coverage:

```bash
# SAST engine (Semgrep). Works natively on Windows, macOS, Linux with recent
# versions. Prefer an isolated environment (pipx / venv) to avoid disturbing
# other packages:
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

# CI gate: non-zero exit if anything HIGH or worse is found
python scripts/praetor.py /path/to/target --fail-on HIGH --format json
```

### Options

| Option | Meaning |
|--------|---------|
| `--engines` | Comma list of `sast,secrets,sca,aisec` (default: all) |
| `--format` | `text`, `json`, or `both` (default: text) |
| `--out DIR` | Write `praetor-report.txt` / `.json` to DIR |
| `--min-severity` | Hide active findings below this level |
| `--fail-on` | Exit 1 if any active finding is at/above this level |
| `--sca-backend` | `auto` (default), `osv`, `pip-audit`, `npm` |
| `--semgrep-runtime` | `auto` (default), `native`, `wsl`, `docker` |
| `--no-registry` | Bundled Semgrep rules only; no network fetch |
| `--semgrep-config` | Extra Semgrep `--config` (repeatable) |
| `--exclude REGEX` | Exclude matching relative paths (repeatable) |
| `--max-file-size` | Skip files larger than N bytes (default 3 MB) |

Exit codes: `0` clean (or below `--fail-on`), `1` findings at/above `--fail-on`,
`2` usage/internal error.

## Output

Every finding includes: severity x confidence, engine, location, category,
CWE/OWASP mapping, a concrete fix, and a reference. Findings are sorted
most-dangerous-first. Likely false positives are moved to a separate **FILTERED**
section with a stated reason (never dropped silently). Detected secrets are
**redacted** - PRAETOR never prints a live credential.

The JSON report is a stable schema (`schema_version`) suitable for a CI job, an
apply-gate, or another agent to consume.

## Verifying it works

The repo ships a deliberately-vulnerable sample and a clean baseline:

```bash
python references/test-corpus/_generate_corpus.py     # materialize fixtures
python scripts/praetor.py references/test-corpus/vulnerable   # expect many findings
python scripts/praetor.py references/test-corpus/clean        # expect ~none (from code engines)
```

All "secrets" in the corpus are fake, generated from harmless parts - see
`references/test-corpus/README.md`.

### On false positives

The "clean corpus produces no findings from the code engines" result is measured
on a **clean** codebase. PRAETOR deliberately **does not self-exempt** or exempt
security tooling, so scanning code that legitimately *contains* security patterns
- a scanner's own detection rules and regex strings, security documentation, or
example payloads - will surface expected matches on those strings. That is correct
behavior, not a bug: a tool that silently ignored files "because they look like
rules" could be blinded by an attacker who dressed a payload up as one. Low-
confidence matches in documentation land in the **FILTERED** bucket with a reason;
higher-confidence matches on pattern strings remain active for a human to judge.
"Low false positives" therefore describes ordinary application code, not files
whose job is to describe attacks.

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

## License

MIT - see [`LICENSE`](LICENSE).
