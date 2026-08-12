---
name: praetor
description: >-
  Multi-engine STATIC security analysis of a codebase, file, repo, skill, or
  plugin. Fuses four engines into one prioritized, deduplicated report: SAST via
  Semgrep (OWASP Top 10, injection, auth flaws across many languages), secret
  detection (provider patterns + entropy + base64 unwrap), dependency/SCA (known-
  vulnerable packages via osv-scanner/pip-audit/npm audit), and an AI-security
  engine (prompt-injection payloads, invisible-Unicode/Trojan-Source smuggling,
  data-exfiltration patterns, dangerous auto-run hooks, and safety-bypass
  instructions). Use when the user wants to security-review, audit, or scan code
  for vulnerabilities, hardcoded secrets, or vulnerable dependencies; when
  vetting an untrusted skill/plugin/MCP server/repo before trusting or installing
  it; or when checking agent-facing files (SKILL.md, README, CLAUDE.md, hooks,
  settings.json) for prompt injection or supply-chain risk. Triggers: "security
  review", "audit this code", "scan for secrets/vulnerabilities", "is this repo/
  skill safe", "check for prompt injection", "SAST", "dependency vulnerabilities".
---

# PRAETOR - Multi-Engine Security Analysis

PRAETOR runs four complementary security engines over a target path and merges
their output into a single prioritized report. It is **static** - it reads
files, and never executes, imports, installs, or evaluates the code it scans.

## When to use this skill

- The user asks to **security-review / audit / scan** a file, directory, or repo.
- **Vetting untrusted code** before running it: a downloaded skill, plugin, MCP
  server, GitHub repo, or dependency.
- Checking **agent-facing files** (`SKILL.md`, `README`, `CLAUDE.md`, `.claude/`
  hooks, `settings.json`, `package.json`) for prompt injection or supply-chain
  compromise - the attack surface a self-improving agent faces.
- Pre-commit / CI gating on secrets, vulnerable dependencies, or SAST findings.

## The four engines

| Engine | What it finds | Backend |
|--------|---------------|---------|
| **sast** | OWASP Top 10, injection, auth, unsafe deserialization, weak crypto, XSS, many languages | Semgrep (OSS) + bundled offline rules |
| **secrets** | Hardcoded API keys/tokens, PEM private keys, DB connection-string passwords, base64-wrapped secrets, high-entropy strings | built-in (stdlib) |
| **sca** | Known-vulnerable dependencies with CVE/GHSA IDs + upgrade path | osv-scanner -> pip-audit -> npm audit |
| **aisec** | Prompt injection, invisible-Unicode / Trojan-Source smuggling, data exfiltration, dangerous auto-run hooks, safety-bypass instructions | built-in (stdlib) |

The **interpretation layer** then deduplicates across engines (cross-engine
agreement raises confidence), ranks by unified severity, and moves likely false
positives into a separate bucket **with a stated rationale** (never dropped
silently).

## How to run it

```bash
python <skill_dir>/scripts/praetor.py <TARGET_PATH> [options]
```

Common invocations:

```bash
# Full scan of a repo, human-readable report
python scripts/praetor.py /path/to/repo

# Machine-readable JSON, written to a directory, for CI / another agent
python scripts/praetor.py /path/to/repo --format json --out ./praetor-out

# Only the AI-security + secret engines (fast; no external tools needed)
python scripts/praetor.py /path/to/skill --engines aisec,secrets

# Offline: bundled Semgrep rules only, no registry fetch
python scripts/praetor.py /path/to/repo --no-registry

# CI gate: exit 1 if anything HIGH or worse is found
python scripts/praetor.py /path/to/repo --fail-on HIGH --format json
```

Key options (see `--help` for all): `--engines`, `--format {text,json,both}`,
`--out DIR`, `--min-severity`, `--fail-on`, `--allow-degraded`,
`--sca-backend {auto,osv,pip-audit,npm}`,
`--semgrep-runtime {auto,native,wsl,docker}`, `--no-registry`, `--exclude REGEX`.

Exit codes: `0` fully measured and clean (or below `--fail-on`), `1` findings
at/above `--fail-on`, `2` usage/internal error, `3` an engine **could not
measure** under `--fail-on` (errored or unavailable).

🔴 **Never report exit `3` as a clean scan.** It means an engine did not run, so
its zero findings say nothing about the target. Read the `engines` block in the
report, fix the runtime, and scan again — or pass `--allow-degraded` if the
blind spot is knowingly accepted.

## Interpreting the output

- **Severity** (CRITICAL > HIGH > MEDIUM > LOW > INFO) x **Confidence** (HIGH/
  MEDIUM/LOW). Work top-down; each finding carries a location, CWE/OWASP mapping,
  a concrete fix, and a reference.
- The **FILTERED** section lists suppressed low-signal findings **with reasons** -
  skim it; suppression is a judgment call, not proof of safety.
- Always read the **LIMITS** section. A clean result means "nothing matched these
  rules," never "this code is safe." See `references/LIMITS.md`.
- Detected secrets are **redacted** in every report (first/last few chars only).

## Prerequisites and graceful degradation

- **Python 3.8+** is the only hard requirement; the `secrets` and `aisec` engines
  are pure standard library and always run.
- **Semgrep** powers `sast`. Install with `pip install semgrep` (verified working
  natively on Windows, macOS, and Linux with recent versions). If it is not
  present natively, PRAETOR can run it via WSL or Docker (`--semgrep-runtime`).
  If no Semgrep runtime exists, `sast` reports itself **skipped** and the other
  engines still run.
- **osv-scanner** (preferred) powers `sca` (`winget install Google.OSVScanner`,
  `brew install osv-scanner`, or a release binary). PRAETOR falls back to
  `pip-audit` (Python) or `npm audit` (Node) if osv-scanner is absent.
- Missing engines never abort the scan - the report states honestly which ran and
  which were skipped.

## Safety of this skill itself

PRAETOR is designed to be safe to run against hostile input:

- **Static only** - it never executes, sources, imports, or installs the target.
  The one path that shells out per-dependency, SCA, stays static too: osv-scanner
  reads lockfiles; **pip-audit runs with `--disable-pip`** so a hostile
  `requirements.txt` cannot trigger a build/`setup.py` execution (an unpinnable
  file is reported as an SCA error, never resolved); npm audit reads the lockfile
  with a pinned registry. See `references/LIMITS.md` for the exact SCA boundary
  and its residual trust (advisory-DB network calls; a target `.npmrc`).
- **No exfiltration** - PRAETOR's own code makes no outbound network calls.
  (Semgrep may fetch its registry rulesets unless you pass `--no-registry`;
  osv-scanner, pip-audit, and npm audit query vulnerability databases. Use
  `--no-registry` + an offline `--sca-backend` to run fully air-gapped.)
- **No secret leakage** - matched credentials are redacted before display.
- The code is dependency-light and auditable; see `references/ARCHITECTURE.md`.

## Further reading (progressive disclosure)

- `README.md` - project overview, install, usage, honest limits (start here).
- `references/ARCHITECTURE.md` - how each engine and the interpretation layer work.
- `references/LIMITS.md` - what PRAETOR can and cannot find; residual risk.
- `references/test-corpus/` - deliberately-vulnerable and clean samples to verify
  behavior (`python references/test-corpus/_generate_corpus.py` to materialize).
