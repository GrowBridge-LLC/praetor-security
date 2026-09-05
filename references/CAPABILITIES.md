# PRAETOR — what it does, exactly

A complete statement of PRAETOR's functionality: what ships today, what is
committed, and what is deliberately excluded. Written to be checkable — every
count here was read off the code, not estimated, and the command to re-derive it
is given where the number could drift.

**Status keys used throughout:**

| Key | Meaning |
|---|---|
| ✅ | in `main`, tested, in the gate |
| 🔨 | committed direction, not built |
| 🔬 | researched, not committed — needs a decision |
| ❌ | deliberately excluded, with the reason |

---

## 0. The two rules that constrain everything else

**1. PRAETOR never executes, imports, installs or builds the code it scans.**
This has been false once — the SCA path let `pip` resolve a target's
requirements, which builds source distributions and runs `setup.py` from an
attacker-controlled tree. The fix is `--disable-pip`, and
`tests/test_invariant_never_executes_target.py` asserts it *behaviourally*, by
capturing the argv PRAETOR would hand to the subprocess.

Every new engine or backend widens this surface. The model engine is the newest
test of it, and it holds: `pickletools.genops()` reads pickle opcodes without
running them.

**2. A clean scan is `NO FINDING`, never `SAFE`.** The vocabulary enforces it: a
capability reads `present` or `none`; an engine that could not run reports
`unavailable` or `error`, never a quiet zero; every coverage cap discloses itself.

---

## 1. The five engines

### ✅ `secrets` — credentials in the tree

- **17 anchored provider patterns**: AWS access key and secret key, Azure storage
  account key, GCP API key / OAuth client secret / OAuth refresh token, GitHub
  token and fine-grained PAT, Slack token and webhook, Stripe secret key, OpenAI,
  Anthropic, Twilio auth token, SendGrid, npm token, JWT.
  Re-derive: `python -c "import sys;sys.path.insert(0,'scripts');import engine_secrets as s;print(len(s.PROVIDERS))"`
- **Connection strings** with embedded passwords across 14 schemes.
- **Generic keyword-and-entropy detection** for anything no provider rule covers,
  in two branches: a quoted value, and an unquoted one that must look like a
  credential (16+ characters of credential alphabet, no whitespace).
- **Base64 unwrapping** that asks the *provider table itself* rather than a
  hand-written marker list, so a provider added tomorrow is covered in wrapped
  form on the same commit. One decode level.
- **Placeholder rejection** before a finding is created, and a **confidence
  downgrade** for test/example paths — never a suppression.
- **Central redaction at the `Finding` boundary**, so a report cannot leak a live
  credential and neither can a fingerprint.

Long lines: the anchored rules read the **whole** line; the unanchored passes stop
at 4000 characters and the coverage note says which of the two ran.

### ✅ `aisec` — the agent attack surface

**29 rules across six families.** Re-derive with
`grep -oE 'rule_id="[a-z0-9-]+"' scripts/engine_aisec.py | sort -u`.

| Family | Rules | What it catches |
|---|---|---|
| **Prompt injection** | 6 | instruction-override phrasing (9 languages), role/authority hijack, system-role forgery, agent-directed imperatives, new-instruction framing |
| **Hidden content** | 5 | zero-width and invisible Unicode, Unicode-Tags ASCII smuggling (U+E0000–E007F), bidirectional Trojan Source controls, raw ANSI/CSI terminal escapes, instruction-bearing HTML comments, mixed-script homoglyph domains |
| **Exfiltration** | 7 | remote-execution pipes, PowerShell download-and-exec, environment dumps, DNS exfiltration, base64 exfiltration, sensitive-file reads, markdown-image beacons |
| **Dangerous hooks** | 4 | agent hooks that auto-run (Claude Code, Cursor, Windsurf, Cline/Roo, Codeium, Gemini), git hooks (24 names), npm lifecycle scripts, network-executing git hooks |
| **Safety bypass** | 3 | text telling an agent to turn off its guardrails, approve without review, or raise its own privileges; dangerous permission flags |
| **MCP** | 2 | servers that auto-start from an unpinned source, credentials handed to a server — across 5 manifest names *and* any file whose content declares `mcpServers` |
| **Encoded payloads** | — | base64, hex and URL-encoded payloads decoded **one level** and rescanned against the tables above |

**Vendor-neutral by design.** A hostile `.cursorrules` is the same attack as a
hostile `CLAUDE.md`; PRAETOR must not see only one vendor's spelling.

**Reaches into pruned directories by name.** A hostile agent config inside
`vendor/` or `node_modules/` is found, because those directory names are chosen
by the scanned tree and are therefore an attacker-controlled scope boundary.
`.git/hooks/` is walked deliberately — it is the one path inside `.git` that git
executes.

### ✅ `sast` — Semgrep

Bundled offline ruleset (**15 rules** written for PRAETOR, MIT, authored from the
underlying vulnerability concept rather than copied) plus, by default, curated
public packs when the network is reachable. Runs natively, or via WSL or Docker.

⚠️ A `.semgrepignore` inside the scanned tree once switched this engine off at
exit 0. Scope disagreement between PRAETOR and Semgrep is now itself a finding.

### ✅ `sca` — known-vulnerable dependencies

`osv-scanner` preferred (a purely static lockfile read), falling back to
`pip-audit --disable-pip --no-deps` and `npm audit` with the registry pinned on
the command line, so a target-controlled npm config file cannot redirect the
audit request to an attacker host.
Grouped one finding per vulnerable package, carrying max severity, advisory IDs
and the upgrade path.

### ✅ `model` — serialized models and pickles

**15 file extensions**: `.pt` `.pth` `.ckpt` `.pkl` `.pickle` `.npy` `.npz` `.h5`
`.hdf5` `.keras` `.bin` `.joblib` `.dill` and zip-wrapped containers.

Disassembles the pickle opcode stream with `pickletools.genops()` and never calls
`pickle.load`. Reports **dangerous globals** — `os.system`, `subprocess.*`,
`builtins.eval`, gadget-chain components — referenced by `GLOBAL` or
`STACK_GLOBAL`. A bounded heuristic for Keras `Lambda`-layer RCE in HDF5.
`.safetensors` is recognised as safe by design.

---

## 2. The interpretation layer — the part that makes five engines one answer

### ✅ Dedup, rank, corroborate
Category-aware identity: distinct CVEs on one package stay distinct; the same
leaked token found by two engines merges and *raises confidence*; the same CWE on
one line from a bundled rule and a registry rule merges and records both.

### ✅ False-positive filtering that is auditable
Filtered findings move to a separate bucket **carrying a written reason**. Nothing
is deleted. Four suppression passes, each narrowly scoped:

| Pass | Suppresses | Cannot touch |
|---|---|---|
| lexical context | a **behaviour** in a comment or docstring | instructions, hidden content, secrets |
| reachability | a string that provably never reaches a sink *in that file* | secrets, model findings |
| injection exemplar | a **quoted** injection specimen inside text that tells the reader to treat it as data | anything unquoted or unframed |
| prohibition | a safety-bypass phrase **governed by an adjacent prohibition** in the author's own prose | live code, trailing prohibitions, any ungoverned occurrence on the line |

Every one of these fails **safe**: unproven means KEEP.

### ✅ Attack chains
Findings that COMPOSE, reported as a separate add-only section. Each states its
`basis`: `same-file` is real evidence and may exceed its links' severity;
`same-tree` is co-occurrence, capped at MEDIUM in code, and is a prompt to look.

### ✅ Agent capability profile
Six dimensions answering *"if I open this repository in an agent right now, what
have I authorised?"* — executes on load, holds credentials, reaches network,
carries agent instructions, hides content from review, runs unpinned code. Each
reports `present` or `none`, **never** `safe`, with the worst severity behind it
and production evidence split from test/example evidence.

---

## 3. The output contract

### ✅ Text report
Engine status first, then the capability profile, the chains, the ranked
findings, the filtered bucket with reasons, the coverage notes, and the limits.

### ✅ JSON, `schema_version` 4.2
Versioned and additive. The version history is in `README.md`; the rule is that a
MINOR bump only adds keys.

**For anything consuming PRAETOR programmatically — a dashboard, a CI gate, a
triage store — these are the fields that matter:**

| Field | Use it for |
|---|---|
| `fingerprint` | **cross-scan identity.** Survives the finding moving within its file. Key trend views and "new since last scan" on this. |
| `dedup_key` | within-scan identity. Includes the line, deliberately. Do **not** use it across scans. |
| `meta.engines[name].status` | whether an engine actually ran. Only `ok` means its zero means something. |
| `meta.scope.*` | what the walker refused: skipped dirs, oversize, binary, unstattable, excluded-by-pattern. |
| `chains` / `capability_profile` | the two interpretation sections. Always present; empty is not "safe". |
| exit code | `0` no findings at/above the gate · `1` findings · `2` usage error · `3` **the scan was not measured enough to pass** |

🔴 A consumer that reads only the exit code cannot tell "clean" from "half the
engines never ran". Read `meta.engines`.

### 🔨 SARIF output
The interchange format GitHub code scanning, Azure DevOps and most enterprise
tooling consume. PRAETOR's `fingerprint` already matches SARIF's
`partialFingerprints` concept, which is the hard part.

### 🔨 Scan provenance in `meta`
Target repository, commit SHA, scan duration, and per-engine timings — so a
dashboard can show a trend line against commits rather than against wall-clock.

---

## 4. Distribution

| | Status |
|---|---|
| GitHub Action (`action.yml`, composite) | ✅ |
| pre-commit hook (`.pre-commit-hooks.yaml`) | ✅ |
| Publish workflow (`publish.yml`, OIDC trusted publishing, no stored token) | ✅ |
| **PyPI release** | 🔨 **blocked on the owner's login** — pending-publisher registration |
| Editor/IDE integration | 🔬 |

---

## 5. What PRAETOR deliberately does not do

- ❌ **Execute, import, install or build the target.** Rule 1.
- ❌ **Phone home.** No telemetry, no licence check, no usage counting. The CLI is
  uncapped and always will be; the commercial layer is the hosted product.
- ❌ **Claim a repository is safe.** It reports what matched.
- ❌ **Suppress on path alone.** A credential in `.env.example` is still a
  credential. Renaming a file must never disarm the scanner.
- ❌ **Runtime, logic and authorization flaws.** Static analysis cannot see them.
- ❌ **Decode more than one level.** Following attacker-chosen nesting to an
  attacker-chosen depth is how a scanner is made to spend unbounded time on one
  file.

---

## 6. Committed direction

### 🔨 Cross-file analysis — "spatial awareness"
Today every built-in engine is per-file, and reachability is per-file too. An
attacker who spreads a payload across a long call chain — a string assembled in
fragments, a dangerous call reached through three layers of indirection — is
invisible to a per-file view. This is the largest single capability gap and is
being designed against real technique research, staged so each stage is
shippable.

### 🔨 Self-authored rule packs
Semgrep's registry packs are proprietary-licensed since December 2024 and cannot
legally be run on a customer's behalf by a hosted service. PRAETOR's own packs
remove that dependency. `rules/semgrep-praetor.yaml` already sets the discipline:
authored from the vulnerability concept, never copied from another project's rule
body.

### 🔨 Command-position analysis
The right fix for the largest remaining false-positive class: is a matched token
somewhere it would actually be passed to a program, or is it prose about it? This
subsumes several regex-level heuristics and does not depend on wording at all.

---

## 7. Where the numbers in this document come from

| Claim | Command |
|---|---|
| 17 provider patterns | `python -c "import sys;sys.path.insert(0,'scripts');import engine_secrets as s;print(len(s.PROVIDERS))"` |
| 29 aisec rules | `grep -oE 'rule_id="[a-z0-9-]+"' scripts/engine_aisec.py \| sort -u \| wc -l` |
| 15 bundled Semgrep rules | `grep -c '  - id:' rules/semgrep-praetor.yaml` |
| 24 git hook names | `python -c "import sys;sys.path.insert(0,'scripts');import core;print(len(core.GIT_HOOK_NAMES))"` |
| test count, gate state | `bash tests/precommit.sh; echo $?` |

⚠️ This table exists because a count in prose rots. This repository has already
had a document claim "9 checks" while the gate had grown to 13. **Read the number
off the code, not off this page.**

---

## 8. A note this document had to earn

Two lines of the text above were themselves findings in PRAETOR's own self-scan
when first written: the safety-bypass row, which listed the phrases that rule
detects, and the SCA paragraph, which named a config file the exfiltration rule
watches for.

Both were reworded to DESCRIBE rather than REPRODUCE — the same remedy a
downstream team applied after measuring that their report of these false
positives generated five more of them.

It is left recorded rather than tidied away. A scanner that taxes the
documentation of its own behaviour has a real cost, that cost lands hardest on
whoever is trying to improve it, and the fix for it is tracked in §6.
