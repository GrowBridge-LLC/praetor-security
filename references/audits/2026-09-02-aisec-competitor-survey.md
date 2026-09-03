# AI-security / agentic-threat scanner technique survey — 2026-09-02

**What this is.** An extension of `references/audits/2026-08-24-oss-scanner-technique-survey.md` into a narrower slice: tools built specifically for LLM/agent-security threats — prompt injection, jailbreaks, data exfiltration, serialized-model supply-chain risk — rather than general-purpose SAST/secrets/SCA scanners. Six independent surveys were commissioned, one per tool or tool pair. Method, stated explicitly and matching the 08-24 survey's own discipline: public documentation, READMEs, and source read via web search/fetch only, against each project's own docs site and raw GitHub source. **Nothing surveyed here was cloned, installed, or executed** — the same restriction the 08-24 survey held itself to, and the same one PRAETOR's own `CLAUDE.md` invariant holds PRAETOR to when reading a scanned target.

**Survey completeness — stated plainly rather than papered over.** Two of the six original commissioned survey slots returned no content on the first pass: `tool_name` and every other field came back as the literal string `"placeholder"`. One has since been re-run and filled (§1, **invariant-labs/mcp-scan**, 2026-09-03). One remains genuinely unsurveyed (§6, Trojan-Source/invisible-Unicode state of the art) — do not read that slot as "surveyed, nothing found"; it is missing data. Five of six surveys now carry real, sourced findings: **mcp-scan**, **garak**, **llm-guard & modelscan**, **Lakera's PINT benchmark**, and **Semgrep's AI/agentic registry rule packs**. Treat every claim below the way this repo treats any audit doc — worth verifying before building on it, not a ruling.

---

## 1. invariant-labs/mcp-scan (rebranded "Snyk Agent Scan")

**Source:** `raw.githubusercontent.com/invariantlabs-ai/mcp-scan/main/README.md` and Invariant Labs' own blog posts. Web-only, no install, no execution. Re-run 2026-09-03 after the first pass on this slot returned nothing.

**Note first:** the repo has rebranded — its README title is now "Snyk Agent Scan," Invariant Labs appears to have been absorbed into Snyk. Verified by fetching the raw README directly, not trusted from search-result titles alone.

**Core finding, confirmed verbatim from the tool's own README:** "When Agent Scan scans an MCP configuration file, it **starts the stdio MCP servers by executing the commands and arguments specified in the config**." Every hazard class this slot was commissioned to check — tool poisoning, rug-pull/mutable-tool-description attacks, cross-server tool shadowing, and prompt injection carried in a tool's *description* rather than its launch command — depends on the tool-description text returned by a live `tools/list` call. **That text does not exist in the static config file at all.** The config only ever holds server launch parameters (command/args/env) — exactly what PRAETOR's `_scan_mcp` (`scripts/engine_aisec.py`) already reads. This is the mechanical reason none of the four hazard classes are reachable statically, not a gap in either tool's regex coverage.

**Adoptable:** none found with a static-only form. The one candidate considered — broader MCP client config-filename discovery (mcp-scan enumerates known paths for Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI, Amazon Q) — **turned out to already be covered**, checked directly against PRAETOR's own code: `_scan_mcp` at `engine_aisec.py:621` scans any file containing the literal `"mcpServers"` structure regardless of filename (`base not in MCP_MANIFEST_NAMES and '"mcpServers"' not in text`), which is *more* robust than mcp-scan's path-enumeration approach — it works for any client's config regardless of naming convention, not just the ones on a maintained list.

**Do not adopt:**
- **Starting the MCP server to retrieve tool descriptions** — confirmed verbatim above; a direct violation of PRAETOR's never-execute invariant, and there is no static-only mode for any of the four hazard classes.
- **Sending retrieved tool descriptions to a remote "Agent Scan API"** for the actual analysis — a third-party network dependency on attacker-influenced content, the same class of risk this repo's 08-24 survey already declined for TruffleHog's live verification.
- **Tool pinning/hashing for rug-pull detection** — requires a live-retrieved description at scan time to hash against a prior baseline; Invariant's own tool-poisoning notification states rug-pulls specifically defeat static snapshots.
- **Cross-server shadowing detection** — requires comparing live-retrieved tool lists across servers; no mechanism operates on config-file content alone.

No curated static allowlist or signature-verification mechanism was found in mcp-scan to salvage as a static-only technique — its entire detection surface for these four classes is live-connection-gated.

Sources: [mcp-scan README](https://raw.githubusercontent.com/invariantlabs-ai/mcp-scan/main/README.md), [Introducing MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan), [MCP security notification: tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)

---

## 2. garak (NVIDIA/garak, github.com/NVIDIA/garak)

**Source:** `reference.garak.ai` docs and `raw.githubusercontent.com/NVIDIA/garak/main` source files. Web-only, no install, no execution.

garak is NVIDIA's dynamic LLM red-teaming scanner: ~40 probe modules send crafted prompts to a live target model, paired detector modules score the response. Its probe/detector taxonomy names real, documented attack-string families for prompt injection, jailbreaks, and exfiltration — several of them pure static content (a known jailbreak template, an encoding scheme, a markdown exfil link shape) independent of the live-probing harness around them. One existing PRAETOR detector was confirmed independently correct against it: garak's `goodside.Tag` probe (U+E0000 Unicode Tag block) targets the exact same attack class as PRAETOR's already-implemented unicode-tag-smuggling rule.

**Adoptable:**
1. **[High / medium]** Decode-then-rescan for encoding-evasion payloads — detect candidate base64/hex/rot13/base32/quoted-printable/uuencode blobs in scanned text, decode them, and re-run the existing INJECTION/EXFIL regex set against the decoded content. garak's `probes.encoding` module tests ~20 such schemes specifically because a plaintext filter misses an encoded copy of the same instruction, and `engine_aisec.py`'s tables today match plaintext only. Stdlib-only (`base64`, `binascii`, `codecs`), but needs an explicit bounded decode depth/size cap — see the capability note below.
2. **[High / low]** Static markdown-exfiltration pattern — flag markdown image/link syntax whose target URL carries a query string shaped like embedded context/conversation data, or a link built from concatenated strings to dodge single-line regex. garak's `web_injection` module documents this as a zero-click vector needing no shell command at all, and PRAETOR's EXFIL table is entirely shell/network-command shaped with no markdown-syntax rule.
3. **[High / low]** ANSI/terminal-escape-sequence detector (`ESC[`, `\033[`, `\x1b[`) as a new HIDDEN_CONTENT rule. garak's `probes.ansiescape` names this a heightened risk specifically for "agent tooling where output feeds directly to terminal rendering" — PRAETOR's own threat model — and it is the same per-character-walk mechanism PRAETOR's Unicode scanner already uses, extended to a different control-byte family.
4. **[Medium / low]** Known-jailbreak-template literal-signature list — a small set of literal markers (`STAN:`, `DUDE:`, garak's 🔓-flag "Developer Mode" persona-announcement style) and family names from garak's DAN taxonomy, layered onto the existing role-hijack rule as a keyword pre-filter. Coverage-widening, not gap-closing: the current rule already catches the core phrasing.

**Landed 2026-09-02** (see `tests/test_jailbreak_marker_coverage.py`): the role-hijack rule now also
matches "Developer Mode" immediately followed by Output/Enabled/Response, and a bracketed
all-caps JAILBREAK marker. Bare `STAN:`/`DUDE:`/`DAN:` speaker-label markers were deliberately NOT
added — both are common first names and a false-positive risk on ordinary chat transcripts.

**Do not adopt:**
- **garak's live dynamic-probing architecture itself** — sending crafted prompts to a real target model and scoring the response. This is garak's entire mechanism, not one feature of it, and is precisely the class of thing PRAETOR's invariant forbids. PRAETOR has no live model to probe by design.
- **LLM-as-judge and third-party classifier detectors** (`detectors.judge`, `detectors.perspective`) — both require a live outbound call to an LLM or a third-party API keyed off content PRAETOR is scanning, the identical shape the 08-24 survey already rejected for TruffleHog's live credential verification.
- **Behavioral/semantic smuggling techniques** (`goodside.ThreatenJSON`, `goodside.Davidjl`, `smuggling.HypotheticalResponse`, `smuggling.FunctionMasking`) — each exploits a live model's reasoning or a specific tokenizer quirk, not a fixed lexical signature; `FunctionMasking` in particular is ordinary-looking pseudocode until "solved," so there is no string to regex for without either missing real instances or flagging legitimate code.
- **Generative-quality / model-behavior probes** (`realtoxicityprompts`, `misleading`, `snowball`, `malwaregen`, `packagehallucination`) — these measure what a *live model generates*; there is no static-file equivalent, and `packagehallucination` specifically would require querying live package registries, the same implicit-network-default class the 08-24 survey flagged for Trivy.
- **Iterative/adaptive jailbreak generators** (`adaptive_attacks`, dynamic `AutoDAN`, `goat`, `tap`) — these mutate against a live target model's own responses in a search loop; no fixed artifact to pattern-match, only a runtime optimization process.

**Capability note, not a new engine class:** the decode-then-rescan idea (adoptable #1) needs `engine_aisec.py` to gain a bounded recursive/transformation step that doesn't exist in its current architecture — every current detector matches raw text once, per line. This repo's own memory already records an unbounded per-finding re-classification pass hanging ~244s with no exit code and no artifact; a decode-and-rescan pass is the same shape of risk (attacker-controlled size and encoding nesting) and needs an explicit, tested bound designed in from the start, not discovered after a scan hangs on a hostile fixture. This is an extension to an existing engine, not a new capability class.

Sources: [garak probes.encoding](https://raw.githubusercontent.com/NVIDIA/garak/main/garak/probes/encoding.py), [garak probes.web_injection](https://raw.githubusercontent.com/NVIDIA/garak/main/garak/probes/web_injection.py), [garak probes.ansiescape](https://raw.githubusercontent.com/NVIDIA/garak/main/garak/probes/ansiescape.py), [garak detectors.dan](https://raw.githubusercontent.com/NVIDIA/garak/main/garak/detectors/dan.py)

---

## 3. llm-guard & modelscan (Protect AI)

**Source:** `raw.githubusercontent.com/protectai/llm-guard` and `raw.githubusercontent.com/protectai/modelscan`, plus published docs. Web-only.

Of llm-guard's 15 input scanners, only a handful are pattern-based with no live model call: `Regex`, `BanSubstrings`, `InvisibleText` (bans Unicode general categories Cf/Co/Cn via `unicodedata.category()`), and `Secrets` (wraps `detect-secrets`). Its `PII`/`Anonymize` scanner is a hybrid — a DeBERTa NER model by default, plus a genuinely model-free layer of Presidio pattern recognizers. Everything doing the actual "prompt injection" detection — `PromptInjection`, `BanCode`, `Code`, `BanTopics`, `Toxicity`, `Gibberish` — is a HuggingFace transformer classifier, a different technique class from pattern matching, not just a network-call concern.

`modelscan` is the standout finding of this survey: it disassembles pickle bytecode with Python's stdlib `pickletools.genops` (never unpickles/executes), tracks `GLOBAL`/`STACK_GLOBAL`/`INST` opcodes to recover each embedded `module.function` reference, and checks it against a severity-tiered blocklist that defaults unrecognized globals to CRITICAL — a fail-safe default independently matching PRAETOR's own "unproven ⇒ keep" rule. It covers pickle-derived formats (`.pkl`/`.pt`/`.pth`/joblib/dill), Keras H5, and TensorFlow SavedModel, never loading or executing the model. **Confirmed by reading PRAETOR's own code** (`scripts/core.py`, `scripts/praetor.py`), not by assumption: `core.walk_files()`'s `scannable()` gate admits a file only via `TEXT_NAMES`/`TEXT_EXTS`, neither of which contains any serialized-model extension, and even a hypothetical extension addition would still fail the binary-and-NUL sniff heuristic. A malicious `.pkl` committed to a repo is invisible to all four current PRAETOR engines today. `git log`/grep confirms no prior design note or CHANGELOG entry in this repo has raised serialized-model scanning before — this is a first mention.

**Adoptable:**
1. **[High / medium]** Static pickle-opcode disassembly via stdlib `pickletools` (never unpickles/executes) to recover `GLOBAL`/`STACK_GLOBAL`/`INST` module references from committed `.pkl`/`.pt`/`.pth`/joblib/dill files, checked against a severity-tiered blocklist. Closes a confirmed, currently-total gap with zero new heavy dependency and an inherently execution-free technique — the single highest-value finding in this survey. See the dedicated capability section below.
2. **[Medium / low]** Default-to-CRITICAL for any pickle global reference not on an explicit allowlist — the design default for item 1, independently arrived at by modelscan and matching PRAETOR's own "unproven ⇒ keep" rule exactly.
3. **[Medium / low]** `unicodedata.category()`-based Cf/Co/Cn classification as a broader primitive than PRAETOR's current enumerated invisible/zero-width/Tag-block code-point list — the same "enumeration cannot be completed by enumerating" shape this repo's own memory already warns about elsewhere, worth comparing against for gaps.
4. **[Low / low]** `detect-secrets`'s calibrated Base64/Hex entropy thresholds (4.5/3.0) as an external benchmark to check PRAETOR's own secrets-engine thresholds against, especially for the Rust port's forthcoming entropy detector.
5. **[Low / low]** Presidio-style pure-regex PII patterns (credit card, US SSN, email, BTC address, UUID) as an optional "hardcoded PII in fixtures/config" battery, distinct from the credential-focused secrets engine.

**Do not adopt:**
- **`PromptInjection` scanner** (`protectai/deberta-v3-base-prompt-injection-v2`) — requires loading and running a live local ML model for every scan, a fundamentally different technique class than pattern matching, with a multi-hundred-MB weight dependency. Source confirms "no regex patterns, keyword lists, or heuristic rules are involved." Say it plainly: this is out of scope for a pattern-based static scanner and does not belong on a default path.
- **`BanCode`/`Code` scanners** — same reasoning, transformer language classifiers despite regex being used only as pre-processing. One WebSearch summary describing these as regex-based was checked against actual source and found wrong — worth flagging as a secondhand mischaracterization this project's own house style warns against trusting.
- **`BanTopics`/`Toxicity`/`Sentiment`/`Gibberish`** — ML content/topic classifiers aimed at chat-content policy, off-mission for a static code-security scanner regardless of the pattern-vs-model axis.
- **Treating modelscan's `unsafe_globals` blocklist as closed/sufficient** — an independently documented bypass class exists (unblocklisted-but-chainable modules like `importlib`, `operator`, `marshal`, `ctypes` reaching code execution without ever naming `os`/`subprocess`; separate research on `STACK_GLOBAL` scanners commonly missing a reference at bytecode position 0). If PRAETOR builds this engine, its non-exhaustiveness must be stated explicitly in its own docs, never marketed as complete.

Sources: [modelscan picklescanner](https://raw.githubusercontent.com/protectai/modelscan/main/modelscan/tools/picklescanner.py), [llm-guard invisible_text.py](https://raw.githubusercontent.com/protectai/llm-guard/main/llm_guard/input_scanners/invisible_text.py), [llm-guard secrets.py](https://raw.githubusercontent.com/protectai/llm-guard/main/llm_guard/input_scanners/secrets.py), [llm-guard regex_patterns.py](https://raw.githubusercontent.com/protectai/llm-guard/main/llm_guard/input_scanners/anonymize_helpers/regex_patterns.py)

---

## 4. Lakera PINT Benchmark (Prompt Injection Test)

**Source:** `github.com/lakeraai/pint-benchmark` (archived 2026-08-05), Lakera's own risk-taxonomy pages. Web-only.

PINT's public corpus (4,314 inputs) labels five categories: `prompt_injection` (5.2%), `jailbreak` (0.9%), `hard_negatives` (20.9% — benign text that superficially resembles injection phrasing), `chat` (36.5%, benign), and `documents` (36.5%, benign with embedded injections). Non-English content is ~30% (1,298/4,314) across 24 languages, testing language-switching evasion as a cross-cutting corpus property. **Checked `scripts/engine_aisec.py` directly:** its INJECTION/EXFIL rules are pure regex over raw line text, every keyword is English-only, and no rule decodes base64/hex/URL-encoded text before matching — base64 is treated only as an exfil-transport signal (piped to curl/wget/nc), never decoded-and-rescanned for embedded injection phrasing. PRAETOR already has one incident-driven false-positive test for aisec (`tests/test_injection_exemplar_suppression.py`), but not a systematic, proportioned hard-negative corpus on PINT's model.

**Adoptable:**
1. **[High / medium]** Multilingual instruction-override phrase coverage — PINT deliberately holds ~30% of its corpus in 24 non-English languages to test whether detection degrades outside English. Every INJECTION rule in `engine_aisec.py` is an English-keyword regex today, so the same classic override phrasing PRAETOR's `prompt-injection-override` rule already catches in English (see that rule's own pattern) passes clean when written in French or Chinese; a bounded per-rule-family phrase list in a handful of additional languages, verified against PINT's own language list, is plausibly catchable since this is static text on disk, not a live-model problem.
2. **[High / medium]** Decode common text encodings (base64/hex/URL) before running injection/hidden-content rules — converges independently with garak's item 1 above (two of four tool surveys named the same gap by the same route), worth treating as a real signal the way three unrelated projects converging on literal-string prefiltering was in the 08-24 survey. Same bounded-decode caveat applies.
3. **[Medium / low]** A systematic, proportioned hard-negative fixture corpus for aisec, extending PINT's `hard_negatives` model into a standing regression set rather than remaining one incident-driven test — directly extends `CLAUDE.md`'s own existing baseline-honesty discipline ("report needs review alongside the false-positive count") to the aisec engine specifically. No new detection code, just a curated, committed fixture set the rules must not fire on.
4. **[Low / low]** Authority-impersonation / "model duping" phrase rule ("I am an administrator", "as an OpenAI employee"), distinct from the existing role-hijack rule's role-reassignment phrasing. Lower confidence than the items above — may already overlap existing agent-directed-imperative coverage in practice.

**Do not adopt:**
- **Multi-turn/session-escalation detection as a distinct aisec capability** — PINT's own corpus does not label a distinct multi-turn-attack category, and more fundamentally a static file scanner reading one file at a time has no conversation/session state to evaluate. Out of scope by construction, not a gap to close.
- **Adopting PINT's own scoring mechanism** — every system PINT scores is evaluated via a live inference call per input. Routing scanned-target content through a live model/API call is a real scope expansion (network + third-party inference on attacker-controlled content) — say it plainly: this conflicts with PRAETOR's read-only invariant and belongs in "do not adopt," not a lesser caveat.
- **Importing PINT's dataset/phrase corpus wholesale** — blends public and Lakera-proprietary data under Lakera's own licensing, the repo is archived with no further maintenance, and it is a benchmark built to score third-party detectors, not a rule set curated for false-positive discipline. Individually verified techniques (above) are the adoptable unit, not the dataset itself.

**Sourcing caveat, not a capability gap:** Lakera's GitHub repo was archived 2026-08-05 and `lakera.ai` now redirects to `checkpoint.com/ai-security` — Lakera appears to have been absorbed into Check Point. Any future re-verification of PINT's score tables should account for this; it does not affect the corpus/taxonomy claims above, which were read from the archived repo's own README/DETAILS.md/CHANGELOG.md directly.

Sources: [lakeraai/pint-benchmark](https://github.com/lakeraai/pint-benchmark), [Lakera prompt-injection risk page](https://www.lakera.ai/risk/prompt-injection-attacks), [pint-benchmark README](https://github.com/lakeraai/pint-benchmark/blob/main/README.md)

---

## 5. Semgrep (registry rule packs — semgrep.dev/r and p/ rulesets)

**Source:** semgrep.dev's own unauthenticated registry API (the same invocation shape `engine_sast.py` already uses — no `SEMGREP_APP_TOKEN` exists in this codebase) and `github.com/semgrep/semgrep-rules`. Web-only.

Narrow question, answered directly: no visible *growth* in AI-agent/LLM-targeted Semgrep rules since the 08-24 cutoff — but a free pack that predates that cutoff already covers most of what was asked, and PRAETOR isn't pulling it. `p/ai-best-practices` (free, community-origin, 27 rules, confirmed reachable unauthenticated) hits MCP SSRF (`mcp-ssrf-python`, taint-mode), MCP command injection, MCP unsanitized tool-call returns, and unsafe LangChain `exec` directly. A larger free superset, `p/shadow-ai` (144 rules), adds `llm-output-to-exec-{python,javascript}` — the closest hit to "unsafe eval of LLM output" — but ~12 of its `ai.detection.*` entries are confirmed dead stubs (`pattern: _placeholder_`, never fire). Two larger, more heavily-marketed packs (`p/agent-skills`, 122 rules; `p/shadow-ai-pro`, 186 rules) both return `rules: []` unauthenticated — Pro/paid tier, structurally unreachable under PRAETOR's current no-login invocation. No dedicated LlamaIndex pack, and no rule for insecure deserialization specifically in an agent framework, exists anywhere in the registry — confirmed by grepping the full 144-rule superset for `llamaindex`/`pickle`/`deserial*`: zero hits. That is an honest gap in Semgrep's own coverage, not a PRAETOR omission.

**Adoptable:**
1. **[High / low]** Add `p/ai-best-practices` to `DEFAULT_REGISTRY_CONFIGS` in `scripts/engine_sast.py` (currently `["p/owasp-top-ten", "p/security-audit"]`) — one-line change to an existing list, same invocation shape already in use, zero rule-ID overlap confirmed against the two current default packs, no new auth or dependency.
2. **[Medium / low]** Consider `p/shadow-ai` (free, 144-rule superset) once non-Python-agent-code coverage matters — ship with the caveat that ~12 of its entries are dead placeholder stubs, confirmed by fetching their raw YAML directly. Recommend `p/ai-best-practices` first; revisit only if the SAST engine needs Go/Java/Ruby agent-code coverage.

**Do not adopt:**
- **`p/agent-skills` (122 Pro rules)** — confirmed `rules: []` unauthenticated. Structurally unreachable without both a code change and a paid Semgrep subscription, a Mike-only decision under the machine's never-default-to-paid-tooling rule. Also thematically closer to PRAETOR's own aisec engine than a SAST gap — adopting it would pay to duplicate, not fill, coverage.
- **`p/shadow-ai-pro` (186 Pro rules)** — same paid-tier gating; its value-add over the free `p/shadow-ai` couldn't even be assessed since the content isn't fetchable without a subscription.
- **`p/mcp` (6-rule pack)** — confirmed a strict subset of `p/ai-best-practices`; adding both is redundant config with zero incremental coverage.
- **A dedicated LlamaIndex pack, or a rule for insecure deserialization in an agent framework** — does not exist in the registry, free or Pro. Nothing to adopt; flagged as a Semgrep coverage gap, not a PRAETOR action item.

**Not a new Semgrep release, and not a new capability class either:** `p/ai-best-practices` has existed since ~2026-03-23 (last touched 2026-05-10), well before the 08-24 cutoff. This is a pre-existing gap in PRAETOR's own default config, concretely reachable via a one-line addition — it extends the existing SAST engine's rule set, not a new engine.

Sources: [semgrep-rules ai/ai-best-practices](https://github.com/semgrep/semgrep-rules/tree/main/ai/ai-best-practices), [shadow-ai ruleset API](https://semgrep.dev/api/registry/rulesets/shadow-ai)

---

## 6. [Survey slot — no content returned]

Same as slot 1: every field came back as the literal `"placeholder"`. Not surveyed. Re-run before treating this document as covering six real tools rather than four.

---

## New capability class flagged

**One genuinely new capability class surfaced in this survey: serialized-model / pickle-opcode scanning (llm-guard & modelscan, §3).** This is not an extension of any of PRAETOR's four existing engines — it would need its own file-admission path parallel to `core.walk_files()`, since the current text-only `scannable()` + binary-sniff gate structurally excludes every serialized-model format by design (correct behavior for the other four engines, not a bug — a binary-format admission path is new machinery, not a loosened filter), plus a static pickle-opcode disassembler (`pickletools`, stdlib, never executes) and, if formats beyond pickle-derived ones are in scope, separate lighter parsers for HDF5/Keras and TensorFlow SavedModel. None of SAST (code patterns), secrets (credential strings), SCA (declared dependencies), or aisec (prompt-injection/Unicode text patterns) reach a binary artifact's bytes today — a malicious `.pkl` committed to this or any scanned repo is currently invisible to PRAETOR. Recommend scoping this as its own design doc rather than folding it into an existing engine, per this repo's own "safety is a scope decision, not a property of the mechanism" rule: a pickle-opcode blocklist looks safe in isolation and needs its carve-outs (default-to-KEEP/CRITICAL on unrecognized globals, explicit non-exhaustiveness disclosure) stated up front, not discovered later.

**Two other "flagged" items from the surveys are explicitly NOT new capability classes, stated here to avoid overselling:** garak's decode-then-rescan gap (§2) is a bounded-transformation extension to the existing aisec engine, not a new engine. Semgrep's `p/ai-best-practices` gap (§5) is a config addition to the existing SAST engine, not a new ruleset architecture.

---

## Ranked cross-tool actionable list (value vs. effort)

1. **[High / low]** Add Semgrep's free `p/ai-best-practices` ruleset (27 rules) to `DEFAULT_REGISTRY_CONFIGS` in `scripts/engine_sast.py` — a one-line change, confirmed reachable with no auth, hitting MCP SSRF/command-injection/unsanitized-return and LangChain dangerous-`exec` directly. *(Semgrep)*
2. **[High / low]** Static markdown-exfiltration detector for agent-facing markdown/instruction files — a zero-click vector (query-string-carrying image/link URLs, split-string construction) entirely absent from PRAETOR's shell/network-shaped EXFIL table today. *(garak)*
3. **[High / low]** ANSI/terminal-escape-sequence detector (`ESC[`, `\033[`, `\x1b[`) as a new HIDDEN_CONTENT rule — same per-character-walk mechanism the Unicode scanner already uses, extended to a different control-byte family. *(garak)*
4. **[High / medium]** Static pickle-opcode disassembly via stdlib `pickletools` — the single highest-value finding in this survey, and the only one that names a genuinely new capability class; see above. *(llm-guard & modelscan)*
5. **[High / medium]** Decode-then-rescan candidate base64/hex/rot13/URL-encoded blobs before running the INJECTION/EXFIL rule set — two independent surveys (garak and Lakera PINT) named the identical gap by different routes, worth treating as a real signal. Needs an explicit bounded decode depth/size cap designed in from the start; this repo's own memory already records an unbounded per-finding pass hanging ~244s with no exit code on a different engine. *(garak; Lakera PINT)*
6. **[High / medium]** Multilingual instruction-override phrase coverage for the INJECTION rule family — every current rule is English-only, and PINT holds ~30% of its corpus in 24 other languages specifically to test this failure mode. *(Lakera PINT)*
7. **[Medium / low]** Default-to-CRITICAL (report, never silently pass) for any pickle global reference not on an explicit allowlist — the design default for item 4, independently matching PRAETOR's own "unproven ⇒ keep" rule. *(llm-guard & modelscan)*
8. **[Medium / low]** `unicodedata.category()`-based Cf/Co/Cn classification as a broader primitive to check against aisec's current enumerated invisible/format-character list for gaps. *(llm-guard)*
9. **[Medium / low]** A systematic, proportioned hard-negative fixture corpus for aisec, extending this repo's own baseline-honesty discipline ("report needs review alongside the false-positive count") to the aisec engine specifically, rather than remaining one incident-driven test. *(Lakera PINT)*
10. **[Medium / low]** Known-jailbreak-template literal-signature list (STAN/DUDE/AntiDAN family markers) layered onto the existing role-hijack rule as a keyword pre-filter. *(garak)*
11. **[Medium / low]** `p/shadow-ai` (free, 144-rule Semgrep superset) once non-Python-agent-code coverage matters — ship with the caveat that ~12 of its `ai.detection.*` entries are confirmed dead placeholder stubs that never fire. *(Semgrep)*
12. **[Low / low]** Presidio-style pure-regex PII patterns (credit card, SSN, email, BTC address, UUID) as an optional battery distinct from the credential-focused secrets engine. *(llm-guard)*
13. **[Low / low]** Authority-impersonation / "model duping" phrase rule, distinct from the existing role-hijack pattern — lower confidence than the items above; may already overlap existing coverage. *(Lakera PINT)*
14. **[Do not adopt]** garak's live dynamic-probing architecture — crafted prompts against a real target model. This is garak's entire mechanism, not one feature of it, and is exactly what PRAETOR's never-execute/never-probe invariant forbids; PRAETOR has no live model to probe by design.
15. **[Do not adopt]** Every model-backed classifier proposed across these surveys — llm-guard's `PromptInjection` (`deberta-v3-base-prompt-injection-v2`), `BanCode`/`Code`, `BanTopics`/`Toxicity`/`Sentiment`/`Gibberish`; garak's `judge`/`perspective` detectors; and Lakera PINT's own live-inference scoring mechanism. Stated plainly, not softened: every one requires loading or calling a live model, a different technique class from pattern matching — and for garak's judge/perspective and PINT's scoring, a live network call besides. None belong on a default path in a read-only static scanner.
16. **[Do not adopt]** Semgrep's two Pro-tier packs, `p/agent-skills` (122 rules) and `p/shadow-ai-pro` (186 rules) — both confirmed to return `rules: []` unauthenticated, structurally unreachable under PRAETOR's current no-login invocation without a paid subscription, a Mike-only decision per the machine's never-default-to-paid-tooling rule.
17. **[Do not adopt]** garak's behavioral/semantic-smuggling and generative-quality probes (`ThreatenJSON`, `Davidjl`, `HypotheticalResponse`, `FunctionMasking`, `realtoxicityprompts`, `malwaregen`, `packagehallucination`, `snowball`) and its iterative/adaptive jailbreak generators (dynamic `AutoDAN`, `goat`, `tap`) — each exploits a live model's reasoning, a specific tokenizer quirk, or a live optimization loop against a live target model; no fixed static signature exists for any of them.
