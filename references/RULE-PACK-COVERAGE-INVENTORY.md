# Rule-pack coverage inventory — step 1 of the self-authored rule-pack effort

**What this is.** The first step `references/ROADMAP-V1.md` §3a calls for before writing
any new rules: a mapping of what PRAETOR's own bundled ruleset covers today against what a
customer-facing hosted scan needs to not regress on, so new-rule effort goes to genuine gaps
first. **Not a rule-writing pass — no new rules are added in this document.**

**Why this exists at all.** Semgrep's own registry packs (`p/owasp-top-ten`,
`p/security-audit`, `p/ai-best-practices`) have been under a proprietary license since
December 2024 that forbids running them on a customer's behalf as a hosted service.
PRAETOR's local CLI use is unaffected, but a future hosted scan needs its own equivalent
coverage that isn't borrowed from a source that can't follow it there.

## Method and its real limits

`rules/semgrep-praetor.yaml`'s own coverage below is measured directly — read from the file,
every `owasp:`/`cwe:` tag counted, not estimated. **Semgrep's registry-side coverage is NOT
independently measured here.** Both `semgrep.dev/p/owasp-top-ten` and
`semgrep.dev/p/security-audit` are JavaScript-rendered pages that returned no usable content
to a fetch this session — attempted and failed, not skipped. What follows for the registry
side is the well-established, stable OWASP Top 10 (2021) category structure itself, which
doesn't need a live citation, plus general knowledge of what a "security audit" pack of this
kind typically spans. Treat the registry-side column as a reasonable planning approximation,
not a verified rule-for-rule count — a real registry-side inventory (via GitHub source or the
Semgrep CLI's own `--config` dry-run listing) is real follow-up work, not done here.

## PRAETOR's current coverage — measured directly, 15 rules

| OWASP category | PRAETOR rules | Languages |
|---|---|---|
| A02:2021 Cryptographic Failures | 2 — `requests-verify-false`, `weak-hash` | Python |
| A03:2021 Injection | 7 — `os-system-concat`, `subprocess-shell-true`, `eval-exec`, `sql-fstring` (Python); `child-process-exec-concat`, `eval`, `innerhtml` (JS) | Python, JavaScript |
| A04:2021 Insecure Design | 1 — `underscore-only-attribute-denylist` | Python |
| A05:2021 Security Misconfiguration | 1 — `flask-debug-true` | Python |
| A08:2021 Software and Data Integrity Failures | 2 — `yaml-load-unsafe`, `pickle-loads` | Python |
| LLM02 / LLM06 (OWASP *LLM* Top 10, a separate taxonomy) | 2 — `llm-output-to-shell`, `hardcoded-system-prompt-secret` | language-agnostic (aisec-style patterns, not a `languages:` SAST rule) |

## Gaps against the standard OWASP Top 10 (2021) — categorical, not a rule count

- **A01 Broken Access Control** — zero PRAETOR rules. Genuine gap; this category is usually
  framework-specific (missing `@login_required`-style decorators, IDOR patterns) and needs
  real design work, not a quick port.
- **A06 Vulnerable and Outdated Components** — zero SAST rules here **by design, not a gap**:
  PRAETOR's separate `sca` engine (`osv-scanner`/`pip-audit`) already owns this category
  entirely. Don't duplicate it as a SAST rule.
- **A07 Identification and Authentication Failures** — zero PRAETOR rules. Session-fixation,
  weak password-reset flows, missing MFA enforcement patterns. Real gap.
- **A09 Security Logging and Monitoring Failures** — zero PRAETOR rules. Genuinely hard to
  express as a single-file static pattern (it's usually an absence-of-something-across-the-
  codebase claim) — lowest priority of the four, flag rather than force a weak rule.
- **A10 Server-Side Request Forgery (SSRF)** — zero PRAETOR *web-framework* SSRF rules.
  Partially adjacent coverage already exists in a different form: `p/ai-best-practices`
  (already in PRAETOR's default registry config) covers **MCP-specific** SSRF, and
  `engine_aisec.py`'s own `EXFIL`/`env-exfil` rules catch a related but distinct shape
  (outbound data exfiltration, not inbound forged-request SSRF). A generic
  `requests.get(user_input)`-style SSRF rule is still a real, unaddressed gap.

## Other real gaps, not OWASP-Top-10-shaped

- **Language coverage is the biggest structural gap.** All 15 rules are Python or JavaScript.
  Zero coverage for Go, Java, Ruby, PHP, Rust, or C/C++ — each would need its own rule set,
  not a translation of the existing 15.
- **Path traversal (CWE-22)** — no PRAETOR rule. A common, high-signal, low-false-positive
  pattern (`open(user_input)`-style) that both Bandit and the Semgrep registry cover; a good
  early candidate given this session's research already flagged Bandit as the closest
  technique-source match for PRAETOR's SAST style.
- **Insecure randomness (CWE-330)** — `random`/`Math.random()` used for security-sensitive
  values (tokens, session IDs). No PRAETOR rule; common in both Bandit and Semgrep's audit
  pack.
- **Open redirect (CWE-601)** — no PRAETOR rule.
- **XXE (CWE-611)** — no PRAETOR rule; Python's `lxml`/`xml.etree` unsafe-parsing patterns are
  a well-known, well-scoped addition.
- **Hardcoded credentials** — deliberately **not** a SAST-rule gap: PRAETOR's `secrets`
  engine already owns this category structurally, and adding a SAST-side duplicate would
  violate this project's own dedup discipline.

## Recommended next-rule order, by effort/value (not committed, a proposal)

1. **Path traversal** and **insecure randomness** — both single-pattern, low-false-positive,
   directly following the existing rule style (`rules/semgrep-praetor.yaml`'s own template).
2. **A generic SSRF rule** (Python `requests`/`urllib`, JS `fetch`/`axios` with unsanitized
   URL input) — closes the clearest OWASP-category gap that isn't already covered elsewhere.
3. **XXE and open redirect** — well-scoped, lower urgency.
4. **A01/A07** — real gaps, but need actual design work (what does "missing access control"
   even look like as a single-file static pattern?) before any rule gets written, not a
   quick port from an existing idiom.
5. **A second language** (Go is the most likely next target given the estate's own stack) —
   a materially larger effort than any single rule above; scope as its own thread.

## What this document is not

Not a commitment to build all of the above. Not a claim that PRAETOR's registry-pack
coverage was measured rule-for-rule against Semgrep's actual packs — that comparison still
needs doing, through the Semgrep CLI's own listing rather than the JS-rendered registry
pages. Not new rule code — zero rules were added by this document.
