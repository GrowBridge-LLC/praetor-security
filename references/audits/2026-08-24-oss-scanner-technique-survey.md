# OSS scanner technique survey — 2026-08-24

**What this is.** A read-only research pass over seven other open-source security
scanners, looking for techniques PRAETOR could adopt and for design choices PRAETOR
should explicitly decline. Method: public documentation, READMEs, and source read via
web search/fetch only — nothing here was cloned, installed, or executed. That
restriction was deliberate, not incidental: it is the same discipline PRAETOR holds
itself to when reading a scanned target, applied here to reading a peer project.

**What this is NOT.** A single research pass, one agent, no independent verification
and no adversarial second read. Every claim below carries a source link so it can be
checked; none of it has been checked by a second, differently-built reader the way
this project's own code changes are (`AGENTS.md`'s collaboration model). Treat findings
here the way any audit doc in this directory is treated — a claim to verify before
building on it, not a ruling. `git log` this file if a "designed but not built" item
below is later picked up, and check whether the *current* code has already superseded
the finding — see `[[a-design-doc-does-not-know-what-happened-after-it-was-written]]`
in this project's memory for exactly why that check matters.

Scope note up front: all seven targets had usable public documentation or source; none
were skipped.

---

## 1. Gitleaks (Go, secrets, git-history aware)

**Source:** `github.com/gitleaks/gitleaks` README and `config/gitleaks.toml`.

Gitleaks separates *what to scan* into three independent commands: `git` (runs `git
log -p` and scans the patch stream, so it sees every historical commit's diff, not
just what's on disk today), `dir` (scans a working tree with no git awareness at all),
and `stdin`. The rule format is TOML: each `[[rules]]` entry carries `id`, `regex`, a
`secretGroup` (which capture group is the actual secret, separate from surrounding
context that helped match it), an optional `entropy` float, a `path` regex, and
`keywords` — a cheap pre-filter list of literal substrings checked before the
expensive regex runs at all.

**Adoptable:**
- **`secretGroup` capture-group separation.** Distinguishing "the regex that had to
  match for context" from "the substring that IS the secret" is cleaner than full-match
  extraction, especially for rules like `API_KEY\s*=\s*"([a-zA-Z0-9]{32})"` where only
  the 32-char value should be reported/hashed, not the whole assignment.
- **Two-tier allowlists**, with a `stopwords` list matched against the *extracted
  secret* rather than the full line — cheaper and more precise than a broad
  regex-based "is this a test fixture" heuristic, and composes with PRAETOR's existing
  lexical-context work rather than replacing it.

**Do not adopt:** `git log -p` history-walking is a scope expansion PRAETOR's
reads-only-the-tree posture should not fold into a default path — it doesn't execute
target code, but it does require PRAETOR to become git-aware and trust the
repository's own git plumbing. If ever wanted, it belongs as a distinctly-flagged
opt-in mode.

Sources: [gitleaks/gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md), [gitleaks.toml](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)

---

## 2. TruffleHog (Go, secrets, live verification) — deliberate non-adoption case

**Source:** `github.com/trufflesecurity/trufflehog`, Truffle Security's own blog "How
TruffleHog Verifies Secrets."

TruffleHog's defining feature is a second pipeline stage after regex/entropy
detection: for each of its ~800 detector types it makes a **real, live network call to
the credential's issuing service** and classifies the finding as `verified` /
`unverified` / `unknown`. Truffle Security's own post states verification calls must
be "stateless," but the same post admits this is not solved generally — some
providers only signal validity via response body rather than HTTP status,
rate-limited-but-valid credentials return errors that look like failures, and the
authors write they are "still working on an elegant solution" for reporting network
errors.

**Explicitly do NOT adopt.** This is the clearest violation of PRAETOR's invariant
that exists in this survey. Verification requires PRAETOR to (1) originate outbound
network traffic keyed off attacker-influenced content from a scanned target, (2) send
potentially the scanned repo owner's real credentials to third-party services — a
disclosure event distinct from the scan itself, and (3) trust ~800 per-provider
integrations' claims about their own statelessness, a claim PRAETOR has no way to
independently verify and which TruffleHog's own maintainers say is incompletely
solved even for cooperating providers. Exactly the "safety is a scope decision, not a
property of the mechanism" pattern this project's own `CLAUDE.md` already names.

**One narrow idea worth salvaging without the network call:** TruffleHog's
`Keywords()` pre-filter (cheap literal substrings checked before the full regex runs)
is architecturally identical to Gitleaks' `keywords` and is a fine, network-free
optimization.

Sources: [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog), [How TruffleHog Verifies Secrets](https://trufflesecurity.com/blog/how-trufflehog-verifies-secrets)

---

## 3. ripsecrets (Rust, secrets) — directly relevant to PRAETOR's Rust port

**Source:** `github.com/sirwart/ripsecrets`, its `Cargo.toml`.

Its dependencies are the real finding: `regex`, `grep` and `ignore` (ripgrep's own
matcher/searcher and gitignore-aware walking crates, reused rather than reimplemented),
`num_cpus`, `clap`, `memoize`, `tempfile`, `lazy_static`. **No JSON crate at all** —
ripsecrets has no structured-config input, so it has nothing to say directly about
PRAETOR's own open JSON-crate question (see §8).

The speed story is architectural: all secret-pattern regexes compile into a **single
combined regex/`RegexSet`** so each file is scanned in one pass rather than once per
pattern, and file-walking is delegated to `ignore` + `grep` — literally ripgrep's own
internal crates — rather than a hand-rolled traversal. `.gitignore`-aware walking by
default is also a false-positive reduction: generated/vendored code with high-entropy
strings never gets scanned.

**Adoptable, both directly usable in PRAETOR's Rust port:**
- Reuse the `ignore` + `grep` crates rather than writing a custom walker/regex-apply
  loop — a solved problem, the exact crates that make ripgrep itself correct on
  `.gitignore` semantics.
- Combine all secret-pattern regexes into one `RegexSet`/alternation before the file
  loop, for O(1) passes per file rather than O(patterns).

**Nothing to avoid here** — architecturally aligned with PRAETOR's own constraints
(local-only, no network, no execution).

Sources: [sirwart/ripsecrets](https://github.com/sirwart/ripsecrets), [ripsecrets Cargo.toml](https://raw.githubusercontent.com/sirwart/ripsecrets/main/Cargo.toml)

---

## 4. detect-secrets (Python, Yelp) — suppression-mechanism comparison

**Source:** `github.com/Yelp/detect-secrets`, `docs/design.md`.

Its core suppression primitive is the **baseline file**: a JSON artifact recording
every currently-known finding, generated once against a legacy codebase, after which
the tool only flags *new* findings not already in the baseline. A separate `audit`
subsystem lets a human interactively label each baseline entry true/false positive,
and that label persists. Plugins are independent `BasePlugin` subclasses, and — a
maximize-recall choice, not a dedup one — the same secret matched by two plugins
produces two separate findings.

**Comparison to PRAETOR's own suppression:** a different axis entirely. detect-secrets
suppresses via **accumulated human judgment persisted as data**; PRAETOR suppresses
via **automated structural proof** (lexical context, reachability). These are
complementary, not competing — and the baseline model is exactly the piece PRAETOR's
`secrets` engine structurally lacks, per its own `CLAUDE.md`, which correctly excludes
`secrets` from lexctx/reachability suppression (a secret's danger doesn't depend on
control flow).

**Adoptable — the highest-value single idea in this survey:** a baseline/audit
workflow is the correct mechanism for the secrets engine specifically, because
PRAETOR's own rule says structural suppression must never apply there. It lets a human
mark "yes, this is a real credential, it's a test fixture I control, I accept the
risk" without weakening the detector or writing a path-based carve-out — which
`CLAUDE.md` separately flags as unsafe ("never suppress on path alone"). Concretely: a
`praetor scan --baseline .praetor-baseline.json` mode recording finding fingerprints
(file + rule id + hash of matched text), silently dropping only *exact* re-matches on
later scans, with an `audit` command to review/relabel. Nothing here weakens the
"unproven ⇒ keep" default for anything not already in the baseline.

**Do not adopt as-is:** detect-secrets' cross-plugin duplicate-finding behavior would
add noise to PRAETOR's existing dedup/rank pass in `interpret.py`; a baseline should
key on PRAETOR's own already-deduplicated finding identity, not raw per-plugin hits.

Sources: [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets), [design.md](https://github.com/Yelp/detect-secrets/blob/master/docs/design.md)

---

## 5. Semgrep (OCaml/Python) — architecture beyond "subprocess wrapper"

**Source:** semgrep-architecture overview (rodolpheg.xyz), Semgrep's own taint-mode
docs and blog posts.

**Prefiltering via mandatory-literal extraction.** Before parsing, Semgrep statically
analyzes each rule to extract literal strings the matched code *must* contain (a rule
matching `subprocess.call(...)` extracts `"subprocess"` and `"call"`), then skips
parsing any file lacking those literals via a cheap substring check — eliminating most
files before the expensive step runs. The same idea as Gitleaks' `keywords` and
TruffleHog's `Keywords()`, applied to full AST matching — three independent projects
converging on the same pre-filter pattern is worth treating as a real signal, and
worth checking whether PRAETOR's own SAST/secrets engines already do this before
invoking Semgrep or running regex over every file regardless of content.

**Taint-mode's source/sink/sanitizer/propagator model is directly comparable to
PRAETOR's `taint.py`.** Semgrep's taint carries **provenance** — which source rule
produced it, and the call-chain that carried it — and merges to a `Both` state at
control-flow joins where one branch is tainted and another isn't, rather than
collapsing to one boolean. PRAETOR's own `CLAUDE.md` already documents the sharp edge
in `is_provably_inert()`: a key declared in one file and used in another can't be
proven reachable *in that file* and reads as inert. Semgrep's inter-procedural
(paid-tier) taint tracking targets exactly this gap via cross-file call graphs —
confirming PRAETOR's known limitation is a recognized, named hard problem in this
space, not a shortcut PRAETOR uniquely took, and that a real fix is a large
undertaking Semgrep itself gates behind a paid tier.

**Adoptable:**
- Literal-string prefiltering before any expensive per-file analysis, if not already
  uniform across PRAETOR's engines.
- A **provenance-tagged taint state** (`Clean` / `Tainted(sources)` / `Both`) as a
  richer return type than a boolean from `is_provably_inert()`, so a suppression
  decision's report can say *which* source justified it — `CLAUDE.md` already requires
  suppression to carry a stated reason, never silence.

**Do not adopt:** cross-file taint tracking is a large-scope commitment (call graphs,
per-function summaries) — reasonable to note as a known limitation with Semgrep's own
gating precedent, not something to casually add.

Sources: [Semgrep architecture writeup](https://blog.rodolpheg.xyz/posts/semgrep-architecture/), [Semgrep taint-mode overview](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview), [Demystifying Taint Mode](https://semgrep.dev/blog/2022/demystifying-taint-mode/)

---

## 6. Trivy (Go, Aqua Security) — multi-engine result aggregation

**Source:** `aquasecurity/trivy` GitHub, `pkg/types/report.go`/`vulnerability.go`.

The closest published precedent for PRAETOR's own "four engines, one report" problem.
Trivy's `types.Report` holds `Results []Result`, and each `Result` carries a `Target`,
a `Class` enum discriminating vuln/config/secret-class results, and **typed slices for
each finding kind directly on the same struct** (`Vulnerabilities`,
`Misconfigurations`, `Secrets`, `Licenses`) — one result-per-target record, each engine
populating its own typed field, rather than four separate per-engine objects merged
downstream. Its secret rule format is explicitly modeled on Gitleaks' TOML approach.

**Adoptable:** a **`Class`-discriminated, per-target unified result record** is
cleaner than merging four independently-formatted engine outputs after the fact. If
`report.py`/`interpret.py` currently normalize four different engine-native shapes
late, Trivy's approach — define the finding-kind enum first, require every engine to
emit into the same typed container from its own boundary — tends to simplify dedup
logic by pushing normalization earlier.

**Do not adopt:** Trivy's breadth is achieved partly by **auto-downloading
vulnerability databases at scan time** — reasonable for a general vuln scanner, in
tension with PRAETOR's minimal-network posture. Any DB/rule-update path PRAETOR adds
should stay explicit and operator-controlled, not an implicit fetch-on-run default.

Sources: [aquasecurity/trivy](https://github.com/aquasecurity/trivy), [pkg/types/vulnerability.go](https://github.com/aquasecurity/trivy/blob/main/pkg/types/vulnerability.go), [builtin-allow-rules.go](https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/secret/builtin-allow-rules.go)

---

## 7. cargo-audit / cargo-deny (Rust, dependency auditing) — self-scanning precedent

**Source:** `RustSec/rustsec` (`cargo-audit`), `EmbarkStudios/cargo-deny`,
`rustsec.org`, their `Cargo.toml` files.

Both consume the RustSec Advisory Database (mirrored into OSV, so Trivy and others can
also consume it) against a project's `Cargo.lock`. `cargo-audit` is narrower —
vulnerabilities, unmaintained-crate warnings. `cargo-deny` is broader — the same
vulnerability check plus license-allowlisting, dependency-source restriction, and
duplicate-version detection, as layered independently-configurable policy sections.

**Directly answers an open question:** PRAETOR's Rust port will eventually need to
audit its own Rust dependency tree, and this is exactly what these tools are for.
Running `cargo audit` (or `cargo deny check`) as a `precommit.sh`/CI gate against
PRAETOR's own `Cargo.lock` the moment the port has real dependencies is low-effort,
high-value, and fully compatible with the never-execute invariant even when the
"target" is PRAETOR's own tree — neither tool executes or builds the audited crates,
only reads `Cargo.lock` and queries the advisory database.

Sources: [RustSec/rustsec – cargo-audit](https://github.com/RustSec/rustsec/tree/main/cargo-audit), [rustsec/advisory-db](https://github.com/rustsec/advisory-db), [rustsec.org](https://rustsec.org/)

---

## 8. The open Rust JSON/regex crate question

PRAETOR's `aisec` engine needs to parse potentially attacker-controlled MCP manifest
JSON in the Rust port (`references/ADR-001-engine-language.md`'s Amendment 3
proposal, same commit as this file, has the full measurement). The two Rust
security-tooling projects surveyed that actually parse structured/untrusted-ish data
both converged on the same answer:

- **cargo-audit**: `serde` + `serde_json` (workspace-pinned) for JSON.
- **cargo-deny**: `serde` + `serde_json "1.0"` for JSON, and notably `toml-span "0.7"`
  rather than plain `toml` for its own policy-file parsing, because `toml-span` tracks
  source spans for precise line/column error reporting back to the offending
  policy-file location.
- **ripsecrets** has no JSON dependency at all — silent on this question, not a
  counter-example.

**Recommendation, with a specific caveat:** `serde_json` is the ecosystem-standard
choice both RustSec's own tool and Embark's tool made — reasonable precedent. But
there is a concrete, documented safety wrinkle relevant to exactly PRAETOR's use case
(parsing attacker-supplied JSON): `serde_json::from_str` enforces a recursion-depth
limit (128, via a `remaining_depth` counter) against stack-overflow DoS from
deeply-nested JSON — but (a) this guard was found bypassable when deserializing from
an already-built `serde_json::Value` using `IgnoredAny` rather than going through
`from_str` directly (fixed upstream, `serde-rs/serde` issue #3023), and (b)
`serde_json` ships an optional `unbounded_depth` feature that disables the limit
entirely and **must never be enabled** on a manifest-parsing path reading
attacker-controlled content. If PRAETOR adopts `serde_json`: parse MCP manifests via
`from_str`/`from_slice` directly into a typed struct (not a generic `Value` walked
with a discard-visitor), confirm `unbounded_depth` is absent from the enabled feature
set, and add a deeply-nested-JSON fixture that must fail cleanly as one of the "add
its test" cases `CLAUDE.md` already requires for any engine widening the never-execute
surface.

For regex: ripsecrets' plain `regex` crate plus ripgrep's own `grep`/`ignore` crates
for file-walking is the clean precedent for PRAETOR's Rust secrets engine — `regex`
guarantees linear-time matching (no catastrophic backtracking), which matters more for
PRAETOR than a typical CLI tool given PRAETOR scans attacker-authored regex-adjacent
content by design.

Sources: [ripsecrets Cargo.toml](https://raw.githubusercontent.com/sirwart/ripsecrets/main/Cargo.toml), [cargo-audit Cargo.toml](https://raw.githubusercontent.com/rustsec/rustsec/main/cargo-audit/Cargo.toml), [cargo-deny Cargo.toml](https://raw.githubusercontent.com/EmbarkStudios/cargo-deny/main/Cargo.toml), [serde-rs/serde #3023](https://github.com/serde-rs/serde/issues/3023), [serde-rs/json #162](https://github.com/serde-rs/json/issues/162)

---

## Ranked actionable-adoption list (value vs. effort)

1. **[High / low]** `serde_json` for aisec's MCP-manifest parsing, with the
   recursion-limit caveat above turned into a test fixture — directly informs the open
   decision in `ADR-001` Amendment 3; the caveat is cheap to encode as a guard test.
2. **[High / low]** `cargo-audit` and/or `cargo-deny` as a precommit/CI gate on
   PRAETOR's own `Cargo.lock` the moment the Rust port has dependencies.
3. **[High / medium]** A baseline/audit suppression mode for the secrets engine
   specifically (detect-secrets pattern) — fills a real structural gap rather than
   duplicating existing coverage, since PRAETOR's own rules forbid structural
   suppression there.
4. **[Medium / low]** Literal-string/keyword prefiltering before per-file regex or
   Semgrep invocation, if not already uniform.
5. **[Medium / low]** `secretGroup`-style capture-group separation and
   `stopwords`-on-extracted-value (Gitleaks), complementary to existing suppression.
6. **[Medium / medium]** Reuse ripgrep's own `ignore` + `grep` crates in the Rust
   secrets-engine port; combine all secret patterns into one `RegexSet`.
7. **[Medium / medium]** Trivy's `Class`-discriminated unified per-target `Result`
   struct as the target shape for merging PRAETOR's four engines' output.
8. **[Low / medium]** Provenance-tagged taint state (`Clean`/`Tainted(sources)`/`Both`)
   in `taint.py`, borrowed from Semgrep's taint model — nice-to-have, not urgent.
9. **[Do not adopt]** TruffleHog's live credential verification — directly conflicts
   with the never-execute/never-network invariant.
10. **[Do not adopt / watch only]** Trivy's implicit vulnerability-database
    auto-fetch, and Gitleaks'/Semgrep's git-history- or cross-file-scope-widening
    features — reasonable for their own projects, each would expand PRAETOR's
    execution/network/scope surface and needs an explicit, separately-gated opt-in
    rather than a default.
