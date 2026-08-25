# OSS scanner technique survey — 2026-08-24

**What this is.** A read-only research pass over seven other open-source security
scanners, looking for techniques PRAETOR could adopt and for design choices PRAETOR
should explicitly decline. Method: public documentation, READMEs, and source read via
web search/fetch only — nothing here was cloned, installed, or executed. That
restriction was deliberate, not incidental: it is the same discipline PRAETOR holds
itself to when reading a scanned target, applied here to reading a peer project.

**What this is NOT.** A single research pass, one agent, no independent verification
and no adversarial second read at the time it was first written. Every claim below
carries a source link so it can be checked. Treat findings here the way any audit doc
in this directory is treated — a claim to verify before building on it, not a ruling.
`git log` this file if a "designed but not built" item below is later picked up, and
check whether the *current* code has already superseded the finding — see
`[[a-design-doc-does-not-know-what-happened-after-it-was-written]]` in this project's
memory for exactly why that check matters.

**Update, 2026-08-25.** It got the second, differently-built read the paragraph above
said it hadn't had yet: CodeRabbit's first-ever review of this repository (`.coderabbit.yaml`
had been configured and unused until this document's own commit finally opened a pull
request). It found real defects, not style nits — an incomplete dependency list for
`ripsecrets` (verified independently against the live manifest before accepting the
correction), a technically wrong claim about `RegexSet` capture semantics (verified
against PRAETOR's own existing Rust `secrets.rs`), a design flaw in the proposed
baseline fingerprint, a mislabeled attribution of a proposed PRAETOR design as
Semgrep's own implementation, an imprecise claim about `cargo-deny`'s execution
model, and — the most serious one — this document originally recommended reusing
`ignore`'s default `.gitignore`-awareness for PRAETOR's Rust secrets port without
the caveat that PRAETOR's own secrets engine must NOT inherit that default, which
would have recommended reintroducing the exact false-clean regression `0930947`
already fixed once. All corrected in place below, each marked where it happened,
after independently re-verifying the two most checkable claims (the ripsecrets
manifest, and whether `serde-rs/serde#3023` is actually fixed) rather than trusting
the review at face value either — the same discipline this document asks of its own
future readers.

**Citations below point to mutable `main`/`master` branches** rather than pinned
commits or release tags (CodeRabbit flagged this too, correctly, as a lower-severity
nitpick): a later upstream change could shift what a link shows without this
document knowing. Every fact cited from one was verified as stated on 2026-08-24
(the OSS-scanner survey) or 2026-08-25 (the corrections); if a citation and this
document ever disagree, the document's stated access date is what to trust as "true
when written," not the live link.

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

**Corrected 2026-08-25 against the live manifest** (the version below was incomplete
— it omitted a runtime dependency and did not separate build/dev dependencies from
runtime ones, caught by CodeRabbit's first review pass on this document, verified
independently by re-fetching `raw.githubusercontent.com/sirwart/ripsecrets/main/Cargo.toml`
directly before accepting the correction):

- **Runtime:** `regex`, `grep`, `ignore` (ripgrep's own matcher/searcher and
  gitignore-aware walking crates, reused rather than reimplemented), `termcolor`,
  `num_cpus`, `clap` (derive), `memoize`, `tempfile`, `lazy_static`.
- **Build-time only** (`[build-dependencies]`, a *second*, separate `clap` entry plus
  two more): `clap`, `clap_complete`, `clap_mangen` — shell-completion/man-page
  generation, not part of the shipped scanning binary's runtime behaviour.
- **Dev-only** (`[dev-dependencies]`): `criterion`, for its benchmark harness.

**No JSON crate at all** — ripsecrets has no structured-config input, so it has
nothing to say directly about PRAETOR's own open JSON-crate question (see §8).

The speed story is architectural: all secret-pattern regexes compile into a
**`RegexSet`, used as a prefilter** — file-walking is delegated to `ignore` + `grep`
— literally ripgrep's own internal crates — rather than a hand-rolled traversal.
`.gitignore`-aware walking by default is also a false-positive reduction for
ripsecrets: generated/vendored code with high-entropy strings never gets scanned.

**Adoptable, with one caveat each — both corrected 2026-08-25 after the same review pass:**
- Reuse the `ignore` + `grep` crates for file-walking rather than writing a custom
  walker/regex-apply loop — a solved problem, the exact crates that make ripgrep
  itself correct on `.gitignore` semantics. **🔴 CAVEAT, and it is not cosmetic: `ignore`'s
  default `.gitignore`-awareness is exactly the property PRAETOR's OWN secrets engine
  must NOT inherit.** `SECRETS_SKIP_DIRS` (`scripts/core.py`) is deliberately three
  entries (`.git`, `.hg`, `.svn`) — far narrower than the walker's `DEFAULT_SKIP_DIRS`
  — specifically so the secrets wide walk reads `vendor/`, `node_modules/`, `.venv/`,
  `dist/`, `build/`, and every gitignored file, because a committed credential there
  is disclosed exactly as much as one at the root. This is not a hypothetical: commit
  `0930947` reverted an EARLIER attempt at exactly this kind of git/gitignore-status
  narrowing after it turned a real gitignored credential into a false clean — see
  `[[a-design-doc-does-not-know-what-happened-after-it-was-written]]` in this
  project's memory, and `AGENTS.md`'s "Designed but not built" section, both about
  the identical failure this survey nearly recommended repeating one file over. If the
  Rust secrets port uses `ignore`, it must be built with default ignores explicitly
  disabled (`ignore::WalkBuilder::standard_filters(false)` or equivalent) and
  `SECRETS_SKIP_DIRS`'s narrower three-entry skip list applied instead — reusing the
  crate for its walking mechanics, not its default policy.
- Compile secret patterns into a `RegexSet` **as a prefilter only, not as the
  extraction step.** `RegexSet` reports which pattern INDICES matched a haystack; per
  Rust `regex` crate documentation, it does not return `Captures` or match locations
  at all. Verified directly against PRAETOR's own existing Rust secrets engine
  (`rust/praetor-core/src/secrets.rs`): it already does this correctly — 16 provider
  patterns each with a named `(?P<secret>...)` group, matched via
  `provider.regex.captures_iter(line)` and `.name("secret")`, feeding
  `redact_line(line, secret)` — and does not currently use `RegexSet` at all. The
  correct two-step shape, if `RegexSet` is added as a speed optimization: use it to
  cheaply determine which pattern(s) matched, then re-run only the matched pattern's
  individual `Regex` to extract the named `secret` capture for redaction/reporting.
  Total matching cost is then "one `RegexSet` pass, plus one `Regex` pass per matched
  pattern" — not O(1) per file as originally stated here, since the second pass's
  cost still scales with how many patterns actually matched.

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
`praetor scan --baseline .praetor-baseline.json` mode recording finding fingerprints,
silently dropping only *exact* re-matches on later scans, with an `audit` command to
review/relabel. Nothing here weakens the "unproven ⇒ keep" default for anything not
already in the baseline.

**🔴 CORRECTED 2026-08-25 (caught in review): the fingerprint above must NOT be
`file + rule id + hash of matched text` alone.** That is a SET identity, not a
per-occurrence one — the same secret value appearing twice in one file under the
same rule collapses to a single baseline entry, so a genuinely new second
occurrence at a different line reads as "already baselined" and silently
disappears, which is exactly the false-clean shape this whole document argues
against elsewhere. The fingerprint needs an occurrence-distinguishing component
(line number, or a stable occurrence index within the file) so two identical
secrets at two different locations remain two distinct baseline entries. Any
implementation of this idea needs a regression test asserting exactly that: two
copies of the same credential in one file, baseline one occurrence, confirm the
second still reports.

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

**Taint-mode's source/sink/sanitizer/propagator RULE MODEL is directly comparable to
PRAETOR's `taint.py`.** Semgrep's rule DSL declares `pattern-sources`,
`pattern-sinks`, `pattern-sanitizers`, and propagators. **Correction, 2026-08-25:**
the earlier version of this section attributed a specific `Clean` /
`Tainted(sources)` / `Both` state-machine to Semgrep's own implementation as if it
were documented fact; a live query against Semgrep's actual internals
(`src/tainting/Shape_and_sig.ml` and related OCaml source) found its real
field-sensitive dataflow tracking uses `Tainted` / `Clean` / `Bot` (an
inherits-from-parent "no explicit marker" state, not a merge-of-two-branches
`Both`), and that the specific three-state lattice named here does not appear as a
documented architectural concept in Semgrep's own materials. PRAETOR's own
`CLAUDE.md` already documents the sharp edge this comparison was reaching for, in
`is_provably_inert()`: a key declared in one file and used in another can't be
proven reachable *in that file* and reads as inert. Semgrep's inter-procedural
(paid-tier) taint tracking targets a related gap via cross-file call graphs —
worth noting as a recognized, named hard problem in this space, not a shortcut
PRAETOR uniquely took, and that a real fix is a large undertaking Semgrep itself
gates behind a paid tier — but the specific state-machine below is now labeled
correctly: ours, not theirs.

**Adoptable:**
- Literal-string prefiltering before any expensive per-file analysis, if not already
  uniform across PRAETOR's engines.
- **A PROPOSED PRAETOR design** (not a description of Semgrep's own implementation —
  see the correction above): a provenance-tagged taint state (`Clean` /
  `Tainted(sources)` / `Both`) as a richer return type than a boolean from
  `is_provably_inert()`, so a suppression decision's report can say *which* source
  justified it — `CLAUDE.md` already requires suppression to carry a stated reason,
  never silence. The general idea — richer-than-boolean taint state — is inspired by
  seeing that Semgrep's rule model separately tracks sources/sinks/sanitizers, not by
  copying a specific Semgrep data structure.

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
Running `cargo audit` as a `precommit.sh`/CI gate against PRAETOR's own `Cargo.lock`
the moment the port has real dependencies is low-effort, high-value, and compatible
with the never-execute invariant — it only reads `Cargo.lock` and queries the
advisory database.

**🔴 CORRECTED 2026-08-25: `cargo-deny` is not the same claim, and the original text
here conflated the two tools.** `cargo deny check` invokes `cargo metadata`
internally by default to build its dependency graph — confirmed against
`cargo-deny`'s own documentation — and while `cargo metadata` does not execute build
scripts itself, dependency-graph *resolution* is a different operation from `cargo
audit`'s read-only `Cargo.lock` parse, and worth stating precisely rather than
folding into one "neither executes anything" sentence. This is PRAETOR's own tree
being resolved, not an attacker-controlled target, so it is not the invariant-1
class of danger the never-execute rule exists for — but a self-scanning gate this
project would add to its own precommit gate deserves the same precision this
project demands of everything else it certifies as safe. If `cargo-deny` is adopted,
prefer `cargo-deny --metadata-path <pre-generated-metadata.json> check` (documented,
supported) over the implicit default, so the gate's own inputs stay explicit and
the network/resolution step is a visible, separate command rather than hidden
inside the check.

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
`from_str` directly. **🔴 CORRECTED 2026-08-25: this is NOT fixed upstream.**
Independently re-checked directly against the GitHub API (`gh api
repos/serde-rs/serde/issues/3023`) before accepting the correction: `state: open`,
`closed_at: null`, as of this writing — the earlier version of this document
asserted a fix that does not exist. The guidance below does not depend on the issue
being fixed and is unchanged by the correction. And (b) `serde_json` ships an
optional `unbounded_depth` feature that disables the limit entirely and **must
never be enabled** on a manifest-parsing path reading attacker-controlled content.
If PRAETOR adopts `serde_json`: parse MCP manifests via `from_str`/`from_slice`
directly into a typed struct (not a generic `Value` walked with a
discard-visitor — the `IgnoredAny` bypass in issue #3023 is exactly that path),
confirm `unbounded_depth` is absent from the enabled feature set, and add a
deeply-nested-JSON fixture that must fail cleanly as one of the "add its test"
cases `CLAUDE.md` already requires for any engine widening the never-execute
surface.

⚠️ **This creates a real tension with `ADR-001` Amendment 3's own cost measurement,
worth stating rather than leaving implicit.** That measurement's "4 new crates"
figure explicitly assumes parsing into a generic `serde_json::Value` — its own text
says the `serde_derive`/`syn`/`quote`/`proc-macro2` chain "never enters `cargo
tree`'s actual compile graph... because parsing a generic `Value`... does not use
`serde`'s derive machinery," and separately flags that a typed-struct approach
"would pull the derive chain in for real." The security recommendation directly
above this paragraph says to use a typed struct, not a generic `Value` — so the
true dependency cost of following this survey's own safety guidance is higher than
Amendment 3's headline "4 new crates," and whoever rules on Amendment 3 should
re-measure `cargo tree` against a typed-struct parse path before treating "4 new
crates" as the number that decision is made against.

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
   secrets-engine port **with default ignores explicitly disabled and
   `SECRETS_SKIP_DIRS` applied instead** (see §3's caveat — this is not optional);
   add a `RegexSet` prefilter ahead of the existing per-pattern captures, not in
   place of them.
7. **[Medium / medium]** Trivy's `Class`-discriminated unified per-target `Result`
   struct as the target shape for merging PRAETOR's four engines' output.
8. **[Low / medium]** A PROPOSED (not Semgrep's own) provenance-tagged taint state
   (`Clean`/`Tainted(sources)`/`Both`) in `taint.py`, inspired by Semgrep's
   source/sink/sanitizer rule model — nice-to-have, not urgent.
9. **[Do not adopt]** TruffleHog's live credential verification — directly conflicts
   with the never-execute/never-network invariant.
10. **[Do not adopt / watch only]** Trivy's implicit vulnerability-database
    auto-fetch, and Gitleaks'/Semgrep's git-history- or cross-file-scope-widening
    features — reasonable for their own projects, each would expand PRAETOR's
    execution/network/scope surface and needs an explicit, separately-gated opt-in
    rather than a default.
