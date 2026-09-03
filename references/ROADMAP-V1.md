# PRAETOR — road to a genuine v1

**Status of this document.** `pyproject.toml` already says `version = "1.0.0"`, but
that number was never earned — nothing is tagged, nothing is published, and
`CHANGELOG.md`'s own `1.0.0` entry says so directly: *"Not a release — a version
number... nothing has been tagged and nothing is published to PyPI."* This document
defines what would have to be true before that version number stops being aspirational.
Written 2026-09-03, after two competitor surveys (`references/audits/2026-08-24-*`
and `references/audits/2026-09-02-*`) and a full round of feature work informed by them.

## What "v1 complete" means here

Not "every idea implemented." A specific, checkable bar: **a developer can install
PRAETOR in under a minute, point it at a real repository or a real AI-agent skill,
and get a result they can act on — with PRAETOR's own stated engines actually
covering what its README claims they cover.** Four categories, each with a concrete
gate.

## 1. Distribution — the biggest gap, and it's not a code gap

Right now: not on PyPI, no published GitHub Action, no pre-commit-framework hook
entry, no VS Code/editor integration. A developer who wants to try PRAETOR today has
to clone the repo and run a Python script directly. That is real adoption friction,
independent of how good the engines are.

- [ ] **Publish to PyPI** as `praetor-security`, so `pip install praetor-security`
  works — the package metadata in `pyproject.toml` is already correct, this is a
  packaging/CI task, not a design one.
- [ ] **Publish a GitHub Action** wrapping the CLI, so a repo can add PRAETOR to its
  own CI in a few lines of YAML instead of scripting a Python invocation.
- [ ] **A `.pre-commit-hooks.yaml` entry**, so PRAETOR can be added to any repo's
  existing `pre-commit` config the same way Gitleaks/detect-secrets already are —
  this is the single most common way developers actually adopt a scanner.
- [ ] Tag an actual `v1.0.0` release once the above lands, so "PRAETOR 1.0" refers
  to something real.

## 2. Rust port — unblocked this session, not finished

`references/ADR-001-engine-language.md` is the authority here; this section only
tracks status against it, doesn't restate the reasoning.

- [x] `secrets` engine ported (`rust/praetor-core/src/secrets.rs`), differential-tested
  against the Python reference.
- [x] `sca` argv-construction and never-execute guard ported (`sca.rs`).
- [x] Amendment 3 ratified 2026-09-02 — `serde_json` pinned, `aisec` un-deferred.
- [ ] **`aisec`'s `_scan_mcp` ported**, the specific function Amendment 3 existed to
  unblock. Not started — needs its own differential corpus and `.expected` contract
  file, matching `references/differential/secrets.{tsv,expected}`'s existing shape.
  Scoped deliberately narrow (one function, not the whole engine) to keep the port
  incremental, per ADR-001's own stated philosophy.
- [ ] **The rest of `aisec`** (prompt-injection tables, Unicode/ANSI scanning, HTML
  comment scanning, hook scanning) — larger, comes after `_scan_mcp` proves the
  pattern.
- [ ] **`sast`/`sca` subprocess orchestration** — ADR-001 already says these come
  last, since they own the subprocess boundary; no change to that ordering here.
- [ ] **Wire a Rust engine into the actual CLI binary.** `rust/praetor/src/main.rs`
  currently refuses to scan on principle — an honest refusal is correct until an
  engine is differentially proven, but nothing is wired even for `secrets`, which
  already passes its differential harness. This is the step that turns "a port
  exists" into "the port ships."

## 3. New detection capability from this session's research

Two surveys (`references/audits/2026-08-24-oss-scanner-technique-survey.md`,
`references/audits/2026-09-02-aisec-competitor-survey.md`) produced a combined,
ranked backlog. Landed this session: `p/ai-best-practices` registry pack,
`ansi-escape-sequence`, `markdown-image-exfil`. Still open, ranked by the surveys'
own value/effort tags:

- [ ] **Serialized-model / pickle-opcode scanning** — the single highest-value
  finding across both surveys, and the only one naming a genuinely new capability
  class. A malicious `.pkl`/`.pt`/`.h5` file committed to a repo is invisible to
  all four current engines. Needs its own design doc before code — a new
  file-admission path parallel to `core.walk_files()`, plus a static
  `pickletools`-based disassembler (stdlib, never executes). **This is the biggest
  single feature gap for v1**, not a nice-to-have.
- [ ] **Decode-then-rescan** for base64/hex/rot13/URL-encoded injection payloads —
  two independent surveys named this gap by different routes. Needs an explicit
  bounded decode depth/size cap designed in from the start (this repo's own memory
  already recorded an unbounded pass hanging ~244s on a different engine).
- [ ] **Multilingual instruction-override phrase coverage** — every INJECTION rule
  is English-only today; PINT's own benchmark holds ~30% of its corpus in 24 other
  languages specifically to catch this failure mode.
- [ ] A **systematic hard-negative fixture corpus** for `aisec`, extending the
  existing baseline-honesty discipline to false-positive tracking specifically.
- [ ] Known-jailbreak-template signature list (STAN/DUDE/AntiDAN family markers).
- [ ] Re-run the one still-unsurveyed slot (Trojan-Source/invisible-Unicode state
  of the art) to close out the second survey properly.

## 4. What's explicitly NOT going into v1, and why

Stated so nobody re-proposes these without re-deriving why they were declined:

- **Anything requiring a live model call** (LLM-as-judge detectors, live
  prompt-injection classifiers, PINT-style scoring) — conflicts with PRAETOR's
  own never-execute/read-only invariant. This is PRAETOR's actual competitive
  edge in the AI-security space, not a limitation to route around.
- **mcp-scan-style live server connection** to detect tool poisoning/rug-pulls —
  confirmed this session: that entire hazard class requires starting the MCP
  server, which is out of scope by construction, not by oversight.
- **Git-history scanning** (Gitleaks' `git log -p` mode) — a real scope expansion
  PRAETOR's reads-only-the-tree posture shouldn't fold into a default path.

## Where this leaves "v1"

Realistically: distribution (§1) and the pickle-scanning engine (§3) are the two
items that would most change PRAETOR's actual competitive position — one closes
the adoption-friction gap, the other closes the biggest honest capability gap. The
Rust port (§2) is real engineering debt worth paying down but doesn't change what
PRAETOR can detect today; Python already does the job correctly. Prioritize
accordingly rather than treating this list as one flat queue.
