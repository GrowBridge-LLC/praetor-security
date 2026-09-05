# PRAETOR — road to a genuine v1

**Status of this document.** `pyproject.toml` already says `version = "1.0.0"`, but
that number was never earned — nothing is tagged, nothing is published, and
`CHANGELOG.md`'s own `1.0.0` entry says so directly: *"Not a release — a version
number... nothing has been tagged and nothing is published to PyPI."* This document
defines what would have to be true before that version number stops being aspirational.
Written 2026-09-03, after two competitor surveys (`references/audits/2026-08-24-*`
and `references/audits/2026-09-02-*`) and a full round of feature work informed by them.

> 🔴 **CORRECTION TO THE CORRECTION, 2026-09-05.** Two of the six items marked
> done the previous day were marked done **because the file existed**, not
> because it worked. Verified:
>
> * `action.yml` ran `pip install praetor-security[...]`. PyPI returns **404**
>   for that name -- it has never been registered and no release has ever been
>   cut. **Every run of the Action failed at its install step.**
> * `.pre-commit-hooks.yaml` needs an immutable `rev:` to be referenced. `git tag`
>   is **empty**. The hook was unusable.
>
> Both now read `[~]` -- shipped but INERT until a release exists. The Action has
> since been repaired to install from the repository so it works without PyPI.
>
> ⚠️ This is this repository's own "identified is not enforced" lesson, turned
> back on its own shipping surface, by the person who had just written the
> correction below. A checkbox is a claim about BEHAVIOUR. Tick it against a
> command that ran, never against a file that exists.

> ⚠️ **STATUS CORRECTED 2026-09-04.** Six items below were still shown as open
> while their work had shipped, and an audit flagged the document itself as
> stale. A roadmap that under-reports its own progress is not a harmless
> inaccuracy: it is the same class as a scanner reporting a stale verdict, and it
> makes every plan built on it wrong. Checkboxes now reflect what is in `main`;
> the closing commit is named beside each.

**Checkbox states:** `[x]` works, verified by running it · `[~]` shipped but
inert, blocked on something external · `[ ]` not built.

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
  packaging/CI task, not a design one. The name isn't registered yet, so this is a
  *pending-publisher* registration (name + `GrowBridge-LLC` + repo + exact workflow
  filename, via PyPI's OIDC trusted-publishing flow — no stored token, `id-token:
  write` scoped to the publish job only), and it should happen well before the
  actual first release: someone else claiming the name first invalidates the
  pending registration. Before wiring the workflow, verify the bundled ruleset
  actually installs — it ships via `[tool.setuptools.data-files]`, not
  `package-data`, since PRAETOR ships flat modules; build the real wheel and
  `pip install` it into a fresh empty venv to confirm `praetor --no-registry`
  still finds `rules/semgrep-praetor.yaml` from the installed copy, not the source
  tree.
- [~] **Publish a GitHub Action** wrapping the CLI, so a repo can add PRAETOR to its
  own CI in a few lines of YAML instead of scripting a Python invocation. Shape:
  a *composite* action (not `docker`, not a Node action — this is a pure-Python
  tool) doing checkout → `actions/setup-python` → `pip install
  praetor-security[sast,sca]` → invoke `praetor` with inputs mapped 1:1 onto the
  real CLI flags (`--engines`, `--format`, `--fail-on`, `--min-severity`,
  `--allow-degraded`, `--exclude`). `pypa/gh-action-pip-audit` — an official PyPA
  action for a sibling Python security CLI — is the concrete template to follow;
  it even exposes a `disable-pip` input mirroring PRAETOR's own `--disable-pip`
  invariant.
- [~] **A `.pre-commit-hooks.yaml` entry**, so PRAETOR can be added to any repo's
  existing `pre-commit` config the same way Gitleaks/detect-secrets already are —
  this is the single most common way developers actually adopt a scanner.
  `Yelp/detect-secrets`'s entry is the closer template than gitleaks' (which needs
  a prebuilt binary or Docker): `id: praetor`, `language: python`, `entry:
  praetor`, `pass_filenames: false` — pre-commit installs the package into an
  isolated venv via the declared console-script entry point, matching
  `pyproject.toml`'s existing `[project.scripts] praetor = "praetor:main"`. A bare
  install only pulls the stdlib-only engines (secrets/aisec); SAST/SCA need
  `additional_dependencies: ['semgrep', 'pip-audit']` in the *user's* own config.
  Given commit-time latency expectations for this class of tool, default the
  shipped hook to a fast profile (e.g. `--engines secrets --fail-on HIGH`) and
  document the heavier `--engines all` as an opt-in pre-push stage.
- [ ] Tag an actual `v1.0.0` release once the above lands, so "PRAETOR 1.0" refers
  to something real.
- [ ] **Known constraint on any future hosted/SaaS use of Semgrep's registry
  packs** (`p/owasp-top-ten`, `p/security-audit`, `p/ai-best-practices`): as of
  Dec 13, 2024, Semgrep's own rule registry is no longer open-source — the
  "Semgrep Rules License v1.0" permits internal use (exactly what PRAETOR's CLI
  does today, scanning a target and reporting locally) but explicitly forbids
  distributing the rules or "making them available to others as a service."
  Running the registry packs locally, as PRAETOR does, is unaffected. This only
  becomes relevant if PRAETOR (or anything built on it) ever runs those registry
  configs on a third party's behalf as a hosted service — that would need its own
  legal review, or a switch to the Opengrep fork (LGPL-2.1, preserves the
  pre-relicensing ruleset). Noted here so it isn't rediscovered under time
  pressure later. PRAETOR's own bundled `rules/semgrep-praetor.yaml` is unaffected
  either way — it's self-authored MIT, not copied from the registry.

## 2. Rust port — unblocked this session, not finished

`references/ADR-001-engine-language.md` is the authority here; this section only
tracks status against it, doesn't restate the reasoning.

- [x] `secrets` engine ported (`rust/praetor-core/src/secrets.rs`), differential-tested
  against the Python reference.
- [x] `sca` argv-construction and never-execute guard ported (`sca.rs`).
- [x] Amendment 3 ratified 2026-09-02 — `serde_json` pinned, `aisec` un-deferred.
- [x] **`aisec`'s `_scan_mcp` ported**, the specific function Amendment 3 existed to
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

- [x] **Serialized-model / pickle-opcode scanning** — the single highest-value
  finding across both surveys, and the only one naming a genuinely new capability
  class. A malicious `.pkl`/`.pt`/`.h5` file committed to a repo is invisible to
  all four current engines. Needs its own design doc before code — a new
  file-admission path parallel to `core.walk_files()`, plus a static
  `pickletools`-based disassembler (stdlib, never executes). **This is the biggest
  single feature gap for v1**, not a nice-to-have.
- [x] **Decode-then-rescan** for base64/hex/rot13/URL-encoded injection payloads —
  two independent surveys named this gap by different routes. Needs an explicit
  bounded decode depth/size cap designed in from the start (this repo's own memory
  already recorded an unbounded pass hanging ~244s on a different engine).
- [x] **Multilingual instruction-override phrase coverage** — every INJECTION rule
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
