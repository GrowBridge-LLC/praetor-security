# Changelog

Notable changes to PRAETOR, most recent first.

This file starts at `1.0.0`, the version in `pyproject.toml` at the time it was
written. No releases are tagged yet, so everything below `Unreleased` is on `main`
and not in any published artifact.

Because PRAETOR is a security scanner, entries say what a change means for
**detection** — a bug here is not a broken feature, it is a scanner reporting
"nothing found" while something is there.

## Unreleased

### 🔴 Security — suppression on PATH ALONE; renaming a file disarmed the gate

Found by independent adversarial audit, re-derived before fixing.

- **Any secret in a `.env.example` was suppressed without inspecting its value**
  (`scripts/interpret.py`). Measured with a byte-identical, structurally valid
  cloud key: **2 active findings and exit 1** in `settings.py`, **0 active and
  exit 0** in `.env.example`. The filename was the whole predicate, and a
  filename is chosen by whoever wrote the file.

  🔴 **Deleted rather than narrowed, because it could not have been doing useful
  work.** By the time a `SECRET` finding reaches the false-positive pass it has
  already passed `engine_secrets.is_dummy()`, which drops placeholders at
  detection. The example path was already handled proportionately, as a
  confidence downgrade (HIGH → MEDIUM via `_path_is_test_or_example`). The right
  response had been applied twice before this rule ran; the rule applied it a
  third time, as suppression, to exactly the findings the first two had judged
  real. A live credential committed to a `.env.example` is one of the commonest
  real leaks there is.

  Both directions are pinned: a real credential in all four example suffixes now
  fires, and placeholders in the same files still do not — the latter is the test
  that would catch this deletion having made example files noisy.

- **`"lock" in path` matched any path containing the substring**, so
  high-entropy findings were suppressed in `src/locks/keys.py`, `app/unlock.js`
  and `clockwork/`. Now anchored to actual dependency lockfile **basenames** — a
  directory named for locking is where credential handling tends to live.

  ⚠️ `.env.template` and `.env.dist` now report at full confidence, because the
  downgrade list does not match them. Deliberately **not** "fixed" by adding
  substrings: `dist` would match `dist/` build directories, widening a
  suppression to close a reports-too-loudly gap.

### 🔴 Security — every engine trusted, none of them measured

Found by independent adversarial audit and re-derived before fixing.

- **A scan in which nothing ran was a clean bill of health.** The gate asked a
  per-engine question — *"can I trust this engine's silence?"* — and answered it
  correctly. Nothing asked the whole-scan question: *"did anything actually
  look?"* `disabled` and `not-applicable` are trustworthy silences, so a scan
  made entirely of trustworthy silences passed.

  Reached by `--engines ""`, which parsed to the empty list, left all four
  engines `disabled`, and returned **exit 0** on a tree containing a live
  credential under `--fail-on INFO`. An *invalid* engine name was correctly
  rejected with exit 2 — so a typo was caught and the empty string was not, which
  is exactly how it arrives in CI as `--engines "$ENGINES"` with the variable
  unset.

  Two fixes, deliberately. An empty selection is now rejected at parse time
  (**exit 2**) — that is the diagnostic. The guarantee is a whole-scan floor:
  with `--fail-on`, a scan where **no engine measured** exits **3**, keyed on
  that property rather than on the empty-string spelling that demonstrated it.
  `--engines sca` against a target with no manifests reaches the same state by a
  different route and now fails the same way. `--allow-degraded` still opts out.

  ⚠️ `ENGINE_MEASURED_STATUSES` is a *proper* subset of `GATE_TRUSTED_STATUSES`,
  and a test asserts the strict relationship: if the two ever become equal the
  floor silently stops meaning anything, firing only where the degraded path
  already had.

  The degraded path keeps its own diagnosis when both faults hold at once —
  `SCAN DEGRADED` names which engines failed; the floor does not.

### 🔴 CI had been failing on every push, and the obvious fix corrupted a table

- **The invariants workflow was red on every push for two days.** It pinned
  Python 3.12 while `tests/precommit.sh` pins `py -3.14`, and
  `rust/praetor-core/src/unicode_tables.rs` is *generated* from Python's
  `unicodedata` — so its content is a function of the interpreter. CI's 15.0.0
  could not reproduce a table built from 16.0.0.

  The workflow is the one guarding "PRAETOR never executes the code it scans". A
  check that is always red carries no information: had the never-execute test
  started failing, the signal would have been identical. **A local gate that pins
  the interpreter making it pass is a tautology, not a verification.**

- **`--check` could not tell "you are stale" from "you are ahead of me"**
  (`tools/gen_unicode_tables.py`). It compared content only, and those two
  conditions demand opposite actions — regenerate, or refuse. It reported both as
  `STALE`, with a remediation naming `py -3.14`: the **Windows launcher**, which
  does not exist on the Linux runner printing the message. The reachable
  substitute regenerated against the older database, exited 0, printed
  `wrote ...`, discarded 353 lines of code points, and the downgraded table then
  **passed its own `--check`**. The wrong action was rewarded with green.

  The generator now reads the `UNICODE_VERSION` constant it has always emitted —
  under a comment saying it existed "so a mismatch is diagnosable", which nothing
  read — and branches on **direction**: an older interpreter gets
  `WRONG INTERPRETER` and **exit 2**, and the write path refuses outright unless
  `--allow-downgrade` is passed. An unreadable header falls back to the stale
  path, so a mangled header cannot block a legitimate regeneration.

  ⚠️ The cross-language differential gate did not catch the downgrade either —
  not because its cases miss the shifted code points, but because its only corpus
  is line-splitting. **There is no homoglyph corpus for these tables at all.**

### 🔴 Security — three suppressions the scanned tree could trigger itself

Found by independent adversarial audit, re-verified from source. **None was
introduced by the commit under audit; all three were pre-existing and live.**
PRAETOR reads attacker-controlled input by definition, so any suppression the
target can trigger makes the scanner an oracle for the attacker.

- **Dedup elected a *filtered* finding over an unfiltered one**
  (`scripts/interpret.py`). All five injection rules share `CWE-77`, so every
  `PROMPT_INJECTION` finding on a line collapses into one dedup group.
  `_sort_key` ignored `filtered`, so a quoted, defensively-framed exemplar —
  correctly suppressed — won primary election and **discarded the live payload
  beside it**. Measured, identical payload: alone it is a HIGH active finding
  and exits 1; with a quoted specimen appended to the same line, `active` is
  empty and it exits 0. The live finding was in *neither* bucket and carried no
  `filter_reason`, so a reviewer auditing suppressions could not have found it.
  The rule-level guard was correct; the defect re-entered one layer down.

- **The inline-ignore marker was a bare substring of the whole line**
  (`scripts/praetor.py`). No word boundary and no comment required, so a JSON
  file — which has no comment syntax at all — could suppress a real credential
  via a key named `"nosec_note"`, and `nosec` matched inside `nosecret`,
  `nosecurity`, `nosection`. Markers must now be whole words inside an actual
  comment (`scripts/lexctx.py`); string literals are blanked first, so a marker
  appearing as a *value* no longer suppresses.

- **`.github/`, `.githooks/` and `.gitlab/` were never walked**
  (`scripts/core.py`). `not d.startswith(".git")` skipped every sibling of
  `.git`. `.github/workflows/` is executable CI code and `.githooks/` is the
  conventional `core.hooksPath` home, so the git-hook detector could not see
  hooks where they normally live. The engines still reported `status: ok`.
  `TEXT_NAMES` listed `copilot-instructions.md`, which lives under `.github/`
  and was therefore unreachable — a name documented as covered that no file
  could match.

### 🔴 Security — the SAST engine was not running, and the target could stop it

- **A broken semgrep was reported as a working runtime**
  (`scripts/engine_sast.py`). `detect_runtime` answered `available: True` from
  `shutil.which("semgrep")` alone. The version check beside it, `_native_version`,
  ignored the exit code and had `except Exception: return "semgrep"` — a probe
  that could not fail, whose result was used only as a display label.

  On the box this project is developed on, a pip-installed Windows `semgrep.EXE`
  exits 1 and prints nothing. PRAETOR reported it available, **preferred it over a
  healthy WSL semgrep**, ran it, got no output, and reported `[error] sast`. The
  engine covering OWASP and injection had not run here at all. Turning it on
  surfaced two HIGH findings in this repository's own CI workflow.

  Every branch now probes: `--version` must exit 0 *and* print something. In
  `auto`, a candidate that fails falls through, so one broken install cannot mask
  a working runtime beside it.

- **WSL was resolved in a non-login shell.** `wsl -d <distro> which semgrep`
  reports on the bare system PATH, not the one the operator's profile builds, so
  per-user installs (pipx, a venv, `~/.local/bin`) were invisible. Resolution now
  uses a login shell, and **the resolved absolute path is used in the command** —
  the old prefix invoked bare `semgrep`, repeating the non-login lookup at run
  time, so a passing probe could still be followed by a failing run.

- **Any scanned tree could disable an engine with one typographic quote**
  (`scripts/core.py`). Engines called `subprocess.run(..., text=True)` with no
  `encoding`, which decodes with the *locale* codec — cp1252 on a stock Windows
  install, where five bytes are undefined. Semgrep and osv-scanner embed snippets
  and paths **from the scanned tree** in their JSON, so those bytes arrive from
  the target. `U+201D` (`”`) is `E2 80 9D`; its mirror `U+201C` is `E2 80 9C` and
  was harmless.

  The decode runs on subprocess's reader thread, so `run` returned normally with
  `stdout=None` and the next `.strip()` raised outside the engine's try block —
  surfacing as `'NoneType' object has no attribute 'strip'`. All engine
  subprocesses now go through `core.run_tool`, which decodes UTF-8 with
  replacement; a source-level guard keeps new call sites from bypassing it.

- **Findings from WSL and Docker carried unusable paths.** Semgrep reports under
  the root it was given (`/mnt/c/...`, `/src/...`), and the relative path was
  computed against the Windows target, yielding
  `../../mnt/c/projects/…/ci.yml`. `f.file` is the key that inline `# nosec`
  suppression, lexical context, taint reachability and the baseline classifier
  all use to reopen a file, so each degraded silently — and because "cannot open
  ⇒ keep the finding" is the fail-safe direction, it hid as noise rather than as
  an error. Snippet reads used the same unusable path.

### 🔴 Security — a fail-open in the gating path

- **`--fail-on` returned exit 0 when an engine could not measure**
  (`scripts/praetor.py`). The exit-code block consulted the active-findings list
  and nothing else, so an engine that errored — a dead semgrep runtime, an
  unreachable Docker daemon, unparseable tool output — contributed zero findings
  and the gate passed. In CI that is indistinguishable from a scan that ran and
  found nothing.

  PRAETOR already computed the answer: `engine_meta` recorded `ok`/`error`/
  `disabled` per engine and put it in the report. It was never read for any
  decision. The fix is one wire, plus the vocabulary needed to make it safe.

  **New exit code `3`** — `--fail-on` was requested and an engine did not
  measure. `--allow-degraded` opts out per run. `1` still outranks `3`.

- **`unavailable` split into two states.** It meant both "this target has no
  dependency manifests" (nothing to measure) and "this box has no semgrep
  runtime" (could not measure) — opposite facts under one word, which forces a
  gate to choose between failing every manifest-free repo and going blind. The
  target-property cases are now `not-applicable`. **JSON consumers keying on
  `"status": "unavailable"` for an empty-manifest scan must update.**

- **Unknown engine statuses now fail toward "unmeasured."** The gate reads an
  allowlist (`core.GATE_TRUSTED_STATUSES`), so a status word introduced by a
  future engine and never considered here blocks rather than passes silently.

- **The report says so too.** An unmeasured engine renders `[BLIND]`, not
  `[skipped]`, and the "No active findings" line carries the caveat directly —
  that line is the one most likely to be read as a clean bill of health.

- **The Docker runtime probe checked the binary, not the daemon**
  (`scripts/engine_sast.py`). `shutil.which("docker")` proves the CLI is
  installed; it does not prove the daemon is reachable. With Docker Desktop
  installed but stopped, SAST reported available and then failed with a connect
  error surfaced as `Run 'docker run --help' for more information` — naming the
  wrong layer entirely. The probe now asks the daemon. The native and WSL
  branches already did this; Docker was the one that asserted the capability.

  ⚠️ These two composed: a probe that reports a dead runtime as available
  produces an errored engine, and an errored engine used to produce exit 0.

  Both were found by independent readers, not by this repo's own tests.

### 🔴 Security — a suppression bypass in PRAETOR itself

- **One definition of a line** (`scripts/core.py: split_lines`). PRAETOR resolved
  line numbers with Python's `str.splitlines()`, which splits on eleven characters
  (`\v \f \x1c \x1d \x1e \x85 U+2028 U+2029` and friends). Every other tool in the
  chain — Semgrep, `grep -n`, `sed`, `git`, editors — splits on `\n` only.

  A single such character anywhere earlier in a file therefore shifted PRAETOR's
  line numbering relative to reality, so an attacker-placed `# nosec` marker could
  suppress a finding on a line that does not contain it. Every line-number site now
  uses the shared `split_lines()`; a call-site guard fails the build if a new one
  reaches for `str.splitlines()`.

  Found by porting the code to another language, not by testing — the whole test
  suite, the self-scan and code review all passed over it.

### Added

- **Homoglyph / confusable detection** (`aisec`). Fires on mixed scripts *within a
  token* — `paypal` with its Latin `a` replaced by Cyrillic `U+0430`, which renders
  identically — not on the presence of non-Latin text; a Russian README is not an
  attack.

  ⚠️ Described by code point rather than spelled out, because the first draft of
  this entry contained a live confusable and the detector correctly flagged its own
  changelog. Fix the fixture, not the rule.
- **Agent hook configs from any assistant** (`aisec`). Auto-running `command`
  fields were only recognised in Claude-format paths; Cursor, Windsurf, Cline, Roo
  and friends went unread. Claude-specific paths are all retained — detecting only
  one vendor was the defect; removing it would be a worse one.
- **CVE-2026-53753 class rule** (`sast`, bundled offline ruleset). Attribute
  denylists guarded solely by `startswith("_")`, which let `gi_frame` / `f_back` /
  `tb_frame` walk out of a sandbox. Scoped to one recognisable shape and rated
  MEDIUM confidence, because "is this sandbox sound" is undecidable.
- **A Rust workspace** under `rust/`, with the never-execute invariant test ported
  first. **No detector has been ported**; the binary refuses to scan rather than
  pretend to. See `references/ADR-001-engine-language.md`.
- **A cross-language differential contract** (`references/differential/`). 🔴 The
  `*.expected` files are contracts, not fixtures — never regenerate one to make a
  test pass.

### Fixed

- **`sca` no longer reports a clean scan when osv-scanner analysed nothing.** A
  target with no recognised lockfile produced `status: "ok"` and zero findings,
  which is indistinguishable from a genuinely clean result. It now reports honestly
  that nothing was analysed.
- **Two audit-found gaps where a guard's comment outran the guard**: an invariant
  sweep whose "covers EVERY backend" claim keyed on a hand-written list, and a
  call-site guard that exempted the entire file it was guarding. Both fixed by
  writing the missing enforcement rather than softening the prose. Recorded in
  `references/audits/2026-08-10-independent-audit.md`.

### Changed — ⚠️ breaking for machine-readable consumers

- `SCHEMA_VERSION` is now **2.0**. Two `rule_id`s were renamed as part of making
  hook detection vendor-neutral: `claude-hook-autorun` → `agent-hook-autorun` and
  `claude-hook-autorun-dangerous` → `agent-hook-autorun-dangerous`. Anything
  keying on those strings — `--fail-on` filters, JSON consumers, dashboards —
  needs updating. See the README's `schema_version 2.0` section.

## 1.0.0

⚠️ **Not a release — a version number.** `pyproject.toml` says `1.0.0`, but nothing has
been tagged and nothing is published to PyPI. This entry records the state that
version designates, not a distribution event.

Four engines (`sast`, `secrets`, `sca`, `aisec`), the
interpretation layer (dedup, ranking, false-positive filtering with stated
reasons), text and JSON reporting, and bundled offline Semgrep rules.
