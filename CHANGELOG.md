# Changelog

Notable changes to PRAETOR, most recent first.

This file starts at `1.0.0`, the version in `pyproject.toml` at the time it was
written. No releases are tagged yet, so everything below `Unreleased` is on `main`
and not in any published artifact.

Because PRAETOR is a security scanner, entries say what a change means for
**detection** — a bug here is not a broken feature, it is a scanner reporting
"nothing found" while something is there.

## Unreleased

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

Initial public release: four engines (`sast`, `secrets`, `sca`, `aisec`), the
interpretation layer (dedup, ranking, false-positive filtering with stated
reasons), text and JSON reporting, and bundled offline Semgrep rules.
