# SAST language eligibility requirement

**Status:** binding for the shipped Python scanner and any future Rust SAST port.

## Binding SAST coverage predicate (Python and future Rust)

`ALIASES` is one fixed table in code from each language PRAETOR detects to the
Semgrep language IDs for it. In particular: `shell -> {bash, sh}`, `python ->
{python, python3, py}`, `javascript -> {javascript, js}`, and `typescript ->
{typescript, ts}`. A detected language with no table entry is never covered.
The conformance guard asks the installed Semgrep for its supported-language
list and requires every alias in the table to appear there; its evidence records
the installed Semgrep version used for that check.
Every scan report also records the installed Semgrep version that resolved and
ran its SAST rules. Docker uses the same exact version pin as tracked installs.

The in-effect rules are the pinned rules plus every operator config actually
supplied to Semgrep: the built-in registry packs when registry use is enabled,
and every `--semgrep-config`, including registry packs. Each source is resolved
to its rule list through the same Semgrep config loader and validator the scan
uses. A config found inside the scanned target never counts. A config that
cannot be resolved is an eligibility error that names the source and fails the
scan closed. This applies equally to operator configs and enabled registry packs. A
local config directory that contains or is an ancestor of the scanned target is
also target-controlled and never counts. This is an authority boundary, not a
scan exclusion: every explicitly supplied operator config still executes and
its findings remain enforceable even when it cannot establish trusted coverage.
In Docker mode, resolution and scanning bind each local config from the same
exact read-only host source under a path unique to that source.
Registry identifiers such as `p/security-audit` remain semantic identifiers
even when an attacker-controlled relative path with that spelling exists.
Local operator paths are expanded and made absolute once; trust classification,
resolution, and native, WSL, or Docker execution all consume that same identity.
Existing-path containment is decided by filesystem identity rather than
case-sensitive spelling. Both config and target paths are canonicalized before
their parents are compared, so symlinked leaves, symlinked parents, and a
symlinked target cannot cross the authority boundary. Uncertainty fails closed.

The resolved pinned source must account for every canonical language declared
by the shipped pinned YAML. Any unrecognized resolved language token, or any
declared language absent after resolution, is dump-format or language-ID drift
and is an eligibility error. It must never collapse into `NO COVERAGE`.
Field-shaped rule-controlled text cannot supply eligibility facts: if the
resolved dump contains ambiguous selector or paths fields, source resolution
fails closed, including when a real field wraps and quoted text supplies the
only single-line field-shaped string. Rule boundaries come from balanced
top-level objects in the resolved rules list, never from a `Rule.id`-shaped
payload line. A physical multiline rendered string is structurally ambiguous
and fails closed. The one true top-level final
`invalid_rules` field in every `Rule_fetching` record must be empty. Multi-file
config directories aggregate only when every emitted record validates;
quoted metadata cannot spoof it. A validated `target_selector = None` rule is
preserved with an empty language set, so generic rules run but never establish
language coverage.

A rule counts for detected language `L` only when all four conditions hold:

1. It parsed and validated.
2. Its `languages` list contains at least one ID from `ALIASES[L]`.
3. It is not `generic`, `regex`, or `none` only; those never count for any `L`.
4. It has no `paths.include` filter. An include filter can scope a rule away
   from every file of `L`, so it cannot establish coverage.

`covers(L)` is true only when at least one in-effect rule counts for `L`.
Findings never enter this decision.

For every detected language, a covered result names every covering source and
its count of counting rules, for example `SAST: shell covered by operator config
<path> (3 rules)`. It emits no `NO COVERAGE` line for that language. A language
that is not covered emits `SAST: NO COVERAGE (<language>)`. The named gap is
nonblocking by itself and other selected engines
continue running. It is trusted evidence of a gap, not evidence that SAST
examined source. Coverage classification never suppresses the Semgrep run:
PRAETOR's walker population is not Semgrep's target population, so an uncovered
detected file cannot hide findings in a file only Semgrep classified. A gated
scan in which `NO COVERAGE` is the only enabled engine
result fails the existing `NOTHING WAS MEASURED` floor. The gap remains
nonblocking when another selected engine actually measured, and a mixed target
remains measured when SAST ran for a covered language while naming another
language's gap.

Eligibility resolution and the Semgrep scan receive the same effective timeout:
the explicit CLI override when present, otherwise `PRAETOR_SEMGREP_TIMEOUT`,
otherwise the shipped default. All rule-source resolution subprocesses share
that one total budget; each successive source receives only the remaining time.
There is no second timeout policy. Resolution disables metrics and version
checks just as the scan does, propagating that policy inside native, WSL, and
Docker runtimes rather than relying only on the parent process environment.

Known ceiling: rule-level `paths.exclude` and Semgrep's own per-language
file-extension matching are not modelled. Either can narrow a counted rule, in
the worst case to no file of `L`, so the report can overstate coverage for `L`.
That is the unsafe direction. It is accepted because an exclude that removes
every file of a language is not a normal rule pattern. If one is ever observed,
condition 4 must change to reject any `paths` filter, including `paths.exclude`.

This predicate is binding word for word on the future Rust SAST port. Its
wrapper and differential corpus must preserve the same source resolution,
counting conditions, evidence, and named-gap behavior.

## Tracked follow-up

- [ ] **SAST-SHELL-001 / issue #2:** design, pin and positive-control a shell
  Semgrep ruleset before any downstream shell enforcement hook is enabled.
  This release deliberately ships truthful `NO COVERAGE` reporting instead of
  shell rules: https://github.com/GrowBridge-LLC/praetor-security/issues/2
