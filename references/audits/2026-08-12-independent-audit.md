# Independent adversarial audit — 2026-08-12

**Verdict: BLOCK, unanimously, from two independent passes.**

Scope: four commits, `8980f71..a04b951`.

| commit | subject | state at audit |
|---|---|---|
| `236f184` | `--fail-on` returned 0 when an engine could not measure | **already published** |
| `a100117` | a display filter was silently narrowing `--fail-on` | **already published** |
| `36c00af` | the SAST engine was not running, and any target could stop it | held |
| `a04b951` | three suppressions the scanned tree could trigger itself | held |

Two reviewers worked from the diff with no knowledge of the author's reasoning,
each defaulted to BLOCK, each mutation-testing in throwaway `git archive`
extracts. Neither modified the repository; the tree was verified clean before and
after both.

Both reached the same top-line conclusion, in almost the same words: **the four
commits do what their messages say — and the *class* each one closes is still
open somewhere else.** Six named guards were mutation-proved to redden the
correct test. The findings below are all about the ground those guards do not
cover, plus prose that describes coverage which does not exist.

> This is the fourth consecutive audit on this codebase to find that a fix closed
> the instance it was shown and described itself as closing the class. That is now
> a documented property of how this project fails, not an accident.
> ⇒ `CLAUDE.md`, "A FIX IS UNAUDITED CODE".

---

## Confirmed by re-derivation

Three findings were independently reproduced by a third party after the reports
landed, using their own targets and reading exit codes directly. These are not
awaiting confirmation.

| # | condition | result |
|---|---|---|
| B-F1 | an agent-directed imperative in `CLAUDE.md` | 1 active HIGH, exit **1** |
| B-F1 | the same line plus a parenthetical containing a hash character | 0 active, exit **0** |
| B-F6 | a structurally valid cloud key in `settings.py` | 2 active, exit **1** |
| B-F6 | the byte-identical key in `.env.example` | 0 active, exit **0** |
| B-F7 | `--engines ""` with that key present, `--fail-on INFO` | all engines off, exit **0** |

---

## HIGH — a scanned tree can still delete findings

### A-F1 · An ignore-file in the target deletes every SAST finding; the engine still reports `ok`

`scripts/engine_sast.py:329-344`. The argv passes `--no-git-ignore`, but nothing
disables semgrep's **own** ignore file, which semgrep resolves from the *scan
target root* — i.e. from attacker-controlled ground.

A single-line ignore file at the target root removes the finding from **both**
buckets, with no `filter_reason`, while the engine reports `status: ok`,
`scan errors=0`, and the exit code moves 1 → 0. The operator-facing report reads
`[ran] sast … (0 finding(s))` followed by "No active findings".

Pre-existing — but these commits are what make it *live*: `36c00af` is what makes
SAST actually run here, and `236f184` is what makes an engine's `ok` load-bearing
for the exit code.

The comment immediately above the argv argues at length that git must not impose
"a SECOND, invisible filter" and concludes *"If you scan it, scan it. Exclusion is
the caller's call, not git's."* The identical argument applies to the tool's own
ignore file, which is neither handled nor disclosed. ⇒ An incomplete gaps list
reads as exhaustive.

### A-F2 · A URL is treated as a comment, so a marker in a URL path suppresses a credential

`scripts/lexctx.py:86-100` (new in `a04b951`), consumed at `scripts/praetor.py:195-198`.

`_strip_inline_strings` blanks only *quoted* text, so **any unquoted comment
introducer anywhere on the line** opens a comment — including the `//` inside a
bare URL. In YAML, Markdown, `.txt` and `.env`, none of those introducers is
comment syntax.

Measured: a credential on a line whose trailing documentation URL ends in a path
segment equal to an ignore marker moved to `filtered`, exit 1 → 0. The control,
with any other final path segment, stayed active at exit 1.

Not a regression — the base's bare-substring test matched too. But the CHANGELOG
claims *"Markers must now be whole words inside an actual comment"*, and that is
false for every format without comment syntax. The four tests added cover JSON
(safe by construction — it has no unquoted text) and the three substring cases;
**none covers an unquoted introducer.**

### A-F3 · `not-applicable` is gate-**trusted** and is decided by a hand-written filename list

`scripts/engine_sca.py:44-51` (`ANY_LOCKFILES`) and `:445-450`.

Identical pinned vulnerable dependencies produced two active HIGH findings and
exit 1 in a recognised layout, and **`sca: not-applicable`, no findings, exit 0**
when moved to the very common split layout `requirements/prod.txt`.

`236f184` introduced `not-applicable` and placed it in `GATE_TRUSTED_STATUSES` —
"there was nothing to measure, so nothing is unmeasured". The comment states that
as fact: *"A property of the TARGET, not of this box."* It is a property of
`ANY_LOCKFILES`, which omits `package.json`, `Pipfile`, `Cargo.toml`, `Gemfile`,
`composer.json`, `*.csproj`, `environment.yml`, and every non-canonical
requirements filename.

The honest word is "no **recognised** manifest", and that does not license trust.
🔴 **This is the `unavailable` split's one genuinely new fail-open**: the state
existed before, but nothing had yet declared it trustworthy.

### B-F1 · A hash character deletes findings in formats where it is not a comment

`scripts/lexctx.py:103,161` default `comment_prefixes` to the hash character for
**every** file type, and `classify_lines` (`:146-154`) labels a line as comment if
one appears anywhere after string-blanking.

In Markdown — the primary target for the agent-security engine — that character
is a *heading*: the most prominent rendered content an agent reads. Re-derived
above. The recorded suppression reason ("appears in a code comment, which cannot
execute") is provably false for the file it was applied to.

`a04b951` added `comment_text` directly beside this, with a docstring calling the
list "DELIBERATELY CONSERVATIVE" and a "STATED IN FULL" gap list naming only
*under*-recognition — the safe direction — while over-recognition was live one
function below.

### B-F2 · The tool's own error count is computed, reported, and never gated on

`scripts/engine_sast.py:448-450` sets `status: "ok"` unconditionally whenever the
JSON parses, regardless of the tool's `errors[]`; the skipped-paths list is
ignored entirely. Driving the real `run()` with a payload carrying a timeout and
a system error yields `status: ok`, `scan errors=2`, gate-trusted.

🔴 This is `236f184`'s own thesis — *"the observable existed, was correct, was
populated, and was wired to the report instead of the gate"* — reproduced one
layer down, **in the file `36c00af` rewrote**. The per-file timeout means a target
can induce it.

*Both reviewers reached this independently; one proved the mechanism, the other
rated it unproven because they could not drive `errors[]` from target content.
The status is hardcoded either way.*

### B-F3 / A-F6 · Files the walker drops are invisible; every engine still reports `ok`

`scripts/core.py:503-505` drops oversize and binary-looking files with no record
anywhere. Four measured routes, each on a target whose only content was a
structurally valid credential, each with `--fail-on INFO`, each reporting
`Files (text): 0`, `[ran] secrets`, **exit 0**:

- a file padded past the 3 MB default cap
- a file with a long run of leading control characters
- a **UTF-16-encoded** source file — not adversarial; Windows tooling emits it
- `--max-file-size 0`

Raising the operator's limit does not raise the SAST engine's: with
`--max-file-size 50000000` the walker enumerated the file while SAST still
reported `ok` with zero findings, because its byte cap is a hardcoded constant
(`engine_sast.py:330`).

Each of these directly falsifies the newly added definition of exit `0` as
**"fully measured and clean"**.

---

## MEDIUM

### A-F4 / B-F4 · The structural guard is a hardcoded five-file list

`tests/test_tool_output_is_not_target_controlled.py:100-128`. **Found independently
by both reviewers**, with four different mutations, all leaving the suite green:

1. the original defect verbatim but aliased, so the literal call spelling is
   absent, applied to real engine code → `170 passed`
2. a **new engine file** with a bare unwrapped call — literally "a new caller" →
   guard `3 passed`, suite `170 passed`
3. the deferred-execution form of the same call, added to a **listed** file,
   reintroducing the identical decode defect
4. the same call reached through an aliased module import

The anti-vacuity `assert scanned == 5` counts the hardcoded tuple rather than the
directory, so it **actively locks the guard to the list**. Also unreached: the
`from`-import form, the output-capture and call convenience wrappers, and the
OS-level pipe helper.

The commit claims: *"A source-level guard keeps new call sites from bypassing it,
because a test asserting keyword arguments cannot notice a new caller that never
uses it."* That is precisely the case demonstrated to fail.

This is the third recorded occurrence of *key the guard on the spelling, not the
property* in this repository.

### A-F5 · Dedup's mirror direction still discards into neither bucket

`scripts/interpret.py:22-98`. `a04b951` fixed the direction that mattered most —
a suppressed finding can no longer win primary election over a live one. But
`dedup` still elects one member and drops the rest, so in the mirror case a
*suppressed* finding colliding with an unfiltered sibling is discarded with **no
`filter_reason` and no bucket**.

This breaks `CLAUDE.md`'s *"Suppress with a stated reason, never silently"*, and
erodes the stated justification for the gate ignoring the filtered bucket ("that
exclusion is auditable"). The new `test_filtered_never_wins_primary_election`
asserts only that the live finding survives — never that the suppressed one is
retained. **The same one-direction shape the commit message says every test now
avoids.**

### A-F7 · Upstream-consumed suppressions carry no reason and land in neither bucket

The tool's own inline-ignore comment is honoured by the tool itself, so the
finding never reaches PRAETOR's `_apply_inline_ignores` — which *does* know that
marker and *would* have recorded a reason. Result: exit 0, both buckets empty,
`sast: ok`. Same class as A-F1 at line granularity.

### B-F6 · Suppression on PATH ALONE

`scripts/interpret.py:109` suppresses **any** secret finding whose filename ends
in one of four example/template suffixes, with no inspection of the value.
Re-derived above: a structurally valid, non-placeholder key is active at exit 1 in
a normal source file and silently filtered at exit 0 in the example file.

`engine_secrets.is_dummy()` is exactly the structural property required and is
never consulted. Two more at `:113` and `:121` key on substrings that match real
source paths.

🔴 Directly violates this project's own written rule — *"Never suppress on PATH
alone… Require the actual structural or semantic property"* — a rule that exists
because this same mistake was made here before. **Renaming a file is enough.**

### B-F7 · An empty engine selection runs nothing and passes the gate

`scripts/praetor.py:371-376` maps an empty, whitespace, or comma-only value to an
empty list, and the validation loop has nothing to reject. All four engines become
`disabled` — a gate-trusted status documented as *"the OPERATOR excluded this
engine… their choice, made knowingly"*. Re-derived above: exit **0** on
`--fail-on INFO` with a live critical credential in the tree, while an *invalid*
engine name is correctly rejected with exit 2.

A CI invocation passing an unset variable is a total, silent false clean. No test
covers it, and no floor requires that at least one engine actually ran.

### B-F8 · The project's own pre-commit gate cannot detect the defect `36c00af` fixed

`tests/precommit.sh` gate 4 runs the scanner with **no `--fail-on`**, greps two
count lines, and never reads the exit code or the engine block — it does not use
the mechanism these commits added. Measured byte-identical output with SAST
working and with SAST dead: both `active=12 filtered=53`, both PASS. The
"SCAN DEGRADED" banner is captured into the variable and never grepped.

Third recorded occurrence of *a check that reports does not gate*.

---

## LOW / unproven

- **A-F8** — the fast path in `_relative_to_report_root` (`engine_sast.py:50-79`)
  returns its suffix before normalisation, bypassing the escape check below it, so
  a crafted absolute path yields a traversal-shaped relative path that four
  consumers rejoin to the target root. The docstring's *"Never invents a path"*
  holds only for the slow path. **No target could be constructed that makes the
  tool emit such a path** — rated a hardening gap, not a demonstrated exploit.
- **B-F9** — `detect_runtime`'s docstring asserts *every* branch measures the
  runtime; the container branch probes the daemon and then infers the analyser
  from it. The inline comment is honest; the emphatic docstring above it is not.
  Fail-safe outcome, hence low.

---

## Prose that certifies coverage no test enforces

Flagged separately because this is the project's documented recurring failure.

1. CHANGELOG — *"Markers must now be whole words inside an actual comment"*. False
   for every format without comment syntax (A-F2).
2. `36c00af` — *"A source-level guard keeps new call sites from bypassing it"*.
   False for the literal case named, demonstrated four ways (A-F4/B-F4).
3. README and SKILL — exit `0` means *"fully measured and clean"*. Falsified by
   A-F1, A-F3 and A-F6/B-F3.
4. `engine_sca.py:445-448` — *"A property of the TARGET, not of this box"*. False
   whenever dependencies live in an unlisted filename (A-F3).
5. `engine_sast.py:331-344` — *"If you scan it, scan it. Exclusion is the caller's
   call, not git's."* Reads as exhaustive; the tool's own ignore file still
   applies (A-F1).
6. 🔴 **The project's own standing rule was not followed.** `CLAUDE.md`: *"Every
   new engine or backend widens this surface. If you add one, add its test
   there."* `36c00af` adds **three new subprocess call sites** — including one
   that starts a **login shell** — and adds nothing to
   `tests/test_invariant_never_executes_target.py`, which still covers only the
   two package-manager backends. The analyser's argv has never been covered there
   at all.

---

## Verified clean (do not redo)

- **The never-execute invariant holds.** The disable-resolution flags are still on
  the audited argv; nothing in the diff resolves, builds or installs from the
  target; the container branch mounts read-only; every probe reads nothing from
  the target; the scan stays argv, with no target path handed to a shell.
- **Exit-code decision, end to end**, with the code read directly rather than
  through a pipe: degraded → 3; opted out → 0; no gate requested → 0; blind engine
  *plus* a real finding → 1 (1 correctly outranks 3); nonexistent path → 2; empty
  directory → 0 with honest statuses.
- **Status vocabulary is complete**; unknown, empty and missing all resolve to
  blind, and every engine is unconditionally present in the metadata.
- **`a100117` is genuinely fixed, both directions** — the gate list is captured
  before the display filter.
- **Word-boundary matching holds** for the three substring cases; a marker inside a
  quoted string is blanked; the string-blanking failure mode is toward
  *over*-blanking, which is the safe direction.
- **Dedup among unfiltered findings is safe** — severity still dominates.
- **The walk fix is correct**: the git directory is still skipped exactly, and its
  siblings are now walked.
- Six mutations reddened their named tests. 170 tests pass; all 8 gates green.

## Not covered by either pass

Easy gaps first, per this project's own disclosure rule.

- **The SCA analogue of A-F1**: the dependency scanner honours an in-tree config
  file that can ignore advisories. Untested. Given A-F1, expected to work.
- **`--exclude` semantics**, and its interaction with the two *separate* exclusion
  passes inside the SCA engine.
- **Detection quality of the secrets and agent-security engines** — used only as a
  signal source for gate tests; no regex evasion work.
- **SCA end to end** — all three backends are installed here and none was run
  against a genuinely vulnerable manifest, so the partial-error path and the
  npm error handling are unverified.
- **Registry rulesets** — everything ran offline; the login-required fallback is
  unexercised.
- **The container runtime for real** — every assertion about it was monkeypatched.
- **Native analyser runtime** — the install on this machine is the broken one the
  commit describes.
- **Symlink divergence** — the walker does not follow links; the analyser has its
  own policy, so a symlinked directory is likely scanned by one and not the other.
- **The Rust port** — its tests pass, but no Rust source was read and nothing
  checks that these Python-side fixes have counterparts there. This project has
  already recorded conformance-is-not-parity as a past failure.
- **Report output to a directory**, and the JSON schema consumers key on.
- Homoglyph tricks against the marker word-boundary regex; `.gitattributes`; a
  target-supplied package-manager config.

---

## Method note — a flaw in how this audit was run

The two passes were given **adjacent scratch directories under one shared root**.
One reviewer's cleanup partially removed the other's working directory mid-run.
No repository file was touched, and the affected reviewer's findings were
independently re-derived afterwards, so nothing here rests on damaged evidence.

⇒ **Parallel reviewers need disjoint, private scratch roots.** Shared temporary
space makes one reviewer's housekeeping into another's corrupted measurement, and
the corruption is silent.
