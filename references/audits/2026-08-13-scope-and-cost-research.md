# Scope, cost, and an independent review — 2026-08-13

**Status:** research complete, two fixes landed, four items designed-not-built.
**Commits covered:** `23df5ea..208ed71` (10, all unpushed at time of writing).
**Reviewer:** CodeRabbit CLI 0.7.2, `review --committed --base origin/main -c CLAUDE.md`.

> **Why this file exists.** All of the below lived only in one session's context.
> Memory files do not cross a machine boundary and a session scratchpad does not
> survive the session; a commit survives both. The measurements here are the
> expensive part — several took 10+ minutes of wall clock — and re-deriving them
> from scratch would be the real cost of losing this.

---

## 1. An external reviewer found two things six adversarial passes did not

Three rounds of 2× independent adversarial audits (six passes total) ran over this
same code. CodeRabbit's **first** run found two defects none of them reported.

| id | finding | state |
|---|---|---|
| CR-4 | the runtime-probe test **fails on any host without semgrep/wsl/docker** | ✅ fixed, `208ed71` |
| CR-3 | the wide secrets walk ran **even when secrets was not selected** | ✅ fixed, `208ed71` |
| CR-1 | `--exclude` is a **regex** to PRAETOR and a **glob** to semgrep | ⬜ open |
| CR-2 | after the flag-rejection fallback, reporting `ok` is indefensible | ⬜ open |

### CR-4 — a test that only passed on this box

`test_the_runtime_probes_never_receive_the_target_at_all` asserts a probe was
attempted. Every probe sits behind `shutil.which(...)`, so on a machine with no
tools — **i.e. every CI runner, since the invariants job installs none by design** —
`detect_runtime` makes zero calls and the arming assertion fails. Measured:

```
bare runner, without the stub : 0 probe calls  -> assert calls FAILS
bare runner, with the stub    : 6 probe calls  -> passes
```

The suite was green locally only because this box happens to have WSL. **This would
have turned CI red on the first push.** Fixed by stubbing `which` as well as
`run_tool`.

### CR-1 — two pattern languages, one user input (OPEN)

`core.py` compiles `--exclude` values with `re.compile`. `engine_sast.py` passes
the *same strings* to semgrep, whose `--exclude` takes **gitignore-style globs**.

- `--exclude '^generated/'` → excludes for PRAETOR (regex anchor), **no-op** for semgrep.
- `--exclude '*.min.js'` → valid glob for semgrep, **invalid regex** — `re.compile`
  raises `PatternError` and the run dies with a bare traceback at **exit 1**, which
  the documented contract reserves for "findings at/above `--fail-on`".

⇒ The two walkers silently disagree about scope, which is the exact class this
repo spent three days closing elsewhere. **Not fixed.**

### CR-2 — `ok` after the fallback (OPEN, and it dissolves a separate question)

When semgrep rejects `_SEMGREPIGNORE_OFF`, the engine retries **without** it, so the
target's own `.semgrepignore` is honoured again. An ignore file can exclude one
vulnerable file while leaving another visible: `scanned > 0`, the scope guard
passes, status is `ok`, and `--fail-on` can exit 0 over an attacker-controlled
**partial** blind spot.

🔴 **This removes the need for a ratio heuristic.** The open `!decoy.py` item was
framed as "pick a threshold for how much shrink is suspicious." It is not a
threshold problem: **after the fallback we know by construction that scope is
target-controlled**, so `ok` is never justified there, at any ratio. The repo's own
rule applies directly — *"Fail safe. Always. Unproven ⇒ KEEP the finding."*

Suggested shape: after a fallback, either return `error`, or compare the **set** of
code files PRAETOR enumerated against the set semgrep reports opening, and refuse
`ok` if any is missing. The set comparison also covers partial shrink generally.

---

## 2. Semgrep's real default ignore set — measured, not documented

Semgrep's defaults are undocumented and version-dependent, so this was read off
behaviour. Method: one identical finding in a directory named after each of
`core.DEFAULT_SKIP_DIRS`, scanned with and without the ignore-disabling flag; the
difference is what semgrep drops on its own. Script:
`scratch only — reproduce with the recipe below.`

```
semgrep --config <rules> --json --quiet --no-git-ignore <tree>
semgrep --config <rules> --json --quiet --no-git-ignore --x-ignore-semgrepignore-files <tree>
# diff the paths.scanned sets
```

**Result, semgrep 1.172.0 — exactly 10 directories:**

```
.git  .hg  .svn  .tox  .venv  .yarn  build  dist  node_modules  vendor
```

`core.DEFAULT_SKIP_DIRS` has **30**. So emitting `--exclude` for all 30 (as the
current code does) removes SAST coverage from **26 directories semgrep had been
scanning**, including `out/`, `coverage/`, `target/`, `env/`, `site-packages/`,
`Pods/`, `__pycache__/`.

🔴 **The correct fix follows from what the flag actually broke.** The flag was meant
to disable `.semgrepignore` (attacker-controlled) and disabled semgrep's defaults
(not attacker-controlled) as a side effect. A genuine *restore* is **those 10 and
nothing more**. The other 20 are a new policy decision that was smuggled in under
the word "restore" and should be made deliberately or not at all.

⚠️ A hard-coded list of 10 is an enumeration coupled to a semgrep version — the
shape that has caused three separate defects here. **Pin it with a test that
performs the measurement above**, so a semgrep upgrade reddens a test instead of
silently shifting coverage.

---

## 3. The scan cost is an implementation artifact, not the price of the feature

Widening the secrets walk to vendored directories closed a real false clean but
measured **75× slower** end-to-end on a real production web repo. Profiled to find
out where it actually goes:

```
pure traversal (no file opens)     267,311 entries        2.06 s   <- free
wide walk (with opens)             111,605 files        790.35 s   <- 7.1 ms/file
read_text                                                0.606 ms/file
full scan (read + regex)                                 8.001 ms/file
  └─ regex share                                         92%   (~826 s projected)
```

Two costs, roughly equal, and **neither is "too many files"**:

1. **Per-file `open()`**, and PRAETOR opens every file **twice** — once in
   `walk_files` for the binary sniff, once in `read_text` at scan time.
2. **Regex**, 92% of scan time, mostly over minified bundles.

⚠️ Measurement caveat: the 0.606 ms/file read figure is **warm-cache** (those files
had just been walked) while the 790 s walk was **cold**. Cold/warm differs ~10×, so
per-open cost dominates more than the warm numbers suggest.

### 🔴 The better fix: select files by a PROPERTY, not by directory name

The threat is a credential **committed** to the repository. Installed dependencies
are not committed. Measured on the same repo:

| selection | files |
|---|---|
| current wide walk | **111,605** |
| git-tracked + untracked-but-not-ignored | **2,001** |
| …of those, inside `node_modules`/`vendor`/`dist`/`build` | **3** |

**56× fewer files, and the directory-name evasion stays closed** — a *committed*
`vendor/` directory is tracked, and tracked-ness is a property, not a list of 30
names. `.gitignore` cannot hide a tracked file either, so the scanned tree cannot
opt itself out.

**Three things this design must handle, or it trades one hole for another:**

1. **A gitignored `.env` holding live credentials is a real finding** that
   tracked-only selection would lose. High-risk basenames must be scanned
   regardless of ignore status: dotenv files, PEM/key material, SSH private-key
   names, and credential-store filenames. (Deliberately described rather than
   listed -- spelling those tokens out in this file trips PRAETOR's own EXFIL
   detector, self-scan 12 -> 13. Fix the fixture, never the rule; the real list
   belongs in code, where it is data rather than prose.)
2. **Not every target is a git repository.** Fall back to the directory walk.
3. 🔴 **Running `git` inside an untrusted tree can execute code.** `core.fsmonitor`
   in the target's own `.git/config` names a command git will run. That touches
   INVARIANT 1 directly. Any implementation needs at minimum
   `git -c core.fsmonitor= --no-optional-locks -C <target> ls-files`, plus
   `GIT_CONFIG_NOSYSTEM=1`, **and its own test in
   `tests/test_invariant_never_executes_target.py`** — the invariant file's header
   says every new backend widens the surface, and this is a new subprocess against
   attacker-controlled configuration.

---

## 4. What an external reviewer is worth here

Six adversarial passes over three rounds each found real defects — and each round's
*fix* introduced a new one, three times running. The external reviewer's first pass
found a CI-breaking test and a scope disagreement that all six missed.

⇒ **The two are not substitutes.** The adversarial passes found deep behavioural
holes (a `.semgrepignore` disabling an engine; a floor satisfied by a disabled
engine's walk). The external reviewer found ordinary engineering defects that a
session deep in its own model does not see. **A session reviewing its own fixes is
the weakest reviewer available, and this file is the evidence.**
