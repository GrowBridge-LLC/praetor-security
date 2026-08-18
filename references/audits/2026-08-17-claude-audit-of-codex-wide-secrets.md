# Outside-reader audit — the git-aware wide secrets walk

**Auditor:** `claude-f` (Claude Code). **Builder:** `codex-f` (Codex Desktop),
session in `C:\projects\PRAETOR` from 2026-08-17 02:29, files last written 04:05.
**Subject:** the 13-file, 690-insertion uncommitted change in the working tree.
**Verdict: 🔴 BLOCK.** Do not land as written.

This is the outside read `AGENTS.md` requires: the change touches suppression and
gate-exit-code logic, the 🔴 sections of `CLAUDE.md`, so the builder's own review of
it does not count.

## The gate is green and the change is unsafe

```
== ALL GATES PASSED ==   (242 passed, 0 skipped; 8/8 gates; GATE_EXIT=0)
```

That is the finding, not a preamble to it. **A green gate is what this defect looks
like from inside.**

## F1 🔴 CRITICAL — a `.gitignore` in the scanned tree removes files from the secrets scan

`walk_files(..., git_aware=True)` is used for exactly one list — `secret_files` at
`scripts/praetor.py:456` — and `engine_secrets.scan()` reads **only** that list. So
Git's view of the target now decides the entire scope of the secrets engine.

Measured, same tree, same flags, no pipes in the measurement:

| tree | code | `--fail-on INFO` | secrets scanned |
|---|---|---|---|
| `terraform.tfvars` gitignored, holding an AWS secret key | **HEAD `a9b3e59`** | **exit 1** — reports `AWS Secret Access Key @ terraform.tfvars:2` | 3 |
| the same tree | **this change** | **exit 0 — clean** | 1 |

Reproduction:

```
git init t && cd t
printf 'terraform.tfvars\n' > .gitignore
printf 'aws_secret_access_key = "AKIA...EXAMPLEKEY"\n' > terraform.tfvars
git add .gitignore && git commit -m init
praetor . --engines secrets --fail-on INFO   # exit 0, and the key is not reported
```

**This is the class this repo has already named twice** — `[[scanned-tree-decided-the-scope]]`.
A file the attacker writes into the tree decides what the scanner examines. It was a
`.semgrepignore` last time. It is `.gitignore` now.

## F2 🔴 CRITICAL — the empty result is not distinguished from a measured scan

`_git_selected_relpaths()` returns `None` on any Git uncertainty and the caller then
walks safely. It returns an **empty set** when Git succeeds and reports nothing, and
the caller treats that as a completed selection.

```
printf '*\n' > .gitignore        # nothing tracked, everything ignored
praetor . --engines secrets --fail-on INFO
  ⇒ "secrets scanned 0", engine status ok, Findings (active): 0, EXIT 0
```

`--fail-on` does not rescue it. All four documented exit-3 routes are defeated at
once: the engine did not error, `scan_files` is non-zero so "0 files examined" is
false, the scope-disagreement check is SAST-only, and `secrets` reports `ok` and
counts as having measured.

⚠️ **The builder applied this exact principle one test lower down.**
`test_git_aware_selection_falls_back_to_the_wide_walk_on_git_uncertainty` carries the
docstring *"No Git repository is a scope condition, never a clean empty result."*
That is the right rule. It was applied to Git **failing** and not to Git **succeeding
with nothing** — `[[per-item-trust-never-sees-the-empty-set]]`, recurring verbatim.

## F3 🔴 The test does not miss the hole. It specifies it.

`tests/test_invariant_never_executes_target.py:301` builds a fixture containing
`ignored.py`, an ordinary-named gitignored file, and then asserts:

```python
assert {sf.relpath for sf in files} == {"tracked.py", "new.md", ".env.production"}, (
    "git-aware selection must omit ordinary ignored files but retain a high-risk "
    "ignored dotenv file; ...")
```

So this is a deliberate design decision, encoded and locked, not an oversight. It has
to be argued down rather than patched around — which is why this audit blocks instead
of proposing a one-line fix.

## F4 — the only mitigation is an enumeration, and it is short

`_HIGH_RISK_IGNORED_NAMES` / `_HIGH_RISK_IGNORED_EXTS` keep credential-*named*
ignored files in scope. `CLAUDE.md`: *"When a guard enumerates, ask what spelling of
the thing it misses."* It misses, at least: `terraform.tfvars`, `*.tfstate` (stores
credentials in plaintext), `local_settings.py`, `docker-compose.override.yml`,
`settings.local.json`, `.pgpass`, `.my.cnf`, `.htpasswd`, `.s3cfg`, `.boto`,
`kubeconfig`, `*.p12`, `*.pfx`, `*.jks`.

Extending the list is **not** the fix. The list is unbounded, and a scanner whose
recall depends on guessing filenames has the same shape as the defect above.

## What is right in this change, and should survive the rework

Stated so the rework does not throw it away:

- **The `core.fsmonitor` defence is correct and important.** `git ls-files` is a
  subprocess against an untrusted repository, and `.git/config` can name a command.
  Clearing it on the command line, dropping `GIT_*` injection vectors, and setting
  `GIT_CONFIG_NOSYSTEM` is the right shape, and the test asserts the argv rather than
  the resulting file list. That is the correct way to test the invariant.
- **The symlink boundary is now closed in all three selection paths** — direct target,
  normal walk, and Git selection — with `commonpath` plus `islink` refusal before any
  read. `os.walk(followlinks=False)` never covered linked *files*, and this does.
- **The Git-failure fallback fails safe**, and its test says why.
- **CR-1 is genuinely fixed.** `--exclude` has one meaning again: validated as a regex
  up front, used for PRAETOR's walks, applied to normalized SAST findings, and no
  longer handed to Semgrep's glob-only `--exclude`. Invalid regexes exit 2 instead of
  a traceback impersonating a findings exit.
- **CR-2 is genuinely fixed.** The ignore-flag fallback records `error`, never `ok`.
- **The Semgrep default-ignore set is now measured**, not copied from
  `DEFAULT_SKIP_DIRS`, with a live check that fails if an upgrade moves it.

## Required before this lands

1. **An empty Git selection must not be a scope.** Distinguish "Git listed nothing"
   from "Git listed files". Fail to the safe walk, or fail the run — never to silence.
2. **Decide the ignored-file question explicitly, and write the scope decision next to
   the code.** A gitignored file is where live credentials actually sit. If ordinary
   ignored files are dropped for cost, that is a recall-for-speed trade in a security
   scanner and must be stated as one, not left implied by a test assertion.
3. **A positive control**: a gitignored, ordinary-named file holding a detectable
   secret must be found, and the test must fail if it stops being found.
4. Re-run the measurement in F1 and quote the new numbers.

⇒ The cost of the walk this replaced was real — 111,605 files / 1,739 MB on one repo.
The rework should keep chasing that. It may not buy the speed with recall the operator
did not agree to give up.
