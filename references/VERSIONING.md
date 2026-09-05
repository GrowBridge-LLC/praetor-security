# PRAETOR — versioning policy

Semantic versioning, with the parts that are ambiguous for a *security scanner*
decided explicitly. A scanner's contract is not only its API: it is its **exit
codes**, its **JSON schema**, and what its silence means.

---

## Two version numbers, and they move independently

| Number | Where | What it describes |
|---|---|---|
| **tool version** | `pyproject.toml`, `praetor --version`, the git tag | the distribution |
| **`schema_version`** | the JSON report | the machine-readable output contract |

They are **not** kept in lockstep, deliberately. A rule addition bumps the tool
and not the schema. A new report key bumps both. Tying them would force a
meaningless bump on one side every time the other moved, and a consumer pinning
`schema_version` would start chasing noise.

`tests/test_version_consistency.py` asserts that every place the tool version
appears agrees. Nothing asserts the two numbers relate, because they should not.

---

## What each part means here

### MAJOR — a consumer must change something

- An exit code changes **meaning**. Not "a new situation now reaches exit 3" —
  that is a bug fix — but `3` coming to mean something other than *the scan was
  not measured enough to pass*.
- A JSON key is **removed or re-typed**. Renaming counts.
- A CLI flag is removed, or its default flips in a way that changes a verdict.
- The `NO FINDING` / `SAFE` vocabulary changes. It will not.

### MINOR — new capability, nothing breaks

- A new engine, rule, or detector family.
- A new JSON key. (Additive only — see the schema rule below.)
- A new CLI flag with a default that preserves prior behaviour.
- A suppression pass being **narrowed**, so more findings are reported.

🔴 **A suppression pass being WIDENED is never MINOR.** It makes the tool report
less, which is the failure this project exists to prevent. It is either a PATCH
that corrects a demonstrated false positive with a test naming it, or it does not
ship.

### PATCH — behaviour corrected, contract unchanged

- A false negative fixed. **Including one that makes a previously-passing scan
  fail.**
- A false positive removed, with a test pinning both directions.
- Performance, wording, documentation.

⚠️ **A fixed false negative can turn a green CI job red.** That is the tool
working, not a breaking change — the finding was always there and PRAETOR was
wrong to miss it. Under this policy that stays a PATCH, and the CHANGELOG entry
must say plainly that a gate may newly fail. Calling it MAJOR would create
pressure to withhold detection fixes, which is exactly backwards for a scanner.

---

## The schema rule

`schema_version` is `MAJOR.MINOR`.

- **MINOR** — keys added. A consumer on the older minor ignores them and keeps
  working.
- **MAJOR** — a key removed, renamed, or re-typed; or a **status word gaining a
  new member**, because a consumer matching on an exhaustive list will not
  recognise it.

🔴 **A consumer must treat an unrecognised engine status as a BLIND SPOT, never
as a pass.** That rule is in `core.py` beside the status constants and it is the
reason a new status word is a MAJOR bump: silence from a word you do not know is
not evidence of anything.

Every schema change gets a section in `README.md` naming what moved and what a
consumer must do.

---

## Release process

1. The gate is green — `bash tests/precommit.sh`, read the **exit code**.
2. The CHANGELOG has a section for the version, and it is not `Unreleased`.
3. Bump the version in every source (the consistency test names them).
4. Commit, then **tag** `vX.Y.Z`.
5. Push the tag. `publish.yml` fires on the tag and publishes via OIDC trusted
   publishing — no stored token.
6. Verify from a clean venv: `pip install praetor-security==X.Y.Z`, then
   `praetor --version`.

⚠️ **The tag is not optional decoration.** `.pre-commit-hooks.yaml` consumers
must reference an immutable `rev:`, and a branch is not immutable. Shipping a
pre-commit hook with no tags is shipping something nobody can use — which is
exactly what happened, and it went unnoticed because the file existed.

---

## Version history and the numbering decision

**`1.0.0` was never published.** It was a designation in `pyproject.toml` on a
public repository, with no tag and nothing on PyPI. Its CHANGELOG section says so
in its first line.

**The first installable release is `1.1.0`**, not a re-used `1.0.0`. Re-using it
would mean two different code states shared one version number — one of them
installable from git at that designation — and a version number that meant two
things is precisely the ambiguity this document exists to remove.

⚠️ **`1.1.0` contains changes that make previously-passing scans fail**, because
several false negatives were fixed: a payload split across two files is no longer
suppressed, a file the walker refuses now discloses itself, and a hostile agent
config inside `vendor/` is now reachable. Under the rule above those are PATCH-
class corrections; the release is MINOR because it also adds an engine and two
report sections. **The CHANGELOG says so at the top of the entry**, because a
team whose gate turns red deserves to find the reason in the first paragraph.
