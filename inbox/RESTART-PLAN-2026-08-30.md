# PRAETOR — the restart plan, ordered

Written for the next session. `.local/AUDIT-STATE.md` is the live ledger and
outranks this file on any question of current state.
`inbox/MASTERPLAN-ASSESSMENT-2026-08-30.md` says where we ARE; this says what to
DO, in order.

---

## 0. DONE — what landed before this plan was written

```
origin/main = 2ffa0d9      canonical 0 dirty (-uall)     builder 0 unlanded (12 0)
```

- **The branch is merged and pushed.** F35, F36, F37, F38 and the restart record
  are all on `origin/main`. 13/13 gate checks green, `rc` read from `$?`.
- **The wiki is live** with a capabilities-and-outcomes landing page.
- **A pre-merge backup ref is on the remote**, under `backup/praetor/`. Its
  full name is not written here: the ref embeds a commit hash and our own
  secrets engine reads the result as a high-entropy string, correctly.
  Find it with `git ls-remote --heads origin 'backup/*'`.

---

## 1. DONE — the merge, recorded because its method is reusable

```bash
git push origin main                      # 3 held docs commits
# then, only after that lands:
git merge --no-ff codex-f/build           # F38 + the restart handoff, 4 commits
```

**MEASURED, not predicted: ZERO conflicts.**

```bash
git merge-tree $(git merge-base main codex-f/build) main codex-f/build | grep -c '^+<<<<<<<'
# -> 0
```

The builder's four commits touch `tests/test_output_atomicity.py` and
`inbox/HANDOFF-codex-f.md`; canonical's three touch `inbox/` documents only. I
first wrote this as a prediction from the touched paths and then ran the check,
because a prediction I told someone else to verify is one I should verify myself.
**Re-run it at merge time — it is cheap and the trees may have moved.**

⚠️ **The builder ran the same probe and agreed. That is NOT a second
measurement.** `merge-tree` is deterministic on its inputs; two readers of one
deterministic function over the same objects perform one computation twice. It
rules out a mistyped ref and says nothing about whether the merge is genuinely
clean. A real second measurement is performing the merge in a scratch worktree —
a history operation, so not while held.

**Then re-check CI, and read the step count, not the colour:**

```bash
gh api repos/<owner>/<repo>/actions/runs/<id>/jobs --jq '[.jobs[].steps|length]|add'
```

Zero steps is a ghost run from the Actions outage and means nothing. **The red on
`9cbbe4c` was real — 16 steps — and F38 is its fix.**

---

## 1a. 🔴 ITEM ONE — F39, the `aisec` hang. Assigned, not built.

**This blocked another project's 409 commits and forced Mike to run a push by
hand.** It is the top technical item.

**Mechanism, measured end to end:**

```
_apply_lexical_context   25 findings ->  7.03 s
                         50 findings -> 14.42 s
                        100 findings -> 26.69 s      ~0.28 s PER FINDING
one lexctx.context_of call           ->  0.310 s
```

`lexctx.context_of` calls `classify_lines(text, file_identity)` on **every**
call and `lexctx` caches nothing, so each finding re-classifies the whole file.
One 1.2 MB file with 787 findings ≈ **244 seconds**.

**Everything else exonerated by measurement:** 24 regex patterns <0.5 s, five
scan stages 0.15 s, per-line loop 0.39 s, `interpret()` 0.00 s, the other three
suppression passes 0.00 s. **Only `aisec` hangs because `_LEXCTX_ENGINES =
("aisec",)`.**

**Fix:** memoize the classification per file. **Do NOT change what
`classify_lines` returns** — a wrong label cached is worse than a slow correct
one. Key on text AND `file_identity`; the identity selects comment syntax, so
keying on text alone would classify a Markdown file as Python. Bound the cache.

**Also add a scan timeout that FAILS LOUDLY** rather than silently producing no
artifact. That turns any future hang into a legible error, and it is already an
acceptance gate on the App spec below.

---

## 2. SECOND — PRAETOR becomes mechanical (Mike's direct instruction)

*"make himself mechanical … install him as an app in github and make him part of
the custom workflow."*

**This closes an objection this lane raised against its own tool:** a scanner
someone must invoke is not a gate that fires on the event. It also fixes the
drift measured today — an App has **one** installed version, visible in the org,
while the copy that actually loads on this machine is 54-or-more commits behind
and missing F35 and F37.

### What already exists — measured, not assumed

| piece | state |
|---|---|
| installable | ✅ `pyproject.toml`, console script `praetor` |
| gate contract | ✅ `--fail-on` + exit codes 0/1/2/3 |
| CI tuning | ✅ `--exclude`, `--no-registry`, `--engines`, `--format json --out` |
| runtime | ✅ 27 s on this repo |
| a workflow that RUNS it | ❌ today's CI only TESTS PRAETOR |
| SARIF output | ❌ needed for the Security tab |

### Three levels, in build order

**L2 first — a reusable workflow** in this repo, called by each consumer in ~5
lines against a pinned ref. One place to update; no vendored copy to drift. This
is the structural fix, and it is one slice.

**L1 semantics** come free with it: `praetor . --fail-on HIGH`, non-zero fails
the build. Works on public and private, no licence cost.

**L3 later — SARIF.** `--format sarif` plus `upload-sarif` puts findings in the
Security tab and annotates PRs. ⚠️ **Free on public repos, billable on private.**
So: annotations on the 2 public repos, pass/fail plus a JSON artifact on the 12
private ones. That line needs no Advanced Security licences.

### 🔴 The gate the spec must carry BEFORE any build

Mike does not pay for metered per-call API usage. **`ANTHROPIC_API_KEY` outranks
the OAuth token in credential precedence**, so a workflow reading whatever key is
in the environment would violate that rule **by accident** and bill him.

⇒ **The design must state where compute runs and prove it cannot reach a metered
key.** Treat this as an acceptance gate, not a note. A build that satisfies every
functional requirement and fails this one is a BLOCK.

⚠️ **And an App does not replace push protection.** A workflow runs *after* the
push; push protection blocks a secret *before* it lands. Different controls. Do
not let a green PRAETOR job be cited as making the free one unnecessary.

---

## 3. THIRD — close the documentation defects the inventory found

Small, independent, no permission needed beyond the commit ruling.

- **`README.md:273` understates the port.** It says *"no detector has been ported
  yet"* and lists three things in `rust/`. There are four —
  `rust/praetor-core/src/secrets.rs` is 835 lines with a live differential
  contract. **The denial ships publicly.**
- **`ADR-001`'s binding-conditions table contradicts its own Amendment 2.**
  Condition 1 still says `aisec` ports first; Amendment 2 Part B reversed it to
  `secrets` first. A reader of the table alone gets the superseded plan.
- **Amendment 3** (a JSON crate for `aisec`) is RESEARCHED, NOT RULED ON. It is
  the next open decision on the port track.

---

## 4. FOURTH — the wiki, and it is gated twice

**STATE CHANGED — an earlier version of this section said the wiki had never been
initialized. Mike has since created the first page by hand on all 14 repos.**

Re-derived: `git ls-remote <alias>:...praetor-security.wiki.git` returns rc=0,
`refs/heads/master = 95b186b5`. Read-only clone shows **one page, `Home.md`, 39
bytes, GitHub's default welcome line** — nothing sensitive.

⚠️ **Verify a wiki by the REPOSITORY, never by `has_wiki`.** That flag was true on
all 14 repos while zero wikis existed, so it never distinguished the two states.

🔴 **The repo is PUBLIC. Writing a page publishes it irreversibly.** Capabilities
and outcomes only — never mechanism, never internal topology, never another
project's name. No page without Mike's explicit per-page approval.

⚠️ **§4 is blocked on the KB question in §0.** If "the KB is superseded" includes
`references/kb/`, note that **three of thirteen precommit checks depend on it**
and it is machine-readable by design — its generator exists to make staleness
*detectable rather than trusted*. A wiki page cannot do that job. **Do not remove
a gating subsystem on a relayed instruction.**

---

## 5. What NOT to do — closed questions, do not re-open

- **Do not harden PRAETOR** to protect consumers from their own staleness or gate
  defects. Reports already carry `meta.timestamp`, `meta.target`, `meta.version`.
- **Do not touch another project's files.** Reading across is fine; writing is
  not, however correct the diagnosis.
- **Do not ask for the push guard to be narrowed.** The candidate narrowing was
  measured WEAKER than what it replaces, and bundled short options were never
  blocked by any version.
- **Do not regenerate `SELF-SCAN-BASELINE.json`** to reflect an improvement.
- **Do not chase the tip in any handoff.** Cite the parent and tell the reader to
  re-derive.

---

## 6. What is NOT verified

- Whether "the KB" means ours. **The single largest unknown in this plan.**
- Any CI result whose step count was not read.
- That the three doc defects in §3 are the only stale claims. I checked the Rust
  and port-order statements specifically, not every document.
- The exact drift of the installed skill. **"54 or more"** — a lower bound. The
  ref another lane and I both read had been written by that lane's own `git
  fetch`, so two readings of it are not two measurements.
