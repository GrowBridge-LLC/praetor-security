# `LF-2` — malfunction vs unavailable at the default-config boundary

> ✅ **STATUS: IMPLEMENTED AND TESTED, 2026-08-22.** Landed in `0930947`. The hole
> described below is CLOSED on `main`.
>
> ↩️ **This header read "AUTHORIZED, NOT IMPLEMENTED. The hole it closes is LIVE on
> `main`" until 2026-08-22, and by then it had been false for some time.** The row
> below told the reader to run `grep -rn NON_MALFUNCTION_STATUSES scripts/` and
> expect nothing; that grep returns three hits in `core.py` and one in `praetor.py`.
> A stale "not built yet" claim is the exact converse of a stale "this is enforced"
> claim, and it costs the same way: a session read this file, believed it, and came
> within one post of assigning a builder work that was already finished. **When a
> feature ships, sweep every document that asserts its old status — not only the
> one you happen to be editing.**
>
> | | |
> |---|---|
> | Authorized | 2026-08-12, in the operator's own words: *"sounds good agreed"* |
> | Precondition attached | *"apply only after both adversarial audits report"* |
> | Precondition status | ✅ **MET** — both passes reported 2026-08-12 (`references/audits/2026-08-12-independent-audit.md`) |
> | Implemented | ✅ **Yes**, `0930947`. `core.py` defines `NON_MALFUNCTION_STATUSES` and `engine_malfunctions`; `praetor.py`'s report-only branch returns 3 on a malfunction |
> | Blast radius | **Behaviour change** — report-only runs that today exit 0 with a dead engine would exit 3 |
>
> **Why this file exists in the repo rather than a handoff.** This design was
> agreed, written up, and then lost at a context-compaction boundary; it survived
> only in a session scratchpad that dies at session close, and in a superseded
> memory file no future session had reason to open. A pre-close audit of the
> conversation transcript is what found it. Memory does not cross a machine
> boundary and scratch does not survive a session — **a commit is the only channel
> that survives both**, which is why it is here.
>
> ⚠️ **Do not treat this document as a decision record for the exit-code contract
> generally.** It predates the 2026-08-13 gate work, which added a file-count floor
> and rejected `--exclude ""`. Re-derive the table below against current `main`
> before implementing; the reasoning is sound, the surrounding code has moved.
>
> **The hole this closed, in one line:** `praetor .` in CI with `if rc != 0`, no
> `--fail-on`, and a dead SAST engine used to be green. It now exits 3, and six
> tests in `tests/test_exit_code_never_hides_a_blind_spot.py` hold that behaviour —
> including the carve-out that an *unavailable* runtime must NOT fail a report-only
> run. They assert exit codes rather than function names, which is why a search for
> the implementation's identifiers does not find them.

---


Authorized by Mike 2026-08-12 ("sounds good agreed"). **Apply only after both
adversarial audits report**, and fold their findings into the same change so the
audited tree and the shipped tree do not diverge.

## The decision

`--fail-on` answers *"is this code clean?"*. An engine dying answers *"did the
tool do its job?"*. Hanging the degraded check off `--fail-on` made the second a
sub-case of the first — the same category error as the original fail-open.

`LF-2` says *"an enabled engine reporting **error** yields exit 3, never 0, in the
default configuration."* **`error`, not `unavailable`.** The current code treats
those two words as synonyms at exactly the boundary where they differ.

| engine state | default (no `--fail-on`) | with `--fail-on` |
|---|---|---|
| `ok` / `not-applicable` / `disabled` | 0 | 0, or 1 by findings |
| `unavailable` | **0** — report already says `[BLIND]` | **3** |
| `error` | **3** ← the change | **3** |

**Why `unavailable` is carved out of the default case, deliberately:** the runtime
being absent is the normal state of most Windows boxes — it is why the
native/WSL/Docker fallback exists at all. Returning 3 on every default run there
makes the tool look broken, earns a `|| true`, and destroys the signal. That is
the same reasoning the PRD applied to the size cap. A malfunction is abnormal
*anywhere*; a missing runtime is a knowable environment fact.

⚠️ **This carve-out is the mechanism's safety scope, not a property of the
mechanism** — write it down next to the code, per CLAUDE.md.

## `scripts/core.py`

```python
#: Statuses describing a NORMAL execution -- the run itself did not malfunction,
#: whatever it did or did not find. 🔴 An ALLOWLIST for the same reason
#: GATE_TRUSTED_STATUSES is one: an unrecognised status means a state nobody here
#: considered, and the fail-safe reading of that is "something went wrong."
#:
#: ⚠️ ENGINE_UNAVAILABLE is listed here DELIBERATELY, and it is the one entry that
#: is a judgement rather than a definition. A missing semgrep runtime is the
#: normal state of most Windows boxes; exiting non-zero on every default run there
#: would earn the tool a `|| true` and destroy the signal entirely. It still
#: BLOCKS under --fail-on (see GATE_TRUSTED_STATUSES) -- the operator asked for a
#: gate and does not have one. Without --fail-on they asked for a report, and the
#: report says [BLIND] in two places.
NON_MALFUNCTION_STATUSES = frozenset({
    ENGINE_OK, ENGINE_NOT_APPLICABLE, ENGINE_DISABLED, ENGINE_UNAVAILABLE,
})


def engine_malfunctions(engine_meta: dict) -> list:
    """Engines that LAUNCHED AND BROKE -- a failure of the run, not of the target.

    Same [(name, status, detail), ...] shape as engine_blind_spots(). Non-empty
    means the tool did not do its job, which is true independently of whether the
    caller asked to gate on findings.
    """
    bad = []
    for name in sorted(engine_meta or {}):
        info = engine_meta[name] or {}
        status = info.get("status", "")
        if status not in NON_MALFUNCTION_STATUSES:
            bad.append((name, status or "?", info.get("detail", "")))
    return bad
```

## `scripts/praetor.py` — exit block

```python
    if args.fail_on:
        threshold = core.Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in gate_findings):
            return 1
        blind = core.engine_blind_spots(engine_meta)
        if blind and not args.allow_degraded:
            <existing stderr block>
            return 3
    elif not args.allow_degraded:
        # 🔴 No --fail-on means "do not fail me on FINDINGS". It does not mean
        # "do not tell me the tool broke". An engine that launched and died is a
        # malfunction of the run, and `praetor . && deploy` must not proceed on
        # one. Scoped to malfunctions, NOT to every blind spot -- see
        # core.NON_MALFUNCTION_STATUSES for why `unavailable` is excluded here.
        broken = core.engine_malfunctions(engine_meta)
        if broken:
            sys.stderr.write("praetor: ENGINE MALFUNCTION -- the scan did not complete.\n")
            for name, status, detail in broken:
                sys.stderr.write(f"  [{status}] {name}: {detail}\n")
            return 3
    return 0
```

## Tests to add — `tests/test_exit_code_never_hides_a_blind_spot.py`

Each needs its mutation checked (break the real code, confirm the NAMED test reds):

1. `test_errored_engine_fails_without_fail_on` — broken engine, **no `--fail-on`** ⇒ 3.
   *This is the hole open on `main` today: `praetor .` + `if rc != 0` is green with a dead engine.*
2. `test_unavailable_runtime_does_not_fail_a_report_only_run` — KEEP direction ⇒ 0,
   and assert `[BLIND]` is still in the report so the carve-out is visible, not silent.
3. `test_unavailable_runtime_still_blocks_a_gated_run` — with `--fail-on` ⇒ 3 (regression pin).
4. `test_unknown_status_is_a_malfunction_by_default` — status `"partial"`, no
   `--fail-on` ⇒ 3. The allowlist's fail-safe direction, same guard shape that was
   the ONLY test to catch the denylist mutation last time.
5. `test_allow_degraded_suppresses_the_default_malfunction_exit` ⇒ 0.

## Docs to update in the same commit

`praetor.py` module docstring (exit-code table) · `README.md` (exit codes para +
`--allow-degraded` row) · `SKILL.md` · `CHANGELOG.md` — and state plainly that
**exit 3 without `--fail-on` is a behaviour change** for anyone whose CI runs
PRAETOR report-only and tests `rc != 0`. That is the whole point of the change,
so it must be the loudest line in the entry, not a footnote.

## Then

Re-run `bash tests/precommit.sh` (all 8), re-run the live matrix, and report the
`LF-2` conformance change back to the coordination channel so the downstream spec review is not working from a stale reading.
