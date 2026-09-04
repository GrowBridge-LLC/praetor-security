# `_scan_mcp` Rust port — independent adversarial review, 2026-09-04

**Status of the port as of this review: differential-tested against its own
42-case corpus (`references/differential/mcp.jsonl`), passing end to end
(`py -3.14 tests/differential/run_differential.py` exits 0, `python == rust
== committed contract`). Not wired into the live CLI** — `rust/praetor/src/main.rs`
still refuses to scan anything and exits 2, unchanged. Two real, empirically
confirmed parity gaps below must be closed before this port is ever wired into
anything that runs against untrusted target repos — landing the differential
infrastructure now, with these documented, is a deliberate choice: rushing a
fix under time pressure has repeatedly cost this project more than it saved
(see this repo's own audit history), and nothing here is live-exposed today.

## Method

A 5-step pipeline (design → build corpus → Rust port → wire differential gate
→ independent adversarial review) produced the port. The review agent had no
context from the earlier four steps and verified everything empirically —
building two scratch crates outside this repo that call the real
`praetor_core::aisec::scan_mcp` and the real `engine_aisec._scan_mcp` side by
side, not just reading code and reasoning about it.

## HIGH — Finding 1: deep JSON nesting silently blinds the Rust scanner

**A manifest with a real, dangerous MCP server entry plus unrelated JSON
nested past ~127 levels anywhere in the document causes the Rust port to
return zero findings for the whole file — including the real threat.**
`serde_json`'s default bounded recursion depth (128) makes the entire
document fail to parse, hitting `_scan_mcp`'s fail-safe `Err(_) => return
Vec::new()`. Python's `json.loads` at the same depths (verified to depth
1500) never fails. Empirically confirmed:

```
depth=126 -> rule=mcp-server-autostart-remote line=1  (Rust: correctly flags it)
depth=127 -> NO FINDINGS                              (Rust: silently blind)
depth=200 -> NO FINDINGS                              (Rust: silently blind)
```

None of the 42 corpus cases nest beyond ~4 levels, so this was entirely
unexercised. This is a real, trivially attacker-reachable evasion primitive
specific to which implementation ends up deployed — exactly the "goes quiet
under exactly the conditions an attacker creates" failure class this
project's own CLAUDE.md names as the central risk, except here it's an
unintended side effect of a parser-limit mismatch nobody decided on, not a
suppression decision.

**Not fixed in this pass.** Fixing it correctly needs a real design decision,
not a quick patch: either raise `serde_json`'s recursion limit via the
`unbounded_depth` feature (which requires a stack-guard crate like
`serde_stacker` to avoid reintroducing genuine stack-overflow risk — a new
dependency needing its own ADR-001-style authorization, the same process
Amendment 3 went through for `serde_json` itself), or add a disclosed
COVERAGE-style finding on the Rust side specifically for "this file could not
be fully parsed, results may be incomplete" so the gap is at least visible
rather than silent. Either approach changes the port's finding set and needs
its own corpus cases and differential-contract handling, not a rushed edit.

## HIGH — Finding 2: a lone/unpaired UTF-16 surrogate escape has the same effect

**Any JSON string anywhere in the manifest containing a single unpaired
`\ud800`-style escape drops the whole file in Rust, not in Python.** Python's
`json.loads` accepts CPython's documented lone-surrogate leniency and
produces the real finding; `serde_json::from_str` returns
`Err("unexpected end of hex escape")`, so `_scan_mcp` returns nothing.
Same failure class as Finding 1 (a narrower parser-acceptance boundary in
Rust causing a total, silent parse failure) — arguably cheaper for an
attacker to trigger (one malformed escape anywhere in the file, vs. 127
levels of nesting) — and, like Finding 1, entirely unexercised by the
corpus (zero cases contain a `\u` escape at all).

**Not fixed in this pass**, same reasoning as Finding 1 — this needs its own
considered decision (pre-validating manifest text for lone surrogates with a
lenient fallback path, or another approach), not a rushed patch.

## MEDIUM — Finding 3: non-string `command`/`args` values diverge in content

Python's `str(cfg.get("command", ""))` stringifies *any* JSON value (numbers,
bools, null, nested objects) if present but not a string; the Rust port does
the same via a `json_scalar_str` helper, and the two representations agree in
every construction tested — **except** for integers outside safe
`i64`/`u64`/`f64`-exact range, where `serde_json::Number::to_string()` loses
precision and switches to scientific notation (e.g. a 20-digit exact integer
`command` renders as `"1e+20"` in Rust vs. the exact digits in Python). In
every case tested this didn't flip a `rule_id` (the only thing the
differential gate checks), so it's a content-level gap, not an
identity-level one — but the corpus has zero cases with any non-string
`command`/`args` element, so the space is unexercised beyond the six
constructions the review tried by hand. Lower urgency than Findings 1-2;
worth a corpus case and a corrected doc comment (the current one in
`aisec.rs` claims numbers/bools/null get "a correct rendering," which
undersells the big-integer precision gap) as a follow-up, not a blocker.

## Cleared

- **Server name containing an embedded quote** — both implementations
  independently fall back to line 1 for the same underlying reason (a
  pre-existing Python quirk, faithfully reproduced, not a new divergence).
- **Basename path-separator handling** (`os.path.basename` is
  platform-dependent on `/` vs `\`; the Rust port always splits on both) —
  self-disclosed in the port's own comment, low real-world impact, not
  exercised by the corpus but not believed to matter for how `rel` values
  actually get constructed upstream.
- **Panics on attacker-controlled input** — none found. Every `.unwrap()`/
  `.expect()`/`panic!` in the file is confined to either hardcoded static
  regex compilation (via `OnceLock`, never attacker-influenced) or the
  differential corpus loader (`pub mod differential`, only ever runs against
  the trusted checked-in corpus file, never a scanned target). `scan_mcp`
  itself is fail-safe throughout, matching Python's
  `except (ValueError, RecursionError): return []` at every branch.
- **The never-execute-the-target invariant** — confirmed clean. No
  `Command`/`process`/`spawn`/`exec`/filesystem-path-following of any kind in
  the scanning path; purely structural JSON parsing and textual regex
  matching.
- **Uncached per-server regex compilation** (LOW/informational, not a
  correctness bug) — `mcp_line_of` compiles a fresh `Regex` per server name
  instead of caching, measurably slow in debug builds (5.25s vs Python's
  0.44s on a 3000-server manifest) though faster than Python in release
  builds (220ms vs 437ms). Not security-relevant; a real but low-priority
  cleanup.

## What must happen before this port is ever wired into a live scan path

1. Findings 1 and 2 get a real, considered fix — not a rushed patch — and new
   corpus cases proving the fix, following the same design → build → verify
   discipline this whole port used.
2. Finding 3 gets at least one corpus case so the gate can see the
   divergence class going forward, and the misleading doc comment in
   `aisec.rs` gets corrected.
3. Until then, `rust/praetor/src/main.rs` continues to refuse to scan, as it
   does today — that refusal is the actual safety mechanism protecting
   against these two gaps mattering in practice right now.
