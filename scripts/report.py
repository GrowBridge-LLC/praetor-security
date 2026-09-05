"""
PRAETOR reporting: human-readable text and machine-readable JSON.

The text report is plain ASCII by default (CI/log friendly). The JSON report is
a stable, documented schema for programmatic consumers (a factory apply-gate, a
CI job, another agent).
"""

from __future__ import annotations

import datetime
import json

import capability

from core import (Severity, engine_blind_spots, ENGINE_OK, ENGINE_NOT_APPLICABLE,
                  ENGINE_DISABLED, ENGINE_UNAVAILABLE, ENGINE_ERROR)

# 2.0 (2026-08-10): BREAKING for consumers that match on `rule_id`.
#   `claude-hook-autorun`  -> `agent-hook-autorun`
#   `claude-hook-autorun-dangerous` -> `agent-hook-autorun-dangerous`
# The detector stopped being Claude-specific (it now recognises Cursor, Windsurf,
# Cline and Roo hook configs), so a vendor-named id was actively misleading.
# Both ids are emitted from ONE ternary; they were renamed together, because
# renaming the bare id alone would have orphaned the HIGH-severity variant.
# 🔴 BUMPED TO 3.0 (2026-08-13). TWO breaking wire changes had shipped under an
# unchanged "2.0", so a consumer could not tell the old wire from the new one:
#   * engine status `unavailable` was SPLIT -- "nothing to scan" became
#     `not-applicable`, leaving `unavailable` to mean only "could not scan". Its
#     own commit message said "BREAKING for JSON consumers keying on unavailable"
#     and the version did not move.
#   * `meta.secret_file_count` was added, and `meta.file_count` stopped covering
#     the scope that produces secrets findings -- so a consumer treating
#     `file_count == 0` as "nothing was scanned" is now wrong.
# ⇒ A version that does not move across a breaking change is the same defect this
# repo fixed in its generated Unicode table: one label for two incompatible facts.
#: 🔴 Bump on ANY change to the set of possible `status` words, same precedent
#: as the 2.0 rule_id rename and the 3.0 unavailable/not-applicable split — a
#: consumer doing exhaustive status matching breaks silently otherwise. 4.0
#: adds `partial-parse` (core.ENGINE_PARTIAL_PARSE); see README.md's
#: "schema_version 4.0" section.
#: 4.1 adds the top-level `chains` array (attack-chain correlation, see
#: scripts/chains.py). MINOR, not major, and the distinction is the point: it is
#: purely additive, no existing key changed meaning, and a consumer reading only
#: `findings`/`filtered` is unaffected. A status-word change breaks exhaustive
#: matching; a new sibling array cannot.
#:
#: 4.3 adds `meta.scope.walked_nothing` -- the whole-scan measurement that says
#: no file was opened. It is what the exit code's `3` and SARIF's
#: `executionSuccessful: false` are both computed from, exposed so a consumer
#: does not have to re-derive a safety question. Additive; a 4.2 consumer
#: ignores it.
#:
#: 🔴 THE KEY SHIPPED BEFORE THIS NUMBER MOVED, AND THAT IS THE DEFECT WORTH
#: RECORDING. `walked_nothing` was added in commit 3e8bc0f while
#: `SCHEMA_VERSION` stayed "4.2", so for a few hours two different reports both
#: claimed to be 4.2 and one of them had a key the other did not. A downstream
#: consumer had already proposed pinning 4.2 as its ingest contract. Nothing in
#: the gate catches this: `test_the_schema_version_is_major_minor` checks the
#: SHAPE of the number, and no test relates a new report key to a bump.
#: ⇒ **Adding a key to the report means editing this line in the same commit.**
SCHEMA_VERSION = "4.3"

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

LIMITS_TEXT = """\
PRAETOR is a high-signal aid, not a guarantee of security. Known limits:
  * Static analysis only. It never executes the target, so it cannot find
    runtime-only, logic, or business-authorization flaws.
  * Secret detection uses provider patterns + entropy. Denylists are never
    exhaustive; novel/rotated formats and cleverly obfuscated secrets can be
    missed, and entropy heuristics trade recall for precision. A "clean" secret
    result is not proof there are no secrets.
  * SAST coverage equals the active Semgrep ruleset. Rules are good but finite;
    absence of a finding is not absence of a vulnerability.
  * SCA only sees declared dependencies in supported lockfiles, checked against
    known-advisory databases. Zero-days and unpinned/transitive gaps remain.
  * AI-security detection is pattern-based. A determined adversary can phrase an
    injection to evade regexes; treat this engine as raising the cost of attack,
    not closing it.
  * Treat every finding as a lead to verify, and every clean result as "nothing
    matched these rules," never as "this code is safe."
"""


#: 🔴 Any status word NOT listed here renders as [BLIND], never as [?] or
#: [skipped]. A benign-looking mark on an unrecognised status is how a blind
#: spot reads as a clean engine -- the same failure the exit code carried.
#: `unavailable` was rendered "[skipped]" until 2026-08-12, which reads as
#: "nothing to do here" for a state that actually means "could not look".
#: ⚠️ ENGINE_PARTIAL_PARSE (core.py) has NO entry here, deliberately. It is a
#: full malfunction for text-report/gate-4b purposes, same as ENGINE_ERROR --
#: only meta.engines[*].detail carries the more specific diagnosis. Giving it
#: its own mark here was tried and reverted: it opted the status out of the
#: "[BLIND]" fail-safe below, which is exactly the failure this dict's own
#: warning describes.
_STATUS_MARKS = {
    ENGINE_OK: "[ran]",
    ENGINE_NOT_APPLICABLE: "[n/a]",
    ENGINE_DISABLED: "[off]",
    ENGINE_UNAVAILABLE: "[BLIND]",
    ENGINE_ERROR: "[error]",
}


def _engine_status_block(meta: dict) -> list:
    engines = meta.get("engines", {})
    lines = ["Engine status:"]
    for name, info in engines.items():
        status = info.get("status", "?")
        detail = info.get("detail", "")
        mark = _STATUS_MARKS.get(status, "[BLIND]")
        lines.append(f"  {mark:10} {name:8} {detail}")
    blind = engine_blind_spots(engines)
    if blind:
        lines.append("")
        lines.append("  🔴 SCAN DEGRADED -- " + ", ".join(n for n, _, _ in blind) +
                     " did not measure. Their zero is not evidence of anything.")
    return lines


def render_text(result: dict, meta: dict, redacted: bool = True) -> str:
    active = result["active"]
    filtered = result["filtered"]
    summary = result["summary"]

    out = []
    out.append("=" * 74)
    out.append("  PRAETOR  --  multi-engine security analysis report")
    out.append("=" * 74)
    out.append(f"Target      : {meta.get('target')}")
    out.append(f"Scanned at  : {meta.get('timestamp')}")
    # 🔴 TWO SCOPES, TWO NUMBERS. The secrets engine deliberately walks wider than
    # the others (core.SECRETS_SKIP_DIRS vs DEFAULT_SKIP_DIRS), because a
    # credential in `vendor/` is disclosed and a CVE there mostly is not yours.
    # Printing ONE count over findings from BOTH scopes is exactly the defect that
    # made a `vendor/` finding look like it came from a tree nobody scanned -- so
    # when the two differ, say both.
    _fc = meta.get("file_count")
    _sfc = meta.get("secret_file_count")
    if _sfc is not None and _sfc != _fc:
        out.append(f"Files (text): {_fc}  (secrets scanned {_sfc}, incl. vendored/build dirs)")
    else:
        out.append(f"Files (text): {_fc}")
    _nfc = meta.get("nul_text_file_count")
    if _nfc:
        out.append(f"NUL-bearing text files: {_nfc} (retained for text scanning)")
    out.append(f"PRAETOR ver : {meta.get('version')}")
    # 🔴 A SUPPRESSION WITH NO STATED REASON IS NOT TRIAGE, and skipped
    # directories were the one suppression in this tool that said nothing at all.
    # The count is printed whenever code went unread, so a reader can tell a real
    # clean scan from a scan that never opened the code.
    _scope = meta.get("scope") or {}
    _skipped_code = _scope.get("skipped_code_files", 0)
    if _skipped_code:
        _dirs = _scope.get("skipped_dirs") or {}
        _worst = ", ".join(
            f"{d}/ ({n})" for d, n in sorted(_dirs.items(), key=lambda kv: -kv[1])[:4]
        )
        out.append(
            f"Scope       : {_skipped_code} code file(s) NOT read -- inside skipped "
            f"dirs: {_worst}"
        )
        out.append(
            "              (build/dependency dirs are skipped by default; for a "
            "DISTRIBUTED artifact use --no-default-skips)"
        )
    _unread = _scope.get("unreadable_files", 0)
    if _unread:
        out.append(
            f"Scope       : {_unread} file(s) selected but NOT DECODABLE -- a blind "
            "spot, not a clean file"
        )
        for _u in (_scope.get("unreadable_sample") or [])[:3]:
            out.append(f"              {_u.get('file')}: {_u.get('error')}")
    if _scope.get("default_skips_disabled"):
        out.append("Scope       : --no-default-skips ACTIVE -- build/dependency dirs were read")
    out.append("")
    out.extend(_engine_status_block(meta))
    out.append("")
    counts = "  ".join(f"{s.label}={summary.get(s.label,0)}" for s in _SEV_ORDER)
    out.append(f"Findings (active): {result['total_active']}    {counts}")
    out.append(f"Filtered (likely FP / low-signal, shown separately): {result['total_filtered']}")
    out.append("")

    if not active:
        out.append("No active findings at or above the reporting threshold.")
        out.append("(Read the LIMITS section below -- 'nothing matched' is not 'proven safe'.)")
        blind = engine_blind_spots(meta.get("engines", {}))
        if blind:
            # The emptiest result is the one most likely to be misread, so the
            # caveat goes HERE as well as in the status block above -- a reader
            # who skips to "No active findings" must not be able to miss it.
            out.append("")
            out.append("🔴 ...but this scan was NOT fully measured: " +
                       ", ".join(f"{n} [{s}]" for n, s, _ in blind) + ".")
            out.append("   Zero findings from an engine that never ran is not a clean result.")
    else:
        out.append("-" * 74)
        out.append("  FINDINGS  (most dangerous first)")
        out.append("-" * 74)
        for idx, f in enumerate(active, 1):
            loc = f"{f.file}:{f.line}" + (f"-{f.end_line}" if f.end_line and f.end_line != f.line else "")
            out.append("")
            out.append(f"[{idx}] {f.severity.label}/{f.confidence.label}  ({f.engine})  {f.title}")
            out.append(f"     rule    : {f.rule_id}   category: {f.category}")
            out.append(f"     location: {loc}")
            if f.cwe:
                out.append(f"     cwe     : {f.cwe}")
            if f.owasp:
                out.append(f"     owasp   : {f.owasp}")
            if f.corroborated_by:
                out.append(f"     corroborated by: {', '.join(f.corroborated_by)}")
            if f.description:
                out.append(f"     detail  : {f.description}")
            if f.snippet:
                out.append(f"     code    : {f.snippet}")
            if f.fix:
                out.append(f"     fix     : {f.fix}")
            if f.references:
                out.append(f"     refs    : {f.references[0]}")

    if filtered:
        out.append("")
        out.append("-" * 74)
        out.append("  FILTERED  (suppressed with rationale -- audit these, do not ignore blindly)")
        out.append("-" * 74)
        for idx, f in enumerate(filtered, 1):
            out.append(f"  ({idx}) {f.severity.label}/{f.confidence.label} {f.title} @ {f.file}:{f.line}")
            out.append(f"        reason: {f.filter_reason}")

    prof = result.get("capability_profile") or {}
    if prof:
        out.append("")
        out.append("-" * 74)
        out.append("  AGENT CAPABILITY PROFILE  (what opening this repo would authorise)")
        out.append("-" * 74)
        out.append("  " + capability.summary_line(prof))
        out.append("")
        for key, dim in prof.items():
            mark = "YES" if dim["status"] == "present" else " no"
            count = ""
            if dim["evidence_count"]:
                # The split is shown, never subtracted. Twelve production
                # configs and one test fixture used to render identically.
                fixtures = dim.get("test_or_example_evidence_count", 0)
                extra = f", {fixtures} in test/example paths" if fixtures else ""
                count = (f"  [{dim['worst_severity']}] "
                         f"({dim['evidence_count']} finding(s){extra})")
            out.append(f"  [{mark}] {key.replace('_', ' ')}{count}")
            if dim["status"] == "present":
                for ex in dim["examples"]:
                    out.append(
                        f"          - {ex['severity']}/{ex['confidence']} "
                        f"{ex['rule_id']} @ {ex['file']}:{ex['line']}"
                    )
        out.append("")
        out.append("  A capability reads PRESENT or no -- never SAFE. 'no' means no rule")
        out.append("  matched it, which is not the same as the repository not having it.")

    chain_hits = result.get("chains") or []
    if chain_hits:
        out.append("")
        out.append("-" * 74)
        out.append("  ATTACK CHAINS  (findings that COMPOSE -- verify, not proof)")
        out.append("-" * 74)
        out.append("  Each chain below is a hypothesis that separate findings form one")
        out.append("  path. It does not assert the path is reachable. Nothing here")
        out.append("  suppresses or re-scores any finding above; chains only add.")
        for idx, c in enumerate(chain_hits, 1):
            out.append("")
            out.append(f"[C{idx}] {c['severity']}  {c['title']}")
            out.append(f"     chain   : {c['chain_id']}")
            # Proximity and scope are printed because they ARE the evidence for
            # the severity. "same-file" means the links share one file;
            # "same-tree" means only that both appear somewhere in the scan. A
            # reader who cannot tell those apart cannot check the claim.
            out.append(f"     basis   : {c['proximity']} -- {c['scope']}")
            out.append(f"     why     : {c['why_it_composes']}")
            out.append(f"     verify  : {c['what_to_verify']}")
            for link in c["links"]:
                shown, total = link["shown"], link["total"]
                more = f" (showing {shown} of {total})" if total > shown else ""
                out.append(f"     link    : {link['link']}{more}")
                for ref in link["findings"]:
                    out.append(
                        f"                - {ref['severity']}/{ref['confidence']} "
                        f"{ref['rule_id']} @ {ref['file']}:{ref['line']}"
                    )

    out.append("")
    out.append("-" * 74)
    out.append("  LIMITS  /  RESIDUAL RISK")
    out.append("-" * 74)
    out.append(LIMITS_TEXT)
    out.append("=" * 74)
    return "\n".join(out)


def render_json(result: dict, meta: dict) -> str:
    doc = {
        "schema_version": SCHEMA_VERSION,
        "tool": "praetor",
        "meta": meta,
        "summary": {
            "active": result["total_active"],
            "filtered": result["total_filtered"],
            "by_severity": result["summary"],
        },
        "findings": [f.to_dict() for f in result["active"]],
        "filtered": [f.to_dict() for f in result["filtered"]],
        # Additive: a consumer reading only `findings`/`filtered` is unaffected,
        # which is why this is a MINOR schema bump (4.0 -> 4.1) rather than the
        # breaking bump a changed status word needed. `chains` is always present
        # -- an empty list means no chain matched, which (like an empty findings
        # list) is NOT a statement that the tree is safe.
        "chains": result.get("chains") or [],
        "capability_profile": result.get("capability_profile") or {},
        "limits": [ln.strip() for ln in LIMITS_TEXT.strip().splitlines() if ln.strip()],
    }
    return json.dumps(doc, indent=2, ensure_ascii=True)


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
