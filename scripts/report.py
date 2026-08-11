"""
PRAETOR reporting: human-readable text and machine-readable JSON.

The text report is plain ASCII by default (CI/log friendly). The JSON report is
a stable, documented schema for programmatic consumers (a factory apply-gate, a
CI job, another agent).
"""

from __future__ import annotations

import datetime
import json

from core import Severity

# 2.0 (2026-08-10): BREAKING for consumers that match on `rule_id`.
#   `claude-hook-autorun`  -> `agent-hook-autorun`
#   `claude-hook-autorun-dangerous` -> `agent-hook-autorun-dangerous`
# The detector stopped being Claude-specific (it now recognises Cursor, Windsurf,
# Cline and Roo hook configs), so a vendor-named id was actively misleading.
# Both ids are emitted from ONE ternary; they were renamed together, because
# renaming the bare id alone would have orphaned the HIGH-severity variant.
SCHEMA_VERSION = "2.0"

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


def _engine_status_block(meta: dict) -> list:
    lines = ["Engine status:"]
    for name, info in meta.get("engines", {}).items():
        status = info.get("status", "?")
        detail = info.get("detail", "")
        mark = {"ok": "[ran]", "unavailable": "[skipped]", "error": "[error]", "disabled": "[off]"}.get(status, "[?]")
        lines.append(f"  {mark:10} {name:8} {detail}")
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
    out.append(f"Files (text): {meta.get('file_count')}")
    out.append(f"PRAETOR ver : {meta.get('version')}")
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
        "limits": [ln.strip() for ln in LIMITS_TEXT.strip().splitlines() if ln.strip()],
    }
    return json.dumps(doc, indent=2, ensure_ascii=True)


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
