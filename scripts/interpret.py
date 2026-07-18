"""
PRAETOR interpretation layer -- what turns N scanners into one coherent report.

Responsibilities:
  * DEDUP across engines: findings describing the same issue at the same location
    collapse into one, keeping the highest severity and recording which engines
    corroborated it (corroboration raises confidence).
  * RANK: unified severity order (CRITICAL -> INFO), then confidence, then engine.
  * FALSE-POSITIVE FILTERING: low-signal findings are not deleted -- they are
    moved to a separate bucket WITH A RATIONALE so a reviewer can audit the
    suppression. Honest triage, not silent dropping.
"""

from __future__ import annotations

from core import Finding, Severity, Confidence

# engine priority when severity+confidence tie (higher = surfaced first)
_ENGINE_RANK = {"sca": 4, "sast": 3, "secrets": 2, "aisec": 1}


def _sort_key(f: Finding):
    return (
        -int(f.severity),
        -int(f.confidence),
        -_ENGINE_RANK.get(f.engine, 0),
        f.file,
        f.line,
    )


def dedup(findings: list) -> list:
    """Merge findings that share a dedup_key. Cross-engine corroboration raises confidence."""
    for f in findings:
        if not f.dedup_key:
            f.compute_dedup_key()
    groups: dict = {}
    for f in findings:
        groups.setdefault(f.dedup_key, []).append(f)

    merged = []
    for _, group in groups.items():
        if len(group) == 1:
            merged.append(group[0])
            continue
        # keep the highest-severity finding as the primary
        group.sort(key=_sort_key)
        primary = group[0]
        engines = sorted({g.engine for g in group})
        rule_ids = sorted({g.rule_id for g in group})
        primary.corroborated_by = [e for e in engines if e != primary.engine]
        if len(engines) > 1:
            # multiple independent engines agree -> promote confidence
            primary.confidence = Confidence.HIGH
            primary.description += (
                f"  [Corroborated by {len(engines)} engines: {', '.join(engines)} "
                f"({', '.join(rule_ids)})]"
            )
        merged.append(primary)
    return merged


# --------------------------------------------------------------------------- #
# False-positive heuristics -> (is_fp, reason)
# --------------------------------------------------------------------------- #

def _fp_assessment(f: Finding) -> tuple:
    file_low = (f.file or "").lower()

    # 1. Example/placeholder env files are documentation, not live secrets.
    if f.category == "SECRET" and file_low.endswith((".env.example", ".env.sample", ".env.template", ".env.dist")):
        return True, "secret in an example/template env file (documentation, not a live credential)"

    # 2. Low-confidence entropy hits inside lockfiles/minified assets.
    if f.rule_id in ("high-entropy-string",) and (
        "lock" in file_low or file_low.endswith((".min.js", ".min.css", ".map", ".snap"))
    ):
        return True, "high-entropy token in a lockfile/minified/generated asset (typically an integrity hash, not a secret)"

    # 3. LOW-confidence prompt-injection phrasing found in this tool's own docs or
    #    obvious security-education material is expected (a scanner's rules mention
    #    the very phrases it hunts for).
    if f.engine == "aisec" and f.confidence == Confidence.LOW and any(
        seg in file_low for seg in ("readme", "changelog", "docs/", "/doc/", "license", "limits", "architecture")
    ):
        return True, "low-confidence AI-security phrasing in documentation (frequently discusses these patterns by nature)"

    # 4. Generic secret assignment that is very short and low-confidence.
    if f.rule_id == "hardcoded-secret-assignment" and f.confidence == Confidence.LOW and f.severity <= Severity.MEDIUM:
        # keep MEDIUM+ real ones; only demote clearly weak matches
        if "entropy" in f.description and any(x in f.description for x in ("2.", "1.", "0.")):
            return True, "low-entropy value assigned to a secret-named variable (likely a config key, not a secret)"

    return False, ""


def apply_fp_filter(findings: list) -> list:
    for f in findings:
        is_fp, reason = _fp_assessment(f)
        if is_fp:
            f.filtered = True
            f.filter_reason = reason
    return findings


def interpret(findings: list) -> dict:
    """
    Full pipeline. Returns:
      {active: [...], filtered: [...], summary: {...}}
    """
    merged = dedup(findings)
    merged = apply_fp_filter(merged)

    active = sorted([f for f in merged if not f.filtered], key=_sort_key)
    filtered = sorted([f for f in merged if f.filtered], key=_sort_key)

    summary = {s.label: 0 for s in Severity}
    for f in active:
        summary[f.severity.label] += 1

    return {
        "active": active,
        "filtered": filtered,
        "summary": summary,
        "total_active": len(active),
        "total_filtered": len(filtered),
    }
