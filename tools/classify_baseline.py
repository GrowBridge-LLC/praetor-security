"""
Assign a PREDICATE to every self-scan finding, and emit the S2 baseline.

WHY A PREDICATE AND NOT A COUNT
-------------------------------
"False positives went from 47 to 6" is unfalsifiable on its own: the number
describes whichever filter happened to be in place. A predicate is a stated,
checkable reason a finding is suppressed -- so a later change can be shown to
have suppressed the RIGHT things, and a regression shows up as a finding whose
predicate no longer holds.

This is PRAETOR's own A5 rule ("state the predicate alongside the count")
applied to PRAETOR before PRAETOR applies it to anyone else.

WHAT THIS IS AND IS NOT
-----------------------
This is an ANALYSIS tool that produces the baseline artifact. It is deliberately
NOT wired into the engines -- suppressing findings for real is S3, and doing it
here would mean the baseline and the filter share a bug and agree with each other.

Each predicate below is falsifiable: it names a check anyone can run against the
source line, not a judgement.

    python tools/classify_baseline.py <praetor-report.json>
"""

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Taxonomy labels that the secrets engine's entropy/assignment heuristics misread
# as credentials. These are published identifiers, not secrets.
_TAXONOMY = re.compile(r"\b(A\d{2}:20\d{2}|CWE-\d+|OWASP)\b")


def _line_of(rel_path, lineno):
    """Return the source line a finding points at, or None if unreadable."""
    path = os.path.join(REPO, rel_path.replace("/", os.sep))
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    if not (1 <= lineno <= len(lines)):
        return None
    return lines[lineno - 1]


def _inside_open_bracket(rel_path, lineno):
    """
    True if the line sits inside an unclosed (, [ or { -- i.e. inside a collection
    literal or a call's argument list, rather than at statement level.

    This is what separates a detector's PATTERN TABLE (a tuple/set/dict of strings,
    or a Finding(...) display template) from an ordinary scalar assignment that
    merely happens to live in the same directory.

    🔴 THIS DISCRIMINATOR EXISTS BECAUSE THE FIRST VERSION DID NOT HAVE IT.
    P1 originally matched on directory alone ("under scripts/"), and a planted
    CRITICAL hardcoded AWS secret in live code at scripts/_probe_inside.py was
    SUPPRESSED -- a suppression rule that would have hidden real credentials
    anywhere in PRAETOR's own engine directory. Found by planting the probe, not
    by reading the code. Do not relax this back to a path check.

    Approximate by construction: it ignores brackets appearing inside string
    literals. Recorded as a known limit rather than claimed exact.
    """
    path = os.path.join(REPO, rel_path.replace("/", os.sep))
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read().splitlines()[: lineno - 1]
    except OSError:
        return False
    depth = 0
    for l in head:
        depth += l.count("(") + l.count("[") + l.count("{")
        depth -= l.count(")") + l.count("]") + l.count("}")
    return depth > 0


def _in_docstring(rel_path, lineno):
    """
    True if the line sits inside a triple-quoted block.

    Approximate by construction: it counts triple-quote delimiters before the
    line, so a triple-quote inside a normal string would fool it. Recorded as a
    known limit rather than claimed exact -- see LIMITS in the emitted baseline.
    """
    path = os.path.join(REPO, rel_path.replace("/", os.sep))
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read().splitlines()[: lineno - 1]
    except OSError:
        return False
    return (sum(l.count('"""') + l.count("'''") for l in head) % 2) == 1


def classify(finding):
    """
    Return (predicate_id, why). Order matters: the most specific structural
    reason wins, so a comment inside the test corpus is reported as a comment.
    """
    rel, lineno = finding.get("file", ""), int(finding.get("line") or 0)
    line = _line_of(rel, lineno)
    stripped = (line or "").strip()

    if rel.startswith("references/test-corpus/"):
        return "P4-FIXTURE-CORPUS", (
            "file's declared purpose is emitting malicious samples; a match here is the "
            "fixture working, not a defect"
        )

    if rel.endswith(".md"):
        return "P5-DOC-PROSE", "documentation describing an attack pattern in prose"

    if stripped.startswith("#"):
        return "P2-COMMENT", "match is inside a `#` comment; deleting comments removes it"

    if _TAXONOMY.search(stripped):
        return "P6-TAXONOMY-LABEL", (
            "value is a published OWASP/CWE identifier misread as a credential by the "
            "entropy/assignment heuristic"
        )

    if (
        rel.startswith("scripts/")
        and finding.get("engine") in ("aisec", "secrets")
        and _inside_open_bracket(rel, lineno)
    ):
        return "P1-DETECTOR-SELF-MATCH", (
            "match is inside PRAETOR's own detection machinery -- a string inside a pattern "
            "collection or a Finding(...) display template. It is data the tool compares or "
            "prints, never executed and never read as a path. NOTE: being under scripts/ is "
            "NOT sufficient; the match must be inside a collection/call, or a real secret "
            "in live code would be suppressed here"
        )

    if _in_docstring(rel, lineno):
        return "P3-DOCSTRING", "match is inside a docstring explaining the threat being guarded"

    return "P7-REVIEW", "no structural predicate applies -- requires human review"


PREDICATES = {
    "P1-DETECTOR-SELF-MATCH": "SUPPRESS",
    "P2-COMMENT": "SUPPRESS",
    "P3-DOCSTRING": "SUPPRESS",
    "P4-FIXTURE-CORPUS": "SUPPRESS",
    "P5-DOC-PROSE": "SUPPRESS",
    "P6-TAXONOMY-LABEL": "SUPPRESS",
    "P7-REVIEW": "KEEP",
}


def main(report_path):
    with open(report_path, "r", encoding="utf-8") as fh:
        report = json.load(fh)

    rows, counts = [], {}
    for f in report.get("findings", []):
        pid, why = classify(f)
        counts[pid] = counts.get(pid, 0) + 1
        rows.append({
            "rule_id": f.get("rule_id"),
            "engine": f.get("engine"),
            "severity": f.get("severity"),
            "file": f.get("file"),
            "line": f.get("line"),
            "predicate": pid,
            "disposition": PREDICATES[pid],
            "why": why,
        })

    baseline = {
        "baseline_version": 1,
        "generated_against": {
            "praetor_version": report.get("meta", {}).get("version"),
            "engines": {k: v.get("status") for k, v in report.get("meta", {}).get("engines", {}).items()},
            "file_count": report.get("meta", {}).get("file_count"),
        },
        "predicate_definitions": PREDICATES,
        "counts": counts,
        "total_active": len(rows),
        "kept_for_review": sum(1 for r in rows if r["disposition"] == "KEEP"),
        "findings": sorted(rows, key=lambda r: (r["predicate"], r["file"], r["line"])),
    }
    print(json.dumps(baseline, indent=2))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
