"""Fail-safe content anchor check for every non-empty KB citation."""
from __future__ import annotations

import glob
import json
import re
import sys
import unicodedata
from pathlib import Path

EXPECTED_UNRESOLVED = 57
# The sweep in the F13-B audit reaches the existing 57-record pin at 20
# lines (65, 60, 59, 57, 57... at windows 5, 10, 15, 20, 25...). Keeping
# the knee makes future line insertions stricter without changing today's
# corpus result; re-run the sweep if the pin moves.
WINDOW_LINES = 20


def normalize(value: str, disabled: str | None = None) -> str:
    if disabled != "nfkc":
        value = unicodedata.normalize("NFKC", value)
    if disabled != "dash":
        value = value.replace("—", "--").replace("–", "--").replace("−", "--")
    if disabled != "comment":
        value = re.sub(r"^[ \t]*(?:#:\s?|#\s?)", "", value, flags=re.MULTILINE)
    if disabled != "markup":
        value = re.sub(r"[*`_~]", "", value)
    if disabled != "quotes":
        value = value.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
    if disabled != "ws":
        value = re.sub(r"\s+", " ", value)
    return value.strip().lower()


def resolve(record: dict) -> bool:
    quote = normalize(str(record.get("verbatim") or ""))
    if not quote:
        return True
    source = Path(record["source_file"])
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
        start = max(0, int(record["source_line"]) - 1)
    except (OSError, ValueError, KeyError):
        return False
    window = normalize("\n".join(lines[start : start + WINDOW_LINES]))
    return quote in window


def resolve_without(record: dict, rule: str) -> bool:
    """Resolve a record with one named normalization rule disabled."""
    quote = normalize(str(record.get("verbatim") or ""), rule)
    if not quote:
        return True
    try:
        lines = Path(record["source_file"]).read_text(encoding="utf-8").splitlines()
        start = max(0, int(record["source_line"]) - 1)
    except (OSError, ValueError, KeyError):
        return False
    return quote in normalize("\n".join(lines[start : start + WINDOW_LINES]), rule)


def main() -> int:
    records = []
    for path in sorted(glob.glob("references/kb/claims-*.jsonl")):
        records.extend(json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip())
    unresolved = [r for r in records if r.get("verbatim") and not resolve(r)]
    controls = {
        "plain": next((r for r in records if r.get("id") == "RULES-readme-0002"), None),
        "wrapped": ("ws", next((r for r in records if r.get("id") == "ARCH-adr-001-0001"), None)),
        "dash": ("dash", next((r for r in records if r.get("id") == "HIST-changelog-0052"), None)),
        "markdown": ("markup", next((r for r in records if r.get("id") == "ARCH-adr-001-0004"), None)),
    }
    if controls["plain"] is None or not resolve(controls["plain"]):
        print("kb-content-anchor: POSITIVE CONTROL FAILED", file=sys.stderr)
        return 1
    for rule, record in (controls[name] for name in ("wrapped", "dash", "markdown")):
        if record is None or not resolve(record) or resolve_without(record, rule):
            print(f"kb-content-anchor: POSITIVE CONTROL FAILED ({rule})", file=sys.stderr)
            return 1
    # A synthetic quote that cannot occur in this source is the negative control;
    # unlike the old unresolved-set tautology, a broken matcher makes this fail.
    impossible = {"verbatim": "__KB_CONTENT_ANCHOR_SYNTHETIC_NEVER_PRESENT_7f3c__", "source_file": __file__, "source_line": 1}
    if resolve(impossible):
        print("kb-content-anchor: synthetic negative control resolved", file=sys.stderr)
        return 1
    # Comment-prefix has dependents but no pure single-rule corpus control; NFKC
    # and smart-quote folding have none. Keep all three, but exercise mechanics
    # synthetically so presence is not mistaken for measured coverage.
    if (
        normalize("Ａ", "nfkc") == normalize("Ａ")
        or normalize("“q”", "quotes") == normalize("“q”")
        or normalize("# quoted", "comment") == normalize("# quoted")
    ):
        print("kb-content-anchor: unexercised-rule synthetic control failed", file=sys.stderr)
        return 1
    if len(unresolved) != EXPECTED_UNRESOLVED:
        print(f"kb-content-anchor: unresolved {len(unresolved)} != EXPECTED {EXPECTED_UNRESOLVED}", file=sys.stderr)
        return 1
    print(f"kb-content-anchor: {len(records)} claims; resolved {len(records)-len(unresolved)}; unresolved {len(unresolved)}")
    print("positive-controls: plain + measured ws/dash/markup; negative-control: synthetic impossible quote")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
