"""Fail-safe content anchor check for every non-empty KB citation."""
from __future__ import annotations

import glob
import json
import re
import sys
import unicodedata
from pathlib import Path

EXPECTED_UNRESOLVED = 57
WINDOW_LINES = 100


def normalize(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    value = value.replace("—", "--").replace("–", "--").replace("−", "--")
    value = re.sub(r"^[ \t]*(?:#:\s?|#\s?)", "", value, flags=re.MULTILINE)
    value = re.sub(r"[*`_~]", "", value)
    value = value.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
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


def main() -> int:
    records = []
    for path in sorted(glob.glob("references/kb/claims-*.jsonl")):
        records.extend(json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip())
    unresolved = [r for r in records if r.get("verbatim") and not resolve(r)]
    controls = {
        "plain": next((r for r in records if r.get("id") == "RULES-readme-0002"), None),
        "wrapped": next((r for r in records if r.get("id") == "ARCH-architecture-0004"), None),
        "dash": next((r for r in records if r.get("id") == "ARCH-adr-001-0015"), None),
        "markdown": next((r for r in records if r.get("id") == "ARCH-architecture-0015"), None),
    }
    if any(r is None or not resolve(r) for r in controls.values()):
        print("kb-content-anchor: POSITIVE CONTROL FAILED", file=sys.stderr)
        return 1
    if any(resolve(r) for r in unresolved):
        print("kb-content-anchor: internal unresolved-set error", file=sys.stderr)
        return 1
    if len(unresolved) != EXPECTED_UNRESOLVED:
        print(f"kb-content-anchor: unresolved {len(unresolved)} != EXPECTED {EXPECTED_UNRESOLVED}", file=sys.stderr)
        return 1
    print(f"kb-content-anchor: {len(records)} claims; resolved {len(records)-len(unresolved)}; unresolved {len(unresolved)}")
    print("positive-controls: plain wrapped dash markdown; negative-control: unresolved set")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
