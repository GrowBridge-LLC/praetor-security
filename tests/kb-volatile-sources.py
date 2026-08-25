"""Gate that keeps rewritten inbox sources explicitly marked volatile."""
from __future__ import annotations

import glob
import json
import sys


def main() -> int:
    violations = []
    total = 0
    for path in sorted(glob.glob("references/kb/claims-*.jsonl")):
        with open(path, encoding="utf-8") as fh:
            for line_no, raw in enumerate(fh, start=1):
                if not raw.strip():
                    continue
                record = json.loads(raw)
                source = str(record.get("source_file") or "").replace("\\", "/")
                if source.startswith("inbox/"):
                    total += 1
                    if record.get("volatile") is not True:
                        violations.append(f"{record.get('id', '?')} ({path}:{line_no})")
    if violations:
        print(
            f"kb-volatile-sources: {len(violations)} inbox claim(s) missing volatile=true:",
            file=sys.stderr,
        )
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1
    print(f"kb-volatile-sources: {total} inbox claim(s), all volatile=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
