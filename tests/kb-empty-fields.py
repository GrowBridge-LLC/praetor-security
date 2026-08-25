"""Pin existing KB empty-string debt without allowing it to grow.

The current debt is 206 claims with a null/empty ``verbatim`` value after the
bounded F12 backfill of the smallest claims file.  This is
deliberately not backfilled here: ``verbatim`` is the only required citation
field that ``kb-build.py`` does not regenerate, so an empty value removes the
independent check on that record's source anchor.  The pin stops new debt while
the separate backfill work is scoped.
"""

from __future__ import annotations

import glob
import json
import sys

# F12 bounded backfill: 43 citations in the smallest claims file now carry
# source-line verbatim anchors; the remaining debt is 206 claims.
EXPECTED_EMPTY_VERBATIM = 206
FIELDS = ("verbatim",)


def main() -> int:
    counts = {field: 0 for field in FIELDS}
    total = 0
    for path in sorted(glob.glob("references/kb/claims-*.jsonl")):
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                if not raw.strip():
                    continue
                total += 1
                record = json.loads(raw)
                for field in FIELDS:
                    value = record.get(field)
                    if value is None or (isinstance(value, str) and not value.strip()):
                        counts[field] += 1
    missing_volatile_reason = 0
    for path in sorted(glob.glob("references/kb/claims-*.jsonl")):
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                if not raw.strip():
                    continue
                record = json.loads(raw)
                if record.get("volatile") and not str(record.get("volatile_reason") or "").strip():
                    missing_volatile_reason += 1
    if counts["verbatim"] != EXPECTED_EMPTY_VERBATIM:
        print(
            f"kb-empty-fields: verbatim empty count {counts['verbatim']} "
            f"!= EXPECT_EMPTY_VERBATIM {EXPECTED_EMPTY_VERBATIM}",
            file=sys.stderr,
        )
        return 1
    if missing_volatile_reason:
        print(f"kb-empty-fields: {missing_volatile_reason} volatile claims lack volatile_reason", file=sys.stderr)
        return 1
    print(f"kb-empty-fields: {total} claims; empty verbatim {counts['verbatim']}; volatile missing reason 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
