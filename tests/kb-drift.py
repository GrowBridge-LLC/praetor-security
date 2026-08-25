"""
PRAETOR KB drift gate.

Recomputes every record's source-line hash against the CURRENT tree and
compares it to the hash stored in `references/kb/records.jsonl`. Any mismatch
means the cited source moved since the claim was authored, and the record can
no longer be trusted at face value -- so this exits non-zero, not a warning.

A check that prints and does not gate is a printout, not a gate: this is
wired into `tests/precommit.sh` as its own gate, and it must be run through
that (or invoked directly and its exit code checked) -- reading its stdout is
not a substitute for reading `$?`.
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "kb_build", os.path.join(ROOT, "scripts", "kb-build.py")
)
kb_build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kb_build)

RECORDS_PATH = os.path.join(ROOT, "references", "kb", "records.jsonl")


def main() -> int:
    if not os.path.isfile(RECORDS_PATH):
        sys.stderr.write(
            f"kb-drift: {os.path.relpath(RECORDS_PATH, ROOT)} does not exist -- "
            "run scripts/kb-build.py first. A missing KB is not a passing gate.\n"
        )
        return 1

    with open(RECORDS_PATH, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]

    if not records:
        sys.stderr.write("kb-drift: records.jsonl is empty -- nothing was measured.\n")
        return 1

    drifted = []
    for rec in records:
        rid = rec.get("id", "?")
        stored_sha = rec.get("source_sha")
        try:
            current_sha = kb_build.compute_source_sha(rec["source_file"], rec["source_line"])
        except (OSError, IndexError) as exc:
            drifted.append(f"{rid}: {rec.get('source_file')}:{rec.get('source_line')} "
                            f"UNRESOLVABLE -- {exc}")
            continue
        if current_sha != stored_sha:
            drifted.append(
                f"{rid}: {rec.get('source_file')}:{rec.get('source_line')} "
                f"hash changed ({stored_sha} -> {current_sha}) -- "
                f"'{rec.get('assertion')}' may no longer be true"
            )

    if drifted:
        sys.stderr.write(f"kb-drift: {len(drifted)} of {len(records)} record(s) drifted:\n")
        for line in drifted:
            sys.stderr.write(f"  {line}\n")
        sys.stderr.write(
            "\nRe-verify each assertion against its current source, then re-run "
            "scripts/kb-build.py to refresh the stored hash. Do not just re-run\n"
            "the build to silence this without reading what changed -- that is\n"
            "the same shape as regenerating a baseline to hide a regression.\n"
        )
        return 1

    print(f"kb-drift: {len(records)} record(s), 0 drifted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
