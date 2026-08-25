"""
PRAETOR knowledge-base generator -- fills in the content hash that makes a KB
record's staleness DETECTABLE rather than trusted.

Per the estate-wide 2026-08-24 standing directive: a hand-maintained wiki is a
drift generator, not a drift control. This script does not write prose and
does not decide what the project's facts are -- that is done once, by reading
the docs (this session used four territory subagents), into the CLAIMS files
below. What this script does is MECHANICAL and DETERMINISTIC: for every claim,
read its cited source line right now and hash it. Two runs against an
unchanged tree must produce byte-identical output -- that is the whole
contract, and `tests/kb-drift.py` is what actually gates on it later.

Nobody hand-edits `references/kb/records.jsonl`. Edit a claims-*.jsonl file
(or add a source doc and a new claims file) and re-run this script.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KB_DIR = os.path.join(ROOT, "references", "kb")
CLAIMS_GLOB = os.path.join(KB_DIR, "claims-*.jsonl")
RECORDS_PATH = os.path.join(KB_DIR, "records.jsonl")

REQUIRED_FIELDS = (
    "id", "kind", "subject", "assertion", "verbatim", "source_file",
    "source_line", "authority", "binds", "exceptions", "volatile",
    "volatile_reason",
)

# Present in the estate-wide schema but not required on every claim: a claim
# defaults to "supersedes nothing, conflicts with nothing" rather than being
# rejected for omitting them, so every claims-*.jsonl file written before this
# was added still builds. Set explicitly on a claim when a real conflict or
# supersession is known; ⚠️ this pass does not exhaustively cross-reference
# every record pair for conflicts -- known conflicts are captured in prose
# within `assertion` on both sides (per the directive's own instruction not to
# resolve them), not necessarily linked here by id yet.
OPTIONAL_DEFAULTS = {"supersedes": None, "conflicts_with": []}

# Existing debt is pinned by the gate; new or changed claims may not introduce
# another empty string in a required field.  The generated records are not the
# authority for this check because this script rewrites their hashes.
EMPTY_STRING_FIELDS = {"id", "kind", "subject", "assertion", "verbatim",
                       "source_file", "authority", "binds"}


def compute_source_sha(source_file: str, source_line: int) -> str:
    """Hash the exact line a claim is anchored to, read from disk NOW.

    The "source span" is deliberately one line, not a paragraph or a byte
    range: a wider span drifts on any nearby edit, which is indistinguishable
    from the cited fact actually changing and would make every claim look
    stale within days. A single anchored line is the narrowest span that
    still catches the fact itself moving or being reworded.

    Raises FileNotFoundError / IndexError on a claim whose source moved so far
    it no longer resolves at all -- that is not a hash mismatch, it is a
    worse failure, and the caller must not silently treat it as either.
    """
    path = os.path.join(ROOT, source_file)
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    if source_line < 1 or source_line > len(lines):
        raise IndexError(
            f"{source_file}:{source_line} is out of range (file has {len(lines)} lines)"
        )
    span = lines[source_line - 1].rstrip("\n").strip()
    return hashlib.sha256(span.encode("utf-8", "replace")).hexdigest()[:16]


def _load_claims() -> list:
    claims = []
    for path in sorted(glob.glob(CLAIMS_GLOB)):
        with open(path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    sys.stderr.write(
                        f"kb-build: {path}:{line_no} is not valid JSON -- {exc}\n"
                    )
                    sys.exit(2)
                missing = [f for f in REQUIRED_FIELDS if f not in rec]
                if missing:
                    sys.stderr.write(
                        f"kb-build: {path}:{line_no} (id={rec.get('id', '?')}) "
                        f"missing required field(s): {missing}\n"
                    )
                    sys.exit(2)
                claims.append(rec)
    return claims


def main() -> int:
    claims = _load_claims()
    if not claims:
        sys.stderr.write(
            f"kb-build: no claims found under {CLAIMS_GLOB} -- nothing to build. "
            "A zero-claim KB is not a clean result, it is an unmeasured one.\n"
        )
        return 2

    existing = {}
    if os.path.exists(RECORDS_PATH):
        with open(RECORDS_PATH, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    existing[rec.get("id")] = rec

    seen_ids = set()
    unresolved = []
    records = []
    for rec in claims:
        rid = rec["id"]
        if rid in seen_ids:
            sys.stderr.write(f"kb-build: duplicate id '{rid}' across claims files\n")
            return 2
        seen_ids.add(rid)
        previous = existing.get(rid)
        for field in EMPTY_STRING_FIELDS:
            value = rec.get(field)
            if value is not None and (not isinstance(value, str) or value.strip()):
                continue
            old_value = previous.get(field) if previous else None
            old_empty = old_value is None or (isinstance(old_value, str) and not old_value.strip())
            if previous is None or not old_empty:
                sys.stderr.write(
                    f"kb-build: {rid} introduces empty required field {field!r}\n"
                )
                return 1
        try:
            source_sha = compute_source_sha(rec["source_file"], rec["source_line"])
        except (OSError, IndexError) as exc:
            unresolved.append(f"{rid}: {rec['source_file']}:{rec['source_line']} -- {exc}")
            continue
        out = dict(rec)
        out["source_sha"] = source_sha
        for field, default in OPTIONAL_DEFAULTS.items():
            out.setdefault(field, default)
        records.append(out)

    if unresolved:
        sys.stderr.write(
            "kb-build: %d claim(s) could not be resolved against current source "
            "-- fix or remove them before building:\n" % len(unresolved)
        )
        for line in unresolved:
            sys.stderr.write(f"  {line}\n")
        return 1

    records.sort(key=lambda r: r["id"])
    os.makedirs(KB_DIR, exist_ok=True)
    with open(RECORDS_PATH, "w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True, ensure_ascii=False))
            fh.write("\n")

    n_volatile = sum(1 for r in records if r.get("volatile"))
    print(f"kb-build: {len(records)} record(s), {n_volatile} volatile, "
          f"written to {os.path.relpath(RECORDS_PATH, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
