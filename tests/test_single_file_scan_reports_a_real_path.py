"""
A single-file scan used to report the bare basename, not a path.

`walk_files(target)` reports each finding's location as `ScanFile.relpath`. Scanning a
directory computes it relative to that directory, so a finding in `research/x.js` inside
`scripts/` reports as `research/x.js`. Scanning `scripts/research/x.js` directly reported
just `x.js` -- the directory context vanished.

That is not cosmetic. A downstream consumer matching findings to a per-file ruling by path
cannot distinguish `x.js` from any other `x.js` in the tree, or from any of its own historical
copies sitting under a build worktree -- found live, 2026-08-24, by a caller invoking PRAETOR
once per changed file (exactly the shape a per-commit gate needs) and having to re-derive the
real path itself before a path-scoped suppression could match reliably.

Fixed: a single-file scan now reports a path relative to the current working directory, with
the bare basename only as a fallback when no relative path exists (crossing drives on
Windows). `scannable()`/`is_code()` still receive the plain basename -- both match on name
prefixes (".env", "dockerfile") that a path would defeat, so the fix must not feed them the
new value.
"""

import os

import core


def test_a_nested_single_file_reports_its_directory(tmp_path, monkeypatch):
    nested = tmp_path / "scripts" / "research"
    nested.mkdir(parents=True)
    target = nested / "x.js"
    target.write_text("var ok = 1;\n")

    monkeypatch.chdir(tmp_path)
    files = core.walk_files(str(target))

    assert len(files) == 1
    assert files[0].relpath == "scripts/research/x.js", files[0].relpath
    assert files[0].relpath != "x.js", (
        "regressed to a bare basename -- a caller cannot tell this file apart "
        "from any other x.js in the tree"
    )


def test_two_same_named_files_in_different_directories_report_differently(tmp_path, monkeypatch):
    for sub in ("a", "b"):
        d = tmp_path / sub
        d.mkdir()
        (d / "same.py").write_text("x = 1\n")

    monkeypatch.chdir(tmp_path)
    rel_a = core.walk_files(str(tmp_path / "a" / "same.py"))[0].relpath
    rel_b = core.walk_files(str(tmp_path / "b" / "same.py"))[0].relpath

    assert rel_a != rel_b, "two distinct files collapsed onto the same reported path"
    assert rel_a == "a/same.py"
    assert rel_b == "b/same.py"


def test_scannable_still_sees_the_plain_name_for_a_dotenv_file(tmp_path, monkeypatch):
    """The fix must not feed `scannable()` a path -- it matches on `.startswith(".env")`,
    which a directory prefix would defeat, silently un-scanning every nested .env file."""
    nested = tmp_path / "config"
    nested.mkdir()
    target = nested / ".env.staging"
    target.write_text("SECRET=x\n")

    monkeypatch.chdir(tmp_path)
    files = core.walk_files(str(target))

    assert len(files) == 1, ".env file under a subdirectory was not scanned"
    assert files[0].relpath == "config/.env.staging"


def test_dockerfile_variant_still_scanned_when_nested(tmp_path, monkeypatch):
    nested = tmp_path / "build"
    nested.mkdir()
    target = nested / "Dockerfile.dev"
    target.write_text("FROM scratch\n")

    monkeypatch.chdir(tmp_path)
    files = core.walk_files(str(target))

    assert len(files) == 1, "Dockerfile.dev under a subdirectory was not scanned"


def test_directory_scan_is_unchanged(tmp_path, monkeypatch):
    """The bug and the fix are both single-file-target-only. A directory scan already
    reported a real relative path and must keep doing so, unaffected."""
    nested = tmp_path / "scripts" / "research"
    nested.mkdir(parents=True)
    (nested / "x.js").write_text("var ok = 1;\n")

    files = core.walk_files(str(tmp_path))

    assert len(files) == 1
    assert files[0].relpath == "scripts/research/x.js"
