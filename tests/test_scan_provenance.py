"""
Which commit a scan was of, read WITHOUT invoking git.

A dashboard plotting findings over time needs the commit. Getting it the obvious
way -- shelling out to `git rev-parse` in the target -- makes git read THAT
directory's `.git/config`, and git config can name external commands
(`core.fsmonitor`, `core.pager`, `diff.external`, `credential.helper`). Running
git inside an untrusted tree is a plausible route to executing something the
target chose, which is the one thing PRAETOR must never do.

⚠️ HONEST ABOUT THE EVIDENCE. That execution was not reproduced here. An attempt
failed for an unrelated reason -- the fixture was not a valid repository, so git
refused before reading any config -- and therefore demonstrated nothing. The
design is conservative on the STRUCTURE of the risk, not on a measurement. It
costs two small file reads, so nothing is being traded for it.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import core  # noqa: E402

_PRAETOR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "praetor.py")

_SHA = "0123456789abcdef0123456789abcdef01234567"


def _fake_repo(root, head_content, ref_content=None, packed=None):
    git = root / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text(head_content, encoding="utf-8")
    if ref_content is not None:
        (git / "refs" / "heads" / "main").write_text(ref_content, encoding="utf-8")
    if packed is not None:
        (git / "packed-refs").write_text(packed, encoding="utf-8")
    (root / "a.py").write_text("x = 1\n", encoding="utf-8")
    return root


def _scan(target, *extra):
    proc = subprocess.run(
        [sys.executable, _PRAETOR, str(target), "--engines", "secrets",
         "--no-registry", "--format", "json", "--quiet", *extra],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    return json.loads(proc.stdout)["meta"]["provenance"]


# --------------------------------------------------------------------------- #
# Reading it
# --------------------------------------------------------------------------- #

def test_a_branch_checkout_yields_branch_and_commit(tmp_path):
    _fake_repo(tmp_path, "ref: refs/heads/main\n", _SHA + "\n")
    prov = _scan(tmp_path)
    assert prov["commit"] == _SHA
    assert prov["branch"] == "main"
    assert prov["provenance_source"] == "target-git-files"


def test_a_detached_head_yields_the_commit(tmp_path):
    _fake_repo(tmp_path, _SHA + "\n")
    assert _scan(tmp_path)["commit"] == _SHA


def test_a_packed_ref_is_found(tmp_path):
    """Refs are packed on any repository that has been gc'd, which is most of
    them. Reading only the loose ref would silently return nothing for those."""
    _fake_repo(tmp_path, "ref: refs/heads/main\n",
               packed="# pack-refs with: peeled\n" + _SHA + " refs/heads/main\n")
    assert _scan(tmp_path)["commit"] == _SHA


def test_a_non_repository_is_not_an_error(tmp_path):
    """Most scan targets are not git checkouts. Absent means 'not known', and
    that is a normal result, not a failure."""
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    prov = _scan(tmp_path)
    assert prov.get("provenance_source") == "none"
    assert "commit" not in prov


# --------------------------------------------------------------------------- #
# The target wrote these bytes, so they are validated
# --------------------------------------------------------------------------- #

def test_a_malformed_sha_from_the_target_is_dropped(tmp_path):
    """🔴 THE TARGET AUTHORED THIS STRING and it lands in a report a dashboard
    renders. Only a 40-character hex SHA is accepted; anything else is dropped
    rather than passed along."""
    _fake_repo(tmp_path, "ref: refs/heads/main\n", "not-a-sha; rm -rf /\n")
    prov = _scan(tmp_path)
    assert "commit" not in prov


def test_a_hostile_branch_name_is_stripped(tmp_path):
    """Same reasoning one field over."""
    hostile = "main</script><script>alert(1)</script>"
    _fake_repo(tmp_path, "ref: refs/heads/" + hostile + "\n", _SHA + "\n")
    branch = _scan(tmp_path).get("branch", "")
    assert "<" not in branch and ">" not in branch


def test_a_very_long_branch_name_is_bounded(tmp_path):
    _fake_repo(tmp_path, "ref: refs/heads/" + ("a" * 5000) + "\n", _SHA + "\n")
    assert len(_scan(tmp_path).get("branch", "")) <= 100


# --------------------------------------------------------------------------- #
# The caller outranks the target
# --------------------------------------------------------------------------- #

def test_caller_supplied_provenance_wins(tmp_path):
    """🔴 CI KNOWS WHICH COMMIT IT CHECKED OUT, from its own environment, and that
    source is trustworthy in a way the scanned tree is not."""
    _fake_repo(tmp_path, "ref: refs/heads/main\n", _SHA + "\n")
    caller_sha = "deadbeef" * 5
    prov = _scan(tmp_path, "--commit", caller_sha, "--repo", "owner/name")
    assert prov["commit"] == caller_sha
    assert prov["repo"] == "owner/name"
    assert prov["provenance_source"] == "caller"


def test_the_source_of_the_provenance_is_always_stated(tmp_path):
    """A value read from the scanned tree is target-controlled; one from CI is
    not. A consumer that cannot tell them apart has lost that distinction
    silently, so the field is never omitted."""
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert "provenance_source" in _scan(tmp_path)


# --------------------------------------------------------------------------- #
# It must not invoke git
# --------------------------------------------------------------------------- #

def test_the_reader_touches_no_subprocess(monkeypatch, tmp_path):
    """🔴 THE INVARIANT, ASSERTED BEHAVIOURALLY rather than by reading the code.

    A future edit that reaches for `git rev-parse` because it is easier would
    pass every other test in this file.
    """
    _fake_repo(tmp_path, "ref: refs/heads/main\n", _SHA + "\n")

    def explode(*a, **k):
        raise AssertionError("git_provenance must not spawn a process")

    monkeypatch.setattr(subprocess, "run", explode)
    monkeypatch.setattr(subprocess, "Popen", explode)
    monkeypatch.setattr(subprocess, "check_output", explode)
    assert core.git_provenance(str(tmp_path))["commit"] == _SHA
