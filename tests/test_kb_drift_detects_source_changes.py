"""
The KB drift gate exists to catch a record whose cited source moved. These
tests prove it actually does that, mutating a source file after the record
was built and confirming the SAME hash function used by the gate sees it.

Both `scripts/kb-build.py` and `tests/kb-drift.py` import their hashing logic
from one place (`kb_build.compute_source_sha`) precisely so this test cannot
pass by exercising a function neither script actually uses.
"""

import importlib.util
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "kb_build", os.path.join(_ROOT, "scripts", "kb-build.py")
)
kb_build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kb_build)


@pytest.fixture()
def fake_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(kb_build, "ROOT", str(tmp_path))
    doc = tmp_path / "doc.md"
    doc.write_text("line one\nline two: the fact under test\nline three\n", encoding="utf-8")
    return tmp_path, doc


def test_the_same_line_hashes_the_same_every_time(fake_repo):
    _, doc = fake_repo
    a = kb_build.compute_source_sha("doc.md", 2)
    b = kb_build.compute_source_sha("doc.md", 2)
    assert a == b


def test_different_lines_hash_differently(fake_repo):
    _, doc = fake_repo
    assert kb_build.compute_source_sha("doc.md", 1) != kb_build.compute_source_sha("doc.md", 2)


def test_editing_the_cited_line_changes_the_hash(fake_repo):
    """THE HEADLINE. If this fails, the drift gate cannot detect drift."""
    _, doc = fake_repo
    before = kb_build.compute_source_sha("doc.md", 2)
    doc.write_text("line one\nline two: the fact under test, NOW WRONG\nline three\n",
                   encoding="utf-8")
    after = kb_build.compute_source_sha("doc.md", 2)
    assert before != after, "editing the cited line must change its hash"


def test_editing_an_unrelated_line_does_not_change_the_hash(fake_repo):
    """KEEP DIRECTION. A one-line span must not drift on a neighbour's edit,
    or every record near an active file would false-alarm constantly."""
    _, doc = fake_repo
    before = kb_build.compute_source_sha("doc.md", 2)
    doc.write_text("line one EDITED\nline two: the fact under test\nline three EDITED\n",
                   encoding="utf-8")
    after = kb_build.compute_source_sha("doc.md", 2)
    assert before == after


def test_out_of_range_line_raises_rather_than_silently_resolving(fake_repo):
    with pytest.raises(IndexError):
        kb_build.compute_source_sha("doc.md", 99)


def test_a_moved_source_file_raises(fake_repo):
    with pytest.raises(OSError):
        kb_build.compute_source_sha("does-not-exist.md", 1)


def test_build_then_drift_roundtrip_is_clean(fake_repo, monkeypatch):
    """End-to-end: build records from a claim, then the SAME hash function
    (as kb-drift.py would call it) must agree -- no drift on an unchanged tree.
    """
    tmp_path, doc = fake_repo
    claim = {
        "id": "TEST-0001", "kind": "claim", "subject": "test",
        "assertion": "the fact under test", "verbatim": None,
        "source_file": "doc.md", "source_line": 2, "authority": "measured",
        "binds": "nobody", "exceptions": [], "volatile": False,
        "volatile_reason": None,
    }
    sha_at_build = kb_build.compute_source_sha(claim["source_file"], claim["source_line"])
    record = dict(claim, source_sha=sha_at_build)

    # Simulate the drift gate re-deriving the hash later, unchanged tree.
    sha_at_check = kb_build.compute_source_sha(record["source_file"], record["source_line"])
    assert sha_at_check == record["source_sha"]

    # Now mutate the source and confirm the gate's own comparison would fail.
    doc.write_text("line one\nline two: DRIFTED\nline three\n", encoding="utf-8")
    sha_after_drift = kb_build.compute_source_sha(record["source_file"], record["source_line"])
    assert sha_after_drift != record["source_sha"], "drift must be visible to a re-check"
