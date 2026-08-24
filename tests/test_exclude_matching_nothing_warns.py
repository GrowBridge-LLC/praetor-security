"""
`--exclude` that matches zero files is indistinguishable from having nothing to
exclude, and the only visible symptom used to be a much larger scan than expected.

MEASURED DEFECT (2026-08-24), found in the field by a downstream consumer wiring
PRAETOR into another project's own commit gate. A pattern meant to skip a build
worktree matched nothing -- a shell had silently rewritten the argument before
Python ever saw it (Git Bash / MSYS2 path conversion, triggered by a bare `/`
next to alternation) -- and the only symptom was a scan roughly 16x larger than
expected timing out under `rc=124`, which reads as "the tree is just that big",
not as "the exclusion never fired". Reproduced directly: `walk_files()` correctly
matches a Windows-style path when the pattern survives the shell intact; the
silent failure is upstream of this function, in the shell, not in the regex
matching itself -- which is exactly why `walk_files()` cannot know it happened
and PRAETOR must ask the only question it CAN answer: did this pattern do
anything at all.

⇒ `--exclude` with no matches, on a tree with anything to measure, now warns.
Not an error -- excluding a pattern that legitimately matches nothing in THIS
tree is ordinary -- but it must never be silent, because the two cases print
identically otherwise.
"""

import praetor


def _tree_with_a_skippable_subdir(tmp_path):
    keep = tmp_path / "src"
    keep.mkdir()
    (keep / "main.py").write_text("x = 1\n", encoding="utf-8")

    skip = tmp_path / "worktree" / "vendored-copy"
    skip.mkdir(parents=True)
    (skip / "main.py").write_text("x = 1\n", encoding="utf-8")
    return str(tmp_path)


def test_warns_when_the_pattern_matches_nothing(tmp_path, capsys):
    target = _tree_with_a_skippable_subdir(tmp_path)

    rc = praetor.main([target, "--engines", "secrets",
                        "--exclude", "this-never-matches-anything"])

    err = capsys.readouterr().err
    assert rc in (0, 1)
    assert "excluded 0 files" in err, err
    assert "WARNING" in err, err


def test_silent_when_the_pattern_actually_excludes_something(tmp_path, capsys):
    target = _tree_with_a_skippable_subdir(tmp_path)

    rc = praetor.main([target, "--engines", "secrets",
                        "--exclude", "(^|/)worktree/"])

    err = capsys.readouterr().err
    assert rc in (0, 1)
    assert "excluded 0 files" not in err, err


def test_silent_when_no_exclude_was_given_at_all(tmp_path, capsys):
    target = _tree_with_a_skippable_subdir(tmp_path)

    rc = praetor.main([target, "--engines", "secrets"])

    err = capsys.readouterr().err
    assert rc in (0, 1)
    assert "excluded 0 files" not in err, err


def test_silent_on_an_empty_tree_even_with_an_exclude(tmp_path, capsys):
    """Nothing to measure at all is the existing scope-floor's job (exit 3), not
    this warning's. An --exclude that matches 0 of 0 files is not evidence of
    anything -- the floor below is the one that must fire here, not this one."""
    empty = tmp_path / "empty"
    empty.mkdir()

    praetor.main([str(empty), "--engines", "secrets",
                  "--exclude", "this-never-matches-anything"])

    err = capsys.readouterr().err
    assert "excluded 0 files" not in err, err
