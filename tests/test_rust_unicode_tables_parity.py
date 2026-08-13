r"""
The Rust port's Unicode tables must still match the Python implementation.

🔴 THIS TEST WAS CLAIMED BEFORE IT EXISTED. Three separate comments -- in
`rust/praetor-core/src/unicode_tables.rs` and twice in
`tools/gen_unicode_tables.py` -- asserted that "`tests/test_rust_unicode_tables_parity.py`
fails if this file stops matching the generator". No such file existed. An
independent audit caught it.

That is the exact failure class this repo's own `CLAUDE.md` names as the killer:
**a safety property asserted in a header that the code does not implement.** The
generated table would have drifted the moment Python's bundled `unicodedata`
advanced, and the only thing standing between that and a silently divergent port
was a comment describing a test nobody had written. Writing the test is the fix;
softening the sentence would not have been.

## What drift would actually cost

`scripts/engine_aisec.py` derives two things from Python's Unicode database:

    _WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)      # what counts as a token
    _script_of(ch) -> unicodedata.name(ch).split(" ")[0]  # what script it is in

Rust's std has neither, and `praetor-core` carries no dependencies, so the port
ships a generated table instead. If that table and Python's database disagree by
even one code point, tokenisation differs, token boundaries move, and a
mixed-script token can fire in one implementation and not the other -- while both
test suites stay green, because each is consistent with itself.
"""

import shutil
import subprocess
import sys
import unicodedata

import gen_unicode_tables as gen


def test_generated_rust_table_matches_the_python_unicode_database():
    """The committed .rs file is exactly what the generator produces today."""
    committed = gen.OUT_PATH.read_text(encoding="utf-8")
    current = gen.render()

    assert committed == current, (
        f"rust/praetor-core/src/unicode_tables.rs is STALE.\n\n"
        f"It no longer matches what tools/gen_unicode_tables.py produces from Python's "
        f"unicodedata (now {gen.unicodedata.unidata_version}). The Rust port's notion of "
        f"'what is a letter' and 'what script is this' has drifted from the Python "
        f"engine's, which silently moves token boundaries and can make a mixed-script "
        f"finding fire in one implementation and not the other.\n\n"
        f"Regenerate deliberately:  py -3.14 tools/gen_unicode_tables.py\n"
        f"Do NOT hand-edit the .rs file -- that creates a second divergent definition."
    )


def test_the_check_mode_the_comments_point_at_actually_works():
    """
    The generator's `--check` is what the source comments tell a reader to run.
    A documented command that silently no-ops is the same defect one level down.
    """
    r = subprocess.run(
        [sys.executable, str(gen.__file__), "--check"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, (
        f"gen_unicode_tables.py --check failed (exit {r.returncode}).\n"
        f"stdout: {r.stdout}\nstderr: {r.stderr}"
    )


def test_the_table_is_not_vacuous():
    """
    Anti-vacuity. A generator that produced empty tables would satisfy the parity
    test above perfectly -- committed and current would both be empty and equal.
    Assert the tables actually carry the scripts the detector depends on.
    """
    rs = gen.OUT_PATH.read_text(encoding="utf-8")

    for name in ("SCRIPT_LATIN", "SCRIPT_CYRILLIC", "SCRIPT_GREEK",
                 "SCRIPT_ARMENIAN", "SCRIPT_CHEROKEE"):
        assert name in rs, f"{name} missing from the generated table"

    # The confusable scripts the homoglyph detector keys on must be represented.
    # Derived, not hardcoded, so this stays true across Unicode versions.
    word_ranges, script_ranges = gen.collect()
    assert len(word_ranges) > 100, f"only {len(word_ranges)} word ranges -- table looks empty"

    ids_present = {sid for _, _, sid in script_ranges}
    for script in gen.CONFUSABLE_SCRIPTS:
        assert gen.SCRIPT_IDS[script] in ids_present, (
            f"{script} has no code points in the generated table; the homoglyph "
            f"detector's confusable set would be inert in Rust"
        )


def test_python_and_the_table_agree_on_the_characters_that_matter():
    """
    Spot-check the derived table against Python directly, on the code points the
    homoglyph detector was actually built around. Cheap, and it fails loudly if
    the range-collapsing logic ever mangles a boundary.
    """
    _, script_ranges = gen.collect()

    def script_id_of(cp):
        for lo, hi, sid in script_ranges:
            if lo <= cp <= hi:
                return sid
        return gen.SCRIPT_IDS["OTHER"]

    cases = [
        (0x0061, "LATIN"),      # a
        (0x0430, "CYRILLIC"),   # looks exactly like "a"
        (0x03BF, "GREEK"),      # looks exactly like "o"
        (0x0561, "ARMENIAN"),
        (0x13A0, "CHEROKEE"),
        (0x00E9, "LATIN"),      # e-acute: Latin, NOT a confusable
    ]
    for cp, expected in cases:
        assert script_id_of(cp) == gen.SCRIPT_IDS[expected], (
            f"U+{cp:04X} classified as id {script_id_of(cp)}, expected {expected} "
            f"(id {gen.SCRIPT_IDS[expected]}). Python says "
            f"{gen.script_of(cp)!r}."
        )
        # And the table must agree with the function it was generated from.
        assert gen.script_of(cp) == expected, (
            f"generator's script_of disagrees with the expectation for U+{cp:04X}"
        )


# ---------------------------------------------------------------------------
# 🔴 DIRECTION. Added 2026-08-12 after CI had been red on EVERY push for two days.
#
# The parity test above compares CONTENT, and content equality cannot tell apart
# two conditions that demand opposite actions:
#
#     table behind interpreter  -> Unicode advanced.  REGENERATE.
#     interpreter behind table  -> wrong Python.      REFUSE.
#
# CI pinned 3.12 (Unicode 15.0.0) against a table generated from 16.0.0, so it
# reported the second as the first, with a remediation naming `py -3.14` -- the
# Windows launcher, absent on the Linux runner printing it. The reachable
# substitute regenerated against the older database: exit 0, "wrote ...", 353
# code points discarded, and the downgraded table then PASSED --check.
#
# These tests exist because the recorded version was already in the file, under
# a comment saying it was there "so a mismatch is diagnosable", and nothing read
# it. Assert the mechanism, not the constant.
# ---------------------------------------------------------------------------


def _mirror_generator(tmp_path, recorded_version):
    """A throwaway tree with the real generator and a table claiming a version.

    OUT_PATH is derived from __file__, so mirroring the layout redirects every
    write into tmp_path. The real committed table is never touched.
    """
    tools = tmp_path / "tools"
    src = tmp_path / "rust" / "praetor-core" / "src"
    tools.mkdir(parents=True)
    src.mkdir(parents=True)
    shutil.copy2(gen.__file__, tools / "gen_unicode_tables.py")

    table = gen.render().replace(
        f'pub const UNICODE_VERSION: &str = "{unicodedata.unidata_version}";',
        f'pub const UNICODE_VERSION: &str = "{recorded_version}";',
    )
    assert f'"{recorded_version}"' in table, "fixture did not arm: version not substituted"
    out = src / "unicode_tables.rs"
    out.write_text(table, encoding="utf-8")
    return tools / "gen_unicode_tables.py", out


def test_a_table_from_a_newer_unicode_is_not_reported_as_stale():
    """The distinction the old check could not make."""
    newer = gen.render().replace(
        f'pub const UNICODE_VERSION: &str = "{unicodedata.unidata_version}";',
        'pub const UNICODE_VERSION: &str = "99.0.0";',
    )
    assert gen.interpreter_is_behind(newer), (
        "a table recording Unicode 99.0.0 must be recognised as AHEAD of this "
        "interpreter -- otherwise regenerating here silently discards code points"
    )
    older = gen.render().replace(
        f'pub const UNICODE_VERSION: &str = "{unicodedata.unidata_version}";',
        'pub const UNICODE_VERSION: &str = "1.0.0";',
    )
    assert not gen.interpreter_is_behind(older), (
        "a genuinely stale table must stay on the regenerate path"
    )


def test_an_unreadable_version_header_falls_back_to_regenerate_not_refuse():
    """Unprovable direction must not block a legitimate regeneration.

    The fail-safe direction here is the opposite of the scanner's: an unreadable
    header should yield a diagnosable STALE, never a table nobody can update.
    """
    assert gen.recorded_version("no version constant here") is None
    assert gen.interpreter_is_behind("no version constant here") is False


def test_the_write_path_refuses_to_downgrade_the_committed_table(tmp_path):
    """🔴 BEHAVIOURAL. Drives the real generator, not the predicate.

    A unit test of `interpreter_is_behind` cannot notice it being unplugged from
    `main()` -- which is exactly how the original defect survived: the version
    constant existed and no code path consulted it.
    """
    script, table = _mirror_generator(tmp_path, "99.0.0")
    before = table.read_text(encoding="utf-8")

    r = subprocess.run([sys.executable, str(script)],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace")

    assert r.returncode == 2, (
        f"regenerating against an older Unicode database must REFUSE (exit 2), "
        f"got {r.returncode}.\nstdout: {r.stdout}\nstderr: {r.stderr}"
    )
    assert table.read_text(encoding="utf-8") == before, (
        "the generator rewrote a table built from a NEWER Unicode version -- "
        "this is the silent downgrade the refusal exists to prevent"
    )
    assert "--allow-downgrade" in r.stderr, "the refusal must name its own override"


def test_the_check_mode_says_wrong_interpreter_not_stale(tmp_path):
    """The message is the fix: 'stale' sends the reader to destroy the table."""
    script, _ = _mirror_generator(tmp_path, "99.0.0")

    r = subprocess.run([sys.executable, str(script), "--check"],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace")

    assert r.returncode == 2, f"expected exit 2, got {r.returncode}: {r.stderr}"
    assert "WRONG INTERPRETER" in r.stderr
    assert "STALE" not in r.stderr, (
        "reporting this as STALE is what sent a CI operator to regenerate and "
        "silently drop code points"
    )


def test_the_remediation_names_something_runnable_on_the_platform_printing_it():
    """`py` is the Windows launcher. The old message named it unconditionally,
    and was being printed by a Linux runner where it does not exist."""
    hint = gen.required_interpreter_hint("16.0.0")
    assert "16.0.0" in hint, "the hint must name the requirement, not just a launcher"
    if sys.platform == "win32":
        assert "py -3.14" in hint
    else:
        assert "py -3.14" not in hint, (
            "naming the Windows launcher on a non-Windows platform is the "
            "original defect: advice that cannot run where it is printed"
        )
