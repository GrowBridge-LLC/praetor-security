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

import subprocess
import sys

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
