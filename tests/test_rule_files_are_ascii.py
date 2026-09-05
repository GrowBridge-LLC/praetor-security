"""
Bundled rule files must be pure ASCII.

🔴 SEMGREP READS ITS CONFIG WITH THE LOCALE CODEC, NOT UTF-8. Writing this
repository's ordinary house-style warning glyph into a rule file's header made
semgrep die before loading a single rule:

    'charmap' codec can't decode byte 0x8f in position 476

The whole `sast` engine went to `error`. The gate caught it — but only because an
engine in `error` fails the run, not because anything checked the file.

⚠️ THE FIRST EXPLANATION OF THIS WAS WRONG, AND THE WRONG VERSION WAS ALREADY
WRITTEN DOWN. "Non-ASCII breaks semgrep" is not the mechanism, and a 🔴 sitting
in this same file at offset 9337 for weeks disproves it. Measured on this
machine:

    cp1252 leaves exactly five bytes undefined: 0x81 0x8d 0x8f 0x90 0x9d
    U+26A0 U+FE0F  ->  e2 9a a0 ef b8 8f   contains 0x8f  ->  CRASH
    U+1F534        ->  f0 9f 94 b4         contains none  ->  silent mojibake

So one emoji kills the engine and another is merely garbled. **Which glyph you
happen to type decides whether the scanner runs.**

⇒ The guard is still ASCII-only, deliberately, and not "avoid those five bytes".
A byte-specific rule would be tied to cp1252; another machine's locale leaves a
different set undefined. ASCII is the only property that holds everywhere, and
it also removes the silent-mojibake case, which is not a crash but is not right
either.

⚠️ THE TRAP IS THAT THE FILE LOOKS FINE. `yaml.safe_load` parses it without
complaint and reports all 15 rules present. Only semgrep disagrees, and only on a
machine whose locale codec is not UTF-8. On a UTF-8 machine this file would be
green and the rule pack would break for Windows users.

⚠️ AND THE HOUSE STYLE PULLS YOU STRAIGHT INTO IT. Every other file here uses
🔴 and ⚠️ freely, so the natural thing to write in a rule file is the thing that
breaks it. That is why this is a test and not a note.

Same class as this repository's recorded lesson about `subprocess(text=True)`
with no `encoding=`: a decode that silently uses the platform codec.
"""

import pathlib

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_RULES = _ROOT / "rules"


def _rule_files():
    return sorted(p for p in _RULES.rglob("*")
                  if p.is_file() and p.suffix in (".yaml", ".yml"))


def test_there_are_rule_files_to_check():
    """🔴 THE POSITIVE CONTROL. Without it, deleting or renaming the rules
    directory would make every assertion below pass over an empty list — a green
    test proving nothing, which is the failure mode this whole repository is
    built to avoid."""
    files = _rule_files()
    assert files, f"no rule files found under {_RULES}"
    assert any(p.name == "semgrep-praetor.yaml" for p in files), \
        "the bundled pack is missing; this test would otherwise pass vacuously"


def test_every_bundled_rule_file_is_pure_ascii():
    """The one that would have caught it."""
    offenders = []
    for path in _rule_files():
        data = path.read_bytes()
        bad = [(i, hex(b)) for i, b in enumerate(data) if b > 127]
        if bad:
            offset = bad[0][0]
            context = data[max(0, offset - 40):offset + 10]
            offenders.append(
                f"{path.relative_to(_ROOT)}: {len(bad)} non-ASCII byte(s), "
                f"first at offset {offset} near "
                f"{context.decode('utf-8', 'replace')!r}")
    assert not offenders, (
        "semgrep reads its config with the LOCALE codec, so a non-ASCII byte "
        "here kills the whole sast engine on a non-UTF-8 machine:\n  "
        + "\n  ".join(offenders))


def test_the_rule_pack_still_declares_its_licence():
    """⚠️ AN ASCII-ONLY RULE IS EASY TO SATISFY BY DELETING PROSE. The header
    carries the licence, and the licence is not decoration: the pack is MIT while
    PRAETOR itself is AGPL-3.0, deliberately, so the rules stay reusable by a
    hosted service without section 13 reaching them."""
    header = (_RULES / "semgrep-praetor.yaml").read_text(encoding="ascii")[:2000]
    assert "License: MIT" in header
    assert "AGPL-3.0" in header, (
        "the header must say what PRAETOR's own licence is, because the phrase "
        "it replaced -- 'MIT (same as PRAETOR)' -- was false after relicensing")
