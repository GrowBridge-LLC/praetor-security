"""
Two ways a credential sat in plain sight and no rule could see it.

Both were found by an audit sent to look for something else, which is the
recurring shape here: a blind spot survives because nobody asked the question
that reveals it, not because anyone decided it was acceptable.
"""

import os
import subprocess
import sys
import json

import engine_secrets

_PRAETOR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "praetor.py"
)

# Assembled from parts, tied to no account.
_AWS_KEY = "AKIA" + "QWERTYUIOPASDFGH"
_VALUE = "Xk7Qz2Rm9Xb4Tp8Nv6Lw3Hc5"


def _scan(tmp_path):
    proc = subprocess.run(
        [sys.executable, _PRAETOR, str(tmp_path), "--engines", "secrets",
         "--no-registry", "--format", "json", "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return json.loads(proc.stdout)


# --------------------------------------------------------------------------- #
# UTF-16 with no byte-order mark
# --------------------------------------------------------------------------- #

def test_a_credential_in_bom_less_utf16_is_found(tmp_path):
    """🔴 THE DEMONSTRATED MISS, and it is an ORDINARY file on Windows.

    PowerShell 5.1's `Out-File` and `Set-Content` write UTF-16LE with no BOM by
    default. Those bytes decode cleanly as UTF-8 -- `A\\x00W\\x00S\\x00` -- so
    nothing raises, nothing is recorded unreadable, and every pattern fails
    because a NUL sits between each pair of letters.

    The report even said the file was "retained for text scanning".
    """
    (tmp_path / "credentials.txt").write_bytes(
        f"AWS_ACCESS_KEY_ID={_AWS_KEY}\r\n".encode("utf-16-le")
    )
    data = _scan(tmp_path)
    assert any(f["rule_id"] == "aws-access-key-id" for f in data["findings"])


def test_the_utf8_control_still_works(tmp_path):
    """THE POSITIVE CONTROL. Without it, a green result above could mean the
    decoder change broke ordinary files and the fixture never triggered."""
    (tmp_path / "credentials.txt").write_text(
        f"AWS_ACCESS_KEY_ID={_AWS_KEY}\n", encoding="utf-8"
    )
    data = _scan(tmp_path)
    assert any(f["rule_id"] == "aws-access-key-id" for f in data["findings"])


def test_utf16_big_endian_is_covered_too():
    """Fixing only the byte order the audit demonstrated would be the narrowest
    possible scope, and would feel like the whole class from the inside."""
    from core import _decode_if_utf16_without_bom
    text = f"AWS_ACCESS_KEY_ID={_AWS_KEY}\r\n"
    assert _AWS_KEY in (_decode_if_utf16_without_bom(text.encode("utf-16-le")) or "")
    assert _AWS_KEY in (_decode_if_utf16_without_bom(text.encode("utf-16-be")) or "")


def test_ordinary_utf8_is_not_mistaken_for_utf16():
    """THE KEEP DIRECTION. Misdetecting UTF-8 as UTF-16 would corrupt every
    file in every scan, which is far worse than the miss being fixed."""
    from core import _decode_if_utf16_without_bom
    assert _decode_if_utf16_without_bom(b"a normal ASCII line of source code\n") is None
    assert _decode_if_utf16_without_bom("# a comment with unicode: éè\n".encode()) is None


def test_binary_noise_is_not_mistaken_for_utf16():
    """A file full of NULs at BOTH offset classes is binary, not UTF-16. The
    check requires the other class to be nearly NUL-free for exactly this."""
    from core import _decode_if_utf16_without_bom
    assert _decode_if_utf16_without_bom(b"\x00" * 4096) is None


# --------------------------------------------------------------------------- #
# The generic keyword pass could not match a JSON key
# --------------------------------------------------------------------------- #

def test_the_generic_pass_matches_a_json_key():
    """🔴 EVERY `{"password": "..."}` IN EVERY SCANNED TREE WAS INVISIBLE to
    this pass. It required the name to be followed immediately by `\\s*[:=]`,
    and JSON puts a closing quote in between."""
    m = engine_secrets.GENERIC.search('{"password": "%s"}' % _VALUE)
    assert m and engine_secrets._generic_value(m) == _VALUE


def test_the_generic_pass_matches_an_unquoted_value():
    """A YAML or `.env` value carries no quotes, and the old pattern required
    them on the value as well."""
    for line in (f"api_token: {_VALUE}", f"API_KEY={_VALUE}"):
        m = engine_secrets.GENERIC.search(line)
        # ⚠️ `_generic_value`, not `m.group("secret")`. The quoted and unquoted
        # branches carry DIFFERENT group names, because Python forbids two
        # groups with one name -- so a reader of `secret` alone silently drops
        # every unquoted match. This test read it directly and went red, which
        # is the same mistake a call site would make.
        assert m and engine_secrets._generic_value(m) == _VALUE, line


def test_the_generic_pass_still_matches_a_plain_assignment():
    """THE KEEP DIRECTION. The shape that always worked must keep working."""
    m = engine_secrets.GENERIC.search(f'password = "{_VALUE}"')
    assert m and engine_secrets._generic_value(m) == _VALUE


def test_the_generic_pass_does_not_swallow_prose():
    """🔴 THE COST OF ADMITTING UNQUOTED VALUES, bounded on purpose. Allowing an
    unquoted value without stopping at whitespace would turn every sentence
    containing the word `password:` into a finding -- trading one blind spot for
    a flood of noise, which hides real findings just as effectively."""
    m = engine_secrets.GENERIC.search(
        "The password: is stored in the vault by the operator"
    )
    assert m is None


def test_the_generic_pass_does_not_match_ordinary_code():
    """🔴 THE FALSE-POSITIVE FLOOD, CAUGHT BY THE SELF-SCAN.

    Making the value's quotes simply optional matched source code: the pin went
    from 32 active findings to 68, twenty-five of them shapes like these, nine
    in one file. The quotes were not incidental -- they were what kept this
    pattern out of code.
    """
    for line in (
        "secrets_n = int(x)",
        'secret = match.group("secret")',
        "py_secrets = python_core()",
        "_SECRETS_CORPUS = os.path.join(a, b)",
        "let token = capture.select(y);",
    ):
        m = engine_secrets.GENERIC.search(line)
        assert not (m and engine_secrets._generic_value(m)), line
