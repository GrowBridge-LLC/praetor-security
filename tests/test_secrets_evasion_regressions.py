"""
Regression tests for two evasions a breaker audit demonstrated live.

Both produced the failure this tool exists to prevent: PRAETOR exited 0 on a
tree that held a live-shaped credential, and the report read as a complete
clean scan.

⚠️ Every credential-shaped string below is ASSEMBLED FROM PARTS. A literal one
would be found by PRAETOR's own self-scan, and this repository's rules say to
fix the fixture rather than exempt the directory -- exempting `tests/` would
also exempt a real credential committed to a test file, one of the commonest
real leaks there is.
"""

import base64
import os

import engine_secrets
from core import ScanFile


# Assembled, never written whole. Structurally valid, tied to no account.
_AWS_KEY = "AKIA" + "QWERTYUIOPASDFGH"
_ANTHROPIC_KEY = "sk-" + "ant-" + "api03-" + ("Kf7Qz2Rm9Xb4Tp8Nv6Lw3Hc5Ja1Yd" * 2)[:30]
_PAD = "x" * 5000


def _scan_text(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    sf = ScanFile(abspath=str(p), relpath=name, size=os.path.getsize(p))
    return engine_secrets.scan(
        [sf], lambda path: open(path, encoding="utf-8").read()
    )


def _rule_ids(findings):
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------- #
# Break 1: pad the line, hide the credential
# --------------------------------------------------------------------------- #

def test_a_credential_on_a_very_long_line_is_still_found(tmp_path):
    """🔴 THE DEMONSTRATED EVASION. Padding a line past the analysis cap made
    every secrets check skip it. `--fail-on HIGH` returned exit 0 with a
    live-shaped AWS key in the tree, and the only trace was an INFO coverage
    note, which gates nothing.
    """
    findings = _scan_text(tmp_path, "config.py", f'KEY = "{_AWS_KEY}"  # {_PAD}\n')
    assert "aws-access-key-id" in _rule_ids(findings), \
        "an anchored provider rule must still reach a padded line"


def test_the_credential_is_found_even_when_the_padding_comes_first(tmp_path):
    """The attacker chooses where to pad. Front-padding pushes the credential
    past the first window, so this fails unless the whole line is windowed."""
    findings = _scan_text(tmp_path, "config.py", f'# {_PAD}\nX = "{_AWS_KEY}"\n')
    assert "aws-access-key-id" in _rule_ids(findings)

    same_line = f'# {_PAD} KEY = "{_AWS_KEY}"\n'
    findings = _scan_text(tmp_path, "config2.py", same_line)
    assert "aws-access-key-id" in _rule_ids(findings), \
        "padding BEFORE the credential must not push it out of every window"


def test_a_credential_straddling_a_window_boundary_is_still_whole_in_one(tmp_path):
    """The reason the windows overlap. A credential landing exactly on a
    boundary would be cut in half by every window if they abutted."""
    # ⚠️ Padded with a NON-WORD character on purpose. The provider regex is
    # anchored with \b, so padding with a letter would make this test fail for
    # a reason that has nothing to do with windowing -- a fixture bug that
    # looks exactly like the defect it is meant to catch.
    boundary = engine_secrets._LINE_CAP - len(_AWS_KEY) // 2
    line = "-" * boundary + _AWS_KEY + "-" * 3000
    findings = _scan_text(tmp_path, "config.py", line + "\n")
    assert "aws-access-key-id" in _rule_ids(findings)


def test_the_long_line_coverage_note_states_what_actually_ran(tmp_path):
    """THE HONESTY DIRECTION. The unanchored passes really are still capped, so
    the note must say so -- and must no longer claim the line was skipped."""
    findings = _scan_text(tmp_path, "config.py", f'KEY = "{_AWS_KEY}"  # {_PAD}\n')
    note = next(f for f in findings if f.rule_id == "secrets-long-line-skip")
    assert "anchored_rules=ran" in note.snippet
    assert "unanchored_rules=skipped" in note.snippet


# --------------------------------------------------------------------------- #
# Break 2: base64-wrap a provider the marker list never named
# --------------------------------------------------------------------------- #

def test_base64_unwrap_asks_the_provider_rules_not_a_marker_list(tmp_path):
    """🔴 THE DEMONSTRATED EVASION. The unwrap recognised six hand-written
    marker strings, so every other provider was invisible once base64-wrapped.
    The audit proved it with an Anthropic-shaped key: zero findings, exit 0,
    and the capability profile then reported `holds_credentials: none`.
    """
    blob = base64.b64encode(_ANTHROPIC_KEY.encode()).decode()
    findings = _scan_text(tmp_path, "settings.yaml", f"api_token: {blob}\n")
    assert "base64-wrapped-secret" in _rule_ids(findings), \
        "a wrapped provider key must be found by asking the provider rules"


def test_the_unwrap_still_finds_the_structural_shapes(tmp_path):
    """THE KEEP DIRECTION. A PEM block matches no provider TOKEN pattern -- it
    is recognised by its structure. Replacing the marker list with the provider
    rules must not have dropped it."""
    pem = "-----BEGIN" + " RSA PRIVATE KEY-----\n" + "A" * 64 + "\n"
    blob = base64.b64encode(pem.encode()).decode()
    findings = _scan_text(tmp_path, "key.txt", f"data: {blob}\n")
    assert "base64-wrapped-secret" in _rule_ids(findings)


def test_the_unwrap_does_not_fire_on_ordinary_base64(tmp_path):
    """THE KEEP DIRECTION, other half. Widening the unwrap must not turn every
    base64 blob into a credential report."""
    blob = base64.b64encode(("the quick brown fox " * 20).encode()).decode()
    findings = _scan_text(tmp_path, "data.yaml", f"payload: {blob}\n")
    assert "base64-wrapped-secret" not in _rule_ids(findings)


def test_the_unwrap_decodes_one_level_only(tmp_path):
    """THE STATED BOUND. Following attacker-chosen nesting to an attacker-chosen
    depth is not a fix. Double-wrapping is a disclosed gap, and this test exists
    so the bound is a decision on record rather than an accident."""
    once = base64.b64encode(_ANTHROPIC_KEY.encode()).decode()
    twice = base64.b64encode(once.encode()).decode()
    findings = _scan_text(tmp_path, "settings.yaml", f"api_token: {twice}\n")
    assert "base64-wrapped-secret" not in _rule_ids(findings)
