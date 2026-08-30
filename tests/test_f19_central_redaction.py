"""F19: provider-recognised credentials are masked for every engine."""

import os
import sys
import hashlib
import string

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from core import Finding


_ALPHABET = string.ascii_letters + string.digits


def _token(seed: bytes) -> str:
    """Create a deterministic provider-shaped fixture only at runtime."""
    digest = hashlib.sha256(seed).digest()
    return "sk-" + "ant-" + "".join(_ALPHABET[b % len(_ALPHABET)] for b in digest[:32])


TOKEN = _token(b"f19-central-redaction")


def test_engine_snippets_are_redacted_at_finding_boundary():
    for engine in ("secrets", "aisec", "sast", "sca"):
        finding = Finding(
            engine=engine, rule_id="fixture", title="fixture", severity="HIGH",
            snippet=f'curl -H "Authorization: Bearer {TOKEN}" https://example.test',
        )
        assert TOKEN not in finding.snippet
        assert "sk-a" in finding.snippet
        assert "len=" in finding.snippet


def test_unknown_credential_format_is_explicitly_out_of_scope():
    unknown = "-".join(("vendor", "secret", "format")) + "-" + "_".join(
        ("THIS", "IS", "NOT", "A", "PROVIDER", "PATTERN")
    )
    finding = Finding(
        engine="aisec", rule_id="fixture", title="fixture", severity="HIGH",
        snippet=unknown,
    )
    assert unknown in finding.snippet
