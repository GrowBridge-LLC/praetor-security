"""F19: provider-recognised credentials are masked for every engine."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from core import Finding


TOKEN = "sk-ant-" + "Qr7TzWmK9Le2Vd4Nb8XcJf5Hp3Rt6Yw2"


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
    finding = Finding(
        engine="aisec", rule_id="fixture", title="fixture", severity="HIGH",
        snippet="vendor-secret-format-THIS_IS_NOT_A_PROVIDER_PATTERN",
    )
    assert "vendor-secret-format-THIS_IS_NOT_A_PROVIDER_PATTERN" in finding.snippet
