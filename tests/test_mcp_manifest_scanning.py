"""
MCP manifest scanning (A4).

An MCP server is a process the agent starts automatically at load and then trusts
for the whole session -- the same load-time execution risk as an auto-run hook,
with a longer lifetime and a wider tool surface. Nothing covered this surface
before; `grep -c mcpServers scripts/engine_aisec.py` returned 0.

🔴 The first test is the one that matters most. This scanner keys on PARSED JSON
STRUCTURE, never on the string "mcpServers", because documentation about MCP
contains that string constantly. A substring match would flag every doc discussing
the feature -- the self-noise class this repo has demonstrated on its own tree four
separate times, including in the sentence warning about it.
"""

import engine_aisec


def _scan(text, rel="config.json"):
    return engine_aisec._scan_mcp(text, rel)


def _ids(findings):
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------- #
# the self-noise guard
# --------------------------------------------------------------------------- #

def test_prose_about_mcpServers_is_not_a_finding():
    """Documentation mentioning the key must never be flagged."""
    doc = (
        "# Configuring MCP\n"
        "Add an `mcpServers` block to your config. Each entry needs a `command`\n"
        'and optional `args`. Example: "mcpServers": { ... }\n'
    )
    assert _scan(doc, "docs/mcp-guide.md") == [], (
        "SELF-NOISE REGRESSION: prose describing mcpServers was flagged. The scanner "
        "must require parsed JSON structure, not the substring."
    )


def test_unparseable_config_yields_nothing():
    """Fail safe: what cannot be parsed is not evidence of anything."""
    assert _scan('{"mcpServers": { broken json', ".mcp.json") == []


def test_mcpServers_present_but_not_an_object_is_ignored():
    assert _scan('{"mcpServers": "see docs"}', ".mcp.json") == []


# --------------------------------------------------------------------------- #
# real detections
# --------------------------------------------------------------------------- #

def test_local_server_is_flagged_as_autostart():
    cfg = '{"mcpServers": {"files": {"command": "node", "args": ["./server.js"]}}}'
    found = _scan(cfg, ".mcp.json")
    assert _ids(found) == {"mcp-server-autostart"}
    assert found[0].severity.name == "MEDIUM"


def test_remote_or_unpinned_source_escalates():
    """`@latest` means what runs can change without the config changing."""
    cfg = '{"mcpServers": {"x": {"command": "npx", "args": ["-y", "some-server@latest"]}}}'
    found = _scan(cfg, ".mcp.json")
    assert "mcp-server-autostart-remote" in _ids(found)
    remote = next(f for f in found if f.rule_id == "mcp-server-autostart-remote")
    assert remote.severity.name == "HIGH"


def test_credential_env_is_flagged_separately():
    cfg = (
        '{"mcpServers": {"gh": {"command": "node", "args": ["s.js"],'
        ' "env": {"GITHUB_TOKEN": "x", "LOG_LEVEL": "debug"}}}}'
    )
    found = _scan(cfg, ".mcp.json")
    assert "mcp-server-credential-env" in _ids(found)
    cred = [f for f in found if f.rule_id == "mcp-server-credential-env"][0]
    assert "GITHUB_TOKEN" in cred.snippet
    assert "LOG_LEVEL" not in cred.snippet, "a non-credential env var must not be reported as one"


def test_recognised_by_filename_even_without_the_key_quoted():
    """claude_desktop_config.json is a known manifest name."""
    cfg = '{"mcpServers": {"a": {"command": "python", "args": ["-m", "srv"]}}}'
    assert _scan(cfg, "claude_desktop_config.json") != []


def test_server_without_a_command_is_not_invented():
    assert _scan('{"mcpServers": {"a": {"description": "no command here"}}}', ".mcp.json") == []
