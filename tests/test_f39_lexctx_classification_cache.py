"""F39: lexical classification is per file, never per finding.

The lexical pass is allowed to suppress only an auditable behavioural finding in
inert text.  Caching must preserve those outcomes and must include file identity:
the same bytes are comments in Markdown but live code in Python.
"""

from types import SimpleNamespace
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import lexctx
import praetor


def _finding(file, line):
    return SimpleNamespace(
        engine="aisec",
        # "EXFIL", not "REMOTE_CODE": the engine emits no such category, and this
        # test is about CACHING, not policy -- it needs a finding the suppression
        # pass will actually consider.
        category="EXFIL",
        file=file,
        line=line,
        filtered=False,
        filter_reason="",
    )


def _uncached_outcomes(source, findings):
    """The pre-cache semantic reference for this real lexical fixture."""
    outcomes = []
    for finding in findings:
        ctx = lexctx.context_of(source, finding.line, finding.file)
        outcomes.append((
            bool(praetor._LEXCTX_REASONS.get(ctx)),
            praetor._LEXCTX_REASONS.get(ctx, ""),
        ))
    return outcomes


def test_f39_classifies_one_file_once_for_many_findings(monkeypatch):
    source = "# inert commentary\nrun_payload()\n"
    findings = [_finding("subject.py", 1) for _ in range(6)]
    calls = []
    original = lexctx.classify_lines

    def counted(text, file_identity):
        calls.append((text, file_identity))
        return original(text, file_identity)

    monkeypatch.setattr(lexctx, "classify_lines", counted)
    praetor._apply_lexical_context(findings, "/tree", lambda _path: source)

    assert calls == [(source, "subject.py")], (
        "F39: classification must happen once per source file, not once per finding"
    )
    assert all(f.filtered for f in findings)
    assert {f.filter_reason for f in findings} == {
        praetor._LEXCTX_REASONS[lexctx.COMMENT]
    }


def test_f39_cache_key_keeps_file_identity_and_outcomes(monkeypatch, tmp_path):
    source = "<!-- inert commentary -->\n"
    findings = [_finding("same.md", 1), _finding("same.py", 1)]
    expected = _uncached_outcomes(source, findings)
    target = tmp_path / "one-source-file"
    target.write_text(source, encoding="utf-8")
    calls = []
    original = lexctx.classify_lines

    def counted(text, file_identity):
        calls.append((text, file_identity))
        return original(text, file_identity)

    monkeypatch.setattr(lexctx, "classify_lines", counted)
    praetor._apply_lexical_context(findings, str(target), lambda _path: source)
    actual = [(f.filtered, f.filter_reason) for f in findings]

    assert actual == expected, "F39 cache changed a lexical suppression verdict"
    assert calls == [(source, "same.md"), (source, "same.py")], (
        "F39 cache key must include file identity, not source text alone"
    )
    assert findings[0].filtered and not findings[1].filtered
