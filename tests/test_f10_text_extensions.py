"""Reach-proving fixtures for the F10 text-extension tranche.

Each suffix is exercised through ``core.walk_files`` (not just set
membership) and then passed to the text engine with a detectable coverage
finding.  A removed extension or a walker regression therefore turns this
test red.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import core
import engine_aisec


def test_f10_extensions_are_reached_by_walker_and_engine(tmp_path):
    payload = "x" * 6001 + "\n"
    suffixes = (".csv", ".log", ".out", ".ndjson", ".har")
    for suffix in suffixes:
        (tmp_path / ("fixture" + suffix)).write_text(payload, encoding="utf-8")

    files = core.walk_files(str(tmp_path))
    assert {os.path.splitext(f.relpath)[1] for f in files} == set(suffixes)
    findings = engine_aisec.scan(
        files, lambda path: open(path, encoding="utf-8").read()
    )
    reached = {os.path.splitext(f.file)[1] for f in findings if f.category == "COVERAGE"}
    assert reached == set(suffixes)
