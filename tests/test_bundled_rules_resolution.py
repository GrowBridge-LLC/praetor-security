"""
The bundled offline Semgrep rules must be findable however PRAETOR was obtained.

This regressed silently once. `RULES_DIR` was hardcoded to `<praetor.py dir>/../rules`,
which is correct from a clone and wrong from a wheel — installed, it resolves to the
environment's lib directory, where nothing exists. `--no-registry` then ran with no
rules at all.

⚠️ It degraded HONESTLY (the engine reported `[skipped] no rules available` rather
than a clean zero), which is why it survived: nothing was ever wrong-looking, the
feature was just absent. A test asserting "the scan succeeded" would still pass today
with the rules missing — so these assert the RESOLUTION, and the ordering that makes
a developer's edits win over an installed copy.
"""

import os
import sys

import praetor


def test_clone_layout_resolves_to_the_repo_rules_dir():
    """From a checkout, the sibling rules/ directory must win."""
    d, f = praetor._find_bundled_rules()
    assert os.path.isfile(f), f"bundled rules not found from a clone: {f}"
    assert os.path.basename(d) == "rules"


def test_env_override_takes_precedence(tmp_path, monkeypatch):
    """A packager must be able to point at a location this list does not anticipate."""
    (tmp_path / "semgrep-praetor.yaml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setenv("PRAETOR_RULES_DIR", str(tmp_path))
    d, _f = praetor._find_bundled_rules()
    assert os.path.normpath(d) == os.path.normpath(str(tmp_path))


def test_installed_layout_is_searched_under_sys_prefix(tmp_path, monkeypatch):
    """
    THE REGRESSION. A wheel installs the rules under sys.prefix/share/praetor/rules;
    if that path is not searched, `--no-registry` silently has no ruleset.
    """
    fake_prefix = tmp_path / "venv"
    installed = fake_prefix / "share" / "praetor" / "rules"
    installed.mkdir(parents=True)
    (installed / "semgrep-praetor.yaml").write_text("rules: []\n", encoding="utf-8")

    monkeypatch.delenv("PRAETOR_RULES_DIR", raising=False)
    monkeypatch.setattr(sys, "prefix", str(fake_prefix))
    # Make the clone-relative candidate miss, so sys.prefix is the only one left.
    monkeypatch.setattr(praetor, "HERE", str(tmp_path / "nowhere" / "scripts"))

    d, f = praetor._find_bundled_rules()
    assert os.path.isfile(f), (
        "PACKAGING REGRESSION: rules installed under sys.prefix/share/praetor/rules "
        f"were not found. --no-registry would run with no ruleset. searched -> {d}"
    )


def test_missing_everywhere_returns_a_path_rather_than_raising(tmp_path, monkeypatch):
    """Absent rules are reported by the SAST engine, not raised here."""
    monkeypatch.delenv("PRAETOR_RULES_DIR", raising=False)
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "empty"))
    monkeypatch.setattr(praetor, "HERE", str(tmp_path / "nowhere" / "scripts"))

    d, f = praetor._find_bundled_rules()
    assert isinstance(d, str) and f.endswith("semgrep-praetor.yaml")
    assert not os.path.isfile(f)
