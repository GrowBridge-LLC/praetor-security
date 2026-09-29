"""
SYSTEMD UNITS AND SUDOERS DROP-INS MUST BE READ. THEY WERE NOT.

MEASURED (2026-09-29): `core.scannable("factory-cred-readback.service")` and
`core.scannable("factory-cred.sudoers")` both returned False, so a scan of a
deployment tree never opened either -- not "scanned and clean", never read.
Both are security-relevant configuration: a unit names what runs, as whom, and
with which credentials; a sudoers drop-in grants privilege. A skipped one is a
blind spot that still exits 0.

The companion half of this change (the `praetor-ai-llm-output-to-shell` rule no
longer firing on `exec` of a constant) needs a REAL semgrep, so it lives in
tests/semgrep_live_check.py, not here: this suite fails on any skip, and the CI
job that runs it installs no tools.
"""

import core


def test_systemd_units_and_sudoers_dropins_are_scannable():
    for name in ("factory-cred-readback.service", "factory-cred.sudoers"):
        assert core.scannable(name), (
            "%s is security-relevant config (what runs as whom / who may escalate) "
            "and must be opened" % name
        )


def test_walker_reports_unit_and_sudoers_as_examined(tmp_path):
    """Reach, not set membership: the walker must actually hand both files over."""
    (tmp_path / "x.service").write_text("[Service]\nExecStart=/bin/true\n",
                                        encoding="utf-8")
    (tmp_path / "y.sudoers").write_text("deploy ALL=(root) NOPASSWD: /bin/true\n",
                                        encoding="utf-8")
    files = core.walk_files(str(tmp_path))
    assert sorted(f.relpath for f in files) == ["x.service", "y.sudoers"]


def test_units_and_sudoers_do_not_count_as_code_for_the_scope_floor(tmp_path):
    """Read as config, never as evidence that code was examined."""
    for name in ("factory-cred-readback.service", "factory-cred.sudoers"):
        assert not core.is_code(name), "%s must not satisfy the scope floor" % name
    (tmp_path / "x.service").write_text("[Service]\n", encoding="utf-8")
    (tmp_path / "y.sudoers").write_text("# none\n", encoding="utf-8")
    stats = {}
    files = core.walk_files(str(tmp_path), stats=stats)
    assert len(files) == 2
    assert stats["kept_code_files"] == 0


def test_widening_did_not_admit_binaries_or_drop_source():
    assert not core.scannable("a.png"), "a binary-ish name must stay unscanned"
    assert core.scannable("a.py"), "source must stay scannable"
