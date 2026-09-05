"""
Every place the version appears must agree, and the CHANGELOG must describe it.

🔴 WHY. The tool version lives in TWO files that no code connects:
`pyproject.toml` (what pip installs) and `scripts/praetor.py` (what
`praetor --version` prints, and what every report's `meta.version` carries).

Nothing asserted they matched. A release cut from a tree where they had drifted
would install as one version and report itself as another — and the report is the
artifact a dashboard stores, so the wrong number would be the one that persisted.

`references/VERSIONING.md` is the policy this file enforces.
"""

import pathlib
import re
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent

sys.path.insert(0, str(_ROOT / "scripts"))

import praetor  # noqa: E402
import report  # noqa: E402

_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _pyproject_version():
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert m, "pyproject.toml has no version -- read it, do not assume"
    return m.group(1)


def test_the_two_version_sources_agree():
    """🔴 THE LOAD-BEARING ONE. pip installs one number and the report carries
    the other; a drift means the artifact a dashboard stores is wrong."""
    assert praetor.VERSION == _pyproject_version(), (
        f"praetor.py says {praetor.VERSION!r}, pyproject.toml says "
        f"{_pyproject_version()!r} -- a release from this tree would install as "
        "one version and report itself as another"
    )


def test_the_version_is_semver():
    """The policy is semantic versioning; a version that cannot be parsed as one
    cannot be compared, sorted or pinned."""
    assert _SEMVER.match(praetor.VERSION), praetor.VERSION


def test_the_schema_version_is_major_minor():
    """`schema_version` is MAJOR.MINOR by policy -- it describes a contract, and
    a contract has no patch level."""
    assert re.match(r"^\d+\.\d+$", report.SCHEMA_VERSION), report.SCHEMA_VERSION


def test_the_changelog_has_a_section_for_this_version():
    """🔴 A RELEASE WITH NO CHANGELOG ENTRY IS A RELEASE NOBODY CAN EVALUATE.

    This is the check that would have caught shipping a version whose changes
    existed only in commit messages -- which is where they live until someone
    writes them down for a reader who was not here.
    """
    text = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = f"## {praetor.VERSION}"
    assert heading in text, (
        f"CHANGELOG.md has no '{heading}' section. Every version gets one before "
        "it is tagged -- see references/VERSIONING.md."
    )


def test_the_current_version_section_is_not_left_under_Unreleased():
    """`Unreleased` must sit ABOVE the current version's section, never contain
    it. If the two are the same thing, the release was never actually cut."""
    text = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if "## Unreleased" not in text:
        return  # a tree with nothing pending is fine
    unreleased_at = text.index("## Unreleased")
    version_at = text.index(f"## {praetor.VERSION}")
    assert unreleased_at < version_at, (
        "the current version's section must come AFTER Unreleased; it appears "
        "before, which means the release heading was never moved"
    )


def test_the_versioning_policy_document_exists():
    """The rules for what MAJOR, MINOR and PATCH mean HERE are not obvious for a
    scanner -- a fixed false negative can turn a green CI job red, and this
    project calls that a PATCH on purpose. That decision has to be written down
    somewhere a maintainer will find it."""
    policy = _ROOT / "references" / "VERSIONING.md"
    assert policy.is_file()
    text = policy.read_text(encoding="utf-8")
    for required in ("MAJOR", "MINOR", "PATCH", "schema_version"):
        assert required in text, f"VERSIONING.md does not cover {required}"


def test_a_widened_suppression_is_never_minor_is_written_down():
    """🔴 THE RULE MOST LIKELY TO BE FORGOTTEN UNDER PRESSURE, so it is asserted
    rather than trusted to memory: widening a suppression makes the tool report
    LESS, which is the failure this project exists to prevent."""
    text = (_ROOT / "references" / "VERSIONING.md").read_text(encoding="utf-8")
    assert "WIDENED is never MINOR" in text
