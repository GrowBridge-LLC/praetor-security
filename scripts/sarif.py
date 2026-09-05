"""
SARIF 2.1.0 output -- the interchange format GitHub code scanning, GitLab,
SonarQube, Azure DevOps and DefectDojo all consume.

⚠️ THIS IS A FLOOR, NOT A LEVER, and the honest framing matters because it sets
expectations. Research into how comparable scanners actually got adopted found
NO case where SARIF support caused an adoption inflection. What it does is remove
a reason to be excluded: one artifact reaches five ecosystems, upload is free and
self-serve, and without it PRAETOR cannot appear in a repository's Security tab
at all.

🔴 FINGERPRINTS ARE THE POINT, NOT AN EXTRA. GitHub explicitly warns that SARIF
without fingerprint data produces DUPLICATE ALERTS ON EVERY SCAN -- which makes a
scanner unusable in a pull-request loop, because every run re-opens everything.
`Finding.fingerprint` was built line-independent for the dashboard, and that is
exactly the property `partialFingerprints` needs. The hard half was already done
for a different reason.

⚠️ WHAT THIS DELIBERATELY DOES NOT DO. It does not emit `fixes` (SARIF's
machine-applicable patch format). PRAETOR's `fix` field is human guidance --
"rotate the key", "pin the version" -- not a patch, and rendering advice into a
field consumers may APPLY would be an overclaim with a blast radius.
"""

from __future__ import annotations

import json

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

#: PRAETOR severity -> SARIF level.
#:
#: SARIF has four levels and PRAETOR has five severities, so the mapping is
#: lossy in one direction and that is stated rather than hidden: CRITICAL and
#: HIGH both become `error`. The original severity survives in
#: `properties.severity`, and `rank` carries the ordering, so a consumer that
#: cares can recover the distinction.
#:
#: ⚠️ NOTHING MAPS TO SARIF's `none`. `none` means "not a problem", and PRAETOR
#: does not emit findings it considers unproblematic -- an INFO coverage note is
#: still telling you something was not examined. Mapping INFO to `none` would
#: hand consumers a reason to hide exactly the notes that say the scan was
#: incomplete.
_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

#: SARIF `rank` is 0.0-100.0, higher is worse. Recovers the CRITICAL/HIGH
#: distinction that `level` collapses.
_RANK = {"CRITICAL": 100.0, "HIGH": 80.0, "MEDIUM": 50.0, "LOW": 20.0, "INFO": 5.0}


def _rule_descriptor(finding: dict) -> dict:
    """One SARIF reportingDescriptor, built from a finding that used the rule."""
    rule = {
        "id": finding["rule_id"],
        "name": finding["rule_id"],
        "shortDescription": {"text": finding.get("title") or finding["rule_id"]},
        "fullDescription": {"text": finding.get("description") or finding.get("title") or ""},
        "defaultConfiguration": {
            "level": _LEVEL.get(finding.get("severity"), "warning"),
        },
        "properties": {
            "engine": finding.get("engine"),
            "category": finding.get("category"),
        },
    }
    tags = []
    if finding.get("cwe"):
        tags.append(f"external/cwe/{finding['cwe'].lower()}")
    if finding.get("owasp"):
        tags.append(finding["owasp"])
    if finding.get("engine"):
        tags.append(f"praetor/{finding['engine']}")
    if tags:
        rule["properties"]["tags"] = tags
    refs = finding.get("references") or []
    if refs:
        rule["helpUri"] = refs[0]
    # `help` is what GitHub renders in the alert body. Give it the remediation,
    # because an alert a reader cannot act on is noise however accurate it is.
    if finding.get("fix"):
        rule["help"] = {"text": finding["fix"]}
    return rule


def _result(finding: dict) -> dict:
    """One SARIF result."""
    severity = finding.get("severity", "MEDIUM")
    # 🔴 A LINE OF 0 OR LESS IS INVALID SARIF -- `startLine` is 1-based and
    # consumers reject or mis-render anything else. Several PRAETOR findings are
    # whole-file facts (a coverage note, a model-file verdict) and legitimately
    # have no line, so they are clamped to 1 rather than dropped: losing the
    # finding to satisfy a schema would be the wrong trade.
    line = finding.get("line") or 1
    if line < 1:
        line = 1

    result = {
        "ruleId": finding["rule_id"],
        "level": _LEVEL.get(severity, "warning"),
        "rank": _RANK.get(severity, 50.0),
        "message": {"text": finding.get("description") or finding.get("title") or finding["rule_id"]},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    # SARIF wants a URI-style relative path. PRAETOR already
                    # normalises to forward slashes, but a Windows-produced
                    # report can still carry backslashes from a caller.
                    "uri": (finding.get("file") or "").replace("\\", "/"),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {"startLine": line},
            },
        }],
        "properties": {
            "severity": severity,
            "confidence": finding.get("confidence"),
            "engine": finding.get("engine"),
            "category": finding.get("category"),
        },
    }

    # 🔴 THE FIELD THAT MAKES THIS USABLE IN A PR LOOP. Without it GitHub opens a
    # duplicate alert on every scan, because it has nothing stable to match on.
    if finding.get("fingerprint"):
        result["partialFingerprints"] = {"praetorFingerprint/v1": finding["fingerprint"]}

    snippet = finding.get("snippet")
    if snippet:
        # Already redacted at the Finding boundary -- a SARIF file is uploaded to
        # a third party, so this is a disclosure boundary, not a nicety.
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": snippet}

    # ⚠️ A SUPPRESSED FINDING IS EMITTED, NOT DROPPED, and SARIF has a first-class
    # way to say so. Dropping it would make PRAETOR's filtered bucket invisible
    # to every consumer -- and the whole point of that bucket is that suppression
    # is auditable.
    if finding.get("filtered"):
        result["suppressions"] = [{
            "kind": "external",
            "justification": finding.get("filter_reason") or "filtered by PRAETOR",
        }]
    return result


def render_sarif(result: dict, meta: dict) -> str:
    """Render a full SARIF 2.1.0 log for one scan."""
    findings = list(result.get("active") or [])
    filtered = list(result.get("filtered") or [])

    def as_dict(f):
        return f if isinstance(f, dict) else f.to_dict()

    all_findings = [as_dict(f) for f in findings] + [as_dict(f) for f in filtered]

    # One descriptor per rule, first occurrence wins.
    rules: dict = {}
    for f in all_findings:
        rules.setdefault(f["rule_id"], _rule_descriptor(f))

    driver = {
        "name": "PRAETOR",
        "version": meta.get("version", ""),
        "semanticVersion": meta.get("version", ""),
        "informationUri": "https://github.com/GrowBridge-LLC/praetor-security",
        "rules": list(rules.values()),
    }

    invocation = {
        # 🔴 `executionSuccessful` IS NOT "no findings". It says the TOOL ran
        # correctly. A scan that could not measure the tree must report false
        # here, or a consumer reading this field learns nothing -- which is the
        # same false-clean this project exists to prevent, one layer out.
        "executionSuccessful": not _scan_was_degraded(meta),
        "endTimeUtc": meta.get("timestamp"),
    }
    if meta.get("duration_seconds") is not None:
        invocation["properties"] = {"durationSeconds": meta["duration_seconds"]}

    run = {
        "tool": {"driver": driver},
        "results": [_result(f) for f in all_findings],
        "invocations": [invocation],
        "properties": {
            # Everything a consumer needs to judge whether the zero means
            # anything, carried through rather than lost in translation.
            "praetorSchemaVersion": meta.get("schema_version"),
            "engines": meta.get("engines"),
            "scope": meta.get("scope"),
            "provenance": meta.get("provenance"),
        },
    }

    prov = meta.get("provenance") or {}
    if prov.get("commit"):
        run["versionControlProvenance"] = [{
            "repositoryUri": prov.get("repo") or "",
            "revisionId": prov["commit"],
            "branch": prov.get("branch") or "",
        }]

    return json.dumps(
        {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]},
        indent=2, ensure_ascii=False,
    )


def _scan_was_degraded(meta: dict) -> bool:
    """True when any engine could not measure what it was asked to.

    Mirrors `core.GATE_TRUSTED_STATUSES`: anything outside that set -- including
    a status word this function has never heard of -- is a blind spot. Failing
    toward `executionSuccessful: false` is the safe direction, because a
    consumer reading `true` will treat the run as authoritative.
    """
    engines = meta.get("engines") or {}
    trusted = {"ok", "not-applicable", "disabled"}
    for info in engines.values():
        status = (info or {}).get("status")
        if status not in trusted:
            return True
    return False
