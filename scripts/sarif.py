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
import re

import core

SARIF_VERSION = "2.1.0"

#: The published schema location.
#:
#: ⚠️ THE OBVIOUS URL 404s. `.../sarif-spec/master/Schemata/...` is the address
#: most examples still carry, and the repository renamed its default branch and
#: moved the directory. A `$schema` that does not resolve makes every validating
#: consumer either reject the file or silently skip validation.
#:
#: The first test written for this asserted `.endswith("sarif-schema-2.1.0.json")`
#: -- which the dead URL also satisfies. **Assert the whole string.** A test that
#: checks the last component of a URL is not checking the URL.
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
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


#: Anything that looks like an absolute filesystem path.
#:
#: 🔴 A SARIF FILE IS UPLOADED TO A THIRD PARTY. `meta.engines[].detail` is built
#: from tool output and exception text, and both carry absolute paths -- which on
#: this machine means `C:\\Users\\Admin\\...`, disclosing the operating-system
#: account name of whoever ran the scan into an artifact that may end up in a
#: public repository's Security tab.
_ABS_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/]|(?<![\w.])/)(?:[^\s\"'<>|]*[\\/])*[^\s\"'<>|]*"
)

#: Credentials that reach SARIF through a route the snippet redactor never sees.
#:
#: ⚠️ A SECRET CAN BE IN THE FILE NAME. `secrets/AKIA<...>.env` is a real shape --
#: a key checked in as a filename. Snippets are redacted at the `Finding`
#: boundary; the `file` field is not, because inside PRAETOR it is a path, not
#: content. Crossing into SARIF changes that: the path is published.
_UNSAFE_URI_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _scrub_paths(text):
    """Replace absolute paths with their final component.

    Returns the value unchanged when it is not a string, so it can be mapped
    over an arbitrary metadata structure without knowing its shape.
    """
    if not isinstance(text, str):
        return text

    def keep_the_tail(m):
        raw = m.group(0)
        tail = raw.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        return tail or "<path>"

    return _ABS_PATH.sub(keep_the_tail, text)


def _scrub_structure(value):
    """`_scrub_paths` applied through dicts and lists, values only."""
    if isinstance(value, dict):
        return {k: _scrub_structure(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_structure(v) for v in value]
    return _scrub_paths(value)


def _safe_uri(path: str) -> str:
    """A finding's file path, made safe to publish.

    Redacts a provider-recognised credential appearing in the path itself and
    strips control characters, which are invalid in a SARIF URI and are a
    terminal-spoofing vector in any consumer that echoes the value.
    """
    uri = (path or "").replace("\\", "/")
    uri = core.redact_finding_snippet(uri)
    return _UNSAFE_URI_CHARS.sub("", uri)


def _repository_uri(repo: str) -> str:
    """An absolute URI for `versionControlProvenance`, or "" if none can be made.

    ⚠️ `owner/name` IS NOT A URI, and emitting it raises SARIF1005 in GitHub's
    own validator. PRAETOR accepts `--repo owner/name` because that is what CI
    variables hold, so the shorthand is expanded here rather than rejected.

    🔴 USERINFO IS STRIPPED. A CI system that passes a clone URL can pass
    `https://x-access-token:<a token>@github.com/owner/name` -- which would
    publish a live credential inside the provenance block of an uploaded file.
    """
    if not repo:
        return ""
    text = str(repo).strip()
    if "://" not in text:
        if re.fullmatch(r"[\w.-]+/[\w.-]+", text):
            return f"https://github.com/{text}"
        return ""
    scheme, _, rest = text.partition("://")
    authority, slash, tail = rest.partition("/")
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]  # drop user:password
    return f"{scheme}://{authority}{slash}{tail}"


def _rule_descriptor(finding: dict) -> dict:
    """One SARIF reportingDescriptor, built from a finding that used the rule."""
    rule = {
        "id": finding["rule_id"],
        # ⚠️ NO `name` FIELD. SARIF1001 fires when `name` equals `id`, and
        # PRAETOR's rule ids are already the human-readable name. A duplicate
        # that trips a validator is worse than an absent optional field.
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
                    # Redacted, because a credential can be in the NAME.
                    "uri": _safe_uri(finding.get("file")),
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

    # 🔴 COVERAGE NOTES GO IN TWO PLACES, DELIBERATELY.
    #
    # A coverage note is a whole-scan fact -- "12 files were too large to read"
    # -- so it carries `file="."`, a directory. A consumer that requires a
    # result to resolve to a real file may drop it. That would delete exactly
    # the finding this project cares most about: the one saying the scan was
    # incomplete. A false clean, arriving through the presentation layer.
    #
    # `toolExecutionNotifications` is SARIF's own channel for "the tool could
    # not process this", and it needs no file location at all. Emitting there
    # as well costs a few lines and removes the single point of failure.
    #
    # ⚠️ NOT INSTEAD OF the result. A notification is not an alert in most
    # consumers, so dropping the result would hide the note from anyone reading
    # the alert list. Both, or neither is reliable.
    notifications = [{
        "level": "warning",
        "message": {"text": f["title"] + " -- " + (f.get("description") or "")},
        "descriptor": {"id": f["rule_id"]},
        "properties": {"praetorCategory": "COVERAGE"},
    } for f in all_findings if f.get("category") == "COVERAGE"]

    invocation = {
        # 🔴 `executionSuccessful` IS NOT "no findings". It says the TOOL ran
        # correctly. A scan that could not measure the tree must report false
        # here, or a consumer reading this field learns nothing -- which is the
        # same false-clean this project exists to prevent, one layer out.
        "executionSuccessful": not _scan_was_degraded(meta),
        "endTimeUtc": meta.get("timestamp"),
    }
    if notifications:
        invocation["toolExecutionNotifications"] = notifications
    if meta.get("duration_seconds") is not None:
        invocation["properties"] = {"durationSeconds": meta["duration_seconds"]}

    run = {
        "tool": {"driver": driver},
        "results": [_result(f) for f in all_findings],
        "invocations": [invocation],
        "properties": {
            # Everything a consumer needs to judge whether the zero means
            # anything, carried through rather than lost in translation --
            # with host paths scrubbed, because this file gets uploaded.
            "praetorSchemaVersion": meta.get("schema_version"),
            "engines": _scrub_structure(meta.get("engines")),
            "scope": _scrub_structure(meta.get("scope")),
            "provenance": _scrub_structure(meta.get("provenance")),
        },
    }

    prov = meta.get("provenance") or {}
    repo_uri = _repository_uri(prov.get("repo") or "")
    if prov.get("commit") and repo_uri:
        # ⚠️ EMITTED ONLY WITH AN ABSOLUTE URI. SARIF requires one, and an empty
        # or shorthand value fails GitHub's validator (SARIF1005) -- which
        # rejects the whole upload, so a malformed block loses every result.
        run["versionControlProvenance"] = [{
            "repositoryUri": repo_uri,
            "revisionId": prov["commit"],
            "branch": prov.get("branch") or "",
        }]

    return json.dumps(
        {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]},
        indent=2,
        # 🔴 `ensure_ascii=False` CRASHES ON A LONE SURROGATE, and a scanner
        # reads attacker-controlled bytes for a living. A file holding an
        # unpaired surrogate made the whole run exit 2 with no report at all --
        # a scan defeated by one malformed character. `report.py` had this
        # right; SARIF did not.
        ensure_ascii=True,
    )


def _scan_was_degraded(meta: dict) -> bool:
    """True when the scan cannot be treated as authoritative.

    🔴 TWO QUESTIONS, AND THE FIRST VERSION ASKED ONLY ONE. It checked each
    engine's status and stopped there. `core.engines_that_measured`'s docstring
    states in capitals why that is half an answer: a per-engine check cannot see
    the EMPTY SET. Measured, an empty directory scanned with four engines:

        SARIF   executionSuccessful: true,  results: 0
        PRAETOR rc=3, "NOTHING WAS EXAMINED -- 0 files were opened"

    Every engine was individually trustworthy and none of them looked at
    anything. A consumer reading `true` with zero results treats the run as an
    authoritative clean bill -- and GitHub may close existing alerts as fixed on
    exactly that signal.

    ⇒ The whole-scan half is now READ FROM `meta`, not re-derived here. The CLI
    already computes it for the exit code; a second consumer computing its own
    version of a safety question is how these two came to disagree.

    ⚠️ `GATE_TRUSTED_STATUSES` is imported rather than copied, for the same
    reason. The hardcoded set here claimed to "mirror" it, and nothing asserted
    the mirror -- so tightening `core` would have left this silently permissive.
    """
    scope = meta.get("scope") or {}
    if scope.get("walked_nothing"):
        return True

    engines = meta.get("engines") or {}
    if not engines:
        return True  # nothing ran at all
    for info in engines.values():
        status = (info or {}).get("status")
        if status not in core.GATE_TRUSTED_STATUSES:
            return True
    return False
