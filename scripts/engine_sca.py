"""
PRAETOR SCA (Software Composition Analysis) engine -- pluggable, honest.

Flags known-vulnerable dependencies. Rather than hard-requiring one tool, PRAETOR
prefers the strongest cross-ecosystem option available and degrades gracefully:

  1. osv-scanner (Google OSV)  -- PREFERRED. Language-agnostic; reads lockfiles
     for pip/npm/go/cargo/maven/composer/... against the OSV.dev database.
  2. pip-audit                 -- Python projects (pure-Python, pip-installable).
  3. npm audit                 -- Node projects (bundled with npm).

Static-by-construction dependency reads -- the SCA subprocess boundary:

  * osv-scanner statically reads lockfiles; it never builds or runs the target.
  * pip-audit is invoked with --disable-pip (together with --no-deps), which
    forbids pip from resolving OR BUILDING the target's requirements. This is the
    load-bearing safety flag: --no-deps alone does NOT stop pip-audit from doing a
    full pip resolve of the requirements, which builds source distributions and
    executes attacker-controlled setup.py / PEP517 backends (arbitrary code
    execution). --disable-pip removes that resolve step entirely, so no target
    code is ever executed. It requires fully-pinned requirements; when a file
    cannot be audited that way, PRAETOR reports an ERROR and NEVER falls back to
    any resolving mode.
  * npm audit reads the lockfile and queries advisories, with the registry pinned
    on the command line so a target .npmrc cannot redirect the request.

A non-zero exit WITH parseable output means "vulnerabilities found". A non-zero
exit (or empty/unparseable output) WITHOUT parseable results is a tool ERROR and
is surfaced as status="error" -- never laundered into a clean "0 findings" result.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import core
from core import Finding, Severity, Confidence, ENGINE_NOT_APPLICABLE

_TIMEOUT = 300

PY_MANIFESTS = ("requirements.txt", "requirements-dev.txt", "requirements.in",
                "Pipfile.lock", "poetry.lock", "pyproject.toml")
NODE_MANIFESTS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
ANY_LOCKFILES = PY_MANIFESTS + NODE_MANIFESTS + (
    "go.mod", "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock",
    "pom.xml", "build.gradle", "gradle.lockfile", "mix.lock",
)


def _find_manifests(target: str, names) -> list:
    hits = []
    if os.path.isfile(target):
        if os.path.basename(target) in names:
            hits.append(target)
        return hits
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor"}]
        for fn in files:
            if fn in names:
                hits.append(os.path.join(root, fn))
    return hits


import math as _math

# CVSS v3.x base-metric weights (spec: https://www.first.org/cvss/v3.1/specification-document)
_CVSS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS_AC = {"L": 0.77, "H": 0.44}
_CVSS_UI = {"N": 0.85, "R": 0.62}
_CVSS_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _cvss3_base(vector: str):
    """Compute a CVSS v3.0/3.1 base score from its vector string. Returns float or None."""
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    except ValueError:
        return None
    try:
        scope_changed = parts.get("S") == "C"
        av = _CVSS_AV[parts["AV"]]
        ac = _CVSS_AC[parts["AC"]]
        ui = _CVSS_UI[parts["UI"]]
        pr_raw = parts["PR"]
        pr = {"N": 0.85,
              "L": 0.68 if scope_changed else 0.62,
              "H": 0.50 if scope_changed else 0.27}[pr_raw]
        c, i, a = _CVSS_CIA[parts["C"]], _CVSS_CIA[parts["I"]], _CVSS_CIA[parts["A"]]
    except KeyError:
        return None
    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    else:
        impact = 6.42 * isc_base
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 * (impact + exploitability)) if scope_changed else (impact + exploitability)
    base = min(raw, 10.0)
    # CVSS "roundup": smallest one-decimal value >= base
    return _math.ceil(base * 10) / 10.0


def _score_to_severity(s: float) -> Severity:
    if s >= 9.0:
        return Severity.CRITICAL
    if s >= 7.0:
        return Severity.HIGH
    if s >= 4.0:
        return Severity.MEDIUM
    if s > 0.0:
        return Severity.LOW
    return Severity.INFO


def _osv_severity(vuln: dict) -> Severity:
    """Rank an OSV advisory: explicit label first, else computed CVSS, else MEDIUM."""
    ds = (vuln.get("database_specific", {}) or {})
    label = str(ds.get("severity", "")).upper()
    label_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                 "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM,
                 "LOW": Severity.LOW}
    if label in label_map:
        return label_map[label]
    for sev in vuln.get("severity", []) or []:
        score = sev.get("score", "")
        if isinstance(score, str) and score.startswith("CVSS:3"):
            computed = _cvss3_base(score)
            if computed is not None:
                return _score_to_severity(computed)
    # Known advisory with no severity rating (e.g. many PYSEC entries): treat as
    # MEDIUM -- real, but not auto-promoted above rated High/Critical findings.
    return Severity.MEDIUM


def _run_osv(target: str) -> dict:
    exe = shutil.which("osv-scanner")
    if not exe:
        return {"ok": False}
    cmd = [exe, "--format", "json", "--recursive", os.path.abspath(target)]
    try:
        r = core.run_tool(cmd, timeout=_TIMEOUT)
    except Exception as e:  # noqa
        return {"ok": True, "status": "error", "detail": f"osv-scanner launch error: {e}", "findings": []}
    out = (r.stdout or "").strip()
    if not out:
        # No output => osv-scanner analysed NOTHING. This must NEVER be reported as
        # a successful scan. An earlier version returned status "ok" here, commented
        # "treat as clean-but-ran", and that was a FALSE CLEAN in the machine-readable
        # contract: `"status": "ok"` with zero findings is read by every consumer --
        # including a CI gate -- as "SCA ran and the target is clean", when in fact
        # nothing was examined. `status` is the ONLY signal telling a consumer whether
        # a zero means anything.
        #
        # `_run_pip_audit` and `_run_npm_audit` already treat this exact condition as
        # not-ok; osv was the sole outlier. The two cases are distinguished because
        # they call for different action from the reader:
        #   exit 128  -> osv's documented "no packages found": nothing to scan here.
        #                UNAVAILABLE -- a property of the TARGET, no action needed.
        #   otherwise -> the scanner exited abnormally with no output.
        #                ERROR -- a property of the ENVIRONMENT, needs investigation.
        # The old comment claimed "exit 128" while the code checked no return code at
        # all, so a crashing scanner was laundered into a clean result too.
        if r.returncode == 128:
            return {"ok": True, "status": ENGINE_NOT_APPLICABLE,
                    "detail": "osv-scanner found no lockfile packages to analyse (exit 128); nothing was scanned",
                    "findings": []}
        return {"ok": True, "status": "error",
                "detail": (f"osv-scanner produced no output (exit {r.returncode}); "
                           "the scan did NOT complete and this is not a clean result"),
                "findings": []}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {"ok": True, "status": "error", "detail": "unparseable osv-scanner JSON", "findings": []}

    findings = []
    for result in data.get("results", []):
        src = result.get("source", {}).get("path", "")
        try:
            rel = os.path.relpath(src, os.path.abspath(target)).replace("\\", "/")
        except ValueError:
            rel = src
        for pkg in result.get("packages", []):
            info = pkg.get("package", {})
            name = info.get("name", "?")
            ver = info.get("version", "?")
            vulns = pkg.get("vulnerabilities", []) or []
            if not vulns:
                continue
            findings.append(_group_package(name, ver, vulns, rel))
    return {"ok": True, "status": "ok", "detail": "osv-scanner", "findings": findings}


def _group_package(name: str, ver: str, vulns: list, rel: str) -> Finding:
    """One finding per vulnerable package: max severity, advisory count, IDs, upgrade."""
    max_sev = Severity.INFO
    ids, fixed_all, cwes, refs = [], set(), set(), []
    top_summary = ""
    top_sev_val = -1
    for v in vulns:
        vid = v.get("id", "")
        if vid:
            ids.append(vid)
        sev = _osv_severity(v)
        if int(sev) > int(max_sev):
            max_sev = sev
        if int(sev) > top_sev_val:
            top_sev_val = int(sev)
            top_summary = (v.get("summary") or v.get("details", "") or "")[:200]
        for fv in _osv_fixed_versions(v).split(", "):
            if fv:
                fixed_all.add(fv)
        for c in (v.get("database_specific", {}) or {}).get("cwe_ids", []) or []:
            cwes.add(c)
        for r2 in v.get("references", [])[:2]:
            if r2.get("url"):
                refs.append(r2["url"])
    id_preview = ", ".join(ids[:8]) + (f" (+{len(ids) - 8} more)" if len(ids) > 8 else "")
    fixed = ", ".join(sorted(fixed_all)[:5])
    desc = (f"{name} {ver} has {len(vulns)} known advisor" + ("y" if len(vulns) == 1 else "ies")
            + f" (highest severity {max_sev.label}). "
            + (f"Most severe: {top_summary}. " if top_summary else "")
            + f"IDs: {id_preview}.")
    return Finding(
        engine="sca", rule_id=(ids[0] if ids else f"OSV-{name}"),
        title=f"{name} {ver}: {len(vulns)} known vulnerabilit" + ("y" if len(vulns) == 1 else "ies"),
        severity=max_sev, confidence=Confidence.HIGH,
        file=rel, line=0, category="VULNERABLE_DEPENDENCY",
        description=desc, snippet=f"{name}@{ver}",
        fix=(f"Upgrade {name} to {fixed} (or later)." if fixed else f"Update {name}; see the advisories."),
        cwe=", ".join(sorted(cwes)[:4]),
        owasp="A06:2021 Vulnerable and Outdated Components",
        references=refs[:4] + ([f"https://osv.dev/vulnerability/{ids[0]}"] if ids else []),
    )


def _osv_fixed_versions(v: dict) -> str:
    fixed = []
    for a in v.get("affected", []) or []:
        for rng in a.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return ", ".join(sorted(set(fixed))[:3])


def _pip_audit_severity(v: dict) -> Severity:
    """
    Rank a pip-audit advisory. pip-audit's default JSON does NOT carry a CVSS
    vector or a severity label, so most advisories fall back to MEDIUM -- the same
    unrated default the osv path uses, NOT an assumed HIGH. If an enriched output
    ever carries a label or a CVSS vector, honor it.
    """
    label = str(v.get("severity", "") or "").upper()
    label_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                 "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM,
                 "LOW": Severity.LOW}
    if label in label_map:
        return label_map[label]
    for key in ("cvss", "cvss_vector", "vector"):
        vec = v.get(key)
        if isinstance(vec, str) and vec.startswith("CVSS:3"):
            computed = _cvss3_base(vec)
            if computed is not None:
                return _score_to_severity(computed)
    return Severity.MEDIUM


def _run_pip_audit(manifests: list, target: str) -> dict:
    exe = shutil.which("pip-audit")
    if not exe:
        return {"ok": False}
    reqs = [m for m in manifests if os.path.basename(m) in ("requirements.txt", "requirements-dev.txt", "requirements.in")]
    if not reqs:
        return {"ok": False}
    findings = []
    detail_parts = []
    errored = False
    for req in reqs:
        base = os.path.basename(req)
        # SAFETY (CRITICAL): --disable-pip forbids pip from resolving/building the
        # target's requirements, so no attacker-controlled setup.py / PEP517
        # backend is ever executed during the audit. It requires fully-pinned
        # requirements (paired with --no-deps); if the file is not auditable this
        # way, pip-audit exits without parseable output and we record an ERROR --
        # we NEVER retry in a resolving mode.
        cmd = [exe, "--format", "json", "--progress-spinner", "off",
               "--no-deps", "--disable-pip", "-r", req]
        try:
            r = core.run_tool(cmd, timeout=_TIMEOUT)
        except Exception as e:  # noqa
            errored = True
            detail_parts.append(f"pip-audit ERROR on {base}: {e}")
            continue
        out = (r.stdout or "").strip()
        if not out:
            # No parseable output => the audit did NOT complete (commonly: the reqs
            # are not fully pinned, so --disable-pip cannot audit them without
            # resolving). This is an ERROR, never a clean '0 findings' result.
            errored = True
            err = (r.stderr or "").strip().splitlines()
            reason = err[-1] if err else f"exit {r.returncode}, no output"
            detail_parts.append(f"pip-audit ERROR on {base}: {reason}")
            continue
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            errored = True
            detail_parts.append(f"pip-audit ERROR on {base}: unparseable output (exit {r.returncode})")
            continue
        try:
            rel = os.path.relpath(req, os.path.abspath(target)).replace("\\", "/")
        except ValueError:
            rel = req
        deps = data.get("dependencies", data) if isinstance(data, dict) else data
        for dep in deps:
            name = dep.get("name", "?")
            ver = dep.get("version", "?")
            vulns = dep.get("vulns", []) or []
            if not vulns:
                continue
            ids = [v.get("id", "") for v in vulns if v.get("id")]
            fixes = set()
            max_sev = Severity.INFO
            for v in vulns:
                for fv in v.get("fix_versions", []) or []:
                    fixes.add(fv)
                sev = _pip_audit_severity(v)
                if int(sev) > int(max_sev):
                    max_sev = sev
            if int(max_sev) < int(Severity.MEDIUM):
                max_sev = Severity.MEDIUM  # unrated known advisory -> MEDIUM (never auto-HIGH)
            fixed = ", ".join(sorted(fixes)[:5])
            id_preview = ", ".join(ids[:8]) + (f" (+{len(ids) - 8} more)" if len(ids) > 8 else "")
            findings.append(Finding(
                engine="sca", rule_id=(ids[0] if ids else "PYSEC"),
                title=f"{name} {ver}: {len(vulns)} known vulnerabilit" + ("y" if len(vulns) == 1 else "ies"),
                severity=max_sev, confidence=Confidence.HIGH,
                file=rel, line=0, category="VULNERABLE_DEPENDENCY",
                description=f"{name} {ver} has {len(vulns)} known advisory record(s). IDs: {id_preview}.",
                snippet=f"{name}=={ver}",
                fix=(f"Upgrade {name} to {fixed} (or later)." if fixed else f"Update {name}; see the advisories."),
                owasp="A06:2021 Vulnerable and Outdated Components",
                references=[f"https://osv.dev/vulnerability/{ids[0]}"] if ids else [],
            ))
        detail_parts.append(f"pip-audit ({base}) [--disable-pip: static, no build]")
    status = "error" if errored else "ok"
    detail = "; ".join(detail_parts)
    if errored:
        detail = ("pip-audit could NOT safely audit all requirements "
                  "(unpinned/unresolvable without a build); results INCOMPLETE -- " + detail)
    return {"ok": True, "status": status, "detail": detail, "findings": findings}


def _run_npm_audit(manifests: list, target: str) -> dict:
    exe = shutil.which("npm")
    if not exe:
        return {"ok": False}
    dirs = sorted({os.path.dirname(m) for m in manifests if os.path.basename(m) in ("package-lock.json", "npm-shrinkwrap.json")})
    if not dirs:
        return {"ok": False}
    findings = []
    detail_parts = []
    errored = False
    for d in dirs:
        # SAFETY: pin the registry on the command line so a target-controlled
        # .npmrc in `d` cannot redirect the audit request (which carries the
        # dependency list) to an attacker host -- CLI config outranks a project
        # .npmrc. Residual trust (scoped-registry `@scope:registry=` entries and
        # ${ENV} auth-token expansion in a target .npmrc) is documented in
        # references/LIMITS.md and references/ARCHITECTURE.md.
        cmd = [exe, "audit", "--json", "--audit-level", "low",
               "--registry", "https://registry.npmjs.org/"]
        try:
            r = core.run_tool(cmd, timeout=_TIMEOUT, cwd=d)
        except Exception as e:  # noqa
            errored = True
            detail_parts.append(f"npm audit ERROR in {d}: {e}")
            continue
        out = (r.stdout or "").strip()
        if not out:
            errored = True
            detail_parts.append(f"npm audit ERROR: no output in {d} (exit {r.returncode})")
            continue
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            errored = True
            detail_parts.append(f"npm audit ERROR: unparseable output in {d}")
            continue
        # npm emits {"error": {...}} on failure -- do not launder that into 0 findings.
        if isinstance(data, dict) and "error" in data and "vulnerabilities" not in data:
            errored = True
            summary = (data.get("error", {}) or {}).get("summary", "npm audit failed")
            detail_parts.append(f"npm audit ERROR in {d}: {str(summary)[:200]}")
            continue
        try:
            rel = os.path.relpath(os.path.join(d, "package-lock.json"), os.path.abspath(target)).replace("\\", "/")
        except ValueError:
            rel = "package-lock.json"
        # npm v7+ schema: data['vulnerabilities'] is a dict keyed by package.
        for name, v in (data.get("vulnerabilities", {}) or {}).items():
            sev = str(v.get("severity", "moderate"))
            via = v.get("via", [])
            titles = [x.get("title") for x in via if isinstance(x, dict) and x.get("title")]
            urls = [x.get("url") for x in via if isinstance(x, dict) and x.get("url")]
            findings.append(Finding(
                engine="sca", rule_id="npm-audit",
                title=f"{name}: {titles[0] if titles else 'known vulnerability'}",
                severity=Severity.parse(sev), confidence=Confidence.HIGH,
                file=rel, line=0, category="VULNERABLE_DEPENDENCY",
                description=("; ".join(titles)[:400] or f"{name} has a known vulnerability ({sev})."),
                snippet=f"{name} ({sev})",
                fix=(f"Run `npm audit fix --ignore-scripts`" + (" --force" if v.get("fixAvailable") is False else "")
                     + f" to remediate {name}; this may break packages that require native build scripts. Review the lockfile first."),
                owasp="A06:2021 Vulnerable and Outdated Components",
                references=urls[:4],
            ))
        detail_parts.append(f"npm audit ({os.path.relpath(d, target) if os.path.isdir(target) else d})")
    status = "error" if errored else "ok"
    detail = "; ".join(detail_parts)
    if errored:
        detail = "npm audit did not complete for all lockfiles; results INCOMPLETE -- " + detail
    return {"ok": True, "status": status, "detail": detail, "findings": findings}


def run(target: str, backend: str = "auto", excludes=None) -> dict:
    """
    Returns {findings, status, detail, backend}.
    backend: auto | osv | pip-audit | npm
    """
    import re as _re
    all_manifests = _find_manifests(target, set(ANY_LOCKFILES))
    if excludes:
        rxs = [_re.compile(p) for p in excludes]
        tabs = os.path.abspath(target)
        def _kept(m):
            rel = os.path.relpath(m, tabs).replace("\\", "/")
            return not any(rx.search(rel) for rx in rxs)
        all_manifests = [m for m in all_manifests if _kept(m)]
    if not all_manifests and backend == "auto":
        # A property of the TARGET, not of this box: there are no dependencies to
        # audit, so nothing is left unmeasured. Distinct from "no SCA backend
        # available" below, which IS a blind spot. See core.ENGINE_NOT_APPLICABLE.
        return {"findings": [], "status": ENGINE_NOT_APPLICABLE,
                "detail": "no dependency manifests/lockfiles found", "backend": "none"}

    tried = []

    def try_osv():
        res = _run_osv(target)
        if res.get("ok"):
            return res
        tried.append("osv-scanner: not installed")
        return None

    def try_pip():
        res = _run_pip_audit(all_manifests, target)
        if res.get("ok"):
            return res
        tried.append("pip-audit: not installed or no requirements.txt")
        return None

    def try_npm():
        res = _run_npm_audit(all_manifests, target)
        if res.get("ok"):
            return res
        tried.append("npm audit: npm missing or no package-lock.json")
        return None

    order = {
        "auto": [try_osv, try_pip, try_npm],
        "osv": [try_osv],
        "pip-audit": [try_pip],
        "npm": [try_npm],
    }.get(backend, [try_osv, try_pip, try_npm])

    exclude_rxs = [_re.compile(p) for p in (excludes or [])]

    def _filter_findings(findings):
        if not exclude_rxs:
            return findings
        return [f for f in findings if not any(rx.search(f.file or "") for rx in exclude_rxs)]

    for fn in order:
        res = fn()
        if res is not None:
            res["findings"] = _filter_findings(res.get("findings", []))
            res["backend"] = res.get("detail", "").split()[0] if res.get("detail") else backend
            if tried:
                res["detail"] = res.get("detail", "") + " | fallbacks: " + "; ".join(tried)
            return res

    return {"findings": [], "status": "unavailable",
            "detail": "no SCA backend available (" + "; ".join(tried) + ")", "backend": "none"}
