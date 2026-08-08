"""
PRAETOR SAST engine -- a thin, honest wrapper around Semgrep (OSS).

Semgrep is the industry-standard open-source static analyzer (OWASP Top 10,
injection, auth, many languages). PRAETOR does not reimplement it; it runs it,
parses its JSON, and normalizes the results into the shared Finding model.

Runtime detection, in order of preference:
  1. NATIVE   `semgrep` on PATH  (verified working on native Windows, v1.170.0+)
  2. WSL      `wsl -d <distro> semgrep ...`  (paths translated to /mnt/<drive>/...)
  3. DOCKER   `docker run --rm -v <target>:/src semgrep/semgrep ...`

Rulesets: PRAETOR ships an offline baseline (rules/semgrep-praetor.yaml) that
always runs, and by default ALSO pulls Semgrep's curated registry packs
(p/owasp-top-ten, p/security-audit) when the network is reachable. Use
--no-registry for fully offline / reproducible scans.

Semgrep performs static analysis only; it never executes the scanned code.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from core import Finding, Severity, Confidence

DEFAULT_REGISTRY_CONFIGS = ["p/owasp-top-ten", "p/security-audit"]
_SEMGREP_TIMEOUT = 900  # seconds, overall


def _win_to_wsl(path: str) -> str:
    p = os.path.abspath(path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def detect_runtime(prefer: str = "auto", wsl_distro: str = "Ubuntu") -> dict:
    """Return {mode, cmd_prefix, available, detail}. mode in native|wsl|docker|none."""
    if prefer in ("native", "auto"):
        exe = shutil.which("semgrep")
        if exe:
            return {"mode": "native", "prefix": [exe], "available": True,
                    "detail": _native_version(exe)}
        if prefer == "native":
            return {"mode": "none", "prefix": [], "available": False,
                    "detail": "semgrep not on PATH"}

    if prefer in ("wsl", "auto") and shutil.which("wsl"):
        try:
            r = subprocess.run(["wsl", "-d", wsl_distro, "which", "semgrep"],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout.strip():
                return {"mode": "wsl", "prefix": ["wsl", "-d", wsl_distro, "semgrep"],
                        "available": True, "detail": f"wsl:{wsl_distro}"}
        except Exception:
            pass

    if prefer in ("docker", "auto") and shutil.which("docker"):
        # We do not pull here; caller runs with -v mount. Report as available-if-image.
        return {"mode": "docker", "prefix": ["docker"], "available": True,
                "detail": "docker (image semgrep/semgrep will be used)"}

    return {"mode": "none", "prefix": [], "available": False,
            "detail": "no semgrep runtime found (native/WSL/Docker)"}


def _native_version(exe: str) -> str:
    try:
        r = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30)
        return "semgrep " + r.stdout.strip().splitlines()[0] if r.stdout.strip() else "semgrep"
    except Exception:
        return "semgrep"


def _map_severity(sev: str, md: dict) -> Severity:
    # Prefer explicit metadata impact if present.
    impact = (md.get("impact") or "").upper()
    if impact in ("CRITICAL",):
        return Severity.CRITICAL
    if impact in ("HIGH",):
        return Severity.HIGH
    base = Severity.parse(sev)
    return base


def _confidence(md: dict) -> Confidence:
    c = (md.get("confidence") or "").upper()
    if c == "HIGH":
        return Confidence.HIGH
    if c == "LOW":
        return Confidence.LOW
    return Confidence.MEDIUM


def _first(x):
    if isinstance(x, list):
        return x[0] if x else ""
    return x or ""


def _source_line(path: str, line_no: int, cache: dict) -> str:
    """Read a single source line for a redacted snippet. Static read only."""
    if line_no <= 0:
        return ""
    if path not in cache:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                cache[path] = fh.read().splitlines()
        except OSError:
            cache[path] = []
    lines = cache[path]
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""


def run(target: str, bundled_rules: str, use_registry: bool = True,
        extra_configs=None, prefer: str = "auto", wsl_distro: str = "Ubuntu",
        timeout: int = _SEMGREP_TIMEOUT, excludes=None) -> dict:
    """
    Returns {findings: [...], status: 'ok'|'unavailable'|'error', detail: str,
             runtime: str}.
    """
    rt = detect_runtime(prefer, wsl_distro)
    if not rt["available"]:
        return {"findings": [], "status": "unavailable", "detail": rt["detail"], "runtime": "none"}

    configs = []
    if bundled_rules and os.path.exists(bundled_rules):
        configs.append(bundled_rules)
    if use_registry:
        configs.extend(DEFAULT_REGISTRY_CONFIGS)
    configs.extend(extra_configs or [])
    if not configs:
        configs = ["p/security-audit"] if use_registry else []
    if not configs:
        return {"findings": [], "status": "unavailable",
                "detail": "no rules available (offline and no bundled rules found)", "runtime": rt["mode"]}

    mode = rt["mode"]
    common = ["--json", "--quiet", "--metrics", "off", "--disable-version-check",
              "--timeout", "60", "--max-target-bytes", "3000000",
              # 🔴 Semgrep honours .gitignore by default. PRAETOR's own walker already
              # decides scope (--exclude, size limits), so letting semgrep apply a
              # SECOND, invisible filter made the engines disagree about what was
              # scanned -- and the report presented that as one result.
              #
              # Measured: pointed at the repo's own deliberately-vulnerable corpus,
              # which is gitignored, secrets+aisec returned 27 findings (6 CRITICAL)
              # while sast reported "ran ... 0 findings". Not a skip -- a successful
              # clean scan of a directory full of vulnerabilities. That is the exact
              # false-clean this tool exists to prevent, and it broke the README's own
              # "Verifying it works" procedure.
              #
              # If you scan it, scan it. Exclusion is the caller's call, not git's.
              "--no-git-ignore"]
    # Semgrep --exclude takes a path/glob pattern; pass each exclude through so
    # the SAST engine honors the same exclusions as the built-in engines.
    for pat in (excludes or []):
        common += ["--exclude", pat]

    if mode == "native":
        cfg_args = []
        for c in configs:
            cfg_args += ["--config", c]
        cmd = rt["prefix"] + cfg_args + common + [os.path.abspath(target)]
        cwd = None
    elif mode == "wsl":
        wt = _win_to_wsl(target)
        cfg_args = []
        for c in configs:
            cfg_args += ["--config", (_win_to_wsl(c) if os.path.exists(c) else c)]
        cmd = rt["prefix"] + cfg_args + common + [wt]
        cwd = None
    else:  # docker
        tgt = os.path.abspath(target)
        cfg_args = []
        for c in configs:
            # bundled local file must be mounted too; registry packs pass as-is
            cfg_args += ["--config", ("/rules/" + os.path.basename(c) if os.path.exists(c) else c)]
        vols = ["-v", f"{tgt}:/src:ro"]
        if bundled_rules and os.path.exists(bundled_rules):
            vols += ["-v", f"{os.path.dirname(os.path.abspath(bundled_rules))}:/rules:ro"]
        cmd = ["docker", "run", "--rm", "--network", "host"] + vols + \
              ["semgrep/semgrep", "semgrep"] + cfg_args + common + ["/src"]
        cwd = None

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    except subprocess.TimeoutExpired:
        return {"findings": [], "status": "error", "detail": "semgrep timed out", "runtime": mode}
    except Exception as e:  # noqa
        return {"findings": [], "status": "error", "detail": f"semgrep failed to launch: {e}", "runtime": mode}

    # semgrep exit codes: 0 = ran (findings or not), 1 = findings, 2+ = error.
    out = r.stdout.strip()
    if not out:
        detail = (r.stderr.strip().splitlines()[-1] if r.stderr.strip() else f"exit {r.returncode}, no output")
        return {"findings": [], "status": "error", "detail": detail, "runtime": mode}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {"findings": [], "status": "error", "detail": "unparseable semgrep JSON", "runtime": mode}

    findings = []
    target_abs = os.path.abspath(target)
    line_cache: dict = {}
    for res in data.get("results", []):
        extra = res.get("extra", {}) or {}
        md = extra.get("metadata", {}) or {}
        raw_path = res.get("path", "")
        try:
            rel = os.path.relpath(raw_path, target_abs).replace("\\", "/")
        except ValueError:
            rel = raw_path
        rid = res.get("check_id", "semgrep-rule")
        short = rid.split(".")[-1]
        refs = md.get("references", []) or []
        cwe = _first(md.get("cwe", ""))
        owasp = _first(md.get("owasp", ""))

        # robust fix extraction: never stringify a bool/None
        fix_text = extra.get("fix")
        if not isinstance(fix_text, str) or not fix_text.strip():
            fix_text = md.get("fix")
        if not isinstance(fix_text, str) or not fix_text.strip():
            fix_text = "See rule message and references for remediation."

        line_no = int(res.get("start", {}).get("line", 0) or 0)
        # Prefer the real source line -- semgrep redacts extra.lines to
        # "requires login" for unauthenticated registry rules.
        snippet = (extra.get("lines", "") or "").strip()
        if (not snippet) or snippet.lower() == "requires login":
            snippet = _source_line(raw_path, line_no, line_cache)

        findings.append(Finding(
            engine="sast", rule_id=short, title=(md.get("shortDescription") or short.replace("-", " ")),
            severity=_map_severity(extra.get("severity", "WARNING"), md),
            confidence=_confidence(md),
            file=rel, line=line_no,
            end_line=int(res.get("end", {}).get("line", 0) or 0),
            category=(_first(md.get("category", "")) or "SAST").upper(),
            description=(extra.get("message", "") or "").strip()[:600],
            snippet=snippet[:200],
            fix=str(fix_text)[:400],
            cwe=(cwe if str(cwe).upper().startswith("CWE") else ""),
            owasp=str(owasp),
            references=refs[:5] + [f"semgrep:{rid}"],
        ))
    n_errors = len(data.get("errors", []))
    detail = f"{rt['detail']}; ran configs={configs}; scan errors={n_errors}"
    return {"findings": findings, "status": "ok", "detail": detail, "runtime": mode}
