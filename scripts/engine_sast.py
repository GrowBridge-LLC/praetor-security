"""
PRAETOR SAST engine -- a thin, honest wrapper around Semgrep (OSS).

Semgrep is the industry-standard open-source static analyzer (OWASP Top 10,
injection, auth, many languages). PRAETOR does not reimplement it; it runs it,
parses its JSON, and normalizes the results into the shared Finding model.

Runtime detection, in order of preference. Each candidate is PROBED -- asked for
its version and required to answer -- and a candidate that fails falls through to
the next, so a broken install cannot mask a working runtime beside it:
  1. NATIVE   `semgrep` on PATH
  2. WSL      `wsl -d <distro> <abs path> ...`  (paths translated to /mnt/<drive>/...)
  3. DOCKER   `docker run --rm -v <target>:/src semgrep/semgrep ...`

⚠️ This block used to claim native Windows semgrep was "verified working,
v1.170.0+". A pip-installed `semgrep.EXE` that exits 1 and prints nothing is a
common enough state that this repo's own development box was in it, undetected,
while the docstring said otherwise. Runtime availability is a property of the
box in front of you; nothing stated here can establish it.

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

import core
from core import Finding, Severity, Confidence, split_lines

DEFAULT_REGISTRY_CONFIGS = ["p/owasp-top-ten", "p/security-audit"]
_SEMGREP_TIMEOUT = 900  # seconds, overall


def _win_to_wsl(path: str) -> str:
    p = os.path.abspath(path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def _relative_to_report_root(raw_path: str, report_root: str) -> str:
    """A finding's path as it sits inside the scanned tree.

    🔴 THE ROOT SEMGREP REPORTS UNDER IS NOT ALWAYS THE ROOT WE ASKED ABOUT.
    Under WSL we hand it `/mnt/c/projects/X` and it answers in those terms; under
    Docker the tree is mounted at `/src`. The caller used `os.path.relpath(path,
    <Windows abspath>)` for all three runtimes, so every WSL finding came back as

        ../../mnt/c/projects/PRAETOR/.github/workflows/invariants.yml

    That is not cosmetic. `f.file` is the key every later pass uses: inline
    `# nosec` suppression, lexical comment context and taint reachability all
    reopen the file by that path, and the self-scan baseline classifier matches on
    it. A path that resolves to nothing degrades each of them silently -- and
    "cannot open ⇒ keep the finding" means the failure hides as noise rather than
    as an error. It went unseen because the only runtime anyone exercised was
    native, and the runtime probe defect meant SAST was not running at all here.

    Never invents a path: anything that does not sit under the expected root is
    returned as semgrep reported it.
    """
    p = (raw_path or "").replace("\\", "/")
    root = (report_root or "").replace("\\", "/").rstrip("/")
    if root and p.startswith(root + "/"):
        return p[len(root) + 1:]
    if root and p == root:
        return os.path.basename(p)
    try:
        rel = os.path.relpath(p, root).replace("\\", "/") if root else p
    except ValueError:  # different drives on Windows
        return p
    # An escaping relpath means our root assumption was wrong. Semgrep's own
    # answer is worth more than a computed path that points outside the tree.
    return p if rel.startswith("..") else rel


def _report_root(mode: str, target: str) -> str:
    """The prefix semgrep will use when reporting paths, for each runtime."""
    if mode == "wsl":
        return _win_to_wsl(target)
    if mode == "docker":
        return "/src"
    return os.path.abspath(target)


def detect_runtime(prefer: str = "auto", wsl_distro: str = "Ubuntu") -> dict:
    """Return {mode, cmd_prefix, available, detail}. mode in native|wsl|docker|none.

    🔴 EVERY BRANCH MEASURES THE RUNTIME. None infers a working semgrep from a
    file existing somewhere on a PATH -- see `_probe_semgrep`, and
    tests/test_runtime_probe_checks_the_runtime.py.

    In `auto`, a branch that fails to measure FALLS THROUGH to the next rather
    than reporting unavailable, so one broken install cannot mask a healthy
    runtime beside it. Every rejection is accumulated into `why` and reported
    together: an operator with three possible runtimes needs to know what was
    wrong with each, not merely that none worked.
    """
    why = []

    if prefer in ("native", "auto"):
        exe = shutil.which("semgrep")
        if exe:
            ok, detail = _probe_semgrep([exe])
            if ok:
                return {"mode": "native", "prefix": [exe], "available": True, "detail": detail}
            why.append(f"native semgrep at {exe} {detail}")
        else:
            why.append("no semgrep on PATH")
        if prefer == "native":
            return {"mode": "none", "prefix": [], "available": False, "detail": "; ".join(why)}

    if prefer in ("wsl", "auto") and shutil.which("wsl"):
        exe = _wsl_semgrep_path(wsl_distro)
        if exe:
            prefix = ["wsl", "-d", wsl_distro, exe]
            ok, detail = _probe_semgrep(prefix)
            if ok:
                return {"mode": "wsl", "prefix": prefix, "available": True,
                        "detail": f"{detail} (wsl:{wsl_distro})"}
            why.append(f"wsl:{wsl_distro} semgrep at {exe} {detail}")
        else:
            why.append(f"no semgrep on the login PATH of wsl:{wsl_distro}")
        if prefer == "wsl":
            return {"mode": "none", "prefix": [], "available": False, "detail": "; ".join(why)}

    if prefer in ("docker", "auto") and shutil.which("docker"):
        # 🔴 `shutil.which` proves the CLI is INSTALLED. It does not prove the
        # DAEMON is REACHABLE, and it is the daemon that decides whether semgrep
        # can run. Docker Desktop installed-but-stopped reported available:True
        # here; the run then died with a connect error PRAETOR surfaced as
        # "Run 'docker run --help' for more information" -- naming the wrong
        # layer, so it read as a malformed command rather than a dead daemon.
        # Found by an outside user running a real scan, not by this repo's tests.
        #
        # ⚠️ When this was fixed it was recorded here, and in that test file, that
        # "the native and WSL branches already probe the capability itself" and
        # docker "was the sole branch that asserted one". BOTH HALVES WERE FALSE,
        # and saying so in a comment is what stopped anyone looking:
        #   * native called `_native_version`, which IGNORED the exit code and
        #     swallowed every exception, so it could not fail;
        #   * WSL ran `which semgrep` in a NON-login shell, answering about a PATH
        #     it would not use.
        # Fixing the demonstrated case and then generalising from it in prose is
        # how a defect class survives its own repair.
        ready, reason = _docker_daemon_ready()
        if ready:
            # We do not pull here; caller runs with -v mount. Report as available-if-image.
            return {"mode": "docker", "prefix": ["docker"], "available": True,
                    "detail": "docker (image semgrep/semgrep will be used)"}
        why.append(f"docker CLI present but {reason}")

    return {"mode": "none", "prefix": [], "available": False,
            "detail": "; ".join(why) if why else "no semgrep runtime found (native/WSL/Docker)"}


def _docker_daemon_ready(timeout: int = 10) -> tuple:
    """(ready, reason) -- probe the Docker DAEMON, not the `docker` binary.

    `docker version` queries the daemon and exits non-zero when it is
    unreachable. It reads nothing from the scan target and starts no container,
    so it does not widen the never-execute-the-target invariant.
    """
    try:
        r = core.run_tool(["docker", "version", "--format", "{{.Server.Version}}"],
                          timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"the daemon did not respond within {timeout}s"
    except Exception as e:  # noqa -- probe must never take the scan down
        return False, f"the daemon could not be probed ({e})"
    if r.returncode != 0 or not r.stdout.strip():
        said = ((r.stderr or "") + (r.stdout or "")).strip().splitlines()
        why = said[0][:160] if said else f"exit {r.returncode}"
        return False, f"the daemon is unreachable ({why})"
    return True, ""


def _probe_semgrep(cmd: list, timeout: int = 60) -> tuple:
    """(ok, detail) -- ask semgrep for its version and REQUIRE a real answer.

    🔴 A PROBE MUST MEASURE THE CAPABILITY, NOT ASSERT IT.

    This replaces `_native_version`, which ran the same command and then discarded
    everything it learned: it ignored the exit code, and `except Exception: return
    "semgrep"` turned a failure into a version string. `detect_runtime` reported
    `available: True` from `shutil.which` alone and used that string only as a
    label, so the branch had a probe in it that could not fail.

    MEASURED CONSEQUENCE, on the box this repo is developed on: a pip-installed
    Windows `semgrep.EXE` sat on PATH, exiting 1 and printing nothing at all --
    a broken install. PRAETOR reported it available, chose it in preference to a
    healthy WSL semgrep, ran a scan, got no output, and reported `[error] sast`.
    The engine covering OWASP and injection had not run in this repo's own
    self-scan, and the number that scan produced was quoted repeatedly as
    evidence before anyone noticed the banner above it.

    An empty stdout counts as failure even on exit 0: `--version` that prints
    nothing is not a runtime that will produce parseable JSON.

    Reads nothing from the scan target -- the command asks semgrep about itself.
    """
    try:
        r = core.run_tool([*cmd, "--version"], timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"did not answer --version within {timeout}s"
    except Exception as e:  # noqa -- a probe must never take the scan down
        return False, f"could not be launched ({e})"
    lines = [ln for ln in split_lines((r.stdout or "").strip()) if ln.strip()]
    if r.returncode != 0 or not lines:
        said = ((r.stderr or "") + (r.stdout or "")).strip().splitlines()
        detail = said[0][:160] if said else f"exit {r.returncode}, no output"
        return False, f"is present but not runnable ({detail})"
    return True, f"semgrep {lines[0].strip()}"


def _wsl_semgrep_path(distro: str, timeout: int = 60) -> str:
    """Absolute path to semgrep inside `distro`, or "" if it is not installed.

    Resolved through a LOGIN shell so the operator's own PATH setup is honoured
    -- `~/.profile`, `~/.bashrc`, `~/.local/bin`, a venv, a version manager. The
    previous probe ran `wsl -d <distro> which semgrep`, which starts a NON-login
    shell whose PATH is the bare system default. On a box where semgrep was
    installed per-user it answered "not installed" about a semgrep that ran fine
    in every terminal the operator opened.

    🔴 The resolved path is ABSOLUTE and is used verbatim in the argv prefix. The
    old prefix invoked bare `semgrep` through `wsl -d <distro> semgrep`, which
    repeats the non-login PATH lookup AT RUN TIME -- so even had the probe been
    fixed alone, a probe that passed could be followed by a run that could not
    find the binary. Probe and invocation must resolve the same thing.

    The login shell is used ONLY to resolve this path. The scan itself is argv,
    never a shell string, so no target path is ever handed to a shell to parse.
    """
    try:
        r = core.run_tool(["wsl", "-d", distro, "bash", "-lc", "command -v semgrep"],
                          timeout=timeout)
    except Exception:  # noqa -- absence of a runtime is not an error
        return ""
    if r.returncode != 0:
        return ""
    # A login shell may emit profile output before the answer, so take the LAST
    # absolute path printed rather than the first line.
    for line in reversed(split_lines((r.stdout or "").strip())):
        line = line.strip()
        if line.startswith("/"):
            return line
    return ""


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
                # Semgrep's line numbers are \n-based; resolving them against a
                # splitlines() list would show the wrong source line. See
                # core.split_lines.
                cache[path] = split_lines(fh.read())
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
        r = core.run_tool(cmd, timeout=timeout, cwd=cwd)
    except subprocess.TimeoutExpired:
        return {"findings": [], "status": "error", "detail": "semgrep timed out", "runtime": mode}
    except Exception as e:  # noqa
        return {"findings": [], "status": "error", "detail": f"semgrep failed to launch: {e}", "runtime": mode}

    # semgrep exit codes: 0 = ran (findings or not), 1 = findings, 2+ = error.
    # `r.stdout or ""` is not defensive noise: a decode fault on subprocess's
    # reader thread returns a CompletedProcess with stdout=None while raising
    # nothing here, and the bare `.strip()` that used to be on this line failed
    # with an AttributeError naming nothing an operator could act on. core.run_tool
    # now fixes the encoding, and this keeps the failure legible if it ever
    # returns None for a reason we have not met yet.
    out = (r.stdout or "").strip()
    if not out:
        err = (r.stderr or "").strip()
        detail = (split_lines(err)[-1] if err else f"exit {r.returncode}, no output")
        return {"findings": [], "status": "error", "detail": detail, "runtime": mode}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {"findings": [], "status": "error", "detail": "unparseable semgrep JSON", "runtime": mode}

    findings = []
    report_root = _report_root(mode, target)
    line_cache: dict = {}
    for res in data.get("results", []):
        extra = res.get("extra", {}) or {}
        md = extra.get("metadata", {}) or {}
        raw_path = res.get("path", "")
        rel = _relative_to_report_root(raw_path, report_root)
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
            # Read through OUR OWN filesystem, not the path semgrep reported.
            # `raw_path` is `/mnt/c/...` under WSL and `/src/...` under Docker;
            # neither opens on the host, and `_source_line` swallows the failure
            # and returns "". The snippet then silently vanished for exactly the
            # registry rules this fallback exists to serve.
            snippet = _source_line(os.path.join(os.path.abspath(target), rel),
                                   line_no, line_cache)

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
