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

#: Disables semgrep's own `.semgrepignore` handling, so the SCANNED TREE cannot
#: decide what gets scanned. See the long note at the call site.
#:
#: ⚠️ IT IS AN EXPERIMENTAL FLAG (`--x-` prefix), so it is not a stable contract.
#: Measured through this code path 2026-08-13: if semgrep DROPS the flag entirely
#: the run errors (`unknown option`) and PRAETOR reports `error` -> exit 3, which
#: fails SAFE. The dangerous case is the other one: the flag surviving as an
#: ACCEPTED NO-OP (deprecated-but-tolerated, or renamed in meaning). Then semgrep
#: succeeds, honours the ignore file again, and nothing errors.
#: ⇒ That is why the flag is NOT the guarantee. The guarantee is `_scanned_count()`
#: below, which measures what semgrep actually opened.
_SEMGREPIGNORE_OFF = "--x-ignore-semgrepignore-files"

#: Ignore files that live in the SCANNED TREE and can shrink semgrep's scope.
#: ⚠️ Used ONLY to enrich an error message. It is deliberately NOT part of the
#: scope guard's condition any more -- gating the guard on this list is exactly
#: what made the first version miss two total-shrink routes. See the guard.
_TARGET_CONTROLLED_IGNORE_FILES = (".semgrepignore",)

#: Extensions for files semgrep plausibly has a language for. Used only to ask
#: "did PRAETOR find code here?" before accusing semgrep of having opened none.
#:
#: ⚠️ A DELIBERATE NARROWING WITH A KNOWN DIRECTION. A language missing from this
#: set means a repo written only in that language does not get the scope check --
#: it does not mean a false alarm. So the failure mode is losing layer 2 for an
#: exotic language, with layer 1 (the flag) still in place; not blocking a
#: legitimate scan.
#:
#: 🔴 "ADD TO IT FREELY" WAS THE WRONG REMEDY AND POINTED AT THE WRONG GATE.
#: `count_code_files` only ever sees what `core.walk_files` yielded, and that is
#: gated on `core.TEXT_EXTS`. Six extensions ALREADY IN THIS SET are absent from
#: TEXT_EXTS and can therefore never be counted:
#:     .clj  .cljs  .cxx  .ex  .exs  .sol
#: So a Solidity or Elixir repo has `enumerated_code_files == 0` permanently and
#: the two-count scope guard is DISABLED for it -- while `.sol` sitting in this
#: list reads as coverage. An entry here is inert unless TEXT_EXTS has it too.
#: ⇒ To extend, add to BOTH, and prefer deriving this set from TEXT_EXTS so the
#: two cannot drift again. Found by an independent reviewer.
_CODE_EXTENSIONS = frozenset({
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt",
    ".kts", ".go", ".rb", ".php", ".cs", ".c", ".h", ".cc", ".cpp", ".hpp",
    ".cxx", ".rs", ".swift", ".scala", ".sh", ".bash", ".sol", ".ex", ".exs",
    ".lua", ".dart", ".m", ".mm", ".clj", ".cljs", ".hcl", ".tf", ".vue",
})


def count_code_files(scan_files) -> int:
    """How many of PRAETOR's own enumerated files semgrep could plausibly open.

    One half of the scope guard's two counts. Takes anything with `.relpath`.
    """
    n = 0
    for sf in (scan_files or []):
        path = getattr(sf, "relpath", None) or getattr(sf, "abspath", "") or str(sf)
        if os.path.splitext(path)[1].lower() in _CODE_EXTENSIONS:
            n += 1
    return n


def _target_ignore_files(target: str) -> list:
    """Ignore files inside the target that semgrep would otherwise honour.

    Cheap and shallow-ish by design: semgrep resolves `.semgrepignore` from the
    scan root, so the root copy is the one that matters, but a nested one is
    reported too rather than assumed harmless.
    """
    found = []
    if not os.path.isdir(target):
        return found
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__")]
        for name in files:
            if name in _TARGET_CONTROLLED_IGNORE_FILES:
                found.append(os.path.join(root, name))
        if len(found) > 20:
            break
    return found


def _scanned_count(data: dict) -> int:
    """How many files semgrep actually OPENED, per its own JSON.

    🔴 A COUNT, NOT A STATUS. `scan errors=0` and exit 0 are both satisfied by a
    run that opened nothing, which is exactly what an in-tree ignore file
    produces. This number is the only term in the SAST path that a silence
    cannot satisfy. Returns -1 when semgrep did not report it, so "absent" is
    never confused with "zero".
    """
    paths = data.get("paths")
    if not isinstance(paths, dict):
        return -1
    scanned = paths.get("scanned")
    if not isinstance(scanned, list):
        return -1
    return len(scanned)


def _win_to_wsl(path: str) -> str:
    """Map a Windows path to the /mnt/<drive> form WSL reports under.

    🔴 THE DRIVE LETTER MUST BE READ BEFORE `abspath`, NOT AFTER.

    `os.path.abspath` is platform-dependent, and on a NON-Windows interpreter it
    does not recognise `C:\\projects\\X` as absolute -- it treats the whole thing
    as a relative name and prepends the current directory:

        Windows: abspath('C:\\projects\\P') -> 'C:\\projects\\P'      -> /mnt/c/projects/P
        Linux:   abspath('C:\\projects\\P') -> '/home/runner/…/C:\\projects\\P'

    So `p[1] == ":"` was False on Linux, the drive branch never ran, and the
    function silently returned a path anchored under the caller's cwd. Every
    finding's `file` would then be wrong for anyone running `--semgrep-runtime
    wsl` from a non-Windows host, and `_relative_to_report_root` would hand the
    raw path straight through -- which four later passes read as a file to open.

    Found by CI, on the push that fixed the failure masking it: this test had
    been red on Linux since it was written and no Windows run could see it.
    Same shape as the interpreter pin it sat behind -- a gate that only ever runs
    on the platform where the assertion happens to hold is not a check.
    """
    raw = path.replace("\\", "/")
    if len(raw) >= 2 and raw[1] == ":" and raw[0].isalpha():
        return f"/mnt/{raw[0].lower()}{raw[2:]}"
    p = os.path.abspath(path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":" and p[0].isalpha():
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
        timeout: int = _SEMGREP_TIMEOUT, excludes=None,
        enumerated_code_files: int = -1, skip_dirs=None) -> dict:
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
              "--no-git-ignore",
              # 🔴 AND THE SAME CLASS AGAIN, ONE FILENAME OVER. `--no-git-ignore`
              # disables `.gitignore`. It does NOT disable `.semgrepignore`, which
              # is a SEPARATE mechanism semgrep honours by default and which lives
              # in the scanned tree. Measured 2026-08-13 on a target with one
              # os.system-concat finding:
              #     control                            -> [ran] 1 finding,  exit 1
              #     + .semgrepignore containing "*"    -> [ran] 0 findings, exit 0
              #     + .semgrepignore naming the file   -> [ran] 0 findings, exit 0
              # `scan errors=0`, status `ok`, gate-trusted, and it passes the
              # file-count floor too -- that floor counts PRAETOR's OWN walker,
              # which still enumerated the file. ⇒ **A file committed to the
              # scanned repository silently disabled the entire SAST engine.**
              #
              # Neither `--include` (applied AFTER semgrepignore filtering) nor
              # relocating cwd helps -- measured: semgrep resolves the ignore file
              # from the SCAN ROOT, not the working directory.
              _SEMGREPIGNORE_OFF]
    # Semgrep --exclude takes a path/glob pattern; pass each exclude through so
    # the SAST engine honors the same exclusions as the built-in engines.
    for pat in (excludes or []):
        common += ["--exclude", pat]

    # 🔴 `_SEMGREPIGNORE_OFF` DOES NOT ONLY DISABLE `.semgrepignore`. It also
    # disables semgrep's BUILT-IN default ignore set, which is how `node_modules`,
    # `vendor`, `dist`, `build` and `.venv` stop being scanned. Measured on the
    # tree that motivated the flag: scanned went 7 -> 14, and on a synthetic
    # 3000-file `node_modules`, findings went 1 -> 3001 with elapsed 1.6s -> 4.1s.
    #
    # That is the SAME defect the `--no-git-ignore` note above describes, inverted:
    # PRAETOR's own walker skips these directories (core.DEFAULT_SKIP_DIRS), so
    # semgrep was scanning a tree the other engines refuse to open, and the report
    # printed one `Files (text): N` header over findings from both. Third-party
    # vendored code was being reported as the target's own.
    #
    # ⇒ Restore the scope explicitly, from PRAETOR's list rather than semgrep's,
    # so exactly one component decides what is in scope and the engines agree.
    # 🔴 `skip_dirs` MUST come from the caller, not from the constant.
    #
    # This loop used to read `core.DEFAULT_SKIP_DIRS` directly. When
    # `--no-default-skips` was added to praetor.py so a DISTRIBUTED artifact could
    # be scanned, PRAETOR's walker started reading `dist/` while this line kept
    # excluding it -- so the header printed `Files (text): 80` over a semgrep run
    # that had opened almost none of them. Measured on the same npm tarball, same
    # bytes, only the directory NAME differing:
    #     directory named `dist/`     -> semgrep 0 findings
    #     directory named `shipped/`  -> semgrep 10 findings
    # ⇒ That is the very desynchronisation the comment above exists to prevent,
    # reintroduced by the fix for a different scope defect. One component decides
    # scope; this line must follow it rather than re-derive it.
    for d in sorted(core.DEFAULT_SKIP_DIRS if skip_dirs is None else skip_dirs):
        common += ["--exclude", d]

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

    def _invoke(command):
        """Run semgrep; returns (completed, error_result). Exactly one is None."""
        try:
            return core.run_tool(command, timeout=timeout, cwd=cwd), None
        except subprocess.TimeoutExpired:
            return None, {"findings": [], "status": "error",
                          "detail": "semgrep timed out", "runtime": mode}
        except Exception as e:  # noqa
            return None, {"findings": [], "status": "error",
                          "detail": f"semgrep failed to launch: {e}", "runtime": mode}

    r, failed = _invoke(cmd)
    if failed:
        return failed

    # 🔴 AN EXPERIMENTAL FLAG MUST NOT BE ABLE TO BREAK THE ENGINE ON EVERY SCAN.
    # `_SEMGREPIGNORE_OFF` is `--x-` prefixed and therefore not a stable contract.
    # Measured: a semgrep that does not know it exits 2 with `unknown option`, no
    # stdout -- which this function then reports as `error`, so **every SAST scan
    # returns exit 3 under --fail-on**. That is a hard availability break for
    # anyone on an older semgrep, caused entirely by our own hardening flag, and
    # it is exactly the shape that earns a tool a `|| true` in someone's CI.
    #
    # So: detect that specific rejection and retry once WITHOUT the flag. We then
    # run with semgrep honouring `.semgrepignore` again -- degraded, not blind,
    # because the scope guard below compares two independent counts and does not
    # depend on this flag. The degradation is recorded in `detail` so it is
    # visible in the report rather than silent.
    semgrepignore_off = True
    err_text = (r.stderr or "")
    if r.returncode not in (0, 1) and _SEMGREPIGNORE_OFF in err_text and "unknown option" in err_text:
        retry_cmd = [a for a in cmd if a != _SEMGREPIGNORE_OFF]
        r, failed = _invoke(retry_cmd)
        if failed:
            return failed
        semgrepignore_off = False

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

    # 🔴 THE GUARANTEE FOR SCOPE: TWO INDEPENDENT COUNTS THAT MUST NOT DISAGREE.
    # `enumerated_code_files` is what PRAETOR's OWN walker found here.
    # `scanned` is what semgrep says it actually opened. If ours is positive and
    # semgrep's is zero, something decided the scope that neither of us chose,
    # and the SAST engine's silence carries no information.
    #
    # ⚠️ THIS REPLACED A CONJUNCTION THAT WAS THE BUG, and the correction is the
    # whole lesson. The first version fired on "opened nothing" AND "a file named
    # `.semgrepignore` exists INSIDE the target" -- and a comment claimed its only
    # gap was PARTIAL shrink. An independent auditor found two TOTAL-shrink routes
    # it missed, hours later:
    #   * `.semgrepignore` at the GIT ROOT, above the scan target -- the ordinary
    #     CI shape `praetor $REPO/src`. The walk inside `target` cannot see it.
    #   * code living in a directory semgrep ignores by default -- no attacker
    #     file exists anywhere, so there was nothing for the walk to find.
    # ⇒ The measurement was real; it was GATED BEHIND AN ENUMERATION OF SPELLINGS,
    # which made it an enumeration. Same defect as `engines_that_measured` reading
    # a status word, one commit later, in a different file. **The conjunction was
    # the bug.** Comparing the two counts needs no filename and covers all three.
    #
    # `> 0` on our side, not `>= 0`: a genuinely empty or docs-only tree gives 0
    # on both sides and must stay quiet, or the guard false-alarms on every repo
    # semgrep has no language for -- and a gate that cries wolf gets disabled by
    # whoever it blocks.
    #
    # ⚠️ STATED GAP, still real: this catches scope shrunk to NOTHING. An ignore
    # rule that removes only PART of a tree leaves scanned > 0 and passes here.
    scanned = _scanned_count(data)
    if scanned == 0 and enumerated_code_files > 0:
        ignore_files = _target_ignore_files(target)
        because = ""
        if ignore_files:
            rels = ", ".join(os.path.relpath(p, target) for p in ignore_files[:5])
            because = f" the target carries an ignore file semgrep honours ({rels});"
        # Carry the fallback note into THIS path too. Found while testing the live
        # CI check: when semgrep rejects the flag we retry without it, semgrep then
        # honours the tree's ignore file, and the scope guard fires and returns
        # HERE -- before the success path that appends the note. So the operator
        # saw "scope disagreement" and never learned their semgrep was too old,
        # which is the actionable half of the diagnosis.
        stale = ("" if semgrepignore_off else
                 f" NOTE this semgrep rejected {_SEMGREPIGNORE_OFF}, so the target's own"
                 " .semgrepignore was honoured -- upgrade semgrep and re-run before"
                 " treating this as an attack.")
        return {"findings": [], "status": "error",
                "detail": (f"scope disagreement: PRAETOR enumerated {enumerated_code_files} "
                           f"code file(s) here and semgrep opened 0.{because} a zero from an "
                           f"engine that opened nothing is not a clean result.{stale}"),
                "runtime": mode}

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
    if not semgrepignore_off:
        # Visible, not silent: this semgrep did not accept the flag, so the
        # scanned tree's own `.semgrepignore` was honoured on this run. The scope
        # guard above still applies; a reader should know which regime produced
        # this result.
        detail += (f"; NOTE this semgrep rejected {_SEMGREPIGNORE_OFF}, so the target's "
                   "own .semgrepignore was honoured -- scope guard active, but upgrade "
                   "semgrep for full protection")
    return {"findings": findings, "status": "ok", "detail": detail, "runtime": mode}
