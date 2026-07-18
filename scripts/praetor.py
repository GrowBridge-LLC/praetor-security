#!/usr/bin/env python3
"""
PRAETOR -- multi-engine security analysis.

A best-in-class, open-source Claude Code skill that runs four complementary
security engines over a target path and fuses their output into one prioritized,
deduplicated, false-positive-filtered report (human-readable + JSON):

  sast     Semgrep (OSS)                 OWASP Top 10, injection, auth, many langs
  secrets  built-in                      provider patterns + entropy + base64 unwrap
  sca      osv-scanner / pip-audit / npm known-vulnerable dependencies
  aisec    built-in                      prompt injection, invisible-unicode, exfil,
                                         dangerous auto-run hooks, safety-bypass

SAFETY: PRAETOR is a STATIC analyzer. It reads files; it never executes, imports,
installs, or evaluates the code it scans, and it never transmits scan data
anywhere. Detected secrets are redacted in all output.

Usage:
  python praetor.py <target> [options]

Exit codes:
  0  no active findings at/above --fail-on (default: nothing fails the run)
  1  active findings at/above --fail-on
  2  usage / internal error
"""

from __future__ import annotations

import argparse
import os
import sys

# make sibling engine modules importable no matter the CWD
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import core                      # noqa: E402
import engine_secrets            # noqa: E402
import engine_aisec             # noqa: E402
import engine_sast              # noqa: E402
import engine_sca               # noqa: E402
import interpret                # noqa: E402
import report                   # noqa: E402

VERSION = "1.0.0"
RULES_DIR = os.path.normpath(os.path.join(HERE, "..", "rules"))
BUNDLED_SEMGREP = os.path.join(RULES_DIR, "semgrep-praetor.yaml")

ALL_ENGINES = ["sast", "secrets", "sca", "aisec"]


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="praetor",
        description="Multi-engine static security analysis (SAST + secrets + SCA + AI-security).",
    )
    p.add_argument("target", nargs="?", default=".", help="File or directory to scan (default: current dir).")
    p.add_argument("--engines", default="all",
                   help="Comma list of engines to run: sast,secrets,sca,aisec (default: all).")
    p.add_argument("--format", choices=["text", "json", "both"], default="text",
                   help="Report format (default: text).")
    p.add_argument("--out", default="", help="Directory to write praetor-report.txt / .json.")
    p.add_argument("--min-severity", default="INFO",
                   choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Hide active findings below this severity (default: INFO = show all).")
    p.add_argument("--fail-on", default="",
                   choices=["", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Exit 1 if any active finding is at/above this severity (default: never fail).")
    p.add_argument("--sca-backend", default="auto",
                   choices=["auto", "osv", "pip-audit", "npm"],
                   help="SCA backend preference (default: auto = osv -> pip-audit -> npm).")
    p.add_argument("--semgrep-runtime", default="auto",
                   choices=["auto", "native", "wsl", "docker"],
                   help="How to run Semgrep (default: auto = native -> WSL -> Docker).")
    p.add_argument("--wsl-distro", default="Ubuntu", help="WSL distro for the WSL Semgrep runtime.")
    p.add_argument("--no-registry", action="store_true",
                   help="Do not fetch Semgrep registry packs; use only bundled offline rules.")
    p.add_argument("--semgrep-config", action="append", default=[],
                   help="Extra Semgrep --config (repeatable), e.g. p/owasp-top-ten or a local file.")
    p.add_argument("--max-file-size", type=int, default=core.DEFAULT_MAX_BYTES,
                   help="Skip files larger than this many bytes (default: 3MB).")
    p.add_argument("--exclude", action="append", default=[],
                   help="Regex of relative paths to exclude (repeatable).")
    p.add_argument("--no-redact", action="store_true",
                   help="(Discouraged) do not redact matched secrets. Off by default.")
    p.add_argument("--quiet", action="store_true", help="Suppress progress messages on stderr.")
    p.add_argument("--version", action="version", version=f"praetor {VERSION}")
    return p.parse_args(argv)


def _log(quiet, msg):
    if not quiet:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()


IGNORE_MARKERS = ("nosec", "nosemgrep", "praetor:ignore", "praetor-ignore")


def _apply_inline_ignores(findings, target, read_text):
    """
    Mark findings filtered when their flagged source line carries an inline ignore
    marker. This is an explicit, auditable suppression visible in the source --
    the opposite of a scanner silently exempting files from itself.
    """
    cache: dict = {}
    for f in findings:
        if not f.file or f.line <= 0:
            continue
        ap = os.path.join(target, f.file.replace("/", os.sep))
        if ap not in cache:
            txt = read_text(ap)
            cache[ap] = txt.splitlines() if txt else []
        lines = cache[ap]
        if 1 <= f.line <= len(lines):
            low = lines[f.line - 1].lower()
            if any(m in low for m in IGNORE_MARKERS):
                f.filtered = True
                f.filter_reason = "suppressed by inline ignore marker on the flagged line"


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        sys.stderr.write(f"praetor: target not found: {target}\n")
        return 2

    engines = ALL_ENGINES if args.engines.strip().lower() == "all" else \
        [e.strip().lower() for e in args.engines.split(",") if e.strip()]
    for e in engines:
        if e not in ALL_ENGINES:
            sys.stderr.write(f"praetor: unknown engine '{e}' (valid: {', '.join(ALL_ENGINES)})\n")
            return 2

    _log(args.quiet, f"praetor {VERSION}: scanning {target}")

    # Enumerate scannable text files exactly once (shared by secrets + aisec).
    scan_files = core.walk_files(target, max_bytes=args.max_file_size, extra_excludes=args.exclude)
    _log(args.quiet, f"  enumerated {len(scan_files)} text file(s)")

    read_text = (lambda p: core.read_text(p, args.max_file_size))

    all_findings = []
    engine_meta = {}

    # -- secrets --------------------------------------------------------------
    if "secrets" in engines:
        _log(args.quiet, "  [secrets] scanning...")
        try:
            fs = engine_secrets.scan(scan_files, read_text)
            all_findings.extend(fs)
            engine_meta["secrets"] = {"status": "ok", "detail": f"{len(fs)} raw finding(s); provider patterns + entropy + base64-unwrap"}
        except Exception as e:  # noqa
            engine_meta["secrets"] = {"status": "error", "detail": f"{e}"}
    else:
        engine_meta["secrets"] = {"status": "disabled", "detail": "not selected"}

    # -- aisec ----------------------------------------------------------------
    if "aisec" in engines:
        _log(args.quiet, "  [aisec] scanning...")
        try:
            fs = engine_aisec.scan(scan_files, read_text)
            all_findings.extend(fs)
            engine_meta["aisec"] = {"status": "ok", "detail": f"{len(fs)} raw finding(s); injection/unicode/exfil/hooks/bypass"}
        except Exception as e:  # noqa
            engine_meta["aisec"] = {"status": "error", "detail": f"{e}"}
    else:
        engine_meta["aisec"] = {"status": "disabled", "detail": "not selected"}

    # -- sast (semgrep) -------------------------------------------------------
    if "sast" in engines:
        _log(args.quiet, "  [sast] running semgrep (this may download rule packs on first run)...")
        try:
            res = engine_sast.run(
                target, BUNDLED_SEMGREP,
                use_registry=not args.no_registry,
                extra_configs=args.semgrep_config,
                prefer=args.semgrep_runtime, wsl_distro=args.wsl_distro,
                excludes=args.exclude,
            )
            all_findings.extend(res["findings"])
            engine_meta["sast"] = {"status": res["status"],
                                   "detail": f"{res['detail']} ({len(res['findings'])} finding(s)) via {res['runtime']}"}
        except Exception as e:  # noqa
            engine_meta["sast"] = {"status": "error", "detail": f"{e}"}
    else:
        engine_meta["sast"] = {"status": "disabled", "detail": "not selected"}

    # -- sca ------------------------------------------------------------------
    if "sca" in engines:
        _log(args.quiet, "  [sca] scanning dependencies...")
        try:
            res = engine_sca.run(target, backend=args.sca_backend, excludes=args.exclude)
            all_findings.extend(res["findings"])
            engine_meta["sca"] = {"status": res["status"],
                                  "detail": f"{res['detail']} ({len(res['findings'])} finding(s))"}
        except Exception as e:  # noqa
            engine_meta["sca"] = {"status": "error", "detail": f"{e}"}
    else:
        engine_meta["sca"] = {"status": "disabled", "detail": "not selected"}

    # -- inline suppression ---------------------------------------------------
    # Honor auditable, in-source ignore markers on the flagged line
    # (# nosec / # nosemgrep / # praetor:ignore, and // variants). Suppressed
    # findings are marked filtered WITH a reason -- never silently dropped.
    _apply_inline_ignores(all_findings, target, read_text)

    # -- interpretation -------------------------------------------------------
    _log(args.quiet, "  interpreting (dedup + rank + FP filter)...")
    result = interpret.interpret(all_findings)

    # min-severity filtering (moves below-threshold active findings out of the active list)
    min_sev = core.Severity.parse(args.min_severity)
    if min_sev > core.Severity.INFO:
        keep, dropped = [], 0
        for f in result["active"]:
            if f.severity >= min_sev:
                keep.append(f)
            else:
                dropped += 1
        result["active"] = keep
        result["total_active"] = len(keep)
        result["summary"] = {s.label: 0 for s in core.Severity}
        for f in keep:
            result["summary"][f.severity.label] += 1

    meta = {
        "target": target,
        "timestamp": report.now_iso(),
        "version": VERSION,
        "file_count": len(scan_files),
        "engines": engine_meta,
        "min_severity": args.min_severity,
    }

    # -- output ---------------------------------------------------------------
    text = report.render_text(result, meta)
    js = report.render_json(result, meta)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "praetor-report.txt"), "w", encoding="utf-8") as fh:
            fh.write(text)
        with open(os.path.join(args.out, "praetor-report.json"), "w", encoding="utf-8") as fh:
            fh.write(js)
        _log(args.quiet, f"  reports written to {args.out}")

    if args.format in ("text", "both"):
        print(text)
    if args.format in ("json", "both"):
        print(js)

    # -- exit code ------------------------------------------------------------
    if args.fail_on:
        threshold = core.Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in result["active"]):
            return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
