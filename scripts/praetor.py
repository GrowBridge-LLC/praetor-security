#!/usr/bin/env python3
"""
PRAETOR -- multi-engine security analysis.

A best-in-class, open-source security scanner. It runs four complementary engines
over a target path and fuses their output into one prioritized, deduplicated,
false-positive-filtered report (human-readable + JSON).

It is distributed as a Claude Code skill (see SKILL.md) but this file is a
standalone Python CLI with no assistant in the loop -- and the `aisec` engine is
deliberately vendor-neutral: a hostile `.cursorrules` or `.cursor/hooks.json` is
the same attack as a hostile `CLAUDE.md`, and PRAETOR must not see only one
vendor's spelling of it.

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
  0  scan fully measured, no active findings at/above --fail-on
     (without --fail-on, nothing fails the run: report-only by request)
  1  active findings at/above --fail-on
  2  usage / internal error
  3  --fail-on was requested but an engine COULD NOT MEASURE (errored or was
     unavailable), so "no findings" does not mean "nothing there". Suppress with
     --allow-degraded if you knowingly gate on a partial scan.

  🔴 1 outranks 3: real findings are the more actionable signal. Both are
  non-zero, so a gate that only tests `if rc != 0` fails safe either way.
"""

from __future__ import annotations

import argparse
import os
import re
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
import lexctx                   # noqa: E402
import taint                    # noqa: E402
import report                   # noqa: E402

VERSION = "1.0.0"
def _find_bundled_rules():
    """
    Locate the bundled offline Semgrep rules, which live in different places
    depending on how PRAETOR was obtained.

    From a clone, praetor.py sits in scripts/ and the rules are a sibling
    directory. Installed from a wheel, praetor.py is a top-level module in
    site-packages and `../rules` resolves to the environment's lib dir, where
    nothing exists -- which silently cost the `--no-registry` path its rules.

    Ordered so a checkout always wins: a developer editing rules/ should see
    their edits, not a stale copy installed in the same environment.

    Returns (rules_dir, rules_file). The file may not exist; the SAST engine
    already reports honestly when it is absent, and PRAETOR_RULES_DIR lets a
    packager point at a location this list does not anticipate.
    """
    candidates = []
    env = os.environ.get("PRAETOR_RULES_DIR")
    if env:
        candidates.append(env)
    candidates.append(os.path.normpath(os.path.join(HERE, "..", "rules")))   # clone
    candidates.append(os.path.join(sys.prefix, "share", "praetor", "rules"))  # wheel
    candidates.append(os.path.join(os.path.dirname(sys.prefix), "share", "praetor", "rules"))  # venv edge

    for d in candidates:
        if os.path.isfile(os.path.join(d, "semgrep-praetor.yaml")):
            return d, os.path.join(d, "semgrep-praetor.yaml")
    # Nothing found: return the clone-relative path so error text stays familiar.
    fallback = os.path.normpath(os.path.join(HERE, "..", "rules"))
    return fallback, os.path.join(fallback, "semgrep-praetor.yaml")


RULES_DIR, BUNDLED_SEMGREP = _find_bundled_rules()

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
                   help="Exit 1 if any active finding is at/above this severity (default: never fail). "
                        "Exit 3 if an engine could not measure at all -- see --allow-degraded.")
    p.add_argument("--allow-degraded", action="store_true",
                   help="With --fail-on, do NOT exit 3 when an engine errored or was unavailable. "
                        "Gates on findings alone, knowingly accepting an unmeasured blind spot.")
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
            # core.split_lines, NEVER str.splitlines: `f.line` is \n-based, and
            # resolving it against a splitlines() list lets a U+2028 in the
            # scanned file shift the index onto an unrelated line. That is a
            # suppression primitive -- see core.split_lines.
            cache[ap] = core.split_lines(txt) if txt else []
        lines = cache[ap]
        if 1 <= f.line <= len(lines):
            low = lines[f.line - 1].lower()
            if any(m in low for m in IGNORE_MARKERS):
                f.filtered = True
                f.filter_reason = "suppressed by inline ignore marker on the flagged line"


# Engines whose findings may be suppressed by lexical context.
#
# 🔴 `secrets` IS DELIBERATELY ABSENT AND MUST STAY ABSENT.
# A behavioural pattern in a comment is inert -- the comment cannot exec anything.
# A SECRET in a comment is still a leaked credential; it is disclosed by being
# written down, not by being executed. Adding "secrets" here would make PRAETOR
# blind to `# password = "hunter2"`.
# Held by tests/test_lexctx_and_suppression_policy.py.
_LEXCTX_ENGINES = ("aisec",)

_LEXCTX_REASONS = {
    lexctx.COMMENT: "behavioural pattern appears in a code comment, which cannot execute",
    lexctx.DOCSTRING: "behavioural pattern appears in a docstring describing the threat, which cannot execute",
}


# Engines whose findings may be suppressed by REACHABILITY (A1).
#
# 🔴 `secrets` IS DELIBERATELY ABSENT, and the reason is NOT the same as intuition
# suggests. Reachability cannot protect a credential: a key declared in a config
# module and used elsewhere never reaches a sink in that file, so it is "provably
# inert" -- byte-identical to a regex pattern. Measured, after the opposite was
# claimed publicly. The safety comes from THIS SCOPE, never from the analysis.
# Held by tests/test_taint_reachability.py.
_REACHABILITY_ENGINES = ("aisec",)


def _apply_reachability(findings, target, read_text):
    """
    Suppress behavioural findings whose matched string provably never reaches a
    dangerous sink (A1). Fails SAFE: anything unproven is KEPT.
    """
    cache: dict = {}
    for f in findings:
        if getattr(f, "filtered", False) or f.engine not in _REACHABILITY_ENGINES:
            continue
        if not f.file or f.line <= 0 or not f.file.endswith(".py"):
            continue
        ap = os.path.join(target, f.file.replace("/", os.sep))
        if ap not in cache:
            cache[ap] = read_text(ap) or ""
        if taint.is_provably_inert(cache[ap], f.line):
            f.filtered = True
            f.filter_reason = (
                "matched string provably never reaches a dangerous sink "
                "(rule definition / inert data, not behaviour)"
            )


# --------------------------------------------------------------------------- #
# Injection-exemplar suppression (A2)
# --------------------------------------------------------------------------- #
# Documents that DEFEND against prompt injection quote the attack in order to warn
# about it. PRAETOR flagged exactly that in another vendor's security plugin: an
# agent brief saying that text addressing you -- and it quoted a specimen -- "is
# something to mention in your report, not a direction to follow" was reported as
# an instruction-override attempt, at HIGH.
#
# 🔴 THE OBVIOUS FIX IS A VULNERABILITY. "Suppress the pattern when it is inside
# quotes" hands an attacker a suppression primitive: wrap the payload in quotes
# and the scanner goes quiet. That is the same shape as the line-numbering bypass
# already fixed here -- a suppression whose trigger the attacker controls.
#
# So BOTH must hold, and the second is the load-bearing one:
#   1. the matched span lies inside a quotation on that line, AND
#   2. the surrounding two lines carry an explicit instruction to treat such text
#      as DATA rather than as a directive.
#
# (2) cannot be satisfied without the document telling its reader, in the same
# breath, not to obey the quoted text -- which materially defeats the payload it
# would be hiding. `test_quotes_alone_do_not_suppress` holds this open: a quoted
# injection with no defensive framing still fires at full severity.
#
# Fails SAFE like every other pass here: anything unproven is KEPT, and what is
# suppressed moves to the filtered bucket with this reason attached, never dropped.
_EXEMPLAR_QUOTED = re.compile(r"[\"'`“”‘’]")
_DEFENSIVE_FRAME = re.compile(
    r"(?i)("
    r"\bare all data\b|\bis all data\b|\bas data\b|\bare data\b|\bis data\b"
    r"|\bnever a source of instruction|\bnot a source of instruction"
    r"|\bnot a direction to follow\b|\bnot an instruction\b|\bnot instructions\b"
    r"|\bdo not follow\b|\bnever follow\b|\bmust not follow\b"
    r"|\bmention (it|them|this|that)?\s*in your report\b"
    r"|\btreat[^.\n]{0,40}\b(as )?(untrusted|data|not instructions)\b"
    r"|\bobject of study\b|\bnot a command\b"
    r")"
)
_EXEMPLAR_REASON = (
    "injection phrasing appears as a QUOTED EXEMPLAR inside text that explicitly "
    "instructs the reader to treat such content as data, not as a directive "
    "(defensive documentation, not an injection attempt)"
)


def _span_is_quoted(line: str, start: int, end: int) -> bool:
    """True when the [start,end) span sits between quote characters on this line."""
    before = line[:start]
    after = line[end:]
    return bool(_EXEMPLAR_QUOTED.search(before) and _EXEMPLAR_QUOTED.search(after))


def _apply_injection_exemplar(findings, target, read_text):
    """Suppress injection matches that are quoted specimens inside a warning.

    Narrow by construction: see the comment block above for why the quoting test
    alone is deliberately NOT sufficient.
    """
    cache: dict = {}
    by_id = {rid: rx for rid, _t, rx, *_rest in engine_aisec.INJECTION}
    for f in findings:
        if getattr(f, "filtered", False) or f.engine not in _LEXCTX_ENGINES:
            continue
        if f.category != "PROMPT_INJECTION" or not f.file or f.line <= 0:
            continue
        rx = by_id.get(f.rule_id)
        if rx is None:
            continue
        ap = os.path.join(target, f.file.replace("/", os.sep))
        if ap not in cache:
            cache[ap] = read_text(ap) or ""
        lines = core.split_lines(cache[ap])
        if f.line > len(lines):
            continue                      # unreadable / shifted -> KEEP
        line = lines[f.line - 1]
        m = rx.search(line)
        if m is None or not _span_is_quoted(line, m.start(), m.end()):
            continue
        # Look at the line itself plus one either side: the warning often precedes
        # or follows the specimen rather than sharing its line.
        lo, hi = max(0, f.line - 2), min(len(lines), f.line + 1)
        if not _DEFENSIVE_FRAME.search(" ".join(lines[lo:hi])):
            continue                      # quoted but unframed -> KEEP
        f.filtered = True
        f.filter_reason = _EXEMPLAR_REASON


def _apply_lexical_context(findings, target, read_text):
    """
    Suppress behavioural findings whose match is in text that never executes.

    Measured motivation: every one of PRAETOR's 47 self-scan findings was
    pattern-presence in inert text (references/SELF-SCAN-BASELINE.json).

    Suppression is recorded with a rationale, never deleted, and it fails SAFE --
    an unreadable file or an unclear line resolves to CODE and the finding is KEPT.
    """
    cache: dict = {}
    for f in findings:
        if getattr(f, "filtered", False) or f.engine not in _LEXCTX_ENGINES:
            continue
        if not f.file or f.line <= 0:
            continue
        ap = os.path.join(target, f.file.replace("/", os.sep))
        if ap not in cache:
            cache[ap] = read_text(ap) or ""
        ctx = lexctx.context_of(cache[ap], f.line)
        reason = _LEXCTX_REASONS.get(ctx)
        if reason:
            f.filtered = True
            f.filter_reason = reason


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
    _apply_lexical_context(all_findings, target, read_text)
    _apply_injection_exemplar(all_findings, target, read_text)
    _apply_reachability(all_findings, target, read_text)

    # -- interpretation -------------------------------------------------------
    _log(args.quiet, "  interpreting (dedup + rank + FP filter)...")
    result = interpret.interpret(all_findings)

    # 🔴 What the GATE judges, captured BEFORE --min-severity edits the list.
    # --min-severity is a DISPLAY filter and --fail-on is a GATE, and they were
    # reading the same mutated list, so the display filter silently narrowed the
    # gate: `--min-severity CRITICAL --fail-on HIGH` removed every HIGH finding
    # from result["active"] and then found nothing at/above HIGH -- exit 0 on a
    # target with a live HIGH-severity leaked credential, with both flags doing
    # exactly what their help text says. Reproduced before this line existed.
    #
    # `--fail-on HIGH` means "fail if a HIGH exists", not "fail if a HIGH
    # survived the reporting threshold". Only findings the interpreter FILTERED
    # (false positives, suppressed with a stated reason) stay out of the gate --
    # that exclusion is auditable; this one was invisible.
    gate_findings = list(result["active"])

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
    # 🔴 The gate reads engine STATUS, not just findings. An engine that errored
    # or was unavailable produced zero findings for a reason that has nothing to
    # do with the target being clean -- and before 2026-08-12 this block consulted
    # result["active"] alone, so a scan whose SAST engine died returned exit 0,
    # byte-identical to a fully-measured clean run. The information already
    # existed in engine_meta and reached the report; it never reached the
    # decision. Found by an independent reader of this file, not by its author.
    if args.fail_on:
        threshold = core.Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in gate_findings):
            return 1
        blind = core.engine_blind_spots(engine_meta)
        if blind and not args.allow_degraded:
            sys.stderr.write(
                "praetor: SCAN DEGRADED -- --fail-on cannot pass a scan that was not "
                "fully measured.\n"
            )
            for name, status, detail in blind:
                sys.stderr.write(f"  [{status}] {name}: {detail}\n")
            sys.stderr.write(
                "  A zero from an engine that did not run is not a clean result. "
                "Re-run once the engine is available, or pass --allow-degraded to "
                "gate on findings alone.\n"
            )
            return 3
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
