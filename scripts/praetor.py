#!/usr/bin/env python3
"""
PRAETOR -- multi-engine security analysis.

A best-in-class, open-source security scanner. It runs five complementary engines
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
  model    built-in                      pickle-opcode disassembly (pickletools.genops,
                                         never pickle.load) for .pt/.pth/.ckpt/.pkl/.npy/
                                         .npz/.h5/.hdf5/.keras/.bin/.joblib/.dill

SAFETY: PRAETOR is a STATIC analyzer. It reads files; it never executes, imports,
installs, or evaluates the code it scans, and it never transmits scan data
anywhere. Detected secrets are redacted in all output.

Usage:
  python praetor.py <target> [options]

Exit codes:
  0  no active findings at/above --fail-on. NOT a certificate of coverage:
     without --fail-on, an unavailable runtime remains visible as [BLIND], but
     an enabled engine error is a malfunction and exits 3.
  1  active findings at/above --fail-on
  2  usage / internal error
  3  THE SCAN DID NOT COMPLETE safely enough to pass. An enabled engine error or
     unrecognised status reaches 3 even without --fail-on; an explicit findings gate also returns 3
     for these blind-spot routes:
       * an unavailable runtime;
       * zero files were examined (a byte cap or --exclude emptied the tree);
       * two components disagreed about scope -- PRAETOR enumerated code and
         semgrep opened none of it, which is how a file in the scanned repo
         switched an engine off;
       * every engine held a TRUSTED status and none of them measured
         ("NOTHING WAS MEASURED") -- the `--engines ""` family.
     (This list said THREE until an independent reviewer counted the fourth.)
     Suppress with --allow-degraded if you knowingly accept a partial scan.

  🔴 1 outranks 3: real findings are the more actionable signal. Both are
  non-zero, so a gate that only tests `if rc != 0` fails safe either way.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
import time
import traceback

# make sibling engine modules importable no matter the CWD
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def _drop_the_working_directory_from_the_import_path():
    """🔴 THE NEVER-EXECUTE INVARIANT, BROKEN THROUGH `python -m praetor`.

    PRAETOR installs as FIFTEEN FLAT TOP-LEVEL MODULES (`core`, `interpret`,
    `taint`, every `engine_*`). `python -m <name>` puts the CURRENT WORKING
    DIRECTORY first on `sys.path`. So running

        cd <a repository you were asked to vet>
        python -m praetor .

    made PRAETOR's own `import core` resolve to **the target's** `core.py` and
    execute it. Measured, on an installed copy: a planted `core.py` wrote its
    marker file and the scan produced no output at all.

    ⚠️ AND THE EXIT CODE HID IT. That run returned 1 -- the same code as "found
    findings at or above --fail-on". A CI gate reading `$?` could not tell a real
    HIGH finding from "the scanner never ran and your target's code did".

    ⇒ Any `sys.path` entry that is the working directory is removed before the
    first first-party import. `HERE` is kept even when it happens to equal the
    working directory, because running `python praetor.py` from inside
    `scripts/` is a legitimate invocation and its imports must still resolve.

    ⚠️ WHAT THIS DOES NOT CLOSE, stated rather than left to a later audit: a
    target that plants a file named `praetor.py` pre-empts `python -m praetor`
    BEFORE any line of this file runs. Nothing inside this file can defend
    against that, and no ordering of these statements would. The complete fix is
    to stop installing flat top-level modules and ship a package instead, so no
    single-word module name is shadowable. That is recorded as work, not done.

    The console script (`praetor ...`) and `python scripts/praetor.py ...` were
    measured UNAFFECTED: neither puts the working directory on the path.
    """
    try:
        cwd = os.path.realpath(os.getcwd())
    except OSError:
        return  # an unreadable CWD cannot shadow anything
    here = os.path.realpath(HERE)
    for entry in list(sys.path):
        if entry in ("", "."):
            sys.path.remove(entry)
            continue
        try:
            resolved = os.path.realpath(entry)
        except (OSError, ValueError):
            continue
        if resolved == cwd and resolved != here:
            sys.path.remove(entry)


_drop_the_working_directory_from_the_import_path()

import core                      # noqa: E402
import engine_secrets            # noqa: E402
import engine_aisec             # noqa: E402
import engine_sast              # noqa: E402
import engine_sca               # noqa: E402
import engine_model             # noqa: E402
import interpret                # noqa: E402
import lexctx                   # noqa: E402
import taint                    # noqa: E402
import report                   # noqa: E402
import sarif                    # noqa: E402
import crossfile                # noqa: E402


#: Counters that describe WHAT A WALK REFUSED, as opposed to the SHAPE of the
#: primary text scope.
#:
#: 🔴 THE DISTINCTION IS LOAD-BEARING AND SHARING THE WHOLE DICT BROKE IT. The
#: supplementary walks were given `scope_stats` directly so their drops would
#: stop being silent -- and they then also incremented `kept_code_files`, which
#: the "NO CODE WAS EXAMINED" floor reads. A tree whose only real code sat in
#: `dist/` started returning exit 0 because the aisec walk had admitted a
#: `package.json` at the root, so the floor concluded code had been measured.
#: Three tests caught it; without them the repair for one false clean would have
#: created another.
#:
#: `kept_code_files`, `skipped_code_files`, `skipped_dirs` and
#: `excluded_by_pattern` describe the PRIMARY walk's scope and must come from
#: that walk alone. The drop counters below are additive facts about refusals
#: and are merged from every walk.
_DROP_COUNTERS = ("oversize", "binary", "unstattable")


def _merge_drop_counters(into: dict, extra: dict) -> None:
    """Fold a supplementary walk's refusals into the reported scope.

    Counts are REFUSALS, not distinct files: the walks overlap, so one file
    refused by two of them counts twice. Stated in the report rather than
    deduplicated -- an over-count of "what I did not read" errs toward
    disclosure, and making it tidy is how the first version came to report zero.
    """
    for key in _DROP_COUNTERS:
        into[f"{key}_files"] = into.get(f"{key}_files", 0) + extra.get(f"{key}_files", 0)
        examples = into.setdefault(f"{key}_examples", [])
        for item in extra.get(f"{key}_examples", []):
            if len(examples) >= 20:
                break
            if item not in examples:
                examples.append(item)


def _emit_nothing_examined(target: str, args) -> None:
    """Explain a scan that opened zero files. Called from BOTH exit paths.

    It used to be written out inline at one of them. The gated path now checks
    the same condition earlier -- see the comment at that call site -- and two
    copies of an operator-facing explanation drift.
    """
    sys.stderr.write(
        "praetor: NOTHING WAS EXAMINED -- 0 files were opened, so --fail-on "
        "has no basis to pass.\n"
    )
    sys.stderr.write(
        f"  target: {target}\n"
        f"  --max-file-size: {args.max_file_size}\n"
        f"  --exclude: {args.exclude or '(none)'}\n"
    )
    sys.stderr.write(
        "  An empty file set is not a clean tree. Widen the filters, or pass "
        "--allow-degraded to gate on findings alone.\n"
    )


def _atomic_write_text(path: str, content: str) -> None:
    """Publish a complete report without exposing a partially-written file."""
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(prefix=".praetor-report-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        for attempt in range(3):
            try:
                os.replace(temp_path, path)
                break
            except PermissionError as exc:
                if attempt == 2:
                    # Never fall back to open(path, "w"): that would reintroduce
                    # torn reports. A blocked atomic publish must fail loudly.
                    raise RuntimeError(
                        f"atomic report publish failed for {path}: destination is in use"
                    ) from exc
                time.sleep(0.01 * (attempt + 1))
    except BaseException:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        raise

VERSION = "1.1.0"
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

#: Engines that find their own files instead of consuming a walk list. They
#: ignore --max-file-size and --exclude, so an empty walk says nothing about
#: whether they measured the target. See the `nothing_examined` comment.
_SELF_DISCOVERING_ENGINES = frozenset({"sast", "sca"})

ALL_ENGINES = ["sast", "secrets", "sca", "aisec", "model"]


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="praetor",
        description="Multi-engine static security analysis (SAST + secrets + SCA + AI-security + serialized-model).",
        # 🔴 argparse abbreviates long options BY DEFAULT, and one of ours disarms
        # the gate. With allow_abbrev left at True, `--allow` is an unambiguous
        # prefix of `--allow-degraded`, so seven characters turned exit 3 into
        # exit 0 on a scan that measured nothing. Measured 2026-08-13:
        #   praetor <clean> --engines sca --fail-on INFO          -> 3
        #   praetor <clean> --engines sca --fail-on INFO --allow  -> 0
        # An exit code is this tool's entire contract with CI, so no prefix of a
        # bypass flag may be spelled by accident. This also freezes the CLI
        # surface: adding any `--allow-*` sibling would silently have made
        # `--allow` ambiguous and started erroring on scripts that relied on it.
        allow_abbrev=False,
    )
    p.add_argument("target", nargs="?", default=".", help="File or directory to scan (default: current dir).")
    p.add_argument("--engines", default="all",
                   help="Comma list of engines to run: sast,secrets,sca,aisec,model (default: all).")
    p.add_argument("--format", choices=["text", "json", "both", "sarif"], default="text",
                   help="Report format (default: text).")
    p.add_argument("--out", default="", help="Directory to write praetor-report.txt / .json.")
    p.add_argument("--min-severity", default="INFO",
                   choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Hide active findings below this severity (default: INFO = show all).")
    p.add_argument("--fail-on", default="",
                   choices=["", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Exit 1 if any active finding is at/above this severity (default: never fail). "
                        "Exit 3 if the scan was not measured: an engine failed, zero files were "
                        "examined, or components disagreed about scope. An engine failure also exits "
                        "3 without --fail-on. See --allow-degraded.")
    p.add_argument("--allow-degraded", action="store_true",
                   help="Do NOT exit 3 for a degraded scan, with or without --fail-on. "
                        "Knowingly accepts an unmeasured blind spot.")
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
    # 🔴 PROVENANCE THE CALLER SUPPLIES OUTRANKS ANYTHING READ FROM THE TARGET.
    # CI already knows which commit it checked out, from its own environment,
    # and that source is trustworthy in a way the scanned tree is not. When
    # neither is given, PRAETOR reads `.git/HEAD` as TEXT -- it never invokes
    # git, because git would evaluate the target's own config. See
    # core.git_provenance.
    p.add_argument("--repo", default=None,
                   help="Repository identity to record in the report (e.g. owner/name). "
                        "Recorded verbatim; PRAETOR never contacts it.")
    p.add_argument("--commit", default=None,
                   help="Commit SHA this scan is of. Overrides anything read from "
                        ".git/HEAD. CI should pass its own checked-out SHA.")
    p.add_argument("--max-file-size", type=int, default=core.DEFAULT_MAX_BYTES,
                   help="Skip files larger than this many bytes (default: 3MB).")
    p.add_argument("--exclude", action="append", default=[],
                   help="Regex of relative paths to exclude (repeatable).")
    p.add_argument("--semgrep-timeout", type=int, default=0,
                   help="Overall seconds allowed for Semgrep (default: 900, or "
                        "PRAETOR_SEMGREP_TIMEOUT). Raise it for a large tree: 900s is "
                        "not enough for several thousand files and the engine then "
                        "reports an error, which exits 3. A timeout can never "
                        "produce a passing scan.")
    p.add_argument("--no-default-skips", action="store_true",
                   help="Do not skip build-output and dependency directories "
                        "(dist, build, out, target, vendor, node_modules, ...). "
                        "Required to scan a DISTRIBUTED artifact such as an "
                        "unpacked npm tarball, where dist/ is the shipped code "
                        "rather than generated output. .git is still skipped.")
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

#: 🔴 The marker must be a WHOLE WORD, inside an actual COMMENT.
#:
#: This was `any(m in low for m in IGNORE_MARKERS)` -- a bare substring test over
#: the entire line, with no word boundary and no comment requirement. Measured:
#:
#:     {"nosec_note": "x", "apiKey": "<a real key>"}   -> EXIT 0, finding suppressed
#:     {"note": "x",       "apiKey": "<a real key>"}   -> EXIT 1
#:
#: JSON has no comment syntax at all, so nothing on that line could possibly be an
#: authored suppression -- and `nosec` is a substring of `nosecret`, `nosecurity`,
#: `nosection`, and of any path or hostname containing it. The scanned tree is
#: attacker-controlled, which made this a suppression primitive rather than a
#: papercut.
_IGNORE_WORD_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(m) for m in IGNORE_MARKERS) + r")(?![A-Za-z0-9_])",
    re.IGNORECASE,
)


def _finding_source_path(target: str, finding_file: str) -> str:
    """Return the source path a suppression pass must reopen.

    The walker reports a finding path relative to the scan target for directory
    scans, but a single-file target is already the source file.  Joining its
    reported path again produces ``file/file`` and makes every suppression pass
    silently inert, so all four passes use this shared resolver.
    """
    if os.path.isfile(target):
        return target
    return os.path.join(target, finding_file.replace("/", os.sep))


#: Engines whose `f.line` is a BYTE OFFSET into a binary stream (currently:
#: `model`, from `pickletools.genops()`'s own `pos`), never a source line.
#:
#: Unlike `_LEXCTX_ENGINES`/`_REACHABILITY_ENGINES`, which are ALLOWLISTS that
#: already exclude `model` by simply never naming it, `_apply_inline_ignores`
#: below has NO allowlist -- it runs for every engine's findings by design (a
#: human's `# nosec` next to a hardcoded secret must be able to suppress it,
#: so `secrets` is deliberately NOT exempted there the way it is from lexctx/
#: reachability). That makes `model` a special case needing its OWN explicit
#: exemption, or `_apply_inline_ignores` would call `read_text()` on a binary
#: pickle/ZIP/HDF5/npy file and:
#:   1. very likely RAISE -- `core.read_text` raises on an invalid UTF-8 start
#:      byte by design (see its own docstring), and a binary model file is
#:      essentially arbitrary bytes, so this is the COMMON case, not an edge
#:      case. The caught exception feeds `unreadable` (the TEXT decode-failure
#:      accumulator secrets/aisec's blind-spot status depends on), so every
#:      scan with a non-COVERAGE model finding would spuriously degrade under
#:      `--fail-on` -- a model finding would make the SCAN LOOK LESS MEASURED,
#:      the opposite of what a real finding should do.
#:   2. even on the rare byte sequence that happened to decode without
#:      raising, resolve a byte OFFSET as if it were a 1-based source LINE
#:      INDEX against `split_lines()` output -- meaningless, and a suppression
#:      mechanism trusting meaningless input is exactly the "fails toward
#:      suppression" shape CLAUDE.md's suppression section warns against.
#: This is the same class of scope decision as `secrets`' own exclusion from
#: lexctx/reachability: the safety is not a property of `_apply_inline_ignores`
#: itself, it is this exclusion made next to it, for a reason specific to what
#: `model` findings' `line` field actually means.
_BINARY_STREAM_ENGINES = ("model",)


def _apply_inline_ignores(findings, target, read_text):
    """
    Mark findings filtered when their flagged source line carries an inline ignore
    marker. This is an explicit, auditable suppression visible in the source --
    the opposite of a scanner silently exempting files from itself.
    """
    cache: dict = {}
    for f in findings:
        if getattr(f, "category", "") == "COVERAGE":
            continue
        if f.engine in _BINARY_STREAM_ENGINES:
            continue
        if not f.file or f.line <= 0:
            continue
        ap = _finding_source_path(target, f.file)
        if ap not in cache:
            txt = read_text(ap)
            # core.split_lines, NEVER str.splitlines: `f.line` is \n-based, and
            # resolving it against a splitlines() list lets a U+2028 in the
            # scanned file shift the index onto an unrelated line. That is a
            # suppression primitive -- see core.split_lines.
            cache[ap] = core.split_lines(txt) if txt else []
        lines = cache[ap]
        if 1 <= f.line <= len(lines):
            # Only the COMMENT part of the line can carry a marker, and only as a
            # whole word. lexctx owns what a comment is -- praetor.py must not
            # grow a second, divergent idea of comment syntax.
            comment = lexctx.comment_text(lines[f.line - 1], f.file)
            if comment and _IGNORE_WORD_RE.search(comment):
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
#
# 🔴 `model` IS ALSO DELIBERATELY ABSENT, for a THIRD, DIFFERENT reason from
# either of the above. `f.line` for a `model` finding is a BYTE OFFSET into a
# binary pickle-opcode stream (`pickletools.genops()`'s own `pos`), not a
# source line -- there is no "comment" or "docstring" for a byte offset to be
# inside, because the file has no source text at all. `lexctx.classify_lines`
# expects `read_text()`-decoded source; feeding it a binary model file's
# (attempted, likely-raising) decode would be meaningless even if it somehow
# succeeded. See `_BINARY_STREAM_ENGINES` below, which is what actually keeps
# `model` findings out of `read_text()` entirely, and `_apply_inline_ignores`'
# own comment for the fuller version of this reasoning.
_LEXCTX_ENGINES = ("aisec",)

#: 🔴 CATEGORIES A COMMENT CANNOT MAKE INERT. THE ENGINE ALLOWLIST WAS NOT A
#: FINE ENOUGH SCOPE, AND AN AUDIT PROVED IT ON THIS TOOL'S OWN RULES.
#:
#: The suppression's stated reason is "which cannot execute", and for a
#: BEHAVIOURAL finding that is exactly right -- a `curl … | sh` written in a
#: comment does not run, which is why this mechanism exists and why CLAUDE.md
#: uses that very line as its teaching example.
#:
#: It is FALSE for an instruction. A prompt injection does not need to execute;
#: it needs to be READ, and an agent reading a `.py` file reads its comments and
#: its docstrings. Measured, byte-identical text:
#:
#:     notes.txt  -- instruction to exfiltrate ~/.aws  -> HIGH, exit 1
#:     notes.py   -- the SAME text in two `#` comments -> filtered, exit 0
#:                   capability profile: carries_agent_instructions = none
#:
#: The sharpest instance was `hidden-instruction-html-comment` -- the rule whose
#: entire subject is an instruction hidden in a comment -- being suppressed on
#: the grounds that it was in a comment.
#:
#: ⇒ This is the identical carve-out CLAUDE.md already documents for `secrets`,
#: one category across. A secret is dangerous because it EXISTS; an instruction
#: is dangerous because it is READ; only a behaviour is dangerous because it
#: RUNS. Lexical context can only ever speak to the third.
#:
#: 🔴 THE FIRST VERSION OF THIS WAS A KEEP LIST, AND ITS COMMENT CLAIMED THAT
#: MADE IT FAIL-SAFE. IT DID THE OPPOSITE. The code read `if category in KEEP:
#: continue`, so a category NOT named fell through to suppression -- a category
#: added tomorrow would default to SUPPRESSIBLE, which is exactly the direction
#: CLAUDE.md forbids ("Unproven ⇒ KEEP"). An auditor read the code against the
#: comment and found they disagreed.
#:
#: ⇒ Inverted. This is now an ALLOWLIST OF WHAT MAY BE SUPPRESSED. Anything not
#: named here -- including a category nobody has invented yet -- is KEPT.
#:
#: These three are behavioural: a shell pipe, an install-time script, an auto-run
#: hook. Each is dangerous because it RUNS, so a comment really does make it
#: inert. `PROMPT_INJECTION`, `SAFETY_BYPASS` and `HIDDEN_CONTENT` are absent
#: because they are dangerous because they are READ.
_LEXCTX_SUPPRESSIBLE_CATEGORIES = frozenset({
    "EXFIL",
    "SUPPLY_CHAIN",
    "DANGEROUS_HOOK",
})

#: 🔴 RULES THAT FIRE ON AN INSTRUCTION DESPITE A BEHAVIOURAL CATEGORY.
#:
#: Category is the right axis and it is not a perfect one. `markdown-image-exfil`
#: is filed under EXFIL, but it detects an agent being TOLD to emit
#: `![x](https://evil.example/?d=…)` -- it fires because content is read, not
#: because code runs. An audit demonstrated the same before/after as the headline
#: case, one rule over: byte-identical payload, HIGH and exit 1 in `notes.txt`,
#: filtered and exit 0 in a `#` comment in `notes.py`.
#:
#: ⚠️ THIS LIST IS COMPLETE FOR THE CURRENT RULE TABLE, and I checked rather than
#: assumed: `engine_aisec` declares seven EXFIL rules, and that module's own
#: comment beside this one says "Every EXFIL rule above this one is shell/network
#: command shaped; none would catch this." The other six are genuinely
#: behavioural. Nothing enforces that a later rule of the read-me-and-act shape
#: gets added to this list -- `references/LIMITS.md` says so too.
#:
#: (That sentence is deliberately worded the long way round. Its natural phrasing
#: names a rule this very engine detects, and the self-scan flagged this comment.)
_LEXCTX_INSTRUCTION_RULES = frozenset({
    "markdown-image-exfil",
})


def _lexctx_may_suppress(finding) -> bool:
    """True only when lexical context can honestly speak to this finding.

    Fails toward KEEP on every unknown: an unlisted category, an instruction
    rule wearing a behavioural category, a missing attribute.
    """
    if getattr(finding, "rule_id", "") in _LEXCTX_INSTRUCTION_RULES:
        return False
    return getattr(finding, "category", "") in _LEXCTX_SUPPRESSIBLE_CATEGORIES

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
#
# 🔴 `model` IS ALSO ABSENT, and for the SAME reason it is absent from
# `_LEXCTX_ENGINES` above: `taint.is_provably_inert()` parses Python SOURCE
# (`ast.parse` on `read_text()`-decoded text) to ask whether a matched string
# reaches a dangerous sink in that file. A pickle-opcode stream is not Python
# source and `f.line` is a byte offset, not a line -- there is no AST to walk
# and no sink-reachability question that means anything here. This is the
# identical class of decision CLAUDE.md's suppression section names: the
# safety is a SCOPE decision made next to the mechanism, not a property the
# mechanism has on its own -- reachability analysis would not "rescue" a
# model finding any more than it rescues a secret, just for a different
# underlying reason (no source to analyze at all, vs. disclosure-not-execution).
_REACHABILITY_ENGINES = ("aisec",)


def _apply_reachability(findings, target, read_text):
    """
    Suppress behavioural findings whose matched string provably never reaches a
    dangerous sink (A1). Fails SAFE: anything unproven is KEPT.
    """
    cache: dict = {}
    for f in findings:
        if getattr(f, "category", "") == "COVERAGE":
            continue
        if getattr(f, "filtered", False) or f.engine not in _REACHABILITY_ENGINES:
            continue
        if not f.file or f.line <= 0 or not f.file.endswith(".py"):
            continue
        ap = _finding_source_path(target, f.file)
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


# --------------------------------------------------------------------------- #
# Prohibition suppression (A3) -- prose that FORBIDS the thing it names
# --------------------------------------------------------------------------- #
#
# 🔴 THE PROBLEM, MEASURED IN A SECOND REPOSITORY. A team documenting these very
# false positives found that WRITING THE REPORT PRODUCED FIVE MORE OF THEM: the
# document quoted the four offending lines so a reader could see them, and the
# next scan went from 5 findings to 10, all five new ones inside the report. They
# rewrote it to DESCRIBE each line instead of reproducing it and it went back to
# 5. Measured, both directions.
#
# Their conclusion is the one worth acting on: **the rules impose a cost on
# documenting their own failures, and the cost lands hardest on whoever is trying
# to fix them.** Every one of their five is a comment that PROHIBITS the thing
# detected -- including one warning that a scanner flags this exact prohibition,
# and one that is a detector's own docstring defining the category it detects.
#
# 🔴 THE OBVIOUS FIX IS A VULNERABILITY, exactly as it was for quoting. "Suppress
# when the line contains a negation" hands an attacker a suppression primitive:
# prefix the payload with "Never" and the scanner goes quiet. The attacker writes
# the whole line.
#
# So BOTH must hold, and neither is sufficient alone:
#   1. the match sits in a COMMENT or DOCSTRING -- prose the file's author wrote,
#      not a string that arrived as data; AND
#   2. a prohibition token IMMEDIATELY GOVERNS the matched span -- within a short
#      window ending where the match begins, not merely somewhere on the line.
#
# (2) is the load-bearing half and adjacency is what makes it so. A line that
# forbids something and then does it -- a line reading "never use <flag>; for
# deploys use <flag>" -- still fires on the SECOND occurrence, because no
# prohibition governs it.
#
# (The flag is written as <flag> rather than spelled out. Spelled out, this
# comment is itself a finding in PRAETOR's own self-scan -- the documentation
# tax this pass exists to reduce, charged to the file that implements it.)
# `test_a_prohibition_does_not_cover_a_later_live_instruction` holds that open.
#
# ⚠️ SCOPED TO SAFETY_BYPASS. Not to PROMPT_INJECTION, which has its own narrower
# guard above, and not to anything behavioural, which lexical context already
# handles. Widening this to another category needs its own argument.
#
# Fails SAFE like every other pass here: anything unproven is KEPT, and what is
# suppressed moves to the filtered bucket with this reason attached.

#: How far back from the match a prohibition may sit and still govern it.
#: Deliberately short. "Never use X" and "do not pass X" fit; a prohibition three
#: clauses earlier in the same sentence does not, because by then the line may
#: have turned into an instruction again.
_PROHIBITION_WINDOW = 40

#: Tokens whose grammatical effect is to FORBID, REFUSE or REPORT the thing that
#: follows them, rather than to ask for it.
#:
#: The last group -- flags/detects/reports/warns -- covers the case a second
#: repository measured directly: a comment saying a scanner FLAGS a phrase is
#: describing the detector, not issuing the instruction. One of their findings
#: was a test comment anticipating this very false positive, flagged by it.
_PROHIBITION_WORDS = (
    r"never|do not|don't|must not|must never|cannot|can't|may not|"
    r"forbidden|prohibited|disallowed|not allowed|refuses?|refused|rejects?|"
    r"rejected|blocks?|blocked|prevents?|prevented|guards? against|"
    r"without|instead of|rather than|no longer|skips? every|"
    r"flags?|flagged|flagging|detects?|detected|reports?|warns? about"
)

_PROHIBITION = re.compile(
    r"(?i)\b(" + _PROHIBITION_WORDS + r")\b[^.\n]{0,%d}$" % _PROHIBITION_WINDOW
)

_PROHIBITION_REASON = (
    "the matched phrase is GOVERNED BY A PROHIBITION in the file's own prose "
    "(a comment or docstring forbidding, or describing a tool that flags, the "
    "thing named) -- documentation of the rule, not an instruction to follow it"
)


def _prohibition_governs(line: str, start: int) -> bool:
    """True when a prohibition token sits immediately before the matched span.

    Adjacency, not mere presence on the line. The window ends exactly where the
    match begins, so a prohibition that has already been discharged earlier in
    the line cannot cover a later live instruction.
    """
    return bool(_PROHIBITION.search(line[:start]))


def _apply_prohibition(findings, target, read_text):
    """Suppress SAFETY_BYPASS matches that the file's own prose forbids.

    Both conditions must hold -- author's prose AND an adjacent prohibition. See
    the comment block above for why either alone is a suppression primitive.
    """
    source_cache: dict = {}
    label_cache: dict = {}
    by_id = {rid: rx for rid, _t, rx, *_rest in engine_aisec.INJECTION}
    for f in findings:
        if getattr(f, "filtered", False) or f.engine not in _LEXCTX_ENGINES:
            continue
        if getattr(f, "category", "") != "SAFETY_BYPASS":
            continue
        if not f.file or f.line <= 0:
            continue
        rx = by_id.get(f.rule_id)
        if rx is None:
            continue
        ap = _finding_source_path(target, f.file)
        if ap not in source_cache:
            source_cache[ap] = read_text(ap) or ""
        text = source_cache[ap]
        lines = core.split_lines(text)
        if f.line > len(lines):
            continue                      # unreadable / shifted -> KEEP
        line = lines[f.line - 1]

        # Condition 1: the file's own prose, not data.
        key = (ap, f.file)
        if key not in label_cache:
            label_cache[key] = lexctx.classify_lines(text, f.file)
        labels = label_cache[key]
        if f.line > len(labels):
            continue
        if labels[f.line - 1] not in (lexctx.COMMENT, lexctx.DOCSTRING):
            continue                      # live code or data -> KEEP

        # Condition 2: a prohibition governs EVERY occurrence on the line.
        #
        # 🔴 `finditer`, NOT `search`, AND THE FIRST VERSION USED `search`. A
        # finding is recorded per LINE, so testing only the first match let a
        # single line carry a governed occurrence and an ungoverned one and be
        # suppressed on the strength of the first:
        #
        #     a comment that forbids <flag> and then, after a semicolon,
        #     tells the reader to use <flag> for deploys
        #
        # That is a suppression primitive the attacker writes, which is the exact
        # shape of the quoting bypass this project already fixed once. If ANY
        # occurrence on the line is ungoverned, the finding is KEPT.
        matches = list(rx.finditer(line))
        if not matches:
            continue
        if not all(_prohibition_governs(line, m.start()) for m in matches):
            continue                      # any ungoverned occurrence -> KEEP

        f.filtered = True
        f.filter_reason = _PROHIBITION_REASON


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
        ap = _finding_source_path(target, f.file)
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
    source_cache: dict = {}
    # Bound to this suppression pass, so a whole-tree scan cannot retain labels
    # after its findings have been processed.  File identity is part of the key:
    # identical text may be Markdown in one file and Python in another.
    label_cache: dict = {}
    for f in findings:
        if getattr(f, "category", "") == "COVERAGE":
            continue
        if getattr(f, "filtered", False) or f.engine not in _LEXCTX_ENGINES:
            continue
        # See _lexctx_may_suppress. An instruction is dangerous because it is
        # READ, and an agent reads comments; only a behaviour is made inert by
        # sitting in one. Anything unlisted is KEPT.
        if not _lexctx_may_suppress(f):
            continue
        if not f.file or f.line <= 0:
            continue
        ap = _finding_source_path(target, f.file)
        if ap not in source_cache:
            source_cache[ap] = read_text(ap) or ""
        cache_key = (ap, f.file)
        if cache_key not in label_cache:
            label_cache[cache_key] = lexctx.classify_lines(source_cache[ap], f.file)
        ctx = lexctx.context_from_labels(label_cache[cache_key], f.line)
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
    # An empty selection is not a scan. `--engines ""` used to parse to [], leave
    # every engine `disabled` -- a gate-TRUSTED status -- and exit 0 on a tree
    # containing a live credential. A typo was rejected here; the empty string
    # sailed through, so `--engines "$ENGINES"` with the variable unset was a
    # silent false clean. This is the diagnostic; the guarantee is the
    # measured-engine floor in the exit-code block below.
    if not engines:
        sys.stderr.write(
            f"praetor: --engines selected nothing (valid: {', '.join(ALL_ENGINES)}, or 'all').\n"
            "  An empty selection scans nothing and is never a clean result. If a CI "
            "variable expanded to empty here, that is the bug.\n"
        )
        return 2

    # The SAME shape as `--engines ""`, one flag over, and it survived the fix
    # that was written to close the class. `--exclude ""` compiles to
    # `re.compile("")`, which matches every path, so the walker returns zero
    # files, every engine is handed an empty list, every engine returns without
    # raising, and every engine reports `ok` -- a MEASURED status. Measured
    # 2026-08-13 on a tree holding a live-shaped key: control `Files (text): 1`
    # / exit 1; with `--exclude ""` `Files (text): 0` / exit 0.
    # ⇒ Found by an independent reader AFTER this file's author had written a
    # comment claiming the class was closed. See the file-count floor below,
    # which is the guarantee; this is only the diagnostic.
    if any(pattern == "" for pattern in (args.exclude or [])):
        sys.stderr.write(
            "praetor: --exclude was given an empty pattern, which matches every path.\n"
            "  That excludes the entire tree and scans nothing, which is never a clean "
            "result. If a CI variable expanded to empty here, that is the bug.\n"
        )
        return 2
    _scan_started = time.monotonic()
    _log(args.quiet, f"praetor {VERSION}: scanning {target}")

    # Enumerate scannable text files exactly once (shared by secrets + aisec).
    # `scope_stats` records what the walker REFUSED, so a scan that read almost
    # nothing cannot report itself as clean in silence. See the scope floor below
    # and core.walk_files' docstring for the measurement that produced it.
    scope_stats = {}
    scan_skip_dirs = set() if args.no_default_skips else None
    scan_files = core.walk_files(target, skip_dirs=scan_skip_dirs,
                                 max_bytes=args.max_file_size,
                                 extra_excludes=args.exclude, stats=scope_stats)
    # 🔴 A SECOND, WIDER WALK FOR SECRETS ONLY -- see core.SECRETS_SKIP_DIRS.
    # `core.DEFAULT_SKIP_DIRS` is 36 directory names, and the SCANNED TREE CHOOSES
    # ITS OWN DIRECTORY NAMES, so it is an attacker-controlled scope boundary.
    # Skipping `vendor/` for SAST is right (its findings are third-party noise and
    # scanning it explodes semgrep's target count). Skipping it for SECRETS is
    # not: a credential committed there is disclosed exactly as much as one at the
    # root. Same target, same excludes, same size cap -- only the skip list differs.
    # ⚠️ ONLY WHEN THE ENGINE THAT USES IT IS SELECTED. This walk opens every
    # vendored and build file in the tree; doing it for `--engines sast` was pure
    # waste, and it also made the report claim `secret_file_count` for an engine
    # that never ran. Measured on a real repo: 111,605 files / 1,739 MB walked to
    # produce a number nothing consumed.
    #
    # Git status is deliberately NOT a secrets scope boundary. An ignored file is
    # a common place for a live credential, and `.gitignore` is target-controlled;
    # narrowing this walk to Git's tracked/unignored list turned a detectable
    # ignored config file into a successful clean result. The cost is real, but
    # recall is not an implicit speed trade an operator has authorized.
    #
    # 🔴 AISEC NEEDS THIS SAME WIDE WALK, FOR AGENT-CONFIG FILES ONLY. A breaker
    # audit put a `.cursor/hooks.json` that pipes a downloaded script into a
    # shell at `vendor/evil-pkg/`. PRAETOR reported zero findings,
    # `executes_on_load: no`, exit 0. The identical file at the repository root
    # was correctly reported HIGH. The only difference was a directory name the
    # SCANNED TREE chose.
    #
    # That is aisec's own threat model -- a malicious dependency planting hostile
    # agent instructions -- landing in exactly the blind spot this comment block
    # already described for secrets. The reasoning was written down and then not
    # carried to the second engine that needed it.
    #
    # ⚠️ ONLY the agent-config files, not the whole vendored tree. aisec's prose
    # rules over every vendored README would be cost and noise; its CONFIG rules
    # are keyed on specific basenames and directories, so the widening is cheap
    # and targeted. Vendored prose remains out of scope, stated rather than
    # implied.
    # ⚠️ TWO SEPARATE WIDE WALKS, NOT ONE SHARED ONE, and the difference is
    # cost. The secrets walk admits every text file and opens each to sniff for
    # binary content; doing that unconditionally was a measured mistake --
    # 111,605 files / 1,739 MB on a real repository, for an engine that never
    # ran. The aisec walk passes `admit=`, which `core._consider_file` applies
    # BEFORE getsize() and before the sniff, so it traverses the same
    # directories and opens almost nothing.
    # 🔴 EVERY WALK PASSES `stats`, AND THE FIRST REPAIR OF THIS DID NOT.
    # The oversize/binary bookkeeping in core._consider_file is guarded by
    # `if stats is not None`, and only THIS first walk was instrumented. The
    # wide secrets walk below is the only one that enters `vendor/`,
    # `node_modules/` and `dist/` -- so an oversized credential there dropped
    # exactly as silently as before, and `meta.scope.oversize_files` reported 0
    # while asserting the cap discloses itself. Two independent audits found it
    # the same day the disclosure shipped.
    #
    # ⇒ `scope_stats` is now shared by all four walks. The counters are additive
    # and the walks overlap, so a file inside `vendor/` that is refused by both
    # the text walk and the secrets walk is counted twice. That is stated in the
    # report rather than deduplicated: an over-count of "what I did not read"
    # errs toward disclosure, and dropping it to look tidy is how the first
    # version came to report zero.
    secrets_walk_stats: dict = {}
    secret_files = (
        core.walk_files(target, skip_dirs=core.SECRETS_SKIP_DIRS,
                        max_bytes=args.max_file_size, extra_excludes=args.exclude,
                        stats=secrets_walk_stats)
        if "secrets" in engines else []
    )
    _merge_drop_counters(scope_stats, secrets_walk_stats)
    aisec_walk_stats: dict = {}
    if "aisec" in engines:
        already = {sf.abspath for sf in scan_files}
        aisec_files = scan_files + [
            sf for sf in core.walk_files(
                target, skip_dirs=core.SECRETS_SKIP_DIRS,
                max_bytes=args.max_file_size, extra_excludes=args.exclude,
                admit=engine_aisec.is_agent_config_path, stats=aisec_walk_stats)
            if sf.abspath not in already
        ]
    else:
        aisec_files = scan_files
    _merge_drop_counters(scope_stats, aisec_walk_stats)
    # 🔴 A THIRD, DIFFERENTLY-SHAPED WALK FOR MODEL FILES ONLY -- mode="model"
    # on the SAME `core.walk_files`/`_consider_file` used above, not a second
    # implementation (see references/DESIGN-model-scanning.md §1.2). Gated
    # behind engine selection for the identical reason `secret_files` is: an
    # unconsumed enumeration is wasted cost (measured precedent: 111,605 files
    # walked to produce a number nothing consumed, above).
    #
    # `max_bytes` here is DELIBERATELY `core.DEFAULT_MODEL_MAX_ADMIT_BYTES`
    # (50 GB), NOT `args.max_file_size` (default 3 MB): a real checkpoint's
    # pickled object graph is KB-scale but the file on disk routinely runs
    # into the gigabytes (raw tensor storage this engine never opens), so the
    # operator's TEXT byte cap would reject essentially every real model file
    # from candidacy -- see design §1.2. The engine's OWN internal per-format
    # bounds (engine_model.py's MAX_RAW_PICKLE_BYTES_SCANNED etc.) are the
    # real scanning-cost controls, not this admission ceiling.
    model_walk_stats: dict = {}
    model_files = (
        core.walk_files(target, skip_dirs=scan_skip_dirs,
                        max_bytes=core.DEFAULT_MODEL_MAX_ADMIT_BYTES,
                        extra_excludes=args.exclude, mode="model", stats=model_walk_stats)
        if "model" in engines else []
    )
    _merge_drop_counters(scope_stats, model_walk_stats)

    # 🔴 THE WHOLE-SCAN MEASUREMENT, COMPUTED ONCE AND RECORDED.
    # `core.engines_that_measured`'s docstring states in capitals that a
    # per-engine trust check answers only half the question. SARIF's first
    # version re-derived the per-engine half in its own file and never asked the
    # other, so it reported `executionSuccessful: true` for a scan where
    # PRAETOR's own gate said "NOTHING WAS EXAMINED" and returned 3.
    #
    # One computation, read by everyone. A second consumer re-deriving a safety
    # question is how the two came to disagree.
    _walked_nothing = not (scan_files or secret_files or aisec_files or model_files)

    nul_text_files = {
        sf.abspath for sf in (scan_files + secret_files + aisec_files) if sf.contains_nul
    }
    _log(args.quiet, f"  enumerated {len(scan_files)} text file(s)"
                     f" ({len(secret_files)} for secrets, {len(aisec_files)} for aisec,"
                     f" {len(model_files)} for model)")

    # 🔴 --exclude MATCHING NOTHING IS INDISTINGUISHABLE FROM HAVING NOTHING TO
    # EXCLUDE, AND THE ONLY VISIBLE SYMPTOM WAS A TIMEOUT UNDER THE WRONG NAME.
    #
    # Measured 2026-08-24: a pattern that never fires (a shell mangled it, a typo,
    # a path-separator mismatch) produces the same silence as a pattern that
    # correctly matched zero files because there was nothing to remove. One is
    # ordinary; the other means every file the pattern was meant to skip got
    # scanned anyway, on a tree that can be tens of thousands of files larger
    # than the operator believes. This is that scope's mirror of the zero-files-
    # read floor below: an --exclude that did nothing is a blind spot, not a
    # clean result, and it stays silent otherwise.
    if args.exclude and scope_stats.get("excluded_by_pattern", 0) == 0 and (
            scope_stats.get("kept_code_files", 0) or scope_stats.get("skipped_code_files", 0)):
        sys.stderr.write(
            "praetor: WARNING -- --exclude was given %d pattern(s) but excluded 0 files.\n"
            "  Either there was genuinely nothing to exclude, or the pattern never matched --\n"
            "  a shell (Git Bash/MSYS path conversion is a known cause on Windows), a typo, or\n"
            "  a path-separator mismatch can all silently turn --exclude into a no-op. Verify\n"
            "  with the pattern against a real path before trusting the scan's scope.\n"
            % len(args.exclude))

    # 🔴 ONE UNDECODABLE FILE USED TO BLIND AN ENTIRE ENGINE.
    #
    # `core.read_text` raises on an invalid start byte, and that is the correct
    # design -- a `surrogateescape` fallback was added 2026-08-13 and REVERTED the
    # same day because it turned a LOUD failure into a SILENT MISS. That decision
    # stands and this does not touch it.
    #
    # What was wrong is the BLAST RADIUS. The engines read in a bare loop, so the
    # first unreadable file aborted the whole scan and the engine reported
    # `error` having examined nothing. Measured 2026-08-22 on a real container
    # image filesystem, 30,790 files:
    #     secrets -> error  "'utf-8' codec can't decode byte 0xb1 in position 81"
    #     aisec   -> error  "'utf-8' codec can't decode byte 0xff in position 163"
    # Two bytes, in two files, and nothing else in that tree was ever looked at.
    #
    # ⚠️ THE SILENCE IS THE DANGER, NOT THE SKIP. Recording the file and moving on
    # is only safe because `unreadable` is REPORTED and, below, DEGRADES the scan.
    # Returning "" without that record would be precisely the reverted fallback
    # wearing a different hat: engines reporting `ok` over files they never read.
    unreadable: list = []

    def read_text(path):
        try:
            return core.read_text(path, args.max_file_size)
        except Exception as exc:  # noqa -- the reason is recorded, not swallowed
            unreadable.append((path, f"{type(exc).__name__}: {exc}"[:160]))
            return ""

    # A SECOND, BINARY-FLAVORED accumulator for the model engine -- see
    # references/DESIGN-model-scanning.md §5.1. `core.read_bytes` already
    # catches `OSError` internally and returns `b""` (mirroring
    # `core.read_text`'s own OSError branch), so this wrapper's `except` is a
    # forward-compatible net for whatever `core.read_bytes` might someday need
    # to raise rather than swallow -- kept separate from `unreadable` (not
    # merged into it) so a model-engine read failure is never confused with a
    # text-decode failure in either the report or the degraded-scan gate.
    unreadable_binary: list = []

    def read_bytes(path, max_bytes):
        try:
            return core.read_bytes(path, max_bytes)
        except Exception as exc:  # noqa -- the reason is recorded, not swallowed
            unreadable_binary.append((path, f"{type(exc).__name__}: {exc}"[:160]))
            return b""

    def _status_after_reading(name, before, ok_detail, unreadable_list=None, verb="decoded"):
        """Record `name`'s status, refusing to say `ok` about a file it could not read.

        🔴 THE EXIT CODE IS THE GATE; THE STATUS IS WHAT A HUMAN READS. Isolating
        the decode failure per file is only half the job -- an engine that then
        reports `ok` is claiming work it did not do, which is the same lie one
        layer up and survives any exit-code-only assertion.
        `tests/test_suppression_is_not_attacker_controlled.py` pins this, and it
        caught exactly this regression in the first version of the isolation.

        `unreadable_list` defaults to the TEXT accumulator (`unreadable`) so
        every existing call site is unchanged; the model engine passes
        `unreadable_binary` and `verb="opened"` instead -- a model file that
        could not be read failed to OPEN, not to decode (there is no decode
        step for raw bytes).
        """
        src = unreadable if unreadable_list is None else unreadable_list
        missed = src[before:]
        if not missed:
            return {"status": "ok", "detail": ok_detail}
        first = os.path.relpath(missed[0][0], target)
        return {"status": "error",
                "detail": (f"{len(missed)} file(s) could not be {verb} and were NOT "
                           f"scanned (first: {first}: {missed[0][1]}); "
                           f"the rest of the tree was scanned -- {ok_detail}")}

    all_findings = []
    engine_meta = {}

    # -- secrets --------------------------------------------------------------
    if "secrets" in engines:
        _log(args.quiet, "  [secrets] scanning...")
        try:
            _unread_before = len(unreadable)
            fs = engine_secrets.scan(secret_files, read_text)
            all_findings.extend(fs)
            engine_meta["secrets"] = _status_after_reading(
                "secrets", _unread_before,
                f"{len(fs)} raw finding(s); provider patterns + entropy + base64-unwrap")
        except Exception as e:  # noqa
            engine_meta["secrets"] = {"status": "error", "detail": f"{e}"}
    else:
        engine_meta["secrets"] = {"status": "disabled", "detail": "not selected"}

    # -- aisec ----------------------------------------------------------------
    if "aisec" in engines:
        _log(args.quiet, "  [aisec] scanning...")
        try:
            _unread_before = len(unreadable)
            fs = engine_aisec.scan(aisec_files, read_text)
            all_findings.extend(fs)
            engine_meta["aisec"] = _status_after_reading(
                "aisec", _unread_before,
                f"{len(fs)} raw finding(s); injection/unicode/exfil/hooks/bypass")
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
                # PRAETOR's own count of code here, so the engine can compare it
                # against what semgrep says it opened. Two independent counts
                # disagreeing is the only signal that survives semgrep changing
                # how it decides scope -- see the scope guard in engine_sast.
                enumerated_code_files=engine_sast.count_code_files(scan_files),
                # The SAME skip set the walker used. Passing it rather than
                # letting the engine re-read the constant is what keeps the two
                # components agreeing about scope under --no-default-skips.
                skip_dirs=scan_skip_dirs,
                # 0 means "not given"; the engine's own default (or the env var)
                # then applies. Passing it explicitly would freeze the default at
                # import time and defeat PRAETOR_SEMGREP_TIMEOUT.
                **({"timeout": args.semgrep_timeout} if args.semgrep_timeout > 0 else {}),
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

    # -- model ------------------------------------------------------------------
    # Pickle-opcode disassembly (pickletools.genops() only -- see engine_model.py's
    # own header for the never-execute argument). `not-applicable` mirrors how
    # `sca` reports "no dependency manifests": no model-shaped files existing in
    # the TARGET is a property of what was scanned, not something unmeasured --
    # see references/DESIGN-model-scanning.md §5.2, confirmed against
    # report.py's _STATUS_MARKS (ENGINE_NOT_APPLICABLE renders "[n/a]" and sits in
    # both GATE_TRUSTED_STATUSES and NON_MALFUNCTION_STATUSES).
    if "model" in engines:
        if not model_files:
            engine_meta["model"] = {"status": "not-applicable",
                                    "detail": "no model-shaped file (.pt/.pth/.ckpt/.pkl/.npy/"
                                              ".npz/.h5/.hdf5/.keras/.bin/.joblib/.dill/"
                                              ".safetensors) found in target"}
        else:
            _log(args.quiet, "  [model] scanning serialized-model files...")
            try:
                _unread_before = len(unreadable_binary)
                fs = engine_model.scan(model_files, read_bytes)
                all_findings.extend(fs)
                engine_meta["model"] = _status_after_reading(
                    "model", _unread_before,
                    f"{len(fs)} raw finding(s); pickle-opcode disassembly via pickletools.genops "
                    "(never pickle.load)",
                    unreadable_list=unreadable_binary, verb="opened")
            except Exception as e:  # noqa
                engine_meta["model"] = {"status": "error", "detail": f"{e}"}
    else:
        engine_meta["model"] = {"status": "disabled", "detail": "not selected"}

    # -- inline suppression ---------------------------------------------------
    # Honor auditable, in-source ignore markers on the flagged line
    # (# nosec / # nosemgrep / # praetor:ignore, and // variants). Suppressed
    # findings are marked filtered WITH a reason -- never silently dropped.
    # 🔴 DISCLOSE EVERY FILE THE WALKER REFUSED FOR SIZE. A breaker audit padded
    # a source file past --max-file-size and PRAETOR reported a complete, clean
    # scan over a live-shaped credential: the drop left no trace in the text
    # report, the JSON, or any stat, and one remaining small file kept the
    # whole-tree floor quiet. The cap stays; the silence does not.
    #
    # ⚠️ Reported at INFO, in the COVERAGE category, exactly like the other
    # coverage notes -- NOT raised to a gating severity. A repository with a
    # large asset has not done anything wrong, and a cap that failed builds
    # would be turned off, which is worse than one that reports. Gating on
    # reduced coverage is the operator's decision, and `--allow-degraded`
    # already exists for it.
    # 🔴 THERE ARE THREE WAYS THE WALKER DISCARDS A WHOLE FILE, and the first
    # version of this block disclosed one of them, on one of four walks. Two
    # independent audits demonstrated the same clean-looking scan over a
    # live-shaped credential through the two it missed.
    #
    # ⚠️ Reported at INFO in the COVERAGE category, exactly like the other
    # coverage notes -- NOT raised to a gating severity. A repository with a
    # large asset or a real binary has done nothing wrong, and a cap that failed
    # builds would be switched off, which is worse than one that reports.
    # Gating on reduced coverage is the operator's decision; --allow-degraded
    # and --fail-on INFO already exist for it.
    for key, rule_id, title, cap_text, remedy in (
        ("oversize", "file-too-large-skipped",
         "File(s) skipped: larger than the size cap",
         f"exceeded --max-file-size ({args.max_file_size} bytes)",
         "Raise --max-file-size, or scan the oversized files separately, if their content matters."),
        ("binary", "binary-file-skipped",
         "File(s) skipped: judged binary by the content sniff",
         "were judged binary (more than 30% control characters in the first 4 KB)",
         "If one of these is really text, re-encode it; the ratio that classified it is chosen by the scanned tree."),
        ("unstattable", "unstattable-file-skipped",
         "File(s) skipped: could not be measured",
         "could not be stat()ed",
         "Check permissions and path length, then re-run."),
    ):
        count = scope_stats.get(f"{key}_files", 0)
        if not count:
            continue
        examples = scope_stats.get(f"{key}_examples", [])
        shown = ", ".join(f"{rel} ({detail})" for rel, detail in examples[:5])
        more = f" (+{count - len(examples)} more not listed)" if count > len(examples) else ""
        all_findings.append(core.Finding(
            engine="praetor", rule_id=rule_id, title=title,
            severity=core.Severity.INFO, confidence=core.Confidence.HIGH,
            file=".", line=1, category="COVERAGE",
            description=(
                f"{count} file record(s) {cap_text} and were NOT scanned by any engine. "
                "Nothing was examined in them, so no finding from them can appear "
                "above -- and their absence is not evidence they are clean. "
                "⚠️ The walks overlap, so one file refused by two of them is counted "
                "twice; this is a count of REFUSALS, not of distinct files."
            ),
            snippet=f"{key}_refusals={count}; examples: {shown}{more}",
            fix=remedy,
        ))

    # 🔴 CROSS-FILE ANALYSIS, AND IT RUNS BEFORE THE SUPPRESSION PASSES ON
    # PURPOSE. Its findings are subject to the same filters as any other, and it
    # must not be able to smuggle a finding past them.
    #
    # ADD-ONLY: it constructs findings and touches nothing existing. A cross-file
    # pass that could suppress would have a whole-repository blast radius.
    if "aisec" in engines:
        def _payload_reason(value):
            """Reuse `aisec`'s OWN exfil table rather than a second rule list.

            Two tables describing "dangerous string" would drift, and the one in
            this file would be the one nobody remembered to update."""
            for rule_id, title, rx, *_rest in engine_aisec.EXFIL:
                if rx.search(value):
                    return f"matches `{rule_id}` ({title.lower()})"
            return None

        _cf_findings, _cf_note = crossfile.analyse(
            aisec_files, read_text, _payload_reason)
        all_findings.extend(_cf_findings)
        if _cf_note:
            all_findings.append(core.Finding(
                engine="aisec", rule_id="crossfile-cap-reached",
                title="Cross-file analysis did not cover every file",
                severity=core.Severity.INFO, confidence=core.Confidence.HIGH,
                file=".", line=1, category="COVERAGE",
                description=_cf_note + ". A payload split into a file beyond the "
                            "cap would not be joined to its use.",
                snippet=_cf_note,
                fix="Scan a narrower subtree, or raise crossfile.MAX_FILES.",
            ))

    _apply_inline_ignores(all_findings, target, read_text)
    _apply_lexical_context(all_findings, target, read_text)
    _apply_injection_exemplar(all_findings, target, read_text)
    _apply_prohibition(all_findings, target, read_text)
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

    # Provenance: the caller's word first, then the target's own files, then
    # nothing. Absent keys mean "not known", never "not applicable".
    _prov = dict(core.git_provenance(target))
    if args.commit:
        _prov["commit"] = args.commit
    if args.repo:
        _prov["repo"] = args.repo
    _prov["provenance_source"] = (
        "caller" if (args.commit or args.repo)
        else ("target-git-files" if _prov else "none")
    )

    meta = {
        "target": target,
        "timestamp": report.now_iso(),
        "version": VERSION,
        # For a dashboard plotting findings against commits rather than against
        # wall-clock. `provenance_source` says WHERE this came from, because a
        # value read from the scanned tree is target-controlled and a value from
        # CI is not -- a consumer that treats them alike has lost that
        # distinction silently.
        "provenance": _prov,
        "duration_seconds": round(time.monotonic() - _scan_started, 3),
        "file_count": len(scan_files),
        # 🔴 WHAT THE WALKER REFUSED, reported rather than dropped. A reviewer can
        # now see "2 files read, 78 code files skipped in dist/" instead of a bare
        # zero-findings result that looks identical to a real clean scan.
        "scope": {
            "skipped_dirs": dict(sorted(scope_stats.get("skipped_dirs", {}).items())),
            "skipped_code_files": scope_stats.get("skipped_code_files", 0),
            "kept_code_files": scope_stats.get("kept_code_files", 0),
            # A file over --max-file-size used to leave no record at all, which
            # let padding a source file past the cap hide it from a scan that
            # then reported itself complete. The count is exact; the examples
            # are a bounded sample -- see core._consider_file.
            "oversize_files": scope_stats.get("oversize_files", 0),
            "oversize_examples": [
                {"file": rel, "bytes": size}
                for rel, size in scope_stats.get("oversize_examples", [])
            ],
            # The other two whole-file drop paths, reported for the same reason.
            # Counts are REFUSALS across four overlapping walks, not distinct
            # files -- an over-count errs toward disclosure.
            "binary_files": scope_stats.get("binary_files", 0),
            "binary_examples": [
                {"file": rel, "bytes": size}
                for rel, size in scope_stats.get("binary_examples", [])
            ],
            "unstattable_files": scope_stats.get("unstattable_files", 0),
            "unstattable_examples": [
                {"file": rel, "error": why}
                for rel, why in scope_stats.get("unstattable_examples", [])
            ],
            "max_file_size": args.max_file_size,
            # Read by the SARIF emitter so it cannot disagree with the gate.
            "walked_nothing": _walked_nothing,
            "default_skips_disabled": bool(args.no_default_skips),
            # Files an engine asked for and could not decode. Reported so the
            # skip is never silent; see the unreadable floor below.
            "unreadable_files": len(unreadable),
            "unreadable_sample": [
                {"file": os.path.relpath(p, target).replace("\\", "/"), "error": why}
                for p, why in unreadable[:5]
            ],
            # Same discipline, BINARY-flavored: model files the engine could not
            # open at all (permissions, a race with the walker). Kept as its own
            # field rather than merged into `unreadable_files` -- see
            # `unreadable_binary`'s own definition above for why the two
            # accumulators must never be confused with each other.
            "unreadable_binary_files": len(unreadable_binary),
        },
        # None, not 0, when secrets did not run: "the engine read nothing" and
        # "the engine was not asked" are different facts, and reporting 0 for the
        # second is the same one-word-two-facts defect as `unavailable` was.
        "secret_file_count": (len(secret_files) if "secrets" in engines else None),
        "model_file_count": (len(model_files) if "model" in engines else None),
        "nul_text_file_count": len(nul_text_files),
        "engines": engine_meta,
        "min_severity": args.min_severity,
    }

    # -- output ---------------------------------------------------------------
    text = report.render_text(result, meta)
    js = report.render_json(result, meta)
    # `meta` is what render_json embeds; SARIF needs the same facts plus the
    # schema version, so it is read back out of the rendered document rather
    # than rebuilt -- two constructions of the same thing drift.
    sarif_doc = sarif.render_sarif(result, dict(meta, schema_version=report.SCHEMA_VERSION))

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        # Concurrent scans sharing one --out use last-writer-wins semantics;
        # each artifact is nevertheless published atomically, so readers see
        # only a complete prior or complete new report, never a torn write.
        _atomic_write_text(os.path.join(args.out, "praetor-report.txt"), text)
        _atomic_write_text(os.path.join(args.out, "praetor-report.json"), js)
        _atomic_write_text(os.path.join(args.out, "praetor-report.sarif"), sarif_doc)
        _log(args.quiet, f"  reports written to {args.out}")

    if args.format in ("text", "both"):
        print(text)
    if args.format in ("json", "both"):
        print(js)
    if args.format == "sarif":
        print(sarif_doc)

    # -- exit code ------------------------------------------------------------
    # 🔴 "NOTHING WAS EXAMINED" MUST MEAN NOTHING, NOT NO TEXT FILE. This
    # condition was `not scan_files`, the TEXT walk alone. That was survivable
    # only because the floor sat after the findings check and a model-only scan
    # never reached it; moving the floor above `has_findings` exposed the
    # narrowness immediately, as two model-engine tests going red.
    #
    # A target holding one `.pkl` and no text file has been measured -- by the
    # model engine, over its own walk. Reporting "0 files were opened" there
    # would be false, and it would fail a legitimate scan. Every list an engine
    # actually reads is counted here, so adding a sixth engine with its own walk
    # means adding it to this line, and nothing else enforces that.
    # 🔴 "NOTHING WAS EXAMINED" MUST MEAN NOTHING, AND TWO ENGINES DO NOT USE
    # THESE LISTS AT ALL. `sast` is handed the target DIRECTORY and semgrep does
    # its own discovery; `sca` reads manifests it finds itself. Neither honours
    # --max-file-size or --exclude.
    #
    # An audit measured the consequence of leaving them out: a target with a
    # real `shell=True` and an `eval()` in it, scanned with `--engines sast
    # --fail-on LOW --max-file-size 1`, returned exit 1 before this block moved
    # and exit 3 after -- while the report above printed the same two real
    # findings, and stderr said "0 files were opened, so --fail-on has no basis
    # to pass." Both codes are non-zero so no gate was disarmed, but 1 means
    # "act on this finding" and 3 means "the environment was broken", and the
    # scan had measured the tree perfectly well.
    #
    # ⚠️ SAFE BECAUSE A SELF-DISCOVERING ENGINE THAT COULD NOT RUN IS CAUGHT
    # ELSEWHERE. An unavailable semgrep is a blind spot and `blind` returns 3 on
    # its own; this term only says that a walk finding no files is not evidence
    # about a scan those walks never fed.
    walked_nothing = _walked_nothing
    # 🔴 A FINDING, NOT A MEMBERSHIP TEST. The first version of this line read
    # `not (_SELF_DISCOVERING_ENGINES & set(engines))`, and `ALL_ENGINES` contains
    # both of them -- so the intersection was non-empty in EVERY DEFAULT SCAN and
    # `nothing_examined` was constant False. The floor, both `return 3` sites and
    # the diagnostic were unreachable by default. An audit measured it: a single
    # file holding a live-shaped AWS secret key, scanned with `--max-file-size 1
    # --fail-on HIGH`, went from exit 3 with "NOTHING WAS EXAMINED" to exit 0 with
    # no output at all.
    #
    # It failed for the exact reason `core.engines_that_measured` warns about in
    # its own docstring: an engine's PRESENCE, like its `ok` status, is a trust
    # token and not a measurement. `sca` reporting `not-applicable` disarmed the
    # floor while examining nothing.
    #
    # ⇒ A finding FROM one of those engines is evidence they examined something.
    # It cannot be satisfied by a silence, which is the property the floor needs.
    #
    # ⚠️ ERRS TOWARD 3, deliberately. An engine that examined the tree and found
    # nothing is indistinguishable here from one that examined nothing -- so a
    # scan whose walks opened ZERO files still reports "did not complete safely
    # enough to pass", which is true of the text engines regardless.
    self_discovered = any(
        getattr(f, "engine", "") in _SELF_DISCOVERING_ENGINES for f in gate_findings
    )
    nothing_examined = walked_nothing and not self_discovered

    # 🔴 The gate reads engine STATUS, not just findings. An engine that errored
    # or was unavailable produced zero findings for a reason that has nothing to
    # do with the target being clean -- and before 2026-08-12 this block consulted
    # result["active"] alone, so a scan whose SAST engine died returned exit 0,
    # byte-identical to a fully-measured clean run. The information already
    # existed in engine_meta and reached the report; it never reached the
    # decision. Found by an independent reader of this file, not by its author.
    if args.fail_on:
        threshold = core.Severity.parse(args.fail_on)
        has_findings = any(f.severity >= threshold for f in gate_findings)
        # F40: blind-spot detection used to run only AFTER the findings check
        # returned, so a real finding sitting next to a blind engine printed
        # exit 1 with no stderr trace that anything else was also unmeasured --
        # even though meta.engines in the JSON report carried the truth the
        # whole time. Computed and printed here, BEFORE either return, so the
        # diagnostic always appears when something is blind. The exit code is
        # unchanged either way: 1 still outranks 3 (test_real_findings_outrank_
        # degradation asserts this is deliberate), this only fixes what a human
        # reading stderr can see.
        blind = core.engine_blind_spots(engine_meta)
        if blind and not args.allow_degraded:
            sys.stderr.write(
                "praetor: SCAN DEGRADED -- --fail-on cannot pass a scan that was not "
                "fully measured.\n"
            )
            for name, status, detail in blind:
                sys.stderr.write(f"  [{status}] {name}: {detail}\n")
            if has_findings:
                sys.stderr.write(
                    "  A real finding was also reported above -- that verdict stands "
                    "(exit 1), but other engines were blind and may be hiding more.\n"
                )
            else:
                sys.stderr.write(
                    "  A zero from an engine that did not run is not a clean result. "
                    "Re-run once the engine is available, or pass --allow-degraded to "
                    "gate on findings alone.\n"
                )
        # 🔴 THE ZERO-FILES FLOOR OUTRANKS `has_findings`, and ONLY it does.
        # "1 outranks 3" is the documented rule everywhere else in this block,
        # because a real finding is the more actionable signal. That reasoning
        # needs a real finding, and when the walker opened ZERO files no finding
        # can be about the target's content -- only about the coverage failure
        # itself.
        #
        # It became reachable when the oversized-file disclosure was added: a
        # byte cap below every file now emits a COVERAGE note, `--fail-on INFO`
        # saw a finding, and exit 3 ("nothing was examined") silently became
        # exit 1 ("a finding exists"). Both are non-zero, so no gate was
        # disarmed -- but 3 names the cause and 1 hides it behind a note about
        # the cause. The more specific diagnosis wins.
        if nothing_examined and not args.allow_degraded:
            _emit_nothing_examined(target, args)
            return 3
        if has_findings:
            return 1
        if blind and not args.allow_degraded:
            return 3
        # 🔴 THE ONLY TERM IN THIS BLOCK THAT IS A MEASUREMENT RATHER THAN A
        # STATUS WORD. An engine handed an empty file list returns without
        # raising and reports `ok` -- so "an engine measured" was itself just
        # another trust token, and `--exclude ""` walked straight through the
        # floor written one commit earlier to close exactly this class:
        #   control                 -> Files (text): 1, exit 1 (live key found)
        #   --exclude ""            -> Files (text): 0, exit 0
        #   --max-file-size 1       -> Files (text): 0, exit 0
        # `len(scan_files)` cannot be satisfied by a silence, so it catches the
        # routes that empty the tree ENTIRELY -- an empty exclude regex, a byte
        # cap below every file, an empty directory.
        #
        # 🔴 IT CATCHES EXACTLY-ZERO AND NOTHING ELSE, AND ONE FILE DEFEATS IT.
        # An earlier version of this comment claimed it covered "every route that
        # empties the tree ... including routes nobody has thought of yet." That
        # was false when written -- the third false safety claim in this area, all
        # by the author of the fix. Measured on unmutated HEAD, all four engines:
        #   credential in vendor/, nothing else       -> exit 3   (floor fires)
        #   same tree + ONE README.md at the root     -> exit 0   file_count=1
        #   same credential at the top level          -> exit 1
        # `core.DEFAULT_SKIP_DIRS` is 36 directory names the walker will not enter,
        # and THE SCANNED TREE CHOOSES ITS OWN DIRECTORY NAMES. So hiding code in a
        # directory called `vendor` and leaving one unrelated file at the root
        # satisfies this floor completely.
        # ⇒ This is a floor against a scan that measured NOTHING. It is NOT a
        # guarantee that anything meaningful was measured, and it must never be
        # described as one. The skip-list evasion is tracked separately; it is
        # older than this floor and is not closed by it.
        # Checked BEFORE the measured-engine floor because zero files examined
        # is the root cause and the more actionable diagnosis.
        # Reached only in a run WITHOUT --fail-on; the gated path checks the same
        # condition above, before `has_findings`. One emitter, called from both,
        # so the two paths cannot drift into saying different things.
        if nothing_examined and not args.allow_degraded:
            _emit_nothing_examined(target, args)
            return 3
        # 🔴 THE SCOPE FLOOR. The floor above catches a tree emptied ENTIRELY and
        # nothing else -- "one file defeats it" is stated in its own comment, and
        # that is precisely how this defect survived. Measured on a real npm
        # tarball 2026-08-22: 81 files, `dist/` pruned by DEFAULT_SKIP_DIRS, the
        # two files left at the root were `README.md` and `package.json`, and
        # `--fail-on HIGH` returned 0. Re-run with the directory renamed: 80 files
        # read, 10 findings. The clean result was an artefact of the skip list.
        #
        # The predicate is NOT a ratio. Measured across real trees, a ratio cannot
        # separate the two cases: this repository itself skips 3,721 files and
        # keeps 174 -- a 21x ratio that is entirely healthy, because `target/` and
        # `.git/` hold no source. The npm tarball skipped 78 and kept 2. What
        # actually distinguishes them is whether ANY CODE WAS READ:
        #
        #     this repo    kept_code=93   skipped_code=0     -> measured
        #     docker-zulip kept_code=19   skipped_code=0     -> measured
        #     npm tarball  kept_code=0    skipped_code=78    -> NOT measured
        #
        # ⚠️ FAIL-SAFE DIRECTION: an extension missing from core.CODE_EXTS makes a
        # tree look LESS measured, so an unclassified language degrades toward
        # "we did not read code", never toward a clean pass. That is why the set
        # is narrow and why `.json` and `.md` are deliberately absent from it.
        if (scope_stats.get("skipped_code_files", 0) > 0
                and scope_stats.get("kept_code_files", 0) == 0
                and not args.allow_degraded):
            skipped = scope_stats.get("skipped_dirs", {})
            worst = ", ".join(
                f"{d}/ ({n} files)"
                for d, n in sorted(skipped.items(), key=lambda kv: -kv[1])[:4]
            )
            sys.stderr.write(
                "praetor: NO CODE WAS EXAMINED -- every source file in this target "
                "is inside a skipped directory, so --fail-on has no basis to pass.\n"
            )
            sys.stderr.write(
                f"  target: {target}\n"
                f"  files read: {len(scan_files)}, of which code: 0\n"
                f"  code files skipped: {scope_stats.get('skipped_code_files', 0)}\n"
                f"  skipped directories: {worst or '(none)'}\n"
            )
            sys.stderr.write(
                "  If this is a DISTRIBUTED artifact (an unpacked npm tarball, a "
                "released bundle), dist/ is the shipped code and not build output: "
                "re-run with --no-default-skips. Pass --allow-degraded to gate on "
                "findings alone.\n"
            )
            return 3
        # 🔴 A BACKSTOP, NOT THE PRIMARY ENFORCEMENT -- stated plainly so nobody
        # mistakes which line is load-bearing.
        #
        # The primary enforcement is `_status_after_reading`, which refuses to
        # report `ok` for an engine that could not decode/open a file; the
        # existing degraded path then returns 3. All three engines that read
        # bytes off disk (secrets/aisec via `read_text`+`unreadable`, model via
        # `read_bytes`+`unreadable_binary`) are wrapped, so on today's code this
        # block is unreachable.
        #
        # It is kept because that wrapping is an ENUMERATION -- three call
        # sites, by hand, across TWO accumulators -- and this repository's whole
        # history is enumerations missing their next member (this block itself
        # grew from "two call sites" to "three, across two accumulators" when
        # `model` was added; the same fate awaits whichever engine comes after
        # it). A future engine that calls `read_text`/`read_bytes` without the
        # wrapper, or introduces a THIRD accumulator nobody adds here, would
        # otherwise reach the gate reporting `ok`. This catches it.
        # ⚠️ It cannot catch an engine that opens files WITHOUT `read_text`/
        # `read_bytes`; that route bypasses the recording entirely and nothing
        # here sees it.
        if (unreadable or unreadable_binary) and not args.allow_degraded:
            total_unreadable = len(unreadable) + len(unreadable_binary)
            sys.stderr.write(
                f"praetor: {total_unreadable} FILE(S) COULD NOT BE READ -- they were "
                "selected for scanning and no engine could decode/open them, so this "
                "scan did not cover its whole target.\n"
            )
            for path, why in (unreadable + unreadable_binary)[:5]:
                sys.stderr.write(f"  {os.path.relpath(path, target)}: {why}\n")
            if total_unreadable > 5:
                sys.stderr.write(f"  ... and {total_unreadable - 5} more\n")
            sys.stderr.write(
                "  An undecodable/unopenable file is a BLIND SPOT, not a clean file. "
                "Exclude them deliberately with --exclude, or pass --allow-degraded to "
                "gate on findings alone.\n"
            )
            return 3
        # 🔴 A whole-scan floor, not a per-engine one. Reached only when every
        # engine holds an individually TRUSTED status and none of them looked at
        # anything -- `disabled` and `not-applicable` are trustworthy silences,
        # and a scan made entirely of trustworthy silences is not a measured
        # scan. Checked AFTER the degraded path so that case keeps its own
        # diagnosis. Keyed on the property, not on `--engines ""`, the spelling
        # that demonstrated it, so any future route to this state fails too.
        if not core.engines_that_measured(engine_meta) and not args.allow_degraded:
            sys.stderr.write(
                "praetor: NOTHING WAS MEASURED -- no engine examined this target, so "
                "--fail-on has no basis to pass.\n"
            )
            for name in sorted(engine_meta or {}):
                info = engine_meta[name] or {}
                sys.stderr.write(
                    f"  [{info.get('status', '?')}] {name}: {info.get('detail', '')}\n"
                )
            sys.stderr.write(
                "  Every engine's silence was individually trustworthy and none of "
                "them ran. That is not a clean result.\n"
            )
            return 3
    elif not args.allow_degraded:
        # Report-only means findings do not choose the exit code. It does not mean
        # an enabled engine that launched and broke can be reported as a successful
        # run: `praetor . && deploy` must stop on that malfunction. Do NOT reuse
        # engine_blind_spots here -- an unavailable runtime is the deliberate normal
        # Windows carve-out in core.NON_MALFUNCTION_STATUSES and stays visible in
        # the report without forcing every report-only scan non-zero.
        broken = core.engine_malfunctions(engine_meta)
        if broken:
            sys.stderr.write("praetor: ENGINE MALFUNCTION -- the scan did not complete.\n")
            for name, status, detail in broken:
                sys.stderr.write(f"  [{status}] {name}: {detail}\n")
            sys.stderr.write(
                "  This is a report-only run, not permission to treat a broken engine "
                "as a successful scan. Re-run after repair, or pass --allow-degraded "
                "to knowingly accept the blind spot.\n"
            )
            return 3
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
    except Exception:
        # Exit 1 means a completed scan found active findings.  Preserve the
        # traceback and reserve 2 for an entry-point failure that wrote no report.
        traceback.print_exc()
        sys.exit(2)
