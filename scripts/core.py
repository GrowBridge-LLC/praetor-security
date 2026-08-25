"""
PRAETOR core: shared data model, severity model, and a safe file walker.

This module has ZERO third-party dependencies (Python 3.8+ standard library only)
so it runs anywhere Python does and stays fully auditable. Nothing here executes,
imports, or evaluates the code being scanned -- PRAETOR is a static analyzer.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Iterable, Optional

# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #


class Severity(IntEnum):
    """Ordered so that higher == more dangerous. Sorting is descending."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def parse(cls, value: str) -> "Severity":
        v = (value or "").strip().upper()
        aliases = {
            "ERROR": cls.HIGH,          # semgrep ERROR
            "WARNING": cls.MEDIUM,      # semgrep WARNING
            "INFO": cls.INFO,           # semgrep INFO
            "MODERATE": cls.MEDIUM,     # npm audit
            "IMPORTANT": cls.HIGH,
            "SEVERE": cls.HIGH,
            "NONE": cls.INFO,
            "UNKNOWN": cls.LOW,
        }
        if v in cls.__members__:
            return cls[v]
        return aliases.get(v, cls.MEDIUM)


class Confidence(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2

    @property
    def label(self) -> str:
        return self.name


# --------------------------------------------------------------------------- #
# Engine status model
# --------------------------------------------------------------------------- #
#
# 🔴 An engine that could not measure must never be indistinguishable from an
# engine that measured and found nothing. Every consumer that turns a scan into
# a DECISION -- `--fail-on`, a CI gate, a human reading the report -- reads these
# five words, so they are defined once, here, and nowhere else.
#
#   ok               the engine ran to completion. Its zero means something.
#   not-applicable   nothing of this kind exists in the TARGET (no dependency
#                    manifests to audit). A property of what was scanned. There
#                    was nothing to measure, so nothing is unmeasured.
#   disabled         the OPERATOR excluded this engine (`--engines`). Their
#                    choice, made knowingly; not a surprise blind spot.
#   unavailable      the ENVIRONMENT could not run this engine (no semgrep
#                    runtime, no SCA backend). 🔴 A BLIND SPOT.
#   error            the engine launched and failed. 🔴 A BLIND SPOT.
#
# ⚠️ `unavailable` and `not-applicable` were ONE word until 2026-08-12, and the
# ambiguity is why this matters: "no dependency manifests in this repo" and
# "semgrep is not installed on this box" are opposite facts, and collapsing them
# forces a gate to choose between failing every manifest-free repo and going
# blind whenever a runtime is missing. The engines already know which case they
# are in; they now say so.

ENGINE_OK = "ok"
ENGINE_NOT_APPLICABLE = "not-applicable"
ENGINE_DISABLED = "disabled"
ENGINE_UNAVAILABLE = "unavailable"
ENGINE_ERROR = "error"

#: Statuses under which an engine's silence is TRUSTWORTHY input to a gate.
#: 🔴 Deliberately an allowlist. Any status word not named here -- including one
#: added by a future engine and never considered here -- is treated as a blind
#: spot. Unproven ⇒ assume unmeasured, exactly as an unproven finding is KEPT.
GATE_TRUSTED_STATUSES = frozenset({ENGINE_OK, ENGINE_NOT_APPLICABLE, ENGINE_DISABLED})


#: Statuses that do not mean the scanner itself malfunctioned. This is a separate
#: allowlist from GATE_TRUSTED_STATUSES because report-only runs answer a different
#: question from findings gates: an unavailable runtime is ordinary on Windows and
#: stays visible as [BLIND], but a launched engine returning error must never let a
#: report-only `praetor . && deploy` pass. Unknown statuses fail closed here too.
#:
#: ENGINE_UNAVAILABLE is deliberately the exception. A missing Semgrep runtime is
#: a normal environment fact; failing every report-only run would earn a `|| true`
#: and erase the signal. Under --fail-on it remains a blind spot and blocks.
NON_MALFUNCTION_STATUSES = frozenset({
    ENGINE_OK, ENGINE_NOT_APPLICABLE, ENGINE_DISABLED, ENGINE_UNAVAILABLE,
})


def run_tool(cmd: list, timeout: int, cwd: Optional[str] = None):
    """Run an external ANALYSIS tool and capture its output as text.

    🔴 THE SCANNED TREE MUST NOT BE ABLE TO DECIDE WHETHER AN ENGINE REPORTS.

    Every engine used to call `subprocess.run(..., text=True)` with no `encoding`.
    `text=True` alone decodes with the LOCALE codec -- cp1252 on a default Windows
    install -- and cp1252 leaves five bytes undefined (0x81 0x8D 0x8F 0x90 0x9D).
    Semgrep and osv-scanner embed SNIPPETS AND PATHS FROM THE TARGET in their
    JSON, so those bytes arrive from the tree being scanned.

    U+201D, the right double quotation mark, is `E2 80 9D`. A single typographic
    quote -- in a docstring, a README, anything pasted from a word processor --
    was therefore enough to make the output undecodable. (Its mirror U+201C is
    `E2 80 9C`, and 0x9C *is* defined in cp1252, so the left quote was harmless
    and the right one was not. Nothing about that is discoverable from a stack
    trace.)

    The failure mode is worse than an exception, because it is not one at the
    call site: the decode happens on subprocess's READER THREAD, so `run` returns
    normally with **`stdout=None`** and prints an unhandled-thread traceback to
    stderr. The engine's next statement was `r.stdout.strip()`, outside its own
    try block, and the AttributeError surfaced as `'NoneType' object has no
    attribute 'strip'` -- naming nothing that could lead a reader here.

    Net effect: any tree could disable PRAETOR's SAST engine at will, and before
    the exit-code gate landed, a disabled engine returned exit 0. Measured, not
    theorised -- it took down this repo's own self-scan, and the same decode
    error hit the tooling used to diagnose it.

    Decoding is UTF-8 with `errors="replace"`: a tool's output is diagnostic
    text, and a mojibake snippet in one finding is strictly better than losing
    every finding in the run. Reads nothing from the target itself.
    """
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        cwd=cwd,
    )


def engine_blind_spots(engine_meta: dict) -> list:
    """Engines whose verdict a gate MUST NOT read as 'clean'.

    Returns [(name, status, detail), ...] sorted by engine name, empty when the
    scan was fully measured. `engine_meta` is the per-engine block PRAETOR puts
    in its report payload under "engines".
    """
    blind = []
    for name in sorted(engine_meta or {}):
        info = engine_meta[name] or {}
        status = info.get("status", "")
        if status not in GATE_TRUSTED_STATUSES:
            blind.append((name, status or "?", info.get("detail", "")))
    return blind


def engine_malfunctions(engine_meta: dict) -> list:
    """Engines whose execution broke, independent of a findings gate.

    Returns sorted ``(name, status, detail)`` triples. An engine unavailable on
    this host is deliberately not a malfunction in a report-only run; an error or
    an unrecognised future status is. The latter fails closed because no caller has
    established that a new status is safe to treat as a completed scan.
    """
    broken = []
    for name in sorted(engine_meta or {}):
        info = engine_meta[name] or {}
        status = info.get("status", "")
        if status not in NON_MALFUNCTION_STATUSES:
            broken.append((name, status or "?", info.get("detail", "")))
    return broken


#: Statuses under which an engine actually LOOKED at the target.
#: 🔴 Strictly narrower than GATE_TRUSTED_STATUSES, and the gap is the point.
#: `disabled` and `not-applicable` are trustworthy silences -- but they are
#: silences. An engine can be trusted without having measured anything.
ENGINE_MEASURED_STATUSES = frozenset({ENGINE_OK})


def engines_that_measured(engine_meta: dict) -> list:
    """Engines that actually examined the target, sorted by name.

    🔴 GATE_TRUSTED_STATUSES ANSWERS A PER-ENGINE QUESTION AND THE GATE ALSO
    NEEDS A WHOLE-SCAN ONE.

    "Can I trust this engine's silence?" is answered correctly for each engine
    on its own. "Did anything actually look at this target?" has no per-engine
    answer at all, and nothing was asking it -- so a scan in which EVERY engine
    was individually trustworthy and NONE of them ran was a clean bill of health.

    Reached by `--engines ""`, which parses to the empty list: all four engines
    become `disabled`, every one of them gate-trusted, and a tree containing a
    live credential exits 0 under `--fail-on INFO`. A CI line reading
    `--engines "$ENGINES"` with the variable unset is a total silent false clean.
    Measured; an *invalid* engine name was correctly rejected with exit 2, so the
    typo was caught and the empty string was not.

    🔴 WHAT THIS DOES **NOT** COVER, corrected 2026-08-13 after an independent
    reader falsified the claim that used to stand here.

    This function reads a STATUS WORD. It does not observe any work. An engine
    handed an empty file list returns without raising and is recorded `ok`, so
    `engines_that_measured` reports it as having measured -- and a scan that
    opened zero files passes this floor with every engine "measuring":

        praetor <tree with a live key> --fail-on INFO               -> exit 1
        praetor <same tree> --fail-on INFO --exclude ""             -> exit 0
        praetor <same tree> --fail-on INFO --max-file-size 1        -> exit 0

    The previous docstring asserted the opposite -- that this was "keyed on the
    whole-scan property" so "any future route fails the same way". It was written
    by the author of the fix, in the same commit, and was false when written: the
    next route was one flag over. ⇒ **`ok` is not a measurement, it is the
    absence of an exception.** The real whole-scan guarantee is the file-count
    floor in `praetor.py`, which keys on `len(scan_files)` -- a count of things
    actually opened, which no silence can satisfy.

    ⇒ Keep this function for the diagnosis it genuinely gives ("every engine's
    silence was individually trustworthy and none ran", i.e. the `--engines ""`
    family). Do not extend anything to depend on it as proof that work happened.
    """
    return [name for name in sorted(engine_meta or {})
            if (engine_meta[name] or {}).get("status", "") in ENGINE_MEASURED_STATUSES]


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    """A single normalized security finding, engine-agnostic."""

    engine: str                       # sast | secrets | sca | aisec
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    file: str = ""                    # path relative to scan target
    line: int = 0
    end_line: int = 0
    category: str = ""                # e.g. INJECTION, SECRET, VULN_DEP, PROMPT_INJECTION
    description: str = ""
    snippet: str = ""                 # ALREADY redacted for secrets before it reaches here
    fix: str = ""
    cwe: str = ""                     # e.g. "CWE-89"
    owasp: str = ""                   # e.g. "A03:2021 Injection" or "LLM01: Prompt Injection"
    references: list = field(default_factory=list)
    # dedup / correlation
    corroborated_by: list = field(default_factory=list)
    # How SPECIFIC the rule that produced this finding is, as a tie-break when a
    # merge collapses two findings that describe the same token at the same spot.
    # Higher wins. 0 = "no opinion", which is every engine that does not set it.
    #
    # 🔴 This exists because a broad rule silently ATE a narrower one. `openai-key`
    # (`sk-`) and `anthropic-key` (`sk-ant-`) both match an Anthropic key, produce
    # the identical SECRET dedup key, and tied on every other sort term -- so the
    # survivor was decided by list order, and the operator was told to revoke the
    # key "in the OpenAI dashboard". They visit the wrong vendor and the live key
    # is never rotated. A scanner that finds a real leak and routes the human away
    # from it is worse than one that missed it.
    specificity: int = 0
    # false-positive handling (set by the interpretation layer)
    filtered: bool = False
    filter_reason: str = ""
    # a stable per-finding key used to merge duplicates across engines
    dedup_key: str = ""

    def compute_dedup_key(self) -> str:
        """
        Collapse findings that describe the SAME issue at the SAME place, while
        preserving genuinely distinct ones. The identity basis is category-aware:

          * VULNERABLE_DEPENDENCY -> (file, package@version, advisory-id): every
            distinct CVE/GHSA stays separate; never merged just for sharing a pkg.
          * SECRET               -> (file, line, token-signature): the same leaked
            token flagged by multiple engines at one spot merges.
          * everything else (SAST/aisec) -> (file, line, normalized-CWE): the same
            weakness on the same line, however phrased or whichever engine found
            it (bundled rule vs registry vs aisec), merges and corroborates.
        """
        norm_file = self.file.replace("\\", "/").lower()
        if self.category == "VULNERABLE_DEPENDENCY":
            basis = f"{norm_file}|dep|{self.snippet}|{self.rule_id}"
        elif self.category == "SECRET":
            sig = re.sub(r"\s+", "", (self.snippet or self.title))[:60].lower()
            basis = f"{norm_file}|{self.line}|secret|{sig}"
        else:
            cwe = (self.cwe or "").split(":")[0].strip().upper()
            disc = cwe if cwe else self.rule_id.split(".")[-1].lower()
            basis = f"{norm_file}|{self.line}|{disc}"
        self.dedup_key = hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]
        return self.dedup_key

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["confidence"] = self.confidence.label
        return d


# --------------------------------------------------------------------------- #
# Line numbering -- ONE definition, used everywhere
# --------------------------------------------------------------------------- #


def split_lines(text: str) -> list:
    r"""
    Split `text` into lines the way EVERY OTHER TOOL DOES: on `\n` only.

    🔴 THIS IS A SECURITY BOUNDARY, NOT A STYLE CHOICE. Use this instead of
    `str.splitlines()` anywhere a line number is produced from, or resolved
    against, scanned text.

    Python's `str.splitlines()` also breaks on `\v`, `\f`, `\x1c`-`\x1e`, `\x85`,
    `U+2028` and `U+2029`. Nothing else in the toolchain agrees with it --
    Semgrep, `grep -n`, `sed -n`, git, GitHub and every editor count `\n`. So a
    line number that came from one definition and is resolved against the other
    silently points at a DIFFERENT line, and the disagreement is triggered by a
    character the reader cannot see.

    ⚠️ That was not hypothetical. `_apply_inline_ignores` resolved a finding's
    `\n`-based line number against a `splitlines()` list, so a file containing
    `U+2028` shifted the indexing and a finding was suppressed by an ignore
    marker sitting on a line the reviewer would never connect to it:

        a<U+2028>b nosec        <- \n-line 1: holds the marker
        payload<ZWSP>           <- \n-line 2: FLAGGED, and carries no marker

    PRAETOR reported *"suppressed by inline ignore marker on the flagged line"*
    for a flagged line that had none. An attacker controls the scanned file, so
    they control that shift -- a silent suppression primitive against exactly the
    mechanism whose stated virtue is being auditable in the source.

    ⚠️ A `\n`-only split leaves the `\r` of a CRLF file at the end of each line,
    which would corrupt snippets and end-anchored matching, so one trailing `\r`
    is removed. Line *count* is unaffected: CRLF files have one `\n` per line,
    which is what Semgrep and every editor count too.

    Note the return shape matches `splitlines()`: a trailing newline does NOT
    produce a final empty element, so `len()` is the number of lines.

    📌 One edge case stated rather than left to be discovered: a final line ending
    in a bare `\r` with no `\n` after it (`"a\r"` as a whole file) also has that
    `\r` stripped, even though the rule above is framed around CRLF. This affects
    snippet text only, never a line NUMBER -- which is the property the security
    boundary rests on -- and the Rust port matches it deliberately.
    """
    if not text:
        return []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [ln[:-1] if ln.endswith("\r") else ln for ln in lines]


# --------------------------------------------------------------------------- #
# Redaction (never emit a full secret into a report)
# --------------------------------------------------------------------------- #


def redact(secret: str, keep: int = 4) -> str:
    """
    Mask the middle of a sensitive token. The report must never itself leak a
    live credential, so PRAETOR shows only enough to locate/rotate it.
    """
    if secret is None:
        return ""
    s = str(secret)
    if len(s) <= keep * 2:
        return s[:1] + "*" * max(1, len(s) - 1)
    return f"{s[:keep]}{'*' * 8}{s[-keep:]} (len={len(s)})"


def redact_line(line: str, secret: str, keep: int = 4) -> str:
    """Redact every occurrence of `secret` within a source line for safe display."""
    if not secret:
        return line.strip()[:200]
    return line.replace(secret, redact(secret, keep)).strip()[:200]


# --------------------------------------------------------------------------- #
# File walking
# --------------------------------------------------------------------------- #

# Directories that are noise / not first-party source. Skipped by default.
DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components",
    "venv", ".venv", "env", ".env.d", "virtualenv", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    "dist", "build", "out", ".next", ".nuxt", ".svelte-kit",
    "target", "vendor", ".gradle", ".idea", ".vs", ".vscode-test",
    "site-packages", ".terraform", "coverage", ".coverage",
    ".cache", ".parcel-cache", ".yarn", "Pods", ".dart_tool",
}

# NOTE: we do NOT skip ".claude" or "hooks" -- those are prime AI-security targets.

#: Directories skipped even when hunting SECRETS. Deliberately tiny.
#:
#: 🔴 DEFAULT_SKIP_DIRS IS AN ATTACKER-CONTROLLED SCOPE BOUNDARY, because the
#: scanned tree chooses its own directory names. Measured 2026-08-13 on a tree
#: holding a live-shaped credential:
#:     credential in vendor/, nothing else    -> exit 3  (the floor fired)
#:     same tree + ONE README.md at the root  -> exit 0  file_count=1
#:     same credential at the top level       -> exit 1
#: Naming a directory `vendor` hid its contents from every engine, and one
#: unrelated file at the root satisfied the whole-scan floor.
#:
#: The asymmetry that resolves it: **a vulnerability in vendored code is mostly
#: not yours; a credential committed there is.** So SAST keeps skipping these --
#: scanning them explodes semgrep's target count (measured 11,127 -> 138,848 on a
#: real repo, against a 900s timeout) and reports third-party findings as the
#: target's own -- while the SECRETS engine scans them, where the finding is a
#: disclosure and the disclosure is real wherever it sits.
#:
#: VCS internals stay skipped: they are not source, and secrets in *history* is a
#: separate problem needing a different tool (a scrubbed file at HEAD still
#: publishes its unscrubbed earlier commits).
SECRETS_SKIP_DIRS = {".git", ".hg", ".svn"}

# Extensions we treat as scannable text. Everything else is skipped for the
# text-based engines (secrets/aisec). SCA/SAST discover their own file types.
TEXT_EXTS = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
    # 🔴 `.cts` / `.mts` were absent while `.cjs` / `.mjs` were present. TypeScript
    # spells its CommonJS and ESM module variants with those two extensions, so a
    # published package shipping them was read as if those files did not exist.
    # Measured 2026-08-22 on a real npm tarball: 25 of its 81 files were dropped
    # here, silently, and the scan still exited 0.
    ".cts", ".mts",
    ".java", ".kt", ".kts", ".scala", ".groovy", ".go", ".rs", ".rb", ".php",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift", ".m", ".mm", ".dart",
    ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".pl", ".lua", ".r",
    ".sql", ".graphql", ".proto",
    ".html", ".htm", ".xml", ".svg",
    ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".tf", ".tfvars", ".hcl",
    ".md", ".markdown", ".mdx", ".mdc", ".rst", ".txt", ".text",
    ".dockerfile", ".gitconfig", ".npmrc",
    # 🔴 DEPLOYMENT AND TEMPLATE CODE. Every one of these was MEASURED going unread
    # on 2026-08-23, scanning a real deployment the estate was about to adopt:
    #     .pp     103 files   Puppet manifests -- the actual deployment configuration
    #     .hbs    466 files   Handlebars templates
    #     .erb     56 files   ERB templates, which embed Ruby
    #     .hook     8 files   pre-deploy.d / post-deploy.d scripts that RUN on deploy
    #     .patch    1 file    384 added lines, including API-credential handling
    # The last two are the ones that matter: a deploy hook is a supply-chain
    # execution point, and a patch is code arriving in a package. Both were
    # invisible, and the patch had to be read by hand.
    ".pp", ".erb", ".hbs", ".handlebars", ".hook", ".patch", ".diff",
    # credential-bearing text files -- a secret scanner should read these
    ".pem", ".key", ".crt", ".cer", ".pub", ".asc", ".ppk", ".pk8",
}

# The names git will actually execute as a hook. Defined HERE, in core, because
# two separate lists needed them and had already drifted apart:
#
# 🔴 `TEXT_NAMES` (which decides what the walker even OPENS) carried five of these
# while the aisec engine's detector knew twenty-three. A `commit-msg` hook that
# fetched a remote script and piped it into a shell was therefore invisible -- not
# "scanned and clean", never read at all. Discovery and detection keying on two
# hand-maintained copies of the same concept is the same missing-shared-definition
# bug this repo already fixed once for line numbering. One definition, both users.
# (The pipe is described rather than spelled: this file is scanned by the engine
# it feeds, and prose naming the pattern becomes a finding in the self-scan.)
GIT_HOOK_NAMES = {
    "applypatch-msg", "pre-applypatch", "post-applypatch",
    "pre-commit", "pre-merge-commit", "prepare-commit-msg", "commit-msg",
    "post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push",
    "pre-receive", "update", "proc-receive", "post-receive", "post-update",
    "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite",
    "sendemail-validate", "fsmonitor-watchman", "post-index-change",
}

# Files with no/other extension that are still worth scanning.
TEXT_NAMES = GIT_HOOK_NAMES | {
    "dockerfile", "makefile", "procfile", "jenkinsfile", "vagrantfile",
    ".env", ".env.local", ".env.production", ".env.development", ".env.example",
    ".npmrc", ".netrc", ".pypirc", ".dockercfg", ".gitconfig",
    # Agent instruction files. Vendor-neutral by intent: a hostile `.cursorrules`
    # is the identical attack to a hostile `CLAUDE.md`, and an instruction file the
    # walker never reaches is invisible to every engine downstream.
    # ⚠️ The ones that MATTER here are the extensionless dotfiles. Anything ending
    # in .md / .mdc / .yml is already reached via TEXT_EXTS -- `.cursor/rules/*.mdc`
    # is not the gap.
    # ⚠️ CORRECTED 2026-08-12: this sentence used to include
    # `.github/copilot-instructions.md` in that reassurance. It was FALSE. The
    # walker's `startswith(".git")` skipped the whole `.github/` tree, so this very
    # entry was unreachable -- a name listed as covered that no file could ever
    # match. Extension-vs-name was the wrong axis to reason about; REACHABILITY was
    # the gap, one layer above. Fixed in walk_files below.
    "claude.md", "agents.md", "skill.md", "readme", "readme.md",
    ".cursorrules", ".clinerules", ".windsurfrules", ".roorules", ".aiderrules",
    ".goosehints", ".continuerules", "copilot-instructions.md",
    "gemini.md", "qwen.md", "cline_instructions.md",
    # (git hook names come from GIT_HOOK_NAMES above -- do not re-list them here)
    "gemfile", "rakefile", "berksfile",
    # 🔴 EXTENSIONLESS CREDENTIAL CARRIERS, measured unread 2026-08-23 in a real
    # deployment repository: `ci/certbot/env` and `ci/http-only/env`. A file named
    # exactly `env` is a shell environment file and is one of the commonest homes
    # for a live credential; `.env` was covered and the bare name was not.
    "env", "credentials", "credentials.txt", "secrets", "htpasswd", ".htpasswd",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa.pub",
}

DEFAULT_MAX_BYTES = 3_000_000  # 3 MB: skip huge minified bundles / data blobs


def _binary_and_nul_in_sniff(path: str, sniff: int = 4096) -> tuple[bool, bool]:
    """
    Decide binary-vs-text on DECODED code points, not raw byte values. Valid
    multibyte UTF-8 (including invisible/zero-width/Unicode-Tag characters, which
    are exactly what the AI-security engine hunts for) is text -- an earlier
    raw-byte heuristic wrongly flagged a Tag-smuggled markdown file as binary
    because its UTF-8 uses high bytes. NUL is retained as an observation; binary
    is signalled by a high ratio of the other control characters / decode failures.
    """
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(sniff)
    except OSError:
        return True, False
    if not chunk:
        return False, False
    text = chunk.decode("utf-8", errors="replace")
    ctrl = sum(
        1 for c in text
        if ((ord(c) < 0x20 and c not in "\x00\t\n\r\f") or
            0x7F <= ord(c) <= 0x9F or ord(c) == 0xFFFD)
    )
    return ctrl / max(1, len(text)) > 0.30, b"\x00" in chunk


def is_probably_binary(path: str, sniff: int = 4096) -> bool:
    return _binary_and_nul_in_sniff(path, sniff)[0]


def has_nul_in_sniff(path: str, sniff: int = 4096) -> bool:
    return _binary_and_nul_in_sniff(path, sniff)[1]


def scannable(name: str) -> bool:
    low = name.lower()
    if low in TEXT_NAMES:
        return True
    _, ext = os.path.splitext(low)
    if ext in TEXT_EXTS:
        return True
    # dotfiles like ".env.staging"
    if low.startswith(".env"):
        return True
    # 🔴 `Dockerfile.dev`, `Dockerfile.prod`, `Dockerfile.test` -- MEASURED unread
    # 2026-08-23. `TEXT_NAMES` carries the exact name `dockerfile`, and
    # `os.path.splitext` turns `Dockerfile.dev` into extension `.dev`, so every
    # variant of the single most security-relevant build file in a repository fell
    # between the two checks. A Dockerfile is a build recipe; the suffix names the
    # environment, and the dev one is often the loosest.
    if low.startswith("dockerfile"):
        return True
    return False


#: Extensions whose files are EXECUTABLE-LANGUAGE source, as opposed to the
#: documentation, metadata and certificate files that also live in TEXT_EXTS.
#:
#: 🔴 THIS SET EXISTS TO ANSWER ONE QUESTION: did this scan read any code at all?
#: It is deliberately NARROWER than TEXT_EXTS, and the narrowness is the safety
#: property. `is_code()` is consulted only by the scope floor below, and that floor
#: degrades a scan when NO code was kept. So an extension MISSING from this set
#: makes a scan look LESS measured, never more -- an unknown language degrades
#: toward "we did not read code here", which is the honest answer for a name
#: nobody has classified. ⇒ Adding an entry here can only ever REDUCE the floor's
#: coverage. Removing one can only increase it. Weigh additions accordingly.
#:
#: ⚠️ `.json`, `.yaml`, `.md` and friends are EXCLUDED ON PURPOSE. A tarball whose
#: only unskipped files are `README.md` and `package.json` has not been measured,
#: and treating either as code is exactly what would hide that.
CODE_EXTS = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".cts", ".mts",
    ".vue", ".svelte", ".java", ".kt", ".kts", ".scala", ".groovy", ".go", ".rs",
    ".rb", ".php", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift", ".m",
    ".mm", ".dart", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd",
    ".pl", ".lua", ".r", ".sql",
    # Deployment code. `.pp` is Puppet and `.erb` embeds Ruby; a `.hook` is a shell
    # script that runs on deploy. All three are executable configuration, so a tree
    # made only of them HAS been measured.
    # ⚠️ `.patch`, `.diff` and `.hbs` are deliberately NOT here. They are READ (see
    # TEXT_EXTS) but they do not count as "code was examined" for the scope floor --
    # a directory of patches or templates is not evidence that the shipped code was
    # read, and this set only ever widens what counts as measured.
    ".pp", ".erb", ".hook",
}


def is_code(name: str) -> bool:
    """Whether `name` is executable-language source, for the scope floor only.

    Git hooks are code regardless of extension -- they are the conventional home
    of a fetch-and-run, and most of them carry no extension at all.
    """
    low = name.lower()
    if low in GIT_HOOK_NAMES:
        return True
    _, ext = os.path.splitext(low)
    return ext in CODE_EXTS


@dataclass
class ScanFile:
    abspath: str
    relpath: str
    size: int
    contains_nul: bool = False


def _consider_file(ap: str, rel: str, max_bytes: int, excludes: list,
                    stats: Optional[dict]) -> Optional["ScanFile"]:
    """The single per-file admission decision used by `walk_files()`'s
    directory-walk loop: symlink refusal, the exclude regex, the size cap,
    the binary/NUL sniff. Factored out so a future second file selector (a
    different candidate SET, same admission RULE) cannot silently diverge
    from this one -- see the git-tracked-selection design note in
    `references/audits/2026-08-13-scope-and-cost-research.md` §3 for why that
    matters and why it was not built: `git log 0930947` reverted an earlier
    attempt after it turned a real, gitignored credential into a false clean.
    """
    if os.path.islink(ap):
        return None
    if any(rx.search(rel) for rx in excludes):
        if stats is not None:
            stats["excluded_by_pattern"] += 1
        return None
    fn = os.path.basename(rel)
    if not scannable(fn):
        return None
    try:
        size = os.path.getsize(ap)
    except OSError:
        return None
    if size > max_bytes:
        return None
    binary, has_nul = _binary_and_nul_in_sniff(ap)
    if binary:
        return None
    if stats is not None and is_code(fn):
        stats["kept_code_files"] += 1
    return ScanFile(ap, rel, size, has_nul)


def walk_files(
    target: str,
    skip_dirs: Optional[set] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    extra_excludes: Optional[Iterable[str]] = None,
    stats: Optional[dict] = None,
) -> list:
    """
    Enumerate scannable text files under `target` exactly once. Returns a list of
    ScanFile. Never opens for execution; never follows into skipped dirs.

    🔴 `stats`, when a dict is passed, RECORDS WHAT THIS WALKER REFUSED.

    Skipping used to be invisible. `DEFAULT_SKIP_DIRS` is 38 directory names and
    THE SCANNED TREE CHOOSES ITS OWN DIRECTORY NAMES, so a tree could put all of
    its code in one of them and nothing in the report said so. Measured on a real
    npm tarball 2026-08-22: 81 files on disk, `dist/` pruned, **2 files read** --
    `README.md` and `package.json` -- and the scan exited 0 reporting no findings.

    Keys populated: `skipped_dirs` (dirname -> file count), `skipped_code_files`,
    `kept_code_files`. The caller decides what to do with them; this function only
    counts. `praetor.py` turns the third and second into the scope floor.

    The extra `os.walk` over pruned subtrees runs ONLY when `stats` is passed, so
    the engines' own hot path is unchanged.
    """
    skip_dirs = DEFAULT_SKIP_DIRS if skip_dirs is None else skip_dirs
    if stats is not None:
        stats.setdefault("skipped_dirs", {})
        stats.setdefault("skipped_code_files", 0)
        stats.setdefault("kept_code_files", 0)
        stats.setdefault("excluded_by_pattern", 0)
    excludes = [re.compile(p) for p in (extra_excludes or [])]
    target = os.path.abspath(target)
    out: list = []

    if os.path.islink(target):
        return out

    if os.path.isfile(target):
        name = os.path.basename(target)
        try:
            size = os.path.getsize(target)
        except OSError:
            return out
        binary, has_nul = _binary_and_nul_in_sniff(target)
        if scannable(name) and size <= max_bytes and not binary:
            # Report a path relative to the CWD, not the bare basename. A
            # single-file scan used to report "x.js" no matter how deep the
            # file actually lived, which is indistinguishable from every
            # other x.js in the tree and from any of its own historical
            # copies under a build worktree -- a downstream consumer
            # matching findings by file path had to re-derive the real path
            # itself to tell them apart. `scannable`/`is_code` still see the
            # plain basename above: they match name prefixes like ".env" and
            # "dockerfile", which a path would defeat.
            try:
                rel = os.path.relpath(target, os.getcwd()).replace("\\", "/")
            except ValueError:
                # Cross-drive on Windows: no relative path exists.
                rel = name
            out.append(ScanFile(target, rel, size, has_nul))
            if stats is not None and is_code(name):
                stats["kept_code_files"] += 1
        return out

    for root, dirs, files in os.walk(target, followlinks=False):
        # 🔴 `d != ".git"`, NOT `d.startswith(".git")`. The prefix form also ate
        # `.github/`, `.githooks/` and `.gitlab/`. Measured: the same credential in
        # `.github/workflows/ci.yml` and in `hooks/same.yml` gave file_count=1 --
        # only the second was found, and `secrets` still reported status "ok".
        #
        # Those directories are the opposite of noise: `.github/workflows/` is
        # EXECUTABLE CI code (a prime home for leaked tokens and for supply-chain
        # injection) and `.githooks/` is the conventional `core.hooksPath` location,
        # so the git-hook detector could not see hooks where they normally live.
        # `TEXT_NAMES` below lists `copilot-instructions.md` -- which lives under
        # `.github/` and was therefore unreachable, i.e. dead code.
        # engine_sca.py's own walker already skipped `".git"` exactly; this was the
        # outlier, not the convention.
        if stats is not None:
            for d in dirs:
                if d not in skip_dirs and d != ".git":
                    continue
                pruned_root = os.path.join(root, d)
                for proot, _pdirs, pfiles in os.walk(pruned_root, followlinks=False):
                    for pfn in pfiles:
                        stats["skipped_dirs"][d] = stats["skipped_dirs"].get(d, 0) + 1
                        # Only files this walker WOULD have opened count toward the
                        # floor. A pruned `.git` object or a compiled artifact is
                        # not evidence that code went unread.
                        if scannable(pfn) and is_code(pfn):
                            stats["skipped_code_files"] += 1
                    del proot, _pdirs
        dirs[:] = [d for d in dirs if d not in skip_dirs and d != ".git"]
        for fn in files:
            ap = os.path.join(root, fn)
            rel = os.path.relpath(ap, target).replace("\\", "/")
            sf = _consider_file(ap, rel, max_bytes, excludes, stats)
            if sf is not None:
                out.append(sf)
    return out


def read_text(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    """
    Read a file as text without ever executing it. Decodes UTF-8 with
    'surrogatepass' so that smuggled/undecodable code points survive intact for
    the AI-security engine to inspect, rather than being silently dropped.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError:
        return ""
    # 🔴 THIS RAISES ON AN INVALID START BYTE, AND THAT IS THE SAFE DIRECTION.
    #
    # A `surrogateescape` fallback was added 2026-08-13 and REVERTED the same day.
    # It stopped the crash, and in doing so converted a LOUD failure into a SILENT
    # MISS. Measured by an independent auditor, aisec engine, identical trees but
    # for one byte inside the word "previous":
    #
    #   payload intact            -> exit 1, aisec ok,      1 finding
    #   payload + 1 invalid byte:
    #       with the fallback     -> exit 0, aisec **ok**,  0 findings
    #       without it (here)     -> exit 3, aisec [error] "codec can't decode"
    #
    # The bad byte becomes U+DCxx, so a pattern spanning it no longer matches --
    # while the text stays perfectly legible to a human AND to the agent that
    # reads the file, which IS the threat model. The operator was told the engine
    # could not read the file; the fallback told them it looked and found nothing.
    # ⇒ **Reversibility of the STRING is not preservation of DETECTION**, and that
    # was the false step in the comment that justified the fallback.
    #
    # It also moved a contained engine error into an uncaught UnicodeEncodeError
    # in the report writer, which left a 0-byte .txt and no .json at all.
    #
    # ⚠️ COST, ACCEPTED DELIBERATELY: a target carrying any non-UTF-8 file -- e.g.
    # any venv with `joblib`, which ships one to TEST encoding handling -- gets
    # `[error]` and exit 3 rather than a scan. That is a scanner saying "I could
    # not measure this", which is correct and actionable. The proper fix is to
    # keep a fallback AND record each decode failure as a per-file fact the report
    # surfaces, so the engine never reports `ok` about a file it could not read.
    # Designed, not built: it needs its own audit, not a fourth same-night patch.
    return data.decode("utf-8", errors="surrogatepass")
