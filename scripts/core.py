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

# Extensions we treat as scannable text. Everything else is skipped for the
# text-based engines (secrets/aisec). SCA/SAST discover their own file types.
TEXT_EXTS = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".java", ".kt", ".kts", ".scala", ".groovy", ".go", ".rs", ".rb", ".php",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift", ".m", ".mm", ".dart",
    ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".pl", ".lua", ".r",
    ".sql", ".graphql", ".proto",
    ".html", ".htm", ".xml", ".svg",
    ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".tf", ".tfvars", ".hcl",
    ".md", ".markdown", ".mdx", ".mdc", ".rst", ".txt", ".text",
    ".dockerfile", ".gitconfig", ".npmrc",
    # credential-bearing text files -- a secret scanner should read these
    ".pem", ".key", ".crt", ".cer", ".pub", ".asc", ".ppk", ".pk8",
}

# Files with no/other extension that are still worth scanning.
TEXT_NAMES = {
    "dockerfile", "makefile", "procfile", "jenkinsfile", "vagrantfile",
    ".env", ".env.local", ".env.production", ".env.development", ".env.example",
    ".npmrc", ".netrc", ".pypirc", ".dockercfg", ".gitconfig",
    # Agent instruction files. Vendor-neutral by intent: a hostile `.cursorrules`
    # is the identical attack to a hostile `CLAUDE.md`, and an instruction file the
    # walker never reaches is invisible to every engine downstream.
    # ⚠️ The ones that MATTER here are the extensionless dotfiles. Anything ending
    # in .md / .mdc / .yml is already reached via TEXT_EXTS -- `.cursor/rules/*.mdc`
    # and `.github/copilot-instructions.md` were never the gap.
    "claude.md", "agents.md", "skill.md", "readme", "readme.md",
    ".cursorrules", ".clinerules", ".windsurfrules", ".roorules", ".aiderrules",
    ".goosehints", ".continuerules", "copilot-instructions.md",
    "gemini.md", "qwen.md", "cline_instructions.md",
    "pre-commit", "post-commit", "pre-push", "post-checkout", "post-merge",
    "gemfile", "rakefile", "berksfile",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa.pub",
}

DEFAULT_MAX_BYTES = 3_000_000  # 3 MB: skip huge minified bundles / data blobs


def is_probably_binary(path: str, sniff: int = 4096) -> bool:
    """
    Decide binary-vs-text on DECODED code points, not raw byte values. Valid
    multibyte UTF-8 (including invisible/zero-width/Unicode-Tag characters, which
    are exactly what the AI-security engine hunts for) is text -- an earlier
    raw-byte heuristic wrongly flagged a Tag-smuggled markdown file as binary
    because its UTF-8 uses high bytes. Binary is signalled by NUL bytes or a high
    ratio of C0/C1 control characters / decode failures.
    """
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(sniff)
    except OSError:
        return True
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    text = chunk.decode("utf-8", errors="replace")
    ctrl = sum(
        1 for c in text
        if (ord(c) < 0x20 and c not in "\t\n\r\f") or ord(c) == 0x7F or ord(c) == 0xFFFD
    )
    return ctrl / max(1, len(text)) > 0.30


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
    return False


@dataclass
class ScanFile:
    abspath: str
    relpath: str
    size: int


def walk_files(
    target: str,
    skip_dirs: Optional[set] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    extra_excludes: Optional[Iterable[str]] = None,
) -> list:
    """
    Enumerate scannable text files under `target` exactly once. Returns a list of
    ScanFile. Never opens for execution; never follows into skipped dirs.
    """
    skip_dirs = DEFAULT_SKIP_DIRS if skip_dirs is None else skip_dirs
    excludes = [re.compile(p) for p in (extra_excludes or [])]
    target = os.path.abspath(target)
    out: list = []

    if os.path.isfile(target):
        base = os.path.dirname(target)
        rel = os.path.basename(target)
        try:
            size = os.path.getsize(target)
        except OSError:
            return out
        if scannable(rel) and size <= max_bytes and not is_probably_binary(target):
            out.append(ScanFile(target, rel, size))
        return out

    for root, dirs, files in os.walk(target, followlinks=False):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".git")]
        for fn in files:
            ap = os.path.join(root, fn)
            rel = os.path.relpath(ap, target).replace("\\", "/")
            if any(rx.search(rel) for rx in excludes):
                continue
            if not scannable(fn):
                continue
            try:
                size = os.path.getsize(ap)
            except OSError:
                continue
            if size > max_bytes:
                continue
            if is_probably_binary(ap):
                continue
            out.append(ScanFile(ap, rel, size))
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
    return data.decode("utf-8", errors="surrogatepass")
