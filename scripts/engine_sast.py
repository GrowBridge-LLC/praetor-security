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

import hashlib
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
import time

import core
from core import (Finding, Severity, Confidence, split_lines,
                   ENGINE_OK, ENGINE_PARTIAL_PARSE, ENGINE_ERROR)

#: Added 2026-09-02, per references/audits/2026-09-02-aisec-competitor-survey.md:
#: `p/ai-best-practices` is free, community-origin, unauthenticated (no
#: `semgrep login`, confirmed live), and covers MCP SSRF, MCP command
#: injection, unsanitized MCP tool-call returns, and unsafe LangChain
#: `exec` -- a real gap, since PRAETOR's aisec engine covers agentic threats
#: via pattern matching but SAST pulled nothing agent-code-specific before
#: this. Verified live before adding: `semgrep --config p/ai-best-practices`
#: loads 27 rules, zero rule-ID overlap with the two packs already below.
DEFAULT_REGISTRY_CONFIGS = ["p/owasp-top-ten", "p/security-audit", "p/ai-best-practices"]
#: Overall semgrep budget, in seconds.
#:
#: 🔴 THIS WAS A HARD-CODED CONSTANT WITH NO OPERATOR OVERRIDE, AND THAT IS A
#: COVERAGE CEILING NOBODY COULD RAISE. Measured 2026-08-23 on a real 7,369-file
#: target: semgrep exceeded 900s and the engine returned `error` twice -- once in
#: a four-engine run and once running alone. PRAETOR correctly returned exit 3
#: rather than a clean result, so it was never a false clean. But the only way to
#: get any static analysis at all was to PARTITION the tree by hand and scan 20
#: directories separately, which is not something a CI caller can do.
#:
#: ⇒ The failure mode of an unraisable ceiling is a silent absence of SAST on
#: exactly the largest and most interesting codebases -- the ones most worth
#: scanning. A budget is an operator decision, so it is now one.
#:
#: ⚠️ RAISING IT IS SAFE; LOWERING IT IS ALSO SAFE. A timeout produces an engine
#: `error`, which the exit-code floor already turns into 3. There is no setting
#: of this value that converts a timeout into a passing scan.
_SEMGREP_TIMEOUT_DEFAULT = 900
_SEMGREP_TIMEOUT = int(os.environ.get("PRAETOR_SEMGREP_TIMEOUT") or _SEMGREP_TIMEOUT_DEFAULT)
_SEMGREP_VERSION = "1.177.0"
_SEMGREP_DOCKER_IMAGE = f"semgrep/semgrep:{_SEMGREP_VERSION}"

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
_DISABLE_NOSEM = "--disable-nosem"
_RETRYABLE_FLAGS = (_SEMGREPIGNORE_OFF, _DISABLE_NOSEM)

#: Ignore files that live in the SCANNED TREE and can shrink semgrep's scope.
#: ⚠️ Used ONLY to enrich an error message. It is deliberately NOT part of the
#: scope guard's condition any more -- gating the guard on this list is exactly
#: what made the first version miss two total-shrink routes. See the guard.
_TARGET_CONTROLLED_IGNORE_FILES = (".semgrepignore",)

# Detection and walker admission share core's source-kind authority. These
# compatibility views do not declare eligibility; rules and runtime admission do.
_LANGUAGE_BY_EXTENSION = core.SOURCE_LANGUAGE_BY_EXTENSION
_CODE_EXTENSIONS = frozenset(_LANGUAGE_BY_EXTENSION)


_INLINE_LANGUAGES = re.compile(r"^    languages\s*:\s*\[([^]]*)\]\s*(?:#.*)?$")
_RULE_START = re.compile(r"^  -\s+id\s*:\s*(\S.*?)\s*$")
_RULE_KEY = re.compile(r"^    ([A-Za-z][A-Za-z0-9_-]*)\s*:")
_DUMP_RULE_START = re.compile(
    r'(?m)^\s*\[?\{\s*Rule\.id\s*=\s*\(\s*"[^"]+"\s*,\s*_\s*\)\s*;'
)
_DUMP_RULE_FIELD = re.compile(r'(?m)^\s*(?:\[?\{\s*)?Rule\.id\s*=')
_DUMP_INVALID_RULES_FIELD = re.compile(r"(?m)^  invalid_rules\s*=")
_DUMP_RECORD_START = re.compile(r"(?m)^\{\s*Rule_fetching\.rules\s*=")
_DUMP_RULES_HEADER = re.compile(r"(?:Rule_fetching\.rules|\brules)\s*=")
_DUMP_TARGET_FIELD = re.compile(
    r"\btarget_selector\s*=\s*(?:(?:\(Some\s*\[([^]]+)\]\))|None)\s*;\s*"
    r"target_analyzer\s*=",
)
_DUMP_TARGET_TOKEN = re.compile(r"\btarget_selector\s*=")
_DUMP_PATH_FIELD = re.compile(
    r"\bpaths\s*=\s*(?:(None\s*;)|\(Some\s*\{\s*Rule\.require\s*=\s*(\[\]|\[))",
)
_DUMP_PATH_TOKEN = re.compile(r"\bpaths\s*=")

#: The one eligibility alias authority. Keys are PRAETOR's detected-language
#: names; values are the Semgrep language IDs PRAETOR recognizes.
#: Recognition does not imply coverage: an empty alias set (currently
#: Objective-C), or a future detected language absent from this table, cannot
#: be covered.
SAST_LANGUAGE_ALIASES = {
    "shell": frozenset({"bash", "sh"}),
    "python": frozenset({"python", "python3", "py"}),
    "javascript": frozenset({"javascript", "js"}),
    "typescript": frozenset({"typescript", "ts"}),
    "java": frozenset({"java"}),
    "kotlin": frozenset({"kotlin", "kt"}),
    "go": frozenset({"go", "golang"}),
    "ruby": frozenset({"ruby"}),
    "php": frozenset({"php"}),
    "csharp": frozenset({"csharp", "c#"}),
    "c": frozenset({"c"}),
    "cpp": frozenset({"cpp", "c++"}),
    "rust": frozenset({"rust"}),
    "swift": frozenset({"swift"}),
    "scala": frozenset({"scala"}),
    "lua": frozenset({"lua"}),
    "dart": frozenset({"dart"}),
    "objective-c": frozenset(),
    "terraform": frozenset({"terraform", "hcl", "tf"}),
    "vue": frozenset({"vue"}),
}

_monotonic = time.monotonic


class RulesetEligibilityError(RuntimeError):
    """Pinned rules cannot establish a trustworthy eligibility population."""


class RulesetRuntimeUnavailable(RuntimeError):
    """The rules are locally well-formed but Semgrep is unavailable to resolve them."""


def _detected_language_for_id(name: str):
    value = name.strip().strip("'\"").lower()
    for detected, aliases in SAST_LANGUAGE_ALIASES.items():
        if value in aliases:
            return detected
    return None


def _is_registry_config(config: str) -> bool:
    """Whether Semgrep must interpret this source as a registry identifier."""
    value = os.fspath(config)
    return bool(re.fullmatch(r"(?:p|r|s)/[A-Za-z0-9_.@/-]+", value))


def _is_local_config_source(config: str) -> bool:
    value = os.fspath(config)
    return not _is_registry_config(value) and not re.match(
        r"^[A-Za-z][A-Za-z0-9+.-]*://", value
    )


def _normalized_config_source(config: str, *, force_local: bool = False) -> str:
    """One identity for every config from coverage resolution through scanning."""
    value = os.fspath(config)
    if not force_local and _is_registry_config(value):
        return value
    if not force_local and not _is_local_config_source(value):
        return value
    return os.path.abspath(os.path.expanduser(value))


def _default_bundled_rules_path() -> str:
    candidates = []
    configured = os.environ.get("PRAETOR_RULES_DIR")
    if configured:
        candidates.append(os.path.join(configured, "semgrep-praetor.yaml"))
    candidates.extend([
        os.path.abspath(os.path.join(
            os.path.dirname(__file__), os.pardir, "rules", "semgrep-praetor.yaml"
        )),
        os.path.join(sys.prefix, "share", "praetor", "rules", "semgrep-praetor.yaml"),
        os.path.join(os.path.dirname(sys.prefix), "share", "praetor", "rules",
                     "semgrep-praetor.yaml"),
    ])
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return candidates[0]


def pinned_rule_languages(bundled_rules: str) -> frozenset:
    """Detected-language names declared by the pinned bundled rules.

    Compatibility/introspection API only. It does not implement ``covers(L)``:
    it cannot validate rules or account for path filters and operator configs.
    ``language_coverage`` is the eligibility authority and resolves rules with
    Semgrep itself. A malformed, unreadable, or missing file still raises here
    rather than collapsing to an empty declaration population.
    """
    languages = set()
    try:
        with open(bundled_rules, encoding="ascii") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeError) as exc:
        raise RulesetEligibilityError(
            f"pinned SAST rules unavailable: {bundled_rules}: {exc}"
        ) from exc

    content = [line.rstrip("\r\n") for line in lines
               if line.strip() and not line.lstrip().startswith("#")]
    if not content or content[0] != "rules:" or content.count("rules:") != 1:
        raise RulesetEligibilityError("pinned SAST rules are malformed: missing top-level rules")

    starts = [i for i, line in enumerate(lines) if _RULE_START.match(line)]
    if not starts:
        raise RulesetEligibilityError("pinned SAST rules are malformed: no rules found")
    starts.append(len(lines))
    for start, end in zip(starts, starts[1:]):
        block = lines[start:end]
        keys = [match.group(1) for line in block if (match := _RULE_KEY.match(line))]
        matches = [_INLINE_LANGUAGES.match(line) for line in block]
        matches = [match for match in matches if match]
        if (len(matches) != 1
                or not {"languages", "message", "severity"}.issubset(keys)
                or not any(key.startswith("pattern") for key in keys)):
            rule_id = _RULE_START.match(lines[start]).group(1)
            raise RulesetEligibilityError(
                f"pinned SAST rule {rule_id!r} is malformed"
            )
        raw_items = [item.strip().strip("'\"")
                     for item in matches[0].group(1).split(",")]
        if (not raw_items or any(not item for item in raw_items)
                or any(not re.fullmatch(r"[A-Za-z0-9_+#.-]+", item)
                       for item in raw_items)):
            raise RulesetEligibilityError("pinned SAST rule has an empty languages list")
        languages.update(
            detected
            for item in raw_items
            if (detected := _detected_language_for_id(item)) is not None
        )
    return frozenset(languages)


def _dump_rule_blocks(output: str, end: int):
    """Return structurally balanced top-level rule objects, or fail closed."""
    header = _DUMP_RULES_HEADER.search(output, 0, end)
    if header is None:
        return None
    list_start = output.find("[", header.end(), end)
    if list_start < 0:
        return None
    square_depth = 0
    brace_depth = 0
    rule_start = None
    blocks = []
    in_string = False
    escaped = False
    for index in range(list_start, end):
        char = output[index]
        if in_string:
            if char == "\n":
                # A physical newline inside a rendered string makes structural
                # lines indistinguishable from attacker-controlled payload.
                return None
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "[":
            square_depth += 1
        elif char == "]":
            square_depth -= 1
            if square_depth < 0:
                return None
            if square_depth == 0:
                if brace_depth or rule_start is not None:
                    return None
                return blocks
        elif char == "{":
            if square_depth == 1 and brace_depth == 0:
                rule_start = index
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
            if brace_depth < 0:
                return None
            if brace_depth == 0 and rule_start is not None:
                blocks.append(output[rule_start:index + 1])
                rule_start = None
    return None


def _rules_from_semgrep_dump_record(output: str):
    """Parse one validated Rule_fetching record, or fail it closed."""
    invalid_fields = list(_DUMP_INVALID_RULES_FIELD.finditer(output))
    if len(invalid_fields) != 1:
        return None
    invalid_field = invalid_fields[0]
    if not re.fullmatch(
            r"\s*\[\s*\]\s*;\s*(?:origin\s*=.*)?\}\s*",
            output[invalid_field.end():], flags=re.DOTALL):
        return None
    invalid_at = invalid_field.start()
    blocks = _dump_rule_blocks(output, invalid_at)
    if blocks is None or len(blocks) != len(_DUMP_RULE_FIELD.findall(output[:invalid_at])):
        # Partial parsing is more dangerous than total failure: a surviving
        # subset could falsely establish coverage for an optional source.
        return None
    rules = []
    for block in blocks:
        starts = list(_DUMP_RULE_START.finditer(block))
        if len(starts) != 1 or starts[0].start() != 0:
            return None
        # Rule-controlled pattern, fix, and metadata text can contain strings
        # shaped like resolved fields on either side of the real fields. There
        # is no trustworthy way to choose among duplicates in this textual dump
        # format, so ambiguity invalidates the whole source fail-closed.
        target_matches = list(_DUMP_TARGET_FIELD.finditer(block))
        if (len(target_matches) != 1
                or len(_DUMP_TARGET_TOKEN.findall(block)) != 1):
            return None
        target_match = target_matches[0]
        # generic, regex, and none resolve with target_selector=None. Preserve
        # the validated rule in the population, but give it no language IDs so
        # it cannot count for any detected language.
        raw_languages = target_match.group(1)
        language_ids = frozenset(
            item.strip().lower() for item in raw_languages.split(";")
            if item.strip()
        ) if raw_languages is not None else frozenset()
        path_matches = list(_DUMP_PATH_FIELD.finditer(block))
        if (len(path_matches) != 1
                or len(_DUMP_PATH_TOKEN.findall(block)) != 1):
            # A future dump shape cannot safely establish coverage.
            return None
        paths_match = path_matches[0]
        has_include = paths_match.group(1) is None and paths_match.group(2) != "[]"
        rules.append({"languages": language_ids, "has_include": has_include})
    return rules


def _rules_from_semgrep_dump(output: str):
    """Extract rules only when every resolved config record validates.

    Semgrep emits one ``Rule_fetching`` record per loaded local config file.
    Each record owns its own final ``invalid_rules`` field; accepting a valid
    subset while another record is malformed would falsely establish coverage.
    Older Semgrep dump shapes are one implicit record and remain supported.
    """
    record_starts = list(_DUMP_RECORD_START.finditer(output))
    if not record_starts:
        records = [output]
    else:
        if output[:record_starts[0].start()].strip():
            return None
        records = [
            output[start.start():(
                record_starts[index + 1].start()
                if index + 1 < len(record_starts) else len(output)
            )]
            for index, start in enumerate(record_starts)
        ]
    resolved = []
    for record in records:
        rules = _rules_from_semgrep_dump_record(record)
        if rules is None:
            return None
        resolved.extend(rules)
    return resolved


def _config_crosses_target_trust_boundary(config: str, target: str) -> bool:
    """Whether local config is target-owned or a directory that can load it."""
    if _is_registry_config(config):
        return False
    unresolved_config = _normalized_config_source(config)
    unresolved_target = os.path.abspath(os.path.expanduser(target)) if target else ""
    if not unresolved_target or not os.path.exists(unresolved_config):
        return False
    try:
        # Parent relationships must be derived from canonical paths. samefile()
        # on an unresolved leaf does not make dirname(unresolved_leaf) canonical.
        config_path = os.path.realpath(unresolved_config)
        target_path = os.path.realpath(unresolved_target)
        if not os.path.samefile(config_path, unresolved_config):
            return True
        if not os.path.samefile(target_path, unresolved_target):
            return True
    except (OSError, ValueError):
        return True

    def within(child: str, parent: str):
        """True/False by filesystem identity; None means fail-closed uncertainty."""
        try:
            if os.path.samefile(child, parent):
                return True
            current = child if os.path.isdir(child) else os.path.dirname(child)
            while True:
                if os.path.samefile(current, parent):
                    return True
                ancestor = os.path.dirname(current)
                if ancestor == current:
                    return False
                current = ancestor
        except (OSError, ValueError):
            return None

    config_inside_target = within(config_path, target_path)
    target_inside_config = (
        within(target_path, config_path) if os.path.isdir(config_path) else False
    )
    if config_inside_target is None or target_inside_config is None:
        return True
    return config_inside_target or target_inside_config


def _docker_local_config_mount(config: str):
    """Return one stable, read-only Docker binding for an exact local source."""
    source = _normalized_config_source(config, force_local=True)
    identity = hashlib.sha256(os.fsencode(os.path.realpath(source))).hexdigest()[:20]
    target = f"/praetor-config-{identity}"
    return source, target, f"{source}:{target}:ro"


def _dump_config_command(runtime: dict, config: str):
    """Build config resolution for the same Semgrep runtime used by the scan."""
    resolved = _normalized_config_source(config)
    is_local = _is_local_config_source(resolved)
    if runtime["mode"] == "native":
        return runtime["prefix"] + ["show", "dump-config", resolved]
    if runtime["mode"] == "wsl":
        config_arg = _win_to_wsl(resolved) if is_local else resolved
        return [
            *runtime["prefix"][:-1], "env", "SEMGREP_SEND_METRICS=off",
            "SEMGREP_ENABLE_VERSION_CHECK=0", runtime["prefix"][-1],
            "show", "dump-config", config_arg,
        ]
    if runtime["mode"] == "docker":
        if is_local and os.path.exists(resolved):
            source, mount_target, binding = _docker_local_config_mount(resolved)
            return [
                "docker", "run", "--rm", "--network", "host",
                "-e", "SEMGREP_SEND_METRICS=off",
                "-e", "SEMGREP_ENABLE_VERSION_CHECK=0",
                "-v", binding, _SEMGREP_DOCKER_IMAGE, "semgrep",
                "show", "dump-config", mount_target,
            ]
        return [
            "docker", "run", "--rm", "--network", "host",
            "-e", "SEMGREP_SEND_METRICS=off",
            "-e", "SEMGREP_ENABLE_VERSION_CHECK=0",
            _SEMGREP_DOCKER_IMAGE, "semgrep", "show", "dump-config", resolved,
        ]
    return []


def _resolve_rule_source(config: str, runtime: dict, timeout: int = 60):
    """Resolve one config with Semgrep; return validated rules or ``None``."""
    command = _dump_config_command(runtime, config)
    if not command:
        return None
    environment = dict(os.environ)
    environment["SEMGREP_SEND_METRICS"] = "off"
    environment["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    try:
        completed = core.run_tool(command, timeout=timeout, env=environment)
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return _rules_from_semgrep_dump(completed.stdout or "")


def _source_rule_counts(rules) -> dict:
    counts = {}
    for detected, aliases in SAST_LANGUAGE_ALIASES.items():
        count = sum(
            1 for rule in rules
            if not rule["has_include"] and aliases.intersection(rule["languages"])
        )
        if count:
            counts[detected] = count
    return counts


def _resolved_language_population(rules):
    """Return canonical resolved languages and unrecognized dump tokens."""
    canonical = set()
    unknown = set()
    for rule in rules:
        for language_id in rule["languages"]:
            normalized = str(language_id).strip().strip("'\"").lower()
            # These validated analyzers deliberately never establish language
            # coverage, but they are known rather than dump-format drift.
            if normalized in {"generic", "regex", "none"}:
                continue
            detected = _detected_language_for_id(normalized)
            if detected is None:
                unknown.add(str(language_id))
            else:
                canonical.add(detected)
    return frozenset(canonical), frozenset(unknown)


def _runtime_filename_extensions(runtime: dict, timeout: int = 30) -> dict:
    """Ask the selected engine for its filename metadata, without a target.

    Neither invocation reads/imports target code. Remote commands use argv, no
    shell; Docker needs no target mount or network. Missing/changed metadata
    proves no admission. Shebang-only admission is deliberately not inferred:
    an unproven filename retains its named coverage gap.
    """
    mode = runtime.get("mode")
    if mode == "native":
        launcher = []
    elif mode == "wsl":
        launcher = runtime["prefix"][:-1]
    elif mode == "docker":
        launcher = ["docker", "run", "--rm", "--network", "none",
                    _SEMGREP_DOCKER_IMAGE]
    else:
        return {}
    semgrep = "semgrep" if mode == "docker" else runtime["prefix"][-1]
    environment = dict(os.environ, SEMGREP_SEND_METRICS="off",
                       SEMGREP_ENABLE_VERSION_CHECK="0")
    try:
        located = core.run_tool(
            launcher + [semgrep, "scan", "--dump-engine-path"],
            timeout=timeout / 2, env=environment,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        binary = (located.stdout or "").strip()
        # The engine, not PATH or a target-relative filename, supplies this path.
        absolute = (binary.startswith("/") if mode != "native"
                    else os.path.isabs(binary))
        if located.returncode or not absolute or "\n" in binary:
            return {}
        dumped = core.run_tool(
            launcher + [binary, "-dump_extensions"],
            timeout=timeout / 2, env=environment,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        if dumped.returncode:
            return {}
        lines = core.split_lines(dumped.stdout or "")
        if not lines or lines[0] != "Language to supported file extension mappings:":
            return {}
        extensions = {}
        for line in lines[1:]:
            language, separator, values = line.strip().partition("->")
            if not separator or not language or not values:
                return {}
            suffixes = tuple(value.strip() for value in values.split(","))
            if not all(suffixes):
                return {}
            extensions[language] = suffixes
        return extensions
    except (OSError, subprocess.SubprocessError):
        return {}


def _filename_admitted(path: str, language: str, extensions: dict) -> bool:
    # Semgrep's suffix matching is case-sensitive, unlike source discovery.
    return any(path.endswith(suffix)
               for alias in SAST_LANGUAGE_ALIASES.get(language, ())
               for suffix in extensions.get(alias, ()))


def _filename_admitted_casefolded(path: str, language: str, extensions: dict) -> bool:
    """PRAETOR's source kind is case-insensitive even when Semgrep's is not."""
    folded = path.casefold()
    return any(folded.endswith(suffix.casefold())
               for alias in SAST_LANGUAGE_ALIASES.get(language, ())
               for suffix in extensions.get(alias, ()))


def _filename_known_to_runtime(path: str, extensions: dict) -> bool:
    """A known suffix selects Semgrep's parser even if the shebang disagrees."""
    return any(path.endswith(suffix)
               for suffixes in extensions.values() for suffix in suffixes)


_SHEBANG_INTERPRETERS = {
    "python": "python", "python2": "python", "python3": "python",
    "bash": "shell", "sh": "shell", "zsh": "shell",
    "node": "javascript", "nodejs": "javascript",
    "ruby": "ruby", "pwsh": "powershell", "powershell": "powershell",
}


def _shebang_language(path: str) -> str | None:
    """Read only the first line of a walker-admitted file; never run it."""
    try:
        with open(path, "rb") as source:
            first = source.readline(256)
    except OSError:
        return None
    if not first.startswith(b"#!") or b"\n" not in first:
        return None
    try:
        words = shlex.split(first[2:].decode("ascii").strip())
    except (UnicodeError, ValueError):
        return None
    if not words:
        return None
    interpreter = os.path.basename(words[0]).lower()
    if interpreter == "env":
        args = words[1:]
        if args and args[0] == "-S":
            args = args[1:]
        args = [arg for arg in args if not arg.startswith("-") and "=" not in arg]
        if not args:
            return None
        interpreter = os.path.basename(args[0]).lower()
    if re.fullmatch(r"python3(?:\.\d+)?", interpreter):
        interpreter = "python3"
    return _SHEBANG_INTERPRETERS.get(interpreter)


def language_coverage(scan_files, bundled_rules: str, *, target=None,
                      extra_configs=None, use_registry=False, prefer="auto",
                      wsl_distro="Ubuntu", timeout=_SEMGREP_TIMEOUT) -> dict:
    """Resolve in-effect rules and report coverage for each detected language."""
    # Validate the pinned artifact before runtime detection.  Runtime absence is
    # an ordinary ENGINE_UNAVAILABLE fact; a missing, unreadable, or malformed
    # trust root remains a scanner error even on a host without Semgrep.
    declared_pinned_languages = pinned_rule_languages(bundled_rules)

    runtime = detect_runtime(prefer, wsl_distro)
    if not runtime["available"]:
        raise RulesetRuntimeUnavailable(runtime["detail"])

    extensions = _runtime_filename_extensions(runtime, timeout=min(timeout, 30))

    detected_files = []
    shebang_by_path = {}
    absolute_by_path = {}
    extension_by_path = {}
    for sf in (scan_files or []):
        path = getattr(sf, "relpath", None) or getattr(sf, "abspath", "") or str(sf)
        absolute = getattr(sf, "abspath", None)
        absolute_by_path[path] = absolute or os.path.abspath(os.path.join(target or ".", path))
        # Establish the suffix language before reading content. A shebang is
        # additive evidence and must never replace a covered suffix.
        extension = core.source_language(path)
        mapped_suffix = (os.path.splitext(os.path.basename(path))[1].casefold()
                         in core.SOURCE_LANGUAGE_BY_EXTENSION)
        shebang = _shebang_language(absolute_by_path[path]) if extensions else None
        # A basename such as pre-commit is a useful code hint, but it is not
        # an extension. Its mapped shebang alone decides SAST eligibility.
        if shebang and not mapped_suffix:
            extension = None
        if extension:
            detected_files.append((path, extension))
            if _filename_admitted_casefolded(path, extension, extensions):
                extension_by_path[path] = extension
        if shebang:
            shebang_by_path[path] = shebang
            if shebang != extension:
                detected_files.append((path, shebang))
    detected = frozenset(language for _, language in detected_files)

    source_specs = [(
        "pinned rules", _normalized_config_source(bundled_rules, force_local=True), True
    )]
    if use_registry:
        source_specs.extend(
            (f"registry config {config}", _normalized_config_source(config), False)
            for config in DEFAULT_REGISTRY_CONFIGS
        )
    source_specs.extend(
        (f"operator config {config}", _normalized_config_source(config), False)
        for config in (extra_configs or [])
    )

    sources = {language: [] for language in detected}
    unresolved = []
    ignored_target_configs = []
    resolved_optional = []
    pinned_languages = set()
    resolution_deadline = _monotonic() + timeout
    for label, config, pinned in source_specs:
        if not pinned and _config_crosses_target_trust_boundary(config, target):
            ignored_target_configs.append(label)
            continue
        remaining = resolution_deadline - _monotonic()
        if remaining <= 0:
            raise RulesetEligibilityError(
                f"SAST rule resolution timeout before {label}"
            )
        rules = _resolve_rule_source(config, runtime, timeout=remaining)
        if rules is None:
            raise RulesetEligibilityError(f"SAST rule source unresolved: {label}")
        if pinned and not rules:
            raise RulesetEligibilityError(
                f"pinned SAST rules are malformed or empty: {bundled_rules}"
            )
        if pinned:
            resolved_pinned_languages, unknown_dump_languages = (
                _resolved_language_population(rules)
            )
            missing_languages = declared_pinned_languages - resolved_pinned_languages
            if unknown_dump_languages or missing_languages:
                details = []
                if unknown_dump_languages:
                    details.append(
                        "unrecognized resolved language id(s): "
                        + ", ".join(sorted(unknown_dump_languages))
                    )
                if missing_languages:
                    details.append(
                        "declared language(s) absent after resolution: "
                        + ", ".join(sorted(missing_languages))
                    )
                raise RulesetEligibilityError(
                    "pinned SAST rule language resolution drift: " + "; ".join(details)
                )
        if not pinned:
            resolved_optional.append(label)
        rule_counts = _source_rule_counts(rules)
        if pinned:
            pinned_languages.update(rule_counts)
        for language, count in rule_counts.items():
            if language in sources:
                sources[language].append({"source": label, "count": count})

    eligible = [(path, language) for path, language in detected_files
                if sources[language] and (extension_by_path.get(path) == language
                                          or shebang_by_path.get(path) == language)]
    covered = frozenset(language for _, language in eligible)
    uncovered = frozenset(language for path, language in detected_files
                          if not sources[language]
                          or (extension_by_path.get(path) != language
                              and shebang_by_path.get(path) != language))
    # One language may have both admitted and omitted source kinds.
    sources = {language: evidence if language in covered else []
               for language, evidence in sources.items()}
    return {
        "detected": detected,
        "covered": covered,
        "uncovered": uncovered,
        "eligible_files": len({path for path, _language in eligible}),
        "eligible_paths": tuple(dict.fromkeys(path for path, _language in eligible)),
        # Mixed-case suffixes and extensionless shebang scripts both need an
        # explicit Semgrep target. The name is retained for caller compatibility.
        "shebang_targets": tuple(dict.fromkeys(absolute_by_path[path]
                                 for path, language in eligible
                                 if not _filename_known_to_runtime(path, extensions))),
        "shebang_languages": {
            absolute_by_path[path]: shebang_by_path.get(path, extension_by_path.get(path))
            for path, language in eligible
            if not _filename_known_to_runtime(path, extensions)
        },
        "additional_languages": {
            absolute_by_path[path]: shebang_by_path[path]
            for path, language in eligible
            if path in extension_by_path and path in shebang_by_path
            and extension_by_path[path] != shebang_by_path[path]
            and _filename_known_to_runtime(path, extensions)
            and language == shebang_by_path[path]
        },
        "pinned": frozenset(pinned_languages),
        "sources": sources,
        "unresolved": tuple(unresolved),
        "ignored_target_configs": tuple(ignored_target_configs),
        "resolved_optional": tuple(resolved_optional),
        "rules_loaded": True,
        "runtime_version": runtime.get("version"),
    }


def coverage_detail(coverage: dict) -> str:
    """Stable per-language coverage evidence, including unresolved sources."""
    details = []
    unresolved = coverage.get("unresolved", ())
    ignored = coverage.get("ignored_target_configs", ())
    uncovered = []
    for language in sorted(coverage.get("detected", ())):
        language_sources = coverage.get("sources", {}).get(language, ())
        if language_sources:
            for source in language_sources:
                noun = "rule" if source["count"] == 1 else "rules"
                details.append(
                    f"SAST: {language} covered by {source['source']} "
                    f"({source['count']} {noun})"
                )
        if language in coverage.get("uncovered", ()) or not language_sources:
            uncovered.append(f"SAST: NO COVERAGE ({language})")
    if unresolved:
        details.append("unresolved: " + ", ".join(unresolved))
    if ignored:
        details.append("ignored scanned-target config: " + ", ".join(ignored))
    if uncovered:
        # Named gaps stay at the end in the stable grammar consumed by the
        # fail-closed exit gate. Evidence may precede them, never follow them.
        details.append(", ".join(uncovered))
    return "; ".join(details)


def no_coverage_detail(languages) -> str:
    """Compatibility formatter for callers without source-resolution evidence."""
    return "; ".join(f"SAST: NO COVERAGE ({name})" for name in sorted(languages))


def count_code_files(scan_files, bundled_rules: str = None) -> int:
    """Count files eligible under the pinned bundled ruleset.

    This is a compatibility API used by downstream receipt adapters, not a
    second eligibility authority.  Source and vendored layouts both keep the
    rules directory beside ``scripts``; the CLI passes its already-resolved
    installed rules path explicitly.
    """
    if bundled_rules is None:
        bundled_rules = _default_bundled_rules_path()
    return language_coverage(scan_files, bundled_rules)["eligible_files"]


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


def _bundled_rule_languages(path: str) -> dict:
    """Known bundled rule IDs for conservative cross-parser filtering."""
    try:
        import yaml
        with open(path, encoding="utf-8") as source:
            document = yaml.safe_load(source)
    except (ImportError, OSError, UnicodeError, ValueError):
        return {}
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        return {}
    languages = {}
    for rule in document["rules"]:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            return {}
        ids = rule.get("languages")
        if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
            return {}
        rid = rule["id"]
        if rid in languages:
            return {}
        languages[rid] = frozenset(item.lower() for item in ids)
    return languages


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
    """Return {mode, prefix, available, detail, version}. mode is native|wsl|docker|none.

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
                return {"mode": "native", "prefix": [exe], "available": True,
                        "detail": detail, "version": detail.removeprefix("semgrep ")}
            why.append(f"native semgrep at {exe} {detail}")
        else:
            why.append("no semgrep on PATH")
        if prefer == "native":
            return {"mode": "none", "prefix": [], "available": False,
                    "detail": "; ".join(why), "version": None}

    if prefer in ("wsl", "auto") and shutil.which("wsl"):
        exe = _wsl_semgrep_path(wsl_distro)
        if exe:
            prefix = ["wsl", "-d", wsl_distro, exe]
            ok, detail = _probe_semgrep(prefix)
            if ok:
                return {"mode": "wsl", "prefix": prefix, "available": True,
                        "detail": f"{detail} (wsl:{wsl_distro})",
                        "version": detail.removeprefix("semgrep ")}
            why.append(f"wsl:{wsl_distro} semgrep at {exe} {detail}")
        else:
            why.append(f"no semgrep on the login PATH of wsl:{wsl_distro}")
        if prefer == "wsl":
            return {"mode": "none", "prefix": [], "available": False,
                    "detail": "; ".join(why), "version": None}

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
                    "detail": f"docker (image {_SEMGREP_DOCKER_IMAGE} will be used)",
                    "version": _SEMGREP_VERSION}
        why.append(f"docker CLI present but {reason}")

    return {"mode": "none", "prefix": [], "available": False,
            "detail": "; ".join(why) if why else "no semgrep runtime found (native/WSL/Docker)",
            "version": None}


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
    """Read a single source line; the shared Finding boundary masks known providers."""
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


def _error_type_name(err: dict) -> str:
    """The error_type constructor name, whether semgrep serialized it as a
    bare string (a unit variant, e.g. "Timeout") or as a [name, payload] pair
    (a variant carrying data, e.g. PartialParsing's list of locations)."""
    t = err.get("type") if isinstance(err, dict) else None
    if isinstance(t, list) and t and isinstance(t[0], str):
        return t[0]
    if isinstance(t, str):
        return t
    return ""


def _classify_scan_errors(errors: list) -> str:
    """core.ENGINE_OK / core.ENGINE_PARTIAL_PARSE / core.ENGINE_ERROR, by TYPE.

    🔴 CLASSIFIED ON error_type, NEVER ON level. An earlier version of this
    classifier filtered on `level` alone and was proven exploitable: Timeout,
    OutOfMemory, StackOverflow and FixpointTimeout all report `level: warn`,
    identically to PartialParsing, so a slow or obfuscated function could hide
    behind the one status meant only for "some source didn't parse."

    Fails toward ENGINE_ERROR: only an errors list containing ONE OR MORE
    PartialParsing entries and NOTHING ELSE downgrades. A single non-
    PartialParsing entry anywhere in the list -- a known hard-failure type, or
    an unrecognised future one -- forces ENGINE_ERROR for the whole run. An
    adversarial file cannot bury a real timeout behind a see-nothing partial
    parse; the harsher classification wins.
    """
    if not errors:
        return ENGINE_OK
    names = {_error_type_name(e) for e in errors}
    if names == {"PartialParsing"}:
        return ENGINE_PARTIAL_PARSE
    return ENGINE_ERROR


def run(target: str, bundled_rules: str, use_registry: bool = True,
        extra_configs=None, prefer: str = "auto", wsl_distro: str = "Ubuntu",
        timeout: int = _SEMGREP_TIMEOUT, excludes=None,
        enumerated_code_files: int = -1, skip_dirs=None,
        shebang_targets=(), shebang_languages=None, eligible_paths=(),
        additional_languages=None) -> dict:
    """
    Returns {findings: [...],
             status: 'ok'|'unavailable'|'error'|'partial-parse', detail: str,
             runtime: str}. 'partial-parse' is SAST-specific -- see
             core.ENGINE_PARTIAL_PARSE and _classify_scan_errors below.
    """
    rt = detect_runtime(prefer, wsl_distro)
    if not rt["available"]:
        return {"findings": [], "status": "unavailable", "detail": rt["detail"], "runtime": "none"}

    configs = []
    if bundled_rules and os.path.exists(bundled_rules):
        configs.append(_normalized_config_source(bundled_rules, force_local=True))
    if use_registry:
        configs.extend(_normalized_config_source(c) for c in DEFAULT_REGISTRY_CONFIGS)
    configs.extend(_normalized_config_source(c) for c in (extra_configs or []))
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
              _SEMGREPIGNORE_OFF, _DISABLE_NOSEM]
    # 🔴 `--exclude` IS DOCUMENTED AND IMPLEMENTED AS REGEX EVERYWHERE ELSE IN
    # THIS TOOL -- `core.walk_files()` and `engine_sca.py` both compile it with
    # `re.compile()` and match with `.search()` against a relative path.
    # Semgrep's OWN `--exclude` flag is a glob, not a regex. This function used
    # to forward the same strings straight through to semgrep's flag, on the
    # claim that doing so "honors the same exclusions as the built-in engines."
    # It does not: a regex like `test_.*\.py$` is a valid glob only by
    # coincidence, and most real patterns (anchors, alternation, char classes)
    # either match nothing under glob semantics or match something unintended
    # -- silently. That is a scope disagreement between SAST and the other
    # three engines on every scan that passes a nontrivial `--exclude`, which
    # is exactly the failure class the `.gitignore`/`.semgrepignore` comments
    # above this one exist to prevent for a different cause.
    #
    # Fix: never ask semgrep to interpret PRAETOR's regex. Let it scan
    # normally (still excluding DEFAULT_SKIP_DIRS below, which are literal
    # directory names -- glob and regex agree on those), then drop matching
    # results ourselves below, with the SAME predicate `core.walk_files()`
    # uses, against the SAME relative-path form. Cost: semgrep spends time
    # analysing files the operator excluded rather than skipping them at
    # open-time. Correctness of scope outranks that; a future optimisation
    # could pass an explicit `--include` file list instead, but that risks an
    # argv-length regression on very large trees and is not this fix.
    exclude_rxs = [re.compile(p) for p in (excludes or [])]

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

    # Semgrep's folder walk does not admit extensionless scripts by shebang.
    # Its explicit-target override opens them without executing their contents.
    # The paths come only from PRAETOR's own already-admitted walker.
    if shebang_targets:
        common.append("--scan-unknown-extensions")

    if mode == "native":
        cfg_args = []
        for c in configs:
            cfg_args += ["--config", c]
        cmd = rt["prefix"] + cfg_args + common + [os.path.abspath(target)] + list(shebang_targets)
        cwd = None
    elif mode == "wsl":
        wt = _win_to_wsl(target)
        cfg_args = []
        for c in configs:
            cfg_args += ["--config", (_win_to_wsl(c) if _is_local_config_source(c) else c)]
        cmd = rt["prefix"] + cfg_args + common + [wt] + [
            _win_to_wsl(path) for path in shebang_targets]
        cwd = None
    else:  # docker
        tgt = os.path.abspath(target)
        cfg_args = []
        config_vols = []
        for c in configs:
            if _is_local_config_source(c) and os.path.exists(c):
                _source, config_target, binding = _docker_local_config_mount(c)
                config_vols += ["-v", binding]
                cfg_args += ["--config", config_target]
            else:
                cfg_args += ["--config", c]
        vols = ["-v", f"{tgt}:/src:ro"]
        cmd = ["docker", "run", "--rm", "--network", "host"] + vols + config_vols + \
              [_SEMGREP_DOCKER_IMAGE, "semgrep"] + cfg_args + common + ["/src"] + [
                  "/src/" + os.path.relpath(path, tgt).replace("\\", "/")
                  for path in shebang_targets]
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
    rejected_flag = None
    err_text = (r.stderr or "")
    if r.returncode not in (0, 1) and "unknown option" in err_text:
        rejected_flag = next((flag for flag in _RETRYABLE_FLAGS if flag in err_text), None)
    if rejected_flag:
        retry_cmd = list(cmd)
        retry_cmd.remove(rejected_flag)
        r, failed = _invoke(retry_cmd)
        if failed:
            return failed
        semgrepignore_off = rejected_flag != _SEMGREPIGNORE_OFF

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
        stale = ("" if rejected_flag != _SEMGREPIGNORE_OFF else
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
    scanned_relpaths = {
        _relative_to_report_root(path, report_root)
        for path in data.get("paths", {}).get("scanned", [])
        if isinstance(path, str)
    }
    missing_paths = sorted(set(eligible_paths) - scanned_relpaths)
    for rel in missing_paths:
        findings.append(Finding(
            engine="sast", rule_id="sast-file-not-scanned",
            title="SAST eligible file was not scanned",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            file=rel, line=1, category="COVERAGE",
            description="PRAETOR selected this file for SAST, but Semgrep did not report opening it.",
            snippet="", fix="Inspect Semgrep target admission and rerun before trusting this scan.",
        ))
    shebang_by_relpath = {
        os.path.relpath(path, os.path.abspath(target)).replace("\\", "/"): language
        for path, language in (shebang_languages or {}).items()
    }
    bundled_language_ids = (_bundled_rule_languages(bundled_rules)
                            if shebang_by_relpath else {})
    line_cache: dict = {}
    for res in data.get("results", []):
        extra = res.get("extra", {}) or {}
        md = extra.get("metadata", {}) or {}
        raw_path = res.get("path", "")
        rel = _relative_to_report_root(raw_path, report_root)
        if any(rx.search(rel) for rx in exclude_rxs):
            continue
        rid = res.get("check_id", "semgrep-rule")
        short = rid.split(".")[-1]
        declared = bundled_language_ids.get(short)
        if rel in shebang_by_relpath and declared is not None:
            expected = SAST_LANGUAGE_ALIASES.get(shebang_by_relpath[rel], frozenset())
            # A case-divergent suffix is unknown to Semgrep's filename walk,
            # so it is passed explicitly and parsed under every config. Its
            # suffix still identifies real source to our walker: retain a
            # Semgrep finding for either that language or the shebang language.
            expected = expected | SAST_LANGUAGE_ALIASES.get(
                core.source_language(rel), frozenset())
            if not declared.intersection(expected):
                # Explicit unknown-extension targets are parsed under every
                # config language. Drop only a provably different bundled
                # parser; unknown/operator rules remain visible, fail safe.
                continue
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
    scan_errors = data.get("errors", []) or []
    n_errors = len(scan_errors)
    error_status = _classify_scan_errors(scan_errors)
    if missing_paths:
        error_status = ENGINE_ERROR
    opened = f"Semgrep opened {scanned} file(s)" if scanned >= 0 else "Semgrep opened file count unavailable"
    detail = (f"{rt['detail']}; ran configs={configs}; scan errors={n_errors}; "
              f"{opened}")
    if missing_paths:
        detail += f"; {len(missing_paths)} eligible file(s) not scanned"
    if n_errors:
        # 🔴 A COUNT, NOT A STATUS ON ITS OWN. `scan errors=N` used to sit in
        # `detail` next to an unconditional `status: "ok"` -- printed,
        # gate-trusted, and never read. Semgrep can return valid JSON and a
        # positive file count while admitting it could not parse or analyse
        # specific files (a NUL-bearing source, a syntax error in an unrelated
        # dialect, a truncated read, a timeout); a non-empty findings list
        # proves SOME files were measured, not that every opened file was.
        if error_status == ENGINE_PARTIAL_PARSE:
            detail += ("; ALL reported errors are PartialParsing -- some source could not "
                       "be parsed, the rest was scanned; --fail-on still refuses to certify "
                       "this clean (see core.GATE_TRUSTED_STATUSES)")
        else:
            detail += ("; Semgrep reported file/analysis errors -- "
                       "SAST coverage cannot be certified")
    if rejected_flag:
        # Visible, not silent: this semgrep did not accept the flag, so the
        # scanned tree's own `.semgrepignore` was honoured on this run. Status
        # stays "ok" here DELIBERATELY -- this branch used to be `error` on
        # every scan against an older semgrep, unconditionally, which is the
        # regression `test_a_semgrep_that_rejects_the_flag_does_not_break_every_scan`
        # exists to pin. The scope guard above still applies and catches the
        # dangerous case (a .semgrepignore hiding EVERYTHING, so semgrep opens
        # zero files); a partial hide agrees with PRAETOR's count and is
        # reported here, visibly, rather than blocking every caller on an old
        # semgrep binary for a risk the scope guard already covers.
        if rejected_flag == _SEMGREPIGNORE_OFF:
            detail += (f"; NOTE this semgrep rejected {rejected_flag}; retry omitted exactly "
                       "that flag, so the target's own .semgrepignore was honoured -- "
                       "upgrade semgrep for full protection")
        else:
            detail += (f"; NOTE this semgrep rejected {rejected_flag}; retry omitted exactly "
                       "that flag -- upgrade semgrep for full protection")
    # Semgrep's parser follows a known suffix even for an explicit target.
    # Scan a disposable unknown-suffix copy under the additional shebang
    # language, then map its findings back to the original file. The target
    # remains read-only; a failed copy or scan is an active HIGH coverage gap.
    for source_path, language in (additional_languages or {}).items():
        rel = os.path.relpath(source_path, os.path.abspath(target)).replace("\\", "/")
        try:
            with tempfile.TemporaryDirectory(prefix="praetor-sast-language-") as spare:
                alias = os.path.join(spare, "source.__praetor_unknown__")
                shutil.copyfile(source_path, alias)
                extra = run(
                    spare, bundled_rules, use_registry=use_registry,
                    extra_configs=extra_configs, prefer=prefer,
                    wsl_distro=wsl_distro, timeout=timeout,
                    skip_dirs=skip_dirs, enumerated_code_files=1,
                    shebang_targets=(alias,), shebang_languages={alias: language},
                    eligible_paths=(os.path.basename(alias),),
                )
        except OSError as exc:
            extra = {"status": ENGINE_ERROR, "detail": str(exc), "findings": [],
                     "scanned_file_count": 0}
        if extra["status"] != ENGINE_OK or extra.get("scanned_file_count") != 1:
            findings.append(Finding(
                engine="sast", rule_id="sast-file-not-scanned",
                title="SAST language was not scanned", severity=Severity.HIGH,
                confidence=Confidence.HIGH, file=rel, line=1,
                category="COVERAGE", description=(
                    f"The {language} shebang parser was not verified: {extra['detail']}"),
                snippet="", fix="Inspect Semgrep target admission and rerun.",
            ))
            error_status = ENGINE_ERROR
            detail += f"; {language} parser not verified for {rel}"
        else:
            for finding in extra["findings"]:
                finding.file = rel
                findings.append(finding)
    return {"findings": findings, "status": error_status, "detail": detail,
            "runtime": mode, "version": rt.get("version"),
            "scanned_file_count": scanned}
