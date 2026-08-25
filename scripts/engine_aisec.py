"""
PRAETOR AI-security / agent-supply-chain engine (pure standard library).

This is PRAETOR's differentiator. It targets the attack surface a self-improving
agent or an LLM-in-the-loop pipeline actually faces -- threats that classic SAST
and secret scanners do not model:

  A. PROMPT INJECTION      instruction-override phrasing, role/authority hijacks,
                           agent-directed imperatives hidden in docs/data.
  B. HIDDEN CONTENT        zero-width / invisible Unicode, Unicode-Tags ASCII
                           smuggling (U+E0000..E007F), bidirectional "Trojan
                           Source" controls, instruction-bearing HTML comments.
  C. DATA EXFILTRATION     curl|sh install pipes, reads of ~/.aws /~/.ssh/.env,
                           env dumps POSTed to external hosts, base64|curl.
  D. DANGEROUS HOOKS       auto-run agent hooks -- Claude Code
                           (SessionStart/PostToolUse/...), Cursor
                           (beforeShellExecution/afterFileEdit/...), Windsurf,
                           Cline/Roo -- plus git hooks and npm/pip lifecycle
                           scripts that execute on load or install.
  E. SAFETY BYPASS         instructions telling an agent to disable safety,
                           auto-approve, skip review, or escalate privileges.

Mapped to the OWASP Top 10 for LLM Applications and to CWE where applicable.
"""

from __future__ import annotations

import json
import os
import re
import unicodedata

from core import Finding, Severity, Confidence, split_lines, GIT_HOOK_NAMES

REF_LLM = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
REF_TROJAN = "https://trojansource.codes/"

# --------------------------------------------------------------------------- #
# B. Hidden / invisible Unicode
# --------------------------------------------------------------------------- #

# zero-width & invisible formatting characters
INVISIBLE = {
    0x200B: "ZERO WIDTH SPACE", 0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER", 0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE / BOM", 0x00AD: "SOFT HYPHEN",
    0x180E: "MONGOLIAN VOWEL SEPARATOR", 0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES", 0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS", 0x206A: "INHIBIT SYMMETRIC SWAPPING",
    0x206B: "ACTIVATE SYMMETRIC SWAPPING", 0x206C: "INHIBIT ARABIC FORM SHAPING",
    0x206E: "NATIONAL DIGIT SHAPES", 0x206F: "NOMINAL DIGIT SHAPES",
}

# bidirectional controls used by Trojan Source attacks (CVE-2021-42574)
BIDI = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING", 0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING", 0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE", 0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE", 0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
}


def _tag_char(cp: int) -> bool:
    # Unicode Tags block: invisible, can smuggle a full ASCII payload past a human.
    return 0xE0000 <= cp <= 0xE007F


def _scan_unicode(text: str, rel: str) -> list:
    out: list = []
    line_no = 1
    inv_hits, bidi_hits, tag_hits = {}, {}, 0
    tag_first_line = None
    for ch in text:
        cp = ord(ch)
        if ch == "\n":
            line_no += 1
            continue
        if _tag_char(cp):
            tag_hits += 1
            if tag_first_line is None:
                tag_first_line = line_no
        elif cp in BIDI:
            bidi_hits.setdefault(line_no, BIDI[cp])
        elif cp in INVISIBLE:
            inv_hits.setdefault(line_no, INVISIBLE[cp])

    if tag_hits:
        out.append(Finding(
            engine="aisec", rule_id="unicode-tag-smuggling",
            title="Invisible Unicode Tag characters (ASCII smuggling)",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            file=rel, line=tag_first_line or 1, category="HIDDEN_CONTENT",
            description=(f"{tag_hits} Unicode Tag code point(s) (U+E0000-E007F) found. These are "
                        "invisible to humans and are a known channel for smuggling hidden "
                        "instructions into an LLM's context."),
            snippet=f"{tag_hits} invisible tag character(s)",
            fix="Strip Tag-block characters from all model-facing text; treat their presence as hostile.",
            cwe="CWE-1007", owasp="LLM01: Prompt Injection", references=[REF_LLM],
        ))
    for ln, name in list(bidi_hits.items())[:20]:
        out.append(Finding(
            engine="aisec", rule_id="bidi-control-trojan-source",
            title="Bidirectional control character (Trojan Source)",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            file=rel, line=ln, category="HIDDEN_CONTENT",
            description=(f"Bidi control '{name}' can make source/text render differently than it "
                        "is parsed, hiding logic from a human reviewer (CVE-2021-42574)."),
            snippet=f"contains {name}",
            fix="Remove bidirectional overrides/isolates from source and model-facing text.",
            cwe="CWE-1007", owasp="LLM01: Prompt Injection",
            references=[REF_TROJAN, "https://cwe.mitre.org/data/definitions/1007.html"],
        ))
    for ln, name in list(inv_hits.items())[:20]:
        out.append(Finding(
            engine="aisec", rule_id="invisible-unicode",
            title="Invisible / zero-width Unicode character",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            file=rel, line=ln, category="HIDDEN_CONTENT",
            description=(f"Zero-width/invisible character '{name}' can hide text from human "
                        "reviewers while remaining in the model's input."),
            snippet=f"contains {name}",
            fix="Normalize and strip zero-width characters from model-facing content.",
            cwe="CWE-1007", owasp="LLM01: Prompt Injection", references=[REF_LLM],
        ))
    return out


# --------------------------------------------------------------------------- #
# B (cont). Homoglyphs / confusables -- MIXED SCRIPT WITHIN ONE TOKEN
# --------------------------------------------------------------------------- #
# The sibling detectors above catch characters that are INVISIBLE. This one
# catches characters that are VISIBLE and look like something they are not:
# Cyrillic U+0430 renders identically to Latin "a", so "p<U+0430>ypal" and "paypal"
# are indistinguishable to a human reviewer and different strings to every machine.
#
# 📌 Note the notation. This comment SPELLS OUT the code point instead of pasting
# the character, and that is not fussiness: an earlier draft pasted it, and this
# detector then flagged its own explanation -- correctly. A literal lookalike in
# prose about lookalikes is unreviewable by construction.
#
# 🔴 THE SCOPE DECISION IS THE WHOLE DETECTOR, and getting it wrong in the
# obvious direction would make this unusable:
#
#   FIRE on   a token that mixes Latin WITH a confusable script  -- "p<U+0430>ypal"
#   NEVER on  a token written wholly in another script           -- `Привет`
#
# A Russian README is not an attack. "Contains non-ASCII" would flag every
# non-English document in the world, and a detector that cries wolf on ordinary
# prose gets disabled, which is a worse outcome than not shipping it. The attack
# signature is the MIXTURE inside a single word -- nobody writes one word half in
# Latin and half in Cyrillic by accident.
#
# ⚠️ This is necessarily incomplete: a wholly-Cyrillic string that mimics a Latin
# one (`расс` for `pacc`) has no mixture to detect and is NOT caught here. Stated
# rather than implied -- absence of this finding is not evidence of authenticity.

# Scripts with characters visually confusable with Latin. Deliberately short:
# every entry here is a script whose lookalikes are used in real attacks.
_CONFUSABLE_SCRIPTS = frozenset({"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"})

# Unicode letters only -- \W with re.UNICODE excludes digits and underscore.
_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)


def _script_of(ch: str) -> str:
    """Derive a character's script from its Unicode name prefix.

    Uses `unicodedata` rather than a bundled confusables table so this stays
    stdlib-only, which the whole aisec engine depends on.
    """
    if ch.isascii():
        return "LATIN"
    try:
        return unicodedata.name(ch).split(" ", 1)[0]
    except ValueError:      # unnamed / private-use code point
        return "UNKNOWN"


def _scan_homoglyphs(text: str, rel: str) -> list:
    out: list = []
    skipped = 0
    # split_lines, not str.splitlines: `_scan_unicode` counts \n, and two
    # detectors in one engine must not disagree about what a line is.
    for ln, line in enumerate(split_lines(text), start=1):
        # Fast path AND a correctness statement: a mixed-script token requires at
        # least one non-ASCII character, so an all-ASCII line cannot contain one.
        if len(line) > 6000:
            skipped += 1
            continue
        if line.isascii():
            continue
        for tok in _WORD_RE.findall(line):
            if tok.isascii():
                continue
            scripts = {_script_of(c) for c in tok}
            if "LATIN" not in scripts:
                continue            # wholly non-Latin: ordinary foreign text
            confusable = sorted(scripts & _CONFUSABLE_SCRIPTS)
            if not confusable:
                continue            # e.g. Latin + accents, or Latin + CJK: not a lookalike
            # Name the offending code points explicitly -- the whole problem is
            # that a reviewer CANNOT see them by looking.
            odd = ", ".join(
                f"U+{ord(c):04X} {unicodedata.name(c, '?')}"
                for c in dict.fromkeys(c for c in tok if _script_of(c) in _CONFUSABLE_SCRIPTS)
            )
            out.append(Finding(
                engine="aisec", rule_id="homoglyph-mixed-script",
                title="Mixed-script token (homoglyph / confusable characters)",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                file=rel, line=ln, category="HIDDEN_CONTENT",
                description=(
                    f"The token '{tok}' mixes Latin with {', '.join(confusable)} characters that "
                    "render identically to Latin letters. A human reviewer cannot distinguish it "
                    "from the legitimate spelling, while every string comparison, allowlist and "
                    "URL resolver treats it as a different value. Offending code point(s): "
                    + odd + "."
                ),
                snippet=f"{tok}  [{odd}]",
                fix=("Normalise model-facing and security-relevant text to a single script; reject "
                     "mixed-script identifiers, domains and package names outright."),
                cwe="CWE-1007", owasp="LLM01: Prompt Injection",
                references=[REF_LLM, "https://www.unicode.org/reports/tr39/"],
            ))
            if len(out) >= 20:
                break
    if skipped:
        out.append(Finding(
            engine="aisec", rule_id="aisec-long-line-skip",
            title="AI-security coverage limited by long line",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            file=rel, line=1, category="COVERAGE",
            description=f"{skipped} line(s) exceeded the 6000-character analysis cap and were skipped by homoglyph scanning.",
            snippet=f"skipped_lines={skipped}; cap=6000",
            fix="Split oversized lines before scanning to restore full AI-security coverage.",
            references=[REF_LLM],
        ))
    return out


# --------------------------------------------------------------------------- #
# A. Prompt injection  /  E. Safety bypass   (regex, per line)
# --------------------------------------------------------------------------- #
# (rule_id, title, regex, severity, confidence, category, cwe, owasp, fix)

INJECTION = [
    ("prompt-injection-override", "Instruction-override phrasing",
     re.compile(r"(?i)\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(all\s+)?(previous|prior|above|earlier|the\s+system|your)\b[^.\n]{0,20}\b(instruction|prompt|rule|direction|context)"),
     Severity.HIGH, Confidence.MEDIUM, "PROMPT_INJECTION", "CWE-77", "LLM01: Prompt Injection",
     "Treat this text as untrusted data, not instructions; do not let file content steer the agent."),

    ("prompt-injection-new-instructions", "Injected 'new instructions' block",
     re.compile(r"(?i)\b(new|updated|revised|real|actual)\s+(instruction|system\s+prompt|directive|task)s?\s*[:\-]"),
     Severity.MEDIUM, Confidence.LOW, "PROMPT_INJECTION", "CWE-77", "LLM01: Prompt Injection",
     "Do not follow instructions embedded in scanned/tool-returned content."),

    ("prompt-injection-role-hijack", "Role/authority hijack",
     re.compile(r"(?i)\b(you\s+are\s+now|from\s+now\s+on\s+you|act\s+as\s+(an?\s+)?(unrestricted|jailbroken|dan|developer\s+mode)|do\s+anything\s+now|pretend\s+you\s+have\s+no\s+(rules|restrictions))\b"),
     Severity.HIGH, Confidence.MEDIUM, "PROMPT_INJECTION", "CWE-77", "LLM01: Prompt Injection",
     "Reject role-reassignment attempts originating from data/content."),

    ("prompt-injection-system-role", "Fake system/assistant role marker in data",
     re.compile(r"(?im)^\s*(?:<\|?(system|assistant)\|?>|\[/?(system|inst)\]|###\s*system\s*:|system\s+prompt\s*:)"),
     Severity.MEDIUM, Confidence.LOW, "PROMPT_INJECTION", "CWE-77", "LLM01: Prompt Injection",
     "Strip chat-role delimiters from untrusted content before it reaches a model."),

    ("agent-directed-imperative", "Agent-directed imperative in content",
     re.compile(r"(?i)\b(assistant|claude|chatgpt|gpt|copilot|the\s+ai|the\s+agent|the\s+model)\s*,?\s+(please\s+)?(run|execute|curl|wget|send|email|forward|delete|exfiltrate|post|upload|fetch|disable|ignore)\b"),
     Severity.HIGH, Confidence.MEDIUM, "PROMPT_INJECTION", "CWE-77", "LLM01: Prompt Injection",
     "Content that addresses the agent by name and issues commands is a hostile-injection signal."),

    ("safety-bypass-instruction", "Instruction to disable safety / auto-approve",
     re.compile(r"(?i)\b(auto[\-\s]?approve|disable\s+(the\s+)?(safety|guard|guardrail|confirmation|sandbox|protection)|bypass\s+(the\s+)?(gate|approval|permission|review|check)|skip\s+(the\s+)?(review|audit|confirmation|approval|permission)|without\s+(asking|confirmation|approval|human)|no\s+confirmation\s+needed)\b"),
     Severity.HIGH, Confidence.MEDIUM, "SAFETY_BYPASS", "CWE-807", "LLM01: Prompt Injection",
     "An agent instruction that removes human approval or safety checks; require review before honoring it."),

    ("dangerous-permission-flag", "Dangerous agent/CLI permission flag",
     re.compile(r"(?i)(--dangerously-skip-permissions|--yes-really|--no-verify\b|--disable-sandbox|--allow-all|acceptAll|autoApprove\s*[:=]\s*true)"),
     Severity.HIGH, Confidence.MEDIUM, "SAFETY_BYPASS", "CWE-250", "LLM01: Prompt Injection",
     "Flags that skip permission prompts or verification should never be baked into shared config."),

    ("privilege-escalation", "Privilege escalation / world-writable",
     re.compile(r"(?i)\b(sudo\s+\S|chmod\s+777|chmod\s+-R\s+777|run\s+as\s+root|setuid)\b"),
     Severity.MEDIUM, Confidence.LOW, "SAFETY_BYPASS", "CWE-250", "LLM01: Prompt Injection",
     "Avoid privilege escalation and world-writable permissions in automation."),
]

# --------------------------------------------------------------------------- #
# C. Data exfiltration
# --------------------------------------------------------------------------- #

EXFIL = [
    ("remote-code-pipe", "Remote code execution via curl|sh",
     re.compile(r"(?i)\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*|node|pwsh|powershell)\b"),
     Severity.HIGH, Confidence.HIGH, "EXFIL", "CWE-494", "LLM05: Supply Chain",
     "Never pipe a remote script straight into a shell; download, review, pin a checksum, then run."),

    ("powershell-download-exec", "PowerShell download-and-execute",
     re.compile(r"(?i)(Invoke-Expression|iex)\b[^\n]{0,80}(Invoke-WebRequest|iwr|DownloadString|Net\.WebClient)"),
     Severity.HIGH, Confidence.HIGH, "EXFIL", "CWE-494", "LLM05: Supply Chain",
     "Do not execute downloaded content; fetch, inspect, and verify before running."),

    ("sensitive-file-read", "Read of sensitive credential path",
     re.compile(r"(?i)(~|\$HOME|%USERPROFILE%)?[/\\]?\.(aws/credentials|ssh/id_[a-z0-9]+|ssh/id_rsa|netrc|npmrc|docker/config\.json|kube/config|config/gcloud|gnupg)\b|\bid_rsa\b"),
     Severity.MEDIUM, Confidence.LOW, "EXFIL", "CWE-200", "LLM06: Sensitive Information Disclosure",
     "Confirm why credential files are accessed; agents/scripts should not read ~/.aws, ~/.ssh, etc."),

    ("env-exfil", "Environment dump sent to network",
     re.compile(r"(?i)\b(printenv|env\b|os\.environ|process\.env|Get-ChildItem\s+env:)[^\n]{0,120}\b(curl|wget|fetch|requests\.(post|get)|Invoke-WebRequest|http\.client|axios|urllib)\b"),
     Severity.HIGH, Confidence.MEDIUM, "EXFIL", "CWE-200", "LLM06: Sensitive Information Disclosure",
     "Sending environment variables to a network endpoint is a classic secret-exfiltration pattern."),

    ("base64-exfil", "Base64-encoded data piped to network",
     re.compile(r"(?i)\bbase64\b[^\n|]{0,60}\|[^\n]{0,60}\b(curl|wget|nc|ncat)\b"),
     Severity.HIGH, Confidence.MEDIUM, "EXFIL", "CWE-200", "LLM06: Sensitive Information Disclosure",
     "Base64+network piping is often used to obfuscate exfiltrated data."),

    ("dns-exfil", "Possible DNS exfiltration",
     re.compile(r"(?i)\b(nslookup|dig|host)\b[^\n]{0,60}\$\(|\bcurl\b[^\n]{0,60}\.(?:oast|burpcollaborator|interact\.sh|requestbin)\b"),
     Severity.MEDIUM, Confidence.LOW, "EXFIL", "CWE-200", "LLM06: Sensitive Information Disclosure",
     "Dynamic hostname lookups can smuggle data out over DNS; verify the destination."),
]

# --------------------------------------------------------------------------- #
# D. Dangerous hooks & supply-chain lifecycle scripts
# --------------------------------------------------------------------------- #

# Agent hook-event names across vendors. A hostile hook config is the same attack
# whichever assistant loads it, so this must not be one vendor's vocabulary.
#
# ⚠️ The case-insensitive flag is doing less work than it looks like it is. It
# makes Cursor's `preToolUse` / `postToolUse` match Claude's spellings for free,
# which is why a path-only fix appeared to work -- but `beforeShellExecution`,
# `afterFileEdit` and `beforeSubmitPrompt` are Cursor-native names with no Claude
# counterpart, so a config using only those stayed invisible. Measured against a
# real `~/.cursor/hooks.json` wiring six auto-run commands: zero findings.
AGENT_HOOK_EVENTS = re.compile(
    r"(?i)\b("
    # Claude Code
    r"SessionStart|SessionEnd|PostToolUse|PreToolUse|UserPromptSubmit|Stop|SubagentStop|PreCompact|Notification"
    # Cursor
    r"|beforeShellExecution|beforeReadFile|afterFileEdit|beforeSubmitPrompt|beforeMCPExecution|stop"
    # Windsurf / Codeium, Cline / Roo
    r"|onFileEdit|onCommandRun|preCommand|postCommand"
    r")\b"
)
# Retained under the old name: this module is imported by tests and tools that
# reference it. Renaming without an alias is a silent break for any consumer.
CC_HOOK_EVENTS = AGENT_HOOK_EVENTS

# Directory prefixes and filenames that indicate an AGENT hook/settings config.
# 🔴 Every Claude-specific entry STAYS. Detecting Claude formats was never the
# defect -- detecting ONLY them was.
AGENT_CONFIG_DIRS = (".claude/", ".cursor/", ".windsurf/", ".codeium/", ".roo/", ".cline/", ".gemini/")
AGENT_CONFIG_NAMES = ("settings.json", "settings.local.json", "hooks.json",
                      "cline_settings.json", "windsurf_settings.json")


def _is_agent_hook_config(low_rel: str, base: str) -> bool:
    """True when this path is an agent's hook/settings config, for ANY vendor."""
    if base in AGENT_CONFIG_NAMES:
        return True
    padded = "/" + low_rel
    return any(d in padded or low_rel.startswith(d) for d in AGENT_CONFIG_DIRS)
# ⚠️ GIT_HOOK_NAMES comes from `core` -- the SAME set the walker uses to decide
# what to open. It used to be a 9-name copy here, survivable only because the
# path predicate also fired on *any* directory called `hooks/`, which quietly
# covered `commit-msg`, `pre-receive`, `update` and the rest. That broad clause
# is gone (it was matching agent/plugin hook directories -- see `_is_git_hook`),
# so completeness is now load-bearing, and a second copy would rot.
NPM_LIFECYCLE = re.compile(r"(?i)\"(preinstall|install|postinstall|prepare|prepublish)\"\s*:\s*\"([^\"]+)\"")

# Evidence for `git-hook-network-exec`, split so the rule cannot fire without the
# thing its own name asserts.
#
# 🔴 It previously fired on a single regex that included `python -c`, `node -e`,
# `base64` and `powershell` -- so `if python3 -c 'import sys'` inside a Claude
# Code plugin's `hooks/` directory produced a HIGH "Git hook performs network/exec
# on a git event": not a git hook, no network, no exec of fetched content. The
# rule's NAME asserted evidence its predicate never required, which is this
# project's own recurring defect class aimed back at itself.
# ⚠️ TWO EVIDENCE BARS, DELIBERATELY DIFFERENT -- do not "unify" them.
#
# `EXEC_IN_HOOK` (broad) serves `agent-hook-autorun-dangerous`, whose claim is
# "this command performs network/exec/ENCODING operations" on an assistant event.
# For that rule a bare `python -c` genuinely is the risk: an agent hook config
# auto-runs it at load time, from a file an attacker may have supplied.
#
# `NETWORK_IN_HOOK` / `OPAQUE_EXEC_IN_HOOK` (narrow) serve `git-hook-network-exec`,
# whose claim is specifically network access or execution of fetched content on a
# git operation. Reusing the broad pattern there is what produced the false
# positive: the rule's name asserted evidence its predicate never required.
#
# The lesson generalises past these two rules: the evidence bar belongs to the
# CLAIM, not to the file. One shared regex serving two different claims will
# always over-fire for the narrower one.
EXEC_IN_HOOK = re.compile(
    r"(?i)(curl|wget|Invoke-WebRequest|iwr|nc\b|bash\s+-c|sh\s+-c|eval\b|base64\b|node\s+-e|python[0-9.]*\s+-c|powershell)"
)

NETWORK_IN_HOOK = re.compile(
    r"(?i)(\b(curl|wget|Invoke-WebRequest|iwr|ncat|telnet)\b|\bnc\s+-|/dev/tcp/)"
)
# Executing content the hook did not author: piping into an interpreter, `eval`,
# PowerShell's `iex`, or decoding a blob to run it. A bare interpreter call
# (`python3 -c`, `node -e`) is how ordinary hooks work and is NOT this.
OPAQUE_EXEC_IN_HOOK = re.compile(
    r"(?i)(\|\s*(sh|bash|zsh|pwsh|powershell|python[0-9.]*|node)\b|\beval\b|\biex\b"
    r"|base64\s+(-d|-D|--decode))"
)


def _is_git_hook(base: str) -> bool:
    """True only for a file git would really run as a hook.

    Name-based, because that is what git itself honours (in `.git/hooks/` or any
    `core.hooksPath`). A `.sample` is never executed by git, and a plugin's
    `hooks/pre-tool-use.sh` is not a git hook however much its directory looks
    like one.
    """
    if base.endswith(".sample"):
        return False
    stem = base.rsplit(".", 1)[0] if "." in base else base
    return base in GIT_HOOK_NAMES or stem in GIT_HOOK_NAMES


def _scan_hooks(text: str, rel: str) -> list:
    out: list = []
    low_rel = rel.lower()
    base = os.path.basename(low_rel)

    # --- agent hook config (Claude .claude/*, Cursor .cursor/hooks.json, ...) ---
    if _is_agent_hook_config(low_rel, base) and AGENT_HOOK_EVENTS.search(text) and '"command"' in text.lower():
        for m in re.finditer(r"(?i)\"command\"\s*:\s*\"([^\"]+)\"", text):
            cmd = m.group(1)
            ln = text.count("\n", 0, m.start()) + 1
            dangerous = bool(EXEC_IN_HOOK.search(cmd))
            out.append(Finding(
                engine="aisec",
                # ⚠️ BOTH ids renamed together. Renaming only the bare id would have
                # left `claude-hook-autorun-dangerous` behind -- orphaning the HIGH
                # severity variant while the MEDIUM one moved. One ternary, two ids.
                rule_id="agent-hook-autorun-dangerous" if dangerous else "agent-hook-autorun",
                title="Auto-run agent hook executes a shell command"
                      + (" (network/exec)" if dangerous else ""),
                severity=Severity.HIGH if dangerous else Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                file=rel, line=ln, category="DANGEROUS_HOOK",
                description=("An agent hook runs a command automatically on an assistant event. "
                             + ("It performs network/exec/encoding operations -- a strong load-time "
                                "code-execution / exfiltration risk." if dangerous
                                else "Review what it does before trusting this config.")),
                snippet=(cmd[:160] + ("..." if len(cmd) > 160 else "")),
                fix="Audit every auto-run hook command; do not accept hook config from untrusted sources.",
                cwe="CWE-829", owasp="LLM05: Supply Chain", references=[REF_LLM],
            ))

    # --- git hooks: by NAME (what git runs), and only on real evidence ---
    if _is_git_hook(base):
        net = NETWORK_IN_HOOK.search(text)
        opaque = OPAQUE_EXEC_IN_HOOK.search(text)
        m = net or opaque
        if m:
            ln = text.count("\n", 0, m.start()) + 1
            got = [n for n, hit in (("network access", net), ("execution of opaque/fetched content", opaque)) if hit]
            out.append(Finding(
                engine="aisec", rule_id="git-hook-network-exec",
                title="Git hook performs network/exec on a git event",
                severity=Severity.HIGH, confidence=Confidence.LOW,
                file=rel, line=ln, category="DANGEROUS_HOOK",
                # State the evidence actually found, so the reader can tell a
                # fetch-into-shell from an `eval` without opening the file.
                description=(
                    "A git hook runs automatically on git operations and shows "
                    + " and ".join(got) + "."
                ),
                snippet=split_lines(text)[ln - 1].strip()[:160] if ln - 1 < len(split_lines(text)) else "",
                fix="Review committed git hooks; a repo should not ship hooks that curl|sh or eval.",
                cwe="CWE-829", owasp="LLM05: Supply Chain", references=[REF_LLM],
            ))

    # --- npm lifecycle scripts ---
    if base == "package.json":
        for m in NPM_LIFECYCLE.finditer(text):
            phase, cmd = m.group(1), m.group(2)
            ln = text.count("\n", 0, m.start()) + 1
            dangerous = bool(EXEC_IN_HOOK.search(cmd))
            if dangerous:
                out.append(Finding(
                    engine="aisec", rule_id="npm-lifecycle-exec",
                    title=f"npm '{phase}' lifecycle script runs network/exec",
                    severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                    file=rel, line=ln, category="SUPPLY_CHAIN",
                    description=(f"The npm '{phase}' script executes automatically on install and performs "
                                 "network/exec operations -- a common supply-chain compromise vector."),
                    snippet=cmd[:160],
                    fix="Remove install-time network/exec; vet dependencies whose install scripts do this.",
                    cwe="CWE-506", owasp="LLM05: Supply Chain", references=[REF_LLM],
                ))
    return out


# --------------------------------------------------------------------------- #
# HTML comment with instruction-like content (multi-line, markdown/html)
# --------------------------------------------------------------------------- #

HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
COMMENT_SUSPICIOUS = re.compile(
    r"(?i)(ignore|disregard|system\s*:|assistant\s*:|instruction|you\s+are\s+now|run\s+this|execute|curl|password|secret|api[_\-]?key|do\s+not\s+tell)"
)


def _scan_html_comments(text: str, rel: str) -> list:
    out: list = []
    if not rel.lower().endswith((".md", ".markdown", ".mdx", ".mdc", ".html", ".htm", ".rst", ".txt")):
        return out
    for m in HTML_COMMENT.finditer(text):
        body = m.group(1)
        if COMMENT_SUSPICIOUS.search(body):
            ln = text.count("\n", 0, m.start()) + 1
            out.append(Finding(
                engine="aisec", rule_id="hidden-instruction-html-comment",
                title="Instruction-like content hidden in an HTML comment",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                file=rel, line=ln, category="HIDDEN_CONTENT",
                description=("An HTML comment (invisible when rendered) contains instruction- or "
                             "secret-like text -- a prompt-injection channel in docs an agent may read."),
                snippet=re.sub(r"\s+", " ", body).strip()[:160],
                fix="Remove hidden instruction text; agents should ignore instructions carried in content.",
                cwe="CWE-1007", owasp="LLM01: Prompt Injection", references=[REF_LLM],
            ))
    return out


# --------------------------------------------------------------------------- #
# E. MCP server manifests
#
# An MCP server is a process the agent STARTS AUTOMATICALLY at load and then
# trusts for the whole session -- the same load-time execution risk as an auto-run
# hook, with a longer lifetime and a broader tool surface.
#
# 🔴 Keyed on PARSED JSON STRUCTURE, never on the string "mcpServers".
# Documentation about MCP contains that string constantly; a substring match would
# flag every doc discussing the feature -- the self-noise class this scanner has
# repeatedly demonstrated on its own tree. Requiring a real object with real server
# entries costs nothing and cannot match prose.
# --------------------------------------------------------------------------- #

MCP_MANIFEST_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json",
                      "mcp_settings.json", "cline_mcp_settings.json"}

# Env var names that carry a credential into a third-party server process.
MCP_CRED_ENV = re.compile(r"(?i)(token|secret|passwd|password|credential|api[_-]?key|_key$|auth)")

# Command shapes that fetch and execute code at server start.
MCP_REMOTE_EXEC = re.compile(
    r"(?i)(https?://|\bcurl\b|\bwget\b|Invoke-WebRequest|\biwr\b|\bbash\s+-c|\bsh\s+-c|\beval\b|@latest\b|@\*)"
)


def _mcp_line_of(text: str, name: str) -> int:
    m = re.search(r'"' + re.escape(name) + r'"\s*:', text)
    return text.count("\n", 0, m.start()) + 1 if m else 1


def _scan_mcp(text: str, rel: str) -> list:
    """Flag MCP servers a manifest would auto-start, and credentials handed to them."""
    base = os.path.basename(rel.lower())
    if base not in MCP_MANIFEST_NAMES and '"mcpServers"' not in text:
        return []
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []  # fail safe: unparseable is not evidence of anything
    if not isinstance(data, dict):
        return []

    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return []

    out: list = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        ln = _mcp_line_of(text, str(name))
        command = str(cfg.get("command", ""))
        args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
        invocation = " ".join([command] + [str(a) for a in args]).strip()
        if not invocation:
            continue

        remote = bool(MCP_REMOTE_EXEC.search(invocation))
        out.append(Finding(
            engine="aisec",
            rule_id="mcp-server-autostart-remote" if remote else "mcp-server-autostart",
            title=("MCP server auto-starts from a remote/unpinned source" if remote
                   else "MCP server auto-starts a local command"),
            severity=Severity.HIGH if remote else Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            file=rel, line=ln, category="DANGEROUS_HOOK",
            description=(
                f"The MCP server '{name}' is started automatically when the agent loads this "
                "config, and is then trusted to serve tools for the whole session. "
                + ("Its invocation fetches or executes code from a remote or unpinned source, so "
                   "what runs can change without the config changing."
                   if remote else
                   "Review what the command does before trusting this config.")
            ),
            snippet=invocation[:160] + ("..." if len(invocation) > 160 else ""),
            fix=("Pin the server to an exact version from a source you control, and audit it before "
                 "adoption; never accept MCP config from an untrusted repo."),
            cwe="CWE-829", owasp="LLM05: Supply Chain", references=[REF_LLM],
        ))

        env = cfg.get("env")
        if isinstance(env, dict):
            leaked = sorted(k for k in env if MCP_CRED_ENV.search(str(k)))
            if leaked:
                out.append(Finding(
                    engine="aisec", rule_id="mcp-server-credential-env",
                    title="Credential passed into an MCP server process",
                    severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                    file=rel, line=ln, category="EXFIL",
                    description=(
                        f"The MCP server '{name}' receives credential-shaped environment variables "
                        f"({', '.join(leaked[:5])}). Whatever that server does with them is outside "
                        "this repo, and it holds them for the whole session."
                    ),
                    snippet=", ".join(leaked[:5])[:160],
                    fix=("Scope the credential to the minimum the server needs, prefer a short-lived "
                         "token, and confirm the server is one you have audited."),
                    cwe="CWE-522", owasp="LLM06: Sensitive Information Disclosure", references=[REF_LLM],
                ))
    return out


# --------------------------------------------------------------------------- #
# Engine entry
# --------------------------------------------------------------------------- #

def scan(scan_files, read_text) -> list:
    findings: list = []
    for sf in scan_files:
        text = read_text(sf.abspath)
        if not text:
            continue
        rel = sf.relpath

        findings.extend(_scan_unicode(text, rel))
        findings.extend(_scan_homoglyphs(text, rel))
        findings.extend(_scan_html_comments(text, rel))
        findings.extend(_scan_hooks(text, rel))
        findings.extend(_scan_mcp(text, rel))

        lines = split_lines(text)
        skipped = 0
        for i, line in enumerate(lines, start=1):
            if len(line) > 6000:
                skipped += 1
                continue
            for group in (INJECTION, EXFIL):
                for rule_id, title, rx, sev, conf, cat, cwe, owasp, fix in group:
                    if rx.search(line):
                        findings.append(Finding(
                            engine="aisec", rule_id=rule_id, title=title,
                            severity=sev, confidence=conf, file=rel, line=i, category=cat,
                            description=title + ".",
                            snippet=line.strip()[:200],
                            fix=fix, cwe=cwe, owasp=owasp, references=[REF_LLM],
                        ))
        if skipped:
            findings.append(Finding(
                engine="aisec", rule_id="aisec-long-line-skip",
                title="AI-security coverage limited by long line",
                severity=Severity.INFO, confidence=Confidence.HIGH,
                file=rel, line=1, category="COVERAGE",
                description=f"{skipped} line(s) exceeded the 6000-character analysis cap and were skipped by injection/exfiltration scanning.",
                snippet=f"skipped_lines={skipped}; cap=6000",
                fix="Split oversized lines before scanning to restore full AI-security coverage.",
                references=[REF_LLM],
            ))
    return findings
