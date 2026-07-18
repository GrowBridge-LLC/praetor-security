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
  D. DANGEROUS HOOKS       auto-run Claude Code hooks (SessionStart/PostToolUse/
                           ...), git hooks, and npm/pip lifecycle scripts that
                           execute on load or install.
  E. SAFETY BYPASS         instructions telling an agent to disable safety,
                           auto-approve, skip review, or escalate privileges.

Mapped to the OWASP Top 10 for LLM Applications and to CWE where applicable.
"""

from __future__ import annotations

import os
import re
import unicodedata

from core import Finding, Severity, Confidence

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

CC_HOOK_EVENTS = re.compile(
    r"(?i)\b(SessionStart|SessionEnd|PostToolUse|PreToolUse|UserPromptSubmit|Stop|SubagentStop|PreCompact|Notification)\b"
)
GIT_HOOK_NAMES = {
    "pre-commit", "post-commit", "pre-push", "post-checkout", "post-merge",
    "pre-rebase", "post-rewrite", "prepare-commit-msg", "post-applypatch",
}
NPM_LIFECYCLE = re.compile(r"(?i)\"(preinstall|install|postinstall|prepare|prepublish)\"\s*:\s*\"([^\"]+)\"")
EXEC_IN_HOOK = re.compile(r"(?i)(curl|wget|Invoke-WebRequest|iwr|nc\b|bash\s+-c|sh\s+-c|eval\b|base64\b|node\s+-e|python[0-9.]*\s+-c|powershell)")


def _scan_hooks(text: str, rel: str) -> list:
    out: list = []
    low_rel = rel.lower()
    base = os.path.basename(low_rel)

    # --- Claude Code hook config (settings.json / .claude/*) ---
    is_cc_settings = base in ("settings.json", "settings.local.json") or "/.claude/" in ("/" + low_rel) or low_rel.startswith(".claude/")
    if is_cc_settings and CC_HOOK_EVENTS.search(text) and '"command"' in text.lower():
        for m in re.finditer(r"(?i)\"command\"\s*:\s*\"([^\"]+)\"", text):
            cmd = m.group(1)
            ln = text.count("\n", 0, m.start()) + 1
            dangerous = bool(EXEC_IN_HOOK.search(cmd))
            out.append(Finding(
                engine="aisec",
                rule_id="claude-hook-autorun-dangerous" if dangerous else "claude-hook-autorun",
                title="Auto-run agent hook executes a shell command"
                      + (" (network/exec)" if dangerous else ""),
                severity=Severity.HIGH if dangerous else Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                file=rel, line=ln, category="DANGEROUS_HOOK",
                description=("A Claude Code hook runs a command automatically on an agent event. "
                             + ("It performs network/exec/encoding operations -- a strong load-time "
                                "code-execution / exfiltration risk." if dangerous
                                else "Review what it does before trusting this config.")),
                snippet=(cmd[:160] + ("..." if len(cmd) > 160 else "")),
                fix="Audit every auto-run hook command; do not accept hook config from untrusted sources.",
                cwe="CWE-829", owasp="LLM05: Supply Chain", references=[REF_LLM],
            ))

    # --- git hooks by path ---
    if base in GIT_HOOK_NAMES or "/hooks/" in ("/" + low_rel):
        if EXEC_IN_HOOK.search(text):
            for m in EXEC_IN_HOOK.finditer(text):
                ln = text.count("\n", 0, m.start()) + 1
                out.append(Finding(
                    engine="aisec", rule_id="git-hook-network-exec",
                    title="Git hook performs network/exec on a git event",
                    severity=Severity.HIGH, confidence=Confidence.LOW,
                    file=rel, line=ln, category="DANGEROUS_HOOK",
                    description="A git hook script runs network/exec commands automatically on git operations.",
                    snippet=text.splitlines()[ln - 1].strip()[:160] if ln - 1 < len(text.splitlines()) else "",
                    fix="Review committed git hooks; a repo should not ship hooks that curl|sh or eval.",
                    cwe="CWE-829", owasp="LLM05: Supply Chain", references=[REF_LLM],
                ))
                break

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
        findings.extend(_scan_html_comments(text, rel))
        findings.extend(_scan_hooks(text, rel))

        lines = text.splitlines()
        for i, line in enumerate(lines, start=1):
            if len(line) > 6000:
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
    return findings
