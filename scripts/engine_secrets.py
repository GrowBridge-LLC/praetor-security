"""
PRAETOR secret-detection engine (pure standard library).

Two complementary strategies:
  1. High-signal PROVIDER patterns -- anchored regexes for AWS, GCP, GitHub,
     Slack, Stripe, OpenAI, Anthropic, Google, Twilio, SendGrid, npm, JWTs,
     PEM private keys, and connection strings with embedded passwords
     (e.g. DATABASE_URL=postgres://user:pass@host/db). These are HIGH confidence.
  2. Generic keyword-assignment + Shannon-entropy detection for high-entropy
     strings that no provider pattern covers (MEDIUM/LOW confidence, aggressively
     filtered against placeholders and known false-positive shapes). Coverage
     outside the provider list rests on entropy; entropy can be diluted by
     embedding a credential in a configuration envelope.

It also unwraps base64 blobs and re-checks the decoded content, catching
base64-wrapped keys that naive denylists miss.

Provider-recognised credentials are redacted centrally at the Finding boundary;
formats without a provider rule may still require a future detector.
"""

from __future__ import annotations

import base64
import hashlib
import math
import re

from core import Finding, Severity, Confidence, redact, redact_line, split_lines

OWASP_SECRET = "A07:2021 Identification and Authentication Failures"
CWE_SECRET = "CWE-798"  # Use of Hard-coded Credentials
REF_SECRET = [
    "https://cwe.mitre.org/data/definitions/798.html",
    "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
]

# --------------------------------------------------------------------------- #
# Provider patterns.  group 'secret' (or group 1) captures the sensitive token.
# --------------------------------------------------------------------------- #
# Each: (rule_id, title, regex, severity, confidence, fix)
_P = Confidence
_S = Severity

PROVIDERS = [
    ("aws-access-key-id", "AWS Access Key ID",
     re.compile(r"\b(?P<secret>(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16})\b"),
     _S.HIGH, _P.HIGH,
     "Revoke the key in IAM, rotate it, and load credentials from the environment or an instance role instead of source."),

    ("aws-secret-access-key", "AWS Secret Access Key",
     re.compile(r"(?i)aws[_\-. ]?(?:secret|sk)[_\-. ]?(?:access)?[_\-. ]?key[\"'\s:=]{1,6}[\"']?(?P<secret>[A-Za-z0-9/+]{40})[\"']?"),
     _S.CRITICAL, _P.HIGH,
     "Rotate the AWS secret key immediately; never commit it -- use IAM roles or a secrets manager."),

    ("azure-storage-account-key", "Azure Storage Account Key",
     re.compile(r"(?i)(?=[^\r\n]*core\.windows\.net)[^\r\n]*AccountKey\s*=\s*(?P<secret>[A-Za-z0-9+/]{40,}={0,2})"),
     _S.HIGH, _P.HIGH,
     "Rotate the Azure storage account key; store it in a secret manager and use managed identity where possible."),

    ("gcp-api-key", "Google API Key",
     re.compile(r"\b(?P<secret>AIza[0-9A-Za-z_\-]{35})\b"),
     _S.HIGH, _P.HIGH,
     "Restrict and rotate the key in the Google Cloud console; scope it to specific APIs/referrers."),

    ("gcp-oauth-client-secret", "Google OAuth Client Secret",
     re.compile(r"\b(?P<secret>GOCSPX-[A-Za-z0-9_\-]{20,})\b"),
     _S.HIGH, _P.HIGH,
     "Rotate the OAuth client secret in Google Cloud; store it server-side only."),

    ("google-oauth-refresh-token", "Google OAuth Refresh Token",
     re.compile(r"\b(?P<secret>1//0[A-Za-z0-9_\-]{30,})\b"),
     _S.CRITICAL, _P.HIGH,
     "Revoke the refresh token (it grants long-lived access); rotate the associated OAuth client."),

    ("github-token", "GitHub Personal Access / OAuth Token",
     re.compile(r"\b(?P<secret>gh[posru]_[A-Za-z0-9]{36})\b"),
     _S.CRITICAL, _P.HIGH,
     "Revoke the token in GitHub Developer settings and rotate; use fine-grained, short-lived tokens."),

    ("github-fine-grained-pat", "GitHub Fine-Grained PAT",
     re.compile(r"\b(?P<secret>github_pat_[0-9a-zA-Z_]{82})\b"),
     _S.CRITICAL, _P.HIGH,
     "Revoke the fine-grained PAT in GitHub settings and rotate."),

    ("slack-token", "Slack Token",
     re.compile(r"\b(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,})\b"),
     _S.HIGH, _P.HIGH,
     "Revoke the Slack token in the app's OAuth settings and rotate."),

    ("slack-webhook", "Slack Incoming Webhook URL",
     re.compile(r"(?P<secret>https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"),
     _S.MEDIUM, _P.HIGH,
     "Regenerate the webhook; anyone with the URL can post to the channel."),

    ("stripe-secret-key", "Stripe Secret Key",
     re.compile(r"\b(?P<secret>(?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"),
     _S.CRITICAL, _P.HIGH,
     "Roll the Stripe secret key in the dashboard immediately; it can move money."),

    ("openai-key", "OpenAI API Key",
     re.compile(r"\b(?P<secret>sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b"),
     _S.HIGH, _P.HIGH,
     "Revoke the key in the OpenAI dashboard and rotate; set a spend limit."),

    ("anthropic-key", "Anthropic API Key",
     re.compile(r"\b(?P<secret>sk-ant-[A-Za-z0-9_\-]{24,})\b"),
     _S.HIGH, _P.HIGH,
     "Revoke the key in the Anthropic console and rotate."),

    ("twilio-account-sid-authtoken", "Twilio Auth Token",
     re.compile(r"(?i)twilio[_\-. ]?(?:auth[_\-. ]?token)[\"'\s:=]{1,6}[\"']?(?P<secret>[0-9a-fA-F]{32})[\"']?"),
     _S.HIGH, _P.HIGH,
     "Rotate the Twilio auth token in the console."),

    ("sendgrid-key", "SendGrid API Key",
     re.compile(r"\b(?P<secret>SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
     _S.HIGH, _P.HIGH,
     "Delete and recreate the SendGrid API key."),

    ("npm-token", "npm Access Token",
     re.compile(r"\b(?P<secret>npm_[A-Za-z0-9]{36})\b"),
     _S.HIGH, _P.HIGH,
     "Revoke the npm token with `npm token revoke` and rotate."),

    ("jwt", "JSON Web Token",
     re.compile(r"\b(?P<secret>eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"),
     _S.MEDIUM, _P.MEDIUM,
     "If this JWT carries secrets or is a long-lived credential, rotate the signing key and invalidate it."),
]

# --------------------------------------------------------------------------- #
# Rule specificity -- DERIVED, never hand-listed
# --------------------------------------------------------------------------- #
# Two provider patterns can legitimately match the same token: an Anthropic key
# `sk-ant-...` satisfies `anthropic-key` AND the broader `openai-key` (`sk-` plus
# 20+ token characters). Both findings land on the same line with the same
# redacted snippet, so they collapse to one in interpret.dedup(). Something has
# to decide which survives, and "whichever the list happened to define first" is
# not a decision -- it is how every Anthropic key came to be reported as an
# OpenAI key, with a fix telling the operator to revoke it in the wrong vendor's
# dashboard.
#
# Specificity = the length of the pattern's leading LITERAL prefix. `sk-ant-` (7)
# beats `sk-` (3). It is computed from the regex itself, so a new provider rule
# gets a correct value with nobody remembering to add one -- the failure mode of
# every hand-maintained list in this repo so far.
#
# ⚠️ What this deliberately does NOT do: it does not rank patterns that share no
# literal prefix (an alternation like the AWS one scores 0). That is correct --
# specificity only ever breaks a tie between rules matching the SAME token, and
# it is a tie-break, never a filter. Nothing is dropped on the strength of it.
_PREFIX_STOP = set("[](){}|*+?.^$\\")


def _literal_prefix_len(pattern: str) -> int:
    """Length of the leading literal run of a provider regex, after its wrapper."""
    p = pattern
    for lead in ("(?i)", "\\b", "(?P<secret>", "("):
        while p.startswith(lead):
            p = p[len(lead):]
    n = 0
    for ch in p:
        if ch in _PREFIX_STOP:
            break
        n += 1
    return n


# rule_id -> specificity, derived once at import.
PROVIDER_SPECIFICITY = {
    rule_id: _literal_prefix_len(rx.pattern) for rule_id, _t, rx, _s, _c, _f in PROVIDERS
}


# Connection strings with an embedded password. group 'secret' == the password.
CONNSTR = re.compile(
    r"(?P<scheme>postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|"
    r"rediss|ftp|sftp|ldaps?|clickhouse|cockroachdb|mssql|jdbc:[a-z]+)://"
    r"(?P<user>[^:@/\s]*):(?P<secret>[^@/\s]+)@[^\s/\"']+",
    re.IGNORECASE,
)

# PEM private-key blocks (multi-line).
PEM = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
)

# GCP / service-account JSON private key field.
SA_KEY = re.compile(r"\"private_key\"\s*:\s*\"-----BEGIN")

# Generic keyword assignment: name = "value".
GENERIC = re.compile(
    r"(?i)(?P<name>[A-Za-z0-9_\-.]*(?:password|passwd|pwd|secret|token|api[_\-]?key|"
    r"access[_\-]?key|client[_\-]?secret|auth[_\-]?token|private[_\-]?key|credential|"
    r"session[_\-]?key|encryption[_\-]?key)[A-Za-z0-9_\-.]*)"
    r"\s*[:=]\s*[\"'](?P<secret>[^\"'\n]{6,})[\"']"
)

# Long base64 blob candidate (for the unwrap check).
B64BLOB = re.compile(r"\b(?P<blob>[A-Za-z0-9+/]{40,}={0,2})\b")

# --------------------------------------------------------------------------- #
# False-positive controls
# --------------------------------------------------------------------------- #

PLACEHOLDER_TOKENS = (
    "xxx", "yyy", "zzz", "example", "sample", "changeme", "change_me", "placeholder",
    "your_", "your-", "yourkey", "yourtoken", "dummy", "redacted", "insert", "todo",
    "fixme", "notreal", "fake", "test_", "testkey", "abcabc", "foobar", "lorem",
    "<", ">", "{{", "}}", "${", "%(", "os.environ", "process.env", "getenv",
    "env[", "secrets.", "vault:", "*****", "......", "0000000", "1234567",
    "aaaaaa", "deadbeef", "n/a", "none", "null", "true", "false",
)

# variable names whose *value* being flagged is usually a false positive
FP_NAME_HINTS = ("public", "example", "sample", "test", "mock", "fixture", "dummy")


# Canonical documentation example tokens: real scanners flag these but they are
# published, non-live values. PRAETOR reports them but marks them filtered.
# (Assembled from parts so this source file itself carries no full token.)
KNOWN_EXAMPLES = {
    "AKIA" + "IOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG" + "/bPxRfiCYEXAMPLEKEY",
}

# Strong markers that indicate an OBVIOUS placeholder even inside an otherwise
# format-valid provider token. Deliberately does NOT include bare "example" or
# short digit runs -- a real AWS key (AKIA + 16 random chars) must still fire.
STRONG_PLACEHOLDER = (
    "xxxx", "your_", "your-", "yourkey", "yourtoken", "changeme", "change_me",
    "placeholder", "redacted", "dummy", "notreal", "insert_", "replace_me",
    "fill_in", "example.com", "<", ">", "{{", "}}", "${", "%(",
)


def is_dummy(value: str) -> bool:
    """Strict placeholder check for high-confidence, format-anchored provider matches."""
    if not value:
        return True
    low = value.lower()
    if any(t in low for t in STRONG_PLACEHOLDER):
        return True
    if re.search(r"x{4,}", low):
        return True
    if len(set(value)) <= 3:            # all-same / trivial repetition
        return True
    if value.strip()[:1] in "$<{%":
        return True
    return False


def looks_like_placeholder(value: str) -> bool:
    """Broad placeholder check for generic keyword / entropy matches."""
    if not value:
        return True
    low = value.lower()
    for t in PLACEHOLDER_TOKENS:
        if t in low:
            return True
    # all same char, or trivial repetition
    if len(set(value)) <= 3:
        return True
    # obvious env interpolation
    if value.strip().startswith(("$", "%", "{", "<")):
        return True
    return False


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# shapes that are high-entropy but almost never secrets
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_COLOR = re.compile(r"^#?[0-9a-fA-F]{6}$")
INTEGRITY_HASH = re.compile(r"^(sha256|sha384|sha512|sha1)-")


def is_known_fp_shape(value: str) -> bool:
    v = value.strip()
    return bool(GIT_SHA.match(v) or UUID.match(v) or HEX_COLOR.match(v) or INTEGRITY_HASH.match(v))


#: Shapes worth naming that NO provider rule matches on its own: a PEM block
#: and a GCP service-account JSON envelope are recognised by their structure,
#: not by a token pattern. Everything a provider rule can find is found by
#: running the provider rules, below -- these are the remainder, not a list to
#: grow whenever a new vendor appears.
_B64_STRUCTURAL_MARKERS = {
    "-----BEGIN": "PEM private key",
    "\"type\": \"service_account\"": "GCP service-account JSON",
}


def _b64_unwrap_hit(blob: str) -> str:
    """Return a short reason if a base64 blob decodes to something secret-shaped.

    🔴 THIS FUNCTION USED TO BE A HAND-WRITTEN LIST OF SIX MARKER STRINGS, and
    a breaker audit proved what that cost. It recognised `AKIA`, `xoxb-`,
    `postgres://`, `mongodb`, a PEM header and a GCP envelope -- so every OTHER
    provider PRAETOR can detect in plaintext was invisible once base64-wrapped.
    The audit demonstrated it live with a base64-encoded Anthropic-shaped key:
    zero findings, exit 0, and the capability profile went on to report
    `holds_credentials: none` on a tree that held one.

    ⇒ The repair is not a longer list. It is to ASK THE REAL DETECTOR. The
    decoded text now goes back through the same PROVIDERS table and connection-
    string rule the plaintext path uses, so a provider added tomorrow is covered
    here on the same commit, with nobody remembering to add it -- the failure
    mode of every hand-maintained list in this repository so far.

    ⚠️ ONE LEVEL ONLY. Decoding the result again would follow attacker-chosen
    nesting to an attacker-chosen depth. Double-wrapped content is a stated,
    accepted gap, not an oversight -- the same bound `engine_aisec` places on
    its own decode pass, for the same reason.
    """
    # 🔴 THIS USED TO REJECT ANY BLOB WHOSE LENGTH WAS NOT A MULTIPLE OF FOUR,
    # and that discarded most real blobs before the unwrap ever ran. `B64BLOB`
    # ends with `\b`, and `=` is not a word character, so the trailing `=`
    # padding is never captured -- the regex backtracks `={0,2}` to zero to
    # satisfy the boundary. Every credential whose plaintext length is not a
    # multiple of three therefore arrived here mis-sized and was dropped.
    #
    # Found by a test written for a DIFFERENT fix: the marker-list repair below
    # looked correct and was still returning nothing, because this check ran
    # first. Restore the padding instead of rejecting the input.
    padded = blob + "=" * (-len(blob) % 4)
    if len(padded) % 4 != 0:
        return ""
    try:
        decoded = base64.b64decode(padded, validate=True).decode("utf-8", "replace")
    except Exception:
        return ""

    for marker, reason in _B64_STRUCTURAL_MARKERS.items():
        if marker in decoded:
            return reason

    # Ask the detector, do not re-describe it.
    for rule_id, title, rx, _sev, _conf, _fix in PROVIDERS:
        for m in rx.finditer(decoded):
            if not is_dummy(m.group("secret")):
                return title
    for m in CONNSTR.finditer(decoded):
        if not is_dummy(m.group("secret")):
            return "database connection string"
    return ""


# --------------------------------------------------------------------------- #
# Path-context confidence hints
# --------------------------------------------------------------------------- #

#: Above this length a line stops getting the unanchored passes (generic
#: keyword assignment, standalone entropy, base64 unwrap). The anchored
#: provider rules still run, in windows -- see the comment at the scan loop.
_LINE_CAP = 4000

#: Windows overlap so a credential straddling a window boundary is still whole
#: inside one of them. It must exceed the longest single token any anchored
#: rule can match; a GitHub fine-grained PAT is 94 characters and is the
#: longest today, so 512 leaves a wide margin without needing a recount here
#: every time a rule is added.
_LINE_WINDOW_OVERLAP = 512


def _line_windows(line: str):
    """Yield the segments the anchored rules should scan for one line.

    A short line yields itself, unchanged -- the overwhelmingly common case
    costs nothing. A long line yields overlapping windows, so padding a line
    can no longer hide a credential from the anchored rules.
    """
    if len(line) <= _LINE_CAP:
        yield line
        return
    step = _LINE_CAP - _LINE_WINDOW_OVERLAP
    for start in range(0, len(line), step):
        yield line[start:start + _LINE_CAP]
        if start + _LINE_CAP >= len(line):
            return


def _path_is_lockfile(relpath: str) -> bool:
    low = relpath.lower()
    return low.endswith((".lock", "-lock.json", "lock.json", ".sum")) or "lock" in low.split("/")[-1]


def _path_is_test_or_example(relpath: str) -> bool:
    low = relpath.lower()
    return any(seg in low for seg in ("/test", "test/", "/tests", "tests/", "fixture", "example", "sample", "mock", "__mocks__", "spec/"))


def _secret_dedup_key(relpath: str, line: int, raw_secret: str) -> str:
    """Give equal raw secrets one identity without retaining their display text."""
    norm_file = (relpath or "").replace("\\", "/").lstrip("./").lower()
    raw_hash = hashlib.sha256(str(raw_secret).encode("utf-8", "replace")).hexdigest()
    basis = f"{norm_file}|{line}|secret|{raw_hash}"
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


def _add_line_secret(findings: list, values: list, finding: Finding, raw_secret: str) -> None:
    """Retain raw-value identity until every value on this line is redacted."""
    finding.dedup_key = _secret_dedup_key(finding.file, finding.line, raw_secret)
    findings.append(finding)
    values.append(raw_secret)


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
        lines = split_lines(text)

        # ---- multi-line: PEM private keys ----
        for m in PEM.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append(Finding(
                engine="secrets", rule_id="private-key-pem",
                title="Private key (PEM block) committed to source",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file=rel, line=line_no, category="SECRET",
                description="A PEM-encoded private key block is embedded in this file. Private keys must never live in a repository.",
                snippet="-----BEGIN ... PRIVATE KEY----- (redacted)",
                fix="Remove the key, rotate it, and load it from a secret store or key-management service.",
                cwe=CWE_SECRET, owasp=OWASP_SECRET, references=REF_SECRET,
            ))

        for m in SA_KEY.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append(Finding(
                engine="secrets", rule_id="gcp-service-account-key",
                title="GCP service-account private key in JSON",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file=rel, line=line_no, category="SECRET",
                description="A Google Cloud service-account JSON key with an embedded private_key was found.",
                snippet='"private_key": "-----BEGIN ... (redacted)',
                fix="Delete and rotate the service-account key; use workload identity / ADC instead of key files.",
                cwe=CWE_SECRET, owasp=OWASP_SECRET, references=REF_SECRET,
            ))

        # ---- per-line scanning ----
        skipped = 0
        for i, line in enumerate(lines, start=1):
            line_findings: list = []
            line_secrets: list = []

            # 🔴 A LONG LINE USED TO SKIP EVERY CHECK, AND THAT WAS AN EVASION.
            # A breaker audit padded one line past the cap and PRAETOR exited 0
            # on a tree holding a live-shaped AWS key -- the only trace was an
            # INFO coverage note, which gates nothing.
            #
            # The cap itself is not the mistake: minified assets really are
            # megabytes of high-entropy text, and running the ENTROPY and
            # GENERIC passes over them floods the report with noise, which is a
            # different way to hide a real finding.
            #
            # ⇒ The two passes are separated instead of the line being dropped.
            # The ANCHORED, high-signal rules (provider patterns and connection
            # strings) now run over the whole line in overlapping windows, so
            # padding no longer hides a credential they can recognise. The
            # noisy, unanchored passes stay capped, and the coverage note below
            # says exactly which of the two ran.
            long_line = len(line) > _LINE_CAP
            if long_line:
                skipped += 1

            for seg in _line_windows(line):
                # provider patterns
                for rule_id, title, rx, sev, conf, fix in PROVIDERS:
                    for m in rx.finditer(seg):
                        secret = m.group("secret")
                        if is_dummy(secret):
                            continue
                        c = conf
                        if _path_is_test_or_example(rel):
                            c = Confidence.MEDIUM if conf == Confidence.HIGH else Confidence.LOW
                        f = Finding(
                            engine="secrets", rule_id=rule_id, title=title,
                            severity=sev, confidence=c, file=rel, line=i, category="SECRET",
                            specificity=PROVIDER_SPECIFICITY.get(rule_id, 0),
                            description=f"Hard-coded credential detected: {title}.",
                            snippet=redact_line(seg, secret),
                            fix=fix, cwe=CWE_SECRET, owasp=OWASP_SECRET, references=REF_SECRET,
                        )
                        if secret in KNOWN_EXAMPLES:
                            f.filtered = True
                            f.filter_reason = "well-known published documentation example token (not a live credential)"
                        _add_line_secret(line_findings, line_secrets, f, secret)
                # connection strings w/ embedded password
                for m in CONNSTR.finditer(seg):
                    pw = m.group("secret")
                    if is_dummy(pw):
                        continue
                    _add_line_secret(line_findings, line_secrets, Finding(
                        engine="secrets", rule_id="db-connection-string-password",
                        title="Database connection string with embedded password",
                        severity=Severity.HIGH, confidence=Confidence.HIGH,
                        file=rel, line=i, category="SECRET",
                        description=f"A {m.group('scheme')} connection string embeds a password in plaintext.",
                        snippet=redact_line(seg, pw),
                        fix="Move the credential to an environment variable / secret manager and reference it; rotate the exposed password.",
                        cwe=CWE_SECRET, owasp=OWASP_SECRET, references=REF_SECRET,
                    ), pw)

            if long_line:
                # The unanchored passes below stay capped. Emit what the
                # anchored passes found and move on.
                if line_findings:
                    findings.extend(line_findings)
                continue

            # generic keyword assignment (+ entropy gate)
            for m in GENERIC.finditer(line):
                name = m.group("name")
                value = m.group("secret")
                if looks_like_placeholder(value) or is_known_fp_shape(value):
                    continue
                if any(h in name.lower() for h in FP_NAME_HINTS):
                    continue
                ent = shannon_entropy(value)
                # require either meaningful entropy or a clearly secret-y name+length
                if ent < 3.0 and len(value) < 16:
                    continue
                conf = Confidence.MEDIUM if ent >= 3.5 else Confidence.LOW
                _add_line_secret(line_findings, line_secrets, Finding(
                    engine="secrets", rule_id="hardcoded-secret-assignment",
                    title=f"Possible hard-coded secret assigned to `{name}`",
                    severity=Severity.MEDIUM, confidence=conf,
                    file=rel, line=i, category="SECRET",
                    description=f"A secret-like value (entropy {ent:.1f} bits/char) is assigned to `{name}`.",
                    snippet=redact_line(line, value),
                    fix="If this is a real credential, rotate it and load it from configuration/secret storage.",
                    cwe=CWE_SECRET, owasp=OWASP_SECRET, references=REF_SECRET,
                ), value)

            # base64-wrapped secret unwrap
            for m in B64BLOB.finditer(line):
                blob = m.group("blob")
                reason = _b64_unwrap_hit(blob)
                if reason:
                    _add_line_secret(line_findings, line_secrets, Finding(
                        engine="secrets", rule_id="base64-wrapped-secret",
                        title=f"Base64-wrapped secret ({reason})",
                        severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                        file=rel, line=i, category="SECRET",
                        description=f"A base64 blob decodes to a {reason}; encoding does not protect it.",
                        snippet=redact_line(line, blob),
                        fix="Remove and rotate the underlying credential; base64 is encoding, not encryption.",
                        cwe=CWE_SECRET, owasp=OWASP_SECRET, references=REF_SECRET,
                    ), blob)

            # standalone high-entropy token in a lockfile-free context (LOW confidence)
            if not _path_is_lockfile(rel):
                for tok in re.findall(r"[\"'`]([A-Za-z0-9+/=_\-]{24,})[\"'`]", line):
                    if looks_like_placeholder(tok) or is_known_fp_shape(tok):
                        continue
                    ent = shannon_entropy(tok)
                    if ent >= 4.3 and len(tok) >= 32:
                        # avoid double-reporting something a provider already caught on this line
                        if line_findings:
                            continue
                        _add_line_secret(line_findings, line_secrets, Finding(
                            engine="secrets", rule_id="high-entropy-string",
                            title="High-entropy string (possible secret)",
                            severity=Severity.LOW, confidence=Confidence.LOW,
                            file=rel, line=i, category="SECRET",
                            description=f"A {len(tok)}-char string with entropy {ent:.1f} bits/char may be a secret.",
                            snippet=redact_line(line, tok),
                            fix="Confirm whether this is a credential; if so, rotate and externalize it.",
                            cwe=CWE_SECRET, owasp=OWASP_SECRET, references=REF_SECRET,
                        ), tok)
            if line_findings:
                shared_snippet = line
                for secret in dict.fromkeys(line_secrets):
                    shared_snippet = redact_line(shared_snippet, secret)
                for finding in line_findings:
                    finding.snippet = shared_snippet
                findings.extend(line_findings)
        if skipped:
            findings.append(Finding(
                engine="secrets", rule_id="secrets-long-line-skip",
                title="Secret-scanning coverage limited by long line",
                severity=Severity.INFO, confidence=Confidence.HIGH,
                file=rel, line=1, category="COVERAGE",
                description=(
                    f"{skipped} line(s) exceeded the {_LINE_CAP}-character cap. The anchored "
                    "provider and connection-string rules DID run over them, in overlapping "
                    "windows. The unanchored passes -- generic keyword assignment, standalone "
                    "entropy, and base64 unwrapping -- did not, because they produce noise on "
                    "minified assets rather than signal."
                ),
                snippet=f"long_lines={skipped}; cap={_LINE_CAP}; anchored_rules=ran; unanchored_rules=skipped",
                fix="Split oversized lines before scanning to restore full secret-detection coverage.",
                cwe=CWE_SECRET, owasp=OWASP_SECRET, references=REF_SECRET,
            ))
    return findings
