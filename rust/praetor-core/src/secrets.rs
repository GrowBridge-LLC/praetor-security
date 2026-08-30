//! Static secret detection, ported from `scripts/engine_secrets.py`.
//!
//! This module accepts text already selected by the caller and performs only
//! in-memory matching. It never opens, executes, imports, installs, or builds the
//! scanned target. Differential acceptance lives in
//! `tests/differential/run_differential.py`: both implementations scan one shared
//! fragment-assembled corpus and must emit identical `(engine, rule_id, file,
//! line)` sets and match the committed contract.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use crate::text::split_lines;

pub const OWASP_SECRET: &str = "A07:2021 Identification and Authentication Failures";
pub const CWE_SECRET: &str = "CWE-798";
pub const REF_SECRET: &[&str] = &[
    "https://cwe.mitre.org/data/definitions/798.html",
    "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub engine: &'static str,
    pub rule_id: &'static str,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub file: String,
    pub line: usize,
    pub category: &'static str,
    pub specificity: usize,
    pub description: String,
    pub snippet: String,
    pub fix: &'static str,
    pub cwe: &'static str,
    pub owasp: &'static str,
    pub references: &'static [&'static str],
    pub filtered: bool,
    pub filter_reason: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ScanInput<'a> {
    pub relpath: &'a str,
    pub text: &'a str,
}

struct Provider {
    rule_id: &'static str,
    title: &'static str,
    regex: Regex,
    severity: Severity,
    confidence: Confidence,
    fix: &'static str,
    specificity: usize,
}

type ProviderDef = (
    &'static str,
    &'static str,
    &'static str,
    Severity,
    Confidence,
    &'static str,
);

const PROVIDER_DEFS: &[ProviderDef] = &[
    ("aws-access-key-id", "AWS Access Key ID", r"\b(?P<secret>(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16})\b", Severity::High, Confidence::High, "Revoke the key in IAM, rotate it, and load credentials from the environment or an instance role instead of source."),
    ("aws-secret-access-key", "AWS Secret Access Key", r#"(?i)aws[_\-. ]?(?:secret|sk)[_\-. ]?(?:access)?[_\-. ]?key[\"'\s:=]{1,6}[\"']?(?P<secret>[A-Za-z0-9/+]{40})[\"']?"#, Severity::Critical, Confidence::High, "Rotate the AWS secret key immediately; never commit it -- use IAM roles or a secrets manager."),
    ("azure-storage-account-key", "Azure Storage Account Key", r#"(?i)AccountKey[=:][\"']?(?P<secret>[A-Za-z0-9+/]{40,})[\"']?;EndpointSuffix=core\.windows\.net"#, Severity::High, Confidence::High, "Rotate the Azure storage account key and store it in a secret manager."),
    ("gcp-api-key", "Google API Key", r"\b(?P<secret>AIza[0-9A-Za-z_\-]{35})\b", Severity::High, Confidence::High, "Restrict and rotate the key in the Google Cloud console; scope it to specific APIs/referrers."),
    ("gcp-oauth-client-secret", "Google OAuth Client Secret", r"\b(?P<secret>GOCSPX-[A-Za-z0-9_\-]{20,})\b", Severity::High, Confidence::High, "Rotate the OAuth client secret in Google Cloud; store it server-side only."),
    ("google-oauth-refresh-token", "Google OAuth Refresh Token", r"\b(?P<secret>1//0[A-Za-z0-9_\-]{30,})\b", Severity::Critical, Confidence::High, "Revoke the refresh token (it grants long-lived access); rotate the associated OAuth client."),
    ("github-token", "GitHub Personal Access / OAuth Token", r"\b(?P<secret>gh[posru]_[A-Za-z0-9]{36})\b", Severity::Critical, Confidence::High, "Revoke the token in GitHub Developer settings and rotate; use fine-grained, short-lived tokens."),
    ("github-fine-grained-pat", "GitHub Fine-Grained PAT", r"\b(?P<secret>github_pat_[0-9a-zA-Z_]{82})\b", Severity::Critical, Confidence::High, "Revoke the fine-grained PAT in GitHub settings and rotate."),
    ("slack-token", "Slack Token", r"\b(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,})\b", Severity::High, Confidence::High, "Revoke the Slack token in the app's OAuth settings and rotate."),
    ("slack-webhook", "Slack Incoming Webhook URL", r"(?P<secret>https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)", Severity::Medium, Confidence::High, "Regenerate the webhook; anyone with the URL can post to the channel."),
    ("stripe-secret-key", "Stripe Secret Key", r"\b(?P<secret>(?:sk|rk)_live_[0-9a-zA-Z]{24,})\b", Severity::Critical, Confidence::High, "Roll the Stripe secret key in the dashboard immediately; it can move money."),
    ("openai-key", "OpenAI API Key", r"\b(?P<secret>sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b", Severity::High, Confidence::High, "Revoke the key in the OpenAI dashboard and rotate; set a spend limit."),
    ("anthropic-key", "Anthropic API Key", r"\b(?P<secret>sk-ant-[A-Za-z0-9_\-]{24,})\b", Severity::High, Confidence::High, "Revoke the key in the Anthropic console and rotate."),
    ("twilio-account-sid-authtoken", "Twilio Auth Token", r#"(?i)twilio[_\-. ]?(?:auth[_\-. ]?token)[\"'\s:=]{1,6}[\"']?(?P<secret>[0-9a-fA-F]{32})[\"']?"#, Severity::High, Confidence::High, "Rotate the Twilio auth token in the console."),
    ("sendgrid-key", "SendGrid API Key", r"\b(?P<secret>SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", Severity::High, Confidence::High, "Delete and recreate the SendGrid API key."),
    ("npm-token", "npm Access Token", r"\b(?P<secret>npm_[A-Za-z0-9]{36})\b", Severity::High, Confidence::High, "Revoke the npm token with `npm token revoke` and rotate."),
    ("jwt", "JSON Web Token", r"\b(?P<secret>eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b", Severity::Medium, Confidence::Medium, "If this JWT carries secrets or is a long-lived credential, rotate the signing key and invalidate it."),
];

fn literal_prefix_len(pattern: &str) -> usize {
    let mut p = pattern;
    for lead in ["(?i)", r"\b", "(?P<secret>", "("] {
        while let Some(rest) = p.strip_prefix(lead) {
            p = rest;
        }
    }
    p.chars()
        .take_while(|ch| !"[](){}|*+?.^$\\".contains(*ch))
        .count()
}

fn providers() -> &'static Vec<Provider> {
    static PROVIDERS: OnceLock<Vec<Provider>> = OnceLock::new();
    PROVIDERS.get_or_init(|| {
        PROVIDER_DEFS
            .iter()
            .map(
                |(rule_id, title, pattern, severity, confidence, fix)| Provider {
                    rule_id,
                    title,
                    regex: Regex::new(pattern)
                        .expect("provider regex is part of the port contract"),
                    severity: *severity,
                    confidence: *confidence,
                    fix,
                    specificity: literal_prefix_len(pattern),
                },
            )
            .collect()
    })
}

fn compiled(slot: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    slot.get_or_init(|| Regex::new(pattern).expect("secret regex is part of the port contract"))
}

fn connstr() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    compiled(
        &RX,
        r#"(?i)(?P<scheme>postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|rediss|ftp|sftp|ldaps?|clickhouse|cockroachdb|mssql|jdbc:[a-z]+)://(?P<user>[^:@/\s]*):(?P<secret>[^@/\s]+)@[^\s/\"']+"#,
    )
}

fn pem() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    compiled(
        &RX,
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
    )
}

fn sa_key() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    compiled(&RX, r#""private_key"\s*:\s*"-----BEGIN"#)
}

fn generic() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    compiled(
        &RX,
        r#"(?i)(?P<name>[A-Za-z0-9_\-.]*(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|client[_\-]?secret|auth[_\-]?token|private[_\-]?key|credential|session[_\-]?key|encryption[_\-]?key)[A-Za-z0-9_\-.]*)\s*[:=]\s*["'](?P<secret>[^"'\n]{6,})["']"#,
    )
}

fn b64blob() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    compiled(&RX, r"\b(?P<blob>[A-Za-z0-9+/]{40,}={0,2})\b")
}

fn git_sha() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    compiled(&RX, r"^[0-9a-f]{40}$")
}

fn uuid() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    compiled(
        &RX,
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    )
}

fn hex_color() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    compiled(&RX, r"^#?[0-9a-fA-F]{6}$")
}

fn integrity_hash() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    compiled(&RX, r"^(sha256|sha384|sha512|sha1)-")
}

fn standalone_token() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    compiled(&RX, r#"["'`]([A-Za-z0-9+/=_\-]{24,})["'`]"#)
}

const PLACEHOLDER_TOKENS: &[&str] = &[
    "xxx",
    "yyy",
    "zzz",
    "example",
    "sample",
    "changeme",
    "change_me",
    "placeholder",
    "your_",
    "your-",
    "yourkey",
    "yourtoken",
    "dummy",
    "redacted",
    "insert",
    "todo",
    "fixme",
    "notreal",
    "fake",
    "test_",
    "testkey",
    "abcabc",
    "foobar",
    "lorem",
    "<",
    ">",
    "{{",
    "}}",
    "${",
    "%(",
    "os.environ",
    "process.env",
    "getenv",
    "env[",
    "secrets.",
    "vault:",
    "*****",
    "......",
    "0000000",
    "1234567",
    "aaaaaa",
    "deadbeef",
    "n/a",
    "none",
    "null",
    "true",
    "false",
];

const FP_NAME_HINTS: &[&str] = &[
    "public", "example", "sample", "test", "mock", "fixture", "dummy",
];

const STRONG_PLACEHOLDER: &[&str] = &[
    "xxxx",
    "your_",
    "your-",
    "yourkey",
    "yourtoken",
    "changeme",
    "change_me",
    "placeholder",
    "redacted",
    "dummy",
    "notreal",
    "insert_",
    "replace_me",
    "fill_in",
    "example.com",
    "<",
    ">",
    "{{",
    "}}",
    "${",
    "%(",
];

fn distinct_chars(value: &str) -> usize {
    value.chars().collect::<HashSet<_>>().len()
}

pub fn is_dummy(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let low = value.to_lowercase();
    if STRONG_PLACEHOLDER.iter().any(|token| low.contains(token)) {
        return true;
    }
    if low.as_bytes().windows(4).any(|window| window == b"xxxx") {
        return true;
    }
    if distinct_chars(value) <= 3 {
        return true;
    }
    matches!(
        value.trim_start().chars().next(),
        Some('$' | '<' | '{' | '%')
    )
}

pub fn looks_like_placeholder(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let low = value.to_lowercase();
    if PLACEHOLDER_TOKENS.iter().any(|token| low.contains(token)) {
        return true;
    }
    if distinct_chars(value) <= 3 {
        return true;
    }
    matches!(
        value.trim_start().chars().next(),
        Some('$' | '%' | '{' | '<')
    )
}

pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for ch in value.chars() {
        *counts.entry(ch).or_default() += 1;
    }
    let n = value.chars().count() as f64;
    -counts
        .values()
        .map(|count| {
            let p = *count as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

pub fn is_known_fp_shape(value: &str) -> bool {
    let value = value.trim();
    git_sha().is_match(value)
        || uuid().is_match(value)
        || hex_color().is_match(value)
        || integrity_hash().is_match(value)
}

fn b64_unwrap_hit(blob: &str) -> Option<&'static str> {
    // Mirror Python's explicit pre-check before `b64decode(validate=True)`.
    // The crate's STANDARD engine then rejects alphabet/padding errors.
    if blob.len() % 4 != 0 && !blob.ends_with('=') {
        return None;
    }
    let bytes = STANDARD.decode(blob).ok()?;
    let decoded = String::from_utf8_lossy(&bytes);
    [
        ("-----BEGIN", "PEM private key"),
        ("\"type\": \"service_account\"", "GCP service-account JSON"),
        ("AKIA", "AWS access key"),
        ("xoxb-", "Slack token"),
        ("postgres://", "database connection string"),
        ("mongodb", "database connection string"),
    ]
    .into_iter()
    .find_map(|(marker, reason)| decoded.contains(marker).then_some(reason))
}

fn path_is_lockfile(relpath: &str) -> bool {
    let low = relpath.to_lowercase();
    low.ends_with(".lock")
        || low.ends_with("-lock.json")
        || low.ends_with("lock.json")
        || low.ends_with(".sum")
        || low
            .rsplit('/')
            .next()
            .is_some_and(|name| name.contains("lock"))
}

fn path_is_test_or_example(relpath: &str) -> bool {
    let low = relpath.to_lowercase();
    [
        "/test",
        "test/",
        "/tests",
        "tests/",
        "fixture",
        "example",
        "sample",
        "mock",
        "__mocks__",
        "spec/",
    ]
    .iter()
    .any(|segment| low.contains(segment))
}

fn redact(secret: &str, keep: usize) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= keep * 2 {
        let first = chars.first().copied().unwrap_or_default();
        return format!(
            "{}{}",
            first,
            "*".repeat(chars.len().saturating_sub(1).max(1))
        );
    }
    let start: String = chars[..keep].iter().collect();
    let end: String = chars[chars.len() - keep..].iter().collect();
    format!("{start}********{end} (len={})", chars.len())
}

fn redact_line(line: &str, secret: &str) -> String {
    let redacted = if secret.is_empty() {
        line.trim().to_string()
    } else {
        line.replace(secret, &redact(secret, 4)).trim().to_string()
    };
    redacted.chars().take(200).collect()
}

fn finding(
    rule_id: &'static str,
    title: impl Into<String>,
    severity: Severity,
    confidence: Confidence,
    file: &str,
    line: usize,
    description: impl Into<String>,
    snippet: impl Into<String>,
    fix: &'static str,
) -> Finding {
    Finding {
        engine: "secrets",
        rule_id,
        title: title.into(),
        severity,
        confidence,
        file: file.to_string(),
        line,
        category: "SECRET",
        specificity: 0,
        description: description.into(),
        snippet: snippet.into(),
        fix,
        cwe: CWE_SECRET,
        owasp: OWASP_SECRET,
        references: REF_SECRET,
        filtered: false,
        filter_reason: String::new(),
    }
}

pub fn scan(inputs: &[ScanInput<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for input in inputs {
        scan_one(input.relpath, input.text, &mut findings);
    }
    findings
}

fn scan_one(relpath: &str, text: &str, findings: &mut Vec<Finding>) {
    if text.is_empty() {
        return;
    }

    for matched in pem().find_iter(text) {
        let line = text[..matched.start()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        findings.push(finding(
            "private-key-pem",
            "Private key (PEM block) committed to source",
            Severity::Critical,
            Confidence::High,
            relpath,
            line,
            "A PEM-encoded private key block is embedded in this file. Private keys must never live in a repository.",
            "-----BEGIN ... PRIVATE KEY----- (redacted)",
            "Remove the key, rotate it, and load it from a secret store or key-management service.",
        ));
    }

    for matched in sa_key().find_iter(text) {
        let line = text[..matched.start()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        findings.push(finding(
            "gcp-service-account-key",
            "GCP service-account private key in JSON",
            Severity::Critical,
            Confidence::High,
            relpath,
            line,
            "A Google Cloud service-account JSON key with an embedded private_key was found.",
            "\"private_key\": \"-----BEGIN ... (redacted)",
            "Delete and rotate the service-account key; use workload identity / ADC instead of key files.",
        ));
    }

    let mut skipped = 0usize;
    for (index, line) in split_lines(text).into_iter().enumerate() {
        let line_no = index + 1;
        if line.chars().count() > 4000 {
            skipped += 1;
            continue;
        }

        for provider in providers() {
            for captures in provider.regex.captures_iter(line) {
                let secret = captures
                    .name("secret")
                    .expect("every provider pattern has a secret capture")
                    .as_str();
                if is_dummy(secret) {
                    continue;
                }
                let confidence = if path_is_test_or_example(relpath) {
                    match provider.confidence {
                        Confidence::High => Confidence::Medium,
                        _ => Confidence::Low,
                    }
                } else {
                    provider.confidence
                };
                let mut item = finding(
                    provider.rule_id,
                    provider.title,
                    provider.severity,
                    confidence,
                    relpath,
                    line_no,
                    format!("Hard-coded credential detected: {}.", provider.title),
                    redact_line(line, secret),
                    provider.fix,
                );
                item.specificity = provider.specificity;
                let known_aws_id = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
                let known_aws_secret = ["wJalrXUtnFEMI/K7MDENG", "/bPxRfiCYEXAMPLEKEY"].concat();
                if secret == known_aws_id || secret == known_aws_secret {
                    item.filtered = true;
                    item.filter_reason =
                        "well-known published documentation example token (not a live credential)"
                            .to_string();
                }
                findings.push(item);
            }
        }

        for captures in connstr().captures_iter(line) {
            let password = captures
                .name("secret")
                .expect("connection secret capture")
                .as_str();
            if is_dummy(password) {
                continue;
            }
            let scheme = captures
                .name("scheme")
                .expect("connection scheme capture")
                .as_str();
            findings.push(finding(
                "db-connection-string-password",
                "Database connection string with embedded password",
                Severity::High,
                Confidence::High,
                relpath,
                line_no,
                format!("A {scheme} connection string embeds a password in plaintext."),
                redact_line(line, password),
                "Move the credential to an environment variable / secret manager and reference it; rotate the exposed password.",
            ));
        }

        for captures in generic().captures_iter(line) {
            let name = captures
                .name("name")
                .expect("generic name capture")
                .as_str();
            let value = captures
                .name("secret")
                .expect("generic secret capture")
                .as_str();
            if looks_like_placeholder(value) || is_known_fp_shape(value) {
                continue;
            }
            let low_name = name.to_lowercase();
            if FP_NAME_HINTS.iter().any(|hint| low_name.contains(hint)) {
                continue;
            }
            let entropy = shannon_entropy(value);
            if entropy < 3.0 && value.chars().count() < 16 {
                continue;
            }
            let confidence = if entropy >= 3.5 {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            findings.push(finding(
                "hardcoded-secret-assignment",
                format!("Possible hard-coded secret assigned to `{name}`"),
                Severity::Medium,
                confidence,
                relpath,
                line_no,
                format!("A secret-like value (entropy {entropy:.1} bits/char) is assigned to `{name}`."),
                redact_line(line, value),
                "If this is a real credential, rotate it and load it from configuration/secret storage.",
            ));
        }

        for captures in b64blob().captures_iter(line) {
            let blob = captures.name("blob").expect("base64 blob capture").as_str();
            if let Some(reason) = b64_unwrap_hit(blob) {
                findings.push(finding(
                    "base64-wrapped-secret",
                    format!("Base64-wrapped secret ({reason})"),
                    Severity::High,
                    Confidence::Medium,
                    relpath,
                    line_no,
                    format!("A base64 blob decodes to a {reason}; encoding does not protect it."),
                    redact_line(line, blob),
                    "Remove and rotate the underlying credential; base64 is encoding, not encryption.",
                ));
            }
        }

        if !path_is_lockfile(relpath) {
            for captures in standalone_token().captures_iter(line) {
                let token = captures.get(1).expect("standalone token capture").as_str();
                if looks_like_placeholder(token) || is_known_fp_shape(token) {
                    continue;
                }
                let entropy = shannon_entropy(token);
                if entropy >= 4.3 && token.chars().count() >= 32 {
                    let already_found = findings.iter().any(|item| {
                        item.line == line_no && item.file == relpath && item.category == "SECRET"
                    });
                    if already_found {
                        continue;
                    }
                    findings.push(finding(
                        "high-entropy-string",
                        "High-entropy string (possible secret)",
                        Severity::Low,
                        Confidence::Low,
                        relpath,
                        line_no,
                        format!(
                            "A {}-char string with entropy {entropy:.1} bits/char may be a secret.",
                            token.chars().count()
                        ),
                        redact_line(line, token),
                        "Confirm whether this is a credential; if so, rotate and externalize it.",
                    ));
                }
            }
        }
    }
    if skipped > 0 {
        findings.push(Finding {
            engine: "secrets",
            rule_id: "secrets-long-line-skip",
            title: "Secret-scanning coverage limited by long line".to_string(),
            severity: Severity::Low,
            confidence: Confidence::High,
            file: relpath.to_string(),
            line: 1,
            category: "COVERAGE",
            specificity: 0,
            description: format!("{skipped} line(s) exceeded the 4000-character analysis cap and were skipped by secret scanning."),
            snippet: format!("skipped_lines={skipped}; cap=4000"),
            fix: "Split oversized lines before scanning to restore secret-detection coverage.",
            cwe: CWE_SECRET,
            owasp: OWASP_SECRET,
            references: REF_SECRET,
            filtered: false,
            filter_reason: String::new(),
        });
    }
}

pub mod differential {
    use super::{scan, ScanInput};
    use std::collections::HashSet;

    fn unescape(value: &str) -> String {
        let mut out = String::new();
        let mut chars = value.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch != '\\' {
                out.push(ch);
                continue;
            }
            match chars.next().expect("secrets corpus: trailing backslash") {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '\\' => out.push('\\'),
                'u' => {
                    assert_eq!(chars.next(), Some('{'), "secrets corpus: \\u needs {{");
                    let mut hex = String::new();
                    loop {
                        match chars.next().expect("secrets corpus: unterminated \\u") {
                            '}' => break,
                            digit => hex.push(digit),
                        }
                    }
                    let code = u32::from_str_radix(&hex, 16).expect("secrets corpus: invalid hex");
                    out.push(char::from_u32(code).expect("secrets corpus: invalid code point"));
                }
                other => panic!("secrets corpus: unknown escape \\{other}"),
            }
        }
        out
    }

    /// Parse `label<TAB>relpath<TAB>fragment...`; fragments are concatenated
    /// only in memory so no committed file contains a credential-shaped token.
    pub fn cases(corpus: &str) -> Vec<(String, String, String)> {
        let mut seen_labels = HashSet::new();
        let mut seen_paths = HashSet::new();
        let mut cases = Vec::new();
        for (line_index, raw) in corpus.lines().enumerate() {
            if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = raw.split('\t').collect();
            assert!(
                fields.len() >= 3,
                "secrets corpus line {} needs label, path, and fragments",
                line_index + 1
            );
            let label = fields[0].to_string();
            let path = fields[1].to_string();
            assert!(
                !label.is_empty(),
                "secrets corpus line {} has empty label",
                line_index + 1
            );
            assert!(
                !path.is_empty(),
                "secrets corpus line {} has empty path",
                line_index + 1
            );
            assert!(
                seen_labels.insert(label.clone()),
                "duplicate secrets corpus label: {label}"
            );
            assert!(
                seen_paths.insert(path.clone()),
                "duplicate secrets corpus path: {path}"
            );
            let text = fields[2..].iter().map(|part| unescape(part)).collect();
            cases.push((label, path, text));
        }
        cases
    }

    pub fn signature(corpus: &str) -> String {
        let cases = cases(corpus);
        let inputs: Vec<ScanInput<'_>> = cases
            .iter()
            .map(|(_, path, text)| ScanInput {
                relpath: path,
                text,
            })
            .collect();
        let mut identities: Vec<String> = scan(&inputs)
            .into_iter()
            .map(|item| {
                format!(
                    "{}|{}|{}|{}",
                    item.engine, item.rule_id, item.file, item.line
                )
            })
            .collect();
        identities.sort();
        identities.dedup();
        identities.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // This checks provider count and unique IDs; differential testing checks cross-port parity.
    fn every_python_provider_pattern_is_present() {
        assert_eq!(providers().len(), 17);
        let names: HashSet<_> = providers()
            .iter()
            .map(|provider| provider.rule_id)
            .collect();
        assert_eq!(names.len(), providers().len(), "duplicate provider rule id");
    }

    #[test]
    fn provider_match_and_placeholder_keep_direction() {
        let live = ["AKIA", "QRSTUVWX23456789"].concat();
        let dummy = ["AKIA", "XXXXXXXXXXXXXXXX"].concat();
        let inputs = [
            ScanInput {
                relpath: "config.py",
                text: &live,
            },
            ScanInput {
                relpath: "dummy.py",
                text: &dummy,
            },
        ];
        let findings = scan(&inputs);
        assert!(findings
            .iter()
            .any(|item| item.rule_id == "aws-access-key-id" && item.file == "config.py"));
        assert!(!findings.iter().any(|item| item.file == "dummy.py"));
    }

    #[test]
    fn differential_corpus_assembles_fragments_only_in_memory() {
        let corpus = "aws\t.cursor/hooks.json\tAKIA\tQRSTUVWX23456789\n";
        let cases = differential::cases(corpus);
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].2, ["AKIA", "QRSTUVWX23456789"].concat());
        assert!(differential::signature(corpus).contains("aws-access-key-id"));
    }
}
