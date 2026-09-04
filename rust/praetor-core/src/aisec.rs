//! AI/agent-security manifest scanning, ported from `scripts/engine_aisec.py`.
//!
//! This module ports exactly one function family from the Python `aisec`
//! engine: `_scan_mcp` (`scripts/engine_aisec.py:802`), its line-lookup
//! helper `_mcp_line_of` (`:797`), and the three module-level constants at
//! `:785-793` (`MCP_MANIFEST_NAMES`, `MCP_CRED_ENV`, `MCP_REMOTE_EXEC`). It
//! does **not** port the rest of `engine_aisec.py` (Unicode/homoglyph
//! scanning, HTML-comment scanning, hook scanning, EXFIL/INJECTION line
//! scanners) -- those stay out of scope until their own ports land.
//!
//! An MCP server is a process the agent starts automatically at load and
//! then trusts for the whole session -- the same load-time execution risk as
//! an auto-run hook, with a longer lifetime and a broader tool surface.
//!
//! Differential acceptance lives in `tests/differential/run_differential.py`:
//! this module and the Python reference must scan one shared corpus
//! (`references/differential/mcp.jsonl`) and emit identical
//! `(engine, rule_id, file, line)` identity sets, matching the committed
//! contract at `references/differential/mcp.expected`.

use regex::Regex;
use std::sync::OnceLock;

pub const REF_LLM: &str =
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/";
const REFERENCES: &[&str] = &[REF_LLM];

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

/// A finding scoped to what `_scan_mcp` actually needs.
///
/// `secrets::Finding` was considered and rejected as a shared type: its
/// `specificity` (provider-priority ranking) and `filtered`/`filter_reason`
/// (known-example-token suppression) fields exist for secrets-engine
/// concepts that `_scan_mcp` has no equivalent of. Forcing every construction
/// site here to fill in three meaningless defaults would be a worse fit than
/// a small local type that says exactly what this function produces.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub engine: &'static str,
    pub rule_id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub file: String,
    pub line: usize,
    pub category: &'static str,
    pub description: String,
    pub snippet: String,
    pub fix: &'static str,
    pub cwe: &'static str,
    pub owasp: &'static str,
    pub references: &'static [&'static str],
}

/// `scripts/engine_aisec.py:785-786`. Exact basenames only -- no
/// suffix/glob matching.
const MCP_MANIFEST_NAMES: &[&str] = &[
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
    "mcp_settings.json",
    "cline_mcp_settings.json",
];

/// `scripts/engine_aisec.py:789`. Env var names that carry a credential into
/// a third-party server process. Unanchored, case-insensitive, except the
/// `_key$` alternative which anchors only its own branch.
fn mcp_cred_env() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| {
        Regex::new(r"(?i)(token|secret|passwd|password|credential|api[_-]?key|_key$|auth)")
            .expect("MCP_CRED_ENV is part of the port contract")
    })
}

/// `scripts/engine_aisec.py:792-794`. Command shapes that fetch and execute
/// code at server start. Note the deliberately mixed boundary shapes: no
/// `\b` at all around `Invoke-WebRequest`; `\b` around `curl`/`wget`/`iwr`/
/// `eval`/`bash -c`/`sh -c`; `@latest` anchors only its trailing edge; `@\*`
/// (a literal asterisk) has no boundary anchoring at all. A port that
/// "normalizes" these for consistency changes behavior.
fn mcp_remote_exec() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| {
        Regex::new(
            r"(?i)(https?://|\bcurl\b|\bwget\b|Invoke-WebRequest|\biwr\b|\bbash\s+-c|\bsh\s+-c|\beval\b|@latest\b|@\*)",
        )
        .expect("MCP_REMOTE_EXEC is part of the port contract")
    })
}

/// `os.path.basename` on a lower-cased path, splitting on either slash
/// direction so this stays correct regardless of which platform produced
/// the `rel` value. Every case in the differential corpus uses forward
/// slashes only, so this is a superset of what the corpus exercises, not a
/// behavior the corpus can distinguish from a forward-slash-only split.
fn basename_lower(rel: &str) -> String {
    let lower = rel.to_lowercase();
    lower
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&lower)
        .to_string()
}

/// Best-effort mirror of Python's `str(value)` for a `json.loads`-decoded
/// value. Exact only for the JSON types the differential corpus actually
/// exercises (`string`, and "missing" via the caller's default) -- every
/// corpus case uses a JSON string for `command` and for each `args`
/// element. Bools/null get a Python-`repr`-shaped rendering exactly; arrays/
/// objects fall back to their JSON text rather than Python's
/// `repr(list)`/`repr(dict)` (e.g. `'single'` quoting), since no corpus case
/// puts a nested array/object in `command` or an `args` element and getting
/// that byte-for-byte right would need a hand-rolled Python-repr formatter
/// for no behavior this port is held to.
/// ⚠️ Numbers are NOT exact in general -- confirmed gap, not a claim of
/// correctness: `serde_json::Number::to_string()` loses precision on
/// integers outside safe i64/u64/f64-exact range and switches to scientific
/// notation (a 20-digit exact integer renders as e.g. "1e+20" here, vs. the
/// exact digits Python's `str()` would produce). See
/// references/audits/2026-09-04-mcp-rust-port-review.md Finding 3 -- did not
/// flip a rule_id in any construction tested, but the corpus has zero cases
/// with a non-string command/args element, so this is unexercised, not
/// proven safe.
fn json_scalar_str(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "None".to_string(),
        serde_json::Value::Bool(true) => "True".to_string(),
        serde_json::Value::Bool(false) => "False".to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `scripts/engine_aisec.py:797-799`.
///
/// 🔴 This is an **unscoped** `re.search` over the *whole* file text, not
/// scoped to the `mcpServers` object -- the first textual occurrence of
/// `"<name>":` anywhere in the file wins, even if it's an unrelated
/// top-level key that happens to share the server's name. Do not "improve"
/// this into a scoped search: that would be a real behavior change from the
/// Python reference, which the differential corpus's
/// `line-lookup-name-collision` case exists specifically to catch. Falls
/// back to line `1` if no match at all.
///
/// The name is regex-escaped before the search pattern is built (mirroring
/// Python's `re.escape(name)`), so a server name containing regex
/// metacharacters (`.`, `+`, etc.) is matched as literal text, not
/// interpreted as regex syntax -- see the `regex-metachar-server-name`
/// corpus case.
fn mcp_line_of(text: &str, name: &str) -> usize {
    let pattern = format!("\"{}\"\\s*:", regex::escape(name));
    let re = match Regex::new(&pattern) {
        Ok(re) => re,
        Err(_) => return 1,
    };
    match re.find(text) {
        Some(m) => {
            text[..m.start()]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1
        }
        None => 1,
    }
}

/// `scripts/engine_aisec.py:802-871` `_scan_mcp`. Flags MCP servers a
/// manifest would auto-start, and credentials handed to them.
///
/// Fail-safe by construction: unparseable JSON, a non-object top level, a
/// missing/non-object `mcpServers`, a non-object server entry, or a
/// non-array `args` all produce zero findings and never panic -- mirroring
/// Python's `except (ValueError, RecursionError): return []`. `serde_json`'s
/// default (bounded) recursion depth plays the same role as Python's
/// `RecursionError` catch: deeply nested attacker-controlled JSON errors out
/// rather than overflowing the stack.
pub fn scan_mcp(text: &str, rel: &str) -> Vec<Finding> {
    let base = basename_lower(rel);
    if !MCP_MANIFEST_NAMES.iter().any(|&name| name == base) && !text.contains("\"mcpServers\"") {
        return Vec::new();
    }

    // 🔴 KNOWN GAP, not fixed here — references/audits/2026-09-04-mcp-rust-port-review.md
    // Findings 1-2. serde_json's default bounded recursion depth (128) and its
    // rejection of lone/unpaired UTF-16 surrogate escapes both make this parse
    // fail on inputs Python's json.loads tolerates (nesting well past 1000
    // levels; lone surrogates at all) -- so a manifest containing EITHER one
    // silently produces zero findings here even when it holds a real,
    // dangerous MCP server entry, while the Python reference correctly flags
    // it. Empirically confirmed, not theoretical. Do not wire this port into
    // any live scan path before this is fixed with its own corpus cases
    // proving the fix -- rust/praetor/src/main.rs's refusal to scan is the
    // actual safety mechanism keeping this from mattering today.
    let data: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Vec::new(), // fail safe: unparseable is not evidence of anything
    };
    let data_obj = match data.as_object() {
        Some(o) => o,
        None => return Vec::new(),
    };
    let servers = match data_obj.get("mcpServers").and_then(|v| v.as_object()) {
        Some(s) => s,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    for (name, cfg) in servers {
        let cfg_obj = match cfg.as_object() {
            Some(o) => o,
            None => continue, // skip: not an object
        };
        let ln = mcp_line_of(text, name);

        let command = match cfg_obj.get("command") {
            Some(v) => json_scalar_str(v),
            None => String::new(),
        };
        let args: Vec<String> = match cfg_obj.get("args").and_then(|v| v.as_array()) {
            Some(arr) => arr.iter().map(json_scalar_str).collect(),
            None => Vec::new(),
        };
        let mut parts = Vec::with_capacity(1 + args.len());
        parts.push(command);
        parts.extend(args);
        let invocation = parts.join(" ");
        let invocation = invocation.trim();
        if invocation.is_empty() {
            continue; // skip: nothing would run
        }

        let remote = mcp_remote_exec().is_match(invocation);
        let rule_id = if remote {
            "mcp-server-autostart-remote"
        } else {
            "mcp-server-autostart"
        };
        let title = if remote {
            "MCP server auto-starts from a remote/unpinned source"
        } else {
            "MCP server auto-starts a local command"
        };
        let severity = if remote { Severity::High } else { Severity::Medium };
        let snippet = if invocation.chars().count() > 160 {
            let truncated: String = invocation.chars().take(160).collect();
            format!("{truncated}...")
        } else {
            invocation.to_string()
        };
        let tail = if remote {
            "Its invocation fetches or executes code from a remote or unpinned source, so what runs can change without the config changing."
        } else {
            "Review what the command does before trusting this config."
        };
        let description = format!(
            "The MCP server '{name}' is started automatically when the agent loads this config, and is then trusted to serve tools for the whole session. {tail}"
        );

        out.push(Finding {
            engine: "aisec",
            rule_id,
            title,
            severity,
            confidence: Confidence::Medium,
            file: rel.to_string(),
            line: ln,
            category: "DANGEROUS_HOOK",
            description,
            snippet,
            fix: "Pin the server to an exact version from a source you control, and audit it before adoption; never accept MCP config from an untrusted repo.",
            cwe: "CWE-829",
            owasp: "LLM05: Supply Chain",
            references: REFERENCES,
        });

        if let Some(env) = cfg_obj.get("env").and_then(|v| v.as_object()) {
            let mut leaked: Vec<&str> = env
                .keys()
                .filter(|k| mcp_cred_env().is_match(k))
                .map(|k| k.as_str())
                .collect();
            leaked.sort_unstable();
            if !leaked.is_empty() {
                let shown: Vec<&str> = leaked.iter().take(5).copied().collect();
                let joined = shown.join(", ");
                let snippet: String = joined.chars().take(160).collect();
                let description = format!(
                    "The MCP server '{name}' receives credential-shaped environment variables ({joined}). Whatever that server does with them is outside this repo, and it holds them for the whole session."
                );
                out.push(Finding {
                    engine: "aisec",
                    rule_id: "mcp-server-credential-env",
                    title: "Credential passed into an MCP server process",
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    file: rel.to_string(),
                    line: ln,
                    category: "EXFIL",
                    description,
                    snippet,
                    fix: "Scope the credential to the minimum the server needs, prefer a short-lived token, and confirm the server is one you have audited.",
                    cwe: "CWE-522",
                    owasp: "LLM06: Sensitive Information Disclosure",
                    references: REFERENCES,
                });
            }
        }
    }
    out
}

pub mod differential {
    use super::scan_mcp;
    use std::collections::HashSet;

    /// Parse the JSONL corpus format: one JSON object per line, with string
    /// fields `label`/`path`/`manifest` (`note` is optional and ignored).
    /// Blank lines and lines starting with `#` (after trimming) are skipped,
    /// exactly like `secrets.rs`'s TSV parser skips comment/blank lines.
    /// Asserts uniqueness of both `label` and `path` across the corpus,
    /// mirroring `secrets.rs`'s own `assert!` style -- a path collision
    /// would silently collapse two cases' identities into one in the
    /// deduplicated signature set (see the design doc's boxed warning).
    pub fn cases(corpus: &str) -> Vec<(String, String, String)> {
        let mut seen_labels = HashSet::new();
        let mut seen_paths = HashSet::new();
        let mut cases = Vec::new();
        for (line_index, raw) in corpus.lines().enumerate() {
            if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
                continue;
            }
            let line_no = line_index + 1;
            let value: serde_json::Value = serde_json::from_str(raw).unwrap_or_else(|err| {
                panic!("mcp corpus line {line_no}: invalid JSON: {err}")
            });
            let obj = value
                .as_object()
                .unwrap_or_else(|| panic!("mcp corpus line {line_no} is not a JSON object"));
            let label = obj
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("mcp corpus line {line_no} missing string `label`"))
                .to_string();
            let path = obj
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("mcp corpus line {line_no} missing string `path`"))
                .to_string();
            let manifest = obj
                .get("manifest")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("mcp corpus line {line_no} missing string `manifest`"))
                .to_string();
            assert!(
                seen_labels.insert(label.clone()),
                "duplicate mcp corpus label: {label}"
            );
            assert!(
                seen_paths.insert(path.clone()),
                "duplicate mcp corpus path: {path}"
            );
            cases.push((label, path, manifest));
        }
        cases
    }

    /// Runs `scan_mcp` over every corpus case's `manifest` against its
    /// `path`, and returns the sorted, deduplicated, space-joined set of
    /// `engine|rule_id|file|line` identities -- identical shape to
    /// `secrets::differential::signature`.
    pub fn signature(corpus: &str) -> String {
        let mut identities: Vec<String> = cases(corpus)
            .iter()
            .flat_map(|(_, path, manifest)| {
                scan_mcp(manifest, path)
                    .into_iter()
                    .map(|item| format!("{}|{}|{}|{}", item.engine, item.rule_id, item.file, item.line))
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
    fn prose_mentioning_mcp_servers_without_the_literal_substring_is_not_a_finding() {
        let text = "Configure your MCP servers by adding an mcpServers block (no quotes) to your config.";
        assert!(scan_mcp(text, "README.md").is_empty());
    }

    #[test]
    fn unparseable_json_fails_safe() {
        let text = r#"{"mcpServers": { "broken": true, "oops""#;
        assert!(scan_mcp(text, "cases/unparseable-json/.mcp.json").is_empty());
    }

    #[test]
    fn non_object_server_entry_is_skipped_not_crashed() {
        let text = r#"{"mcpServers": {"weird": "not-an-object"}}"#;
        assert!(scan_mcp(text, "cases/x/.mcp.json").is_empty());
    }

    #[test]
    fn args_must_be_a_json_array_else_it_coerces_to_empty() {
        let text = "{\n  \"mcpServers\": {\n    \"x\": {\n      \"command\": \"node\",\n      \"args\": \"not-a-list\"\n    }\n  }\n}";
        let findings = scan_mcp(text, "cases/args-not-a-list-coerced/.mcp.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "mcp-server-autostart");
        assert_eq!(findings[0].line, 3);
    }

    /// Branch 12: `_mcp_line_of` is an unscoped search over the whole file --
    /// an unrelated top-level key sharing the server's name, appearing
    /// before the real server definition, wins over the real one.
    #[test]
    fn line_lookup_is_unscoped_and_finds_the_first_textual_occurrence() {
        let text = "{\n  \"files\": \"unrelated top-level key sharing the server name below\",\n  \"mcpServers\": {\n    \"files\": {\n      \"command\": \"node\",\n      \"args\": [\"./server.js\"]\n    }\n  }\n}";
        let findings = scan_mcp(text, "cases/line-lookup-name-collision/.mcp.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2, "must report the bogus line 2 occurrence, not the real server's line 4 -- an unscoped search is the documented Python behavior");
    }

    /// Branch 13: the server name is regex-escaped before building the
    /// search pattern, so metacharacters in the name are literal.
    #[test]
    fn server_name_with_regex_metacharacters_is_matched_literally() {
        let text = "{\n  \"mcpServers\": {\n    \"my.tool+v2\": {\n      \"command\": \"node\",\n      \"args\": [\"tool.js\"]\n    }\n  }\n}";
        let findings = scan_mcp(text, "cases/regex-metachar-server-name/.mcp.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 3);
    }

    #[test]
    fn credential_env_keys_are_sorted_and_non_matching_keys_excluded() {
        let text = "{\n  \"mcpServers\": {\n    \"gh\": {\n      \"command\": \"node\",\n      \"args\": [\"s.js\"],\n      \"env\": {\"GITHUB_TOKEN\": \"x\", \"LOG_LEVEL\": \"debug\"}\n    }\n  }\n}";
        let findings = scan_mcp(text, "cases/cred/.mcp.json");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[1].rule_id, "mcp-server-credential-env");
        assert!(findings[1].description.contains("GITHUB_TOKEN"));
        assert!(!findings[1].description.contains("LOG_LEVEL"));
    }

    #[test]
    fn differential_signature_matches_committed_contract_shape() {
        let corpus = r#"{"label": "t", "path": "cases/t/.mcp.json", "manifest": "{\n  \"mcpServers\": {\n    \"files\": {\n      \"command\": \"node\",\n      \"args\": [\"./server.js\"]\n    }\n  }\n}"}"#;
        let cases = differential::cases(corpus);
        assert_eq!(cases.len(), 1);
        let sig = differential::signature(corpus);
        assert_eq!(sig, "aisec|mcp-server-autostart|cases/t/.mcp.json|3");
    }
}
