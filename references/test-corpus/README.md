# PRAETOR Test Corpus

Two small sample trees used to verify PRAETOR's behavior:

- `vulnerable/` - a deliberately-insecure project that exercises every engine.
- `clean/` - a well-behaved baseline used to check false-positive behavior.

## Regenerate

```bash
python _generate_corpus.py
```

This (re)creates both trees next to the script. It is idempotent.

## Why a generator instead of committed fixtures

The vulnerable fixtures must contain realistic **secret-shaped tokens** and
**injection payloads**. Committing those raw would trip other teams' secret
scanners and pre-commit hooks and pollute their git history. The generator
assembles every token deterministically from harmless parts at generation time,
so this source tree carries **no literal secret**, while still producing on-disk
fixtures the scanner can detect.

## Everything here is fake

All "secrets" are synthetic - deterministically generated dummy values with the
correct provider prefix and length, or obvious placeholders. **None is, or ever
was, a live credential.** The malicious scripts (`install.sh`, the dangerous
hook, the prompt-injection `SKILL.md`, the invisible-Unicode `notes.md`) are
inert samples for testing detection only. Do not run them.

## What each fixture exercises

**`vulnerable/`**
- `app.py` - SQL injection, command injection, `eval`, unsafe `yaml.load`, weak
  hash, disabled TLS verification, hardcoded provider secrets, LLM-output-to-shell.
- `server.js` - command injection, `eval`, DOM XSS.
- `requirements.txt` - dependencies pinned to versions with known advisories (SCA).
- `package.json` - malicious `postinstall` lifecycle script (supply chain).
- `config.env` - connection strings with embedded passwords, a hardcoded token.
- `deploy_key.pem` - a (fake) PEM private key.
- `creds_b64.txt` - a base64-wrapped secret.
- `install.sh` - `curl|sh` RCE, reads of `~/.aws` / `~/.ssh`, environment exfil.
- `SKILL.md` - prompt injection, safety-bypass instructions, a hidden HTML comment.
- `.claude/settings.json` - a dangerous auto-run agent hook.
- `notes.md` - invisible Unicode-Tag smuggling, zero-width, and bidi controls.

**`clean/`**
- `app.py` - parameterized SQL, no-shell subprocess, strong hashing, secrets from
  the environment.
- `requirements.txt` - recent versions (the SCA engine may still legitimately flag
  these if new advisories were published after this was written - that is correct
  behavior, not a false positive).
- `README.md`, `.env.example` - benign docs and placeholder config.

## Expected result

- `vulnerable/` - many findings across all four engines, several CRITICAL/HIGH.
- `clean/` - effectively no findings from the code engines (secrets/sast/aisec).
  Any SCA findings are real, newly-published advisories on the pinned versions.
