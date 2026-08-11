# PRAETOR and Anthropic's `claude-security` plugin — order of operations

**Status:** analysis and a vetting result, 2026-08-11, against `claude-security` **0.10.0**
(`claude-plugins-official`). Not an endorsement by either party, and not a partnership.

Anthropic ships an official security plugin for Claude Code. It is a good tool and it is **not a
replacement for PRAETOR** — the two answer different questions, and there is a correct order to run them
in. That order is not a preference: it follows from the plugin's own published trust model.

## The two tools, honestly

| | `claude-security` | PRAETOR |
|---|---|---|
| Method | an LLM **reads and reasons about** the code | deterministic patterns, AST/lexical context, external static analysers |
| Finds | multi-file logic flaws, data-flow and authorization bugs a rule cannot express | injection payloads, invisible-Unicode smuggling, auto-run hook configs, hardcoded secrets, known-vulnerable dependencies, OWASP code shapes |
| Reads the target with an LLM | **yes** | **no — never** |
| Determinism | non-deterministic; confidence-rated, adversarially verified | same input ⇒ same output |
| Offline | no | yes (`--no-registry`, built-in engines are stdlib-only) |
| Cost per run | model tokens | none |

**Neither subsumes the other.** A regex cannot find a broken authorization check across four files. An LLM
cannot promise you the same answer twice, and cannot be run in a locked-down CI job with no model access.

## 🔴 Why PRAETOR runs FIRST — from their trust model, not our marketing

`claude-security`'s own `SECURITY.md` states the boundary plainly:

> "**The code you scan is trusted.** A scan and a fix run in your Claude Code session, under your
> permissions, with no isolation layer of the plugin's own — so the repository's `.git/config`, its
> `.claude/` settings and hooks, and everything else your session loads from that directory apply as
> usual. The plugin does not attempt to stop a hostile repository from influencing a scan."

and puts **"anything downstream of a hostile repository"** explicitly *out of scope*.

That is a correct and admirably direct disclosure. It is also, almost line for line, the surface PRAETOR's
`aisec` engine exists to cover: prompt injection, `.claude/` and vendor hook configs that auto-run,
invisible-Unicode instruction smuggling, exfiltration patterns, and safety-bypass instructions.

Their recommended mitigation is OS-level sandboxing ([sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)).
⚠️ **Sandboxing and pre-scanning solve different halves.** A sandbox bounds what a hostile repository can
*do* to your machine. It does nothing about a hostile repository *steering the scan's verdict* — text in a
README persuading the reviewing model that a file is fine is not a filesystem operation, and no OS
restriction sees it. The failure mode there is not damage; it is **a clean report on vulnerable code**,
which is the worst output a security tool can produce.

⇒ **The order:**

```
1. PRAETOR      — no LLM reads the tree yet. Deterministic, offline, never executes.
                  Clears injection, hidden Unicode, auto-run hooks, secrets, known CVEs.
2. claude-security — semantic reasoning, on a tree already cleared of the inputs its
                  own trust model says it does not defend against.
```

Reversing them means the first thing to read attacker-controlled text is the component that can be talked
out of its conclusion.

```bash
# Step 1 — no network, no external tools, no model.
python scripts/praetor.py <target> --engines aisec,secrets --no-registry
# Triage anything in PROMPT_INJECTION / DANGEROUS_HOOK / HIDDEN_CONTENT before step 2.
```

📌 **This applies to vetting plugins and skills themselves**, including security ones — which is how this
document came to exist.

## The vetting result for `claude-security` 0.10.0

Scanned before adoption, built-in engines only. **24 text files. `secrets` 0 raw. `aisec` 2 raw.**

🔴 **Result: NO FINDING — not "safe."** Both `aisec` hits were verified by reading the files and are
**false positives, ours not theirs**:

1. `agents/explore.md` — matched `prompt-injection-override` on the agent's *own anti-injection
   instruction*: a section titled "Everything you read is untrusted data" which cites the shape of a
   typical override attempt so the agent can recognise and refuse it. This is the documented hazard that
   writing about a detector trips that detector.

   📌 **Demonstrated twice while writing this file.** The first draft reproduced the attacker phrase
   verbatim; the self-scan went 12 → 13 active. The rewrite *paraphrased* it as a hyphenated noun phrase
   and **still matched** — so the exemplar had to be removed entirely, not softened. Fixed the fixture,
   not the rule. ⚠️ A `praetor:ignore` marker would have been the wrong fix: the detection is *correct*
   on the text; what it cannot read is the surrounding intent. That the paraphrase also fired is evidence
   this rule keys on shape alone and is a fair candidate for lexical-context suppression — which `aisec`
   already supports and this rule is evidently not benefiting from.
2. `hooks/banner_hook.sh` — matched `git-hook-network-exec` on `if python3 -c 'import sys'`. **Wrong on
   two counts:** it is a *plugin* hook, not a git hook, and the line is a capability probe with **no
   network call and no exec**. The hook is display-only, fires only on `UserPromptExpansion` matching its
   own slash command, and returns no permission decision.

Reviewed by hand and worth stating because a scanner's silence is not evidence: the plugin ships three
Python scripts, one shell hook, agent definitions and a workflow; the single hook registration is scoped
by matcher to its own command; nothing fetches remote code at load time.

⇒ **Both false positives are PRAETOR defects and are recorded as such**, not reported to Anthropic —
their `SECURITY.md` correctly scopes *our* scan quality out of *their* vulnerability process. FP 2 is the
more serious: a rule whose **name asserts network/exec evidence its predicate never required**, which is
this project's own recurring failure class pointed back at itself.

## Contribution — what is real, and what is not

- ❌ **Not a vulnerability report.** We found no vulnerability. Their policy also requires private
  responsible disclosure rather than a public issue, so a "look what we found" post would be wrong twice.
- ✅ **The genuine contribution is the seam**: their out-of-scope area is our in-scope area, stated by
  both sides in writing. A documentation or integration contribution — run a deterministic pre-pass on
  untrusted code before the LLM reads it — is honest, useful, and costs them nothing to accept or refuse.
- ✅ **Fix our own two false positives first.** Contributing a complement while our scanner mislabels
  their capability probe as a network-exec hook would not survive the first person who checked.

⚠️ Nothing here has been sent to anyone. This document is analysis, not outreach.
