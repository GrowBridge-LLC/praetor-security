# PRAETOR 1.2.0 — known weaknesses and lessons

PRAETOR 1.2.0 strengthens evidence that SAST examined the files it was meant
to examine. Its license remains AGPL-3.0-or-later. The release gate passed
895 Python and 19 Rust tests; the self-scan reported 47 active and 29 filtered
findings. An independent confirm audit found zero blocking findings against
its predeclared coverage, Markdown flag, and full-gate criteria.

## Weaknesses and status

| ID | Finding | Status |
|---|---|---|
| W1 | A mixed-case source extension could be skipped while the scan reported clean. | Fixed: case-folded covered extensions enter the expected file set and are passed to Semgrep. |
| W2 | A shell shebang on a covered Python extension could replace the extension language and remove that file from the expected set. | Fixed: extension evidence is established first; a mapped shebang can add a language but cannot remove the extension's language. |
| W3 | If Semgrep reports zero scanned paths, PRAETOR exits 3 with a SAST engine error but does not emit a separate HIGH finding and count for each expected file. | Open. Consumers must honor the process exit code and engine status, including when the findings list is empty. |
| W4 | Markdown mentions of dangerous permission flags are reported even when a document forbids their use. | By design. A reviewed allowlist entry can silence one exact current line, bound to its path, line number, SHA256, rule ID, reason, and reviewer. An edited line becomes active again and the stale entry is reported. |
| W5 | Blocking findings from the final independent confirm audit. | None under its predeclared criteria. This is an audit result, not a claim that the scanner has no other limits. |

The W1 and W2 fixes can make a previously passing findings gate fail when it
now sees a real issue. W4 can make documentation checks fail until each
intended exception is reviewed; there is no blanket exemption for prose or
fenced Markdown.

## Lessons carried into the next work cycle

1. Set the invariant before editing a detector. Fix the shared decision that
   produces false-clean variants, rather than only the latest example.
2. Build the set of files that must be scanned before language guessing runs.
   A shebang may add coverage requirements; it cannot erase a mapped extension.
3. Test the scanner's account of what its underlying engine actually opened.
   A successful engine process alone is insufficient evidence of full scope.
4. Keep independent audits with criteria stated before review. Escalate a
   repeated failure class after the agreed round limit instead of patching
   variants indefinitely.
5. Budget for reviewed documentation exceptions when removing suppression.
   Every exact-line exception needs a reason and a reviewer.
6. Record operational tool traps promptly in the relevant tool registry so a
   later work cycle does not rediscover them.
