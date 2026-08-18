# Open findings, re-verified by execution — 2026-08-18

Earlier audits left a set of findings recorded as open. Records rot: a finding listed
as open may have been fixed, and one listed as fixed may never have been. **Every entry
below was re-checked by running the code, not by reading it.** Where a check needed a
probe, the probe carries a control case so a passing result cannot be vacuous.

Two of these were previously mis-stated, and both corrections are recorded in place
rather than quietly amended.

| finding | prior state | verified state |
|---|---|---|
| Markdown `#` suppresses a finding | open | 🔴 **live** |
| `//` in a URL suppresses a finding | open | 🔴 **live, wider than recorded** |
| subprocess guard enumerates filenames | open | 🔴 **live** |
| traversal-shaped path from the fast path | open | 🔴 **live** (hardening gap) |
| container branch asserts an unmeasured analyser | **reported fixed** | 🔴 **live — that report was wrong** |
| deletion rationale in `interpret.py` | open, one false claim | 🔴 **live, two false claims** |
| the `353` figure | open | 🔴 **live, and impossible as written** |

---

## 1. One comment syntax for every file type

`scripts/lexctx.py` decides what a comment is with two flat constants —
`COMMENT_INTRODUCERS = ("#", "//", "/*", "<!--")` and `classify_lines`'s default
`comment_prefixes=("#",)`. Neither consults the file extension, and
`scripts/praetor.py` calls `lexctx.context_of(cache[ap], f.line)` with no prefixes
argument, so **every file is treated as `#`-commented.**

**1a — a Markdown heading suppresses an injection finding.** Two files, identical
payload, directory target:

```
findings | plain.md   1 | prompt-injection-override | ''
filtered | heading.md 1 | prompt-injection-override | 'behavioural pattern appears in a code comment, which cannot execute'
```

In Markdown `#` is a **heading** — rendered content, not an inert comment. Documents
written for agents to read are precisely where an injection payload is delivered, and
a payload behind a `#` is currently classified as something that "cannot execute".

**1b — a URL path segment suppresses a finding, in a file containing no comment.**
`comment_text` (the tuple that includes `//`) feeds the inline-ignore-marker path. In
YAML, which has no `//` comment syntax at all, `//` inside `https://` is read as the
comment introducer, so the URL path becomes "the comment" — and a path segment matching
an ignore marker suppresses the finding:

```
findings | control.yml 2 | ''                 #  https://ci.example/run
filtered | wf.yml      2 | 'suppressed by inline ignore marker on the flagged line'
                                              #  https://ci.example/nosec/run
```

🔴 **The scanned tree writes that URL.** A workflow file, manifest or compose file with
an ignore-marker word in a URL path silently disables a finding on that line.

⇒ **One fix, not two:** comment syntax must be decided per file type, the caller must
pass the file's identity, and an unknown type must fail safe to KEEP.

## 2. The subprocess guard enumerates five filenames

`tests/test_tool_output_is_not_target_controlled.py` is the structural enforcement that
every engine subprocess goes through `core.run_tool` — because a bare `text=True`
decodes with the locale codec and **the scanned tree supplies the bytes**. Its docstring
says it asserts this *"structurally"*. It reads a hand-written tuple of five paths and
pins `assert scanned == 5`.

**Measured:** a probe file was placed in `scripts/` containing a direct
`subprocess.run(..., text=True)` — the exact defect the guard exists to catch — and the
file was run. **3 passed.** The guard never opened it. Probe removed; tree verified
clean afterwards.

`scripts/core.py` is also outside the tuple, and it is now a subprocess call site in its
own right, not merely the home of the wrapper.

⇒ Enumerate by discovery over `scripts/*.py`; bring `core.py` into scope and allow its
one sanctioned call **by line, never by excluding the file**; replace the exact pin with
a floor plus a completeness assertion. A pin that must be hand-edited whenever a file is
added becomes a rubber stamp.

## 3. A traversal-shaped path from the fast path

`_relative_to_report_root` returns `p[len(root)+1:]` as soon as `p` starts with
`root + "/"`, **before any normalisation**. The escape check that rejects an escaping
relative path sits below it and is never reached on that branch:

```
'/src/../../etc/passwd'    root='/src'   -> '../../etc/passwd'    TRAVERSAL
'/src/../../../Windows/…'  root='/src'   -> '../../../Windows/…'  TRAVERSAL
'/src/normal/file.py'      root='/src'   -> 'normal/file.py'      control, correct
```

The control passes, so the probe discriminates. The docstring's *"Never invents a path"*
holds only for the slow path. A finding's path is the key several later passes rejoin to
the target root.

⚠️ **Rated a hardening gap, not a demonstrated exploit.** Neither the original audit nor
this one could construct a target that makes the analyser emit such a path. Fix it as
defence in depth; do not describe it as an exploit.

## 4. ↩️ The container branch asserts an analyser it never contacted

**This was reported FIXED on 2026-08-18 and that report was wrong.** It was concluded
from seeing a daemon-probe helper exist — reading, not measuring. Recorded here rather
than amended away, because the mistake is the same class the finding describes.

The semgrep probe is called only from the native and WSL branches. The container branch
calls a helper whose own docstring says it probes the **daemon**, "not the `docker`
binary", and "starts no container". It then returns `available: True` with a detail
string in the future tense — the analyser has not been reached. Meanwhile
`detect_runtime`'s docstring opens **"🔴 EVERY BRANCH MEASURES THE RUNTIME."**

📌 That branch's own comment already records an earlier claim here being false, and notes
that *saying so in a comment is what stopped anyone looking.* The docstring above it is
now doing that same job.

⇒ Either probe the analyser in the container branch, or state exactly which branches
measure what. Do not leave an emphatic claim that one branch falsifies.

## 5. Two false claims in a deletion rationale

The comment justifying the removal of the example-env suppression rule makes two
load-bearing claims. **Both are false, and the second was not previously recorded.**

- *"by the time a SECRET finding reaches this function it has ALREADY passed
  `is_dummy()`"* — `engine_secrets.py` creates a `SECRET` at **seven** sites;
  `is_dummy()` guards **two**. ⇒ true for 2 of 7.
- *"the example path was ALREADY accounted for … as a confidence downgrade"* —
  `_path_is_test_or_example` is called at **exactly one** of those seven sites.
  ⇒ true for 1 of 7.

**Measured:** a byte-identical placeholder private-key block in two files reports
`CRITICAL / HIGH` in an example env file and `CRITICAL / HIGH` in an ordinary source
file. **No downgrade, identical confidence.** The comment says the right response *"was
applied twice before this rule ran"*; on that path neither was applied.

⚠️ **The deletion itself was correct and must not be reverted** — it is the fail-safe
direction and nothing is newly suppressed. **The stated reason is what is wrong**, and
the same rationale is repeated in the test that controls it. Do not "fix" this by
widening the downgrade predicate: widening a suppression to justify a comment is how
this class begins.

## 6. One number, four files, three units — and impossible as written

The figure `353` ships in four files, described as "code points" in one, "lines of code
points" in another, and "lines" in a third. At most one can be right.

🔴 **Measured directly: the generated table is 181 lines in total.** A 181-line file
cannot discard 353 lines. The "lines" reading is not merely unsupported; it is
arithmetically impossible.

⚠️ **Honest boundary: the true magnitude was not re-derived here.** The original
destructive regeneration was not reproduced against an older database. An earlier record
gives 121 raw diff lines, 178→175 file lines and 4,302 code points lost; that is relayed
as its measurement, not certified by this one. **Re-measure before writing a replacement
number into four files.**

📌 The irony is the point: this is the machinery whose job is to prevent a silent
destructive regeneration, and its own account of the destruction does not reproduce.

---

## What this audit did not cover

Stated so the list is not read as exhaustive — an incomplete "known gaps" note reads as
complete and is worse than none.

- The remaining labelled findings from earlier audits were **not** re-verified here.
- No fix in this document has been implemented. Every entry is a verified defect awaiting
  a change, and each needs its own test seen **red** against current code before the fix
  is trusted.
- Finding 6's replacement figure is unmeasured, as stated above.
