# Design: serialized-model / pickle-opcode scanning

**Status:** design only, nothing built. Written in response to `ROADMAP-V1.md`
§3 ("the biggest single feature gap for v1") and both competitor surveys naming
this as the single highest-value missing capability. No code has been written
against this document; treat every signature below as a proposal, not a
contract.

**Scope of this document:** the six deliverables asked for — file admission,
disassembly/severity model, container formats, resource bounds, code location,
test strategy — plus an explicit accounting of how this avoids the failure mode
that sank the last second-file-selector attempt (`git log 0930947`, discussed
in `references/audits/2026-08-13-scope-and-cost-research.md` §3).

---

## 0. The invariant, restated for this feature specifically

`CLAUDE.md`'s header rule is **PRAETOR NEVER EXECUTES, IMPORTS, INSTALLS OR
BUILDS THE CODE IT SCANS.** Everything below is compatible with that only
because of one stdlib fact: `pickletools.genops()` walks a pickle byte stream
opcode-by-opcode and returns `(opcode, arg, pos)` tuples — it never calls
`pickle.load()`, never resolves a `GLOBAL` reference to an actual importable
object, and never instantiates anything. It disassembles the way `objdump`
disassembles a binary: syntactically, not semantically. This design uses
`pickletools.genops()` and nothing else to look inside a pickle stream.
`pickle.Unpickler.find_class` is never called; `pickle.load`/`pickle.loads`
are never called against target-controlled bytes anywhere in this design,
including in test fixtures (§6). This must have its own assertion in
`tests/test_invariant_never_executes_target.py`, exactly as the file's own
header requires for every new engine or backend — captured the same way the
SCA test captures argv without running anything: capture that `engine_model`
never calls the four banned names (`pickle.load`, `pickle.loads`,
`pickle.Unpickler` with default `find_class`, `importlib.import_module` on
target-derived strings) rather than trusting a code review to notice their
absence forever.

---

## 1. The file-admission path

### 1.1 Why this is the load-bearing design question

`core._consider_file()`'s docstring already names the exact risk: *"a future
second file selector (a different candidate SET, same admission RULE) cannot
silently diverge from this one."* It cites the reverted git-tracked-selection
attempt. That attempt failed for a specific, narrow reason, and understanding
*that* reason is what tells us whether this new selector is safe to build.

**What actually went wrong in the reverted attempt.** It narrowed the
candidate population using an attacker-influenceable property — VCS
tracked/ignored status — to cut cost, and that narrowing ate a real
gitignored credential (`references/audits/2026-08-13-scope-and-cost-research.md`
§3, point 1: *"A gitignored `.env` holding live credentials is a real finding
that tracked-only selection would lose."*). The failure shape is: **a second
selector that excludes on a scannable-controlled property turns a real
finding into a false clean.**

**Why the model-file selector is not the same shape.** It does not narrow
anything on an attacker-controlled property. It *widens* — it admits files
`_consider_file` currently rejects outright (`is_probably_binary(...) ==
True` at core.py:754-756) — and the property it keys candidacy on
(extension) is orthogonal to git status, `.gitignore`, and every other
scanned-tree-controlled scoping decision that has burned this repo before.
A gitignored `.pkl` must be exactly as much a candidate as a tracked one, for
the identical reason `secrets` already treats git status as "deliberately NOT
a scope boundary" (`praetor.py`, the comment above `secret_files`): the
disclosure/danger is real wherever the file sits, and `.gitignore` is
target-controlled.

The residual risk in *this* design is not "narrowed scope hides a real
finding" — it is the more boring risk the `_consider_file` docstring is
actually warning about: **two independent implementations of the shared
admission checks (symlink refusal, `--exclude` regex, skip-dir handling)
silently drifting apart**, so that an operator's `--exclude` pattern, or a
future fix to symlink handling, reaches text files but not model files (or
vice versa) because nobody remembered there were two copies. That is
mechanical, not semantic, and it is closed by construction if there is
literally one function deciding it, not two.

### 1.2 Recommendation: extend `_consider_file` and `walk_files` with a `mode`, not a parallel implementation

Reject the "separate `walk_model_files()` built independently" option and the
"fork `_consider_file`" option. Both reintroduce exactly the two-copies risk
the docstring warns about. Instead:

```
_consider_file(ap, rel, max_bytes, excludes, stats, mode="text")
walk_files(target, skip_dirs=None, max_bytes=..., extra_excludes=None,
           stats=None, mode="text")
```

`mode` controls exactly two things, and nothing else:

1. **Which candidacy predicate decides admission** — `scannable(fn)` for
   `mode="text"` (unchanged), a new `model_candidate(fn)` for
   `mode="model"` (§1.3).
2. **Whether the binary-sniff rejection at core.py:754-756 fires.** For
   `mode="model"`, a positive binary sniff is *expected*, not disqualifying,
   so that branch is skipped entirely — model mode does not call
   `_binary_and_nul_in_sniff` at all, since `contains_nul` is meaningless for
   a binary target and the sniff is 4096 bytes read for nothing.

Everything else in `_consider_file` — symlink refusal (`os.path.islink`),
the exclude-regex loop, the `stats["excluded_by_pattern"]` bookkeeping, the
final `ScanFile` construction — stays as **one code path**, executed for
both modes. This is the concrete, checkable claim that answers the
divergence question: there is no second implementation of "does `--exclude`
apply to this file," there is a second *value* passed into the same
function. A future change to exclude-matching or symlink handling changes
both candidate sets by construction, because it changes the one function
both call.

`walk_files(..., mode="model")` reuses the same `os.walk` traversal, the same
`DEFAULT_SKIP_DIRS` pruning, and the same `stats["skipped_dirs"]` bookkeeping
as the text walk — again, one loop, a threaded-through `mode` argument, not a
parallel loop that has to be kept in sync by hand.

**Size admission is the one place model mode should diverge on policy, and
it should diverge explicitly, not by accident.** `max_bytes` for `mode="text"`
is a real content cap — `read_text` fully materializes the file. Model files
routinely run into the gigabytes and this design never reads a whole model
file into memory (§4) — a 7B-parameter checkpoint's own `data.pkl` member is
KB-scale; the multi-GB payload is raw tensor storage this design never opens.
So `mode="model"` should NOT reject on the existing `--max-file-size` (default
3 MB) — that would exclude essentially every real model file from candidacy,
which defeats the feature. Recommend a new, much larger admission ceiling,
`DEFAULT_MODEL_MAX_ADMIT_BYTES = 50 * 1024**3` (50 GB), purely as a
belt-and-suspenders sanity bound against a pathological input (a sparse file,
a device node), not as a meaningful scanning-cost control — the real cost
controls are internal to the engine (§4) and apply regardless of on-disk
file size.

### 1.3 Candidate identification: extension for admission, magic bytes for classification — deliberately two different layers

**Admission (walker-cheap, name-only, mirrors `scannable()`):**

```
MODEL_EXTS = {
    ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".bin", ".joblib", ".dill",
    ".npy", ".npz", ".h5", ".hdf5", ".keras", ".model", ".safetensors",
}
```

This is the *only* thing `model_candidate(fn)` checks — an `os.path.splitext`
membership test, symmetric with `scannable()`'s extension check, costing
nothing per file and requiring no bytes read. `.bin` is intentionally
included even though it is the least specific entry (`.bin` could be a raw
tensor dump, a disk image, an ELF, anything) — excluding it would create a
silent gap for one of the more common real-world model-weight extensions
(raw PyTorch state-dict-adjacent blobs, GGML/GGUF-adjacent conventions, etc.),
and the ambiguity is exactly what stage two exists to resolve. `.safetensors`
is admitted too, for a different reason (§3.4): the walker's job is candidacy,
not verdict, and the engine needs to *see* a `.safetensors` file in order to
correctly recognize it as safe-by-design and emit nothing rather than an
"unrecognized format" cost-limited disclosure.

**Classification (engine-side, first real read, mirrors the existing
binary/NUL sniff pattern one layer up):** once admitted, `engine_model`
peeks a bounded prefix (first 16 bytes is enough for every signature below)
and classifies by magic bytes, never by trusting the extension:

| signature (bytes) | format | handling |
|---|---|---|
| `PK\x03\x04` or `PK\x05\x06` (empty archive) | ZIP container | §3.1/§3.2 — read `data.pkl`-shaped members only |
| `\x89HDF\r\n\x1a\n` | HDF5 | §3.3 — bounded heuristic, not real parsing |
| `\x93NUMPY` | raw `.npy` | §3.2 — parse the ASCII header only |
| `\x80` followed by a byte in `0..5` | pickle protocol 2–5 | disassemble directly (§2) |
| none of the above | unknown / protocol-0-or-1 pickle | attempt `pickletools.genops()` anyway (protocol 0/1 have no fixed magic — they open with ordinary opcode bytes like `(` MARK or `c` GLOBAL); if it raises on the first opcode, classify as **unrecognized** and emit the coverage disclosure in §4 rather than silently passing |

Extension decides "is this worth looking at" (cheap, walker-side, matches
the architecture's existing division of labor between `scannable()` and the
content sniff that follows it). Magic bytes decide "what am I actually
looking at" (content-dependent, so it belongs in the engine, exactly where
`is_probably_binary` already does a content sniff *after* name-based
admission for text files). Keying candidacy on magic bytes alone was
rejected: it would require opening and reading a prefix of every file in the
tree just to rule pickle-shape out, which is the same cost `scannable()`
exists to avoid paying for text files, and PRAETOR's whole walker
architecture is built around "cheap name check gates an expensive content
check," not the reverse.

### 1.4 Skip-dirs: follow the SAST/aisec precedent, not the secrets one

`DEFAULT_SKIP_DIRS` (vendor, node_modules, venv, dist, build, target, ...)
should apply to the model walk by default, same as it applies to `sast` and
`aisec`. The reasoning is the SAST reasoning, not the secrets one: *"a
vulnerability in vendored code is mostly not yours."* A malicious `.pkl`
shipped inside an installed, third-party ML package under `site-packages/`
or `node_modules/` is a supply-chain concern about that dependency, not
about a file *this repository's own authors committed* — which is the
threat `ROADMAP-V1.md` §3 actually names ("a malicious `.pkl`/`.pt`/`.h5`
file **committed to a repo**"). `--no-default-skips` (existing flag) already
exists for the "scan a distributed artifact where dist/ is the shipped
code" case and extends naturally to model mode with no new flag needed.

Flagged honestly: this is a judgment call, not a certainty. The SCOPE FLOOR
reasoning in `praetor.py` around `scope_stats["skipped_code_files"]` exists
precisely because "vendored code isn't yours" has already produced a real
scope hole once (the npm-tarball case, 78 of 81 files pruned). If a reviewer
decides a model file inside `vendor/`/`node_modules/` *should* be in scope
(e.g., because "installed" and "committed" are the same thing for a vendored
Python package that ships its weights in-tree), that is a one-line change —
pass `--no-default-skips` semantics through, or give model mode its own
skip-dir policy — but it should be a deliberate decision made here, not an
accident of copying the text engine's defaults uncritically.

### 1.5 What this section does NOT do

It does not read git status, `.gitignore`, or any VCS state — deliberately,
per §1.1. It does not change `scannable()`, `TEXT_EXTS`, `TEXT_NAMES`, or
`is_probably_binary()` — the text-file admission path is untouched. It does
not change the binary/NUL sniff's *definition*; it only skips *calling* it
for model-mode candidates, since that sniff's entire purpose (deciding
"reject because binary") is the one property model mode inverts.

---

## 2. The disassembly approach

### 2.1 Mechanism

`pickletools.genops(fileobj_or_bytes)` yields `(opcode, arg, pos)` triples,
streaming from a file object without materializing the whole stream in
memory (§4 bounds how much of the stream is actually read). This design
touches exactly two opcode families:

**Opcodes that carry a resolvable `(module, name)` pair — the only ones that
matter for detection:**

- **`GLOBAL`** (`c`, protocols 0–1, still emitted by many protocol-2 writers
  including `torch.save`'s default `pickle_protocol=2`): the opcode's own
  `arg` field *is* the two-line `"module\nname"` string. No stack tracking
  needed — `pickletools.genops()` hands it over directly.
- **`STACK_GLOBAL`** (`\x93`, protocol 4+): `arg` is `None` — the module and
  name strings are pushed onto the pickle VM's stack by two immediately
  preceding string-literal opcodes (`SHORT_BINUNICODE`, `BINUNICODE`,
  `BINUNICODE8`, or their protocol-0/1-compat string forms) and
  `STACK_GLOBAL` pops them. Resolving this needs a **bounded adjacency
  heuristic**, not a full pickle-VM: track the last two string-literal
  pushes seen, ignoring only `MEMOIZE` in between (a true no-op for stack
  shape — it records top-of-stack into the memo table without popping).
  If anything else intervenes between the two string pushes and the
  `STACK_GLOBAL`, or fewer than two string literals precede it, the target
  is **unresolved** — emit the disclosure finding in §2.4 rather than
  silently passing it. This is explicitly a heuristic, not a stack machine:
  it will not track values built through the memo/`GET` mechanism, tuple
  construction, or any other stack manipulation. A pickle stream's own
  opcode language has no generic string-concatenation primitive, though —
  `GLOBAL`/`STACK_GLOBAL` require the *complete* module and name strings as
  literal values somewhere in the stream, so an attacker cannot synthesize
  `"os.system"` piecewise the way a text-injection payload can be
  fragmented across a line. The heuristic's failure mode is losing the
  *correlation* between two adjacent literals and a `STACK_GLOBAL`, not an
  attacker hiding the literal content itself.
- **`INST`** (`i`, protocol 0/1 class instantiation): like `GLOBAL`, carries
  `"module\nname"` directly in the opcode text — no stack tracking needed,
  handled identically to `GLOBAL`.

**Opcodes that are deliberately given NO special-case logic, and why:**
`OBJ`, `NEWOBJ`, `NEWOBJ_EX`, `REDUCE`, `BUILD` all consume a class or
callable that was *already* pushed onto the stack by a prior `GLOBAL` /
`STACK_GLOBAL` / `INST` — which this design has already resolved and matched
against the danger list at the point it was introduced. Detection triggers
at **reference time** (`GLOBAL`/`STACK_GLOBAL`/`INST`), not at **call time**
(`REDUCE`/`NEWOBJ`), which is a deliberate simplification, argued for below.

### 2.2 Deliberate choice: flag at reference, not at proven invocation

A more "precise" design would try to prove that a dangerous global is
actually *called* — track it through to a `REDUCE` (or `NEWOBJ`/`OBJ`) with
nothing but harmless argument-building opcodes (`MARK`, `TUPLE*`, `EMPTY_TUPLE`)
in between, and only then escalate severity. This was considered and
rejected:

1. It adds real stack-tracking fragility (the same class of heuristic as
   `STACK_GLOBAL` resolution, but now needed for every dangerous global
   instead of just the STACK_GLOBAL-encoded ones) for a benefit that is
   mostly cosmetic.
2. **There is no legitimate reason a serialized model's opcode stream needs
   to reference `os.system`, `subprocess.Popen`, or `builtins.eval` at
   all** — called or not. Unlike a SAST finding where "is this reachable"
   materially changes the risk (dead code truly cannot run), a bare
   *reference* to a code-execution primitive inside a `.pkl`/`.pt` file is
   already the anomaly; a real PyTorch/scikit-learn/joblib artifact has zero
   legitimate call sites for it. This mirrors this repo's own settled
   reasoning for secrets and reachability (`CLAUDE.md`'s suppression
   section): *"A mechanism's safety is almost never a property of the
   mechanism. It is a scope decision made next to it."* Here the scope
   decision is: for model files specifically, reference IS the signal,
   the same way disclosure IS the signal for a hardcoded secret regardless
   of reachability.
3. In the realistic threat model (a crafted `__reduce__` payload), `REDUCE`
   follows immediately in virtually every real case — the entire point of
   the exploit is to get the pushed callable invoked. Chasing call-proof
   buys little detection value for real payloads while adding a plausible
   evasion surface (structure the stream so genuine analysis of "was it
   called" fails even though it was).
4. Detection this way is **memo-independent**: if a dangerous global is
   pushed once and reused ten times via the memo table (`GET`/`BINGET`),
   this design still catches it exactly once, at its first introduction —
   it does not need to re-recognize it at each reuse site.

### 2.3 Danger list and severity tiers

Severity is a function of **which** `(module, name)` matched, never of
"a `GLOBAL` opcode exists" — flagging every `GLOBAL` is pure noise, since a
completely ordinary PyTorch checkpoint's `data.pkl` is full of legitimate
`torch._utils._rebuild_tensor_v2`, `collections.OrderedDict`,
`torch.FloatStorage`, `numpy.core.multiarray._reconstruct`, and similar.
Matching is against a curated denylist of module/callable pairs (exact
name, or `module.*` wildcard meaning "any attribute of this module"),
following the same shape as `ProtectAI/modelscan`'s approach rather than
attempting an exhaustive semantic classifier:

**CRITICAL — direct, unambiguous code execution, no further step needed:**
`os.system`, `os.popen`, `os.exec*` (`execl`, `execv`, `execve`, `execvp`,
`execvpe`), `os.spawn*`, `posix.system`, `nt.system`, `subprocess.*`
(`Popen`, `call`, `check_call`, `check_output`, `run`), `builtins.eval`,
`builtins.exec`, `builtins.compile`, `runpy.*`, `ctypes.CDLL`, `ctypes.cdll`,
`ctypes.PyDLL`, `ctypes.windll`, `ctypes.oledll`, `pty.spawn`.

**HIGH — execution-adjacent primitives and published pickle gadget-chain
components:** `builtins.__import__`, `builtins.globals`, `builtins.locals`,
`builtins.vars`, `importlib.import_module`,
`importlib._bootstrap._call_with_frames_removed`, `importlib.util.*`,
`socket.socket`, `socket.create_connection`, `socket.fromfd`,
`shutil.rmtree`, `shutil.move`, `operator.attrgetter`,
`operator.methodcaller` (both explicitly gadget-chain components published
in real pickle-RCE proof-of-concepts, not execution primitives on their own
— included precisely because they are the known building blocks, per the
task's own framing).

**MEDIUM — dual-use, genuinely fuzzy:** `builtins.getattr` (flagged at its
own tier deliberately — it is the load-bearing half of the classic
`getattr(__import__('os'), 'system')` gadget when paired with `__import__`,
but `getattr` alone has enough legitimate uses in general-purpose
serialization that CRITICAL/HIGH would over-claim certainty), `shutil.copy`,
`shutil.copy2`, `shutil.copyfile`, `webbrowser.open`,
`urllib.request.urlopen`, `platform.system` (info disclosure, not
execution — kept at MEDIUM rather than dropped, since it is a legitimate
environment-fingerprinting primitive with no reason to appear in a model
checkpoint either).

**Where the line is fuzzy, stated plainly:** `getattr` is the fuzziest single
entry on this list — it is used throughout ordinary Python for entirely
benign attribute access, and a serialization framework using it internally
for legitimate reconstruction is plausible in a way `os.system` never is.
It stays on the list at MEDIUM rather than being dropped, because the
combination `builtins.__import__` (HIGH) followed anywhere in the same
stream by `builtins.getattr` (MEDIUM) is a recognizable gadget shape worth
a human's attention even at lower individual confidence — but this design
does not attempt to detect the *combination* as its own elevated finding;
that is a real refinement left undone and named as such rather than quietly
skipped.

### 2.4 The false-positive / false-negative tradeoff, stated honestly

**False negatives this design accepts:**
- Any dangerous callable not on the hardcoded list — the same open-ended gap
  `LIMITS.md` already states for the secrets provider table ("denylists are
  never exhaustive"). A novel gadget-chain composition of otherwise-benign
  stdlib functions, discovered after this list is written, is invisible
  until the list is updated.
- A `STACK_GLOBAL` whose module/name pair the adjacency heuristic cannot
  resolve (§2.1) — falls through to the "unresolved dynamic global"
  disclosure below rather than a denylist match. An adversarial pickle
  author who understands this heuristic could deliberately interpose an
  opcode between the two string pushes to defeat correlation, though doing
  so does not hide that *something* unresolved is happening (see below).
- Multi-hop chains where no single referenced global is individually
  dangerous.

**Mitigation for the first false-negative class, recommended as part of this
design, not optional:** every `STACK_GLOBAL` (and, symmetrically, every
`GLOBAL`/`INST`) whose resolved `(module, name)` is **neither** on the
danger list **nor** inside a short expected-benign prefix allowlist
(`torch`, `numpy`, `sklearn`, `scipy`, `joblib`, `pandas`, `xgboost`,
`lightgbm`, `keras`, `tensorflow`, `collections`, `collections.abc`,
`copyreg`, `datetime`, `decimal`, `fractions`, `array`, and `builtins`/
`__builtin__` restricted to a safe-type subset —
`dict`/`list`/`tuple`/`set`/`frozenset`/`bytes`/`bytearray`/`str`/`int`/
`float`/`complex`/`bool`/`slice`/`object`/`type`/`property`/
`staticmethod`/`classmethod`) produces a capped, low-severity disclosure —
`rule_id="model-unknown-global-import"`, `severity=LOW`, `confidence=LOW`,
`category="SUPPLY_CHAIN"` — first 10 unique `(module, name)` pairs per file,
with a `COVERAGE` finding if more exist. This is not a "finding" in the
sense of asserting danger; it is the same disclosure discipline as
`aisec-long-line-skip`: rather than silently passing an unusual reference,
it says "this file does something outside the common shape, a human should
glance at it," at a severity low enough that it will not gate a typical
`--fail-on MEDIUM`/`HIGH` CI policy. An unresolved `STACK_GLOBAL` (the
heuristic-defeat case above) is folded into this same bucket rather than
silently dropped — so the evasion described above still produces *a*
disclosure, just an unspecific one instead of a targeted denylist match.
This tier is a recommended addition, not a hard requirement of the core
mechanism; it can be deferred without weakening the CRITICAL/HIGH/MEDIUM
tiers above, which carry the actual detection weight.

**False positives this design accepts:** essentially none from the
CRITICAL/HIGH tiers by construction (nothing in `_EXPECTED_BENIGN_PREFIXES`
overlaps the danger list, and the danger-list entries have no ordinary
reason to appear in ML serialization at all) — the honest exposure is
entirely in the MEDIUM tier's `getattr`/`shutil.copy`/`platform.system`
entries, named above, and in the Tier-2 "unknown import" bucket, which is
explicitly designed to be low-severity/low-confidence noise rather than a
gating claim, precisely because its false-positive rate (any legitimately
custom-pickled class, e.g. `__main__.MyModel` or a project-specific
`sklearn`-adjacent estimator) is real and unavoidable without a much larger
allowlist project this design does not attempt.

---

## 3. Container formats

### 3.1 `.pt` / `.pth` / `.ckpt` — usually a ZIP, sometimes a raw pickle

Since PyTorch 1.6, `torch.save`'s default format is a ZIP archive (verify via
the `PK\x03\x04` magic-byte sniff in §1.3) with a top-level directory
(commonly `archive/`, but the exact name is not guaranteed) containing
`data.pkl` (the pickled object graph — small, describes structure and
references tensor storage by index) and separate numbered storage entries
holding the raw tensor bytes (large, uninteresting to this design — never
opened). Handling:

1. `zipfile.ZipFile(path)` opened read-only; `infolist()` enumerated
   (metadata only, no decompression) to find every member whose basename is
   exactly `data.pkl` (matches regardless of the enclosing directory name).
2. Each matching member is opened via `ZipFile.open(name)` and read with an
   explicit byte cap (`.read(N)`, never bare `.read()` — see §4 for `N`),
   then disassembled per §2.
3. If **no** member is named `data.pkl`, this is very likely the older,
   pre-1.6 `torch.save` format — a **raw pickle stream**, not a ZIP at all.
   The ZIP-magic-bytes check in §1.3 already routes this correctly: no `PK`
   signature means "treat the whole (bounded) file as a direct pickle
   stream," handled identically to a bare `.pkl`.
4. Every other member in the archive (the tensor storage blobs) is never
   opened. This is a meaningful, explicit boundary: this design's coverage
   claim is "the pickled object graph," never "the tensor payloads," and
   that should say so in the report the same way `aisec-decode-budget-exceeded`
   says so for its own bound.

### 3.2 `.npz` (ZIP of `.npy`) and standalone `.npy`

A bare `.npy` is **not** a pickle stream by default — it is a fixed binary
array format (`\x93NUMPY` magic, a version pair, then an ASCII-literal
Python-dict-shaped header giving shape/dtype/fortran-order, then raw
little/big-endian numeric bytes). It only embeds a pickle stream when the
array's dtype is `object` (`'|O'` / `dtype('O')`) and `allow_pickle=True` was
used to save it — numpy then pickles the object contents after the header.
Handling: parse the ASCII header (bounded to the first ~4 KB — real headers
are always small) with `ast.literal_eval` (never `eval`) to get the `descr`
field; if `descr` indicates an object dtype, disassemble the remainder of
the file (still bounded, §4) as a pickle stream starting right after the
header; otherwise this `.npy` carries no pickle content at all and nothing
further is read. `.npz` is exactly a ZIP of `.npy` members (verify with the
same `PK` sniff), so the handling is: enumerate members via `infolist()`
(cheap), and for each `.npy` member, read only enough bytes to parse its
header (§4 caps this at one bounded read per member, not full-member
decompression) and apply the same object-dtype check before deciding
whether to disassemble the rest.

### 3.3 `.h5` / `.hdf5` / `.keras` — HDF5, explicitly out of scope for real parsing, and said so on every file scanned

HDF5 is a complex binary container format with **no stdlib parser** —
`h5py` is the standard library for reading it, and it is a third-party,
compiled (libhdf5-backed) dependency. `core.py`'s own module docstring
states the architecture's founding constraint: *"This module has ZERO
third-party dependencies ... so it runs anywhere Python does and stays
fully auditable."* Adding a real HDF5 parser would either violate that
(pull in `h5py`) or require hand-rolling a nontrivial binary-format parser
from the HDF5 spec — both out of scope for this design.

The risk that matters for `.h5`/`.keras` is not pickle at all — it's a
**Keras `Lambda` layer**, whose `function` field can carry an
arbitrary-code-executing serialized callable (historically Python
`marshal`-serialized bytecode, not pickle) inside the model's JSON
architecture config, which Keras itself stores as an HDF5 string attribute
(commonly under a `model_config` attribute on the root group, though this is
not architecturally guaranteed across Keras/TF versions and file layouts).

**Recommended scope: a bounded, honestly-labeled heuristic, not real HDF5
parsing.** HDF5 files frequently store string/JSON attributes uncompressed
and near-readable in the raw byte stream even without parsing the format's
structure (superblock, B-trees, local heaps). So: read the first
`MODEL_HDF5_SCAN_BYTES` bytes of the file (§4) and run a plain substring/
regex search for the literal JSON signature `"class_name": "Lambda"` (or
`"class_name":"Lambda"` without the space — both are valid compact-JSON
renderings). A hit produces a HIGH finding
(`rule_id="keras-lambda-layer"`, `category="SUPPLY_CHAIN"`) naming the risk
by name (arbitrary code execution on model load via a Lambda layer) without
claiming to have parsed or verified the layer's actual payload.

**This must be disclosed on every `.h5`/`.hdf5`/`.keras` file scanned, hit or
not** — per the "disclose the limit, never silently drop" discipline this
repo already applies to `aisec-long-line-skip`. Emit an INFO `COVERAGE`
finding (`rule_id="model-scan-hdf5-heuristic-only"`) unconditionally for
every HDF5-format file admitted, stating plainly: *"HDF5 structural parsing
is not implemented; only a bounded raw-byte search for a Keras Lambda-layer
signature was performed. A compressed, chunked, or otherwise non-adjacent
attribute would not be found by this search."* This is a real, acknowledged
gap, not a rounding error — an attacker who knows PRAETOR only does a raw
substring search can defeat it by ensuring the attribute lands in a
compressed HDF5 chunk. Silence here would be the exact failure this repo's
whole `ENGINE_*` status vocabulary exists to prevent; the honest move is a
disclosed, permanent, unconditional coverage note rather than a clean
result that looks identical to a genuinely-parsed clean HDF5 file.

Full HDF5 parsing (e.g., as an optional dependency backend, mirroring how
`engine_sca.py` already treats `osv-scanner`/`pip-audit`/`npm` as
alternative, optionally-available backends behind a `--sca-backend` flag) is
a real, separately-scoped future option — flagged here as a considered
alternative, not adopted, because it reopens the zero-dependency-core
question this document is not positioned to settle.

### 3.4 `.safetensors` — recognized, never disassembled, treated as a negative

`.safetensors` is safe **by design**: it is a flat header (JSON, giving
tensor names/shapes/dtypes/byte-offsets) followed by raw tensor bytes, with
no code-execution path of any kind — there is no pickle stream to
disassemble and never will be. This design recognizes the extension at
admission (§1.3) purely so the engine can positively identify it and emit
**nothing** — no finding, no coverage-limit disclosure — rather than either
(a) silently skipping it in a way indistinguishable from "we didn't get to
it," or (b) misclassifying it as an unrecognized/unparseable format and
generating disclosure noise. Whether to additionally emit a low-noise,
off-by-default *positive* recommendation (something like "this repo also
contains equivalent `.pt` files alongside `.safetensors` — consider
migrating fully") is a real feature idea but out of scope here: it requires
cross-file correlation this design's per-file engine shape does not do, and
is better left as a documented future idea than half-built now.

### 3.5 ZIP handling hazards — bounded, in-memory only, never extracted to disk

`zipfile` against an attacker-controlled archive has two well-known
hazards, both addressed without ever writing anything to disk (this design
never calls `ZipFile.extract`/`extractall` — only `.open(name).read(N)`,
member-by-member, in memory):

1. **Decompression/zip-bomb risk.** `ZipInfo.file_size` (uncompressed) and
   `.compress_size` are both available from `infolist()` **without
   decompressing anything** — central-directory metadata only. Before
   opening a member for content, check its compression ratio
   (`file_size / max(1, compress_size)`) against a bound (§4); a member
   exceeding it is skipped and counted toward the coverage disclosure,
   never decompressed. As defense in depth, every actual `.read(N)` call
   also passes an explicit byte cap, so even an entry that lies about its
   own metadata (a corrupt or deliberately malformed central directory)
   cannot cause an unbounded read — `ZipExtFile.read(n)` decompresses only
   as much of the underlying deflate stream as needed to satisfy `n` bytes,
   never the whole member.
2. **Central-directory exhaustion.** A crafted archive can carry an
   enormous *number* of tiny entries — cheap to store, expensive to iterate
   — independent of any single entry's compression ratio. `infolist()`
   enumeration itself is bounded (§4) so a pathological entry count is
   capped and disclosed rather than iterated without limit.
3. **Path traversal** (a member named `../../etc/passwd`) is a hazard only
   for extraction-to-disk, which this design never does — reading a member
   in memory via `.open(name)` does not touch the filesystem at the
   member's name at all, so this specific hazard does not apply here, and
   is noted only to state explicitly why it was considered and ruled out
   rather than silently unaddressed.

---

## 4. Resource bounds, as concrete numbers

Every bound below produces a disclosed `COVERAGE` finding when hit —
`severity=INFO`, `confidence=HIGH`, matching `aisec-decode-budget-exceeded`'s
shape exactly (never a silent truncation, per this repo's own memory of the
~244s unbounded-pass hang).

| bound | value | rationale |
|---|---|---|
| `MODEL_MAX_ADMIT_BYTES` | 50 GB | walker-level sanity ceiling only (§1.2); not a content-scanning bound |
| `MAX_RAW_PICKLE_BYTES_SCANNED` | 50 MB | cap on bytes fed to `pickletools.genops()` for a non-container (bare `.pkl`/`.pth`-legacy/`.joblib`/`.dill`) file. A legitimate metadata-only pickle is almost always far under this; a multi-GB raw pickle is itself an anomaly worth disclosing, not silently truncating |
| `MAX_OPCODES_PER_STREAM` | 2,000,000 | belt-and-suspenders cap independent of the byte cap, against a pathological all-tiny-opcode stream engineered to inflate opcode count within the byte budget |
| `MAX_ZIP_MEMBERS_ENUMERATED` | 100,000 | cap on `infolist()` iteration — central-directory exhaustion guard (§3.5.2), metadata-only cost |
| `MAX_ZIP_MEMBERS_READ` | 20 | cap on how many members actually get `.open().read()` per archive — a real `.pt` needs exactly 1 (`data.pkl`); `.npz` header-peeking may need more; 20 covers realistic cases generously |
| `ZIP_MEMBER_MAX_COMPRESSION_RATIO` | 200:1 | metadata-only check (`file_size / compress_size`) before opening a member; standard zip-bomb heuristic order of magnitude |
| `MAX_ZIP_TOTAL_DECOMPRESSED_BYTES` | 100 MB | aggregate cap across every member actually read from one archive, defense-in-depth alongside the per-member ratio check |
| `NPY_HEADER_MAX_BYTES` | 4 KB | bound on how much of a `.npy`/`.npz`-member is read just to parse its ASCII header before deciding whether object-dtype content follows |
| `MODEL_HDF5_SCAN_BYTES` | 20 MB | bound on the raw-byte Lambda-signature search prefix (§3.3); explicitly a heuristic window, not "the whole file was checked" |

**Coverage findings emitted, mirroring the existing precedent exactly:**

- `model-scan-opcode-budget-exceeded` — hit `MAX_RAW_PICKLE_BYTES_SCANNED` or
  `MAX_OPCODES_PER_STREAM`; `snippet` carries
  `opcodes_processed=N; bytes_scanned=M` the same way
  `aisec-decode-budget-exceeded` reports `candidates_processed`/
  `decoded_bytes`.
- `model-scan-zip-bomb-guard-triggered` — a member exceeded
  `ZIP_MEMBER_MAX_COMPRESSION_RATIO` or the archive exceeded
  `MAX_ZIP_TOTAL_DECOMPRESSED_BYTES`/`MAX_ZIP_MEMBERS_ENUMERATED`/
  `MAX_ZIP_MEMBERS_READ`; names which member(s) were skipped.
- `model-scan-hdf5-heuristic-only` — unconditional, every HDF5-format file
  (§3.3), not a budget-exceeded case but the same "never claim more
  coverage than was actually performed" discipline.
- `model-scan-unrecognized-format` — admitted by extension, but neither
  ZIP/HDF5/`.npy` magic bytes nor a parseable pickle-opcode stream from byte
  0 (most relevant to `.bin`, the least specific extension in `MODEL_EXTS`).

All four are `category="COVERAGE"`, matching the existing convention exactly
so `interpret.py` and `report.py` need no new special-casing to route them —
they already treat `COVERAGE` findings as informational, non-suppressible-
by-lexctx (see `praetor.py`'s `_apply_lexical_context`/`_apply_reachability`,
both of which explicitly skip `category == "COVERAGE"` findings).

---

## 5. Where the code lives

### 5.1 Recommendation: a fifth engine, `scripts/engine_model.py`

Extending an existing engine was considered and rejected. `secrets` and
`aisec` share a `scan(scan_files, read_text)` shape because they both
consume **decoded text** — that abstraction is actively wrong for this
feature, which needs raw bytes, bounded reads, and ZIP-member-level access
that `core.read_text`'s UTF-8-decode-with-surrogatepass contract cannot
provide (feeding pickle opcode bytes through a text decoder would corrupt
them or raise). `sca` is architecturally about manifest files and external
tool subprocesses, not a fit either. A genuinely new capability with its own
file-selection mode (§1), its own binary-safe reading contract, and its own
container-format logic warrants its own module, matching this repo's
existing one-concern-per-engine convention.

**New core primitive needed:** `core.read_bytes(path, max_bytes) -> bytes`,
parallel in shape to `core.read_text` — bounded, `try/except OSError`
returning `b""` on failure, no decoding. `praetor.py`'s `main()` needs a
matching `unreadable_binary` accumulator and a `read_bytes` closure
recording failures the same way the existing `read_text` closure does via
`unreadable.append(...)`, feeding the same `_status_after_reading` pattern
so `engine_model` cannot report `ok` about a file it failed to open — this
is the identical discipline `_status_after_reading`'s own docstring states
("THE EXIT CODE IS THE GATE; THE STATUS IS WHAT A HUMAN READS... an engine
that then reports `ok` is claiming work it did not do"), just for a second,
binary-flavored reading contract.

### 5.2 Wiring changes, enumerated so none is missed

- `praetor.py`: `ALL_ENGINES = ["sast", "secrets", "sca", "aisec", "model"]`;
  `import engine_model`; a new `if "model" in engines:` block calling
  `engine_model.scan(model_files, read_bytes)`, structurally identical to
  the existing `secrets`/`aisec` blocks including the
  `_status_after_reading` wrapper.
- A new `model_files = core.walk_files(target, mode="model", ...) if "model"
  in engines else []` enumeration, gated behind engine selection exactly like
  the existing `secret_files` wide walk — for the same reason: an
  unconsumed enumeration is wasted cost (measured precedent:
  111,605 files walked in the secrets case "to produce a number nothing
  consumed").
- `meta.engines["model"]` needs a status among the existing vocabulary —
  `ENGINE_NOT_APPLICABLE` is the correct status when `len(model_files) == 0`
  (no model-shaped files exist in the target at all — a pure web-app repo),
  exactly mirroring how `sca` uses `not-applicable` for "no dependency
  manifests." Confirmed against `report.py`'s `_STATUS_MARKS`:
  `ENGINE_NOT_APPLICABLE` renders `[n/a]` and is a member of both
  `GATE_TRUSTED_STATUSES` and `NON_MALFUNCTION_STATUSES` in `core.py` — so a
  target with zero model files does not trip `--fail-on`'s degraded-scan
  check and does not render `[BLIND]`.
- `--engines` help text (`praetor.py` argparse) and the module docstring's
  engine table (lines 15-19) both need the fifth row.
- `tests/precommit.sh`'s self-scan gate (`EXPECT_ACTIVE=32`,
  `tests/precommit.sh:128` and the "no engine BLIND" check at
  `tests/precommit.sh:198-226`): PRAETOR's own repo has zero model files, so
  the new engine should report `not-applicable` on self-scan, which (per
  the confirmation above) is a non-blind status — the gate should pass
  without modification to `EXPECT_ACTIVE`/`EXPECT_FILTERED`, but this needs
  an actual self-scan run to confirm rather than reasoning alone, since
  `report.py`'s exact rendering is the authority, not this document.
- `tests/test_invariant_never_executes_target.py` gets its new assertion
  (§0) — this is not optional per the file's own stated design.
- **Public framing changes, all real and all necessary, not cosmetic:**
  `README.md`'s "four complementary security engines" (line 5) and "## The
  four engines" heading (line 31) and its `--engines` table
  (`sast,secrets,sca,aisec`, line 124) and `meta.engines` description
  (line 160); `praetor.py`'s own docstring (lines 5, 15-19); `CLAUDE.md`'s
  layout table (`scripts/engine_*.py` row already says "the four engines:
  `sast`, `secrets`, `sca`, `aisec`" and needs updating to five); and
  `pyproject.toml`'s `description` field (`"Multi-engine static security
  analysis (SAST, secrets, SCA, AI-security)..."`, and its
  `py-modules`/packaging list at line 57 which explicitly enumerates
  `engine_sast, engine_secrets, engine_sca, engine_aisec` and needs
  `engine_model` added or the wheel silently ships without it — this is the
  exact failure class `_find_bundled_rules()`'s own docstring warns about
  for rules-directory resolution, just for a module instead of a data file).

None of this is optional cleanup — an engine present in `ALL_ENGINES` but
absent from `pyproject.toml`'s module list would import successfully from a
git clone and silently fail to import from an installed wheel, which is
precisely the "looks fine in the repo, breaks in the distributed artifact"
shape this repo's packaging code already had to fix once for rules.

---

## 6. Test strategy

### 6.1 Position on committing an actually-malicious pickle: don't, generate at test time instead

A pickle byte stream sitting on disk containing `os.system` opcodes cannot
execute anything on its own — the invariant this whole repo rests on means
PRAETOR itself will never call `pickle.load()` on it, and a static `.pkl`
file is inert data by the same logic `CLAUDE.md`'s suppression section
already applies to a comment ("a comment cannot execute anything"). So
committing one would not, strictly, violate PRAETOR's own execution
invariant. That is not the same question as whether it is good practice for
a **public security-tool repository** to host a byte-for-byte working RCE
payload: a casual downloader could copy the file out of the repo and
`pickle.load()` it elsewhere without reading a word of context, and an
automated malware/antivirus scanner operating on the repo has no way to know
it is inert-by-construction test data.

**Recommendation, decisive: generate every fixture at test-collection time,
never commit one.** This is not a new pattern for this repo — it is the
identical discipline `engine_secrets.py`'s `KNOWN_EXAMPLES` already applies
("Assembled from parts so this source file itself carries no full token"),
generalized from string assembly to byte-stream generation. Concretely:

- **Positive fixture** (must fire): a small helper class whose `__reduce__`
  returns `(target_callable, args)` where `target_callable` is built the
  same assembled-from-parts way this repo already writes dangerous-shaped
  literals in test code (e.g. a module/name pair joined from two string
  parts, not typed as one literal), then `pickle.dumps(HelperInstance(),
  protocol=P)` for each protocol `P` in `{0, 1, 2, 3, 4, 5}` — this
  produces **real** `pickletools`-parseable opcode bytes for both the
  `GLOBAL` (protocols 0-3, and torch's own default 2) and `STACK_GLOBAL`
  (protocol 4-5) code paths, exercising the actual heuristic in §2.1 against
  genuine CPython pickle output rather than a hand-typed byte string that
  might not match what real `pickle.Pickler` actually emits.
- **Negative fixture** (must NOT fire): the identical construction, target
  swapped for an allowlisted shape — `collections.OrderedDict`,
  `torch._utils._rebuild_tensor_v2` (this can be fabricated as a bare
  `(module, name)` pair fed directly into a manually-assembled `GLOBAL`
  opcode via `pickletools` primitives, since `pickletools.genops()` never
  needs the referenced module to actually be importable — it disassembles
  syntax, not semantics, so `torch` need not even be installed in the test
  environment for this fixture to be valid input). This mirrors this
  repo's own established "mutate in both directions" testing discipline —
  assert the thing that must fire and the thing that must be kept quiet,
  not just one direction (`test_quotes_alone_do_not_suppress` is the named
  precedent for this shape in `praetor.py`'s own test suite).
- **Container-format fixtures** (`.pt`-shaped ZIP, `.npz`-shaped ZIP): build
  with `zipfile.ZipFile` in `io.BytesIO()`, writing a `data.pkl` member from
  one of the pickle fixtures above — again generated in memory at test time,
  never persisted as a binary blob under `tests/`.
- **Budget/bounds fixtures** (§4): generate an oversized opcode stream
  (e.g., thousands of trivial `POP`/`DUP`-shaped opcodes) and an
  intentionally high-ratio compressed ZIP member, both at test time, to
  exercise `model-scan-opcode-budget-exceeded` and
  `model-scan-zip-bomb-guard-triggered` without ever storing a real
  decompression bomb in the repository.

**Where generated bytes may touch disk at all:** only inside `pytest`'s
`tmp_path` fixture (an OS-temp-dir path, outside the repo tree by
construction) for any end-to-end test that invokes `praetor.py`'s CLI
against a real directory rather than calling `engine_model.scan()`
in-process. Nothing generated by this test suite is ever written under
`tests/`, `references/`, or any other tracked path — this is stricter than
even the existing "assemble from parts" secrets precedent requires, because
unlike a plaintext credential-shaped string (which is only a problem if
PRAETOR's *own* self-scan flags it as noise), a working pickle payload
committed to a tracked path is a distributable artifact the moment the repo
is cloned, which the KNOWN_EXAMPLES precedent does not have to worry about
for a string literal.

### 6.2 Why this fixture strategy carries no "detector self-noise" risk, unlike the existing text-based engines

`CLAUDE.md`'s "Writing tests for a detector adds noise to that detector"
section is about a **tracked file** containing an injection-shaped or
credential-shaped string that PRAETOR's own text-scanning self-scan then
flags. A pickle fixture generated at test-collection time and never written
to a tracked path is invisible to PRAETOR's self-scan by construction — it
never exists as a file in the repository at all, only as bytes in memory
(or a `tmp_path` file outside the tree) for the duration of one test. The
only way this class of noise could recur is if a future contributor
persists a generated fixture to a tracked path "for convenience" — worth a
one-line test-authoring note when this is built, not a structural risk of
the design itself.

---

## 7. What I could not fully determine from the code, stated plainly

- **`interpret.py`'s dedup-key logic** (`core.Finding.compute_dedup_key`)
  branches on `category == "VULNERABLE_DEPENDENCY"` / `"SECRET"` / else. This
  design proposes `category="SUPPLY_CHAIN"` for danger-list matches and
  `category="COVERAGE"` for the bound-disclosure findings, both of which
  fall into the generic `(file, line, cwe-or-rule_id)` dedup basis — I did
  not trace whether a model file's `line` number (an opcode's `pos` — a
  **byte offset** into the pickle stream, not a source line) interacting
  with that basis, or with `_apply_inline_ignores`'/`_apply_lexical_context`'s
  assumption that `f.line` indexes into `core.split_lines(read_text(...))`,
  produces a sensible or even safe result. `_apply_inline_ignores` and
  `_apply_lexical_context` both call `read_text` on the finding's file to
  resolve `f.line` against `\n`-split source — calling `core.read_text` on
  binary pickle/ZIP bytes would likely raise (per `core.read_text`'s own
  documented "raises on an invalid start byte, and that is the safe
  direction" behavior) or, worse, succeed on bytes that happen to be
  UTF-8-decodable-as-garbage and resolve `f.line` against nonsense. **This
  needs an explicit decision before implementation**: either give model
  findings a `line` value that deliberately means "byte offset, not source
  line" and exempt `engine="model"` findings from `_apply_inline_ignores`/
  `_apply_lexical_context`/`_apply_reachability` the same explicit way
  `secrets` is already exempted from lexctx/reachability (with the same
  kind of stated, tested reason — "a byte offset in a binary stream is not
  a source line a human can annotate with `# nosec`"), or map opcode
  position to something else entirely. I could not find precedent in the
  current code for a `Finding` whose `file` is not text-openable via
  `read_text`, so this is a real gap this design surfaces rather than
  resolves.
- **`redact_finding_snippet`** (`core.py`) runs every `Finding.snippet`
  through the secrets-provider redaction table at construction time
  (`Finding.__post_init__`). This should be harmless for model findings
  (snippets here are opcode/module names, not credential-shaped strings)
  but I did not verify there is no pathological interaction between a
  binary-derived snippet string and that regex table.
- **Whether `--exclude`'s regex should also gate model-file candidacy
  identically to text candidacy** — this design assumes yes (§1.2, the
  shared `_consider_file` exclude-regex clause applies unconditionally to
  both modes) but did not verify there is no existing operator expectation
  (documented or implied) that `--exclude` is text-scanning-specific.
- I did not investigate `interpret.py`'s ranking/priority logic in enough
  depth to state confidently how a CRITICAL `model` finding will sort
  relative to a CRITICAL `secrets` finding in the final report ordering —
  worth checking against real output once built, not asserted here.
