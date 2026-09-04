"""
PRAETOR serialized-model / pickle-opcode scanning engine (pure standard library).

Built from references/DESIGN-model-scanning.md -- read that document for the full
rationale; this docstring only orients a reader already inside the code.

🔴 THE INVARIANT, RESTATED FOR THIS ENGINE SPECIFICALLY (CLAUDE.md's header rule):
PRAETOR NEVER EXECUTES, IMPORTS, INSTALLS OR BUILDS THE CODE IT SCANS. This engine
is compatible with that only because of one stdlib fact: `pickletools.genops()`
walks a pickle byte stream opcode-by-opcode and returns `(opcode, arg, pos)`
tuples -- it never calls `pickle.load()`, never resolves a `GLOBAL` reference to
an actual importable object, and never instantiates anything. It disassembles the
way `objdump` disassembles a binary: syntactically, not semantically.
`pickletools.genops()` is the ONLY pickle-stream primitive this file uses.
`pickle.load`, `pickle.loads`, and `pickle.Unpickler` are never imported or
called here, against target-controlled bytes or anything else. NPY headers are
parsed with `ast.literal_eval`, never `eval`. See
tests/test_invariant_never_executes_target.py for the behavioural assertion.

WHAT THIS ENGINE DOES:
  * Classifies an admitted file by MAGIC BYTES (never by trusting the extension
    that got it admitted -- see core.model_candidate / MODEL_EXTS): ZIP
    container (.pt/.pth/.ckpt/.npz), HDF5 (.h5/.hdf5/.keras), raw .npy, or a
    pickle stream (bare .pkl/.pickle/.joblib/.dill, or the fallback attempt for
    anything else, including protocol 0/1 which has no fixed magic).
  * Disassembles pickle-shaped content with `pickletools.genops()` and matches
    every `GLOBAL` / `STACK_GLOBAL` / `INST` opcode's resolved (module, name)
    against a curated CRITICAL/HIGH/MEDIUM danger list (§2.3 of the design).
    Detection triggers at REFERENCE time, not at proven invocation -- a real ML
    checkpoint has zero legitimate reason to reference `os.system` at all,
    called or not (design §2.2).
  * For HDF5, runs a bounded, honestly-disclosed raw-byte heuristic for a Keras
    Lambda-layer signature -- NOT real HDF5 parsing (this repo ships zero
    third-party dependencies; h5py is not one of them).
  * Recognizes `.safetensors` as safe-by-design and emits nothing for it.
  * Never reads an unbounded amount of anything -- every read is capped (§4 of
    the design), and every cap that is actually hit produces a disclosed
    `COVERAGE` finding, never a silent truncation.

WHAT THIS ENGINE DELIBERATELY DOES NOT DO (false negatives accepted, stated
honestly per design §2.4): chase call-proof past `REDUCE`/`NEWOBJ`; track values
built through anything but a two-string-literal STACK_GLOBAL adjacency window;
parse HDF5 structurally; catch a dangerous callable absent from the denylist.
"""

from __future__ import annotations

import ast
import io
import os
import pickletools
import zipfile

from core import Finding, Severity, Confidence

# --------------------------------------------------------------------------- #
# References / classification constants
# --------------------------------------------------------------------------- #

CWE_DESERIALIZATION = "CWE-502"  # Deserialization of Untrusted Data
OWASP_MODEL = "A08:2021 Software and Data Integrity Failures"
REF_MODEL = [
    "https://cwe.mitre.org/data/definitions/502.html",
    "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
]

# --------------------------------------------------------------------------- #
# Resource bounds -- concrete numbers, from DESIGN-model-scanning.md §4.
# Every bound below produces a disclosed COVERAGE finding when hit, never a
# silent truncation -- matching aisec-decode-budget-exceeded's own shape.
# --------------------------------------------------------------------------- #

#: Cap on bytes fed to pickletools.genops() for a non-container pickle stream.
MAX_RAW_PICKLE_BYTES_SCANNED = 50 * 1024 * 1024  # 50 MB
#: Belt-and-suspenders cap independent of the byte cap, against a pathological
#: all-tiny-opcode stream engineered to inflate opcode count within budget.
MAX_OPCODES_PER_STREAM = 2_000_000
#: Central-directory exhaustion guard: metadata-only cost, cap on infolist().
MAX_ZIP_MEMBERS_ENUMERATED = 100_000
#: Cap on how many members actually get .open().read() per archive.
MAX_ZIP_MEMBERS_READ = 20
#: Standard zip-bomb heuristic: file_size / compress_size, metadata-only check.
ZIP_MEMBER_MAX_COMPRESSION_RATIO = 200
#: Aggregate cap across every member actually read from one archive.
MAX_ZIP_TOTAL_DECOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB
#: Bound on how much of a .npy (or .npz member) is read to parse its ASCII
#: header -- real headers are always small.
NPY_HEADER_MAX_BYTES = 4096
#: Bound on the raw-byte Lambda-signature search prefix for an HDF5 file.
MODEL_HDF5_SCAN_BYTES = 20 * 1024 * 1024  # 20 MB

_HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
_LAMBDA_SIGNATURES = (b'"class_name": "Lambda"', b'"class_name":"Lambda"')

# --------------------------------------------------------------------------- #
# Danger list -- severity is a function of WHICH global matched, never of "a
# GLOBAL opcode exists". See DESIGN-model-scanning.md §2.3 for the full table
# and rationale, and §2.4 for the honest false-positive/false-negative
# accounting. Matching is exact-pair, a per-module name-prefix (`os.spawn*`),
# or a full-module wildcard (`runpy.*`, `importlib.util.*`) -- never a bare
# "any GLOBAL fires".
# --------------------------------------------------------------------------- #

#: CRITICAL -- direct, unambiguous code execution, no further step needed.
_CRITICAL_EXACT = frozenset({
    ("os", "system"), ("os", "popen"),
    ("os", "execl"), ("os", "execv"), ("os", "execve"), ("os", "execvp"), ("os", "execvpe"),
    ("posix", "system"), ("nt", "system"),  # `os.system`'s REAL __module__ on Unix/Windows
    ("subprocess", "Popen"), ("subprocess", "call"), ("subprocess", "check_call"),
    ("subprocess", "check_output"), ("subprocess", "run"),
    ("builtins", "eval"), ("builtins", "exec"), ("builtins", "compile"),
    ("__builtin__", "eval"), ("__builtin__", "exec"), ("__builtin__", "compile"),  # py2-compat spelling
    ("ctypes", "CDLL"), ("ctypes", "cdll"), ("ctypes", "PyDLL"),
    ("ctypes", "windll"), ("ctypes", "oledll"),
    ("pty", "spawn"),
})
#: `os.spawn*` -- os.spawnl/spawnle/spawnlp/spawnlpe/spawnv/spawnve/spawnvp/spawnvpe.
#: Matched by module + name-prefix rather than enumerated one by one.
_CRITICAL_NAME_PREFIX = (("os", "spawn"),)
#: `runpy.*` -- a true wildcard: no legitimate reason a model checkpoint's
#: opcode stream references ANY attribute of a module whose entire purpose is
#: running code.
_CRITICAL_MODULE_WILDCARD = frozenset({"runpy"})

#: HIGH -- execution-adjacent primitives and published pickle gadget-chain
#: components (attrgetter/methodcaller are gadget-chain building blocks, not
#: execution primitives on their own -- included because they are the known
#: building blocks, per the design's own framing).
_HIGH_EXACT = frozenset({
    ("builtins", "__import__"), ("builtins", "globals"), ("builtins", "locals"), ("builtins", "vars"),
    ("__builtin__", "__import__"), ("__builtin__", "globals"), ("__builtin__", "locals"), ("__builtin__", "vars"),
    ("importlib", "import_module"),
    ("importlib._bootstrap", "_call_with_frames_removed"),
    ("socket", "socket"), ("socket", "create_connection"), ("socket", "fromfd"),
    ("shutil", "rmtree"), ("shutil", "move"),
    ("operator", "attrgetter"), ("operator", "methodcaller"),
})
_HIGH_MODULE_WILDCARD = frozenset({"importlib.util"})

#: MEDIUM -- dual-use, genuinely fuzzy. `getattr` is the fuzziest single entry
#: on the whole list (see design §2.3's own honest framing) -- kept at MEDIUM
#: rather than dropped because `__import__` (HIGH) followed by `getattr`
#: (MEDIUM) anywhere in the same stream is a recognizable gadget shape, even
#: though this engine does not attempt to detect the COMBINATION as its own
#: elevated finding (a real, named, undone refinement -- design §2.3).
_MEDIUM_EXACT = frozenset({
    ("builtins", "getattr"), ("__builtin__", "getattr"),
    ("shutil", "copy"), ("shutil", "copy2"), ("shutil", "copyfile"),
    ("webbrowser", "open"),
    ("urllib.request", "urlopen"),
    ("platform", "system"),
})


def _classify_global(module: str, qualname: str):
    """Return the Severity a (module, qualname) pair matches, or None."""
    pair = (module, qualname)
    if pair in _CRITICAL_EXACT or module in _CRITICAL_MODULE_WILDCARD:
        return Severity.CRITICAL
    if any(module == m and qualname.startswith(p) for m, p in _CRITICAL_NAME_PREFIX):
        return Severity.CRITICAL
    if pair in _HIGH_EXACT or module in _HIGH_MODULE_WILDCARD:
        return Severity.HIGH
    if pair in _MEDIUM_EXACT:
        return Severity.MEDIUM
    return None


#: Modules a real ML checkpoint's opcode stream legitimately references. Any
#: GLOBAL/STACK_GLOBAL target NEITHER on the danger list above NOR here earns
#: the low-severity "unknown global" disclosure (design §2.4) -- never a
#: silent pass, and never a denylist match either (this is a THIRD bucket).
_EXPECTED_BENIGN_MODULE_PREFIXES = (
    "torch", "numpy", "sklearn", "scipy", "joblib", "pandas", "xgboost",
    "lightgbm", "keras", "tensorflow", "collections", "collections.abc",
    "copyreg", "datetime", "decimal", "fractions", "array",
)
#: `builtins`/`__builtin__` are restricted to a SAFE-TYPE subset, not a blanket
#: pass -- `builtins.eval` must still hit the CRITICAL bucket above, and it is
#: checked first in `_classify_global`, so this allowlist is only ever
#: consulted for names the danger list did not already claim.
_SAFE_BUILTIN_NAMES = frozenset({
    "dict", "list", "tuple", "set", "frozenset", "bytes", "bytearray", "str",
    "int", "float", "complex", "bool", "slice", "object", "type", "property",
    "staticmethod", "classmethod",
})


def _is_expected_benign(module: str, qualname: str) -> bool:
    if module in ("builtins", "__builtin__"):
        return qualname in _SAFE_BUILTIN_NAMES
    return any(module == p or module.startswith(p + ".") for p in _EXPECTED_BENIGN_MODULE_PREFIXES)


_RULE_ID_BY_SEVERITY = {
    Severity.CRITICAL: "model-dangerous-global-critical",
    Severity.HIGH: "model-dangerous-global-high",
    Severity.MEDIUM: "model-dangerous-global-medium",
}

#: Opcodes whose `arg` is a decoded string-literal PUSH. Tracked to resolve
#: STACK_GLOBAL (protocol 4+), whose own `arg` is None -- the module and name
#: strings are pushed by two immediately preceding opcodes of this shape and
#: STACK_GLOBAL pops them. SHORT_BINSTRING/BINSTRING/UNICODE are the
#: protocol-0/1-compatible forms, included defensively even though
#: STACK_GLOBAL itself is protocol-4+-only. See design §2.1.
_STRING_LITERAL_OPS = frozenset({
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8",
    "UNICODE", "SHORT_BINSTRING", "BINSTRING",
})


def _as_text(arg) -> str:
    if isinstance(arg, bytes):
        return arg.decode("latin-1", "replace")
    return "" if arg is None else str(arg)


# --------------------------------------------------------------------------- #
# Pickle-opcode-stream disassembly
# --------------------------------------------------------------------------- #


class _StreamState:
    """Mutable scratch state threaded through one pickle stream's disassembly.

    `pending_strings` is the STACK_GLOBAL adjacency window (design §2.1): the
    last two string-literal pushes seen, cleared by anything except another
    string-literal push or MEMOIZE (a true no-op for stack shape -- it records
    top-of-stack into the memo table without popping).

    `disclosures` holds up to 10 unique (module, qualname, pos) triples for
    globals that matched NEITHER the danger list NOR the expected-benign
    allowlist -- design §2.4's Tier-2 bucket -- plus, folded into the SAME
    bucket, any STACK_GLOBAL the adjacency heuristic could not resolve
    (module=None). `overflow` records whether more than 10 existed.
    """

    __slots__ = ("findings", "pending_strings", "seen_pairs", "disclosures", "overflow")

    def __init__(self):
        self.findings: list = []
        self.pending_strings: list = []
        self.seen_pairs: set = set()
        self.disclosures: list = []  # (module_or_None, qualname_or_None, pos)
        self.overflow = False


def _danger_finding(rel, source_label, module, qualname, pos, severity):
    loc_note = f" (in {source_label})" if source_label else ""
    conf = Confidence.HIGH if severity in (Severity.CRITICAL, Severity.HIGH) else Confidence.MEDIUM
    return Finding(
        engine="model", rule_id=_RULE_ID_BY_SEVERITY[severity],
        title=f"Dangerous global referenced in pickle stream: {module}.{qualname}",
        severity=severity, confidence=conf,
        file=rel, line=pos, category="SUPPLY_CHAIN",
        description=(
            f"The pickle opcode stream{loc_note} references `{module}.{qualname}` at byte "
            f"offset {pos} of the pickle stream (NOT a source line -- a serialized model has "
            "no source text; this engine is exempted from PRAETOR's line-oriented suppression "
            "passes for exactly this reason). PRAETOR never resolves or calls this reference "
            "-- it is disassembled with pickletools.genops(), never pickle.load() -- but a "
            "real ML checkpoint has no legitimate reason to reference this callable AT ALL, "
            "called or not; the reference itself is the signal."
        ),
        snippet=f"GLOBAL {module}.{qualname}",
        fix=("Do not unpickle this file (directly, or via torch.load(weights_only=False), "
             "joblib.load, etc.) unless you fully trust its source. Prefer a safe format "
             "(.safetensors) or torch.load(weights_only=True) for a plain tensor state dict."),
        cwe=CWE_DESERIALIZATION, owasp=OWASP_MODEL, references=REF_MODEL,
    )


def _record_global(state: _StreamState, rel, source_label, module, qualname, pos):
    severity = _classify_global(module, qualname)
    if severity is not None:
        state.findings.append(_danger_finding(rel, source_label, module, qualname, pos, severity))
        return
    if _is_expected_benign(module, qualname):
        return
    key = (module, qualname)
    if key in state.seen_pairs:
        return
    state.seen_pairs.add(key)
    if len(state.disclosures) >= 10:
        state.overflow = True
        return
    state.disclosures.append((module, qualname, pos))


def _record_unresolved(state: _StreamState, pos):
    if len(state.disclosures) >= 10:
        state.overflow = True
        return
    state.disclosures.append((None, None, pos))


def _handle_opcode(state: _StreamState, rel, source_label, opcode_name, arg, pos):
    if opcode_name in _STRING_LITERAL_OPS:
        state.pending_strings.append(_as_text(arg))
        del state.pending_strings[:-2]  # keep only the last two
        return
    if opcode_name == "MEMOIZE":
        return  # true no-op for stack shape -- does not break the adjacency window
    if opcode_name in ("GLOBAL", "INST"):
        # arg IS the two-part "module name" string -- no stack tracking needed.
        mod, _, qual = (arg or "").partition(" ")
        _record_global(state, rel, source_label, mod, qual, pos)
        state.pending_strings = []
        return
    if opcode_name == "STACK_GLOBAL":
        if len(state.pending_strings) == 2:
            mod, qual = state.pending_strings
            _record_global(state, rel, source_label, mod, qual, pos)
        else:
            _record_unresolved(state, pos)
        state.pending_strings = []
        return
    # Anything else breaks the adjacency window -- this is what makes the
    # heuristic a heuristic: GET/BINGET, MARK, TUPLE*, etc. all clear it.
    state.pending_strings = []


def _finalize_disclosures(state: _StreamState, rel, source_label):
    loc_note = f" (in {source_label})" if source_label else ""
    for module, qualname, pos in state.disclosures:
        if module is None:
            state.findings.append(Finding(
                engine="model", rule_id="model-unknown-global-import",
                title="Unresolved STACK_GLOBAL reference in pickle stream",
                severity=Severity.LOW, confidence=Confidence.LOW,
                file=rel, line=pos, category="SUPPLY_CHAIN",
                description=(
                    f"A STACK_GLOBAL opcode{loc_note} at byte offset {pos} (not a source "
                    "line) could not be resolved to a (module, name) pair -- fewer than two "
                    "string-literal pushes immediately preceded it. This does not hide "
                    "WHETHER something unusual is happening in the stream, only WHAT it "
                    "targets; disclosed rather than silently dropped (design §2.4)."
                ),
                snippet="STACK_GLOBAL <unresolved>",
                fix="Inspect this pickle stream manually (pickletools.dis) to identify the actual target.",
                cwe=CWE_DESERIALIZATION, owasp=OWASP_MODEL, references=REF_MODEL,
            ))
        else:
            state.findings.append(Finding(
                engine="model", rule_id="model-unknown-global-import",
                title=f"Unrecognized global reference in pickle stream: {module}.{qualname}",
                severity=Severity.LOW, confidence=Confidence.LOW,
                file=rel, line=pos, category="SUPPLY_CHAIN",
                description=(
                    f"The pickle opcode stream{loc_note} references `{module}.{qualname}` at "
                    f"byte offset {pos} (not a source line), which is neither on PRAETOR's "
                    "dangerous-global denylist nor its expected-benign allowlist for ML "
                    "serialization (torch/numpy/sklearn/... and a safe subset of builtins). "
                    "This is a disclosure, not an accusation -- many legitimate custom "
                    "classes (e.g. a project's own model class) trigger it."
                ),
                snippet=f"GLOBAL {module}.{qualname}",
                fix=("Confirm this reference is expected for this file; an unexpected custom "
                     "global in a downloaded checkpoint is worth a manual look."),
                cwe=CWE_DESERIALIZATION, owasp=OWASP_MODEL, references=REF_MODEL,
            ))
    if state.overflow:
        state.findings.append(Finding(
            engine="model", rule_id="model-unknown-global-import-cap-exceeded",
            title="More than 10 unrecognized pickle globals (not all reported)",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            file=rel, line=1, category="COVERAGE",
            description=(
                "This file referenced more than 10 unique unrecognized globals (or "
                "unresolved STACK_GLOBAL targets); only the first 10 are reported "
                "individually."
            ),
            snippet="unique_unknown_globals>10",
            fix="Review the file manually for the complete list of referenced globals.",
            references=REF_MODEL,
        ))


def _budget_finding(rel, opcodes_processed, bytes_scanned, source_label=None):
    loc_note = f" ({source_label})" if source_label else ""
    return Finding(
        engine="model", rule_id="model-scan-opcode-budget-exceeded",
        title="Pickle-opcode disassembly stopped at the scan budget",
        severity=Severity.INFO, confidence=Confidence.HIGH,
        file=rel, line=1, category="COVERAGE",
        description=(
            f"This pickle stream{loc_note} exceeded PRAETOR's per-file scan budget "
            f"({MAX_RAW_PICKLE_BYTES_SCANNED} bytes / {MAX_OPCODES_PER_STREAM} opcodes). "
            "The remainder of the stream was NOT disassembled and was not scanned for "
            "dangerous globals."
        ),
        snippet=f"opcodes_processed={opcodes_processed}; bytes_scanned={bytes_scanned}",
        fix="This is usually a large, legitimate checkpoint; if the file is untrusted, inspect it manually beyond PRAETOR's budget.",
        references=REF_MODEL,
    )


def _unrecognized_format_finding(rel, reason, location=None):
    loc_note = f" ({location})" if location else ""
    return Finding(
        engine="model", rule_id="model-scan-unrecognized-format",
        title="Model file admitted by extension but not recognized by any parser",
        severity=Severity.INFO, confidence=Confidence.HIGH,
        file=rel, line=1, category="COVERAGE",
        description=(
            f"{reason}{loc_note}. This file was admitted for scanning because its extension "
            "is on PRAETOR's model-file list, but it did not match ZIP, HDF5, or .npy magic "
            "bytes and could not be disassembled as a pickle stream from byte 0. It was NOT "
            "scanned for dangerous content."
        ),
        snippet=reason[:200],
        fix="Confirm this is actually a serialized-model file; if it is a format PRAETOR does not yet understand, treat it as unscanned, not as clean.",
        references=REF_MODEL,
    )


def _zip_bomb_guard_finding(rel):
    return Finding(
        engine="model", rule_id="model-scan-zip-bomb-guard-triggered",
        title="ZIP-container scan bounds triggered (possible zip bomb, or a very large archive)",
        severity=Severity.INFO, confidence=Confidence.HIGH,
        file=rel, line=1, category="COVERAGE",
        description=(
            "One or more of this archive's members exceeded PRAETOR's compression-ratio "
            f"({ZIP_MEMBER_MAX_COMPRESSION_RATIO}:1), aggregate decompressed-bytes "
            f"({MAX_ZIP_TOTAL_DECOMPRESSED_BYTES} bytes), or member-count "
            f"({MAX_ZIP_MEMBERS_READ} read / {MAX_ZIP_MEMBERS_ENUMERATED} enumerated) bound. "
            "Some member(s) were skipped or truncated rather than decompressed in full."
        ),
        snippet="zip_bomb_guard=triggered",
        fix="If this archive is untrusted, inspect it manually with a bounded, memory-safe tool rather than a naive extractall().",
        references=REF_MODEL,
    )


def _disassemble_pickle_bytes(data: bytes, rel: str, truncated: bool, source_label=None) -> list:
    """Disassemble `data` as a pickle opcode stream via pickletools.genops()
    ONLY -- never pickle.load()/loads()/Unpickler. `truncated` says whether
    `data` is already known to be less than the real stream (our own byte
    cap), which decides whether a mid-stream parse failure is reported as a
    budget disclosure (expected: we cut it off) or a genuine unrecognized-
    format disclosure (not expected: the whole stream was available and still
    did not parse).
    """
    state = _StreamState()
    stream = io.BytesIO(data)
    opcode_count = 0
    budget_exceeded = truncated
    parse_error = False
    try:
        for opcode, arg, pos in pickletools.genops(stream):
            opcode_count += 1
            if opcode_count > MAX_OPCODES_PER_STREAM:
                budget_exceeded = True
                break
            _handle_opcode(state, rel, source_label, opcode.name, arg, pos)
    except Exception:
        if truncated:
            budget_exceeded = True
        else:
            parse_error = True

    _finalize_disclosures(state, rel, source_label)

    if budget_exceeded:
        state.findings.append(_budget_finding(rel, opcode_count, len(data), source_label))
    elif parse_error:
        state.findings.append(_unrecognized_format_finding(
            rel, f"pickle-opcode stream could not be fully disassembled (stopped after {opcode_count} opcode(s))",
            location=source_label))
    return state.findings


# --------------------------------------------------------------------------- #
# .npy / .npz -- object-dtype pickle content only; a plain numeric array
# carries no pickle stream at all. See design §3.2.
# --------------------------------------------------------------------------- #


def _parse_npy_header(data: bytes):
    """Parse a bounded NPY prefix's ASCII header with ast.literal_eval (never
    eval). Returns (header_dict, header_end_offset, ok)."""
    if not data.startswith(b"\x93NUMPY") or len(data) < 10:
        return None, 0, False
    try:
        major = data[6]
        if major == 1:
            hlen = int.from_bytes(data[8:10], "little")
            header_start = 10
        else:
            if len(data) < 12:
                return None, 0, False
            hlen = int.from_bytes(data[8:12], "little")
            header_start = 12
        header_end = header_start + hlen
        if header_end > len(data):
            return None, 0, False  # header itself exceeded our bounded read
        header_str = data[header_start:header_end].decode("latin-1")
        header_dict = ast.literal_eval(header_str.strip())
        if not isinstance(header_dict, dict):
            return None, 0, False
        return header_dict, header_end, True
    except Exception:
        return None, 0, False


def _scan_npy_bytes(data: bytes, rel: str, full_size: int, source_label=None) -> list:
    header, header_end, ok = _parse_npy_header(data)
    if not ok:
        return [_unrecognized_format_finding(
            rel, "could not parse .npy ASCII header within the bounded prefix", location=source_label)]
    descr = header.get("descr") if isinstance(header, dict) else None
    is_object = isinstance(descr, str) and (
        descr.strip("'\" ") in ("|O", "|O8") or "object" in descr.lower()
    )
    if not is_object:
        return []  # ordinary numeric array; no pickle content, nothing more to scan
    payload = data[header_end:]
    truncated = full_size > len(data)
    return _disassemble_pickle_bytes(payload, rel, truncated, source_label=source_label)


def _scan_npy(sf, read_bytes) -> list:
    data = read_bytes(sf.abspath, NPY_HEADER_MAX_BYTES + MAX_RAW_PICKLE_BYTES_SCANNED)
    if not data:
        return []
    return _scan_npy_bytes(data, sf.relpath, sf.size, source_label=None)


# --------------------------------------------------------------------------- #
# ZIP containers -- .pt/.pth/.ckpt (data.pkl member) and .npz (.npy members).
# Bounded, in-memory only, never extracted to disk. See design §3.1/§3.5.
# --------------------------------------------------------------------------- #


def _scan_zip_container(sf) -> list:
    findings: list = []
    try:
        zf = zipfile.ZipFile(sf.abspath)
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        return [_unrecognized_format_finding(
            sf.relpath, f"admitted as ZIP by magic bytes but could not be opened: {exc}")]

    bomb_guard = False
    with zf:
        try:
            infolist = zf.infolist()
        except (zipfile.BadZipFile, OSError) as exc:
            return [_unrecognized_format_finding(
                sf.relpath, f"could not read ZIP central directory: {exc}")]

        if len(infolist) > MAX_ZIP_MEMBERS_ENUMERATED:
            bomb_guard = True
            infolist = infolist[:MAX_ZIP_MEMBERS_ENUMERATED]

        # torch.save's data.pkl (any enclosing directory name) and .npz's .npy
        # members are the ONLY members ever opened -- every tensor-storage blob
        # in a real .pt/.pth/.ckpt is never opened, by design (§3.1 point 4).
        data_pkl_members = [zi for zi in infolist if os.path.basename(zi.filename) == "data.pkl"]
        npy_members = [zi for zi in infolist if zi.filename.lower().endswith(".npy")]
        candidates = data_pkl_members + npy_members

        if len(candidates) > MAX_ZIP_MEMBERS_READ:
            bomb_guard = True
        candidates = candidates[:MAX_ZIP_MEMBERS_READ]

        total_decompressed = 0
        for zi in candidates:
            ratio = zi.file_size / max(1, zi.compress_size)
            if ratio > ZIP_MEMBER_MAX_COMPRESSION_RATIO:
                bomb_guard = True
                continue
            if total_decompressed >= MAX_ZIP_TOTAL_DECOMPRESSED_BYTES:
                bomb_guard = True
                break
            is_pkl = os.path.basename(zi.filename) == "data.pkl"
            cap = MAX_RAW_PICKLE_BYTES_SCANNED if is_pkl else (NPY_HEADER_MAX_BYTES + MAX_RAW_PICKLE_BYTES_SCANNED)
            read_cap = min(cap, MAX_ZIP_TOTAL_DECOMPRESSED_BYTES - total_decompressed)
            try:
                with zf.open(zi.filename) as member:
                    data = member.read(read_cap)  # bounded even if metadata lied (§3.5)
            except (zipfile.BadZipFile, OSError) as exc:
                findings.append(_unrecognized_format_finding(
                    sf.relpath, f"could not read member: {exc}", location=zi.filename))
                continue
            total_decompressed += len(data)
            if is_pkl:
                truncated = zi.file_size > len(data)
                findings.extend(_disassemble_pickle_bytes(data, sf.relpath, truncated, source_label=zi.filename))
            else:
                findings.extend(_scan_npy_bytes(data, sf.relpath, zi.file_size, source_label=zi.filename))

        if not data_pkl_members and not npy_members:
            findings.append(_unrecognized_format_finding(
                sf.relpath, "ZIP container admitted by extension but no data.pkl or .npy member was found"))

    if bomb_guard:
        findings.append(_zip_bomb_guard_finding(sf.relpath))
    return findings


# --------------------------------------------------------------------------- #
# HDF5 -- bounded heuristic only, never real parsing. See design §3.3.
# --------------------------------------------------------------------------- #


def _scan_hdf5(sf, read_bytes) -> list:
    findings: list = []
    data = read_bytes(sf.abspath, MODEL_HDF5_SCAN_BYTES)
    if any(sig in data for sig in _LAMBDA_SIGNATURES):
        findings.append(Finding(
            engine="model", rule_id="keras-lambda-layer",
            title="Keras Lambda layer signature found in HDF5 model file",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=sf.relpath, line=1, category="SUPPLY_CHAIN",
            description=(
                "A raw-byte search found the JSON signature for a Keras Lambda layer "
                "(\"class_name\": \"Lambda\") in this HDF5 file. A Lambda layer's `function` "
                "field can carry an arbitrary-code-executing serialized callable (historically "
                "Python `marshal`-serialized bytecode, not pickle), evaluated on model load. "
                "This is a raw substring match against file bytes, not a parsed/verified "
                "payload -- PRAETOR has no HDF5 parser (see the coverage disclosure below)."
            ),
            snippet='"class_name": "Lambda"',
            fix=("Do not load this model with a Lambda layer unless you fully trust its "
                 "source; prefer safe_mode=True (Keras 3) or migrate away from Lambda layers "
                 "to a serializable, non-code layer."),
            cwe=CWE_DESERIALIZATION, owasp=OWASP_MODEL, references=REF_MODEL,
        ))
    # Unconditional -- every HDF5-format file, hit or not. Per CLAUDE.md's own
    # suppression discipline: never let a clean result here look identical to
    # a genuinely-parsed clean HDF5 file.
    findings.append(Finding(
        engine="model", rule_id="model-scan-hdf5-heuristic-only",
        title="HDF5 structural parsing is not implemented (bounded heuristic only)",
        severity=Severity.INFO, confidence=Confidence.HIGH,
        file=sf.relpath, line=1, category="COVERAGE",
        description=(
            "PRAETOR has no HDF5 parser (h5py is a third-party, compiled dependency and this "
            "repo ships zero third-party dependencies by design). Only a bounded raw-byte "
            f"search across the first {MODEL_HDF5_SCAN_BYTES} bytes for a Keras Lambda-layer "
            "JSON signature was performed. A compressed, chunked, or otherwise non-adjacent "
            "attribute would NOT be found by this search."
        ),
        snippet=f"scanned_bytes<={MODEL_HDF5_SCAN_BYTES}",
        fix="Do not treat a clean result here as a verified-safe HDF5 file; inspect with h5py/keras directly if the source is untrusted.",
        references=REF_MODEL,
    ))
    return findings


# --------------------------------------------------------------------------- #
# Engine entry
# --------------------------------------------------------------------------- #


def _scan_one_file(sf, read_bytes) -> list:
    ext = os.path.splitext(sf.relpath)[1].lower()
    if ext == ".safetensors":
        # Safe by design: a flat JSON header + raw tensor bytes, no
        # code-execution path of any kind, no pickle stream ever. Recognized
        # positively so it produces neither a finding NOR an "unrecognized
        # format" disclosure -- design §3.4.
        return []

    prefix = read_bytes(sf.abspath, 16)
    if not prefix:
        return []  # unreadable (permissions, race, zero-byte file) -- nothing to scan

    if prefix.startswith(_ZIP_MAGICS):
        return _scan_zip_container(sf)
    if prefix.startswith(_HDF5_MAGIC):
        return _scan_hdf5(sf, read_bytes)
    if prefix.startswith(b"\x93NUMPY"):
        return _scan_npy(sf, read_bytes)

    # Everything else: attempt raw pickle disassembly regardless of whether a
    # \x80 protocol-2+ marker is present. pickletools.genops() does not
    # require a fixed magic -- a protocol 0/1 pickle opens with an ordinary
    # opcode byte (MARK, GLOBAL, ...), not a magic number -- so there is no
    # separate code path for "recognized protocol marker" vs "unrecognized
    # magic": both attempt disassembly from byte 0, and both disclose
    # honestly (never silently pass) if it fails. This collapses the last two
    # rows of design §1.3's magic-byte table into one code path deliberately
    # -- see this file's own header note on where the design and the build
    # diverged.
    data = read_bytes(sf.abspath, MAX_RAW_PICKLE_BYTES_SCANNED)
    if not data:
        return []
    truncated = sf.size > len(data)
    return _disassemble_pickle_bytes(data, sf.relpath, truncated)


def scan(scan_files, read_bytes) -> list:
    """Engine entry point. `scan_files` is a list of core.ScanFile (from
    `core.walk_files(target, mode="model")`); `read_bytes` is a
    `(path, max_bytes) -> bytes` closure -- see core.read_bytes and
    praetor.py's own wrapper around it.
    """
    findings: list = []
    for sf in scan_files:
        try:
            findings.extend(_scan_one_file(sf, read_bytes))
        except Exception as exc:  # noqa -- never let one malformed file blind the whole engine
            findings.append(Finding(
                engine="model", rule_id="model-scan-unrecognized-format",
                title="Model file could not be scanned",
                severity=Severity.INFO, confidence=Confidence.HIGH,
                file=sf.relpath, line=1, category="COVERAGE",
                description=(
                    f"An unexpected error occurred while scanning this file: "
                    f"{type(exc).__name__}: {exc}. It was NOT scanned for dangerous content."
                ),
                snippet=f"{type(exc).__name__}",
                fix="Investigate manually; PRAETOR could not process this file's format.",
                references=REF_MODEL,
            ))
    return findings
