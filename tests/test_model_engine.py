"""
Tests for `scripts/engine_model.py` -- serialized-model / pickle-opcode scanning.

Built against references/DESIGN-model-scanning.md §6: every fixture here is
generated at test-collection/run time via REAL `pickle.dumps()` (or hand-built
opcode bytes fed through the real `pickletools.genops()`), never a binary blob
committed to this repo. A working pickle payload committed to a tracked path is
a distributable artifact the moment the repo is cloned -- see the design's §6.1
for why that is a stricter bar than the existing `KNOWN_EXAMPLES` string-assembly
precedent in engine_secrets.py, which this file follows for the same reason
CLAUDE.md's "Writing tests for a detector adds noise to that detector" section
requires: dangerous-shaped module/name literals are assembled from string parts,
not typed as one literal, so this file's own source does not read as a hardcoded
`os.system` reference to a casual grep (or to PRAETOR's own self-scan).

Nothing here ever calls `pickle.load`, `pickle.loads`, or `pickle.Unpickler` --
only `pickle.dumps()` (to PRODUCE bytes) and `pickletools.genops()` /
`engine_model.scan()` (to DISASSEMBLE them). `test_never_executes_a_reduce_payload`
below is the behavioural proof.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import pickle
import pickletools
import struct
import zipfile

import pytest

import core
import engine_model
import praetor


# --------------------------------------------------------------------------- #
# Fixture helpers -- assembled from parts, generated at test time, never
# persisted to a tracked path. See this file's own header.
# --------------------------------------------------------------------------- #


def _os_system():
    """The real `os.system` builtin, reached only by string-assembled attribute
    lookup so this source file carries no literal `os.system` token."""
    mod = "o" + "s"
    name = "sys" + "tem"
    return getattr(__import__(mod), name)


class _DangerousReduce:
    """A `__reduce__` target used ONLY to make `pickle.dumps()` emit real
    GLOBAL/STACK_GLOBAL opcodes referencing a CRITICAL-tier callable.

    `pickle.dumps()` calls `__reduce__()` to learn WHAT to serialize; it never
    calls the callable `__reduce__()` returns. Only `pickle.load()` -- which
    this engine and this test file both never call -- would do that. This is
    the same distinction `references/DESIGN-model-scanning.md` §6.1 makes:
    static pickle bytes are inert data, the same way an inert remote-exec
    pipe quoted inside a comment cannot itself execute anything (see
    CLAUDE.md's suppression section) -- NOT typed as one literal here either,
    per this repo's own "fix the fixture, not the rules" instruction: this
    exact docstring tripped aisec's own remote-exec-pipe rule once already
    when it spelled the pattern out directly.
    """

    def __reduce__(self):
        return (_os_system(), ("echo hi",))


class _BenignReduce:
    """A `__reduce__` target on an ALLOWLISTED module (`collections`), used to
    build a genuinely benign real pickle for the negative direction."""

    def __reduce__(self):
        import collections
        return (collections.OrderedDict, ([("a", 1), ("b", 2)],))


def _fabricated_global_opcode(module: str, qualname: str) -> bytes:
    """Hand-build ONE protocol-0 GLOBAL opcode's bytes for (module, qualname).

    `pickletools.genops()` disassembles SYNTAX, not semantics -- per design
    §6.1 it never needs the referenced module to actually be importable, so
    this is valid input without `torch`/`numpy` installed in the test
    environment. Verified against real pickletools.genops() output before
    being relied on here (module/qualname round-trip exactly).
    """
    return b"c" + module.encode("ascii") + b"\n" + qualname.encode("ascii") + b"\n"


def _stack_global_stream(module: str, qualname: str) -> bytes:
    """Hand-build a minimal protocol-4 SHORT_BINUNICODE/SHORT_BINUNICODE/
    STACK_GLOBAL/STOP stream -- the real shape `torch.save`'s default
    protocol-4+ writers emit, and the ONLY way STACK_GLOBAL's arg-less opcode
    can be exercised without a real object graph.
    """
    mb, qb = module.encode("ascii"), qualname.encode("ascii")
    return (
        b"\x80\x04"
        + b"\x8c" + bytes([len(mb)]) + mb
        + b"\x8c" + bytes([len(qb)]) + qb
        + b"\x93"
        + b"."
    )


def _npy_bytes(header_dict_literal: str, payload: bytes, version=(1, 0)) -> bytes:
    """Hand-build a minimal, spec-correct .npy file: magic + version + header
    length + ASCII header + payload. No numpy import required."""
    header = header_dict_literal
    major, minor = version
    if major == 1:
        prefix_len = 10
        pad = (64 - (prefix_len + len(header) + 1) % 64) % 64
        header = header + " " * pad + "\n"
        head = b"\x93NUMPY" + bytes([major, minor]) + struct.pack("<H", len(header))
    else:
        prefix_len = 12
        pad = (64 - (prefix_len + len(header) + 1) % 64) % 64
        header = header + " " * pad + "\n"
        head = b"\x93NUMPY" + bytes([major, minor]) + struct.pack("<I", len(header))
    return head + header.encode("latin-1") + payload


class _SF:
    """Minimal stand-in for core.ScanFile -- engine_model only reads
    .abspath/.relpath/.size."""

    def __init__(self, path):
        self.abspath = str(path)
        self.relpath = os.path.basename(str(path))
        self.size = os.path.getsize(path)


def _scan_bytes(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return engine_model.scan([_SF(p)], core.read_bytes)


def _rule_ids(findings):
    return sorted(f.rule_id for f in findings)


# --------------------------------------------------------------------------- #
# 1. Danger-list detection -- the core positive direction.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("protocol", [0, 1, 2, 3, 4, 5])
def test_dangerous_global_fires_critical_across_all_pickle_protocols(tmp_path, protocol):
    """CRITICAL global reference (os.system-shaped) must fire at every pickle
    protocol -- 0/1 via GLOBAL, 2/3 via GLOBAL, 4/5 via STACK_GLOBAL. This is
    the single test the mutation step (breaking the danger-list check) must
    turn red for every parametrization.
    """
    data = pickle.dumps(_DangerousReduce(), protocol=protocol)
    findings = _scan_bytes(tmp_path, f"danger_{protocol}.pkl", data)
    critical = [f for f in findings if f.rule_id == "model-dangerous-global-critical"]
    assert critical, f"protocol {protocol}: no CRITICAL finding; findings were {_rule_ids(findings)}"
    assert critical[0].severity == core.Severity.CRITICAL
    assert critical[0].category == "SUPPLY_CHAIN"
    assert critical[0].engine == "model"
    # `os.system`'s REAL __module__ is platform-specific (nt/posix), and the
    # danger list carries both -- confirm we matched via the module the real
    # interpreter actually produced, not a hardcoded guess.
    assert "system" in critical[0].title


def test_dangerous_global_fires_high_severity(tmp_path):
    """HIGH tier: a published pickle gadget-chain component, not a direct
    execution primitive (operator.attrgetter)."""
    data = _fabricated_global_opcode("operator", "attrgetter") + b"."
    findings = _scan_bytes(tmp_path, "high.pkl", data)
    high = [f for f in findings if f.rule_id == "model-dangerous-global-high"]
    assert high, f"no HIGH finding; findings were {_rule_ids(findings)}"
    assert high[0].severity == core.Severity.HIGH


def test_dangerous_global_fires_medium_severity(tmp_path):
    """MEDIUM tier: the fuzziest entry on the whole list (builtins.getattr)."""
    data = _fabricated_global_opcode("builtins", "getattr") + b"."
    findings = _scan_bytes(tmp_path, "medium.pkl", data)
    medium = [f for f in findings if f.rule_id == "model-dangerous-global-medium"]
    assert medium, f"no MEDIUM finding; findings were {_rule_ids(findings)}"
    assert medium[0].severity == core.Severity.MEDIUM


def test_stack_global_resolves_via_two_adjacent_string_literals(tmp_path):
    """The STACK_GLOBAL adjacency heuristic itself (design §2.1), independent
    of any real object graph: two SHORT_BINUNICODE pushes immediately
    followed by STACK_GLOBAL must resolve to (module, qualname)."""
    data = _stack_global_stream("subprocess", "Popen")
    findings = _scan_bytes(tmp_path, "stack_global.pkl", data)
    critical = [f for f in findings if f.rule_id == "model-dangerous-global-critical"]
    assert critical, f"STACK_GLOBAL did not resolve; findings were {_rule_ids(findings)}"


def test_memoized_reuse_of_a_dangerous_global_is_still_caught_once(tmp_path):
    """Design §2.2 point 4: detection is memo-independent. Push the dangerous
    global once, then reuse it via GET/BINGET -- the danger-list match must
    still have fired at the introduction point (GET/BINGET carries no module/
    name of its own, so nothing MORE should fire, but nothing should be lost
    either)."""
    body = (
        b"c" + b"os" + b"\n" + b"system" + b"\n"
        + b"q\x00"     # BINPUT 0 -- memoize the GLOBAL just pushed
        + b"h\x00"     # BINGET 0 -- reuse it (no new GLOBAL/STACK_GLOBAL opcode)
        + b"."
    )
    findings = _scan_bytes(tmp_path, "memo.pkl", body)
    critical = [f for f in findings if f.rule_id == "model-dangerous-global-critical"]
    assert len(critical) == 1, f"expected exactly one CRITICAL finding, got {_rule_ids(findings)}"


# --------------------------------------------------------------------------- #
# 2. The negative direction -- ordinary ML serialization must NOT fire.
# --------------------------------------------------------------------------- #


def test_benign_pytorch_shaped_pickle_does_not_fire(tmp_path):
    """A pickle referencing collections.OrderedDict, numpy, and torch globals
    -- the shape of an ordinary PyTorch checkpoint's data.pkl -- must produce
    ZERO findings. `torch`/`numpy` need not be installed (see
    `_fabricated_global_opcode`'s own docstring)."""
    data = (
        _fabricated_global_opcode("collections", "OrderedDict")
        + _fabricated_global_opcode("numpy.core.multiarray", "_reconstruct")
        + _fabricated_global_opcode("torch._utils", "_rebuild_tensor_v2")
        + b"."
    )
    findings = _scan_bytes(tmp_path, "benign_shape.pkl", data)
    assert findings == [], f"benign PyTorch-shaped pickle produced findings: {_rule_ids(findings)}"


def test_real_ordereddict_reduce_does_not_fire(tmp_path):
    """The same negative direction via a REAL `pickle.dumps()` call (not a
    hand-built opcode stream) -- confirms genuine CPython pickle output for a
    stdlib-allowlisted class stays silent."""
    data = pickle.dumps(_BenignReduce(), protocol=4)
    findings = _scan_bytes(tmp_path, "real_benign.pkl", data)
    assert findings == [], f"real OrderedDict-reduce pickle produced findings: {_rule_ids(findings)}"


def test_safe_builtin_types_are_not_flagged(tmp_path):
    """`builtins.dict`/`list`/etc. are on the safe-type subset -- distinct
    from `builtins.eval`/`getattr`, which must still fire (see above)."""
    data = _fabricated_global_opcode("builtins", "dict") + b"."
    findings = _scan_bytes(tmp_path, "safe_builtin.pkl", data)
    assert findings == []


# --------------------------------------------------------------------------- #
# 3. THE INVARIANT -- PRAETOR never executes what it disassembles.
# --------------------------------------------------------------------------- #


def test_never_executes_a_reduce_payload_that_would_touch_the_filesystem(tmp_path):
    """Behavioural proof, not a code-review claim: a `__reduce__` payload
    whose invocation WOULD create a sentinel file must never actually create
    it when scanned. If `engine_model` ever called `pickle.load()` on this
    fixture, the sentinel would exist after `scan()` returns; it must not.
    """
    sentinel = tmp_path / "SENTINEL_MUST_NOT_EXIST"

    class _TouchSentinel:
        def __reduce__(self):
            mod = "o" + "s"
            name = "sys" + "tem"
            # `type nul >` is the Windows-portable equivalent of `touch`; this
            # process is running on Windows, and the whole point is that this
            # command must NEVER actually run.
            cmd = f'type nul > "{sentinel}"'
            return (getattr(__import__(mod), name), (cmd,))

    data = pickle.dumps(_TouchSentinel(), protocol=4)
    findings = _scan_bytes(tmp_path, "would_touch.pkl", data)

    assert not sentinel.exists(), (
        "INVARIANT VIOLATION: engine_model executed the pickle payload it was "
        "meant only to disassemble."
    )
    assert any(f.rule_id == "model-dangerous-global-critical" for f in findings), (
        "the payload should still have been DETECTED even though it must never RUN"
    )


def test_engine_module_never_imports_pickle_load_family():
    """Static guard alongside the behavioural one above: this module's own
    CODE (not its prose -- the module docstring and comments legitimately
    NAME `pickle.load` while explaining why it is never called, the same way
    this test file's own header does) must never actually reference the
    banned unpickling entry points. Mirrors
    tests/test_invariant_never_executes_target.py's own style for a NEW
    engine, per that file's and CLAUDE.md's explicit instruction that every
    new engine/backend widens the never-execute surface and must add its own
    assertion here.

    Parses the real AST rather than substring-matching source text -- a naive
    `"pickle.load" not in src` check is exactly the lexctx-blind-spot class
    this repo has been bitten by before (a prose MENTION is not a CALL), and
    it fired on this very module's own docstring during authoring.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(engine_model))
    banned_attrs = {"load", "loads", "Unpickler"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in banned_attrs:
            pytest.fail(f"engine_model.py CODE references banned attribute: .{node.attr}")
        if isinstance(node, ast.Name) and node.id in banned_attrs:
            pytest.fail(f"engine_model.py CODE references banned name: {node.id}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "import_module":
                pytest.fail("engine_model.py CODE calls importlib.import_module")
    # `import pickletools` (never `import pickle`) is the only pickle-family
    # import this module should have at all.
    top_level_imports = {
        alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "pickle" not in top_level_imports, "engine_model.py must never `import pickle` -- only pickletools"


# --------------------------------------------------------------------------- #
# 4. Container formats -- ZIP-wrapped .pt/.pth/.ckpt (data.pkl) and .npz.
# --------------------------------------------------------------------------- #


def test_zip_wrapped_pt_shaped_container_finds_dangerous_data_pkl(tmp_path):
    data = pickle.dumps(_DangerousReduce(), protocol=2)
    pt_path = tmp_path / "model.pt"
    with zipfile.ZipFile(pt_path, "w") as zf:
        zf.writestr("archive/data.pkl", data)
        zf.writestr("archive/data/0", b"\x00" * 64)  # tensor storage -- never opened
    findings = engine_model.scan([_SF(pt_path)], core.read_bytes)
    assert any(f.rule_id == "model-dangerous-global-critical" for f in findings)


def test_zip_wrapped_container_benign_data_pkl_is_silent(tmp_path):
    data = pickle.dumps(_BenignReduce(), protocol=2)
    pt_path = tmp_path / "clean.pt"
    with zipfile.ZipFile(pt_path, "w") as zf:
        zf.writestr("archive/data.pkl", data)
    findings = engine_model.scan([_SF(pt_path)], core.read_bytes)
    assert findings == []


def test_npz_object_dtype_member_fires(tmp_path):
    npy = _npy_bytes(
        "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }",
        pickle.dumps(_DangerousReduce(), protocol=2),
    )
    npz_path = tmp_path / "danger.npz"
    with zipfile.ZipFile(npz_path, "w") as zf:
        zf.writestr("arr_0.npy", npy)
    findings = engine_model.scan([_SF(npz_path)], core.read_bytes)
    assert any(f.rule_id == "model-dangerous-global-critical" for f in findings)


def test_npz_numeric_members_are_silent(tmp_path):
    npy = _npy_bytes(
        "{'descr': '<f8', 'fortran_order': False, 'shape': (2,), }",
        struct.pack("<2d", 1.0, 2.0),
    )
    npz_path = tmp_path / "clean.npz"
    with zipfile.ZipFile(npz_path, "w") as zf:
        zf.writestr("arr_0.npy", npy)
        zf.writestr("arr_1.npy", npy)
    findings = engine_model.scan([_SF(npz_path)], core.read_bytes)
    assert findings == []


def test_zip_container_with_no_recognized_member_discloses_unrecognized_format(tmp_path):
    """A ZIP admitted by extension but containing neither `data.pkl` nor any
    `.npy` member must be disclosed, not silently passed."""
    empty_path = tmp_path / "empty.pt"
    with zipfile.ZipFile(empty_path, "w") as zf:
        zf.writestr("archive/storages/0", b"raw tensor bytes, not pickle-shaped")
    findings = engine_model.scan([_SF(empty_path)], core.read_bytes)
    assert any(f.rule_id == "model-scan-unrecognized-format" and f.category == "COVERAGE"
               for f in findings)


def test_zip_bomb_guard_triggers_on_high_compression_ratio_member(tmp_path):
    bomb_path = tmp_path / "bomb.pt"
    with zipfile.ZipFile(bomb_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("archive/data.pkl", b"\x00" * (5 * 1024 * 1024))
    findings = engine_model.scan([_SF(bomb_path)], core.read_bytes)
    assert any(f.rule_id == "model-scan-zip-bomb-guard-triggered" and f.category == "COVERAGE"
               for f in findings)


def test_zip_never_extracts_to_disk(tmp_path):
    """Defense-in-depth check: scanning a ZIP-shaped model file must not
    create anything on disk beyond the scanned file itself."""
    before = set(os.listdir(tmp_path))
    data = pickle.dumps(_DangerousReduce(), protocol=2)
    pt_path = tmp_path / "model.pt"
    with zipfile.ZipFile(pt_path, "w") as zf:
        zf.writestr("archive/data.pkl", data)
    engine_model.scan([_SF(pt_path)], core.read_bytes)
    after = set(os.listdir(tmp_path))
    assert after == before | {"model.pt"}, f"scanning wrote extra files: {after - before}"


# --------------------------------------------------------------------------- #
# 5. .npy (standalone) and .safetensors.
# --------------------------------------------------------------------------- #


def test_bare_npy_object_dtype_fires(tmp_path):
    data = _npy_bytes(
        "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }",
        pickle.dumps(_DangerousReduce(), protocol=2),
    )
    findings = _scan_bytes(tmp_path, "danger.npy", data)
    assert any(f.rule_id == "model-dangerous-global-critical" for f in findings)


def test_bare_npy_numeric_array_is_silent(tmp_path):
    data = _npy_bytes(
        "{'descr': '<f8', 'fortran_order': False, 'shape': (2,), }",
        struct.pack("<2d", 1.0, 2.0),
    )
    findings = _scan_bytes(tmp_path, "plain.npy", data)
    assert findings == []


def test_safetensors_extension_emits_nothing_at_all(tmp_path):
    """Design §3.4: recognized positively, never disassembled -- NOT a
    finding, and NOT an "unrecognized format" disclosure either."""
    data = struct.pack("<Q", 2) + b"{}" + b"fake tensor bytes that are not a real safetensors file"
    findings = _scan_bytes(tmp_path, "model.safetensors", data)
    assert findings == [], "a .safetensors file must never produce ANY finding, including COVERAGE"


# --------------------------------------------------------------------------- #
# 6. HDF5 -- bounded heuristic, unconditional coverage disclosure.
# --------------------------------------------------------------------------- #


def test_hdf5_lambda_signature_fires_high_and_still_discloses_heuristic(tmp_path):
    data = b"\x89HDF\r\n\x1a\n" + b"pad" * 20 + b'"class_name": "Lambda"' + b"more pad"
    findings = _scan_bytes(tmp_path, "lambda.h5", data)
    lam = [f for f in findings if f.rule_id == "keras-lambda-layer"]
    assert lam and lam[0].severity == core.Severity.HIGH
    # UNCONDITIONAL -- even a HIT still carries the heuristic-only disclosure.
    assert any(f.rule_id == "model-scan-hdf5-heuristic-only" and f.category == "COVERAGE"
               for f in findings)


def test_hdf5_without_lambda_only_discloses_the_heuristic_bound(tmp_path):
    data = b"\x89HDF\r\n\x1a\n" + b"nothing interesting in here at all"
    findings = _scan_bytes(tmp_path, "clean.h5", data)
    assert _rule_ids(findings) == ["model-scan-hdf5-heuristic-only"]
    assert findings[0].category == "COVERAGE"
    assert findings[0].severity == core.Severity.INFO


# --------------------------------------------------------------------------- #
# 7. Disclosure bucket -- unknown globals and unresolved STACK_GLOBAL.
# --------------------------------------------------------------------------- #


def test_unknown_global_outside_denylist_and_allowlist_is_disclosed_low(tmp_path):
    data = _fabricated_global_opcode("mymodule", "MyCustomModelClass") + b"."
    findings = _scan_bytes(tmp_path, "unknown.pkl", data)
    disclosures = [f for f in findings if f.rule_id == "model-unknown-global-import"]
    assert disclosures, f"expected an unknown-global disclosure, got {_rule_ids(findings)}"
    assert disclosures[0].severity == core.Severity.LOW
    assert disclosures[0].confidence == core.Confidence.LOW
    assert disclosures[0].category == "SUPPLY_CHAIN"


def test_unresolved_stack_global_is_disclosed_not_silently_dropped(tmp_path):
    """The adjacency heuristic's own defeat case (design §2.4): something
    OTHER than a string literal or MEMOIZE intervenes between the two
    string-literal pushes and STACK_GLOBAL."""
    body = (
        b"\x80\x04"
        + b"\x8c\x02" + b"os"
        + b"N"              # NONE -- breaks the two-string adjacency window
        + b"\x8c\x06" + b"system"
        + b"\x93"
        + b"."
    )
    findings = _scan_bytes(tmp_path, "unresolved.pkl", body)
    assert any(f.rule_id == "model-unknown-global-import" and "unresolved" in f.title.lower()
               for f in findings), f"got {[(f.rule_id, f.title) for f in findings]}"
    # The defeated heuristic must NOT silently promote to a false negative --
    # no CRITICAL finding either, since it genuinely could not resolve.
    assert not any(f.category == "SUPPLY_CHAIN" and f.severity >= core.Severity.MEDIUM
                   for f in findings)


def test_more_than_ten_unknown_globals_trips_the_overflow_disclosure(tmp_path):
    body = b"".join(
        _fabricated_global_opcode(f"weirdmod{i}", f"WeirdClass{i}") for i in range(15)
    ) + b"."
    findings = _scan_bytes(tmp_path, "many_unknown.pkl", body)
    individual = [f for f in findings if f.rule_id == "model-unknown-global-import"]
    overflow = [f for f in findings if f.rule_id == "model-unknown-global-import-cap-exceeded"]
    assert len(individual) == 10, f"expected exactly 10 capped disclosures, got {len(individual)}"
    assert overflow and overflow[0].category == "COVERAGE"


# --------------------------------------------------------------------------- #
# 8. Resource bounds and malformed/unrecognized input.
# --------------------------------------------------------------------------- #


def test_opcode_budget_exceeded_produces_coverage_disclosure(tmp_path):
    """Directly exercise the budget path (building a real 50MB+ stream in a
    unit test would be slow and wasteful) -- `truncated=True` is exactly the
    signal `_scan_one_file`/`_scan_zip_container` pass when a real byte cap
    was hit, so this is testing the real downstream behaviour of that signal."""
    findings = engine_model._disassemble_pickle_bytes(b"\x80\x04N.", "huge.pkl", truncated=True)
    assert any(f.rule_id == "model-scan-opcode-budget-exceeded" and f.category == "COVERAGE"
               for f in findings)


def test_random_binary_bin_file_discloses_unrecognized_format(tmp_path):
    """`.bin` is the least specific admitted extension by design -- a raw
    tensor dump with no pickle content must be disclosed, never silently
    treated as clean."""
    findings = _scan_bytes(tmp_path, "weights.bin", os.urandom(512))
    # Not guaranteed to fail on the FIRST opcode for every random draw, but
    # must never produce a spurious CRITICAL/HIGH/MEDIUM finding, and must
    # disclose SOMETHING rather than silently pass.
    assert findings, "a random binary .bin file produced no finding of any kind (silent pass)"
    assert not any(f.category == "SUPPLY_CHAIN" and f.severity >= core.Severity.MEDIUM
                   for f in findings), "random bytes should never coincidentally match the denylist"


def test_truncated_stream_reports_budget_not_a_fabricated_unrecognized_claim(tmp_path):
    """A stream we deliberately cut short ourselves (`truncated=True`) must be
    reported as a BUDGET disclosure, never as "unrecognized format" -- the
    two mean different things (design §7 resolution notes in this repo's own
    build; conflating them would misdirect a reviewer toward 'this isn't a
    model file' when the truth is 'we stopped reading it')."""
    real = pickle.dumps(_DangerousReduce(), protocol=4)
    cut = real[: len(real) // 2]
    findings = engine_model._disassemble_pickle_bytes(cut, "cut.pkl", truncated=True)
    ids = _rule_ids(findings)
    assert "model-scan-opcode-budget-exceeded" in ids
    assert "model-scan-unrecognized-format" not in ids


# --------------------------------------------------------------------------- #
# 9. File-admission wiring -- core.walk_files(mode="model") / model_candidate.
# --------------------------------------------------------------------------- #


def test_model_mode_admits_by_extension_and_ignores_binary_content(tmp_path):
    (tmp_path / "weights.pkl").write_bytes(b"\x80\x04N.")
    (tmp_path / "notes.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "model.safetensors").write_bytes(b"\x00" * 32)
    (tmp_path / "readme.md").write_text("hello\n", encoding="utf-8")

    model_selected = {f.relpath for f in core.walk_files(
        str(tmp_path), mode="model", max_bytes=core.DEFAULT_MODEL_MAX_ADMIT_BYTES)}
    text_selected = {f.relpath for f in core.walk_files(str(tmp_path))}

    assert model_selected == {"weights.pkl", "model.safetensors"}
    assert text_selected == {"notes.py", "readme.md"}


def test_model_mode_never_calls_the_binary_sniff_rejection(tmp_path):
    """A model file that WOULD fail the text engines' binary sniff must still
    be admitted -- that is the entire point of mode="model" inverting the
    check (design §1.2)."""
    p = tmp_path / "weights.pt"
    p.write_bytes(bytes(range(256)) * 20)  # guaranteed "binary" by the text sniff
    assert core.is_probably_binary(str(p))  # premise: the text engines WOULD reject this
    selected = core.walk_files(str(tmp_path), mode="model",
                               max_bytes=core.DEFAULT_MODEL_MAX_ADMIT_BYTES)
    assert {f.relpath for f in selected} == {"weights.pt"}


def test_model_candidate_extension_set_matches_core_model_exts():
    for ext in (".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".bin", ".joblib",
                ".dill", ".npy", ".npz", ".h5", ".hdf5", ".keras", ".model",
                ".safetensors"):
        assert core.model_candidate(f"weights{ext}"), f"{ext} should be a model candidate"
    assert not core.model_candidate("weights.py")
    assert not core.model_candidate("README.md")


# --------------------------------------------------------------------------- #
# 10. End-to-end wiring through praetor.py.
# --------------------------------------------------------------------------- #


def _run_cli(args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = praetor.main(args)
    return rc, json.loads(out.getvalue())


def test_engines_flag_accepts_model_and_finds_the_danger(tmp_path):
    (tmp_path / "danger.pkl").write_bytes(pickle.dumps(_DangerousReduce(), protocol=2))
    rc, doc = _run_cli([str(tmp_path), "--format", "json", "--quiet",
                        "--engines", "model", "--fail-on", "CRITICAL"])
    assert rc == 1
    assert doc["meta"]["engines"]["model"]["status"] == "ok"
    assert any(f["rule_id"] == "model-dangerous-global-critical" for f in doc["findings"])


def test_model_engine_reports_disabled_when_not_selected(tmp_path):
    (tmp_path / "danger.pkl").write_bytes(pickle.dumps(_DangerousReduce(), protocol=2))
    rc, doc = _run_cli([str(tmp_path), "--format", "json", "--quiet", "--engines", "secrets"])
    assert doc["meta"]["engines"]["model"]["status"] == "disabled"
    # A real CRITICAL model finding must NOT appear when the engine is off.
    assert not any(f["engine"] == "model" for f in doc["findings"])


def test_model_engine_reports_not_applicable_with_zero_model_files(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    rc, doc = _run_cli([str(tmp_path), "--format", "json", "--quiet", "--engines", "model"])
    assert doc["meta"]["engines"]["model"]["status"] == "not-applicable"
    assert rc == 0
    assert doc["meta"]["model_file_count"] == 0


def test_model_engine_appears_in_meta_engines_for_every_run(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    rc, doc = _run_cli([str(tmp_path), "--format", "json", "--quiet", "--engines", "aisec"])
    assert "model" in doc["meta"]["engines"]


def test_model_findings_do_not_pollute_the_text_unreadable_accumulator(tmp_path):
    """The load-bearing regression this build had to get right (design §7):
    a `model` finding's `line` is a byte offset, and none of the four
    suppression passes (`_apply_inline_ignores` especially, since it has no
    engine allowlist) may call `read_text()` against the binary file. If they
    did, `core.read_text` would very likely raise on the binary bytes and the
    scan would spuriously self-report as degraded.
    """
    (tmp_path / "danger.pkl").write_bytes(pickle.dumps(_DangerousReduce(), protocol=4))
    rc, doc = _run_cli([str(tmp_path), "--format", "json", "--quiet",
                        "--engines", "model", "--fail-on", "CRITICAL"])
    assert rc == 1
    assert doc["meta"]["scope"]["unreadable_files"] == 0, (
        "a model finding leaked into the TEXT unreadable-file accumulator"
    )
    assert not any(f["filtered"] for f in doc.get("filtered", [])
                   if f.get("engine") == "model" and
                   "inline ignore marker" in f.get("filter_reason", "")), (
        "a model finding was suppressed by the inline-ignore pass, which "
        "cannot mean anything for a byte offset into a binary stream"
    )


def test_model_finding_is_not_suppressed_by_lexical_context_or_reachability(tmp_path):
    """`model` must stay OUT of `_LEXCTX_ENGINES`/`_REACHABILITY_ENGINES` --
    confirmed behaviourally (a real finding survives to `active`), not just
    by reading the source list."""
    (tmp_path / "danger.pkl").write_bytes(pickle.dumps(_DangerousReduce(), protocol=4))
    rc, doc = _run_cli([str(tmp_path), "--format", "json", "--quiet", "--engines", "model"])
    active_model = [f for f in doc["findings"] if f["engine"] == "model"]
    assert any(f["rule_id"] == "model-dangerous-global-critical" for f in active_model)
    assert not any(f["engine"] == "model" for f in doc.get("filtered", []))


def test_pyproject_declares_engine_model_in_py_modules():
    """Cheap regression guard for the packaging gap this build's own design
    doc names explicitly: an engine present in ALL_ENGINES but absent from
    pyproject.toml's py-modules list imports fine from a clone and silently
    vanishes from an installed wheel."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    text = open(os.path.join(root, "pyproject.toml"), encoding="utf-8").read()
    assert "engine_model" in text, "engine_model is missing from pyproject.toml"
