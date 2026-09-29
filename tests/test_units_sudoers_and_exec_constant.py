"""
SYSTEMD UNITS AND SUDOERS DROP-INS MUST BE READ. THEY WERE NOT.

MEASURED (2026-09-29): `core.scannable("factory-cred-readback.service")` and
`core.scannable("factory-cred.sudoers")` both returned False, so a scan of a
deployment tree never opened either -- not "scanned and clean", never read.
Both are security-relevant configuration: a unit names what runs, as whom, and
with which credentials; a sudoers drop-in grants privilege. A skipped one is a
blind spot that still exits 0.

The companion half of this change (the `praetor-ai-llm-output-to-shell` rule no
longer firing on `exec` of a constant) needs a REAL semgrep, so it lives in
tests/semgrep_live_check.py, not here: this suite fails on any skip, and the CI
job that runs it installs no tools.
"""

import core


def test_systemd_units_and_sudoers_dropins_are_scannable():
    for name in ("factory-cred-readback.service", "factory-cred.sudoers"):
        assert core.scannable(name), (
            "%s is security-relevant config (what runs as whom / who may escalate) "
            "and must be opened" % name
        )


def test_walker_reports_unit_and_sudoers_as_examined(tmp_path):
    """Reach, not set membership: the walker must actually hand both files over."""
    (tmp_path / "x.service").write_text("[Service]\nExecStart=/bin/true\n",
                                        encoding="utf-8")
    (tmp_path / "y.sudoers").write_text("deploy ALL=(root) NOPASSWD: /bin/true\n",
                                        encoding="utf-8")
    files = core.walk_files(str(tmp_path))
    assert sorted(f.relpath for f in files) == ["x.service", "y.sudoers"]


def test_units_and_sudoers_do_not_count_as_code_for_the_scope_floor(tmp_path):
    """Read as config, never as evidence that code was examined."""
    for name in ("factory-cred-readback.service", "factory-cred.sudoers"):
        assert not core.is_code(name), "%s must not satisfy the scope floor" % name
    (tmp_path / "x.service").write_text("[Service]\n", encoding="utf-8")
    (tmp_path / "y.sudoers").write_text("# none\n", encoding="utf-8")
    stats = {}
    files = core.walk_files(str(tmp_path), stats=stats)
    assert len(files) == 2
    assert stats["kept_code_files"] == 0


def test_widening_did_not_admit_binaries_or_drop_source():
    assert not core.scannable("a.png"), "a binary-ish name must stay unscanned"
    assert core.scannable("a.py"), "source must stay scannable"


# --------------------------------------------------------------------------- #
# exec/eval of a module string constant: the AST proof in interpret.py
# --------------------------------------------------------------------------- #
# `EXEC(` stands for the sink and is swapped in below, so this file does not
# itself carry exec calls for the engine under test to find.

import os

import pytest

import interpret
from core import Finding, Severity

_SINK = "ex" + "ec("


def _proven(src, line, stem=None):
    return interpret.exec_constant_proven(src.replace("EXEC(", _SINK), line, stem)


FILTERED = {
    "literal": ('EXEC("print(1)")', 1),
    "eval literal": ('eval("1")', 1),
    "module constant": ('N = "x"\nEXEC(N)', 2),
    "constant, sink in a function": ('N = "x"\ndef f():\n    EXEC(N)', 3),
    "comment names a store": ('# globals()["N"] = input()\nN = "x"\nEXEC(N)', 3),
    "docstring names a store": ('"""globals()["N"] = input()"""\nN = "x"\nEXEC(N)', 3),
    "other literal exec, no N": ('N = "x"\nEXEC("print(2)")\nEXEC(N)', 3),
    # RESIDUAL by design: the constant's own text is not inspected.
    "residual: constant reads input": ('EXEC("EXEC(input())")', 1),
    # Commit 5 FLIPS (were NOT_FILTERED in commit 4): a Load-subscript read of
    # globals() cannot store, and a bare `import importlib` rebinds nothing.
    "read of globals()": ('N = "x"\nx = globals()["N"]\nEXEC(N)', 3),
    "importlib": ('import importlib\nN = "x"\nEXEC(N)', 3),
}

NOT_FILTERED = {
    "globals literal key": ('N = "x"\nglobals()["N"] = input()\nEXEC(N)', 3),
    "globals dynamic key": ('N = "x"\nK = "N"\nglobals()[K] = input()\nEXEC(N)', 4),
    "globals spaced": ('N = "x"\nglobals ()["N"] = input()\nEXEC(N)', 3),
    "vars": ('N = "x"\nvars()["N"] = input()\nEXEC(N)', 3),
    "locals": ('N = "x"\nlocals()["N"] = input()\nEXEC(N)', 3),
    "setattr": ('N = "x"\nsetattr(mod, "N", input())\nEXEC(N)', 3),
    "setattr on a call": ('N = "x"\nsetattr(get_mod(), "N", input())\nEXEC(N)', 3),
    "delattr": ('N = "x"\ndelattr(mod, "N")\nEXEC(N)', 3),
    "__dict__": ('N = "x"\nmod.__dict__["N"] = input()\nEXEC(N)', 3),
    "sys.modules": ('import sys\nN = "x"\nsys.modules[__name__].N = input()\nEXEC(N)', 4),
    "attribute store of N": ('N = "x"\nmod.N = input()\nEXEC(N)', 3),
    "__builtins__": ('N = "x"\n__builtins__.foo = 1\nEXEC(N)', 3),
    "from importlib": ('from importlib import reload\nN = "x"\nEXEC(N)', 3),
    "star import": ('from m import *\nN = "x"\nEXEC(N)', 3),
    "alias after store": ('N = "x"\nglobals()["N"] = input()\nb = N\nEXEC(b)', 4),
    "alias of a constant": ('N = "x"\nb = N\nEXEC(b)', 3),
    "exec((N)) after store": ('N = "x"\nglobals()["N"] = input()\nEXEC((N))', 3),
    "rebinding function defined later":
        ('N = "x"\nrebind()\nEXEC(N)\ndef rebind():\n    globals()["N"] = input()', 3),
    "global write inside if":
        ('N = "x"\ndef g(p):\n    global N\n    if p:\n        N = p\nEXEC(N)', 6),
    "global write inside try":
        ('N = "x"\ndef g(p):\n    global N\n    try:\n        N = p\n    except E:\n        pass\nEXEC(N)', 8),
    "global declared, no write": ('N = "x"\ndef g():\n    global N\nEXEC(N)', 4),
    "nonlocal": ('N = "x"\ndef g():\n    def h():\n        nonlocal N\nEXEC(N)', 5),
    # Conservative: the module-level N IS constant here, but a same-named local
    # elsewhere is a second binding and the proof does not reason about scopes.
    "local shadow in another function": ('N = "x"\ndef h():\n    N = input()\nEXEC(N)', 4),
    "reviewer r2: global + local shadow":
        ('def set_payload(p):\n    global N\n    N = p\ndef run():\n    N = "x"\n    EXEC(N)', 6),
    "second assignment": ('N = "x"\nN = input()\nEXEC(N)', 3),
    "AugAssign": ('N = "x"\nN += input()\nEXEC(N)', 3),
    "AnnAssign": ('N: str = "x"\nEXEC(N)', 2),
    "walrus": ('N = "x"\nif (N := input()):\n    pass\nEXEC(N)', 4),
    "for target": ('N = "x"\nfor N in [input()]:\n    pass\nEXEC(N)', 4),
    "with target": ('N = "x"\nwith f() as N:\n    pass\nEXEC(N)', 4),
    "except target": ('N = "x"\ntry:\n    pass\nexcept E as N:\n    pass\nEXEC(N)', 6),
    "import as N": ('N = "x"\nimport os as N\nEXEC(N)', 3),
    "def N": ('N = "x"\ndef N():\n    pass\nEXEC(N)', 4),
    "class N": ('N = "x"\nclass N:\n    pass\nEXEC(N)', 4),
    "del N": ('N = "x"\ndel N\nEXEC(N)', 3),
    "parameter N": ('N = "x"\ndef f(N):\n    EXEC(N)', 3),
    "match capture": ('N = "x"\nmatch v:\n    case N:\n        pass\nEXEC(N)', 5),
    "chained assign": ('N = M = "x"\nEXEC(N)', 2),
    "tuple assign": ('N, M = "x", "y"\nEXEC(N)', 2),
    "not a str": ('N = 1\nEXEC(N)', 2),
    "assigned in a function only": ('def f():\n    N = "x"\n    EXEC(N)', 3),
    "exec string rebinds N": ('N = "x"\nEXEC("N = input()")\nEXEC(N)', 3),
    "non-constant exec elsewhere": ('N = "x"\nEXEC(input())\nEXEC(N)', 3),
    "two args": ('N = "x"\nEXEC(N, {})', 2),
    "two sinks on the line": ('N = "x"\nEXEC(N); EXEC(N)', 2),
    "no sink on the line": ('N = "x"\nEXEC(N)', 1),
    "model output": ('EXEC(resp.choices[0].message.content)', 1),
    "parse error": ('N = "x"\nEXEC(N)\ndef (', 2),
}


@pytest.mark.parametrize("case", sorted(FILTERED))
def test_proof_filters_a_proven_constant(case):
    src, line = FILTERED[case]
    assert _proven(src, line), case


@pytest.mark.parametrize("case", sorted(NOT_FILTERED))
def test_proof_keeps_anything_unproven(case):
    src, line = NOT_FILTERED[case]
    assert not _proven(src, line), case


def _run_interpret(tmp_path, src, line):
    (tmp_path / "app.py").write_text(src.replace("EXEC(", _SINK), encoding="utf-8")
    f = Finding(engine="sast", rule_id=interpret.EXEC_CONSTANT_RULE,
                title="t", severity=Severity.HIGH, file="app.py", line=line,
                cwe="CWE-78")
    return interpret.interpret(
        [f], read_source=lambda fd: (tmp_path / fd.file).read_text(encoding="utf-8"))


def test_end_to_end_constant_is_filtered_with_the_reason(tmp_path):
    res = _run_interpret(tmp_path, 'NET_GUARD = """\nimport socket\n"""\nEXEC(NET_GUARD)\n', 4)
    assert not res["active"]
    assert [f.filter_reason for f in res["filtered"]] == [interpret.EXEC_CONSTANT_REASON]


def test_end_to_end_rebound_constant_stays_active(tmp_path):
    res = _run_interpret(
        tmp_path,
        'NET_GUARD = """\nimport socket\n"""\nglobals()["NET_GUARD"] = input()\nEXEC(NET_GUARD)\n', 5)
    assert len(res["active"]) == 1 and not res["filtered"]


def test_unreadable_source_is_kept(tmp_path):
    f = Finding(engine="sast", rule_id=interpret.EXEC_CONSTANT_RULE,
                title="t", severity=Severity.HIGH, file="gone.py", line=1)
    res = interpret.interpret([f], read_source=lambda fd: None)
    assert len(res["active"]) == 1


# --------------------------------------------------------------------------- #
# Commit 5: the real guard shape, and the narrowed namespace / setattr rules
# --------------------------------------------------------------------------- #
# The fixture is a reduced copy of the shape measured on a real target: a module
# constant exec'd at top level, importlib.util spec/module_from_spec, setattr on
# that NEW module, and a globals()["case_" + x]() read-then-call. `.txt` so the
# self-scan's SAST does not treat it as this repo's own code.

_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "exec_constant_guard_fixture.txt")
_GUARD_STEM = "test_factory_cred"


def _guard(extra=""):
    """Fixture source with `extra` inserted just before the sink line."""
    lines = open(_FIXTURE, encoding="utf-8").read().split("\n")
    at = next(i for i, l in enumerate(lines) if l.startswith("EXEC("))
    if extra:
        lines[at:at] = extra.split("\n")
    return "\n".join(lines), at + 1 + (len(extra.split("\n")) if extra else 0)


def test_real_guard_shape_is_filtered():
    src, line = _guard()
    assert _proven(src, line, _GUARD_STEM)


def test_real_guard_shape_without_a_stem_is_kept():
    """setattr is present, and a self-import cannot be ruled out with no stem."""
    src, line = _guard()
    assert not _proven(src, line, None)


GUARD_VARIANTS_ACTIVE = {
    "setattr on sys.modules[__name__]":
        'setattr(sys.modules[__name__], "NET_GUARD", input())',
    "globals() bound to a name": 'g = globals()\ng["NET_GUARD"] = input()',
    "globals().update": "globals().update(NET_GUARD=input())",
    "globals() store": 'globals()["NET_GUARD"] = input()',
    "import_module(__name__)":
        "import importlib\nimportlib.import_module(__name__).NET_GUARD = input()",
    "__import__(__name__)": "__import__(__name__).NET_GUARD = x",
    "vars() store": 'vars()["NET_GUARD"] = x',
    "setattr + import of own stem": "import " + _GUARD_STEM,
    "setattr + import __main__": "import __main__",
    "setattr + dotted self-import": "import pkg." + _GUARD_STEM + " as me",
    "setattr + from-import of self": "from . import " + _GUARD_STEM,
    "setattr + from self import": "from " + _GUARD_STEM + " import x",
    "aliased globals": 'from builtins import globals as g\ng()["NET_GUARD"] = x',
    "aliased setattr + sys.modules":
        "from builtins import setattr as s\ns(sys.modules[__name__], 'NET_GUARD', x)",
    "setattr + __name__ passed on": "f(__name__)",
    "setattr + __spec__": "s = __spec__",
    "frame globals": 'sys._getframe().f_globals["NET_GUARD"] = x',
    "dynamic getattr": "getattr(sys, name)",
    "getattr spelled frame": 'getattr(sys, "_getframe")',
    "import inspect": "import inspect",
    "__dict__ update": "m.__dict__.update(NET_GUARD=x)",
    "del globals()[...]": 'del globals()["NET_GUARD"]',
    "globals() passed on": "f(globals())",
    "locals() in a for": "for k in locals():\n    pass",
}


@pytest.mark.parametrize("case", sorted(GUARD_VARIANTS_ACTIVE))
def test_real_guard_shape_variants_stay_active(case):
    src, line = _guard(GUARD_VARIANTS_ACTIVE[case])
    assert not _proven(src, line, _GUARD_STEM), case


NARROWED_FILTERED = {
    "globals() read then call": ('N = "x"\nglobals()["f_" + k]()\nEXEC(N)', 3),
    "__dict__ read": ('N = "x"\nv = m.__dict__["k"]\nEXEC(N)', 3),
    "setattr on another object, no self-reach": ('N = "x"\nsetattr(obj, "k", 1)\nEXEC(N)', 3),
    "__name__ in a comparison": ('N = "x"\nif __name__ == "__main__":\n    pass\nEXEC(N)', 4),
}


@pytest.mark.parametrize("case", sorted(NARROWED_FILTERED))
def test_narrowed_rules_still_prove(case):
    src, line = NARROWED_FILTERED[case]
    assert _proven(src, line, "app"), case


def test_aliased_setattr_is_still_a_setter():
    """No plain `setattr` anywhere: only the alias makes this a module write."""
    src = ("from builtins import setattr as s\nimport sys\nN = \"x\"\n"
           "s(sys.modules[__name__], \"N\", x)\nEXEC(N)")
    assert not _proven(src, 5, "app")


def test_end_to_end_real_guard_shape_through_interpret(tmp_path):
    src, line = _guard()
    (tmp_path / (_GUARD_STEM + ".py")).write_text(src.replace("EXEC(", _SINK), encoding="utf-8")
    f = Finding(engine="sast", rule_id=interpret.EXEC_CONSTANT_RULE, title="t",
                severity=Severity.HIGH, file=_GUARD_STEM + ".py", line=line)
    res = interpret.interpret(
        [f], read_source=lambda fd: (tmp_path / fd.file).read_text(encoding="utf-8"))
    assert [x.filter_reason for x in res["filtered"]] == [interpret.EXEC_CONSTANT_REASON]
