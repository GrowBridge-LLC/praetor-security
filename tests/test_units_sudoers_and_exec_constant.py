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
    # Commit 5 FLIP (was NOT_FILTERED in commit 4): a constant-key Load read of
    # globals() cannot store. (Commit 5 also flipped a bare `import importlib`
    # here; commit 7's import allowlist flips it back -- see R7_ACTIVE.)
    "read of globals()": ('N = "x"\nx = globals()["N"]\nEXEC(N)', 3),
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


# --------------------------------------------------------------------------- #
# Commit 6: AST-proof review round 1 (every reviewer snippet is a case here)
# --------------------------------------------------------------------------- #

R6_ACTIVE = {
    # FLIPPED from commit 5 (was filtered): setattr now needs a POSITIVE proof
    # that its target is a fresh module_from_spec() module.
    "setattr on another object": ('N = "x"\nsetattr(obj, "k", 1)\nEXEC(N)', 3),
    # 1) the sink itself rebound (Grok 1) -- literal and name paths
    "grok1: def exec, literal":
        ('import os\ndef EXEC(code):\n    os.system(input())\nEXEC("print(1)")', 4),
    "builtins.exec store, literal": ('import builtins\nbuiltins.exec = f\nEXEC("print(1)")', 3),
    "builtins attr store without import": ('x.exec = f\nEXEC("print(1)")', 2),
    "exec assigned": ('exec = print\nEXEC("print(1)")', 2),
    "exec parameter": ('def f(exec):\n    EXEC("print(1)")', 2),
    "exec import alias": ('from os import system as exec\nEXEC("print(1)")', 2),
    "exec for target": ('for exec in fs:\n    pass\nEXEC("print(1)")', 3),
    "exec walrus": ('(exec := f)\nEXEC("print(1)")', 2),
    "exec comprehension target": ('[0 for exec in fs]\nEXEC("print(1)")', 2),
    "exec with target": ('with f() as exec:\n    pass\nEXEC("print(1)")', 3),
    "exec except target": ('try:\n    pass\nexcept E as exec:\n    pass\nEXEC("print(1)")', 5),
    "exec match target": ('match v:\n    case exec:\n        pass\nEXEC("print(1)")', 4),
    "exec global": ('def f():\n    global exec\nEXEC("print(1)")', 3),
    "exec del": ('del exec\nEXEC("print(1)")', 2),
    "class exec": ('class exec:\n    pass\nEXEC("print(1)")', 3),
    "eval shadowed": ('def eval(s):\n    return s\nN = "x"\neval(N)', 4),
    "from builtins import": ('from builtins import print\nEXEC("print(1)")', 2),
    "__builtins__ use, literal": ('__builtins__.x = 1\nEXEC("print(1)")', 2),
    # 2) namespace reads (Grok 2)
    "grok2: vars(sys) split spelling":
        ('N = "safe"\nimport sys\nme = vars(sys)["mod" + "ules"][globals()["__name__"]]\n'
         'setattr(me, "N", input())\nEXEC(N)', 5),
    "vars(obj) read": ('N = "x"\nv = vars(obj)["k"]\nEXEC(N)', 3),
    "globals with a keyword": ('N = "x"\nv = globals(x=1)["k"]\nEXEC(N)', 3),
    "__dict__ computed key": ('N = "x"\nv = m.__dict__["mod" + "ules"]\nEXEC(N)', 3),
    "__dict__ spelled key": ('N = "x"\nv = m.__dict__["modules"]\nEXEC(N)', 3),
    "__getattribute__ dynamic": ('N = "x"\nv = o.__getattribute__(k)\nEXEC(N)', 3),
    "attrgetter dynamic": ('import operator\nN = "x"\nv = operator.attrgetter(k)(o)\nEXEC(N)', 4),
    "attrgetter dotted spelled":
        ('from operator import attrgetter\nN = "x"\nv = attrgetter("a.modules")(o)\nEXEC(N)', 4),
    "methodcaller dynamic": ('import operator\nN = "x"\nv = operator.methodcaller(k)(o)\nEXEC(N)', 4),
    "attrgetter renamed on import":
        ('from operator import attrgetter as ag\nN = "x"\nv = ag(k)(o)\nEXEC(N)', 4),
    "getattr passed around": ('N = "x"\nf(getattr)\nEXEC(N)', 3),
    "getattr passed after safe args": ('N = "x"\nf(o, "name", getattr)\nEXEC(N)', 3),
    "builtins name reference": ('x = builtins\nEXEC("print(1)")', 2),
    # 3) setattr needs a fresh module target (Sol 3, Grok 3)
    "grok3/sol3: import pkg in __init__":
        ('N = "safe"\nimport pkg\nsetattr(pkg, "N", input())\nEXEC(N)', 4),
    "module_from_spec bound twice":
        ('import importlib.util\nN = "x"\ndef f(s):\n    m = importlib.util.module_from_spec(s)\n'
         '    m = g()\n    setattr(m, "k", 1)\nEXEC(N)', 7),
    "module_from_spec in another scope":
        ('import importlib.util\nN = "x"\nm = importlib.util.module_from_spec(s)\n'
         'def f():\n    setattr(m, "k", 1)\nEXEC(N)', 6),
    "target from something else":
        ('N = "x"\ndef f():\n    m = make()\n    setattr(m, "k", 1)\nEXEC(N)', 5),
    "object.__setattr__":
        ('import importlib.util\nN = "x"\ndef f(s):\n    m = importlib.util.module_from_spec(s)\n'
         '    object.__setattr__(m, "k", 1)\nEXEC(N)', 6),
    "setattr aliased by assignment": ('N = "x"\ns = setattr\nEXEC(N)', 3),
    "importlib rebound":
        ('import importlib.util\nimportlib = fake\nN = "x"\ndef f(s):\n'
         '    m = importlib.util.module_from_spec(s)\n    setattr(m, "k", 1)\nEXEC(N)', 7),
    # 4) class bodies (Sol 2)
    "sol2: metaclass __prepare__":
        ('class Namespace(dict):\n    def __missing__(self, key):\n        if key == "PAYLOAD":\n'
         '            return input()\n        raise KeyError(key)\n\nclass Meta(type):\n'
         '    @classmethod\n    def __prepare__(cls, name, bases):\n        return Namespace()\n\n'
         'PAYLOAD = "print(\'safe\')"\n\nclass Victim(metaclass=Meta):\n    EXEC(PAYLOAD)', 15),
    "literal in a class body": ('class C:\n    EXEC("print(1)")', 2),
    # Conservative: a method uses LOAD_GLOBAL and would be safe, but ANY ClassDef
    # ancestor is rejected.
    "sink in a method": ('N = "x"\nclass C:\n    def f(self):\n        EXEC(N)', 4),
    # 6) parse robustness (Sol 4)
    "sol4: lone surrogate in another exec": ('N = "x"\nEXEC("\\ud800")\nEXEC(N)', 3),
    "deeply nested expression": ('N = "x"\nEXEC(N)\nx = ' + "1+" * 300000 + "1", 2),
    "nested parse too complex": ('N = "x"\nEXEC(N)\nx = ' + "-" * 200000 + "1", 2),
}

R6_FILTERED = {
    "fresh module via importlib.util":
        ('import importlib.util\nN = "x"\ndef f(s):\n    m = importlib.util.module_from_spec(s)\n'
         '    for k, v in d.items():\n        setattr(m, k, v)\nEXEC(N)', 7),
    "fresh module via from-import alias":
        ('from importlib.util import module_from_spec as mfs\nN = "x"\ndef f(s):\n'
         '    m = mfs(s)\n    delattr(m, "k")\nEXEC(N)', 6),
    "locals() read": ('N = "x"\nv = locals()["k"]\nEXEC(N)', 3),
    "getattr constant safe name": ('N = "x"\nv = getattr(o, "name")\nEXEC(N)', 3),
}


@pytest.mark.parametrize("case", sorted(R6_ACTIVE))
def test_r6_reviewer_cases_stay_active(case):
    src, line = R6_ACTIVE[case]
    assert not _proven(src, line, "app"), case


@pytest.mark.parametrize("case", sorted(R6_FILTERED))
def test_r6_positive_cases_still_prove(case):
    src, line = R6_FILTERED[case]
    assert _proven(src, line, "app"), case


def test_r6_init_py_gets_no_stem(tmp_path):
    """Grok 3 / Sol 3 through the real entry: pkg/__init__.py fails closed."""
    src = 'import pkg\nN = "safe"\nsetattr(pkg, "N", input())\nEXEC(N)\n'
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text(src.replace("EXEC(", _SINK), encoding="utf-8")
    f = Finding(engine="sast", rule_id=interpret.EXEC_CONSTANT_RULE, title="t",
                severity=Severity.HIGH, file="pkg/__init__.py", line=4)
    res = interpret.interpret(
        [f], read_source=lambda fd: (tmp_path / fd.file).read_text(encoding="utf-8"))
    assert len(res["active"]) == 1 and not res["filtered"]


def test_r6_init_py_fails_closed_even_on_a_fresh_module(tmp_path):
    """In __init__.py the stem is unknown, so ANY setter keeps the finding --
    even one the positive proof would accept elsewhere."""
    src = ('import importlib.util\nN = "x"\ndef f(s):\n'
           '    m = importlib.util.module_from_spec(s)\n    setattr(m, "k", 1)\nEXEC(N)\n')
    assert _proven(src, 6, "app")                      # control: provable as app.py
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text(src.replace("EXEC(", _SINK), encoding="utf-8")
    f = Finding(engine="sast", rule_id=interpret.EXEC_CONSTANT_RULE, title="t",
                severity=Severity.HIGH, file="pkg/__init__.py", line=6)
    res = interpret.interpret(
        [f], read_source=lambda fd: (tmp_path / fd.file).read_text(encoding="utf-8"))
    assert len(res["active"]) == 1 and not res["filtered"]


def test_r6_runs_without_match_nodes(monkeypatch):
    """Sol 1: ast.Match* do not exist before 3.10. Re-import interpret on an ast
    module without them; the proof must still run (no AttributeError)."""
    import ast
    import importlib
    for n in ("MatchAs", "MatchStar", "MatchMapping"):
        monkeypatch.delattr(ast, n, raising=False)
    try:
        mod = importlib.reload(interpret)
        assert mod._MATCH_NAMED == () and mod._MATCH_MAPPING == ()
        assert mod.exec_constant_proven('N = "x"\n' + _SINK + "N)", 2, "app")
    finally:
        monkeypatch.undo()
        importlib.reload(interpret)


# --------------------------------------------------------------------------- #
# Commit 7: AST-proof review round 2 -- imports are an ALLOWLIST
# --------------------------------------------------------------------------- #

R7_ACTIVE = {
    # Grok r2 snippets (each returned True on 57e3f9d, measured)
    "grok r2: typing.get_type_hints evals an annotation":
        ('import typing\nN = "safe"\ndef f(x: \'globals().update(N="pwned") or int\'):\n'
         '    pass\ntyping.get_type_hints(f)\nEXEC(N)', 6),
    "grok r2: mock.patch.object on this module":
        ('import sys\nfrom unittest.mock import patch\nN = "safe"\n'
         'patch.object(sys.modules[__name__], "N", "pwned").start()\nEXEC(N)', 5),
    "grok r2: mock.patch.object on builtins via computed globals key":
        ('from unittest.mock import patch\npatch.object(globals()["__" + "built" + "ins" + "__"], '
         '"exec", lambda code: input()).start()\nEXEC("print(1)")', 3),
    # FLIPPED back from commit 5 (was filtered): importlib is not allowlisted,
    # only importlib.util.
    "bare import importlib": ('import importlib\nN = "x"\nEXEC(N)', 3),
    # FLIPPED from commit 6 (was filtered): operator is not allowlisted.
    "attrgetter constant": ('from operator import attrgetter\nN = "x"\nv = attrgetter("a.b")(o)\nEXEC(N)', 4),
    "relative import": ('from . import helpers\nN = "x"\nEXEC(N)', 3),
    "relative import of an allowlisted name": ('from .os import path\nN = "x"\nEXEC(N)', 3),
    "from sys import modules": ('from sys import modules\nN = "x"\nEXEC(N)', 3),
    "importlib.util other name": ('from importlib.util import find_spec\nN = "x"\nEXEC(N)', 3),
    "allowed module, spelled name": ('from sys import settrace\nN = "x"\nEXEC(N)', 3),
    "sys.settrace": ('import sys\nN = "x"\nsys.settrace(t)\nEXEC(N)', 4),
    "threading.setprofile": ('import threading\nN = "x"\nthreading.setprofile(t)\nEXEC(N)', 4),
    "sys.addaudithook": ('import sys\nN = "x"\nsys.addaudithook(h)\nEXEC(N)', 4),
    "breakpoint()": ('N = "x"\nbreakpoint()\nEXEC(N)', 3),
    "import inside a function": ('N = "x"\ndef f():\n    import pickle\nEXEC(N)', 4),
    # computed globals() key used any way but an immediate call statement
    "computed key bound": ('N = "x"\nb = globals()["__" + "builtins__"]\nEXEC(N)', 3),
    "computed key passed": ('N = "x"\nf(globals()["a" + "b"])\nEXEC(N)', 3),
    "computed key call result used": ('N = "x"\nr = globals()["case_" + k]()\nEXEC(N)', 3),
}

for _mod in ("typing", "unittest", "collections", "dataclasses", "pickle",
             "functools", "code", "runpy", "doctest"):
    R7_ACTIVE["import " + _mod] = ('import %s\nN = "x"\nEXEC(N)' % _mod, 3)


@pytest.mark.parametrize("case", sorted(R7_ACTIVE))
def test_r7_cases_stay_active(case):
    src, line = R7_ACTIVE[case]
    assert not _proven(src, line, "app"), case


R7_FILTERED = {
    "every allowlisted import":
        ("import ast, base64, datetime, http.client, http.server, json, os, re\n"
         "import secrets, shutil, socket, ssl, subprocess, sys, tempfile, threading, time\n"
         "import importlib.util\nfrom pathlib import Path\n"
         "from importlib.util import module_from_spec, spec_from_file_location\n"
         'N = "x"\nEXEC(N)', 7),
    "computed key immediate call statement": ('N = "x"\nglobals()["case_" + k]()\nEXEC(N)', 3),
}


@pytest.mark.parametrize("case", sorted(R7_FILTERED))
def test_r7_allowlisted_shapes_still_prove(case):
    src, line = R7_FILTERED[case]
    assert _proven(src, line, "app"), case
