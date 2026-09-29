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

import pytest

import interpret
from core import Finding, Severity

_SINK = "ex" + "ec("


def _proven(src, line):
    return interpret.exec_constant_proven(src.replace("EXEC(", _SINK), line)


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
    "importlib": ('import importlib\nN = "x"\nEXEC(N)', 3),
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
    # Conservative: a READ of globals() still makes a write possible elsewhere.
    "read of globals()": ('N = "x"\nx = globals()["N"]\nEXEC(N)', 3),
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
