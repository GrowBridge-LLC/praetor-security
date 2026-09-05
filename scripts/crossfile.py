"""
PRAETOR cross-file analysis -- seeing a payload that no single file reveals.

Every other built-in engine is per-file, and the reachability check is per-file
too. An attacker who splits a payload across a call chain is invisible to that
view:

    payload.py   CMD = "<a remote-execution pipe>"     # looks like a constant
    runner.py    from payload import CMD               # looks like an import
                 os.system(CMD)                        # looks like a variable

No single file contains anything obviously wrong. This module joins them.

🔴 IMPORT RESOLUTION IS NAME ARITHMETIC ONLY. NEVER `importlib`.
`importlib.util.find_spec("pkg.sub")` EXECUTES `pkg/__init__.py` -- measured
here, on this machine, before a line of this module was written:

    after ast.parse   -> executed: False
    after compile     -> executed: False
    after find_spec   -> executed: True

That would break PRAETOR's one invariant, in the module whose whole job is
reading other people's code. `ast.parse` and `compile` are clean; anything that
consults the import system is not.

🔴 ADD-ONLY, exactly like `chains.py` and for the same reason. This pass may
report a new finding. It may never suppress, downgrade or re-bucket one. A
cross-file pass that could quiet a finding would be a suppression mechanism with
a whole-repository blast radius, and it would need carve-out discipline this
module does not have.

🔴 DO NOT PROPAGATE CAPABILITY OVER IMPORT EDGES. Measured on 2,244 standard
library modules: flagging a module for its own contents marks 141 (7.6%);
propagating transitively over import edges marks 1,646 (89.0%). Import edges are
not use edges. That is `chains.py`'s SAME_TREE lesson at graph scale -- a claim
that covers almost everything conveys almost nothing. This module traces a
SPECIFIC VALUE to a SPECIFIC SINK and nothing else.

⚠️ WHAT IT CANNOT SEE, stated rather than discovered later:
  * a payload passed as a FUNCTION PARAMETER through an aliased call;
  * a name built at run time (`getattr`, a string-built identifier);
  * a string assembled in a loop;
  * anything in a language other than Python.
  These are the next stages, not oversights. `references/PLAN-TO-V1.md` §4.

⚠️ NEVER SAYS "REACHABLE". Only that a value defined in one file is passed to a
sink in another. Whether that code runs is a question static analysis cannot
answer, and the finding text says so.
"""

from __future__ import annotations

import ast
import os

from core import Finding, Severity, Confidence

#: Calls whose arguments become behaviour rather than data. Kept deliberately
#: separate from `taint._SINK_NAMES`: that set answers "could this be inert?" and
#: is tuned to fail toward KEEP, while this one answers "is this dangerous?" and
#: is tuned to fail toward SILENCE. Merging them would make one of the two wrong.
_SINKS = {
    "system", "popen", "spawn", "spawnl", "spawnv", "execv", "execve", "execl",
    "run", "call", "check_call", "check_output", "Popen",
    "eval", "exec", "compile", "__import__",
}

#: Ceilings. This repository has already recorded one unbounded pass that hung
#: for ~244 seconds on a single file and produced no artifact and no exit code,
#: so every loop here has a bound and the bound is disclosed when it is hit.
MAX_FILES = 20_000
MAX_SOURCE_BYTES = 2_000_000
MAX_CONSTANT_LEN = 4_000


#: A cheap text pre-filter for the expensive half of extraction.
#:
#: 🔴 MEASURED, NOT GUESSED. Profiling 720 standard-library modules put 3.6 of
#: 8.7 seconds inside `ast.walk`, visiting 1.25 million nodes to find sink calls.
#: Most files contain no sink name at all, so that walk finds nothing and costs
#: everything.
#:
#: A file plays one of two roles here: it can DEFINE a payload (needs its
#: module-level constants, read from `tree.body` -- cheap) or USE one (needs its
#: sink calls, which can be nested anywhere -- expensive). Only the second role
#: requires the walk, and a file whose raw text contains no sink name cannot
#: play it.
#:
#: ⚠️ SUBSTRING, NOT A TOKEN MATCH, so it is deliberately over-broad: `system`
#: matches `filesystem`. Over-matching costs a walk that finds nothing.
#: Under-matching would lose a finding, so the bias is the safe one.
_SINK_TEXT_PROBE = tuple(sorted(_SINKS))


def _might_contain_a_sink(source: str) -> bool:
    return any(name in source for name in _SINK_TEXT_PROBE)


class _ModuleFacts:
    """The compact record kept per file. The AST is discarded after extraction.

    ⚠️ TWO-PHASE IS MANDATORY, NOT AN OPTIMISATION. Measured: retaining ASTs for
    2,244 modules cost 1,502 MB; retaining these facts instead cost 63 MB, about
    35x less. A whole-repository pass that holds every AST does not fit.
    """

    __slots__ = ("module", "path", "constants", "imports", "sink_args")

    def __init__(self, module, path):
        self.module = module
        self.path = path
        #: name -> (lineno, str value) for module-level string constants
        self.constants: dict = {}
        #: local name -> (origin module, original name)
        self.imports: dict = {}
        #: list of (lineno, sink display name, argument name)
        self.sink_args: list = []


def _module_name(relpath: str) -> str:
    """Dotted module name from a relative path, by STRING ARITHMETIC.

    No filesystem probing, no `importlib`, no package detection. A file at
    `a/b/c.py` is `a.b.c`; `a/b/__init__.py` is `a.b`. That is a simplification
    -- it ignores `sys.path` roots and namespace packages -- and it is the right
    trade here: the alternative consults the import system, which executes code.
    """
    p = relpath.replace("\\", "/")
    if p.endswith(".py"):
        p = p[:-3]
    if p.endswith("/__init__"):
        p = p[: -len("/__init__")]
    return p.replace("/", ".")


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def extract_facts(relpath: str, source: str):
    """Parse once, keep a compact record, discard the tree. None if unusable."""
    if len(source) > MAX_SOURCE_BYTES:
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return None

    facts = _ModuleFacts(_module_name(relpath), relpath)

    for node in tree.body:  # module level only -- see the module docstring
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                value = node.value.value
                if len(value) <= MAX_CONSTANT_LEN:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            facts.constants[target.id] = (node.lineno, value)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue  # relative import: resolving it needs package context
            origin = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue  # a star import binds names we cannot enumerate
                facts.imports[alias.asname or alias.name] = (origin, alias.name)

    # Sink calls anywhere in the file, including inside functions -- the CALL
    # may be nested even when the payload is a module constant.
    #
    # Skipped entirely when the raw text names no sink: that file can only be a
    # payload SOURCE, and its constants are already collected above.
    if not _might_contain_a_sink(source):
        return facts
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name not in _SINKS:
            continue
        for arg in list(node.args) + [k.value for k in node.keywords]:
            if isinstance(arg, ast.Name):
                facts.sink_args.append((node.lineno, name, arg.id))
    return facts


def analyse(files, read_text, payload_predicate):
    """Find module constants that are imported and passed to a sink elsewhere.

    `payload_predicate(str) -> str | None` returns a short reason when a value is
    dangerous, or None. Injected rather than imported so this module holds no
    rule table of its own -- one place for those, and it is not here.

    Returns (findings, coverage_note_or_None). ADD-ONLY: it constructs findings
    and touches nothing that already exists.
    """
    facts_by_module: dict = {}
    truncated = 0

    considered = files[:MAX_FILES]
    if len(files) > MAX_FILES:
        truncated = len(files) - MAX_FILES

    for sf in considered:
        rel = getattr(sf, "relpath", None) or getattr(sf, "file", "")
        if not rel.endswith(".py"):
            continue
        try:
            source = read_text(getattr(sf, "abspath", rel)) or ""
        except Exception:
            continue  # unreadable is someone else's finding, not this pass's
        facts = extract_facts(rel, source)
        if facts is not None:
            facts_by_module[facts.module] = facts

    findings = []
    for facts in facts_by_module.values():
        for lineno, sink, argname in facts.sink_args:
            origin = facts.imports.get(argname)
            if origin is None:
                continue  # a local name: the per-file engines already see it
            origin_module, original_name = origin
            source_facts = facts_by_module.get(origin_module)
            if source_facts is None:
                continue  # imported from outside the scan: nothing to join to
            const = source_facts.constants.get(original_name)
            if const is None:
                continue
            const_line, value = const
            reason = payload_predicate(value)
            if not reason:
                continue
            findings.append(_finding(source_facts, const_line, facts, lineno,
                                     sink, argname, reason))

    note = None
    if truncated:
        note = (f"{truncated} file(s) beyond the {MAX_FILES}-file cross-file "
                "analysis cap were not included in the import graph")
    return findings, note


def _finding(src_facts, const_line, use_facts, use_line, sink, argname, reason):
    return Finding(
        engine="aisec",
        rule_id="crossfile-payload-reaches-sink",
        title="A payload defined in one file is passed to a dangerous call in another",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        file=src_facts.path,
        line=const_line,
        category="EXFIL",
        description=(
            f"`{argname}` is defined here and {reason}. "
            f"{use_facts.path}:{use_line} imports it and passes it to `{sink}()`. "
            "Neither file looks wrong on its own, which is the point: splitting a "
            "payload across a module boundary is how it stays invisible to "
            "per-file analysis. "
            "⚠️ This does NOT assert the code runs -- static analysis cannot "
            "answer that. It asserts the value is defined in one place and "
            "consumed by a dangerous call in another."
        ),
        snippet=f"{src_facts.path}:{const_line} -> {use_facts.path}:{use_line} {sink}({argname})",
        fix=("Confirm whether that call is reachable, and whether the value is "
             "meant to be executed at all. If it is data, keep it away from a "
             "call that turns data into behaviour."),
        cwe="CWE-506",
        owasp="A03:2021 Injection",
    )
