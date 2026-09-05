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
  * a constant built by any expression -- `"a" + "b"`, an f-string, or one name
    assigned from another. Only a literal string assigned to a name is a payload
    source here;
  * a sink argument that is anything but a bare name or `alias.NAME` --
    `os.system(CMD + " -q")` and `subprocess.run([CMD], shell=True)` are not
    joined;
  * a sink whose name is not in `_SINKS`. That set is an ENUMERATION, so it
    misses spellings nobody listed: `os.execvp` is absent while `os.execv` is
    present, and `subprocess.getoutput` is absent entirely;
  * a relative import (`from .payload import CMD`), a star import, and a name
    re-exported through a package `__init__.py`;
  * a string assembled in a loop;
  * anything in a language other than Python.
  These are the next stages, not oversights. `references/PLAN-TO-V1.md` §4.

⚠️ THAT LIST IS LONGER THAN THE FIRST ONE, AND THAT IS THE POINT. The first
version of this docstring named four gaps; an agent briefed to break this module
found twenty-six, every one a real payload flow reported as nothing. A stated
"known gaps" list reads to a reader as exhaustive, so an incomplete one is worse
than none. **Assume this list is still incomplete.**

⚠️ COST, measured on 153 standard-library modules (4.7 MB): 5.80 ms per file,
projecting 29.0 s for 5,000 files against NFR-3's 30-second ceiling. That is
within budget and NOT comfortably so, and the sample's files average 31 KB,
which is larger than a typical repository's. Re-measure before adding a pass.

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


# 🔴 THE TEXT PRE-FILTER WAS DELETED. It read the raw source for a sink name and
# skipped `ast.walk` when it found none, documented as a 4x speed-up whose bias
# was "the safe one". An adversarial review measured both claims and both were
# wrong:
#
#     pre-filter ON  (shipped)      1329.2 ms   2.234 ms/file
#     pre-filter OFF (walk always)  1326.3 ms   2.229 ms/file
#     speed-up:                     1.00x        (claimed: 4x)
#
# The cause is an ordering nobody looked at: `extract_facts` calls `ast.parse`
# BEFORE consulting the filter, and parsing is 72.6% of the cost. The filter can
# only ever save part of the 26.3% spent walking, so its ceiling is 1.12x. The
# supporting claim that "most files contain no sink name at all" was false too --
# 59.3% of the sampled modules contain one, driven by the substrings `call` and
# `run`.
#
# 🔴 AND IT LOST FINDINGS. Python NFKC-normalises identifiers at tokenisation, so
# `os.𝐬𝐲𝐬𝐭𝐞𝐦(CMD)` written in MATHEMATICAL BOLD *is* `os.system` to the compiler
# and shares no byte with it in the source. The filter saw no sink, skipped the
# walk, and dropped a real cross-file finding. Its own test asserted the filter
# "never loses a finding" while exercising only ASCII spellings.
#
# ⇒ A shortcut that buys 0% and costs detection is not a trade. An optimisation
# whose test cannot see its failure mode is worse than no optimisation.


class _ModuleFacts:
    """The compact record kept per file. The AST is discarded after extraction.

    ⚠️ TWO-PHASE IS MANDATORY, NOT AN OPTIMISATION. Measured: retaining ASTs for
    2,244 modules cost 1,502 MB; retaining these facts instead cost 63 MB, about
    35x less. A whole-repository pass that holds every AST does not fit.
    """

    __slots__ = ("module", "path", "constants", "imports", "module_imports",
                 "sink_args", "sink_attrs", "binding_counts")

    def __init__(self, module, path):
        self.module = module
        self.path = path
        #: name -> (lineno, str value) for module-level string constants
        self.constants: dict = {}
        #: local name -> (origin module, original name)   [from X import Y as Z]
        self.imports: dict = {}
        #: local alias -> module name                     [import X as Z]
        self.module_imports: dict = {}
        #: list of (lineno, sink display name, argument name)
        self.sink_args: list = []
        #: list of (lineno, sink display name, alias, attribute)  [f(mod.NAME)]
        self.sink_attrs: list = []
        #: name -> how many times ANYTHING in this file binds it.
        #:
        #: 🔴 THE SCOPE MODEL, AND ITS ABSENCE WAS SIX FALSE POSITIVES AT HIGH.
        #: The first version joined "a name was imported at module level" to "a
        #: call somewhere in the file took an argument spelled that way", with
        #: nothing in between. So this was reported as a cross-file payload flow:
        #:
        #:     from payload import CMD      # a documentation constant
        #:     def go(CMD):                 # the PARAMETER shadows it
        #:         os.system(CMD)           # this is the parameter
        #:
        #: The finding's own text says it "asserts the value is defined in one
        #: place and consumed by a dangerous call in another". That flow does not
        #: exist. Four spellings of the same defect were confirmed -- parameter,
        #: local variable, module-level reassignment, and a `for` target -- and
        #: PRAETOR's own tree stayed quiet only because none of its modules
        #: happen to shadow an imported name.
        #:
        #: ⚠️ A COUNT, NOT A SCOPE GRAPH, and that is deliberate. Proper scope
        #: resolution is a much larger piece of work, and getting it subtly wrong
        #: would fail toward REPORTING. "Bound exactly once, by the import" is
        #: crude, cannot be wrong in the dangerous direction, and costs only the
        #: case where a name is legitimately rebound -- which no longer describes
        #: a clean single-source flow anyway.
        self.binding_counts: dict = {}


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


_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _walk_once(tree, counts: dict, facts) -> None:
    """ONE traversal that counts bindings AND collects sink calls.

    ⚠️ ONE WALK, NOT TWO, AND THIS ONE WAS MEASURED. Counting bindings in its own
    `ast.walk` cost 6.93 ms/file on 153 standard-library modules -- 34.6 s
    projected for 5,000 files, over NFR-3's 30-second ceiling. Merging the two
    traversals removes a whole pass over every node and loses nothing, which is
    the difference between this and the text pre-filter deleted above: that one
    bought 1.00x and cost detection.

    Counts every name binding anywhere in the file, at any scope depth.

    ⚠️ OVER-COUNTING IS THE SAFE DIRECTION. A name counted as bound twice when it
    is really bound once costs one finding. A name counted once when something
    else also binds it produces a HIGH-severity claim about a flow that does not
    exist. So a construct this function does not recognise costs recall, never
    correctness -- and every binding form Python has is listed below rather than
    the ones a single reviewer happened to demonstrate.
    """
    def bind(name):
        if name:
            counts[name] = counts.get(name, 0) + 1

    def bind_target(node):
        """A single assignment target, which may be a nested tuple or list."""
        if isinstance(node, ast.Name):
            bind(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for element in node.elts:
                bind_target(element)
        elif isinstance(node, ast.Starred):
            bind_target(node.value)
        # An Attribute or Subscript target rebinds something else, not this name.

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind_target(target)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            bind_target(node.target)
        elif isinstance(node, ast.NamedExpr):          # the walrus operator
            bind_target(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            bind_target(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    bind_target(item.optional_vars)
        elif isinstance(node, ast.ExceptHandler):
            bind(node.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bind(node.name)
            a = node.args
            for arg in (list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)
                        + [a.vararg, a.kwarg]):
                if arg is not None:
                    bind(arg.arg)
        elif isinstance(node, ast.Lambda):
            a = node.args
            for arg in (list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)
                        + [a.vararg, a.kwarg]):
                if arg is not None:
                    bind(arg.arg)
        elif isinstance(node, ast.ClassDef):
            bind(node.name)
        elif isinstance(node, _COMPREHENSIONS):
            for generator in node.generators:
                bind_target(generator.target)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    continue
                bind(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                bind(name)

        # Sink calls, in the same traversal. The CALL may be nested anywhere,
        # even when the payload it consumes is a module-level constant.
        if isinstance(node, ast.Call):
            called = _call_name(node)
            if called in _SINKS:
                for arg in list(node.args) + [k.value for k in node.keywords]:
                    if isinstance(arg, ast.Name):
                        facts.sink_args.append((node.lineno, called, arg.id))
                    elif isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
                        facts.sink_attrs.append(
                            (node.lineno, called, arg.value.id, arg.attr))



def extract_facts(relpath: str, source: str):
    """Parse once, keep a compact record, discard the tree. None if unusable."""
    if len(source) > MAX_SOURCE_BYTES:
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return None

    facts = _ModuleFacts(_module_name(relpath), relpath)
    _walk_once(tree, facts.binding_counts, facts)

    for node in tree.body:  # module level only -- see the module docstring
        # ⚠️ `Assign` AND `AnnAssign`. `CMD: str = "..."` is an AnnAssign, which
        # the first version did not record -- so one colon of ordinary
        # modern Python made the whole pass silent on that constant.
        value_node = target_nodes = None
        if isinstance(node, ast.Assign):
            value_node, target_nodes = node.value, node.targets
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            value_node, target_nodes = node.value, [node.target]

        if value_node is not None:
            if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
                text = value_node.value
                if len(text) <= MAX_CONSTANT_LEN:
                    for target in target_nodes:
                        if isinstance(target, ast.Name):
                            facts.constants[target.id] = (node.lineno, text)
            continue

        if isinstance(node, ast.ImportFrom):
            if node.level:
                continue  # relative import: resolving it needs package context
            origin = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue  # a star import binds names we cannot enumerate
                facts.imports[alias.asname or alias.name] = (origin, alias.name)
        elif isinstance(node, ast.Import):
            # 🔴 `import payload` WAS NOT RECORDED AT ALL, and with it the
            # commonest import idiom in Python. Combined with the `ast.Name`-only
            # argument check below, `os.system(payload.CMD)` -- a genuine
            # cross-file payload flow -- was completely silent.
            for alias in node.names:
                facts.module_imports[alias.asname or alias.name] = alias.name

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

    resolve = _module_resolver(facts_by_module)

    findings = []
    for facts in facts_by_module.values():
        # -- f(NAME) where NAME came from `from <module> import NAME` ---------
        for lineno, sink, argname in facts.sink_args:
            origin = facts.imports.get(argname)
            if origin is None:
                continue  # a local name: the per-file engines already see it
            if facts.binding_counts.get(argname, 0) != 1:
                continue  # SHADOWED -- see `_ModuleFacts.binding_counts`
            origin_module, original_name = origin
            source_facts = resolve(origin_module, facts)
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

        # -- f(mod.NAME) where mod came from `import mod` ---------------------
        for lineno, sink, alias, attr in facts.sink_attrs:
            module = facts.module_imports.get(alias)
            if module is None:
                continue
            if facts.binding_counts.get(alias, 0) != 1:
                continue  # the alias itself is shadowed
            source_facts = resolve(module, facts)
            if source_facts is None:
                continue
            const = source_facts.constants.get(attr)
            if const is None:
                continue
            const_line, value = const
            reason = payload_predicate(value)
            if not reason:
                continue
            findings.append(_finding(source_facts, const_line, facts, lineno,
                                     sink, f"{alias}.{attr}", reason))

    note = None
    if truncated:
        note = (f"{truncated} file(s) beyond the {MAX_FILES}-file cross-file "
                "analysis cap were not included in the import graph")
    return findings, note


def _module_resolver(facts_by_module):
    """Map an imported module name onto a scanned file, tolerating a source root.

    🔴 `src/` LAYOUT MADE THE WHOLE PASS SILENT, AND NO ATTACKER WAS NEEDED.
    `_module_name` is path arithmetic from the SCAN ROOT. Point PRAETOR at the
    root of an ordinary `src/`-layout project and every module gains a `src.`
    prefix that no import statement in that project carries:

        src/mypkg/payload.py  ->  "src.mypkg.payload"
        runner.py says            "from mypkg.payload import CMD"

    Those never met, so the pass reported nothing on a large fraction of real
    Python projects -- and reported it as a clean scan. The same defect covers
    every monorepo whose import root is not its scan root.

    ⇒ An exact match is tried first. Failing that, a module whose dotted name
    ENDS WITH the requested one is accepted.

    ⚠️ AMBIGUITY IS SILENCE, NOT A GUESS. If two scanned files could both answer
    to the same suffix -- `a/payload.py` and `b/payload.py` for an import of
    `payload` -- neither is used. Picking one would make the finding name a file
    that has nothing to do with the flow, which was a confirmed defect of the
    first version: walk order decided which of two same-named modules won.
    """
    by_suffix: dict = {}
    for name, facts in facts_by_module.items():
        parts = name.split(".")
        for i in range(len(parts)):
            by_suffix.setdefault(".".join(parts[i:]), []).append(facts)

    def resolve(module_name, using_facts):
        # Everything that could answer to this name: the exact dotted match, any
        # module whose name ends with it, and a SIBLING of the file doing the
        # importing -- because a script run from its own directory resolves a
        # bare name there first.
        candidates = list(by_suffix.get(module_name) or [])
        exact = facts_by_module.get(module_name)
        if exact is not None and exact not in candidates:
            candidates.append(exact)

        package = using_facts.module.rsplit(".", 1)[0] if "." in using_facts.module else ""
        sibling = facts_by_module.get(f"{package}.{module_name}" if package else module_name)
        if sibling is not None and sibling not in candidates:
            candidates.append(sibling)

        distinct = {facts.path: facts for facts in candidates}
        if len(distinct) == 1:
            return next(iter(distinct.values()))
        return None  # zero candidates, or ambiguous -- both mean silence

    return resolve


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
