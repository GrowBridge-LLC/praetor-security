"""
A1 -- reachability: does a matched string ever reach a DANGEROUS SINK?

WHY THIS IS THE RIGHT MECHANISM, measured
-----------------------------------------
15 of PRAETOR's 24 remaining self-scan findings are strings inside its own regex
tables, filename allowlists and finding templates. They are compared against
text; they are never executed, shelled, or opened.

S3 declined to suppress them with the STRUCTURAL rule "the match is inside a
collection literal", because that is equally true of `API_KEYS = ["sk-ant-…"]`
in an ordinary application -- it would hide real credentials.

This module uses the SEMANTIC rule instead:

    structural : "is it inside a collection?"       -> position in the source
    semantic   : "does it reach a dangerous sink?"  -> what the value is USED FOR

For BEHAVIOURAL findings that is the better question, and it is what suppresses
the 15: a regex literal is compared against text and reaches nothing.

⚠️ It does NOT, however, make the analysis self-sufficient -- see immediately
below, because the opposite was claimed first.

🔴 BUT REACHABILITY IS *NOT* SELF-SUFFICIENT, AND ASSUMING IT WAS IS AN ERROR THIS
   MODULE WAS BUILT TO CORRECT
------------------------------------------------------------------------------
The reasoning above was posted to the coordination channel as "A1 is the safe
general form of the unsafe structural rule." Then it was measured:

    API_KEYS = ["sk-ant-…"]        # never used in this file
    -> is_provably_inert() == True     <-- IDENTICAL to a regex pattern

A leaked credential in a config module is typically never USED in the file that
declares it, so reachability proves it inert and would suppress it. The claim
that "a credential IS the payload, so it reaches a sink" is false exactly where
it matters most.

⇒ The S3 asymmetry is UNCHANGED and is what actually provides the safety:
   a SECRET is disclosed by being WRITTEN DOWN, not by being executed.
   So reachability suppression is scoped to behavioural engines and the secrets
   engine is excluded -- the same carve-out lexctx needs, for the same reason.
   The safety comes from the SCOPE, never from the analysis.
   Held by tests/test_taint_reachability.py.

🔴 FAILS SAFE, BY CONSTRUCTION
------------------------------
The only exported question is `is_provably_inert`, and it answers True ONLY when
inertness is PROVEN. Unparseable file, unfamiliar shape, dynamic access, string
built at runtime, anything unrecognised -> False -> the finding is KEPT.

A reachability engine that guesses "inert" is a scanner that goes quiet under
exactly the conditions an attacker creates.

⚠️ LIMITS, stated rather than discovered later:
  * Python only. Other languages -> False (kept).
  * INTRA-FILE only. A name exported and used elsewhere is treated as reachable.
  * One assignment hop. Deeper chains -> False (kept).
  * No attribute/alias tracking (`s = os.system; s(x)`) -> the call is unrecognised,
    so the literal is not proven inert -> kept. Conservative in the safe direction.
"""

from __future__ import annotations

import ast

# Calls whose arguments become behaviour rather than data.
_SINK_NAMES = {
    "system", "popen", "spawn", "spawnl", "spawnv", "execv", "execve", "execl",
    "run", "call", "check_call", "check_output", "Popen",
    "eval", "exec", "compile", "__import__",
    "open", "read_text", "write_text", "unlink", "remove", "rmtree",
    "urlopen", "get", "post", "put", "delete", "request", "connect", "send", "sendall",
    "loads",  # deserialisation of attacker-controlled data
}

# `re.compile(...)` and friends consume a string AS A PATTERN -- the canonical
# inert use, and the one that dominates a scanner's own source.
_PATTERN_CONSUMERS = {"compile", "match", "search", "fullmatch", "findall", "finditer", "sub", "subn"}


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _is_regex_module_call(node: ast.Call) -> bool:
    """True for `re.compile(...)` / `re.match(...)` etc. -- module-qualified only."""
    f = node.func
    return (
        isinstance(f, ast.Attribute)
        and f.attr in _PATTERN_CONSUMERS
        and isinstance(f.value, ast.Name)
        and f.value.id == "re"
    )


def _parents(tree: ast.AST) -> dict:
    table = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            table[child] = parent
    return table


def _string_nodes_on_line(tree: ast.AST, lineno: int) -> list:
    return [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
        and getattr(n, "lineno", -1) <= lineno <= getattr(n, "end_lineno", getattr(n, "lineno", -1))
    ]


def _enclosing_assigned_names(node, parents) -> list:
    """Walk up to the enclosing Assign, if any, and return its target names."""
    cur = node
    while cur in parents:
        cur = parents[cur]
        if isinstance(cur, ast.Assign):
            names = []
            for t in cur.targets:
                if isinstance(t, ast.Name):
                    names.append(t.id)
            return names
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            break
    return []


def _name_escapes(tree: ast.AST, name: str) -> bool:
    """
    True if `name` flows into ANY call we cannot prove inert, or is itself called.

    🔴 DELIBERATELY BROADER THAN "reaches a known sink". An earlier version matched
    only `_SINK_NAMES`, so an ALIASED sink defeated it:

        CMD = "rm -rf /"
        s = os.system      # alias -- callee is `s`, not in _SINK_NAMES
        s(CMD)             # ...so CMD was reported "provably inert"

    The docstring already claimed such a shape would be conservatively KEPT. It
    did not, and the test caught the claim rather than the code. Unknown callee
    now means UNPROVEN, which is the direction the whole module must fail in.

    Regex-module calls are the one recognised inert consumer.
    """
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        # the name used as the callee, e.g. cmd(...)
        if isinstance(n.func, ast.Name) and n.func.id == name:
            return True
        if _is_regex_module_call(n):
            continue  # consuming a string AS A PATTERN is inert
        for arg in list(n.args) + [k.value for k in n.keywords]:
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Name) and sub.id == name:
                    return True
    return False


def is_provably_inert(source: str, lineno: int) -> bool:
    """
    True ONLY if every string literal on `lineno` provably never reaches a sink.

    Returns False on any doubt -- unparseable source, no literal found, an
    unrecognised construct, or a name that escapes this file's analysis.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return False  # cannot analyse -> keep

    nodes = _string_nodes_on_line(tree, lineno)
    if not nodes:
        return False  # nothing to reason about -> keep

    parents = _parents(tree)

    for node in nodes:
        # 1. Directly an argument to a dangerous call -> reachable, stop.
        cur, direct_sink, pattern_use = node, False, False
        while cur in parents:
            cur = parents[cur]
            if isinstance(cur, ast.Call):
                if _is_regex_module_call(cur):
                    pattern_use = True
                    break
                if _call_name(cur) in _SINK_NAMES:
                    direct_sink = True
                    break
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                break
        if direct_sink:
            return False
        if pattern_use:
            continue  # consumed as a regex pattern: inert

        # 2. Otherwise it must live in an assignment whose name never reaches a sink.
        names = _enclosing_assigned_names(node, parents)
        if not names:
            return False  # bare literal in an unrecognised position -> keep
        if any(_name_escapes(tree, nm) for nm in names):
            return False

    return True
