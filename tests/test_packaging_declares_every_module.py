"""
The wheel must contain every module the source tree imports.

🔴 WHY THIS TEST EXISTS. `scripts/chains.py` and `scripts/capability.py` shipped
in two commits without being added to `pyproject.toml`'s `py-modules`. The whole
suite stayed green, because every test imports from the SOURCE tree. The break
only appears in an INSTALLED wheel, where `interpret.py` raises ImportError on
the first scan -- so a user's very first run fails, and no test PRAETOR runs on
itself could ever have seen it.

This is the same class as the earlier `data-files` bug, where declaring the
bundled Semgrep rules as `package-data` built a wheel with no rules in it and an
installed `--no-registry` run silently found nothing. Both were hand-kept lists
that drifted. This test reads the list instead of trusting it.
"""

import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SCRIPTS = _ROOT / "scripts"
_PYPROJECT = _ROOT / "pyproject.toml"


def _declared_modules():
    text = _PYPROJECT.read_text(encoding="utf-8")
    block = re.search(r"py-modules\s*=\s*\[(.*?)\]", text, re.DOTALL)
    assert block, "pyproject.toml no longer declares py-modules -- read it, do not assume"
    return set(re.findall(r'"([^"]+)"', block.group(1)))


def _source_modules():
    return {p.stem for p in _SCRIPTS.glob("*.py")}


_IMPORT_RE = re.compile(r"^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)


def _reachable_from_entry_point():
    """Every sibling module an installed run can reach from the CLI entry point.

    ⚠️ NOT a glob over `scripts/`. That over-reaches: `kb-build.py` is a build
    tool whose name is not even a valid identifier, so it can never be imported
    and has no business in a wheel. Requiring it would have been a test that
    fails for a reason unrelated to the defect it exists to catch -- and the
    tempting repair, an exclusion list, is one more hand-kept list of exactly
    the kind that produced this bug.

    Reachability is the property that actually matters: if an installed run can
    import it, the wheel must contain it.
    """
    modules = _source_modules()
    reached, frontier = set(), ["praetor"]
    while frontier:
        name = frontier.pop()
        if name in reached:
            continue
        reached.add(name)
        source = (_SCRIPTS / f"{name}.py").read_text(encoding="utf-8")
        frontier.extend(
            found for found in _IMPORT_RE.findall(source)
            if found in modules and found not in reached
        )
    return reached


def test_every_module_an_installed_run_imports_is_declared():
    missing = _reachable_from_entry_point() - _declared_modules()
    assert not missing, (
        f"these modules are imported at run time but would NOT be installed: "
        f"{sorted(missing)}. An installed wheel raises ImportError on the first "
        "scan; the source-tree test suite cannot see it. Add them to "
        "pyproject.toml's py-modules."
    )


def test_no_declared_module_is_missing_from_the_source_tree():
    """THE OTHER DIRECTION. A stale name here builds a wheel that fails at BUILD
    time rather than run time -- less dangerous, still broken, and it hides which
    of the two lists is actually wrong."""
    stale = _declared_modules() - _source_modules()
    # Checked against the full source tree, not the reachable set: a module that
    # exists but is not reached today may be reached tomorrow, and shipping it
    # early is harmless. A module that does not exist at all is not.
    assert not stale, (
        f"pyproject.toml declares modules that no longer exist: {sorted(stale)}"
    )
