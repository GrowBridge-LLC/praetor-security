"""F16: remediation advice must not recommend lifecycle-script execution."""

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]


def _emitted_texts(source: str):
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        names = {kw.arg for kw in node.keywords if kw.arg in {"fix", "description"}}
        f = node.func
        if isinstance(f, ast.Name) and f.id in {"print", "write"}:
            names.add(f.id)
        elif isinstance(f, ast.Attribute) and f.attr == "write":
            names.add(f.attr)
        if not names:
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                yield child.value


def _npm_fix_advice(texts):
    return [text for text in texts if "npm audit fix" in text]


def test_engine_advice_never_recommends_unqualified_npm_audit_fix():
    emitted = []
    for path in sorted((ROOT / "scripts").glob("*.py")):
        emitted.extend(_emitted_texts(path.read_text(encoding="utf-8")))
    advice = _npm_fix_advice(emitted)
    assert advice, "positive control: engine advice population must contain npm remediation text"
    assert all("--ignore-scripts" in text for text in advice)
    assert any("native build" in text for text in emitted)
    assert any("praetor: ENGINE MALFUNCTION" in text for text in emitted), (
        "corpus control: praetor.py's stderr surface must be enumerated"
    )


def test_forbidden_planted_advice_is_detected():
    planted = 'finding = Finding(fix="Run `npm audit fix` to remediate.")'
    advice = _npm_fix_advice(_emitted_texts(planted))
    assert advice
    assert any("--ignore-scripts" not in text for text in advice)


def test_impossible_token_is_not_reported():
    emitted = []
    for path in sorted((ROOT / "scripts").glob("*.py")):
        emitted.extend(_emitted_texts(path.read_text(encoding="utf-8")))
    assert not any("THIS_TOKEN_CANNOT_EXIST_F16" in text for text in emitted)
