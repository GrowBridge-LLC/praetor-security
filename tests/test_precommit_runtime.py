"""Exercise the gate's real runtime preflight before expensive suites start."""
import os
from pathlib import Path
import subprocess
import sys
import shutil
import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "tests/precommit.sh"


def _bash():
    if sys.platform == "win32":
        git = shutil.which("git")
        if git:
            git_dir = Path(git).resolve().parent
            if git_dir.name.lower() == "bin" and git_dir.parent.name.lower() in ("mingw32", "mingw64"):
                git_dir = git_dir.parent
            candidate = git_dir.parent / "bin/bash.exe"
            if candidate.is_file():
                return str(candidate)
        raise RuntimeError("Git Bash is required; WSL bash cannot run native Python")
    return shutil.which("bash")


@pytest.mark.parametrize("git_directory", ["cmd", "bin", "mingw64/bin", "mingw32/bin"])
def test_git_bash_locator_supports_git_install_layouts(tmp_path, monkeypatch, git_directory):
    install = tmp_path / "Git"
    bash = install / "bin/bash.exe"
    bash.parent.mkdir(parents=True)
    bash.touch()
    git = install / git_directory / "git.exe"
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(shutil, "which", lambda name: str(git) if name == "git" else None)
    assert _bash() == str(bash)


def preflight(tmp_path, *, target=None, python=sys.executable, discovery=""):
    source = GATE.read_text(encoding="utf-8")
    # Execute the production preflight, not a second implementation of it.
    body = source.split('# PYTHON is one executable', 1)[1].split('\nFAILED=0', 1)[0]
    env = dict(os.environ, ROOT=str(ROOT))
    env.pop("PYTHON", None)
    if python is not None:
        env["PYTHON"] = python
    env.pop("CARGO_TARGET_DIR", None)
    if target is not None:
        env["CARGO_TARGET_DIR"] = str(target)
    return subprocess.run(
        [_bash(), "-c", "set -uo pipefail\n" + discovery
         + "\n# PYTHON is one executable" + body
         + '\nprintf "TARGET=%s\\n" "$CARGO_TARGET_DIR"\n'
         + 'printf "PYTHON=%s\\n" "${PYTHON_CMD[*]}"\n'
         + '''"${PYTHON_CMD[@]}" -c 'import os; print("TARGET_BYTES=" + os.fsencode(os.environ["CARGO_TARGET_DIR"]).hex())'\n'''],
        cwd=ROOT, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="surrogateescape",
    )


def test_unset_cargo_target_is_rejected(tmp_path):
    result = preflight(tmp_path)
    assert result.returncode == 2
    assert "Set CARGO_TARGET_DIR" in result.stderr


def test_external_cargo_target_is_accepted(tmp_path):
    result = preflight(tmp_path, target=tmp_path / "build")
    assert result.returncode == 0, result.stderr
    assert f"TARGET={(tmp_path / 'build').resolve()}" in result.stdout


def test_cargo_target_bytes_ignore_python_stdout_encoding(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONIOENCODING", "cp1252")
    target = tmp_path / "build-\u00e9"
    result = preflight(tmp_path, target=target)
    assert result.returncode == 0, result.stderr
    assert f"TARGET={target.resolve()}\n" in result.stdout
    assert f"TARGET_BYTES={os.fsencode(str(target.resolve())).hex()}\n" in result.stdout


def test_in_tree_cargo_target_is_rejected(tmp_path):
    result = preflight(tmp_path, target=ROOT / "rust/target")
    assert result.returncode == 2
    assert "inside the repository" in result.stderr


def test_trailing_newline_cargo_target_is_rejected(tmp_path):
    # Command substitution must not turn an approved sibling into ROOT.
    result = preflight(tmp_path, target=str(ROOT) + "\n")
    assert result.returncode == 2
    assert "CARGO_TARGET_DIR" in result.stderr


def test_symlink_into_tree_is_rejected(tmp_path):
    link = tmp_path / "alias"
    if sys.platform == "win32":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(ROOT)], check=True)
    else:
        link.symlink_to(ROOT, target_is_directory=True)
    result = preflight(tmp_path, target=link / "rust/target")
    assert result.returncode == 2
    assert "inside the repository" in result.stderr


def test_invalid_explicit_python_never_falls_back(tmp_path):
    result = preflight(tmp_path, target=tmp_path / "build", python=str(tmp_path / "missing"))
    assert result.returncode == 2
    assert "selected Python" in result.stderr


def test_discovery_prefers_working_python3(tmp_path, monkeypatch):
    # Functions model executable discovery without depending on a host's PATH.
    discovery = 'python3() { "$TEST_PYTHON" "$@"; }; py() { return 97; };'
    monkeypatch.setenv("TEST_PYTHON", sys.executable)
    result = preflight(tmp_path, target=tmp_path / "build", python=None, discovery=discovery)
    assert result.returncode == 0, result.stderr
    assert "PYTHON=python3" in result.stdout


def test_broken_python3_falls_through_to_working_py(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_PYTHON", sys.executable)
    discovery = 'python3() { return 97; }; py() { shift; "$TEST_PYTHON" "$@"; };'
    result = preflight(tmp_path, target=tmp_path / "build", python=None, discovery=discovery)
    assert result.returncode == 0, result.stderr
    assert "PYTHON=py -3" in result.stdout
