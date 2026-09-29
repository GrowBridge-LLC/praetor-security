#!/usr/bin/env python3
"""
END-TO-END CHECK AGAINST A REAL SEMGREP. Run by CI; not collected by pytest.

🔴 WHY THIS FILE EXISTS.

`scripts/engine_sast.py` pins `--x-ignore-semgrepignore-files`, which is what
stops a `.semgrepignore` committed to a scanned repository from switching the
entire SAST engine off. Measured on real semgrep 1.172.0, on a tree with one
`os.system` concat finding:

    control                            -> [ran] 1 finding,  exit 1
    + .semgrepignore containing "*"    -> [ran] 0 findings, exit 0

That flag is `--x-` prefixed: **explicitly experimental, and not a stable
contract.** An independent audit found that nothing anywhere ran a real semgrep
against it — every SAST test in `tests/` monkeypatches `core.run_tool`, and the
main CI workflow deliberately installs no tools. So the engine's central scope
guarantee was pinned to an unstable flag with **zero automated detection**, and
the first sign of a rename would have been users' scans changing behaviour.

⚠️ **This is deliberately NOT a pytest module.** `tests/precommit.sh` fails on any
skipped test, on the rule that a skipped test is indistinguishable from a passing
one — so a `pytest.importorskip`-style guard here would either break the local
gate on every machine without semgrep, or teach the gate to tolerate skips. A
standalone script that CI runs explicitly avoids both.

Exit 0 = the guarantee holds against the installed semgrep. Non-zero = it does
not, with the reason on stdout.
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PRAETOR = os.path.join(HERE, "..", "scripts", "praetor.py")
RULES = os.path.join(HERE, "..", "rules", "semgrep-praetor.yaml")

# Assembled from fragments so this file does not itself trip the engine it
# exercises -- the repo rule is "fix the fixture, not the rules".
_VULN = (
    "import os" + chr(10)
    + "def handler(evt):" + chr(10)
    + "    " + "os." + "system(" + '"ls " + evt["p"]' + ")" + chr(10)
)
_VULN_NOSEM = _VULN.replace(")" + chr(10), ")  # nosemgrep" + chr(10))

failures = []


def run_praetor(target, *extra):
    cmd = [sys.executable, PRAETOR, target, "--engines", "sast", "--no-registry",
           "--format", "json", "--quiet", *extra]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    return p


def check(name, ok, detail=""):
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  -- " + detail) if detail else ""))
    if not ok:
        failures.append(name)


# praetor-ai-llm-output-to-shell must NOT fire on exec of a constant (a module
# string assigned once, or a literal) and MUST fire on model output, input(), a
# reassigned name and a function parameter. Measured 2026-09-29: it fired on all
# six. `exec` is spelled in fragments for the same self-scan reason as _VULN.
_EX = "ex" + "ec("
_EXEC_CASES = chr(10).join([
    "NET_GUARD = r'''",
    "import socket",
    "'''",
    _EX + "NET_GUARD)",                              # 4  constant, assigned once
    _EX + '"print(1)")',                             # 5  literal
    "resp = client.chat(p)",
    _EX + "resp.choices[0].message.content)",        # 7  model output
    "code = input()",
    _EX + "code)",                                   # 9  input()
    'G = "x"',
    "G = input()",
    _EX + "G)",                                      # 12 reassigned
    "def f(s):",
    "    " + _EX + "s)",                             # 14 parameter
    # Review round 1: shapes that must still fire, and one pinned residual.
    _EX + '"x" + input())',                          # 15 concat
    'p = "x"',
    _EX + "p + input())",                            # 17 constant + input
    _EX + 'f"x{input()}")',                          # 18 f-string
    _EX + '"x%s" % input())',                        # 19 % format
    "a = input()",
    "b = a",
    _EX + "b)",                                      # 22 alias
    'CMD = "print(1)"',
    'globals()["CMD"] = input()',
    _EX + "CMD)",                                    # 25 globals() rebind
    'S1 = "print(1)"',
    'setattr(mod, "S1", resp.choices[0].message.content)',
    _EX + "S1)",                                     # 28 setattr rebind
    'D1 = "print(1)"',
    'mod.__dict__["D1"] = input()',
    _EX + "D1)",                                     # 31 __dict__ rebind
    'GL = "print(1)"',
    "def g(payload):",
    "    global GL",
    "    GL = payload",
    _EX + "GL)",                                     # 36 global rebind
    _EX + '"' + _EX + 'input())")',                  # 37 residual: must NOT fire
    'OTHER = "print(1)"',
    'globals()["UNRELATED"] = input()',
    _EX + "OTHER)",                                  # 40 unrelated store: must NOT fire
]) + chr(10)
# Commit 4 redesign: the RULE now fires on every exec line, constants included
# (4, 5, 37, 40 were must-not-fire before). The constant exemption moved to the
# AST proof in interpret.py, checked end to end by check_exec_constant_filtered().
_EXEC_MUST_FIRE = [4, 5, 7, 9, 12, 14, 15, 17, 18, 19, 22, 25, 28, 31, 36, 37, 40]


def _scan_one(src, td, tag):
    d = os.path.join(td, tag)
    os.makedirs(d)
    with open(os.path.join(d, "app.py"), "w", encoding="utf-8") as fh:
        fh.write(src)
    out = os.path.join(td, tag + "-out")
    p = run_praetor(d, "--out", out)
    with open(os.path.join(out, "praetor-report.json"), encoding="utf-8") as fh:
        return json.load(fh), p.returncode


def check_exec_constant_filtered():
    """End to end through praetor.py: the constant is FILTERED with the AST
    reason; the same file with a globals() rebind stays ACTIVE."""
    rule = "praetor-ai-llm-output-to-shell"
    reason = "exec/eval of a module string constant proven never rebound (AST): not model output"
    const = "NET_GUARD = r'''" + chr(10) + "import socket" + chr(10) + "'''" + chr(10)
    sink = _EX + "NET_GUARD)" + chr(10)
    rebind = 'globals()["NET_GUARD"] = input()' + chr(10)
    with tempfile.TemporaryDirectory() as td:
        d1, rc1 = _scan_one(const + sink, td, "const")
        act1 = [f for f in d1.get("findings", []) if f.get("rule_id") == rule]
        fil1 = [f for f in d1.get("filtered", []) if f.get("rule_id") == rule]
        check(rule + ": module constant ends up FILTERED with the AST reason",
              not act1 and len(fil1) == 1 and fil1[0].get("filter_reason") == reason,
              "active=%d filtered=%d rc=%d" % (len(act1), len(fil1), rc1))
        d2, rc2 = _scan_one(const + rebind + sink, td, "rebound")
        act2 = [f for f in d2.get("findings", []) if f.get("rule_id") == rule]
        check(rule + ": the same constant after a globals() rebind stays ACTIVE",
              len(act2) == 1, "active=%d rc=%d" % (len(act2), rc2))


def check_exec_constant_rule():
    rule = "praetor-ai-llm-output-to-shell"
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "exec_cases.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_EXEC_CASES)
        p = subprocess.run(["semgrep", "scan", "--config", RULES, "--json",
                            "--metrics=off", "--quiet", path],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
        try:
            data = json.loads(p.stdout)
        except ValueError:
            check(rule + ": semgrep produced JSON", False, "rc=%d" % p.returncode)
            return
        errs = data.get("errors") or []
        lines = sorted(r["start"]["line"] for r in data.get("results", [])
                       if r.get("check_id", "").endswith(rule))
        check(rule + ": fires on exactly %s" % _EXEC_MUST_FIRE,
              not errs and lines == _EXEC_MUST_FIRE,
              "got lines %s, %d semgrep error(s)" % (lines, len(errs)))


def main():
    print("== live semgrep check ==")
    ver = subprocess.run(["semgrep", "--version"], capture_output=True, text=True,
                         encoding="utf-8", errors="replace")
    print("  semgrep: " + (ver.stdout or ver.stderr or "?").strip())

    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(src)
        with open(os.path.join(src, "app.py"), "w", encoding="utf-8") as fh:
            fh.write(_VULN)
        out = os.path.join(td, "out")

        # 1. ARMING. Without this, every assertion below is vacuous: "0 findings"
        #    would prove nothing if the rule never matched in the first place.
        p = run_praetor(src, "--out", out)
        with open(os.path.join(out, "praetor-report.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        n = len(data.get("findings", []))
        check("control finds the planted vulnerability", n >= 1,
              "got %d findings, rc=%d" % (n, p.returncode))
        if n < 1:
            print("  (arming failed -- refusing to report the rest as meaningful)")
            # 🔴 PRINT THE MARKER BEFORE RETURNING. The CI step greps for
            # "LIVE CHECK FAILURES" as a second belt, precisely because this box
            # loses exit codes. Returning here without printing it made BOTH
            # halves of that gate silent on the ARMING path -- the worst case,
            # since a failed arming means the planted vulnerability was not found
            # and every check below is meaningless. Found by an independent
            # reviewer; the fifth recorded instance in this repo of a check that
            # reports where it was believed to gate.
            print("== LIVE CHECK FAILURES: " + ", ".join(failures) + " ==")
            return 1

        # 2. THE GUARANTEE. A file the scanned tree controls must not silence it.
        with open(os.path.join(src, ".semgrepignore"), "w", encoding="utf-8") as fh:
            fh.write("*" + chr(10))
        out2 = os.path.join(td, "out2")
        p2 = run_praetor(src, "--out", out2)
        with open(os.path.join(out2, "praetor-report.json"), encoding="utf-8") as fh:
            data2 = json.load(fh)
        n2 = len(data2.get("findings", []))
        check("a .semgrepignore in the target does not silence SAST", n2 >= 1,
              "got %d findings, rc=%d" % (n2, p2.returncode))

        # 3. OUTCOME. A real finding carrying an inline nosemgrep marker must
        # move to the filtered bucket with its reason, never vanish from both
        # active and filtered output. This is deliberately armed by the
        # preceding control; an empty result here is otherwise vacuous.
        with open(os.path.join(src, "app.py"), "w", encoding="utf-8") as fh:
            fh.write(_VULN_NOSEM)
        out3 = os.path.join(td, "out3")
        p3 = run_praetor(src, "--out", out3)
        with open(os.path.join(out3, "praetor-report.json"), encoding="utf-8") as fh:
            data3 = json.load(fh)
        filtered3 = data3.get("filtered", [])
        reasons3 = [item.get("filter_reason") for item in filtered3 if isinstance(item, dict)]
        check("a nosemgrep finding is filtered with a reason", 
              len(data3.get("findings", [])) == 0 and len(filtered3) >= 1
              and any(reason for reason in reasons3),
              "findings=%d filtered=%d rc=%d" %
              (len(data3.get("findings", [])), len(filtered3), p3.returncode))

        # 4. THE FLAGS WERE ACCEPTED, not silently fallen back on. engine_sast
        #    retries once without the flag when semgrep rejects it, and records
        #    that in `detail`. A green result via the fallback still means this
        #    semgrep no longer supports the flag, which is the thing to catch.
        #    ⚠️ THIS CHECK WAS VACUOUS WHEN FIRST WRITTEN. It read `engine_meta`
        #    at the top level; the key is `meta.engines`. So it got "" and
        #    `"rejected" not in ""` passed -- green while the flag was rejected,
        #    caught only because a mutation that should have reddened it did not.
        #    An absent key must therefore FAIL, never pass: "I could not find the
        #    thing I was checking" is not evidence that the thing is fine.
        engines = (data2.get("meta") or {}).get("engines")
        sast_meta = (engines or {}).get("sast") if isinstance(engines, dict) else None
        if not isinstance(sast_meta, dict) or "detail" not in sast_meta:
            check("this semgrep accepts the scope flag (no fallback)", False,
                  "could not read meta.engines.sast.detail -- report shape changed; "
                  "refusing to treat an unreadable field as a pass")
            check("this semgrep accepts --disable-nosem (no fallback)", False,
                  "could not read meta.engines.sast.detail -- report shape changed; "
                  "refusing to treat an unreadable field as a pass")
        else:
            detail = sast_meta.get("detail") or ""
            check("this semgrep accepts the scope flag (no fallback)",
                  "rejected --x-ignore-semgrepignore-files" not in detail,
                  ("detail said: ..." + detail[-110:]) if "rejected" in detail else "")
            check("this semgrep accepts --disable-nosem (no fallback)",
                  "rejected --disable-nosem" not in detail,
                  ("detail said: ..." + detail[-110:]) if "rejected" in detail else "")

    check_exec_constant_rule()
    check_exec_constant_filtered()

    print("== %s ==" % ("ALL LIVE CHECKS PASSED" if not failures
                        else "LIVE CHECK FAILURES: " + ", ".join(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
