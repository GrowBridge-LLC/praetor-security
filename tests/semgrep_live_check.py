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

        # 3. THE FLAG WAS ACCEPTED, not silently fallen back on. engine_sast
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
        else:
            detail = sast_meta.get("detail") or ""
            check("this semgrep accepts the scope flag (no fallback)",
                  "rejected" not in detail,
                  ("detail said: ..." + detail[-110:]) if "rejected" in detail else "")

    print("== %s ==" % ("ALL LIVE CHECKS PASSED" if not failures
                        else "LIVE CHECK FAILURES: " + ", ".join(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
