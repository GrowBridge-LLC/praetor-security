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
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import engine_sast

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


def _scanned_top_dirs(payload, root, candidates):
    """Top-level candidate directories Semgrep says it opened in this corpus."""
    paths = ((payload.get("paths") or {}).get("scanned") or [])
    found = set()
    for path in paths:
        rel = os.path.relpath(path, root) if os.path.isabs(path) else path
        top = rel.replace("\\", "/").split("/", 1)[0]
        if top in candidates:
            found.add(top)
    return found


def _measure_default_ignores():
    """Measure Semgrep defaults; an upgrade must not silently change scope."""
    candidates = set(engine_sast.SEMGREP_DEFAULT_IGNORE_DIRS)
    # Include every directory PRAETOR's own source walk names as noise. The
    # expected set is intentionally a subset: widening the explicit restore to
    # this whole list was the original regression.
    candidates |= set(engine_sast.core.DEFAULT_SKIP_DIRS)
    with tempfile.TemporaryDirectory() as td:
        for directory in candidates:
            d = os.path.join(td, directory)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "probe.py"), "w", encoding="utf-8") as fh:
                fh.write("x = 1" + chr(10))
        base = ["semgrep", "--config", RULES, "--json", "--quiet", "--metrics", "off",
                "--disable-version-check", "--no-git-ignore"]
        normal = subprocess.run(base + [td], capture_output=True, text=True,
                                encoding="utf-8", errors="replace")
        widened = subprocess.run(base + [engine_sast._SEMGREPIGNORE_OFF, td],
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace")
        if normal.returncode not in (0, 1) or widened.returncode not in (0, 1):
            return None, (
                "Semgrep measurement failed: normal rc=%d (%s); flag rc=%d (%s)" %
                (normal.returncode, (normal.stderr or "").strip()[-180:],
                 widened.returncode, (widened.stderr or "").strip()[-180:])
            )
        try:
            normal_doc = json.loads(normal.stdout or "{}")
            widened_doc = json.loads(widened.stdout or "{}")
        except json.JSONDecodeError as exc:
            return None, "Semgrep measurement returned invalid JSON: %s" % exc
        normal_dirs = _scanned_top_dirs(normal_doc, td, candidates)
        widened_dirs = _scanned_top_dirs(widened_doc, td, candidates)
        # A candidate omitted in both runs is not evidence of a default ignore;
        # e.g. a future Semgrep might reject a directory structurally. Require it
        # to be visible with the experimental flag before treating the difference
        # as a restorable default.
        return {d for d in candidates if d in widened_dirs and d not in normal_dirs}, ""


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

        # 4. MEASURE THE FLAG'S OTHER EFFECT. It disables Semgrep's built-in
        # defaults as well as `.semgrepignore`; the wrapper restores exactly the
        # measured set. This is intentionally live rather than a pytest fixture:
        # a mocked Semgrep cannot tell us what a newer Semgrep actually ignores.
        observed, measurement_error = _measure_default_ignores()
        if observed is None:
            check("Semgrep default-ignore measurement completed", False, measurement_error)
        else:
            expected = set(engine_sast.SEMGREP_DEFAULT_IGNORE_DIRS)
            check("Semgrep default-ignore set matches PRAETOR restore", observed == expected,
                  "observed=%s expected=%s" % (sorted(observed), sorted(expected)))

    print("== %s ==" % ("ALL LIVE CHECKS PASSED" if not failures
                        else "LIVE CHECK FAILURES: " + ", ".join(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
