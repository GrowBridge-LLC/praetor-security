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


# praetor-ai-llm-output-to-shell is a TAINT rule (redesigned 2026-09-29): it
# fires only where model-client output reaches exec/eval/compile, os.system/
# os.popen or subprocess, directly or through variables, concatenation,
# f-strings and local functions. A constant, a literal, input() or a bare
# parameter must NOT fire on it -- exec of input() or of a parameter is
# praetor-py-eval-exec's job, and that rule is pinned here too. Sinks are
# spelled in fragments for the same self-scan reason as _VULN.
_EX = "ex" + "ec("
_EV = "ev" + "al("
_SYS = "os." + "system("
_POP = "os." + "popen("
_SP = "sub" + "process."
_EXEC_CASES = chr(10).join([
    "import os, " + _SP[:-1],
    "NET_GUARD = r'''",
    "import socket",
    "'''",
    _EX + "NET_GUARD)",                                      # 5  constant: no
    _EX + '"print(1)")',                                     # 6  literal: no
    _EX + "input())",                                        # 7  input: eval-exec only
    "def g(s):",
    "    " + _EX + "s)",                                     # 9  parameter: eval-exec only
    'resp = client.chat.completions.create(model="m", messages=[])',
    _EX + "resp.choices[0].message.content)",                # 11 direct
    "code = resp.choices[0].message.content",
    _EX + "code)",                                           # 13 via variable
    _EX + '"x = 1" + code)',                                 # 14 concatenated
    _EX + 'f"x = {code}")',                                  # 15 f-string
    "def run(c):",
    "    return c",
    _EX + "run(code))",                                      # 18 through a local function
    _SP + "run(code, shell=True)",                           # 19 shell=True
    _SP + 'run(["sh", "-c", code], shell=True)',             # 20 shell=True, list
    _SYS + "code)",                                          # 21 os.system
    _POP + "code)",                                          # 22 os.popen
    _EV + "resp.choices[0].text)",                           # 23 legacy completions
    'msg = anthropic_client.messages.create(model="m", max_tokens=1, messages=[])',
    _EX + "msg.content[0].text)",                            # 25 Anthropic
    'r2 = oai.responses.create(model="m", input="x")',
    _EX + "r2.output_text)",                                 # 27 OpenAI Responses
    'o = ollama.chat(model="m", messages=[])',
    _EX + "o.message.content)",                              # 29 Ollama
    _EX + 'o["message"]["content"])',                        # 30 Ollama dict
    'lc = llm.generate(["x"])',
    _EX + "lc.generations[0][0].text)",                      # 32 LangChain
    'gm = model.generate_content("x")',
    _EX + "gm.text)",                                        # 34 Gemini
    'page = requests.get("u")',
    _EX + "page.text)",                                      # 36 requests .text: no
    _SP + "check_output(code)",                              # 37 subprocess first arg
    "comp" + 'ile(code, "f", "exec")',                       # 38 compile
    "def run_model_command(resp):",
    "    " + _SYS + "resp.choices[0].message.content)",      # 40 corpus shape
    "v = input()",
    _EX + "v)",                                              # 42 input via var: eval-exec only
    # Taint review r1 (Grok G1-G8, Opus O1-O7), each measured on semgrep 1.175.0.
    "msg = resp.choices[0].message",
    _EX + "msg.content)",                                    # 44 G1 split chain
    "choice = resp.choices[0]",
    _EX + "choice.message.content)",                         # 46 G1 split chain
    'code2 = resp.choices[0].message.content or ""',
    _EX + "code2)",                                          # 48 G2 `or ""`
    "parts = []",
    "for chunk in stream:",
    "    if chunk.choices[0].delta.content:",
    "        parts.append(chunk.choices[0].delta.content)",
    _EX + '"".join(parts))',                                 # 53 G3 append
    _EX + "model.generate_content(prompt).text)",            # 54 G5 one-liner
    "async def a1():",
    "    r = await model.generate_content(prompt)",
    "    " + _EX + "r.text)",                                # 57 G5 await
    'gm2 = model.generate_content("x")',
    'gm2 = requests.get("u")',
    _EX + "gm2.text)",                                       # 60 G5 rebind: no
    _EX + "interaction.message.content)",                    # 61 G6: no
    _EX + 'packet["message"]["content"])',                   # 62 G6: no
    "from " + _SP[:-1] + " import check_call",
    "check_call(resp.choices[0].message.content, shell=True)",  # 64 G7 import alias
    "from os import " + _SYS[3:-1],
    _SYS[3:] + "resp.choices[0].message.content)",           # 66 G7 import alias
    "asyncio.create_" + "subprocess_shell(resp.choices[0].message.content)",  # 67 G7
    "class Agent:",
    "    def take(self, resp):",
    "        self.cmd = resp.choices[0].message.content",
    "    def go(self):",
    "        " + _EX + "self.cmd)",                          # 72 G8: RESIDUAL, no
    "call = resp.choices[0].message.tool_calls[0]",
    "args = json.loads(call.function.arguments)",
    _SP + 'run(args["cmd"], shell=True)',                    # 75 O1 tool call
    "message = resp.choices[0].message",
    "if message.content:",
    "    " + _SYS + "message.content)",                      # 78 O2 held message
    'amsg = aclient.messages.create(model="m", max_tokens=1, messages=[])',
    'acode = "".join(b.text for b in amsg.content)',
    _EX + "acode)",                                          # 81 O2 Anthropic blocks
    "async def a2():",
    '    r2 = await client.chat.completions.create(model="m", messages=[])',
    "    await asyncio.create_" + "subprocess_shell(r2.choices[0].message.content)",  # 84 O3
    "async def a3():",
    "    r3 = await model.generate_content_async(prompt)",
    "    " + _EX + "r3.text)",                               # 87 O4 Gemini async
    "NG2 = textwrap.dedent(_BODY)",
    _EX + "NG2)",                                            # 89 O7: eval-exec only
    "def bare_tool(resp):",
    "    " + _SP + "run(resp.choices[0].message.tool_calls[0].function.arguments, shell=True)",  # 91
    "def bare_anthropic_tool(msg):",
    "    " + _SYS + 'msg.content[0].input["cmd"])',          # 93 Anthropic tool_use
    "asyncio.create_" + "subprocess_exec(code)",             # 94
    _SP + "Popen(args=code)",                                # 95
    "os.exec" + "vp(code, [code])",                          # 96
    "pty.spawn(code)",                                       # 97
    "runpy.run_path(code)",                                  # 98
    "buf = io.StringIO()",
    "buf.write(code)",
    _EX + "buf.getvalue())",                                 # 101 write propagator
]) + chr(10)
_EXEC_MUST_FIRE = [11, 13, 14, 15, 18, 19, 20, 21, 22, 23, 25, 27, 29, 30, 32,
                   34, 37, 38, 40,
                   44, 46, 48, 53, 54, 57, 64, 66, 67, 75, 78, 81, 84, 87,
                   91, 93, 94, 95, 96, 97, 98, 101]
# Must NOT fire on the LLM rule (asserted by the line-exact equality above):
# 5, 6 constant/literal; 7, 9, 42 input/parameter; 36 requests .text;
# 60 generate_content result rebound to requests; 61, 62 chat-platform payloads;
# 72 RESIDUAL -- model output stored on self in one method and executed in
# another is outside semgrep OSS taint (no cross-method field flow); 89 an
# assembled constant.
# praetor-py-eval-exec must still fire on exec of input() and of a variable
# holding input() (7, 42), on a parameter (9), and on an assembled constant (89,
# measured); never on the folded constant or the literal.
_EVAL_EXEC_MUST_INCLUDE = [7, 9, 42, 89]
_EVAL_EXEC_MUST_EXCLUDE = [5, 6]


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

        def lines_of(rid):
            return sorted({r["start"]["line"] for r in data.get("results", [])
                           if r.get("check_id", "").endswith(rid)})

        got = lines_of(rule)
        check(rule + ": taint fires on exactly %s" % _EXEC_MUST_FIRE,
              not errs and got == _EXEC_MUST_FIRE,
              "got lines %s, %d semgrep error(s)" % (got, len(errs)))
        ee = lines_of("praetor-py-eval-exec")
        check("praetor-py-eval-exec: fires on exec of input()/a parameter %s, not on %s"
              % (_EVAL_EXEC_MUST_INCLUDE, _EVAL_EXEC_MUST_EXCLUDE),
              all(n in ee for n in _EVAL_EXEC_MUST_INCLUDE)
              and not any(n in ee for n in _EVAL_EXEC_MUST_EXCLUDE),
              "got lines %s" % ee)


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

    print("== %s ==" % ("ALL LIVE CHECKS PASSED" if not failures
                        else "LIVE CHECK FAILURES: " + ", ".join(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
