#!/usr/bin/env python3
r"""THE BLOCKING DIFFERENTIAL GATE: Python and Rust must agree on what a line is.

    py -3.14 tests/differential/run_differential.py

Exits non-zero, naming the exact corpus case that moved, if the two
implementations disagree with each other or with the committed contract.

🔴 WHY THIS EXISTS WHEN BOTH SUITES ALREADY "CHECK THE CONTRACT".

Before this runner, `scripts/core.py::split_lines` and
`rust/praetor-core/src/text.rs::split_lines` each computed a signature over the
shared corpus and asserted it equalled `references/differential/*.expected`. Two
assertions against one file are transitively a comparison of the two
implementations -- *but only while both assertions actually run*.

Nothing checked that they ran. A `#[ignore]`, a rename, a `#[cfg]`, a collection
error, a test file that stops being picked up: every one of those leaves the
suite exiting 0 while the check it was trusted for silently stopped happening.
That is this project's recorded defect class twice over -- a check that reports
but does not gate, and a probe that fails by being correctly ignored. Parity that
depends on an unobserved test having run is an intention, not a gate.

So this runner does what neither suite can do from inside itself:

  1. computes the Python signature here,
  2. makes the Rust crate **emit** its signature as data and reads it,
  3. requires python == rust **directly**, not merely each == the file,
  4. requires both to equal the committed contract, and
  5. refuses to pass on a corpus that could not detect the divergence class.

🔴 `references/differential/line-splitting.expected` IS A CONTRACT, NOT A CACHE.
Never regenerate it to make this pass. That is the same move as regenerating
SELF-SCAN-BASELINE.json to reflect an improvement: it destroys the only artifact
that made the claim checkable. If the line definition is genuinely changing,
change it deliberately and update the corpus, the contract and the reasoning in
one commit.

⚠️ THIS SCRIPT NEVER SKIPS. A missing Rust toolchain, an unbuildable crate or a
missing corpus is a FAILURE, not a "not applicable". A differential harness that
goes quiet when it cannot reach the other implementation reports success at
exactly the moment it has stopped comparing anything.
"""

import ast
import os
import shutil
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))

sys.path.insert(0, os.path.join(_ROOT, "scripts"))

import core  # noqa: E402  -- after the sys.path insert, deliberately
import engine_secrets  # noqa: E402  -- same reference implementation

_CORPUS_DIR = os.path.join(_ROOT, "references", "differential")
_CORPUS = os.path.join(_CORPUS_DIR, "line-splitting.txt")
_CONTRACT = os.path.join(_CORPUS_DIR, "line-splitting.expected")
_SECRETS_CORPUS = os.path.join(_CORPUS_DIR, "secrets.tsv")
_SECRETS_CONTRACT = os.path.join(_CORPUS_DIR, "secrets.expected")

_NL = chr(0x0A)
_CR = chr(0x0D)
_TAB = chr(0x09)
_BS = chr(92)

# The corpus must be able to SEE the divergence class it exists for. `splitlines()`
# is the naive definition both ports could drift back to; if too few cases
# distinguish it from ours, two identically-blind implementations satisfy the
# contract and it certifies nothing. 12 cases distinguish them today.
_MIN_DISCRIMINATING_CASES = 8

# Anti-vacuity floor for the corpus itself: an emptied corpus plus a regenerated
# contract would otherwise agree with anything.
_MIN_CASES = 20

# One case per provider plus every non-provider detection route and both negative
# directions. An emptied or provider-only corpus is not parity evidence.
_MIN_SECRET_CASES = 25
_REQUIRED_SECRET_RULES = {
    "aws-access-key-id", "aws-secret-access-key", "gcp-api-key",
    "gcp-oauth-client-secret", "google-oauth-refresh-token", "github-token",
    "github-fine-grained-pat", "slack-token", "slack-webhook",
    "stripe-secret-key", "openai-key", "anthropic-key",
    "twilio-account-sid-authtoken", "sendgrid-key", "npm-token", "jwt",
    "private-key-pem", "gcp-service-account-key", "db-connection-string-password",
    "hardcoded-secret-assignment", "base64-wrapped-secret", "high-entropy-string",
}
_REQUIRED_SECRET_NEGATIVE_PATHS = {
    "config/placeholder.py", "config/revision.py", "package-lock.json",
}


# --------------------------------------------------------------------------- #
# The shared corpus format
# --------------------------------------------------------------------------- #

def unescape(s):
    r"""Decode the shared corpus format: \n \r \t \\ and \u{XXXX}.

    Strict on purpose -- an unknown escape raises. A corpus line that quietly
    means something other than intended is worse than one that fails to load.
    Mirrors `differential::unescape` in rust/praetor-core/src/text.rs.
    """
    out, i = [], 0
    while i < len(s):
        if s[i] != _BS:
            out.append(s[i])
            i += 1
            continue
        nxt = s[i + 1]
        i += 2
        if nxt == "n":
            out.append(_NL)
        elif nxt == "r":
            out.append(_CR)
        elif nxt == "t":
            out.append(_TAB)
        elif nxt == _BS:
            out.append(_BS)
        elif nxt == "u":
            assert s[i] == "{", "corpus: backslash-u must be followed by {"
            j = s.index("}", i)
            out.append(chr(int(s[i + 1:j], 16)))
            i = j + 1
        else:
            raise AssertionError(f"corpus: unknown escape {_BS}{nxt}")
    return "".join(out)


def escape(s):
    r"""Re-escape a produced line into the corpus's ASCII format.

    🔴 The signature carries CONTENT, not just line counts. A counts-only
    signature was tried first and a mutation exposed it: `str::lines()` in the
    Rust port turns "a\r" into ["a\r"] instead of ["a"] -- same count, different
    text -- and the cross-language contract passed the mutant. An authority blind
    to content is not an authority. Mirrors `differential::escape` in
    rust/praetor-core/src/text.rs.
    """
    out = []
    for c in s:
        if c == _BS:
            out.append(_BS * 2)
        elif c == _NL:
            out.append(_BS + "n")
        elif c == _CR:
            out.append(_BS + "r")
        elif c == _TAB:
            out.append(_BS + "t")
        elif " " <= c <= "~":
            out.append(c)
        else:
            out.append(f"{_BS}u{{{ord(c):04X}}}")
    return "".join(out)


def _kv(text, key):
    """Pull a `key value` line out of the contract file or the emitter's output.

    One parser for both, so the emitter is held to the same shape as the file it
    is compared against.
    """
    for raw in core.split_lines(text):
        line = raw.strip()
        if line.startswith(key):
            return line[len(key):].strip()
    raise AssertionError(f"no {key!r} line found")


def _expected(path, key):
    """A value from one committed contract."""
    with open(path, encoding="utf-8") as fh:
        return _kv(fh.read(), key)


def expected(key):
    return _expected(_CONTRACT, key)


def secrets_expected(key):
    return _expected(_SECRETS_CONTRACT, key)


def corpus_source_lines():
    """The corpus's case lines, still escaped -- for naming a case in a diff."""
    with open(_CORPUS, encoding="utf-8") as fh:
        raw = fh.read()
    return [l for l in core.split_lines(raw)
            if l.strip() and not l.lstrip().startswith("#")]


def corpus_cases():
    """The corpus's cases, decoded, in file order."""
    return [unescape(l) for l in corpus_source_lines()]


def python_parts():
    """This implementation's answer, one `N:line;line;...` string per corpus case."""
    parts = []
    for c in corpus_cases():
        lines = core.split_lines(c)
        parts.append(f"{len(lines)}:" + ";".join(escape(l) for l in lines))
    return parts


def python_signature():
    """The parts, space-joined -- the form the contract is written in."""
    return " ".join(python_parts())


def secrets_corpus_cases():
    r"""Parse `label<TAB>relpath<TAB>fragment...` from the shared corpus.

    Fragments are unescaped and joined only in memory. That lets the corpus
    exercise credential-shaped values without committing those values intact and
    turning the detector's own fixture into repository noise.
    """
    cases = []
    labels, paths = set(), set()
    with open(_SECRETS_CORPUS, encoding="utf-8") as fh:
        raw = fh.read()
    for line_no, raw_line in enumerate(core.split_lines(raw), 1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        fields = raw_line.split(_TAB)
        assert len(fields) >= 3, (
            f"secrets corpus line {line_no} needs label, path, and fragments"
        )
        label, path = fields[:2]
        assert label and path, f"secrets corpus line {line_no} has an empty identity"
        assert label not in labels, f"duplicate secrets corpus label: {label}"
        assert path not in paths, f"duplicate secrets corpus path: {path}"
        labels.add(label)
        paths.add(path)
        cases.append((label, path, "".join(unescape(part) for part in fields[2:])))
    return cases


def python_secrets_signature():
    """Sorted set of the ADR-mandated finding identity from the Python engine."""
    cases = secrets_corpus_cases()
    texts = {label: text for label, _path, text in cases}
    inputs = [
        core.ScanFile(abspath=label, relpath=path, size=len(text.encode("utf-8")))
        for label, path, text in cases
    ]
    findings = engine_secrets.scan(inputs, lambda label: texts[label])
    identities = {
        f"{finding.engine}|{finding.rule_id}|{finding.file}|{finding.line}"
        for finding in findings
    }
    return " ".join(sorted(identities))


def python_defined_secret_rules():
    """Rules the reference engine defines, derived from its real source surface.

    Provider rules are data, while the six non-provider rules are literal
    `Finding(rule_id=...)` calls. Reading both forms makes adding a Python rule
    fail this gate until the shared corpus and Rust port reach it; otherwise a
    new reference rule could leave both ports "equal" only because the corpus
    never asked either implementation the new question.
    """
    rules = {rule_id for rule_id, *_rest in engine_secrets.PROVIDERS}
    with open(engine_secrets.__file__, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=engine_secrets.__file__)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "Finding":
            continue
        for keyword in node.keywords:
            if (
                keyword.arg == "rule_id"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ):
                rules.add(keyword.value.value)
    return rules


# --------------------------------------------------------------------------- #
# Reaching the other implementation
# --------------------------------------------------------------------------- #

def _cargo():
    exe = shutil.which("cargo")
    if exe:
        return exe
    for cand in ("cargo.exe", "cargo"):
        p = os.path.join(os.path.expanduser("~"), ".cargo", "bin", cand)
        if os.path.exists(p):
            return p
    return None


def rust_signatures():
    """Run the Rust emitter and return both blocking contracts.

    Raises RuntimeError -- never returns a sentinel and never skips. A harness
    that cannot reach the other implementation has failed, not passed.
    """
    exe = _cargo()
    if exe is None:
        raise RuntimeError(
            "cargo is not on PATH and not at ~/.cargo/bin. The Rust half of the "
            "differential contract cannot be reached, so parity is UNVERIFIED. "
            "This is a failure, not a skip."
        )
    cmd = [exe, "run", "-q", "-p", "praetor-core", "--example", "emit_line_signature"]
    proc = subprocess.run(
        cmd, cwd=os.path.join(_ROOT, "rust"),
        capture_output=True, text=True, timeout=600,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "the Rust emitter did not run (exit %d). Parity is UNVERIFIED.\n"
            "  cmd: %s\n%s" % (proc.returncode, " ".join(cmd), proc.stderr[-3000:])
        )
    try:
        n = int(_kv(proc.stdout, "cases"))
        sig = _kv(proc.stdout, "signature")
        secrets_n = int(_kv(proc.stdout, "secrets_cases"))
        secrets_sig = _kv(proc.stdout, "secrets_signature")
    except (AssertionError, ValueError) as exc:
        raise RuntimeError(
            "the Rust emitter ran but its output could not be parsed (%s). An "
            "unreadable answer is not agreement.\n--- stdout ---\n%s"
            % (exc, proc.stdout[:3000])
        )
    if not sig:
        raise RuntimeError(
            "the Rust emitter produced an EMPTY signature. Two empty strings "
            "compare equal, so this would otherwise pass as agreement."
        )
    if not secrets_sig:
        raise RuntimeError(
            "the Rust emitter produced an EMPTY secrets signature. A port that "
            "reports nothing must not pass as parity with a missing measurement."
        )
    return n, sig, secrets_n, secrets_sig


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #

def _locate(parts, offset):
    """Map a character offset in the space-joined signature to a case index.

    ⚠️ Do NOT re-split a signature on `" "` to recover its cases. `escape()`
    passes a literal space through unchanged (it is in the printable range), and
    corpus case **19** (0-based, as `_report` prints them) contains one -- so a
    naive split yields 24 fields for a 23-case corpus and reports the wrong case
    as the one that moved. The first draft of this runner did exactly that.

    📌 That index read `20` until an audit caught it: 1-based, in a file whose
    entire subject is two definitions of one index disagreeing. Every case number
    here and in `_report` is 0-based, from `enumerate`.

    The joined-string comparison itself is sound: both implementations build the
    string the same way, and the case COUNT is asserted separately. It is only
    the reverse direction that is ambiguous, so this walks the boundaries we
    actually computed rather than guessing them back out of the text.
    """
    pos = 0
    for idx, p in enumerate(parts):
        if offset <= pos + len(p):
            return idx, pos
        pos += len(p) + 1  # +1 for the joining space
    return len(parts) - 1, max(0, pos - 1)


def _report(label, a_name, a, b_name, b, sources, parts):
    """Name the case that moved, using the boundaries of the Python rendering.

    ⚠️ Must survive an EMPTY corpus. An audit found this raising IndexError
    before the anti-vacuity summary printed -- the run still failed (no false
    pass), but the reader never saw the carefully-worded message explaining
    *why*, in exactly the gutted-corpus scenario those floors exist for. A
    diagnostic that crashes in its own headline case is not a diagnostic.
    """
    print(f"FAIL  {label}", file=sys.stderr)
    if not parts:
        print("      corpus is EMPTY -- there are no cases to compare. See the "
              "corpus/contract failures listed below; that is the real fault.",
              file=sys.stderr)
        return
    n = min(len(a), len(b))
    offset = next((i for i in range(n) if a[i] != b[i]), n)
    idx, start = _locate(parts, offset)
    src = sources[idx] if idx < len(sources) else "<beyond the corpus>"
    width = max(len(parts[idx]) if idx < len(parts) else 0, 24)
    print(f"      first divergence at corpus case {idx} (character offset {offset})",
          file=sys.stderr)
    print(f"      corpus source : {src}", file=sys.stderr)
    print(f"      {a_name:<13} : {a[start:start + width]}", file=sys.stderr)
    print(f"      {b_name:<13} : {b[start:start + width]}", file=sys.stderr)
    print(f"      (both shown from the same offset, width of the Python rendering)",
          file=sys.stderr)


def _report_set(label, a_name, a, b_name, b):
    """Report identity-set drift without pretending an ordering change matters."""
    a_set, b_set = set(a.split()), set(b.split())
    print(f"FAIL  {label}", file=sys.stderr)
    for identity in sorted(a_set - b_set):
        print(f"      only in {a_name}: {identity}", file=sys.stderr)
    for identity in sorted(b_set - a_set):
        print(f"      only in {b_name}: {identity}", file=sys.stderr)


def main():
    failures = []
    sources = corpus_source_lines()
    cases = corpus_cases()
    secret_cases = secrets_corpus_cases()

    print("PRAETOR differential gate -- shared contracts, two implementations")
    print(f"  corpus   : {os.path.relpath(_CORPUS, _ROOT)}  ({len(cases)} cases)")
    print(f"  contract : {os.path.relpath(_CONTRACT, _ROOT)}")
    print(f"  secrets  : {os.path.relpath(_SECRETS_CORPUS, _ROOT)}  ({len(secret_cases)} cases)")
    print(f"  contract : {os.path.relpath(_SECRETS_CONTRACT, _ROOT)}")

    # --- the corpus must be capable of detecting the divergence class -------- #
    want_cases = int(expected("cases"))
    if len(cases) != want_cases:
        failures.append(
            f"corpus has {len(cases)} cases, the contract says {want_cases}. Either the "
            f"corpus changed (update the contract deliberately, in the same commit as "
            f"the reason) or the loader is dropping cases and this gate is going vacuous."
        )
    if want_cases < _MIN_CASES:
        failures.append(
            f"the contract declares only {want_cases} cases (floor {_MIN_CASES}). A "
            f"gutted corpus plus a regenerated contract agrees with anything."
        )

    discriminating = [
        i for i, c in enumerate(cases)
        if c.splitlines() != core.split_lines(c)
    ]
    print(f"  cases where splitlines() would disagree with us: {len(discriminating)}")
    if len(discriminating) < _MIN_DISCRIMINATING_CASES:
        failures.append(
            f"only {len(discriminating)} corpus cases distinguish our line definition "
            f"from the naive splitlines()/str::lines() one (floor "
            f"{_MIN_DISCRIMINATING_CASES}). Two implementations that had BOTH drifted "
            f"back to the naive definition would satisfy this contract, so it would "
            f"certify nothing.\n"
            f"    TWO CAUSES LOOK ALIKE HERE, CHECK WHICH:\n"
            f"      (a) the CORPUS lost its discriminating cases -- restore the "
            f"U+2028/U+2029/U+0085/U+000B-U+001E and lone-CR cases; or\n"
            f"      (b) scripts/core.py::split_lines HAS ITSELF drifted to "
            f"splitlines(), which makes this comparison blind rather than the corpus "
            f"thin. A reading of 0 with an intact corpus means (b)."
        )

    secret_want_cases = int(secrets_expected("cases"))
    if len(secret_cases) != secret_want_cases:
        failures.append(
            f"secrets corpus has {len(secret_cases)} cases, the contract says "
            f"{secret_want_cases}; corpus and truth artifact moved independently."
        )
    if secret_want_cases < _MIN_SECRET_CASES:
        failures.append(
            f"the secrets contract declares only {secret_want_cases} cases (floor "
            f"{_MIN_SECRET_CASES}); a thinned detector corpus is not parity evidence."
        )
    secret_paths = {path for _label, path, _text in secret_cases}
    for required_path in {".cursor/hooks.json", ".agent-instructions"}:
        if required_path not in secret_paths:
            failures.append(
                f"secrets corpus lost required wide-scope path {required_path!r}; two "
                f"ports could now agree while preserving the known scope hole."
            )

    # --- the three-way comparison -------------------------------------------- #
    contract = expected("signature")
    secrets_contract = secrets_expected("signature")
    parts = python_parts()
    py = " ".join(parts)
    py_secrets = python_secrets_signature()

    try:
        rust_cases, rust, rust_secret_cases, rust_secrets = rust_signatures()
    except RuntimeError as exc:
        print(f"FAIL  the Rust implementation could not be reached\n      {exc}",
              file=sys.stderr)
        failures.append("Rust signature unavailable -- parity UNVERIFIED")
        rust_cases, rust, rust_secret_cases, rust_secrets = None, None, None, None

    if py != contract:
        _report("scripts/core.py disagrees with the COMMITTED CONTRACT",
                "python", py, "contract", contract, sources, parts)
        failures.append("python != contract")

    if rust is not None:
        if rust_cases != want_cases:
            failures.append(
                f"the Rust emitter reports {rust_cases} cases, the contract says "
                f"{want_cases} -- it is not reading the corpus this gate is checking."
            )
        if rust != contract:
            _report("rust/praetor-core disagrees with the COMMITTED CONTRACT",
                    "rust", rust, "contract", contract, sources, parts)
            failures.append("rust != contract")
        if py != rust:
            # The comparison neither suite can make. Reported even when both also
            # differ from the contract, because THIS is the interop break: a
            # finding's line number means two different things in two ports.
            _report("scripts/core.py and rust/praetor-core disagree WITH EACH OTHER",
                    "python", py, "rust", rust, sources, parts)
            failures.append("python != rust")

    python_secret_rules = {
        identity.split("|", 3)[1] for identity in py_secrets.split()
    }
    defined_secret_rules = python_defined_secret_rules()
    if defined_secret_rules != _REQUIRED_SECRET_RULES:
        missing_from_contract = defined_secret_rules - _REQUIRED_SECRET_RULES
        stale_in_contract = _REQUIRED_SECRET_RULES - defined_secret_rules
        details = []
        if missing_from_contract:
            details.append(
                "missing from required-rule contract: "
                + ", ".join(sorted(missing_from_contract))
            )
        if stale_in_contract:
            details.append(
                "no longer defined by Python: "
                + ", ".join(sorted(stale_in_contract))
            )
        failures.append(
            "Python secrets rule surface and required-rule contract disagree ("
            + "; ".join(details)
            + ")"
        )
    missing_rules = _REQUIRED_SECRET_RULES - python_secret_rules
    if missing_rules:
        failures.append(
            "secrets corpus does not reach required Python rules: "
            + ", ".join(sorted(missing_rules))
        )
    secret_case_paths = {path for _label, path, _text in secrets_corpus_cases()}
    missing_negative_paths = _REQUIRED_SECRET_NEGATIVE_PATHS - secret_case_paths
    if missing_negative_paths:
        failures.append(
            "secrets corpus is missing required negative paths: "
            + ", ".join(sorted(missing_negative_paths))
        )
    unexpected_negative_findings = {
        identity
        for identity in py_secrets.split()
        if identity.split("|", 3)[2] in _REQUIRED_SECRET_NEGATIVE_PATHS
    }
    if unexpected_negative_findings:
        failures.append(
            "required Python negative cases produced findings: "
            + ", ".join(sorted(unexpected_negative_findings))
        )
    if py_secrets != secrets_contract:
        _report_set("scripts/engine_secrets.py disagrees with the COMMITTED CONTRACT",
                    "python", py_secrets, "contract", secrets_contract)
        failures.append("python secrets != contract")

    if rust_secrets is not None:
        if rust_secret_cases != secret_want_cases:
            failures.append(
                f"the Rust emitter reports {rust_secret_cases} secrets cases, the "
                f"contract says {secret_want_cases}; it is not reading this corpus."
            )
        if rust_secrets != secrets_contract:
            _report_set("rust/praetor-core secrets disagree with the COMMITTED CONTRACT",
                        "rust", rust_secrets, "contract", secrets_contract)
            failures.append("rust secrets != contract")
        if py_secrets != rust_secrets:
            _report_set("Python and Rust secrets engines disagree WITH EACH OTHER",
                        "python", py_secrets, "rust", rust_secrets)
            failures.append("python secrets != rust secrets")

    if failures:
        print("", file=sys.stderr)
        print("DIFFERENTIAL CONTRACT BROKEN:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print("", file=sys.stderr)
        print("A finding identity is part of the scanner's public contract. A divergence "
              "means the result changes with the implementation selected.",
              file=sys.stderr)
        print("🔴 Do NOT regenerate the .expected file to make this pass.", file=sys.stderr)
        return 1

    print(f"  python   : {len(parts)} cases signed, {len(py)} chars")
    print(f"  rust     : {rust_cases} cases signed, {len(rust)} chars")
    print(f"  secrets : {secret_want_cases} cases, "
          f"{len(py_secrets.split())} finding identities")
    print("OK    python == rust == committed contracts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
