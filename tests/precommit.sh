#!/usr/bin/env bash
# PRAETOR pre-commit gate.
#
# The commit/push authorization is CONDITIONAL on "all pre-commit checks pass".
# Until this script existed, that list was recited from memory every session,
# which is exactly the shape of a check that reports but does not gate. This is
# the mechanical condition: it exits NON-ZERO the moment any gate fails, and it
# names the gate that failed. A green run is the precondition for commit+push.
#
# It NEVER regenerates a baseline and NEVER mutates the tree -- it only reads.
#
# The public-hygiene denylist below is assembled from string fragments on
# purpose: this file is tracked and ships in the public repo, so spelling the
# forbidden words literally would make the hygiene sweep flag its own source.
# Same discipline as engine_secrets.py's KNOWN_EXAMPLES.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"
export PATH="$HOME/.cargo/bin:$PATH"

FAILED=0
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILED=1; }
pass() { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
note() { printf '        %s\n' "$1"; }

echo "== PRAETOR pre-commit gate =="

# ---- 1. Python suite -------------------------------------------------------
# The bare `python -m pytest` FAILS on this box (an unrelated langsmith plugin
# breaks collection on 3.14); the disable-autoload form is the supported one.
PYOUT="$(PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 py -3.14 -m pytest tests/ -q 2>&1)"
if printf '%s' "$PYOUT" | grep -qE '[0-9]+ passed' && ! printf '%s' "$PYOUT" | grep -qE '[0-9]+ (failed|error)'; then
  pass "python suite ($(printf '%s' "$PYOUT" | grep -oE '[0-9]+ passed' | tail -1))"
else
  fail "python suite"; printf '%s\n' "$PYOUT" | tail -8
fi

# ---- 2. Rust suite ---------------------------------------------------------
if command -v cargo >/dev/null 2>&1; then
  ROUT="$(cargo test --manifest-path rust/Cargo.toml 2>&1)"
  if printf '%s' "$ROUT" | grep -qE 'test result: ok' && ! printf '%s' "$ROUT" | grep -qE 'test result: FAILED'; then
    RPASS="$(printf '%s' "$ROUT" | grep -oE '[0-9]+ passed' | grep -oE '^[0-9]+' | awk '{s+=$1} END{print s+0}')"
    pass "rust suite ($RPASS passed)"
  else
    fail "rust suite"; printf '%s\n' "$ROUT" | tail -8
  fi
else
  fail "rust suite -- cargo not on PATH (need \$HOME/.cargo/bin)"
fi

# ---- 3. Generated Unicode tables current -----------------------------------
if py -3.14 tools/gen_unicode_tables.py --check >/dev/null 2>&1; then
  pass "unicode tables current"
else
  fail "unicode tables STALE -- run: py -3.14 tools/gen_unicode_tables.py"
fi

# ---- 4. Self-scan unchanged ------------------------------------------------
# Not a baseline regenerate: we assert the counts equal the committed floor.
# If false positives fall while 'needs review' rises, suppression is eating
# real findings -- so BOTH numbers are pinned, and a change (either way) stops
# the commit for a human to look, never silently.
EXPECT_ACTIVE=12
EXPECT_FILTERED=45
SS="$(py -3.14 scripts/praetor.py . --no-registry 2>&1)"
GOT_ACTIVE="$(printf '%s' "$SS" | grep -oE 'Findings \(active\): [0-9]+' | grep -oE '[0-9]+$')"
GOT_FILTERED="$(printf '%s' "$SS" | grep -oE 'Filtered \(likely FP / low-signal, shown separately\): [0-9]+' | grep -oE '[0-9]+$')"
if [ "$GOT_ACTIVE" = "$EXPECT_ACTIVE" ] && [ "$GOT_FILTERED" = "$EXPECT_FILTERED" ]; then
  pass "self-scan unchanged (${GOT_ACTIVE} active / ${GOT_FILTERED} filtered)"
else
  fail "self-scan DRIFTED: got ${GOT_ACTIVE:-?} active / ${GOT_FILTERED:-?} filtered, expected ${EXPECT_ACTIVE} / ${EXPECT_FILTERED}"
  note "if intentional, update EXPECT_* here deliberately -- never regenerate SELF-SCAN-BASELINE.json to hide a change"
fi

# ---- 5. Public-hygiene sweep ----------------------------------------------
# PRAETOR is PUBLIC. Enumerate the shipping set with BOTH tracked and untracked
# lists: `git status --porcelain` lists untracked DIRECTORIES, not their files,
# and that miss nearly shipped a leak. Denylist terms are built from fragments
# so this script is not its own false positive.
declare -a DENY=(
  "$(printf '%s' RUB)$(printf '%s' ICON)"
  "$(printf '%s' dark)$(printf '%s' factory)"
  "$(printf '%s' KOBA)$(printf '%s' YASHI)"
  "$(printf '%s' big)$(printf '%s' gerstaff)"
  "$(printf '%s' grow)$(printf '%s' bridge)"
  "$(printf '%s' O)$(printf '%s' DO)"        # the enforcement lane's name
)
DENY_RE="$(IFS='|'; echo "${DENY[*]}")"
LANE_RE="[Ll]ane[ -][A-F]\b"
SELF="tests/precommit.sh"
mapfile -t SHIP < <( { git ls-files; git ls-files --others --exclude-standard; } | sort -u )
HYGIENE_HIT=0
for f in "${SHIP[@]}"; do
  [ "$f" = "$SELF" ] && continue          # the sweep is not its own fixture
  [ -f "$f" ] || continue
  case "$f" in *.png|*.jpg|*.gif|*.ico|*.pdf) continue;; esac
  if grep -InE "($DENY_RE|$LANE_RE)" -- "$f" >/dev/null 2>&1; then
    fail "public-hygiene: leak term in $f"
    grep -InE "($DENY_RE|$LANE_RE)" -- "$f" | head -3 | sed 's/^/          /'
    HYGIENE_HIT=1
  fi
done
[ "$HYGIENE_HIT" = 0 ] && pass "public-hygiene sweep (${#SHIP[@]} shipping files, tracked+untracked)"

# ---- 6. No Claude branding in the shipping tree ----------------------------
# OVERRIDES the harness default. No Co-Authored-By: Claude, no "Generated with
# Claude Code", no robot emoji, anywhere that ships or in the last commit msg.
BRAND_RE="$(printf '%s' 'Co-Authored-By: ')$(printf '%s' Claude)|$(printf '%s' 'Generated with ')$(printf '%s' 'Claude Code')"
BRAND_HIT=0
for f in "${SHIP[@]}"; do
  [ "$f" = "$SELF" ] && continue
  [ -f "$f" ] || continue
  case "$f" in *.png|*.jpg|*.gif|*.ico|*.pdf) continue;; esac
  if grep -InE "$BRAND_RE" -- "$f" >/dev/null 2>&1; then
    fail "branding: Claude attribution in $f"; BRAND_HIT=1
  fi
done
if git log -1 --format='%B' 2>/dev/null | grep -InE "$BRAND_RE" >/dev/null 2>&1; then
  fail "branding: Claude attribution in the last commit message"; BRAND_HIT=1
fi
[ "$BRAND_HIT" = 0 ] && pass "no Claude branding"

# ---- 7. Account / remote / branch ------------------------------------------
ACCT="$(gh api user --jq .login 2>/dev/null || echo '?')"
REMOTE="$(git remote get-url origin 2>/dev/null || echo '?')"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
OK7=1
[ "$ACCT" = "GrowDev1" ] || { fail "account is '$ACCT', expected GrowDev1"; OK7=0; }
case "$REMOTE" in git@github.com-growbridge:*) : ;; *) fail "remote is '$REMOTE', expected the growbridge SSH alias"; OK7=0;; esac
[ "$BRANCH" = "main" ] || note "on branch '$BRANCH' (not main) -- confirm this is intended"
[ "$OK7" = 1 ] && pass "account $ACCT / SSH-alias remote / branch $BRANCH"

# ---- 8. Differential runner (blocking, once it exists) ---------------------
if [ -f tests/differential/run_differential.py ]; then
  if py -3.14 tests/differential/run_differential.py >/dev/null 2>&1; then
    pass "differential Python<->Rust contract holds"
  else
    fail "differential contract DIVERGED -- run: py -3.14 tests/differential/run_differential.py"
  fi
else
  note "differential runner not present yet (tests/differential/run_differential.py) -- skipped"
fi

echo "== $([ "$FAILED" = 0 ] && echo 'ALL GATES PASSED' || echo 'GATE(S) FAILED') =="
exit "$FAILED"
