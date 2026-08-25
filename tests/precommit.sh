#!/usr/bin/env bash
# PRAETOR pre-commit gate.
#
# The commit/push authorization is CONDITIONAL on "all pre-commit checks pass".
# Until this script existed, that list was recited from memory every session,
# which is exactly the shape of a check that reports but does not gate. This is
# the mechanical condition: it exits NON-ZERO the moment any gate fails, and it
# names the gate that failed. A green run is the precondition for commit+push.
#
# It NEVER regenerates a baseline and never edits a tracked file. It is not
# read-only, though, and saying so would be false: running the suites writes
# __pycache__/, .pytest_cache/ and rust/target/. All three are gitignored, so
# `git status` stays clean -- but "only reads" was literally untrue and this file
# is not the place to be loose about what a check does.
#
# ⚠️ It also has NO protection against a concurrent writer. An audit caught a run
# that straddled another session's in-flight mutation and reported
# `OK rust suite` while text.rs was diverged: the per-gate results are a sequence
# of point-in-time readings, not one coherent snapshot of a single tree state.
# Do not run this against a tree something else is editing.
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
#
# 🔴 A SUITE THAT DID NOT RUN MUST NOT READ AS A SUITE THAT PASSED. An audit
# found this gate green on `0 passed` and the Rust gate green on
# `ok. 6 passed; 2 ignored` -- the *exact* string commit 55a1719 cites as the
# demonstrated bypass. The differential runner closed that hole for ONE contract;
# the generic hole stayed open in this file, in the same commit. So both gates now
# require a FLOOR and refuse any skipped/ignored test.
#
# ⚠️ Floors, not exact pins, and the tradeoff is deliberate: an exact count must be
# edited on every commit that adds a test, and the predictable end of that is
# somebody raising the number without looking -- which is how a pin becomes a
# rubber stamp. A floor cannot fall silently, and `SKIPPED == 0` is what actually
# catches the disappearing-test class.
MIN_PY=232
PYOUT="$(PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 py -3.14 -m pytest tests/ -q 2>&1)"
PYPASS="$(printf '%s' "$PYOUT" | grep -oE '[0-9]+ passed' | tail -1 | grep -oE '^[0-9]+')"
PYSKIP="$(printf '%s' "$PYOUT" | grep -oE '[0-9]+ (skipped|deselected|xfailed)' | grep -oE '^[0-9]+' | awk '{s+=$1} END{print s+0}')"
if printf '%s' "$PYOUT" | grep -qE '[0-9]+ (failed|error)'; then
  fail "python suite"; printf '%s\n' "$PYOUT" | tail -8
elif [ -z "$PYPASS" ]; then
  fail "python suite reported NO pass count -- it did not run. A suite that never ran is not a suite that passed."
  printf '%s\n' "$PYOUT" | tail -8
elif [ "$PYPASS" -lt "$MIN_PY" ]; then
  fail "python suite: $PYPASS passed, floor is $MIN_PY -- tests disappeared. Raise MIN_PY deliberately if they were removed on purpose."
elif [ "$PYSKIP" -gt 0 ]; then
  fail "python suite: $PYSKIP test(s) skipped/deselected. A skipped test is indistinguishable from a passing one; un-skip it or delete it."
else
  pass "python suite ($PYPASS passed, 0 skipped)"
fi

# ---- 2. Rust suite ---------------------------------------------------------
# Same floor-and-zero-tolerance discipline as gate 1. `ignored` is the Rust
# spelling of the bypass: `#[ignore]` on a test leaves `cargo test` exiting 0 and
# reporting "ok", which is precisely how a diverged split_lines was demonstrated
# to survive a green suite.
MIN_RS=8
if command -v cargo >/dev/null 2>&1; then
  ROUT="$(cargo test --manifest-path rust/Cargo.toml 2>&1)"
  RPASS="$(printf '%s' "$ROUT" | grep -oE '[0-9]+ passed' | grep -oE '^[0-9]+' | awk '{s+=$1} END{print s+0}')"
  RIGN="$(printf '%s' "$ROUT" | grep -oE '[0-9]+ ignored' | grep -oE '^[0-9]+' | awk '{s+=$1} END{print s+0}')"
  if ! printf '%s' "$ROUT" | grep -qE 'test result: ok' || printf '%s' "$ROUT" | grep -qE 'test result: FAILED'; then
    fail "rust suite"; printf '%s\n' "$ROUT" | tail -8
  elif [ "$RPASS" -lt "$MIN_RS" ]; then
    fail "rust suite: $RPASS passed, floor is $MIN_RS -- tests disappeared. Raise MIN_RS deliberately if they were removed on purpose."
  elif [ "$RIGN" -gt 0 ]; then
    fail "rust suite: $RIGN test(s) #[ignore]d. An ignored test still reports 'ok' -- that is the documented bypass, not an exemption."
  else
    pass "rust suite ($RPASS passed, 0 ignored)"
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
# F10 deliberately adds two active findings from TSV and six active JSONL
# findings; the five JSONL identities are duplicated across claims/records,
# yielding ten raw instances, with four claim-file instances filtered as
# documentation phrasing. The measured pin is 21 active / 56 filtered.
EXPECT_ACTIVE=21
# 2026-08-12: 45 -> 53, deliberately, and NOT because false positives improved.
# The two causes were measured separately by reverting each change on its own:
#   +3  the dedup fix stopped DISCARDING findings. A filtered finding could win
#       primary election over an unfiltered sibling, and the loser went into
#       neither bucket. The three that reappear are at scripts/interpret.py:33-35
#       -- the comment documenting this very attack was being deleted by it.
#       They land in `filtered`, correctly: they are comment prose.
#   +5  new scan surface. tests/test_suppression_is_not_attacker_controlled.py
#       carries credential- and injection-shaped fixtures by necessity.
# ⚠️ Counts from before and after are therefore NOT comparable as a quality
# measure -- the tree differs. ACTIVE staying at 12 is the control that matters:
# if filtered rose while active FELL, suppression would be eating real findings.
# 2026-08-18 Task C: 12/53 -> 13/52 deliberately. The global `#` rule had
# classified the remote-code-pipe example at CLAUDE.md:42 as a Markdown code
# comment. Reintroducing only that unsafe Markdown mapping returned exactly
# 12 active / 53 filtered (one finding moved back); file-type-aware syntax keeps
# the agent-facing heading active. The regression baseline was NOT regenerated.
EXPECT_FILTERED=56
# 🔴 SCOPE DECISION, stated next to the code because it is one.
# The self-scan pin must measure what PRAETOR SHIPS. Gate 5 already defines the
# shipping set as tracked + untracked-but-not-ignored; this scan walks the tree
# directly and does NOT consult .gitignore, so session-local state landed in it.
# Measured 2026-08-18: `.local/` and `.claude/` added 2 active findings and moved
# the pin from 12 to 14, failing the gate on work that was correct. A pin that any
# session artifact can move is not a measurement of the product.
# ⚠️ THIS IS AN ENUMERATION AND IT WILL MISS A DIRECTORY NOBODY ADDED YET. It is
# NOT a general "ignore what git ignores" rule -- praetor has no such mode, and
# adding one would let a scanned tree shrink its own scope, which is this repo's
# most-recorded defect. If a THIRD session-local directory appears, it belongs
# here, deliberately, with the same reasoning.
#
# The third one appeared on 2026-08-22, exactly as the paragraph above predicted:
# `.codex/PRAETOR-codex` is a linked build worktree, which is a COMPLETE SECOND COPY
# of this repository inside the tree this scan walks. It did not add a few findings;
# it DOUBLED the corpus, 13/52 -> 26/104, because the scanner read every shipping
# file twice. Excluding it restores 13/52 exactly, which is the evidence that the
# duplicate copy was the whole cause and that no real finding is being hidden.
#
# 🔴 THE EXCLUSION IS THE WORKTREE PATH, NOT `.codex/`. Getting this wrong was
# this repo's own most-recorded defect -- suppressing on PATH alone -- and the first
# version of this line did exactly that. `.gitignore` deliberately keeps
# `.codex/hooks/` and `.codex/agents/` VISIBLE and stageable, so those files SHIP and
# must be scanned. Measured both ways with a hardcoded credential planted in
# `.codex/hooks/`: under `^\.codex/PRAETOR-codex/` the scan reports 14 active /
# CRITICAL=2 and catches it; under a wholesale `^\.codex/` it reports 13 / CRITICAL=1
# and the credential is INVISIBLE. A directory-shaped exclusion is one new
# subdirectory away from hiding live executable code.
#
# 🔴 THE GENERAL SHAPE, worth more than either line: any check that walks the tree
# rather than asking git sees a nested worktree as a second repository. A pin
# catches that loudly. A coverage percentage, a lint sweep or a duplicate-code
# check absorbs it silently and still reports a number.
SS="$(py -3.14 scripts/praetor.py . --no-registry --exclude '^\.local/' --exclude '^\.claude/' --exclude '^\.codex/PRAETOR-codex/' 2>&1)"
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

# ---- 8. Differential runner (BLOCKING, and required to exist) --------------
#
# 🔴 The absence of the runner is a FAILURE, not a skip. This gate was written
# with an `else note "... not present yet -- skipped"` branch while the runner was
# being built, and that branch had to go the moment it existed: a gate that
# reports "skipped" when its check is missing means deleting the check turns the
# gate green. That is this repo's recorded `a-check-that-reports-does-not-gate`
# trap, which has already been hit twice.
#
# The runner itself never skips either -- an unreachable cargo or an unbuildable
# emitter is a failure inside it, because a harness that goes quiet when it cannot
# reach the other implementation reports success at the moment it stopped
# comparing anything.
DIFF_RUNNER=tests/differential/run_differential.py
if [ ! -f "$DIFF_RUNNER" ]; then
  fail "differential runner MISSING ($DIFF_RUNNER) -- the Python<->Rust line-definition contract is ungated"
elif DIFFOUT="$(py -3.14 "$DIFF_RUNNER" 2>&1)"; then
  pass "differential Python<->Rust contract holds"
else
  # Not necessarily a divergence: the runner also exits non-zero when the corpus
  # is too thin to discriminate, when the toolchain is unreachable, or when the
  # interpreter is missing. Gating on any of those is correct; naming them all
  # "DIVERGED" sends the reader to the wrong file, so print the real output.
  fail "differential gate FAILED -- run: py -3.14 $DIFF_RUNNER"
  printf '%s\n' "$DIFFOUT" | sed 's/^/      /'
fi

# ---- 9. Session-local artifacts never enter the repo -----------------------
#
# This repo is PUBLIC and carries private working notes locally (drafts,
# assignments, working state). .gitignore expresses the intent; it does not
# enforce it -- git add -f overrides an ignore rule without complaint, and an
# edit to .gitignore itself silently un-ignores the whole directory.
#
# THIS GATE ASSERTS TRACKED STATUS, NEVER FILE EXISTENCE. The directory is
# SUPPOSED to exist on disk; a check on existence would fail on every clean run,
# and a gate that fails when nothing is wrong is a gate somebody deletes.
#
# Both the index and HEAD are checked: git ls-files alone would miss a path
# committed earlier and since removed from the index, which still ships in
# history.
LOCAL_DIR=".local"
IDX_LOCAL="$(git ls-files -- "$LOCAL_DIR" 2>/dev/null)"
HEAD_LOCAL="$(git ls-tree -r --name-only HEAD -- "$LOCAL_DIR" 2>/dev/null)"
if [ -n "$IDX_LOCAL" ] || [ -n "$HEAD_LOCAL" ]; then
  fail "session-local artifact is TRACKED -- it must never enter this public repo"
  printf '%s\n%s\n' "$IDX_LOCAL" "$HEAD_LOCAL" | grep -v '^$' | head -5 | sed 's/^/          /'
  note "untrack with: git rm --cached -r $LOCAL_DIR   (and check history if it was committed)"
else
  pass "no session-local artifact tracked ($LOCAL_DIR/)"
fi

# ---- 10. Knowledge-base drift ----------------------------------------------
#
# Estate-wide 2026-08-24 standing directive: every project's KB must be
# content-hashed against its own source, and the check that proves it must
# GATE, not print. `tests/kb-drift.py` recomputes every record's source-line
# hash from the tree as it stands right now; any mismatch means the record's
# assertion is no longer provably tied to what it cites.
KB_DRIFT=tests/kb-drift.py
if [ ! -f "$KB_DRIFT" ]; then
  fail "KB drift gate MISSING ($KB_DRIFT)"
elif KBOUT="$(py -3.14 "$KB_DRIFT" 2>&1)"; then
  KBN="$(printf '%s' "$KBOUT" | grep -oE '[0-9]+ record' | head -1 | grep -oE '^[0-9]+')"
  pass "KB drift check (${KBN:-0} record(s), 0 drifted)"
else
  fail "KB drift gate FAILED -- run: py -3.14 $KB_DRIFT"
  printf '%s\n' "$KBOUT" | sed 's/^/      /'
fi

EMPTY_FIELDS=tests/kb-empty-fields.py
if [ ! -f "$EMPTY_FIELDS" ]; then
  fail "KB empty-field pin MISSING ($EMPTY_FIELDS)"
elif EMPTYOUT="$(py -3.14 "$EMPTY_FIELDS" 2>&1)"; then
  pass "KB empty-field pin holds (EXPECTED_EMPTY_VERBATIM=249)"
else
  fail "KB empty-field pin FAILED"
  printf '%s\n' "$EMPTYOUT" | sed 's/^/      /'
fi

echo "== $([ "$FAILED" = 0 ] && echo 'ALL GATES PASSED' || echo 'GATE(S) FAILED') =="
exit "$FAILED"
