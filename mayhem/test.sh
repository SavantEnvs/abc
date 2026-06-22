#!/usr/bin/env bash
# abc/mayhem/test.sh — RUN a golden-output functional suite against the normal-flags `abc` driver that
# mayhem/build.sh produced (build-tests/abc) → CTRF. PATCH-grade oracle: it never compiles ABC.
#
# Why a golden suite rather than ABC's CMake/GoogleTest dir: ABC's only checked-in unit test
# (test/gia/gia_test.cc) builds ONLY under CMake, which FetchContent-downloads googletest from GitHub
# at configure time — an unpinned network fetch that is neither reproducible nor offline-buildable in
# the commit image. So we author a self-contained KNOWN-ANSWER suite instead, driving ABC's real
# command interpreter over its own checked-in circuit (i10.aig) and asserting exact circuit statistics
# and equivalence-checking verdicts that ABC's synthesis engine deterministically produces.
#
# These are BEHAVIOR / known-answer oracles, NOT "exit 0" checks:
#   * the AIGER reader must parse i10 to exactly i/o=257/224, and=2675 (parser correctness),
#   * `balance` must reduce it to and=2396 lev=37 (the balancing transform),
#   * a rewrite/refactor synthesis script must reduce it to and=1846 (DAG-aware rewriting),
#   * `resyn2` must reduce it to and=1829 lev=32 (the standard resynthesis recipe),
#   * `cec` must PROVE the synthesized network equivalent to the original (combinational eq-checking).
# A no-op / exit(0) "patch" to ABC emits none of these exact node counts and cannot prove equivalence,
# so it FAILS every assertion — it cannot reward-hack this oracle.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

ABC="$SRC/build-tests/abc"
CIRCUIT="$SRC/i10.aig"
[ -x "$ABC" ]      || { echo "missing $ABC — run mayhem/build.sh first" >&2; emit_ctrf "abc-golden" 0 1 0; exit 2; }
[ -f "$CIRCUIT" ]  || { echo "missing $CIRCUIT (ABC's checked-in test circuit)" >&2; emit_ctrf "abc-golden" 0 1 0; exit 2; }

passed=0; failed=0

# run_abc <command-string> -> prints ABC's stdout with ANSI color codes stripped (print_stats colorizes).
run_abc() { "$ABC" -q "$1" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }

# check <name> <abc-command> <extended-regex-the-output-must-match>
check() {
  local name="$1" cmd="$2" want="$3" out
  out="$(run_abc "$cmd")"
  if printf '%s\n' "$out" | grep -Eq "$want"; then
    echo "PASS $name"
    passed=$((passed+1))
  else
    echo "FAIL $name — expected /$want/, got:" >&2
    printf '%s\n' "$out" >&2
    failed=$((failed+1))
  fi
}

# 1) AIGER reader: i10 parses to exactly 257 inputs / 224 outputs / 2675 AND nodes.
check "read_aiger_stats" \
  "read $CIRCUIT; print_stats" \
  'i/o += *257/ *224.*and += *2675'

# 2) balance: structural balancing reduces the AIG to and=2396, lev=37.
check "balance" \
  "read $CIRCUIT; balance; print_stats" \
  'and += *2396 +lev += *37'

# 3) rewrite/refactor synthesis script: DAG-aware rewriting reduces to and=1846.
check "rewrite_script" \
  "read $CIRCUIT; balance; rewrite -l; rewrite -lz; balance; rewrite -lz; balance; print_stats" \
  'and += *1846'

# 4) resyn2 standard recipe: reduces to and=1829, lev=32.
check "resyn2" \
  "read $CIRCUIT; resyn2; print_stats" \
  'and += *1829 +lev += *32'

# 5) combinational equivalence checking: the synthesized network must be PROVEN equivalent to the
#    original — exercises ABC's SAT-based eq-checker, the strongest behavioral oracle here.
check "cec_equivalence" \
  "read $CIRCUIT; strash; balance; rewrite; dc2; cec" \
  'Networks are equivalent'

echo "abc golden suite: passed=$passed failed=$failed" >&2
emit_ctrf "abc-golden" "$passed" "$failed"
