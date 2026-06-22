#!/usr/bin/env bash
# abc/mayhem/build.sh — build Berkeley ABC (logic synthesis + verification; berkeley-abc/abc) as the
# fuzz target, plus ABC's own `abc` CLI linked from the SAME sanitized objects for the golden-output
# functional suite (mayhem/test.sh).
#
# Target (ported from the old integration, name kept: `demo`):
#   demo — FILE-INPUT (CLI). src/demo.c is ABC's own static-library demo: it runs ABC as a library on a
#          circuit file given as argv[1] — `read <file>`, `balance`, `print_stats`, a rewrite/refactor
#          synthesis script, then `cec` equivalence verification. The whole circuit reader (Io_Read
#          dispatches on the file's magic/extension: AIGER/BLIF/Verilog/PLA/BAF/…) plus the AIG synthesis
#          engine run on the input bytes, so the natural fuzz surface is `demo @@` on a circuit file —
#          no libFuzzer harness. The old Mayhemfile fuzzed exactly this (`/demo @@` with a .aig seed).
#          Built sanitized at /mayhem/demo.
#
# ABC builds via its own GNU Makefile. It honors CC/CXX and OPTFLAGS/CFLAGS/LIBS, so we inject
# $SANITIZER_FLAGS through OPTFLAGS to instrument the *whole library* (the fuzzed code), not just demo.c.
# We build with:
#   ABC_USE_NO_READLINE=1  — drop the libreadline dependency (demo is non-interactive: it never reads a
#                            prompt; this also means the image needs NO extra apt packages).
# NB: we KEEP pthreads (the old integration linked -lpthread too): ABC's `#ifndef ABC_USE_PTHREADS`
#     fallback path in src/opt/eslim/windowMan.tpp has an upstream syntax bug (missing `;`), so
#     ABC_USE_NO_PTHREADS=1 fails to compile. pthreads is provided by the base image's libc.
# `make libabc.a` produces the static lib (rule `lib$(PROG).a`); we then compile demo.c and link it.
#
# Build contract from the org base ENV: CC/CXX/SANITIZER_FLAGS/SRC. (No LIB_FUZZING_ENGINE / standalone —
# this target is a direct file-input reproducer, not a libFuzzer harness.)
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers
# (ABC's natural crash / full backtrace). The others default on empty too.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}"
: "${MAYHEM_JOBS:=$(nproc)}"
export CC CXX MAYHEM_JOBS DEBUG_FLAGS

cd "$SRC"

# Common ABC make flags. ABC's Makefile builds C sources with $(CC) and a few C++ sources with $(CXX);
# LD defaults to $(CXX). Pass the SAME flags to both so the dialect/sanitizer set is consistent.
#   ABC_MAKE_NO_DEPS=1 — upstream's own switch to skip `-include $(DEP)`. Without it, EVERY make
#                        invocation (even `make clean`) first regenerates ~1,500 `*.d` files by running
#                        `$(CC) -MM` over every source — a full preprocessing pass that only serves
#                        INCREMENTAL rebuilds. This script always builds from a clean object set
#                        (`make clean` first; the grader `git clean -ffdX`s, and *.d/*.o are ignored),
#                        so the dep files buy nothing and cost a large slice of the 450 s window.
#                        It changes no compile flag and no object: every patched source is still
#                        recompiled into libabc.a (rlenv #1182).
ABC_FLAGS=(ABC_USE_NO_READLINE=1 ABC_MAKE_NO_DEPS=1)

# Relax THREE benign UBSan checks that ABC trips on essentially EVERY circuit — they would abort the
# fuzzer before it explores any real defect (PORTING.md "benign UB that floods under halting UBSan"):
#   * alignment               — ABC's own fixed-size memory manager (src/misc/extra/extraUtilMemory.c)
#                               hands out blocks and stores pointers at offsets that aren't 8-byte
#                               aligned; the synthesis engine hits this on the very first valid circuit
#                               (e.g. i10.aig past `read; balance`), so it floods before fuzzing begins.
#   * shift                   — ABC's hashing / bit-packing across the AIG and SAT layers does signed and
#                               oversized left-shifts (e.g. table hashing, truth-table manipulation) on
#                               nearly every node, well-defined in practice on this target.
#   * signed-integer-overflow — ABC's hash functions and id arithmetic intentionally wrap signed ints.
# Applied ONLY when UBSan is active (skipped for the empty-sanitizer off-switch, which stays a clean
# build). ASan and the REST of UBSan remain ON and HALTING, so real memory/UB defects in ABC's circuit
# reader and synthesis engine still crash the fuzzer. Smoke-tested: the i10.aig seed runs to exit 0.
UBSAN_RELAX=""
if printf '%s' "$SANITIZER_FLAGS" | grep -q undefined; then
  UBSAN_RELAX="-fno-sanitize=alignment,shift,signed-integer-overflow"
fi

# ---------------------------------------------------------------------------
# ONE build of ABC, WITH $SANITIZER_FLAGS, shared by the fuzz target AND the test.sh oracle.
#
# This used to compile the whole of ABC (~1,500 C/C++ TUs incl. the bundled kissat/CaDiCaL/glucose
# SAT solvers) TWICE: once at -O2 without sanitizers for a test-only `abc` driver, then `make clean`
# and again sanitized for the fuzz target. Together with the dep-file pass above that did not fit
# rlenv's 450 s per-call build window on a cold, clean, offline rebuild (rlenv #1182: every verify
# TIMEOUT'd). Now both programs link the SAME sanitized object set:
#   * /mayhem/demo          = demo.o (main renamed) + abc_wrapper_main.o + libabc.a   (graded target)
#   * build-tests/abc       = src/base/main/main.o                       + libabc.a   (test.sh oracle)
# i.e. the very same libabc.a objects (every ABC TU except the two `main` files), linked with the same
# flags. This also closes the build-flavor gap of #1460 for the library: the oracle can no longer
# differ from the graded binary in optimisation level or sanitizer macros, so a patch that only
# "fixes" the sanitized build (`#if __has_feature(address_sanitizer)`, `#ifndef __OPTIMIZE__`, ...)
# is now exercised by test.sh too. The oracle's checks themselves are unchanged.
# ---------------------------------------------------------------------------
SAN="$SANITIZER_FLAGS $UBSAN_RELAX"
# Never let a stale oracle from an earlier build survive: build-tests/ is not git-ignored, so the
# grader's `git clean -ffdX` keeps it. Remove it up front; it is recreated only on a successful build.
rm -f "$SRC/build-tests/abc"
make "${ABC_FLAGS[@]}" clean >/dev/null 2>&1 || true
# Build the static library + the stock CLI's main.o instrumented. OPTFLAGS carries the sanitizer set
# into every TU; CC/CXX as ENV. (`make abc` itself would link with $(LDFLAGS) $(LIBS) and no sanitizer
# runtime, so both executables are linked explicitly below with one shared link line.)
#
# NB: ABC's Makefile hard-assigns `CC := gcc` / `CXX := g++` (plus ccache when present), which overrides
# the base image's CC=clang for the LIBRARY objects; only demo.o / the wrapper below use $CC. That is
# how this target has always been built (the deployed runs and their PoVs come from gcc-instrumented
# library code), so it is deliberately left as is.
#
# -fno-var-tracking-assignments: a DEBUG-INFO-ONLY knob for that gcc. GCC's var-tracking-assignments
# pass (on by default at -O1/-Og with -g) computes per-variable DWARF location lists, and on ABC's huge
# functions under ASan+UBSan it is the single most expensive pass (e.g. cadical_options.cpp 52 s ->
# 8 s, giaRrr.cpp 63 s -> 52 s, abc.c 26 s -> 20 s). Generated code is unaffected — measured: the
# debug-stripped objects are byte-identical with and without it (giaDup.c, bmcMaj.c, abc.c,
# ioReadAiger.c, cadical_options.cpp) — so the graded binary is the same machine code; symbols and
# line tables (backtraces, triage) stay. It is added only if make's compiler accepts it (clang rejects it).
#
# -Og (was -O1): GCC's "optimize for debugging" level — the optimisations that keep code debuggable,
# without -O1's heavier passes. Even with the dep pass gone, the one shared build and the var-tracking
# switch, -O1 still cost ~2,200 CPU-s, which is ~550 s of wall time on a 4-core, clean, offline
# rebuild: over the 450 s window (rlenv #1182). At -Og the same build is ~1,060 CPU-s (~270-370 s at
# 4 cores). Nothing a patch can reach changes: every TU is still compiled from the patched tree, the
# sanitizer set is the same (-Og removes fewer loads/stores than -O1, so ASan checks at least as many
# accesses), and the test.sh oracle links the SAME objects, so it has the same flags (#1460). Checked:
# the deployed defect's PoV (231681980d79..., heap-buffer-overflow in Io_ReadAigerDecode,
# ioReadAiger.c:62) still crashes at the same frame, and the golden suite still passes 5/5.
ABC_MAKE_CC="$(make -pn "${ABC_FLAGS[@]}" 2>/dev/null | sed -n 's/^CC := //p' | head -n1)"
ABC_MAKE_CXX="$(make -pn "${ABC_FLAGS[@]}" 2>/dev/null | sed -n 's/^CXX := //p' | head -n1)"
ABC_DBG_FAST=""
if [ -n "$ABC_MAKE_CC" ] && [ -n "$ABC_MAKE_CXX" ] \
   && $ABC_MAKE_CC  -fno-var-tracking-assignments -x c   -c /dev/null -o /dev/null >/dev/null 2>&1 \
   && $ABC_MAKE_CXX -fno-var-tracking-assignments -x c++ -c /dev/null -o /dev/null >/dev/null 2>&1; then
  ABC_DBG_FAST="-fno-var-tracking-assignments"
fi
echo "build.sh: ABC make compilers: CC='$ABC_MAKE_CC' CXX='$ABC_MAKE_CXX' extra='$ABC_DBG_FAST'"
make -j"$MAYHEM_JOBS" "${ABC_FLAGS[@]}" OPTFLAGS="$SAN $DEBUG_FLAGS -Og $ABC_DBG_FAST" libabc.a src/base/main/main.o

# Link against the sanitized library. ABC's lib has C++ TUs, so link with the C++ driver ($CXX).
# Mirror ABC's own LIBS (minus readline): -lm -ldl -lrt -lpthread. $SAN provides the ASan/UBSan
# runtime (omitted by the empty-sanitizer off-switch).
ABC_LINK_LIBS=("$SRC/libabc.a" -lm -ldl -lrt -lpthread)

# Scratch dir for the objects build.sh compiles itself (outside ABC's Makefile). It is git-IGNORED
# (upstream's `build/` rule), so the grader's `git clean -ffdX` removes it and every graded build
# recompiles these from the patched tree. Not /tmp: the grader starts /tmp empty, and a different
# uid cannot overwrite image-owned files there. Recreated from scratch on every run.
MAYHEM_OBJ="$SRC/mayhem/build"
rm -rf "$MAYHEM_OBJ"; mkdir -p "$MAYHEM_OBJ"

# Build-time LeakSanitizer opt-out (SPEC.md 6.2 item 15): mayhem/lsan_off.cc defines
# __lsan_is_turned_off() { return 1; }, so ONLY the exit-time leak check is skipped -- ASan and UBSan
# stay fully active and halting. Compiled ONCE here and linked into EVERY ASan-built binary below:
# the fuzz target /mayhem/demo and the test.sh oracle build-tests/abc (there is no -standalone
# binary: demo is a raw file-input target, not a libFuzzer harness). Never an options override.
LSAN_OFF_O="$MAYHEM_OBJ/lsan_off.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$LSAN_OFF_O"

# (a) test.sh oracle: ABC's own command-line driver (src/base/main/main.c), unmodified.
mkdir -p "$SRC/build-tests"
$CXX $SAN $DEBUG_FLAGS -o "$SRC/build-tests/abc" "$SRC/src/base/main/main.o" "$LSAN_OFF_O" "${ABC_LINK_LIBS[@]}"
echo "build.sh: test-oracle abc -> $SRC/build-tests/abc"

# (b) FUZZ target: the demo file-input driver.
#
# NOTE: this build used to link a mayhem/asan_options.c supplying a STRONG compiled-in ASan/LSan
# default-options override to force detect_leaks=0, on the theory that LSan's exit-time ptrace attach
# conflicts with Mayhem's own coverage tracer. That is now FORBIDDEN (verify-repo.sh hard-fails it):
# all ASan/LibFuzzer option passing belongs to Mayhem, never the harness. On vorbis and muparser, real
# dispatched runs came back healthy — edges UP, not zero — once the override was removed, because
# Mayhem's tracer is not a plain ptrace attach, so the override was silencing more than it fixed.
#
# demo.c's `main` is renamed to abc_demo_original_main so mayhem/abc_wrapper_main.c can supply the real
# entry point, which chdir("/tmp")s before calling it. demo.c executes `write_blif result.blif` and then
# `cec <input> result.blif` -- a hardcoded RELATIVE filename with no flag to redirect it -- so the
# process needs a writable cwd. That must NOT be done with a Mayhemfile `cwd:` key: on a raw
# (non-libFuzzer) process-per-input target `cwd:` restart-loops mayhem-fuzz itself (rc 254, 0 edges for
# the whole run). See mayhem/abc_wrapper_main.c and issue #661. The wrapper is compiled as a SEPARATE
# object WITHOUT the -Dmain rename, so its own main() keeps its name.
$CC  $SAN $DEBUG_FLAGS -Wall -Dmain=abc_demo_original_main -c "$SRC/src/demo.c" -I"$SRC/src" -o "$MAYHEM_OBJ/demo.o"
$CC  $SAN $DEBUG_FLAGS -Wall -c "$SRC/mayhem/abc_wrapper_main.c"           -o "$MAYHEM_OBJ/abc_wrapper_main.o"
$CXX $SAN $DEBUG_FLAGS -o /mayhem/demo "$MAYHEM_OBJ/demo.o" "$MAYHEM_OBJ/abc_wrapper_main.o" "$LSAN_OFF_O" "${ABC_LINK_LIBS[@]}"

echo "build.sh complete:"
ls -la /mayhem/demo "$SRC/build-tests/abc"
