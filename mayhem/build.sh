#!/usr/bin/env bash
# abc/mayhem/build.sh — build Berkeley ABC (logic synthesis + verification; berkeley-abc/abc) as the
# fuzz target, plus a clean normal-flags ABC binary for the golden-output functional suite (mayhem/test.sh).
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
ABC_FLAGS=(ABC_USE_NO_READLINE=1)

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
# (1) TEST build — ABC's OWN normal flags (no sanitizer) → the full `abc` driver for test.sh's
#     golden-output oracle. Built first into build-tests/, then the tree is cleaned for the sanitized
#     build (ABC's Makefile builds in-tree, so the two builds can't coexist in one objdir).
# ---------------------------------------------------------------------------
make "${ABC_FLAGS[@]}" clean >/dev/null 2>&1 || true
make -j"$MAYHEM_JOBS" "${ABC_FLAGS[@]}" OPTFLAGS="-O2 $DEBUG_FLAGS" abc
mkdir -p "$SRC/build-tests"
cp -f abc "$SRC/build-tests/abc"
echo "build.sh: test-oracle abc -> $SRC/build-tests/abc"

# ---------------------------------------------------------------------------
# (2) FUZZ build — libabc.a + demo.c compiled WITH $SANITIZER_FLAGS so the fuzzed library is
#     instrumented. The file-input Mayhem target lands at /mayhem/demo.
# ---------------------------------------------------------------------------
SAN="$SANITIZER_FLAGS $UBSAN_RELAX"
make "${ABC_FLAGS[@]}" clean >/dev/null 2>&1 || true
# Build the static library instrumented. OPTFLAGS carries the sanitizer set into every TU; CC/CXX as ENV.
make -j"$MAYHEM_JOBS" "${ABC_FLAGS[@]}" OPTFLAGS="$SAN $DEBUG_FLAGS -O1" libabc.a

# Compile + link the demo file-input driver against the sanitized library. demo.c is C; ABC's lib has
# C++ TUs, so link with the C++ driver ($CXX). Mirror ABC's own LIBS (minus readline): -lm -ldl -lrt
# -lpthread. $SAN provides the ASan/UBSan runtime (omitted by the empty-sanitizer off-switch).
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
$CC  $SAN $DEBUG_FLAGS -Wall -Dmain=abc_demo_original_main -c "$SRC/src/demo.c" -I"$SRC/src" -o /tmp/demo.o
$CC  $SAN $DEBUG_FLAGS -Wall -c "$SRC/mayhem/abc_wrapper_main.c"           -o /tmp/abc_wrapper_main.o
$CXX $SAN $DEBUG_FLAGS -o /mayhem/demo /tmp/demo.o /tmp/abc_wrapper_main.o "$SRC/libabc.a" -lm -ldl -lrt -lpthread

echo "build.sh complete:"
ls -la /mayhem/demo "$SRC/build-tests/abc"
