// mayhem/lsan_off.cc -- build-time LeakSanitizer opt-out (fleet policy, SPEC.md 6.2 item 15).
//
// Why: leaks are not the bug class this target is fuzzed for -- ASan's memory-error checks
// (heap/stack/global overflows, use-after-free, ...) and UBSan are. `-fsanitize=address` always
// bundles LeakSanitizer and there is no compiler flag that leaves it out, and ABC (a large
// synthesis library run as a one-shot CLI) does not free everything before exit, so with LSan on a
// leak report at exit would turn ordinary inputs into "defects" and inflate the defect count.
//
// How: the ASan/LSan runtime calls this weak-hooked function at exit; returning 1 skips ONLY the
// leak check. Nothing else changes: ASan and UBSan stay fully active and halting. This is NOT an
// options override -- no compiled-in ASan/LSan default-options function and no ASAN_OPTIONS (Mayhem
// alone owns the runtime option set), and no runtime LSan disable/enable wrapping.
//
// mayhem/build.sh compiles this ONCE with $SANITIZER_FLAGS $DEBUG_FLAGS and links the object into
// every ASan-built binary: the fuzz target /mayhem/demo and the test.sh oracle build-tests/abc.
extern "C" int __lsan_is_turned_off() { return 1; }
