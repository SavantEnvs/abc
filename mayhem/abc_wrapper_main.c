/*
 * mayhem/abc_wrapper_main.c -- writable-scratch fix for the abc `demo` fuzz target, WITHOUT a
 * Mayhemfile `cwd:` key.
 *
 * Why this exists: src/demo.c runs ABC's full pipeline on the input circuit and then executes
 * `write_blif result.blif` (src/demo.c:168) followed by `cec <input> result.blif` (:180). That
 * filename is a HARDCODED RELATIVE path -- it is fopen()ed relative to the process's current working
 * directory and there is no flag to redirect it. Mayhem mounts the commit image read-only during
 * coverage collection, so the process needs its cwd already pointing somewhere writable.
 *
 * The Mayhemfile previously got that with a per-cmd `cwd: /dev/shm`. That is WRONG for a raw
 * (non-libFuzzer), process-per-input executable target: it restart-loops mayhem-fuzz ITSELF -- the
 * supervisor, not the target -- which dies with rc 254, so tests_run/edges_covered stay 0 for the
 * whole run while docker build, fuzz-smoke and the mayhem.yml Action all report success. See issue
 * #661. Two repos in this fleet proved both halves of this: savantenvs/microscheme went 0 -> 28,084
 * edges and savantenvs/svf (target `saber`) went 0 -> 66,509 edges once the `cwd:` key was dropped,
 * while the raw targets that never used it (armips, dasm, chaos) were green throughout.
 *
 * Fix: do the chdir INSIDE the binary instead of asking Mayhem's supervisor to do it. mayhem/build.sh
 * compiles src/demo.c with `-Dmain=abc_demo_original_main` (a plain, fully-additive preprocessor
 * rename -- no upstream file is edited) and links in this file, which supplies the real main(): one
 * unconditional chdir("/tmp") before handing off to the renamed original. This object is compiled
 * WITHOUT that -D, so its own main() keeps its name.
 *
 * Note the input path is unaffected: Mayhem stages the `@@` input at an absolute path, and fopen() of
 * an absolute path does not care what the cwd is. Only the *output* result.blif needed a writable cwd.
 *
 * Mirrors the precedent already proven in this fleet: microscheme_wrapper_main.c
 * (-Dmain=microscheme_original_main) and chaos_watchdog_main.c (-Dmain=chaos_original_main).
 */
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern int abc_demo_original_main(int argc, char **argv);

/*
 * ORDER MATTERS: resolve argv paths to ABSOLUTE *before* chdir(), not after.
 *
 * The first version of this wrapper chdir("/tmp")'d immediately and then handed argv through
 * untouched. Mayhem does not guarantee the staged `@@` input is an absolute path, and once the cwd
 * has moved a RELATIVE input path no longer resolves -- demo never opens the file, and the run dies
 * in Mayhem's sanity phase with "Your target runs but does not seem to use the file input specified
 * in the Mayhemfile" (savantenvs/abc/demo run #1: 0 tests, 0 edges, t=0s). That is a different
 * failure from the #661 rc-254 restart loop this wrapper exists to avoid -- and it is self-inflicted,
 * so guard against it explicitly rather than assuming absolute inputs.
 *
 * realpath() each existing non-option argument first, then chdir. An argument that does not name an
 * existing file is left exactly as-is (it is a flag, or a path demo means to create).
 *
 * SECOND, and the actual reason runs #1 and #2 recorded 0 tests: ABC's generic file reader dispatches
 * on the file EXTENSION and refuses anything it does not recognise --
 *
 *     $ /mayhem/demo /tmp/b.bin
 *     Generic file reader requires a known file extension to open "/tmp/b.bin".
 *     Error: Empty network.
 *     $ /mayhem/demo /tmp/a.aig
 *     ... Networks are equivalent.
 *
 * Mayhem stages the `@@` input under a name with no recognised extension, so demo never reads it and
 * the run dies in the sanity phase with "Your target runs but does not seem to use the file input
 * specified in the Mayhemfile" (note that message's own wording: "no restrictions on file name or
 * extension" -- ABC has exactly such a restriction). The Mayhemfile remedy for this would be a
 * `filepath:` key, which is FORBIDDEN on a raw process-per-input target (#661: it restart-loops
 * mayhem-fuzz with rc 254). So, as with compiler/pawncc, the naming is done INSIDE the binary: the
 * staged input is copied to a .aig path and demo is handed that instead.
 *
 * .aig is the right extension: the shipped seed is ABC's own i10.aig (binary AIGER) and Io_Read
 * auto-detects the concrete format from the file, so an AIGER-named file is the natural surface.
 */
#define STAGED_INPUT "/tmp/mayhem_in.aig"

/* Copy `src` to STAGED_INPUT so the name carries an extension ABC's reader accepts. 0 on success. */
static int stage_input(const char *src)
{
    FILE *in, *out;
    char buf[65536];
    size_t n;

    in = fopen(src, "rb");
    if (in == NULL)
        return -1;
    out = fopen(STAGED_INPUT, "wb");
    if (out == NULL)
    {
        fclose(in);
        return -1;
    }
    while ((n = fread(buf, 1, sizeof buf, in)) > 0)
    {
        if (fwrite(buf, 1, n, out) != n)
        {
            fclose(in);
            fclose(out);
            return -1;
        }
    }
    fclose(in);
    return fclose(out) == 0 ? 0 : -1;
}

static void prepare_args(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++)
    {
        char resolved[PATH_MAX];
        const char *path;

        if (argv[i][0] == '-')
            continue;                       /* an option, not a path */
        if (access(argv[i], F_OK) != 0)
            continue;                       /* not an existing file — leave it alone */

        /* Resolve BEFORE the chdir below, since a relative path stops resolving once cwd moves. */
        path = realpath(argv[i], resolved) ? resolved : argv[i];

        /* Re-stage under a .aig name so ABC's extension-dispatching reader will open it. */
        if (stage_input(path) == 0)
            argv[i] = (char *)STAGED_INPUT;

        break;                              /* only the first file argument is the fuzz input */
    }
}

int main(int argc, char **argv)
{
    prepare_args(argc, argv);

    if (chdir("/tmp") != 0)
    {
        perror("mayhem: chdir(/tmp)");
        return 1;
    }

    return abc_demo_original_main(argc, argv);
}
