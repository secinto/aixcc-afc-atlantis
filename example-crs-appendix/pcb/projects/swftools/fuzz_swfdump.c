#include "fuzz_swfdump.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int swfdump_main(int argc, char **argv);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char input_filename[256];
    sprintf(input_filename, "/tmp/libfuzzer.%d", getpid());

    FILE *fp = fopen(input_filename, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(data, size, 1, fp);
    fclose(fp);

    // Redirect stdout to /dev/null to suppress output
    FILE *original_stdout = stdout;
    // FILE *original_stderr = stderr;
    stdout = freopen("/dev/null", "w", stdout);
    // stderr = freopen("/dev/null", "w", stderr);

    // Prepare arguments for nasm_main
    char *argv[] = {
        "swfdump",  // Program name
        input_filename,    // Input file
    };
    int argc = 2;
    filename = 0;

    /* idtab stores the ids which are defined in the file. This allows us
       to detect errors in the file. (i.e. ids which are defined more than
       once */
    memset(idtab, 0, sizeof(idtab));

    placements = 0;
    action = 0;
    html = 0;
    xhtml = 0;
    xy = 0;
    showtext = 0;
    showshapes = 0;
    hex = 0;
    used = 0;
    bbox = 0;
    cumulative = 0;
    showfonts = 0;
    showbuttons = 0;

    swfdump_main(argc, argv);

    stdout = original_stdout;
    // stderr = original_stderr;
    // Clean up
    unlink(input_filename);
    return 0;
}
