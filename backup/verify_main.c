#include <config.h>
#include <stdio.h>

#include "lib/exitcodes.h"

#include "backup/api.h"


EXPORTED void fatal(const char *error, int code) {
    fprintf(stderr, "fatal error: %s\n", error);
    exit(code);
}

static void usage(const char *name) {
    fprintf(stderr, "Usage: %s backup_name\n", name);
    exit(EC_USAGE);
}

HIDDEN int main (int argc, char **argv) {
    if (argc != 2) usage(argv[0]);

    char *backup_name = argv[1];
    struct backup *backup = NULL;
    int r;

    r = backup_open_paths(&backup, backup_name, NULL,
                          BACKUP_OPEN_BLOCK);
    if (r) {
        fprintf(stderr, "couldn't open %s\n", backup_name);
        return -1;
    }

    fprintf(stderr, "verifying %s...\n", backup_name);

    r = backup_verify(backup, BACKUP_VERIFY_FULL);
    backup_close(&backup);

    return r;
}
