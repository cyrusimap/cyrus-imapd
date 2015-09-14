/* bulock.c -- tool for manual locking of replication-based backup files
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include <config.h>
#include <stdio.h>

#include "lib/exitcodes.h"
#include "lib/prot.h"

#include "backup/api.h"

EXPORTED void fatal(const char *error, int code)
{
    fprintf(stderr, "fatal error: %s\n", error);
    exit(code);
}

static void usage(const char *name)
{
    fprintf(stderr, "Usage: %s backup_name\n", name);
    exit(EC_USAGE);
}

int main (int argc, char **argv)
{
    if (argc != 2) usage(argv[0]);

    char *backup_name = argv[1];

    /* be nice: accept (and discard) a tab-completed .gz suffix */
    char *suffix = strrchr(backup_name, '.');
    if (suffix && strcmp(suffix, ".gz") == 0 && suffix[strlen(".gz")] == '\0')
        *suffix = '\0';

    // FIXME which signals to ignore/accept?

    printf("* Trying to obtain lock on %s...\n", backup_name);

    struct backup *backup = backup_open(backup_name, NULL);

    if (!backup) {
        printf("NO failed\n");
        return EC_SOFTWARE; // FIXME would something else be more appropriate?
    }

    printf("OK locked\n");

    /* wait until stdin closes */
    char buf[PROT_BUFSIZE] = {0};
    while (!feof(stdin))
        fgets(buf, sizeof(buf), stdin);

    int r = backup_close(&backup);
    if (!r) fprintf(stderr, "warning: backup_close() returned %i\n", r);

    return r;
}
