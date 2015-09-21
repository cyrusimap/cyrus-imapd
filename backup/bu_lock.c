/* bu_lock.c -- tool for manual locking of replication-based backup files
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

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
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
    // FIXME write this
    fprintf(stderr, "Usage: %s backup_name\n", name);
    exit(EC_USAGE);
}

enum bu_lock_open_type {
    BU_LOCK_OPEN_UNSPECIFIED,
    BU_LOCK_OPEN_FILENAME,
    BU_LOCK_OPEN_MBOXNAME,
    BU_LOCK_OPEN_USERNAME
};

enum bu_lock_run_mode {
    BU_LOCK_RUN_PIPE,
    BU_LOCK_RUN_SQL,
    BU_LOCK_RUN_EXEC
};

static struct backup *my_backup_open(enum bu_lock_open_type open_type,
                                     const char *backup_name)
{
    struct backup *backup = NULL;
    mbname_t *mbname = NULL;
    char *suffix;

    switch (open_type) {
    case BU_LOCK_OPEN_UNSPECIFIED:
        break;
    case BU_LOCK_OPEN_FILENAME:
        suffix = strrchr(backup_name, '.');
        if (suffix && strcmp(suffix, ".gz") == 0 && suffix[strlen(".gz")] == '\0')
            *suffix = '\0';
        backup = backup_open(backup_name, NULL);
        break;
    case BU_LOCK_OPEN_MBOXNAME:
        mbname = mbname_from_intname(backup_name);
        backup = backup_open(mboxname_backuppath(/*FIXME*/ "default", mbname), NULL);
        break;
    case BU_LOCK_OPEN_USERNAME:
        mbname = mbname_from_userid(backup_name);
        backup = backup_open(mboxname_backuppath(/*FIXME*/ "default", mbname), NULL);
        break;
    default:
        break;
    }

    if (mbname) mbname_free(&mbname);

    return backup;
}

static int run_pipe(enum bu_lock_open_type open_type, const char *backup_name)
{
    printf("* Trying to obtain lock on %s...\n", backup_name);

    struct backup *backup = my_backup_open(open_type, backup_name);

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
    if (r) fprintf(stderr, "warning: backup_close() returned %i\n", r);

    return 0;
}

static int run_sql(/* FIXME */)
{
    return -1; // FIXME
}

static int run_exec(enum bu_lock_open_type open_type, const char *backup_name,
                    char **argv)
{
    struct backup *backup = my_backup_open(open_type, backup_name);

    if (!backup) {
        fprintf(stderr, "unable to lock %s\n", backup_name);
        return EC_SOFTWARE;
    }

    int r = 0, status;
    pid_t pid = fork();

    switch(pid) {
    case -1:
        fprintf(stderr, "fork failed: %s\n", strerror(errno));
        r = EC_SOFTWARE;
        break;

    case 0:
        /* child */
        execvp(argv[0], argv);
        /* execvp never returns */
        _exit(EC_SOFTWARE);
        break;

    default:
        /* parent */
        waitpid(pid, &status, 0);
        if (WIFEXITED(status))
            r = WEXITSTATUS(status);
        else
            r = EC_SOFTWARE;
        break;
    }

    backup_close(&backup);
    return r;
}

int main (int argc, char **argv)
{
    int opt;
    enum bu_lock_open_type open_type = BU_LOCK_OPEN_UNSPECIFIED;
    enum bu_lock_run_mode run_mode = BU_LOCK_RUN_PIPE;
    const char *backup_name = NULL;

    while ((opt = getopt(argc, argv, "f:m:u:sx")) != EOF) {
        switch (opt) {
        case 'f':
            if (open_type != BU_LOCK_OPEN_UNSPECIFIED) usage(argv[0]);
            open_type = BU_LOCK_OPEN_FILENAME;
            backup_name = optarg;
            break;
        case 'm':
            if (open_type != BU_LOCK_OPEN_UNSPECIFIED) usage(argv[0]);
            open_type = BU_LOCK_OPEN_MBOXNAME;
            backup_name = optarg;
            break;
        case 'u':
            if (open_type != BU_LOCK_OPEN_UNSPECIFIED) usage(argv[0]);
            open_type = BU_LOCK_OPEN_USERNAME;
            backup_name = optarg;
            break;
        case 's':
            if (run_mode != BU_LOCK_RUN_PIPE) usage(argv[0]);
            run_mode = BU_LOCK_RUN_SQL;
            break;
        case 'x':
            if (run_mode != BU_LOCK_RUN_PIPE) usage(argv[0]);
            run_mode = BU_LOCK_RUN_EXEC;
            break;
        }
    }

    if (open_type == BU_LOCK_OPEN_UNSPECIFIED) usage(argv[0]);
    if (backup_name == NULL) usage(argv[0]);
    if (run_mode == BU_LOCK_RUN_EXEC && optind == argc) usage(argv[0]);

    // FIXME which signals to ignore/accept?

    switch (run_mode) {
        case BU_LOCK_RUN_PIPE:
            return run_pipe(open_type, backup_name);
        case BU_LOCK_RUN_SQL:
            return run_sql(open_type, backup_name);
        case BU_LOCK_RUN_EXEC:
            return run_exec(open_type, backup_name, &argv[optind]);
        default:
            fprintf(stderr, "invalid run mode, how did we get here?\n");
            return -1;
    }
}
