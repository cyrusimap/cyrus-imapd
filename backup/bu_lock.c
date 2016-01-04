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

#include "imap/global.h"

#include "backup/api.h"

EXPORTED void fatal(const char *error, int code)
{
    fprintf(stderr, "fatal error: %s\n", error);
    cyrus_done();
    exit(code);
}

static void usage(const char *name)
{
    fprintf(stderr, "Usage: %s backup\n", name);
    fprintf(stderr, "Usage: %s backup -s\n", name);
    fprintf(stderr, "Usage: %s backup -x command\n", name);

    fprintf(stderr, "\nBackup specification:\n");
    fprintf(stderr, "  -f filename\n");
    fprintf(stderr, "  -m mailbox\n");
    fprintf(stderr, "  -u userid\n");

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
                                     const char *backup_spec)
{
    struct backup *backup = NULL;
    mbname_t *mbname = NULL;
    int r;

    switch (open_type) {
    case BU_LOCK_OPEN_UNSPECIFIED:
        break;
    case BU_LOCK_OPEN_FILENAME:
        r = backup_open_paths(&backup, backup_spec, NULL, BACKUP_OPEN_BLOCK);
        break;
    case BU_LOCK_OPEN_MBOXNAME:
        mbname = mbname_from_intname(backup_spec);
        r = backup_open(&backup, mbname, BACKUP_OPEN_BLOCK);
        break;
    case BU_LOCK_OPEN_USERNAME:
        mbname = mbname_from_userid(backup_spec);
        r = backup_open(&backup, mbname, BACKUP_OPEN_BLOCK);
        break;
    default:
        break;
    }

    if (mbname) mbname_free(&mbname);
    if (r) return NULL;
    return backup;
}

static int run_pipe(enum bu_lock_open_type open_type, const char *backup_spec)
{
    printf("* Trying to obtain lock on %s...\n", backup_spec);

    struct backup *backup = my_backup_open(open_type, backup_spec);

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

static int run_sql(enum bu_lock_open_type open_type, const char *backup_spec)
{
    struct backup *backup = my_backup_open(open_type, backup_spec);

    if (!backup) {
        fprintf(stderr, "unable to lock %s\n", backup_spec);
        return EC_SOFTWARE;
    }

    const char *index_fname = backup_get_index_fname(backup);
    int r = 0, status;
    pid_t pid = fork();

    switch (pid) {
    case -1:
        fprintf(stderr, "fork failed: %s\n", strerror(errno));
        r = EC_SOFTWARE;
        break;

    case 0:
        /* child */
        fprintf(stderr, "execlp: %s %s\n", "sqlite3", index_fname);
        execlp("sqlite3", "sqlite3", index_fname, NULL);
        /* execlp never returns */
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

static int run_exec(enum bu_lock_open_type open_type, const char *backup_spec,
                    char **argv)
{
    struct backup *backup = my_backup_open(open_type, backup_spec);

    if (!backup) {
        fprintf(stderr, "unable to lock %s\n", backup_spec);
        return EC_SOFTWARE;
    }

    int r = 0, status;
    pid_t pid = fork();

    switch (pid) {
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
    int opt, r;
    enum bu_lock_open_type open_type = BU_LOCK_OPEN_UNSPECIFIED;
    enum bu_lock_run_mode run_mode = BU_LOCK_RUN_PIPE;
    const char *alt_config = NULL;
    const char *backup_spec = NULL;

    while ((opt = getopt(argc, argv, "C:f:m:u:sx")) != EOF) {
        switch (opt) {
        case 'C':
            alt_config = optarg;
            break;
        case 'f':
            if (open_type != BU_LOCK_OPEN_UNSPECIFIED) usage(argv[0]);
            open_type = BU_LOCK_OPEN_FILENAME;
            backup_spec = optarg;
            break;
        case 'm':
            if (open_type != BU_LOCK_OPEN_UNSPECIFIED) usage(argv[0]);
            open_type = BU_LOCK_OPEN_MBOXNAME;
            backup_spec = optarg;
            break;
        case 'u':
            if (open_type != BU_LOCK_OPEN_UNSPECIFIED) usage(argv[0]);
            open_type = BU_LOCK_OPEN_USERNAME;
            backup_spec = optarg;
            break;
        case 's':
            if (run_mode != BU_LOCK_RUN_PIPE) usage(argv[0]);
            run_mode = BU_LOCK_RUN_SQL;
            break;
        case 'x':
            if (run_mode != BU_LOCK_RUN_PIPE) usage(argv[0]);
            run_mode = BU_LOCK_RUN_EXEC;
            /* rest of argv is command for -x: don't try to process it */
            goto no_more_opts;
            break;
        }
    }

no_more_opts:
    if (open_type == BU_LOCK_OPEN_UNSPECIFIED) usage(argv[0]);
    if (backup_spec == NULL) usage(argv[0]);
    if (run_mode == BU_LOCK_RUN_EXEC && optind == argc) usage(argv[0]);

    cyrus_init(alt_config, "bu_lock", 0, 0);

    // FIXME which signals to ignore/accept?
    switch (run_mode) {
        case BU_LOCK_RUN_PIPE:
            r = run_pipe(open_type, backup_spec);
            break;
        case BU_LOCK_RUN_SQL:
            r = run_sql(open_type, backup_spec);
            break;
        case BU_LOCK_RUN_EXEC:
            r = run_exec(open_type, backup_spec, &argv[optind]);
            break;
        default:
            fprintf(stderr, "invalid run mode, how did we get here?\n");
            r = EC_SOFTWARE;
            break;
    }

    cyrus_done();
    exit(r);
}
