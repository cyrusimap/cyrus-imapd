/* ctl_backups.c -- tool for managing replication-based backup files
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

#include <assert.h>
#include <stdlib.h>

#include "lib/cyrusdb.h"
#include "lib/exitcodes.h"

#include "imap/global.h"
#include "imap/imap_err.h"

#include "backup/api.h"

EXPORTED void fatal(const char *error, int code)
{
    fprintf(stderr, "fatal error: %s\n", error);
    cyrus_done();
    exit(code);
}

static const char *argv0 = NULL;
static void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s [options] lock [lock_opts] [mode] backup\n", argv0);
    fprintf(stderr, "    %s [options] reindex [mode] backup...\n", argv0);
    fprintf(stderr, "    %s [options] verify [mode] backup...\n", argv0);

    fprintf(stderr, "\n%s\n",
            "Commands:\n"
            "    lock [lock_opts]    # lock specified backup\n"
            "    reindex             # reindex specified backups\n"
            "    verify              # verify specified backups\n"
    );

    fprintf(stderr, "%s\n",
            "Options:\n"
            "    -C alt_config       # alternate config file\n"
            "    -v                  # verbose (repeat for more verbosity)\n"
    );

    fprintf(stderr, "%s\n",
            "Lock options:\n"
            "    -p                  # lock backup and wait for eof on stdin (default)\n"
            "    -s                  # lock backup and open index in sqlite3\n"
            "    -x command          # lock backup and execute command\n"
    );

    fprintf(stderr, "%s\n",
            "Modes:\n"
            "    -A                  # all known backups\n"
//            "    -P prefix           # backups for all users starting with \"prefix\"\n"
//            "    -D domain           # backups for all users in domain\n"
            "    -f                  # specified backups interpreted as filenames\n"
            "    -m                  # specified backups interpreted as mboxnames\n"
            "    -u                  # specified backups interpreted as userids (default)\n"
            "\n"
            "    Modes -A, -P, -D not available for all commands\n" /* FIXME which */
    );

    exit(EC_USAGE);
}

enum ctlbu_mode {
    CTLBU_MODE_UNSPECIFIED = 0,
    CTLBU_MODE_FILENAME,
    CTLBU_MODE_MBOXNAME,
    CTLBU_MODE_USERNAME,
    CTLBU_MODE_ALL,
};

enum ctlbu_lock_mode {
    CTLBU_LOCK_MODE_UNSPECIFIED = 0,
    CTLBU_LOCK_MODE_PIPE,
    CTLBU_LOCK_MODE_SQL,
    CTLBU_LOCK_MODE_EXEC,
};

struct ctlbu_cmd_options {
    enum ctlbu_mode mode;
    enum ctlbu_lock_mode lock_mode;
    int verbose;
    int list_stale;
    const char *lock_exec_cmd;
};

enum ctlbu_cmd {
    CTLBU_CMD_UNSPECIFIED = 0,
    CTLBU_CMD_COMPRESS,
    CTLBU_CMD_DELETE,
    CTLBU_CMD_LIST,
    CTLBU_CMD_LOCK,
    CTLBU_CMD_MOVE,
    CTLBU_CMD_RECONSTRUCT,
    CTLBU_CMD_REINDEX,
    CTLBU_CMD_VERIFY,
};

/* same signature as foreach_cb */
static int cmd_compress_one(void *rock,
                            const char *userid, size_t userid_len,
                            const char *fname, size_t fname_len);
static int cmd_delete_one(void *rock,
                          const char *userid, size_t userid_len,
                          const char *fname, size_t fname_len);
static int cmd_list_one(void *rock,
                        const char *userid, size_t userid_len,
                        const char *fname, size_t fname_len);
static int cmd_lock_one(void *rock,
                        const char *userid, size_t userid_len,
                        const char *fname, size_t fname_len);
static int cmd_move_one(void *rock,
                        const char *userid, size_t userid_len,
                        const char *fname, size_t fname_len);
static int cmd_reindex_one(void *rock,
                           const char *userid, size_t userid_len,
                           const char *fname, size_t fname_len);
static int cmd_verify_one(void *rock,
                          const char *userid, size_t userid_len,
                          const char *fname, size_t fname_len);

static foreach_cb *const cmd_func[] = {
    NULL,
    cmd_compress_one,
    cmd_delete_one,
    cmd_list_one,
    cmd_lock_one,
    cmd_move_one,
    NULL, /* reconstruct one doesn't make sense */
    cmd_reindex_one,
    cmd_verify_one,
};

static enum ctlbu_cmd parse_cmd_string(const char *cmd)
{
    assert(cmd != NULL);

    switch(cmd[0]) {
    case 'c':
        if (strcmp(cmd, "compress") == 0) return CTLBU_CMD_COMPRESS;
        break;
    case 'd':
        if (strcmp(cmd, "delete") == 0) return CTLBU_CMD_DELETE;
        break;
    case 'l':
        if (strcmp(cmd, "list") == 0) return CTLBU_CMD_LIST;
        if (strcmp(cmd, "lock") == 0) return CTLBU_CMD_LOCK;
        break;
    case 'm':
        if (strcmp(cmd, "move") == 0) return CTLBU_CMD_MOVE;
        break;
    case 'r':
        if (strcmp(cmd, "reconstruct") == 0) return CTLBU_CMD_RECONSTRUCT;
        if (strcmp(cmd, "reindex") == 0) return CTLBU_CMD_REINDEX;
        break;
    case 'v':
        if (strcmp(cmd, "verify") == 0) return CTLBU_CMD_VERIFY;
        break;
    };

    return CTLBU_CMD_UNSPECIFIED;
}

static void save_argv0(const char *s)
{
    const char *slash = strrchr(s, '/');
    if (slash)
        argv0 = slash + 1;
    else
        argv0 = s;
}

int main (int argc, char **argv)
{
    save_argv0(argv[0]);

    int opt;
    const char *alt_config = NULL;
    enum ctlbu_cmd cmd = CTLBU_CMD_UNSPECIFIED;
    struct ctlbu_cmd_options options = {0};

    while ((opt = getopt(argc, argv, ":AC:fmpst:x:uv")) != EOF) {
        switch (opt) {
        case 'A':
            if (options.mode != CTLBU_MODE_UNSPECIFIED) usage();
            options.mode = CTLBU_MODE_ALL;
            break;
        case 'C':
            alt_config = optarg;
            break;
        case 'f':
            if (options.mode != CTLBU_MODE_UNSPECIFIED) usage();
            options.mode = CTLBU_MODE_FILENAME;
            break;
        case 'm':
            if (options.mode != CTLBU_MODE_UNSPECIFIED) usage();
            options.mode = CTLBU_MODE_MBOXNAME;
            break;
        case 'p':
            if (options.lock_mode != CTLBU_LOCK_MODE_UNSPECIFIED) usage();
            options.lock_mode = CTLBU_LOCK_MODE_PIPE;
            break;
        case 's':
            if (options.lock_mode != CTLBU_LOCK_MODE_UNSPECIFIED) usage();
            options.lock_mode = CTLBU_LOCK_MODE_SQL;
            break;
        case 't':
            options.list_stale = atoi(optarg);
            if (!options.list_stale) usage();
            break;
        case 'u':
            if (options.mode != CTLBU_MODE_UNSPECIFIED) usage();
            options.mode = CTLBU_MODE_USERNAME;
            break;
        case 'v':
            options.verbose ++;
            break;
        case 'x':
            if (options.lock_mode != CTLBU_LOCK_MODE_UNSPECIFIED) usage();
            options.lock_mode = CTLBU_LOCK_MODE_EXEC;
            options.lock_exec_cmd = optarg;
            break;
        case ':':
            if (optopt == 't') options.list_stale = 24;
            else usage();
            break;
        default:
            usage();
            break;
        }
    }

    /* get the command */
    if (optind == argc) usage();
    cmd = parse_cmd_string(argv[optind++]);
    if (cmd == CTLBU_CMD_UNSPECIFIED) usage();

    if (options.lock_mode != CTLBU_LOCK_MODE_UNSPECIFIED
        && cmd != CTLBU_CMD_LOCK)
        usage();

    switch (cmd) {
    /* list defaults to all */
    case CTLBU_CMD_LIST:
        if (options.mode == CTLBU_MODE_UNSPECIFIED && argc - optind == 0)
            options.mode = CTLBU_MODE_ALL;
        break;

    /* some commands only accept one backup at a time */
    case CTLBU_CMD_LOCK:
    case CTLBU_CMD_MOVE:
    case CTLBU_CMD_DELETE:
        if (options.mode == CTLBU_MODE_ALL) usage();
        if (argc - optind > 1) usage();
        break;

    /* reconstruct doesn't accept named backups */
    case CTLBU_CMD_RECONSTRUCT:
        if (options.mode != CTLBU_MODE_UNSPECIFIED) usage();
        if (optind != argc) usage();
        break;

    default:
        break;
    }

    /* default mode is username */
    if (options.mode == CTLBU_MODE_UNSPECIFIED)
        options.mode = CTLBU_MODE_USERNAME;

    /* mode all doesn't want any named backups */
    if (options.mode == CTLBU_MODE_ALL && optind != argc) usage();

    cyrus_init(alt_config, "ctl_backups", 0, 0);

    if (cmd == CTLBU_CMD_RECONSTRUCT) {
        /* special handling for reconstruct */
        // FIXME
    }
    else if (options.mode == CTLBU_MODE_ALL) {
        // FIXME dedup this or make it api
        // FIXME transactionality
        // FIXME error checking
        char *backups_db_fname = xstrdup(config_getstring(IMAPOPT_BACKUPS_DB_PATH));
        if (!backups_db_fname)
            backups_db_fname = strconcat(config_dir, "/backups.db", NULL);

        struct db *backups_db = NULL;
        struct txn *tid = NULL;

        int r = cyrusdb_open(config_backups_db, backups_db_fname, CYRUSDB_CREATE,
                            &backups_db);

        if (!r)
            r = cyrusdb_foreach(backups_db, NULL, 0, NULL,
                                cmd_func[cmd], &options,
                                &tid);

        if (backups_db) {
            if (tid) cyrusdb_abort(backups_db, tid);
            cyrusdb_close(backups_db);
        }
        free(backups_db_fname);
    }
    else {
        /* loop over backups named on command line */
        struct buf userid = BUF_INITIALIZER;
        struct buf fname = BUF_INITIALIZER;
        int i;

        for (i = optind; i < argc; i++) {
            buf_reset(&userid);
            buf_reset(&fname);
            mbname_t *mbname = NULL;

            // FIXME error checking in here

            if (options.mode == CTLBU_MODE_USERNAME)
                mbname = mbname_from_userid(argv[i]);
            else if (options.mode == CTLBU_MODE_MBOXNAME)
                mbname = mbname_from_intname(argv[i]);

            if (mbname) {
                backup_get_paths(mbname, &fname, NULL);
                buf_setcstr(&userid, mbname_userid(mbname));
            }
            else
                buf_setcstr(&fname, argv[i]);

            if (cmd_func[cmd])
                cmd_func[cmd](&options,
                              buf_cstring(&userid),
                              buf_len(&userid),
                              buf_cstring(&fname),
                              buf_len(&fname));

            if (mbname) mbname_free(&mbname);
        }

        buf_free(&userid);
        buf_free(&fname);
    }

    cyrus_done();
    exit(0);
}

static int cmd_compress_one(void *rock,
                            const char *userid, size_t userid_len,
                            const char *fname, size_t fname_len)
{
    struct ctlbu_cmd_options *options = (struct ctlbu_cmd_options *) rock;
    (void) options;
    fprintf(stderr, "unimplemented: %s %s[%zu] %s[%zu]\n", __func__,
            userid, userid_len, fname, fname_len);
    return -1;
}

static int cmd_delete_one(void *rock,
                          const char *userid, size_t userid_len,
                          const char *fname, size_t fname_len)
{
    struct ctlbu_cmd_options *options = (struct ctlbu_cmd_options *) rock;
    (void) options;
    fprintf(stderr, "unimplemented: %s %s[%zu] %s[%zu]\n", __func__,
            userid, userid_len, fname, fname_len);
    return -1;
}

static int cmd_list_one(void *rock,
                        const char *userid, size_t userid_len,
                        const char *fname, size_t fname_len)
{
    struct ctlbu_cmd_options *options = (struct ctlbu_cmd_options *) rock;
    (void) options;
    fprintf(stderr, "unimplemented: %s %s[%zu] %s[%zu]\n", __func__,
            userid, userid_len, fname, fname_len);
    return -1;
}

static int lock_run_pipe(const char *userid, const char *fname)
{
    printf("* Trying to obtain lock on %s...\n", userid ? userid : fname);

    struct backup *backup = NULL;
    int r;

    r = backup_open_paths(&backup, fname, NULL, BACKUP_OPEN_NONBLOCK);

    if (r) {
        printf("NO failed\n");
        return EC_SOFTWARE; // FIXME would something else be more appropriate?
    }

    printf("OK locked\n");

    /* wait until stdin closes */
    char buf[PROT_BUFSIZE] = {0};
    while (!feof(stdin))
        fgets(buf, sizeof(buf), stdin);

    r = backup_close(&backup);
    if (r) fprintf(stderr, "warning: backup_close() returned %i\n", r);

    return 0;
}

static int lock_run_sqlite(const char *userid, const char *fname)
{
    fprintf(stderr, "trying to obtain lock on %s...\n", userid ? userid : fname);

    struct backup *backup = NULL;
    const char *index_fname = NULL;
    int r, status;
    pid_t pid;

    r = backup_open_paths(&backup, fname, NULL, BACKUP_OPEN_NONBLOCK);

    if (r) {
        fprintf(stderr, "unable to lock %s: %s\n",
                userid ? userid : fname,
                error_message(r));
        return EC_SOFTWARE;
    }

    index_fname = backup_get_index_fname(backup);

    /* FIXME probably need to do something with signals here */

    pid = fork();

    switch (pid) {
    case -1:
        perror("fork");
        r = EC_SOFTWARE;
        break;

    case 0:
        /* child */
        fprintf(stderr, "execlp: %s %s\n", "sqlite3", index_fname);
        execlp("sqlite3", "sqlite3", index_fname, NULL);
        /* execlp never returns */
        perror("execlp sqlite3");
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

static int lock_run_exec(const char *userid, const char *fname, const char *cmd)
{
    fprintf(stderr, "trying to obtain lock on %s...\n", userid ? userid : fname);

    struct backup *backup = NULL;
    int r;

    r = backup_open_paths(&backup, fname, NULL, BACKUP_OPEN_NONBLOCK);

    if (r) {
        fprintf(stderr, "unable to lock %s: %s\n",
                userid ? userid : fname,
                error_message(r));
        return EC_SOFTWARE;
    }

    r = system(cmd);

    if (r == -1)
        r = EC_SOFTWARE;
    else if (WIFEXITED(r))
        r = WEXITSTATUS(r);
    else
        r = EC_SOFTWARE;

    backup_close(&backup);
    return r;
}

static int cmd_lock_one(void *rock,
                        const char *key, size_t key_len,
                        const char *data, size_t data_len)
{
    struct ctlbu_cmd_options *options = (struct ctlbu_cmd_options *) rock;
    char *userid = NULL;
    char *fname = NULL;
    int r;

    /* input args might not be 0-terminated, so make a safe copy */
    if (key_len)
        userid = xstrndup(key, key_len);
    if (data_len)
        fname = xstrndup(data, data_len);

    switch (options->lock_mode) {
    case CTLBU_LOCK_MODE_UNSPECIFIED:
    case CTLBU_LOCK_MODE_PIPE:
        r = lock_run_pipe(userid, fname);
        break;
    case CTLBU_LOCK_MODE_SQL:
        r = lock_run_sqlite(userid, fname);
        break;
    case CTLBU_LOCK_MODE_EXEC:
        r = lock_run_exec(userid, fname, options->lock_exec_cmd);
        break;
    }

    if (userid) free(userid);
    if (fname) free(fname);

    return r;
}

static int cmd_move_one(void *rock,
                        const char *userid, size_t userid_len,
                        const char *fname, size_t fname_len)
{
    struct ctlbu_cmd_options *options = (struct ctlbu_cmd_options *) rock;
    (void) options;
    fprintf(stderr, "unimplemented: %s %s[%zu] %s[%zu]\n", __func__,
            userid, userid_len, fname, fname_len);
    return -1;
}

static int cmd_reindex_one(void *rock,
                           const char *key, size_t key_len,
                           const char *data, size_t data_len)
{
    struct ctlbu_cmd_options *options = (struct ctlbu_cmd_options *) rock;
    char *userid = NULL;
    char *fname = NULL;
    int r;

    (void) options;

    /* input args might not be 0-terminated, so make a safe copy */
    if (key_len)
        userid = xstrndup(key, key_len);
    if (data_len)
        fname = xstrndup(data, data_len);

    r = backup_reindex(fname, options->verbose, stdout);

    printf("reindex %s: %s\n",
           userid ? userid : fname,
           r ? "failed" : "ok");

    if (userid) free(userid);
    if (fname) free(fname);

    return r;
}

static int cmd_verify_one(void *rock,
                          const char *key, size_t key_len,
                          const char *data, size_t data_len)
{
    struct ctlbu_cmd_options *options = (struct ctlbu_cmd_options *) rock;
    struct backup *backup = NULL;
    char *userid = NULL;
    char *fname = NULL;
    int r;

    (void) options;  // not currently using this

    /* input args might not be 0-terminated, so make a safe copy */
    if (key_len)
        userid = xstrndup(key, key_len);
    if (data_len)
        fname = xstrndup(data, data_len);

    r = backup_open_paths(&backup, fname, NULL, BACKUP_OPEN_NONBLOCK);

    if (r == IMAP_MAILBOX_LOCKED) {
        printf("verify %s: locked\n", userid ? userid : fname);
        r = 0;
        goto done;
    }
    else if (r) {
        fprintf(stderr, "error opening %s: %s\n", fname, error_message(r));
    }

    if (!r) r = backup_verify(backup, BACKUP_VERIFY_FULL, options->verbose, stdout);

    printf("verify %s: %s\n",
           userid ? userid : fname,
           r ? "failed" : "ok");

done:
    if (userid) free(userid);
    if (fname) free(fname);

    return r;
}
