/* cyr_backup.c -- tool for examining replication-based backup files
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
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
#include <sys/stat.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/cyrusdb.h"
#include "lib/exitcodes.h"
#include "lib/strarray.h"

#include "imap/global.h"
#include "imap/imap_err.h"

#include "backup/backup.h"

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
    // FIXME
    exit(EC_USAGE);
}

static void save_argv0(const char *s)
{
    const char *slash = strrchr(s, '/');
    if (slash)
        argv0 = slash + 1;
    else
        argv0 = s;
}

enum cyrbu_mode {
    CYRBU_MODE_UNSPECIFIED = 0,
    CYRBU_MODE_FILENAME,
    CYRBU_MODE_MBOXNAME,
    CYRBU_MODE_USERNAME,
};

struct cyrbu_cmd_options {
    strarray_t *argv;
    int verbose;
};

typedef int cyrbu_cmd_func(struct backup *,
                           const struct cyrbu_cmd_options *);

static int cmd_list_all(struct backup *backup,
                        const struct cyrbu_cmd_options *options);
static int cmd_list_chunks(struct backup *backup,
                           const struct cyrbu_cmd_options *options);
static int cmd_list_mailboxes(struct backup *backup,
                              const struct cyrbu_cmd_options *options);
static int cmd_list_messages(struct backup *backup,
                             const struct cyrbu_cmd_options *options);
static int cmd_show_chunks(struct backup *backup,
                           const struct cyrbu_cmd_options *options);
static int cmd_show_mailboxes(struct backup *backup,
                              const struct cyrbu_cmd_options *options);
static int cmd_show_messages(struct backup *backup,
                             const struct cyrbu_cmd_options *options);
static int cmd_dump_chunk(struct backup *backup,
                          const struct cyrbu_cmd_options *options);
static int cmd_dump_mailbox(struct backup *backup,
                            const struct cyrbu_cmd_options *options);
static int cmd_dump_message(struct backup *backup,
                            const struct cyrbu_cmd_options *options);

enum cyrbu_cmd {
    CYRBU_CMD_UNSPECIFIED = 0,
    CYRBU_CMD_LIST_ALL,
    CYRBU_CMD_LIST_CHUNKS,
    CYRBU_CMD_LIST_MAILBOXES,
    CYRBU_CMD_LIST_MESSAGES,
    CYRBU_CMD_SHOW_CHUNKS,
    CYRBU_CMD_SHOW_MAILBOXES,
    CYRBU_CMD_SHOW_MESSAGES,
    CYRBU_CMD_DUMP_CHUNK,
    CYRBU_CMD_DUMP_MAILBOX,
    CYRBU_CMD_DUMP_MESSAGE,
};

static cyrbu_cmd_func *const cmd_func[] = {
    NULL,
    cmd_list_all,
    cmd_list_chunks,
    cmd_list_mailboxes,
    cmd_list_messages,
    cmd_show_chunks,
    cmd_show_mailboxes,
    cmd_show_messages,
    cmd_dump_chunk,
    cmd_dump_mailbox,
    cmd_dump_message,
};

static enum cyrbu_cmd parse_cmd_string(const char *command, const char *sub)
{
    switch (command[0]) {
    case 'd':
        if (strcmp(command, "dump") == 0) {
            if (strcmp(sub, "chunk") == 0) return CYRBU_CMD_DUMP_CHUNK;
            else if (strcmp(sub, "mailbox") == 0) return CYRBU_CMD_DUMP_MAILBOX;
            else if (strcmp(sub, "message") == 0) return CYRBU_CMD_DUMP_MESSAGE;
        }
        break;
    case 'l':
        if (strcmp(command, "list") == 0) {
            if (strcmp(sub, "all") == 0) return CYRBU_CMD_LIST_ALL;
            else if (strcmp(sub, "chunks") == 0) return CYRBU_CMD_LIST_CHUNKS;
            else if (strcmp(sub, "mailboxes") == 0) return CYRBU_CMD_LIST_MAILBOXES;
            else if (strcmp(sub, "messages") == 0) return CYRBU_CMD_LIST_MESSAGES;
        }
        break;
    case 's':
        if (strcmp(command, "show") == 0) {
            if (strcmp(sub, "chunks") == 0) return CYRBU_CMD_SHOW_CHUNKS;
            else if (strcmp(sub, "mailboxes") == 0) return CYRBU_CMD_SHOW_MAILBOXES;
            else if (strcmp(sub, "messages") == 0) return CYRBU_CMD_SHOW_MESSAGES;
        }
        break;
    default:
        break;
    }

    return CYRBU_CMD_UNSPECIFIED;
}

int main(int argc, char **argv)
{
    save_argv0(argv[0]);

    struct cyrbu_cmd_options options = {0};
    enum cyrbu_mode mode = CYRBU_MODE_UNSPECIFIED;
    enum cyrbu_cmd cmd = CYRBU_CMD_UNSPECIFIED;
    const char *alt_config = NULL;
    const char *backup_name = NULL;
    const char *command = NULL;
    const char *subcommand = NULL;
    struct backup *backup = NULL;
    mbname_t *mbname = NULL;
    int i, opt, r = 0;

    while ((opt = getopt(argc, argv, "C:fmuv")) != EOF) {
        switch (opt) {
        case 'C':
            alt_config = optarg;
            break;
        case 'f':
            if (mode != CYRBU_MODE_UNSPECIFIED) usage();
            mode = CYRBU_MODE_FILENAME;
            break;
        case 'm':
            if (mode != CYRBU_MODE_UNSPECIFIED) usage();
            mode = CYRBU_MODE_MBOXNAME;
            break;
        case 'u':
            if (mode != CYRBU_MODE_UNSPECIFIED) usage();
            mode = CYRBU_MODE_USERNAME;
            break;
        case 'v':
            options.verbose++;
            break;
        default:
            usage();
            break;
        }
    }

    /* default mode is username */
    if (mode == CYRBU_MODE_UNSPECIFIED)
        mode = CYRBU_MODE_USERNAME;

    /* get the backup name */
    if (optind == argc) usage();
    backup_name = argv[optind++];

    /* get the command */
    if (optind == argc) usage();
    command = argv[optind++];

    /* get the subcommand */
    if (optind == argc) usage();
    subcommand = argv[optind++];

    /* parse the command and subcommand */
    cmd = parse_cmd_string(command, subcommand);

    /* check remaining arguments based on command */
    switch (cmd) {
    case CYRBU_CMD_LIST_ALL:
    case CYRBU_CMD_LIST_CHUNKS:
    case CYRBU_CMD_LIST_MAILBOXES:
    case CYRBU_CMD_LIST_MESSAGES:
        /* these want no more arguments */
        if (optind != argc) usage();
        break;
    case CYRBU_CMD_SHOW_CHUNKS:
    case CYRBU_CMD_SHOW_MAILBOXES:
    case CYRBU_CMD_SHOW_MESSAGES:
        /* these need at least one more argument */
        if (optind == argc) usage();
        break;
    case CYRBU_CMD_DUMP_CHUNK:
    case CYRBU_CMD_DUMP_MAILBOX:
    case CYRBU_CMD_DUMP_MESSAGE:
        /* these need exactly one more argument */
        if (argc - optind != 1) usage();
        break;
    default:
        usage();
        break;
    }

    /* build a nice args list */
    options.argv = strarray_new();
    for (i = optind; i < argc; i++) {
        strarray_add(options.argv, argv[i]);
    }

    // FIXME finish parsing options

    cyrus_init(alt_config, "cyr_backup", 0, 0);

    /* open backup */
    switch (mode) {
    case CYRBU_MODE_FILENAME:
        r = backup_open_paths(&backup, backup_name, NULL,
                              BACKUP_OPEN_NONBLOCK, BACKUP_OPEN_NOCREATE);
        break;
    case CYRBU_MODE_MBOXNAME:
        mbname = mbname_from_intname(backup_name);
        if (!mbname) usage();
        r = backup_open(&backup, mbname,
                        BACKUP_OPEN_NONBLOCK, BACKUP_OPEN_NOCREATE);
        break;
    case CYRBU_MODE_USERNAME:
        mbname = mbname_from_userid(backup_name);
        if (!mbname) usage();
        r = backup_open(&backup, mbname,
                        BACKUP_OPEN_NONBLOCK, BACKUP_OPEN_NOCREATE);
        break;
    default:
        usage();
        break;
    }

    /* run command */
    if (!r && cmd_func[cmd])
        r = cmd_func[cmd](backup, &options);

    if (r)
        fprintf(stderr, "%s: %s\n", backup_name, error_message(r));

    /* close backup */
    if (backup)
        backup_close(&backup);

    /* clean up and exit */
    backup_cleanup_staging_path();
    cyrus_done();

    strarray_free(options.argv);
    exit(r ? EC_TEMPFAIL : EC_OK);
}

static int cmd_list_all(struct backup *backup,
                        const struct cyrbu_cmd_options *options)
{
    fprintf(stderr, "listing chunks:\n");
    cmd_list_chunks(backup, options);

    fprintf(stderr, "\nlisting mailboxes:\n");
    cmd_list_mailboxes(backup, options);

    fprintf(stderr, "\nlisting messages:\n");
    cmd_list_messages(backup, options);

    return 0;
}

static int cmd_list_chunks(struct backup *backup,
                           const struct cyrbu_cmd_options *options)
{
    struct backup_chunk_list *chunk_list = NULL;
    struct backup_chunk *chunk;

    (void) options;

    chunk_list = backup_get_chunks(backup);
    if (!chunk_list) return -1;

    // FIXME dedup this with lcb_printinfo.c:detail_full()
    fprintf(stdout, "     id offset\tlength\tratio%%\tstart time           end time\n");
    for (chunk = chunk_list->head; chunk; chunk = chunk->next) {
        char ts_start[32] = "[unknown]";
        char ts_end[32] = "[unknown]";
        double ratio;

        strftime(ts_start, sizeof(ts_start), "%F %T",
                localtime(&chunk->ts_start));
        strftime(ts_end, sizeof(ts_end), "%F %T",
                localtime(&chunk->ts_end));

        if (chunk->next) {
            ratio = 100.0 * (chunk->next->offset - chunk->offset) / chunk->length;
        }
        else {
            // FIXME need to stat the underlying file to see disk size of last chunk
            ratio = 0.0;
        }

        fprintf(stdout, "%7d " OFF_T_FMT "\t" SIZE_T_FMT "\t%6.1f\t%s  %s\n",
                        chunk->id,
                        chunk->offset,
                        chunk->length,
                        ratio,
                        ts_start,
                        ts_end);
    }

    backup_chunk_list_free(&chunk_list);
    return 0;
}

static int cmd_list_mailboxes(struct backup *backup,
                              const struct cyrbu_cmd_options *options)
{
    // FIXME
    (void) backup;
    (void) options;
    fprintf(stderr, "%s: unimplemented\n", __func__);
    return -1;
}

static int cmd_list_messages(struct backup *backup,
                             const struct cyrbu_cmd_options *options)
{
    // FIXME
    (void) backup;
    (void) options;
    fprintf(stderr, "%s: unimplemented\n", __func__);
    return -1;
}

static int cmd_show_chunks(struct backup *backup,
                           const struct cyrbu_cmd_options *options)
{
    // FIXME
    (void) backup;
    (void) options;
    fprintf(stderr, "%s: unimplemented\n", __func__);
    return -1;
}

static int cmd_show_mailboxes(struct backup *backup,
                              const struct cyrbu_cmd_options *options)
{
    // FIXME
    (void) backup;
    (void) options;
    fprintf(stderr, "%s: unimplemented\n", __func__);
    return -1;
}

static int cmd_show_messages(struct backup *backup,
                             const struct cyrbu_cmd_options *options)
{
    // FIXME
    (void) backup;
    (void) options;
    fprintf(stderr, "%s: unimplemented\n", __func__);
    return -1;
}

static int cmd_dump_chunk(struct backup *backup,
                          const struct cyrbu_cmd_options *options)
{
    // FIXME
    (void) backup;
    (void) options;
    fprintf(stderr, "%s: unimplemented\n", __func__);
    return -1;
}

static int cmd_dump_mailbox(struct backup *backup,
                            const struct cyrbu_cmd_options *options)
{
    // FIXME
    (void) backup;
    (void) options;
    fprintf(stderr, "%s: unimplemented\n", __func__);
    return -1;
}

static int cmd_dump_message(struct backup *backup,
                            const struct cyrbu_cmd_options *options)
{
    // FIXME
    (void) backup;
    (void) options;
    fprintf(stderr, "%s: unimplemented\n", __func__);
    return -1;
}
