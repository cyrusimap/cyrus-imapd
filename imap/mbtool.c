/* mbtool.c - tool to fiddle mailboxes
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "assert.h"
#include "index.h"
#include "global.h"
#include "mailbox.h"
#include "message.h"
#include "message_guid.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "seen.h"
#include "times.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

extern int optind;
extern char *optarg;

/* current namespace */
static struct namespace mbtool_namespace;

/* forward declarations */
static int do_cmd(struct findall_data *data, void *rock);

static void usage(void);
void shut_down(int code);

enum {
    CMD_TIME = 1,
    CMD_REID = 2,
};

int main(int argc, char **argv)
{
    int opt, i, r;
    int cmd = 0;
    char *alt_config = NULL;

    while ((opt = getopt(argc, argv, "C:rt")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'r':
            if (cmd == 0) cmd = CMD_REID;
            else usage();
            break;
        case 't':
            if (cmd == 0) cmd = CMD_TIME;
            else usage();
            break;

        default:
            usage();
        }
    }

    /* must provide a command */
    if (!cmd) usage();

    /* must provide some mailboxes */
    if (optind == argc) usage();

    cyrus_init(alt_config, "mbtool", 0, 0);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&mbtool_namespace, 1)) != 0) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EX_CONFIG);
    }

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    for (i = optind; i < argc; i++) {
        mboxlist_findall(&mbtool_namespace, argv[i], 1, 0, 0, do_cmd, &cmd);
    }

    exit(0);
}

static void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    mbtool [options] {-r|-t} mailbox...\n");
    fprintf(stderr, "\nCommands:\n");
    fprintf(stderr, "    -r    create new unique IDs for specified mailboxes\n");
    fprintf(stderr, "    -t    normalise internaldates in specified mailboxes\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "    -C alt_config  use alternate imapd.conf file\n");
    exit(EX_USAGE);
}

/*
 * mboxlist_findall() callback function to examine a mailbox
 */
static int do_timestamp(const mbname_t *mbname)
{
    int r = 0;
    struct mailbox *mailbox = NULL;
    char olddate[RFC5322_DATETIME_MAX+1];
    char newdate[RFC5322_DATETIME_MAX+1];
    const char *extname;
    const char *name;
    struct mailbox_iter *iter;
    const message_t *msg;

    signals_poll();

    /* Convert internal name to external */
    extname = mbname_extname(mbname, &mbtool_namespace, "cyrus");
    printf("Working on %s...\n", extname);

    name = mbname_intname(mbname);

    /* Open/lock header */
    r = mailbox_open_iwl(name, &mailbox);
    if (r) return r;

    iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
	struct index_record copyrecord;

        /* 1 day is close enough */
        if (labs(record->internaldate - record->gmtime) < 86400)
            continue;

        copyrecord = *record;

        time_to_rfc5322(copyrecord.internaldate, olddate, sizeof(olddate));
        time_to_rfc5322(copyrecord.gmtime, newdate, sizeof(newdate));
        printf("  %u: %s => %s\n", copyrecord.uid, olddate, newdate);

        /* switch internaldate */
        copyrecord.internaldate = copyrecord.gmtime;

        r = mailbox_rewrite_index_record(mailbox, &copyrecord);
        if (r) goto done;
    }

 done:
    mailbox_iter_done(&iter);
    mailbox_close(&mailbox);

    return r;
}

static int do_reid(const mbname_t *mbname)
{
    int r = 0;
    struct mailbox *mailbox = NULL;
    mbentry_t *mbentry = NULL;
    const char *name;

    /* Convert internal name to external */
    const char *extname = mbname_extname(mbname, &mbtool_namespace, "cyrus");
    printf("Working on %s...\n", extname);

    name = mbname_intname(mbname);

    r = mailbox_open_iwl(name, &mailbox);
    if (r) return r;

    mailbox_make_uniqueid(mailbox);

    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) return r;

    free(mbentry->uniqueid);
    mbentry->uniqueid = xstrdup(mailbox->uniqueid);

    mboxlist_update(mbentry, 0);

    mailbox_close(&mailbox);

    /* printf("did reid %s\n", mboxname); */
    return r;
}


int do_cmd(struct findall_data *data, void *rock)
{
    int *valp = (int *)rock;

    if (!data) return 0;
    if (!data->is_exactmatch) return 0;

    if (*valp == CMD_TIME)
        return do_timestamp(data->mbname);

    if (*valp == CMD_REID)
        return do_reid(data->mbname);

    return 0;
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    in_shutdown = 1;

    mboxlist_close();
    mboxlist_done();
    exit(code);
}
