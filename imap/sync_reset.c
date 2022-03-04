/* sync_reset.c -- Remove a user account from a replica system
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
 *
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sysexits.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include "global.h"
#include "mboxlist.h"
#include "mailbox.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "proc.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "imapd.h"
#include "user.h"
#include "sync_support.h"
/*#include "cdb.h"*/

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* Static global variables and support routines for sync_reset */

extern char *optarg;
extern int optind;

static struct namespace sync_namespace;
static struct namespace *sync_namespacep = &sync_namespace;
static struct auth_state *sync_authstate = NULL;
static char *sync_userid = NULL;

static int verbose = 0;
static int local_only = 0;

static void shut_down(int code) __attribute__((noreturn));
static void shut_down(int code)
{
    in_shutdown = 1;

    libcyrus_run_delayed();

    if (sync_userid)    free(sync_userid);
    if (sync_authstate) auth_freestate(sync_authstate);

    seen_done();

    cyrus_done();

    exit(code);
}

static int usage(const char *name)
{
    fprintf(stderr,
            "usage: %s [-C <alt_config>] [-v] [-f] user...\n", name);

    exit(EX_USAGE);
}

EXPORTED void fatal(const char* s, int code)
{
    fprintf(stderr, "sync_reset: %s\n", s);
    exit(code);
}

/* ====================================================================== */

static int reset_single(const char *userid)
{
    int r = 0;
    int i;
    struct mboxlock *namespacelock = user_namespacelock(userid);

    /* XXX: adding an entry to userdeny_db here would avoid the need to
     * protect against new logins with external proxy rules - Cyrus could
     * maintain its own safety */

    /* first, disconnect all current connections for this user */
    proc_killuser(userid);

    strarray_t *sublist = mboxlist_sublist(userid);
    strarray_t *mblist = strarray_new();

    /* ignore failures here - the subs file gets deleted soon anyway */
    for (i = sublist->count; i; i--) {
        const char *name = strarray_nth(sublist, i-1);
        (void)mboxlist_changesub(name, userid, sync_authstate, 0, 0, 0);
    }

    mbentry_t *mbentry = NULL;
    char *inbox = mboxname_user_mbox(userid, 0);
    r = mboxlist_lookup_allow_all(inbox, &mbentry, NULL);
    free(inbox);
    if (r) goto fail;

    r = mboxlist_usermboxtree(userid, NULL, addmbox_cb, mblist, MBOXTREE_DELETED);
    if (r) goto fail;

    for (i = mblist->count; i; i--) {
        const char *name = strarray_nth(mblist, i-1);
        r = mboxlist_deletemailbox(name, 1, sync_userid, sync_authstate, NULL,
                MBOXLIST_DELETE_LOCALONLY|MBOXLIST_DELETE_FORCE);
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            printf("skipping already removed mailbox %s\n", name);
        }
        else if (r) goto fail;
        /* XXX - cheap and nasty hack around actually cleaning up the entry */
        r = mboxlist_deleteremote(name, NULL);
        if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
        if (r) goto fail;
    }

    if (mbentry) r = user_deletedata(mbentry, 1);

 fail:
    mboxname_release(&namespacelock);
    mboxlist_entry_free(&mbentry);
    strarray_free(mblist);
    strarray_free(sublist);

    return r;
}

/* ====================================================================== */

int
main(int argc, char **argv)
{
    int   opt;
    char *alt_config = NULL;
    int r = 0;
    int force = 0;
    int i;

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:vfL")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'v': /* verbose */
            verbose++;
            break;

        case 'f': /* force: confirm option */
            force++;
            break;

        case 'L': /* local mailbox operations only */
            local_only++;
            break;

        default:
            usage("sync_reset");
        }
    }

    /* Set up default bounds if no command line options provided */

    cyrus_init(alt_config, "sync_reset", 0, CONFIG_NEED_PARTITION_DATA);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(sync_namespacep, 1)) != 0) {
        fatal(error_message(r), EX_CONFIG);
    }

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    if (!force) {
        fprintf(stderr, "Usage: sync_reset -f user user user ...\n");
        fprintf(stderr, "         -f [force] is obligatory for safety\n");
        shut_down(0);
    }

    for (i = optind; i < argc; i++) {
        if (reset_single(argv[i])) {
            fprintf(stderr, "Bailing out!\n");
            break;
        }
    }

    libcyrus_run_delayed();

    shut_down(0);
}
