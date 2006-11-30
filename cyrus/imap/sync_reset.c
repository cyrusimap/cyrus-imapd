/* sync_reset.c -- Remove a user account from a replica system
 *
 * Copyright (c) 1998-2005 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 * $Id: sync_reset.c,v 1.2 2006/11/30 17:11:20 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>
#include <ctype.h>
#include <sys/resource.h>

#include "global.h"
#include "assert.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imparse.h"
#include "util.h"
#include "xmalloc.h"
#include "retry.h"
#include "imapd.h"
#include "user.h"
#include "sync_support.h"
#include "sync_commit.h"
/*#include "cdb.h"*/

/* global state */
const int config_need_data = 0;

/* Stuff to make index.c link */
int imapd_exists;
struct protstream *imapd_out = NULL;
struct auth_state *imapd_authstate = NULL;
char *imapd_userid = NULL;

void printastring(const char *s)
{
    fatal("not implemented", EC_SOFTWARE);
}

void printstring(const char *s)
{
    fatal("not implemented", EC_SOFTWARE);
}

/* end stuff to make index.c link */

/* ====================================================================== */

/* Static global variables and support routines for sync_server */

extern char *optarg;
extern int optind;

static struct namespace sync_namespace;
static struct namespace *sync_namespacep = &sync_namespace;
static struct auth_state *sync_authstate = NULL;
static char *sync_userid = NULL;

static int verbose = 0;

static void shut_down(int code) __attribute__((noreturn));
static void shut_down(int code)
{
    if (sync_userid)    free(sync_userid);
    if (sync_authstate) auth_freestate(sync_authstate);

    seen_done();

    quotadb_close();
    quotadb_done();

    mboxlist_close();
    mboxlist_done();
    exit(code);
}

static int usage(const char *name)
{
    fprintf(stderr,
            "usage: %s [-C <alt_config>] [-v] [-f] user...\n", name);
 
    exit(EC_USAGE);
}

void fatal(const char* s, int code)
{
    fprintf(stderr, "sync_server: %s\n", s);
    exit(code);
}

/* ====================================================================== */

static int
user_master_is_local(char *user)
{
    int rc = 0;
#if 0 /* XXX make sure we're not the replica */
    const char *filename;
    unsigned long len;
    int fd;

    filename = config_getstring(IMAPOPT_SYNC_MASTER_MAP);

    if ((fd = open(filename, O_RDONLY)) < 0)
        return(0);  /* Couldn't open  */

    rc = cdb_seek(fd, (unsigned char *)user, strlen(user), &len);
    close(fd);
#endif
    /* rc: -1 => error, 0 => lookup failed, 1 => lookup suceeded */
    return(rc == 1);  
}


/* ====================================================================== */

static int
addmbox_full(char *name,
             int matchlen __attribute__((unused)),
             int maycreate __attribute__((unused)),
             void *rock)
{
    struct sync_folder_list *list = (struct sync_folder_list *) rock;

    /* List all mailboxes, including directories and deleted items */

    sync_folder_list_add(list, name, name, NULL, 0, NULL);
    return(0);
}

static int
addmbox_sub(char *name,
            int matchlen __attribute__((unused)),
            int maycreate __attribute__((unused)),
            void *rock)
{
    struct sync_folder_list *list = (struct sync_folder_list *) rock;

    sync_folder_list_add(list, name, name, NULL, 0, NULL);
    return(0);
}

/* ====================================================================== */

static int
reset_single(struct sync_lock *lock, char *user)
{
    struct sync_folder_list *list = NULL;
    struct sync_folder *item;
    char buf[MAX_MAILBOX_NAME+1];
    int r = 0;
    static int md5_dir_set     = 0;
    static const char *md5_dir = NULL;

    if (!md5_dir_set) {
        md5_dir = config_getstring(IMAPOPT_MD5_DIR);
        md5_dir_set = 1;
    }

    if (verbose > 1)
        fprintf(stderr, "   RESET %s\n", user);

    if (user_master_is_local(user)) {
        fprintf(stderr, "Attempt to update master for %s\n", user);
        return(IMAP_INVALID_USER);
    }

    if ((r = sync_lock(lock))) {
        fprintf(stderr, "Failed to lock: %s\n", error_message(r));
        return(r);
    }
    if (sync_userid)    free(sync_userid);
    if (sync_authstate) auth_freestate(sync_authstate);

    sync_userid    = xstrdup(user);
    sync_authstate = auth_newstate(sync_userid);

    /* Nuke subscriptions */
    list = sync_folder_list_create();
    snprintf(buf, sizeof(buf)-1, "user.%s.*", user);
    r = (sync_namespacep->mboxlist_findsub)(sync_namespacep, buf, 0,
                                            user, sync_authstate, addmbox_sub,
                                            (void *)list, 0);
    if (r) goto fail;

    for (item = list->head ; item ; item = item->next) {
        r = mboxlist_changesub(item->name, sync_userid, sync_authstate, 0, 0);
        if (r) goto fail;
    }
    sync_folder_list_free(&list);
#if 0
    /* Nuke DELETED folders */
    list = sync_folder_list_create();

    snprintf(buf, sizeof(buf)-1, "user.%s.^DELETED.*", user);
    r = (sync_namespacep->mboxlist_findall)(sync_namespacep, buf, 0,
                                           user, sync_authstate, addmbox_full,
                                           (void *)list);
    if (r) goto fail;

    for (item = list->head ; item ; item = item->next) {
        r=mboxlist_deletemailbox(item->name, 1, NULL, sync_authstate, 1, 0, 0);

        if (r) goto fail;
    }
    sync_folder_list_free(&list);
#endif
    /* Nuke normal folders */
    list = sync_folder_list_create();

    snprintf(buf, sizeof(buf)-1, "user.%s.*", user);
    r = (sync_namespacep->mboxlist_findall)(sync_namespacep, buf, 0,
                                           user, sync_authstate, addmbox_full,
                                           (void *)list);
    if (r) goto fail;

    for (item = list->head ; item ; item = item->next) {
        r=mboxlist_deletemailbox(item->name, 1, NULL, sync_authstate, 1, 0, 0);

        if (r) goto fail;
    }
    sync_folder_list_free(&list);

    /* Nuke inbox (recursive nuke possible?) */
    snprintf(buf, sizeof(buf)-1, "user.%s", user);
    r = mboxlist_deletemailbox(buf, 1, "cyrus", sync_authstate, 1, 0, 0);
    if (r && (r != IMAP_MAILBOX_NONEXISTENT)) goto fail;

    if ((r=user_deletedata(user, sync_userid, sync_authstate, 1)))
        goto fail;

    /* Nuke md5 database entry (not the end of the world if it fails) */
    if (md5_dir) {
        snprintf(buf, sizeof(buf)-1, "%s/%c/%s", md5_dir, user[0], user);
        unlink(buf);
    }

    sync_unlock(lock);

    return(0);

 fail:
    sync_unlock(lock);
    if (list)
        sync_folder_list_free(&list);
    fprintf(stderr, "Failed to reset account %s: %s\n",
            sync_userid, error_message(r));

    return(r);
}

/* ====================================================================== */

int
main(int argc, char **argv)
{
    int   opt;
    char *alt_config = NULL;
    int r = 0;
    int force = 0;
    struct sync_lock lock;
    int i;

    sync_lock_reset(&lock);

    if(geteuid() == 0)
        fatal("must run as the Cyrus user", EC_USAGE);

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:vf")) != EOF) {
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

        default:
            usage("sync_reset");
        }
    }

    /* Set up default bounds if no command line options provided */

    cyrus_init(alt_config, "sync_reset", 0);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(sync_namespacep, 1)) != 0) {
        fatal(error_message(r), EC_CONFIG);
    }

    /* open the mboxlist and quotadb, we'll need them for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);

    quotadb_init(0);
    quotadb_open(NULL);

    mailbox_initialize();

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    if (!force) {
        fprintf(stderr, "Usage: sync_reset -f user user user ...\n");
        fprintf(stderr, "         -f [force] is obligitory for safety\n");
        shut_down(0);
    }

    for (i = optind; i < argc; i++) {
        if (reset_single(&lock, argv[i])) {
            fprintf(stderr, "Bailing out!\n");
            break;
        }
    }

    shut_down(0);
}
