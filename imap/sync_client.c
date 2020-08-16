/* sync_client.c -- Cyrus synchronization client
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
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sysexits.h>
#include <syslog.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>

#include <netinet/tcp.h>

#include "global.h"
#include "append.h"
#include "mboxlist.h"
#include "mailbox.h"
#include "quota.h"
#include "xmalloc.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imapd.h"
#include "imap_proxy.h"
#include "util.h"
#include "prot.h"
#include "message_guid.h"
#include "sync_log.h"
#include "sync_support.h"
#include "cyr_lock.h"
#include "backend.h"
#include "xstrlcat.h"
#include "signals.h"
#include "cyrusdb.h"
#include "hash.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* ====================================================================== */

/* Static global variables and support routines for sync_client */

extern char *optarg;
extern int optind;

static const char *servername = NULL;
static struct backend *sync_backend = NULL;
static struct protstream *sync_out = NULL;
static struct protstream *sync_in = NULL;
static struct buf tagbuf = BUF_INITIALIZER;

static struct namespace   sync_namespace;

static unsigned flags      = 0;
static int verbose         = 0;
static int verbose_logging = 0;
static int connect_once    = 0;
static int background      = 0;
static int do_compress     = 0;
static int no_copyback     = 0;

static char *prev_userid;

static void shut_down(int code) __attribute__((noreturn));
static void shut_down(int code)
{
    in_shutdown = 1;

    seen_done();
    cyrus_done();
    exit(code);
}

static int usage(const char *name, const char *message)
{
    if (message)
        fprintf(stderr, "%s\n\n", message);
    fprintf(stderr,
            "Usage: %s -S <servername> [-C <alt_config>] [-r] [-v] mailbox...\n", name);

    exit(EX_USAGE);
}

EXPORTED void fatal(const char *s, int code)
{
    fprintf(stderr, "Fatal error: %s\n", s);
    syslog(LOG_ERR, "Fatal error: %s", s);
    exit(code);
}

#define report_verbose(...) do {                            \
    if (verbose) printf(__VA_ARGS__);                       \
    if (verbose_logging) syslog(LOG_INFO, __VA_ARGS__);     \
} while(0)

/* ====================================================================== */

static int do_unuser(const char *userid)
{
    const char *cmd = "UNUSER";
    struct mailbox *mailbox = NULL;
    struct dlist *kl;
    int r;

    /* nothing to do if there's no userid */
    if (!userid || !userid[0]) {
        syslog(LOG_WARNING, "ignoring attempt to %s() without userid", __func__);
        return 0;
    }

    /* check local mailbox first */
    char *inbox = mboxname_user_mbox(userid, NULL);
    r = mailbox_open_irl(inbox, &mailbox);

    /* only remove from server if there's no local mailbox */
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        kl = dlist_setatom(NULL, cmd, userid);
        sync_send_apply(kl, sync_out);
        dlist_free(&kl);

        r = sync_parse_response(cmd, sync_in, NULL);
        if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
    }

    mailbox_close(&mailbox);
    free(inbox);

    return r;
}

/* ====================================================================== */

static int user_sub(const char *userid, const char *mboxname)
{
    int r;

    r = mboxlist_checksub(mboxname, userid);

    switch (r) {
    case CYRUSDB_OK:
        return sync_set_sub(userid, mboxname, 1, sync_backend, flags);
    case CYRUSDB_NOTFOUND:
        return sync_set_sub(userid, mboxname, 0, sync_backend, flags);
    default:
        return r;
    }
}

/* ====================================================================== */

static int do_unmailbox(const char *mboxname, struct backend *sync_be,
                        unsigned flags)
{
    struct mailbox *mailbox = NULL;
    int r;

    r = mailbox_open_irl(mboxname, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* make sure there's an explicit local tombstone */
        mbentry_t *tombstone = NULL;
        r = mboxlist_lookup_allow_all(mboxname, &tombstone, NULL);
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            // otherwise we don't change anything on the replica
            syslog(LOG_NOTICE, "SYNCNOTICE: attempt to UNMAILBOX without a tombstone %s", mboxname);
            r = 0;
            goto skip;
        }
        if (r) {
            syslog(LOG_ERR, "%s: mboxlist_lookup() failed: %s '%s'",
                            __func__, mboxname, error_message(r));
        }
        else if ((tombstone->mbtype & MBTYPE_DELETED) == 0) {
            syslog(LOG_ERR, "attempt to UNMAILBOX non-tombstone: \"%s\"",
                            mboxname);
        }
        else {
            r = sync_folder_delete(mboxname, sync_be, flags);
            if (r) {
                syslog(LOG_ERR, "%s: sync_folder_delete(): failed: %s '%s'",
                                __func__, mboxname, error_message(r));
            }
        }
        skip:
        mboxlist_entry_free(&tombstone);
    }
    mailbox_close(&mailbox);

    return r;
}

/* ====================================================================== */

static void remove_meta(char *user, struct sync_action_list *list)
{
    struct sync_action *action;

    for (action = list->head ; action ; action = action->next) {
        if (!strcmp(user, action->user)) {
            action->active = 0;
        }
    }
}

/* ====================================================================== */

static int do_sync_mailboxes(struct sync_name_list *mboxname_list,
                             struct sync_action_list *user_list,
                             const char **channelp,
                             unsigned flags)
{
    struct sync_name *mbox;
    int r = 0;

    if (mboxname_list->count) {
        r = sync_do_mailboxes(mboxname_list, NULL, sync_backend, channelp, flags);
        if (channelp && r == IMAP_MAILBOX_LOCKED) {
            for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
                if (mbox->mark) continue;
                sync_log_channel_mailbox(*channelp, mbox->name);
                report_verbose("  Deferred: MAILBOX %s\n", mbox->name);
            }
            r = 0;
        }
        else if (r) {
            /* promote failed personal mailboxes to USER */
            int nonuser = 0;

            for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
                /* done OK?  Good :) */
                if (mbox->mark)
                    continue;

                char *userid = mboxname_to_userid(mbox->name);
                if (userid) {
                    mbox->mark = 1;

                    sync_action_list_add(user_list, NULL, userid);
                    report_verbose("  Promoting: MAILBOX %s -> USER %s\n",
                                   mbox->name, userid);
                    free(userid);
                }
                else
                    nonuser = 1; /* there was a non-user mailbox */
            }
            if (!nonuser) r = 0;
        }
    }

    return r;
}

static int do_restart()
{
    sync_send_restart(sync_out);

    return sync_parse_response("RESTART", sync_in, NULL);
}

struct split_user_mailboxes_rock {
    struct sync_name_list *mboxname_list;
    struct sync_action_list *user_list;
    char **channelp;
    unsigned flags;
    int r;
};

static void split_user_mailboxes(const char *key __attribute__((unused)),
                                 void *data,
                                 void *rock)
{
    struct split_user_mailboxes_rock *smrock =
        (struct split_user_mailboxes_rock *) rock;
    struct sync_action_list *mailbox_list = (struct sync_action_list *) data;
    struct sync_action *action;

    for (action = mailbox_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        sync_name_list_add(smrock->mboxname_list, action->name);
    }

    if (smrock->mboxname_list->count >= 1000) {
        syslog(LOG_NOTICE, "sync_mailboxes: doing %lu",
                           smrock->mboxname_list->count);
        smrock->r = do_sync_mailboxes(smrock->mboxname_list, smrock->user_list,
                              (const char **) smrock->channelp, smrock->flags);
        if (smrock->r) return;
        smrock->r = do_restart();
        if (smrock->r) return;
        sync_name_list_free(&smrock->mboxname_list);
        smrock->mboxname_list = sync_name_list_create();
    }
}

/* need this lil wrapper for free_hash_table callback */
static void sync_action_list_free_wrapper(void *p)
{
    struct sync_action_list *l = (struct sync_action_list *) p;
    sync_action_list_free(&l);
}

/*
 *   channelp = NULL    => we're not processing a channel
 *   *channelp = NULL   => we're processing the default channel
 *   *channelp = "foo"  => we're processing the channel named "foo"
 */
static int do_sync(sync_log_reader_t *slr, const char **channelp)
{
    struct sync_action_list *user_list = sync_action_list_create();
    struct sync_action_list *unuser_list = sync_action_list_create();
    struct sync_action_list *meta_list = sync_action_list_create();
    struct sync_action_list *unmailbox_list = sync_action_list_create();
    struct sync_action_list *quota_list = sync_action_list_create();
    struct sync_action_list *annot_list = sync_action_list_create();
    struct sync_action_list *seen_list = sync_action_list_create();
    struct sync_action_list *sub_list = sync_action_list_create();
    hash_table user_mailboxes = HASH_TABLE_INITIALIZER;
    const char *args[3];
    struct sync_action *action;
    int r = 0;

    construct_hash_table(&user_mailboxes, 1024 /* XXX */, 0);

    while (sync_log_reader_getitem(slr, args) != EOF) {
        if (!strcmp(args[0], "USER"))
            sync_action_list_add(user_list, NULL, args[1]);
        else if (!strcmp(args[0], "UNUSER"))
            sync_action_list_add(unuser_list, NULL, args[1]);
        else if (!strcmp(args[0], "META"))
            sync_action_list_add(meta_list, NULL, args[1]);
        else if (!strcmp(args[0], "SIEVE"))
            sync_action_list_add(meta_list, NULL, args[1]);
        else if ((!strcmp(args[0], "APPEND")) /* just a mailbox event */
                 || (!strcmp(args[0], "MAILBOX"))) {
            char *freeme = NULL;
            const char *userid;
            struct sync_action_list *mailbox_list;

            userid = freeme = mboxname_to_userid(args[1]);
            if (!userid) userid = ""; /* treat non-user mboxes as a single cohort */

            mailbox_list = hash_lookup(userid, &user_mailboxes);
            if (!mailbox_list) {
                mailbox_list = sync_action_list_create();
                hash_insert(userid, mailbox_list, &user_mailboxes);
            }
            sync_action_list_add(mailbox_list, args[1], NULL);
            free(freeme);
        }
        else if (!strcmp(args[0], "RENAME")) {
            char *freeme1 = NULL, *freeme2 = NULL;
            const char *userid1, *userid2;
            struct sync_action_list *mailbox_list;

            userid1 = freeme1 = mboxname_to_userid(args[1]);
            if (!userid1) userid1 = "";
            userid2 = freeme2 = mboxname_to_userid(args[2]);
            if (!userid2) userid2 = "";

            /* add both mboxnames to the list for the first one's user */
            mailbox_list = hash_lookup(userid1, &user_mailboxes);
            if (!mailbox_list) {
                mailbox_list = sync_action_list_create();
                hash_insert(userid1, mailbox_list, &user_mailboxes);
            }
            sync_action_list_add(mailbox_list, args[1], NULL);
            sync_action_list_add(mailbox_list, args[2], NULL);

            /* if the second mboxname's user is different, add both names there too */
            if (strcmp(userid1, userid2) != 0) {
                mailbox_list = hash_lookup(userid2, &user_mailboxes);
                if (!mailbox_list) {
                    mailbox_list = sync_action_list_create();
                    hash_insert(userid2, mailbox_list, &user_mailboxes);
                }
                sync_action_list_add(mailbox_list, args[1], NULL);
                sync_action_list_add(mailbox_list, args[2], NULL);
            }

            free(freeme1);
            free(freeme2);
        }
        else if (!strcmp(args[0], "UNMAILBOX"))
            sync_action_list_add(unmailbox_list, args[1], NULL);
        else if (!strcmp(args[0], "QUOTA"))
            sync_action_list_add(quota_list, args[1], NULL);
        else if (!strcmp(args[0], "ANNOTATION"))
            sync_action_list_add(annot_list, args[1], NULL);
        else if (!strcmp(args[0], "SEEN"))
            sync_action_list_add(seen_list, args[2], args[1]);
        else if (!strcmp(args[0], "SUB"))
            sync_action_list_add(sub_list, args[2], args[1]);
        else if (!strcmp(args[0], "UNSUB"))
            sync_action_list_add(sub_list, args[2], args[1]);
        else
            syslog(LOG_ERR, "Unknown action type: %s", args[0]);
    }

    /* Optimise out redundant clauses */

    for (action = user_list->head; action; action = action->next) {
        /* remove per-user items */
        remove_meta(action->user, meta_list);
        remove_meta(action->user, seen_list);
        remove_meta(action->user, sub_list);
    }

    /* duplicate removal for unuser - we also strip all the user events */
    for (action = unuser_list->head; action; action = action->next) {
        /* remove per-user items */
        remove_meta(action->user, meta_list);
        remove_meta(action->user, seen_list);
        remove_meta(action->user, sub_list);

        /* unuser trumps user */
        remove_meta(action->user, user_list);
    }

    for (action = meta_list->head; action; action = action->next) {
        /* META action overrides any user SEEN or SUB/UNSUB action
           for same user */
        remove_meta(action->user, seen_list);
        remove_meta(action->user, sub_list);
    }

    /* And then run tasks. */

    if (hash_numrecords(&user_mailboxes)) {
        struct split_user_mailboxes_rock smrock;
        smrock.mboxname_list = sync_name_list_create();
        smrock.user_list = user_list;
        smrock.channelp = (char **) channelp; /* n.b. casting away constness bc struct */
        smrock.flags = flags;
        smrock.r = 0;

        /* process user_mailboxes in sets of ~1000, splitting only on
         * user boundaries */
        hash_enumerate(&user_mailboxes, split_user_mailboxes, &smrock);
        r = smrock.r;

        /* process any stragglers (<1000 remaining) */
        if (!r)
            r = do_sync_mailboxes(smrock.mboxname_list, user_list, channelp, flags);
        if (!r)
            r = do_restart();

        sync_name_list_free(&smrock.mboxname_list);
        if (r) goto cleanup;
    }

    for (action = quota_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        r = sync_do_quota(action->name, sync_backend, channelp, flags);
        if (channelp && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_quota(*channelp, action->name);
            report_verbose("  Deferred: QUOTA %s\n", action->name);
        }
        else if (r) {
            sync_action_list_add(user_list, action->name, NULL);
            report_verbose("  Promoting: QUOTA %s -> USER %s\n",
                           action->name, action->name);
        }
    }

    for (action = annot_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        /* NOTE: ANNOTATION "" is a special case - it's a server
         * annotation, hence the check for a character at the
         * start of the name */
        r = sync_do_annotation(action->name, sync_backend, channelp, flags);
        if (!*action->name) continue;

        if (channelp && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_annotation(*channelp, action->name);
            report_verbose("  Deferred: ANNOTATION %s\n", action->name);
        }
        else if (r) {
            sync_action_list_add(user_list, action->name, NULL);
            report_verbose("  Promoting: ANNOTATION %s -> USER %s\n",
                           action->name, action->name);
        }
    }

    for (action = seen_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        r = sync_do_seen(action->user, action->name, sync_backend, channelp, flags);
        if (channelp && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_seen(*channelp, action->user, action->name);
            report_verbose("  Deferred: SEEN %s %s\n",
                           action->user, action->name);
        }
        else if (r) {
            char *userid = mboxname_to_userid(action->name);
            if (userid && mboxname_isusermailbox(action->name, 1) && !strcmp(userid, action->user)) {
                sync_action_list_add(user_list, NULL, action->user);
                report_verbose("  Promoting: SEEN %s %s -> USER %s\n",
                               action->user, action->name, action->user);
            } else {
                sync_action_list_add(meta_list, NULL, action->user);
                report_verbose("  Promoting: SEEN %s %s -> META %s\n",
                               action->user, action->name, action->user);
            }
            free(userid);
        }
    }

    for (action = sub_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        r = user_sub(action->user, action->name);
        if (channelp && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_subscribe(*channelp, action->user, action->name);
            report_verbose("  Deferred: SUB %s %s\n",
                           action->user, action->name);
        }
        else if (r) {
            sync_action_list_add(meta_list, NULL, action->user);
            report_verbose("  Promoting: SUB %s %s -> META %s\n",
                           action->user, action->name, action->user);
        }
    }

    /* XXX - is unmailbox used much anyway - we need to see if it's logged for a rename,
     * e.g.
     * RENAME A B:
     *  MAILBOX A
     *  MAILBOX B
     *  UNMAILBOX A
     *
     * suggestion: PROMOTE ALL UNMAILBOX on user accounts to USER foo
     */
    for (action = unmailbox_list->head; action; action = action->next) {
        if (!action->active)
            continue;
        r = do_unmailbox(action->name, sync_backend, flags);
        if (channelp && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_unmailbox(*channelp, action->name);
            report_verbose("  Deferred: UNMAILBOX %s\n", action->name);
        }
        else if (r) goto cleanup;
    }

    for (action = meta_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        r = sync_do_meta(action->user, sync_backend, flags);
        if (channelp && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_sieve(*channelp, action->user);
            report_verbose("  Deferred: META %s\n", action->user);
        }
        else if (r == IMAP_INVALID_USER) {
            goto cleanup;
        }
        else if (r) {
            sync_action_list_add(user_list, NULL, action->user);
            report_verbose("  Promoting: META %s -> USER %s\n",
                           action->user, action->user);
        }
    }

    for (action = user_list->head; action; action = action->next) {
        if (!action->active)
            continue;
        r = sync_do_user(action->user, NULL, sync_backend, channelp, flags);
        if (channelp && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_user(*channelp, action->user);
            report_verbose("  Deferred: USER %s\n", action->user);
        }
        else if (r) goto cleanup;
        r = do_restart();
        if (r) goto cleanup;
    }

    for (action = unuser_list->head; action; action = action->next) {
        if (!action->active)
            continue;
        r = do_unuser(action->user);
        if (channelp && r == IMAP_MAILBOX_LOCKED) {
            sync_log_channel_unuser(*channelp, action->user);
            report_verbose("  Deferred: UNUSER %s\n", action->user);
        }
        else if (r) goto cleanup;
    }

  cleanup:
    if (r) {
        if (verbose)
            fprintf(stderr, "Error in do_sync(): bailing out! %s\n", error_message(r));

        syslog(LOG_ERR, "Error in do_sync(): bailing out! %s", error_message(r));
    }

    sync_action_list_free(&user_list);
    sync_action_list_free(&unuser_list);
    sync_action_list_free(&meta_list);
    sync_action_list_free(&unmailbox_list);
    sync_action_list_free(&quota_list);
    sync_action_list_free(&annot_list);
    sync_action_list_free(&seen_list);
    sync_action_list_free(&sub_list);
    free_hash_table(&user_mailboxes, sync_action_list_free_wrapper);

    return r;
}

static int do_sync_filename(const char *filename)
{
    sync_log_reader_t *slr;
    int r;

    if ((filename == NULL) || !strcmp(filename, "-"))
        slr = sync_log_reader_create_with_fd(0);    /* STDIN */
    else
        slr = sync_log_reader_create_with_filename(filename);

    r = sync_log_reader_begin(slr);
    if (!r)
        r = do_sync(slr, NULL);

    sync_log_reader_end(slr);
    sync_log_reader_free(slr);
    return r;
}


/* ====================================================================== */

enum {
    RESTART_NONE = 0,
    RESTART_NORMAL,
    RESTART_RECONNECT
};

static int do_daemon_work(const char *channel, const char *sync_shutdown_file,
                   unsigned long timeout, unsigned long min_delta,
                   int *restartp)
{
    int r = 0;
    time_t session_start;
    time_t single_start;
    int    delta;
    struct stat sbuf;
    sync_log_reader_t *slr;

    *restartp = RESTART_NONE;
    slr = sync_log_reader_create_with_channel(channel);

    session_start = time(NULL);

    while (1) {
        single_start = time(NULL);

        signals_poll();

        /* Check for shutdown file */
        if (sync_shutdown_file && !stat(sync_shutdown_file, &sbuf)) {
            unlink(sync_shutdown_file);
            /* Have to exit with r == 0 or do_daemon() will call us again.
             * The value of r is unknown from calls to sync_log_reader_begin() below.
             */
            r = 0;
            break;
        }

        /* See if its time to RESTART */
        if ((timeout > 0) &&
            ((single_start - session_start) > (time_t) timeout)) {
            *restartp = RESTART_NORMAL;
            break;
        }

        r = sync_log_reader_begin(slr);
        if (r) {
            /* including specifically r == IMAP_AGAIN */
            if (min_delta > 0) {
                sleep(min_delta);
            } else {
                usleep(100000);    /* 1/10th second */
            }
            continue;
        }

        /* Process the work log */
        if ((r=do_sync(slr, &channel))) {
            syslog(LOG_ERR,
                   "Processing sync log file %s failed: %s",
                   sync_log_reader_get_file_name(slr), error_message(r));
            break;
        }

        r = sync_log_reader_end(slr);
        if (r) break;

        delta = time(NULL) - single_start;

        if (((unsigned) delta < min_delta) && ((min_delta-delta) > 0))
            sleep(min_delta-delta);
    }
    sync_log_reader_free(slr);

    if (*restartp == RESTART_NORMAL) {
        r = do_restart();
        if (r) {
            syslog(LOG_ERR, "sync_client RESTART failed: %s",
                   error_message(r));
        } else {
            syslog(LOG_INFO, "sync_client RESTART succeeded");
        }
        r = 0;
    }

    return(r);
}

static void replica_connect(const char *channel)
{
    int wait;
    sasl_callback_t *cb;
    int timeout;
    const char *port, *auth_status = NULL;
    int try_imap;

    cb = mysasl_callbacks(NULL,
                          sync_get_config(channel, "sync_authname"),
                          sync_get_config(channel, "sync_realm"),
                          sync_get_config(channel, "sync_password"));

    /* get the right port */
    port = sync_get_config(channel, "sync_port");
    if (port) {
        imap_csync_protocol.service = port;
        csync_protocol.service = port;
    }

    try_imap = sync_get_switchconfig(channel, "sync_try_imap");

    for (wait = 15;; wait *= 2) {
        if (try_imap) {
            sync_backend = backend_connect(sync_backend, servername,
                                        &imap_csync_protocol, "", cb, &auth_status,
                                        (verbose > 1 ? fileno(stderr) : -1));

            if (sync_backend) {
                if (sync_backend->capability & CAPA_REPLICATION) {
                    /* attach our IMAP tag buffer to our protstreams as userdata */
                    sync_backend->in->userdata = sync_backend->out->userdata = &tagbuf;
                    break;
                }
                else {
                    backend_disconnect(sync_backend);
                    sync_backend = NULL;
                }
            }
        }

        sync_backend = backend_connect(sync_backend, servername,
                                       &csync_protocol, "", cb, NULL,
                                       (verbose > 1 ? fileno(stderr) : -1));

        if (sync_backend || auth_status || connect_once || wait > 1000) break;

        fprintf(stderr,
                "Can not connect to server '%s', retrying in %d seconds\n",
                servername, wait);
        sleep(wait);
    }

    free_callbacks(cb);
    cb = NULL;

    if (!sync_backend) {
        fprintf(stderr, "Can not connect to server '%s'\n",
                servername);
        syslog(LOG_ERR, "Can not connect to server '%s'", servername);
        _exit(1);
    }

    if (servername[0] != '/' && sync_backend->sock >= 0) {
        tcp_disable_nagle(sync_backend->sock);
        tcp_enable_keepalive(sync_backend->sock);
    }

#ifdef HAVE_ZLIB
    /* Does the backend support compression? */
    if (CAPA(sync_backend, CAPA_COMPRESS)) {
        prot_printf(sync_backend->out, "%s\r\n",
                    sync_backend->prot->u.std.compress_cmd.cmd);
        prot_flush(sync_backend->out);

        if (sync_parse_response("COMPRESS", sync_backend->in, NULL)) {
            if (do_compress) fatal("Failed to enable compression, aborting", EX_SOFTWARE);
            syslog(LOG_NOTICE, "Failed to enable compression, continuing uncompressed");
        }
        else {
            prot_setcompress(sync_backend->in);
            prot_setcompress(sync_backend->out);
        }
    }
    else if (do_compress) fatal("Backend does not support compression, aborting", EX_SOFTWARE);
#endif

    /* links to sockets */
    sync_in = sync_backend->in;
    sync_out = sync_backend->out;

    if (verbose > 1) {
        prot_setlog(sync_in, fileno(stderr));
        prot_setlog(sync_out, fileno(stderr));
    }

    /* Set inactivity timer */
    timeout = config_getduration(IMAPOPT_SYNC_TIMEOUT, 's');
    if (timeout < 3) timeout = 3;
    prot_settimeout(sync_in, timeout);

    /* Force use of LITERAL+ so we don't need two way communications */
    prot_setisclient(sync_in, 1);
    prot_setisclient(sync_out, 1);
}

static void replica_disconnect(void)
{
    backend_disconnect(sync_backend);
}

static void do_daemon(const char *channel, const char *sync_shutdown_file,
                      unsigned long timeout, unsigned long min_delta)
{
    int r = 0;
    int restart = 1;

    signal(SIGPIPE, SIG_IGN); /* don't fail on server disconnects */

    while (restart) {
        replica_connect(channel);
        r = do_daemon_work(channel, sync_shutdown_file,
                           timeout, min_delta, &restart);
        if (r) {
            /* See if we're still connected to the server.
             * If we are, we had some type of error, so we exit.
             * Otherwise, try reconnecting.
             */
            if (!backend_ping(sync_backend, NULL)) restart = 1;
        }
        replica_disconnect();
    }
}

static int do_mailbox(const char *mboxname, const char **channelp, unsigned flags)
{
    struct sync_name_list *list = sync_name_list_create();
    int r;

    sync_name_list_add(list, mboxname);

    r = sync_do_mailboxes(list, NULL, sync_backend, channelp, flags);

    sync_name_list_free(&list);

    return r;
}

static int cb_allmbox(const mbentry_t *mbentry, void *rock)
{
    int r = 0;
    const char **channelp = (const char **)rock;

    char *userid = mboxname_to_userid(mbentry->name);

    if (userid) {
        /* skip deleted mailboxes only because the are out of order, and you would
         * otherwise have to sync the user twice thanks to our naive logic */
        if (mboxname_isdeletedmailbox(mbentry->name, NULL))
            goto done;

        /* only sync if we haven't just done the user */
        if (strcmpsafe(userid, prev_userid)) {
            r = sync_do_user(userid, NULL, sync_backend, channelp, flags);
            if (r) {
                if (verbose)
                    fprintf(stderr, "Error from do_user(%s): bailing out!\n", userid);
                syslog(LOG_ERR, "Error in do_user(%s): bailing out!", userid);
                goto done;
            }
            free(prev_userid);
            prev_userid = xstrdup(userid);
        }
    }
    else {
        /* all shared mailboxes, including DELETED ones, sync alone */
        /* XXX: batch in hundreds? */
        r = do_mailbox(mbentry->name, channelp, flags);
        if (r) {
            if (verbose)
                fprintf(stderr, "Error from do_user(%s): bailing out!\n", mbentry->name);
            syslog(LOG_ERR, "Error in do_user(%s): bailing out!", mbentry->name);
            goto done;
        }
    }

done:
    free(userid);
    return r;
}

/* ====================================================================== */

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

enum {
    MODE_UNKNOWN = -1,
    MODE_REPEAT,
    MODE_USER,
    MODE_ALLUSER,
    MODE_MAILBOX,
    MODE_META
};

int main(int argc, char **argv)
{
    int   opt, i = 0;
    char *alt_config     = NULL;
    char *input_filename = NULL;
    int   r = 0;
    int   exit_rc = 0;
    int   mode = MODE_UNKNOWN;
    int   wait     = 0;
    int   timeout  = 600;
    int   min_delta = 0;
    const char *channel = NULL;
    const char *sync_shutdown_file = NULL;
    const char *partition = NULL;
    char buf[512];
    FILE *file;
    int len;
    struct sync_name_list *mboxname_list;

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:vlLS:F:f:w:t:d:n:rRumsozOAp:")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'o': /* only try to connect once */
            connect_once = 1;
            break;

        case 'v': /* verbose */
            verbose++;
            break;

        case 'l': /* verbose Logging */
            verbose_logging++;
            break;

        case 'L': /* local mailbox operations only */
            flags |= SYNC_FLAG_LOCALONLY;
            break;

        case 'S': /* Socket descriptor for server */
            servername = optarg;
            break;

        case 'F': /* Shutdown file */
            sync_shutdown_file = optarg;
            break;

        case 'f': /* input_filename used by user and mailbox modes; OR
                     alternate sync_log_file used by single-run repeat mode */
            input_filename = optarg;
            break;

        case 'n':
            channel = optarg;
            break;

        case 'w':
            wait = atoi(optarg);
            break;

        case 't':
            timeout = atoi(optarg);
            break;

        case 'd':
            min_delta = atoi(optarg);
            break;

        case 'r':
            background = 1;
            /* fallthrough */

        case 'R':
            if (mode != MODE_UNKNOWN)
                usage("sync_client", "Mutually exclusive options defined");
            mode = MODE_REPEAT;
            break;

        case 'A':
            if (mode != MODE_UNKNOWN)
                usage("sync_client", "Mutually exclusive options defined");
            mode = MODE_ALLUSER;
            break;

        case 'u':
            if (mode != MODE_UNKNOWN)
                usage("sync_client", "Mutually exclusive options defined");
            mode = MODE_USER;
            break;

        case 'm':
            if (mode != MODE_UNKNOWN)
                usage("sync_client", "Mutually exclusive options defined");
            mode = MODE_MAILBOX;
            break;

        case 's':
            if (mode != MODE_UNKNOWN)
                usage("sync_client", "Mutually exclusive options defined");
            mode = MODE_META;
            break;

        case 'z':
#ifdef HAVE_ZLIB
            do_compress = 1;
#else
            do_compress = 0;
            fatal("Compress not available without zlib compiled in", EX_SOFTWARE);
#endif
            break;

        case 'O':
            /* don't copy changes back from server */
            no_copyback = 1;
            break;

        case 'p':
            partition = optarg;
            break;

        default:
            usage("sync_client", NULL);
        }
    }

    if (mode == MODE_UNKNOWN)
        usage("sync_client", "No replication mode specified");

    if (verbose) flags |= SYNC_FLAG_VERBOSE;
    if (verbose_logging) flags |= SYNC_FLAG_LOGGING;
    if (no_copyback) flags |= SYNC_FLAG_NO_COPYBACK;

    /* fork if required */
    if (background && !input_filename && !getenv("CYRUS_ISDAEMON")) {
        int pid = fork();

        if (pid == -1) {
            perror("fork");
            exit(1);
        }

        if (pid != 0) { /* parent */
            exit(0);
        }
    }

    cyrus_init(alt_config, "sync_client",
               (verbose > 1 ? CYRUSINIT_PERROR : 0),
               CONFIG_NEED_PARTITION_DATA);

    /* get the server name if not specified */
    if (!servername)
        servername = sync_get_config(channel, "sync_host");

    if (!servername)
        fatal("sync_host not defined", EX_SOFTWARE);

    /* Just to help with debugging, so we have time to attach debugger */
    if (wait > 0) {
        fprintf(stderr, "Waiting for %d seconds for gdb attach...\n", wait);
        sleep(wait);
    }

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&sync_namespace, 1)) != 0) {
        fatal(error_message(r), EX_CONFIG);
    }
    mboxevent_setnamespace(&sync_namespace);

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    /* load the SASL plugins */
    global_sasl_init(1, 0, mysasl_cb);

    switch (mode) {
    case MODE_USER:
        /* Open up connection to server */
        replica_connect(channel);

        if (input_filename) {
            if ((file=fopen(input_filename, "r")) == NULL) {
                syslog(LOG_NOTICE, "Unable to open %s: %m", input_filename);
                shut_down(1);
            }
            while (fgets(buf, sizeof(buf), file)) {
                /* Chomp, then ignore empty/comment lines. */
                if (((len=strlen(buf)) > 0) && (buf[len-1] == '\n'))
                    buf[--len] = '\0';

                if ((len == 0) || (buf[0] == '#'))
                    continue;

                if (sync_do_user(buf, partition, sync_backend, NULL, flags)) {
                    if (verbose)
                        fprintf(stderr,
                                "Error from sync_do_user(%s): bailing out!\n",
                                buf);
                    syslog(LOG_ERR, "Error in sync_do_user(%s): bailing out!",
                           buf);
                    exit_rc = 1;
                }
            }
            fclose(file);
        } else for (i = optind; !r && i < argc; i++) {
            if (sync_do_user(argv[i], partition, sync_backend, &channel, flags)) {
                if (verbose)
                    fprintf(stderr, "Error from sync_do_user(%s): bailing out!\n",
                            argv[i]);
                syslog(LOG_ERR, "Error in sync_do_user(%s): bailing out!", argv[i]);
                exit_rc = 1;
            }
        }

        replica_disconnect();
        break;

    case MODE_ALLUSER:
        /* Open up connection to server */
        replica_connect(channel);

        if (mboxlist_allmbox(optind < argc ? argv[optind] : NULL, cb_allmbox, &channel, 0))
            exit_rc = 1;

        replica_disconnect();
        break;

    case MODE_MAILBOX:
        /* Open up connection to server */
        replica_connect(channel);

        mboxname_list = sync_name_list_create();
        if (input_filename) {
            if ((file=fopen(input_filename, "r")) == NULL) {
                syslog(LOG_NOTICE, "Unable to open %s: %m", input_filename);
                shut_down(1);
            }
            while (fgets(buf, sizeof(buf), file)) {
                /* Chomp, then ignore empty/comment lines. */
                if (((len=strlen(buf)) > 0) && (buf[len-1] == '\n'))
                    buf[--len] = '\0';

                if ((len == 0) || (buf[0] == '#'))
                    continue;

                char *intname = mboxname_from_external(buf, &sync_namespace, NULL);
                if (!sync_name_lookup(mboxname_list, intname))
                    sync_name_list_add(mboxname_list, intname);
                free(intname);
            }
            fclose(file);
        } else for (i = optind; i < argc; i++) {
            char *intname = mboxname_from_external(argv[i], &sync_namespace, NULL);
            if (!sync_name_lookup(mboxname_list, intname))
                sync_name_list_add(mboxname_list, intname);
            free(intname);
        }

        if (sync_do_mailboxes(mboxname_list, partition, sync_backend, &channel, flags)) {
            if (verbose) {
                fprintf(stderr,
                        "Error from sync_do_mailboxes(): bailing out!\n");
            }
            syslog(LOG_ERR, "Error in sync_do_mailboxes(): bailing out!");
            exit_rc = 1;
        }

        sync_name_list_free(&mboxname_list);
        replica_disconnect();
        break;

    case MODE_META:
        /* Open up connection to server */
        replica_connect(channel);

        for (i = optind; i < argc; i++) {
            if (sync_do_meta(argv[i], sync_backend, flags)) {
                if (verbose) {
                    fprintf(stderr,
                            "Error from sync_do_meta(%s): bailing out!\n",
                            argv[i]);
                }
                syslog(LOG_ERR, "Error in sync_do_meta(%s): bailing out!",
                       argv[i]);
                exit_rc = 1;
            }
        }

        replica_disconnect();

        break;

    case MODE_REPEAT:
        if (input_filename) {
            /* Open up connection to server */
            replica_connect(channel);

            exit_rc = do_sync_filename(input_filename);

            replica_disconnect();
        }
        else {
            /* rolling replication */
            if (!sync_shutdown_file)
                sync_shutdown_file = sync_get_config(channel, "sync_shutdown_file");

            if (!min_delta)
                min_delta = sync_get_durationconfig(channel, "sync_repeat_interval", 's');

            flags |= SYNC_FLAG_BATCH;

            do_daemon(channel, sync_shutdown_file, timeout, min_delta);
        }

        break;

    default:
        if (verbose) fprintf(stderr, "Nothing to do!\n");
        break;
    }

    buf_free(&tagbuf);

    shut_down(exit_rc);
}
