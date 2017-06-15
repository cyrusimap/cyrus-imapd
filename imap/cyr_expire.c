/* cyr_expire.c -- Program to expire deliver.db entries and messages
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
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include <sasl/sasl.h>

#include "annotate.h"
#include "duplicate.h"
#include "exitcodes.h"
#include "global.h"
#include "hash.h"
#include "libcyr_cfg.h"
#include "mboxevent.h"
#include "mboxlist.h"
#include "conversations.h"
#include "util.h"
#include "xmalloc.h"
#include "strarray.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define SECS_IN_A_MIN 60
#define SECS_IN_AN_HR (60 * SECS_IN_A_MIN)
#define SECS_IN_A_DAY (24 * SECS_IN_AN_HR)

/* global state */
static volatile sig_atomic_t sigquit = 0;
static int verbose = 0;
static const char *progname = NULL;
static struct namespace expire_namespace; /* current namespace */

/* command line arguments */
struct arguments {
    int archive_seconds;
    int delete_seconds;
    int expire_seconds;
    int expunge_seconds;

    /* bools */
    int do_expunge;
    int do_cid_expire;
    int do_userflags;
    int skip_annotate;

    const char *altconfig;
    const char *mbox_prefix;
    const char *userid;
};

struct expire_rock {
    struct hash_table table;
    time_t expire_mark;
    time_t expunge_mark;
    unsigned long mailboxes_seen;
    unsigned long messages_seen;
    unsigned long messages_expired;
    unsigned long messages_expunged;
    int skip_annotate;
    bit32 userflags[MAX_USER_FLAGS/32];
    int do_userflags;
    unsigned long userflags_expunged;
};

struct conversations_rock {
    struct hash_table seen;
    time_t expire_mark;
    unsigned long databases_seen;
    unsigned long msgids_seen;
    unsigned long msgids_expired;
};

struct delete_rock {
    int skip_annotate;
    time_t delete_mark;
    strarray_t to_delete;
};

/* The global context */
struct cyr_expire_ctx {
    struct conversations_rock crock;
    struct expire_rock erock;
    struct delete_rock drock;
};

struct cyr_expire_ctx ctx;

static void sighandler(int sig);

/* verbosep - a wrapper to print if the 'verbose' option is
   turned on.
 */
__attribute__((format (printf, 1, 2)))
static inline void verbosep(const char *fmt, ...)
{
    va_list params;

    if (!verbose)
        return;

    va_start(params, fmt);
    vfprintf(stderr, fmt, params);
    va_end(params);
    fputc('\n', stderr);
}

static void cyr_expire_init(const char *progname, struct arguments *args)
{
    struct sigaction action;

    /* Initialise signal handlers */
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    action.sa_handler = sighandler;
    if (sigaction(SIGQUIT, &action, NULL) < 0)
        fatal("unable to install signal handler for SIGQUIT", EC_TEMPFAIL);
    if (sigaction(SIGINT, &action, NULL) < 0)
        fatal("unable to install signal handler for SIGINT", EC_TEMPFAIL);
    if (sigaction(SIGTERM, &action, NULL) < 0)
        fatal("unable to install signal handler for SIGTERM", EC_TEMPFAIL);

    /* zero the expire_rock & delete_rock */
    memset(&ctx.erock, 0, sizeof(ctx.erock));
    construct_hash_table(&ctx.erock.table, 10000, 1);
    memset(&ctx.drock, 0, sizeof(ctx.drock));
    strarray_init(&ctx.drock.to_delete);
    memset(&ctx.crock, 0, sizeof(ctx.crock));
    construct_hash_table(&ctx.crock.seen, 100, 1);

    cyrus_init(args->altconfig, progname, 0, 0);
    global_sasl_init(1, 0, NULL);
}

static void cyr_expire_cleanup(void)
{
    free_hash_table(&ctx.erock.table, free);
    free_hash_table(&ctx.crock.seen, NULL);
    strarray_fini(&ctx.drock.to_delete);

    duplicate_done();
    sasl_done();
    cyrus_done();
}

static void set_progname(const char *str)
{
    const char *slash = strrchr(str, '/');
    if (slash)
        progname = slash + 1;
    else
        progname = str;
}

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", progname);
    fprintf(stderr, "Expire messages and duplicate delivery database entries.\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "-a                       skip annotation lookup\n");
    fprintf(stderr, "-c                       do not expire conversations\n");
    fprintf(stderr, "-h                       print this help and exit\n");
    fprintf(stderr, "-p <mailbox-prefix>      specify prefix for mailboxes\n");
    fprintf(stderr, "-t                       remove user flags which are not used\n");
    fprintf(stderr, "-u <user-id>             specify user id for mailbox lookup\n");
    fprintf(stderr, "-v                       enable verbose output\n");
    fprintf(stderr, "-x                       do not expunge messages\n");
    fprintf(stderr, "-C <config-file>         use <config-file> instead of config from imapd.conf\n");
    fprintf(stderr, "-A <archive-duration>    \n");
    fprintf(stderr, "-D <delete-duration>     \n");
    fprintf(stderr, "-E <expire-duration>     \n");
    fprintf(stderr, "-X <expunge-duration>    \n");

    exit(-1);
}

/*
 * Parse a non-negative duration string as seconds.
 *
 * Convert "23.5m" to fractional days.  Accepts the suffixes "d" (day),
 * (day), "h" (hour), "m" (minute) and "s" (second).  If no suffix, assume
 * days.
 * Returns 1 if successful and *secondsp is filled in, or 0 if the suffix
 * is unknown or on error.
 */
static int parse_duration(const char *s, int *secondsp)
{
    char *end = NULL;
    double val;
    int multiplier = SECS_IN_A_DAY; /* default is days */

    /* no negative or empty numbers please */
    if (!*s || *s == '-')
        return 0;

    val = strtod(s, &end);
    /* Allow 'd', 'h', 'm' and 's' as end, else return error. */
    if (*end) {
        if (end[1]) return 0; /* trailing extra junk */

        switch (*end) {
        case 'd':
            /* already the default */
            break;
        case 'h':
            multiplier = SECS_IN_AN_HR;
            break;
        case 'm':
            multiplier = SECS_IN_A_MIN;
            break;
        case 's':
            multiplier = 1;
            break;
        default:
            return 0;
        }
    }

    *secondsp = multiplier * val;

    return 1;
}

static int expunge_userflags(struct mailbox *mailbox, struct expire_rock *erock)
{
    unsigned int i;
    int r;

    for (i = 0; i < MAX_USER_FLAGS; i++) {
        if (erock->userflags[i/32] & 1<<(i&31))
            continue;
        if (!mailbox->flagname[i])
            continue;
        verbosep("Expunging userflag %u (%s) from %s\n",
                        i, mailbox->flagname[i], mailbox->name);
        r = mailbox_remove_user_flag(mailbox, i);
        if (r) return r;
        erock->userflags_expunged++;
    }

    return 0;
}

/*
 * mailbox_expunge() callback to *only* count userflags.
 */
static unsigned userflag_cb(struct mailbox *mailbox __attribute__((unused)),
                            const struct index_record *record,
                            void *rock)
{
    struct expire_rock *erock = (struct expire_rock *) rock;
    unsigned int i;

    /* record which user flags are set */
    for (i = 0; i < (MAX_USER_FLAGS/32); i++)
        erock->userflags[i] |= record->user_flags[i];

    return 0;   /* always keep the message */
}

static int archive(const mbentry_t *mbentry, void *rock)
{
    struct mailbox *mailbox = NULL;

    if (sigquit)
        return 1;

    if (mbentry->mbtype & MBTYPE_DELETED)
        goto done;

    if (mbentry->mbtype & MBTYPE_REMOTE)
        goto done;

    if (mailbox_open_iwl(mbentry->name, &mailbox))
        goto done;

    verbosep("archiving mailbox %s\n", mbentry->name);

    mailbox_archive(mailbox, NULL, rock, ITER_SKIP_EXPUNGED);

done:
    mailbox_close(&mailbox);

    /* move on to the next mailbox regardless of errors */
    return 0;
}

/*
 * mailbox_expunge() callback to expunge expired articles.
 */
static unsigned expire_cb(struct mailbox *mailbox __attribute__((unused)),
                          const struct index_record *record,
                          void *rock)
{
    struct expire_rock *erock = (struct expire_rock *) rock;
    unsigned int i;

    /* otherwise, we're expiring messages by sent date */
    if (record->gmtime < erock->expire_mark) {
        erock->messages_expired++;
        return 1;
    }

    /* record which user flags are set */
    for (i = 0; i < (MAX_USER_FLAGS/32); i++)
        erock->userflags[i] |= record->user_flags[i];

    return 0;
}

/*
 * callback function to:
 * - expire messages from mailboxes,
 * - build a hash table of mailboxes in which we expired messages,
 * - and perform a cleanup of expunged messages
 */
static int expire(const mbentry_t *mbentry, void *rock)
{
    struct expire_rock *erock = (struct expire_rock *) rock;
    char *buf;
    struct buf attrib = BUF_INITIALIZER;
    int r;
    struct mailbox *mailbox = NULL;
    unsigned numexpunged = 0;
    int expire_seconds = 0;
    int did_expunge = 0;

    if (sigquit) {
        /* don't care if we leak some memory, we are shutting down */
        return 1;
    }

    /* Skip remote mailboxes */
    if (mbentry->mbtype & MBTYPE_REMOTE)
        goto done;

    /* clean up deleted entries after 7 days */
    if (mbentry->mbtype & MBTYPE_DELETED) {
        if (time(0) - mbentry->mtime > SECS_IN_A_DAY*7) {
            verbosep("Removing stale tombstone for %s\n", mbentry->name);
            syslog(LOG_NOTICE, "Removing stale tombstone for %s", mbentry->name);
            mboxlist_delete(mbentry->name);
        }
        goto done;
    }

    buf = xstrdup(mbentry->name);

    /* see if we need to expire messages.
     * since mailboxes inherit /vendor/cmu/cyrus-imapd/expire,
     * we need to iterate all the way up to "" (server entry)
     */
    if (!erock->skip_annotate) {
        do {
            buf_free(&attrib);
            r = annotatemore_lookup(buf, IMAP_ANNOT_NS "expire", "",
                                    &attrib);

            if (r ||                            /* error */
                attrib.s)                       /* found an entry */
                break;

        } while (mboxname_make_parent(buf));
    }
    free(buf);

    memset(erock->userflags, 0, sizeof(erock->userflags));

    r = mailbox_open_iwl(mbentry->name, &mailbox);
    if (r) {
        /* mailbox corrupt/nonexistent -- skip it */
        syslog(LOG_WARNING, "unable to open mailbox %s: %s",
               mbentry->name, error_message(r));
        goto done;
    }

    if (attrib.s && parse_duration(attrib.s, &expire_seconds)) {
        /* add mailbox to table */
        erock->expire_mark = expire_seconds ?
                             time(0) - expire_seconds : 0 /* never */ ;
        hash_insert(mbentry->name,
                    xmemdup(&erock->expire_mark, sizeof(erock->expire_mark)),
                    &erock->table);

        if (expire_seconds) {
            verbosep("expiring messages in %s older than %0.2f days\n",
                           mbentry->name,
                           ((double)expire_seconds/SECS_IN_A_DAY));

            r = mailbox_expunge(mailbox, expire_cb, erock, NULL,
                                EVENT_MESSAGE_EXPIRE);
            if (r)
                syslog(LOG_ERR, "failed to expire old messages: %s", mbentry->name);
            did_expunge = 1;
        }
    }
    buf_free(&attrib);

    if (!did_expunge && erock->do_userflags) {
        r = mailbox_expunge(mailbox, userflag_cb, erock, NULL,
                            EVENT_MESSAGE_EXPIRE);
        if (r)
            syslog(LOG_ERR, "failed to scan user flags for %s: %s",
                   mbentry->name, error_message(r));
    }

    erock->messages_seen += mailbox->i.num_records;

    if (erock->do_userflags)
        expunge_userflags(mailbox, erock);

    verbosep("cleaning up expunged messages in %s\n",
                    mbentry->name);

    r = mailbox_expunge_cleanup(mailbox, erock->expunge_mark, &numexpunged);

    erock->messages_expunged += numexpunged;
    erock->mailboxes_seen++;

    if (r) {
        syslog(LOG_WARNING, "failure expiring %s: %s", mbentry->name, error_message(r));
        annotate_state_abort(&mailbox->annot_state);
    }

done:
    mailbox_close(&mailbox);
    /* Even if we had a problem with one mailbox, continue with the others */
    return 0;
}

static int delete(const mbentry_t *mbentry, void *rock)
{
    struct delete_rock *drock = (struct delete_rock *) rock;
    time_t timestamp;

    if (sigquit)
        return 1;

    if (mbentry->mbtype & MBTYPE_DELETED)
        goto done;

    if (mbentry->mbtype & MBTYPE_REMOTE)
        goto done;

    /* check if this is a mailbox we want to examine */
    if (!mboxname_isdeletedmailbox(mbentry->name, &timestamp))
        goto done;

    if ((timestamp == 0) || (timestamp > drock->delete_mark))
        goto done;

    verbosep("Cleaning up %s\n", mbentry->name);

    /* Add this mailbox to list of mailboxes to delete */
    strarray_append(&drock->to_delete, mbentry->name);

done:
    /* Even if we had a problem with one mailbox, continue with the others */
    return 0;
}

static int expire_conversations(const mbentry_t *mbentry, void *rock)
{
    struct conversations_rock *crock = (struct conversations_rock *)rock;
    struct conversations_state *state = NULL;
    unsigned int nseen = 0, ndeleted = 0;
    char *filename = NULL;

    if (sigquit)
        return 1;

    if (mbentry->mbtype & MBTYPE_DELETED)
        goto done;

    if (mbentry->mbtype & MBTYPE_REMOTE)
        goto done;

    filename = conversations_getmboxpath(mbentry->name);
    if (!filename)
        goto done;

    if (hash_lookup(filename, &crock->seen))
        goto done;

    verbosep("Pruning conversations from db %s\n", filename);

    if (!conversations_open_mbox(mbentry->name, &state)) {
        conversations_prune(state, crock->expire_mark, &nseen, &ndeleted);
        conversations_commit(&state);
    }

    hash_insert(filename, (void *)1, &crock->seen);

    crock->databases_seen++;
    crock->msgids_seen += nseen;
    crock->msgids_expired += ndeleted;

done:
    free(filename);
    return 0;
}

static void sighandler(int sig __attribute((unused)))
{
    sigquit = 1;
    return;
}

static int parse_args(int argc, char *argv[], struct arguments *args)
{
    extern char *optarg;
    int opt;

    memset(args, 0, sizeof(*args));
    args->archive_seconds = -1;
    args->delete_seconds = -1;
    args->expire_seconds = -1;
    args->expunge_seconds = -1;
    args->do_expunge = 1;
    /* do_cid_expire defaults to whatever IMAP options are set */
    args->do_cid_expire = config_getswitch(IMAPOPT_CONVERSATIONS);

    while ((opt = getopt(argc, argv, "C:D:E:X:A:p:u:vaxtch")) != EOF) {
        switch (opt) {
        case 'A':
            if (!parse_duration(optarg, &args->archive_seconds)) usage();
            break;

        case 'C':
            args->altconfig = optarg;
            break;

        case 'D':
            if (!parse_duration(optarg, &args->delete_seconds))
                usage();
            break;

        case 'E':
            if (!parse_duration(optarg, &args->expire_seconds))
                usage();
            break;

        case 'X':
            if (!parse_duration(optarg, &args->expunge_seconds))
                usage();
            break;

        case 'a':
            args->skip_annotate = 1;
            break;

        case 'c':
            args->do_cid_expire = 0;
            break;

        case 'p':
            args->mbox_prefix = optarg;
            break;

        case 't':
            args->do_userflags = 1;
            break;

        case 'u':
            args->userid = optarg;
            break;

        case 'v':
            verbose++;
            break;

        case 'x':
            args->do_expunge = 0;
            break;

        case 'h':
        default:
            usage();
            break;
        }
    }

    if (args->archive_seconds == -1 &&
        args->delete_seconds  == -1 &&
        args->expire_seconds  == -1 &&
        args->expunge_seconds == -1 &&
        !args->do_userflags) {
        /* TODO: Print a more useful error message here. */
        fprintf(stderr, "Missing arguments.\n");
        usage();
        return -EINVAL;
    }


    return 0;
}

int main(int argc, char *argv[])
{
    int r = 0;
    struct arguments args;

    set_progname(argv[0]);

    if ((geteuid()) == 0 && (become_cyrus(/*is_master*/0) != 0)) {
        fatal("must run as the Cyrus user", EC_USAGE);
    }

    if (parse_args(argc, argv, &args) != 0)
        exit(EXIT_FAILURE);

    cyr_expire_init(progname, &args);

    ctx.erock.do_userflags = args.do_userflags;
    ctx.erock.skip_annotate = args.skip_annotate;
    ctx.drock.skip_annotate = args.skip_annotate;

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&expire_namespace, 1)) != 0) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EC_CONFIG);
    }

    mboxevent_setnamespace(&expire_namespace);

    if (duplicate_init(NULL) != 0) {
        fprintf(stderr,
                "cyr_expire: unable to init duplicate delivery database\n");
        exit(1);
    }

    if (args.archive_seconds >= 0) {
        time_t archive_mark = time(0) - args.archive_seconds;
        /* XXX - add syslog? */
        if (args.userid)
            mboxlist_usermboxtree(args.userid, archive, &archive_mark, MBOXTREE_DELETED);
        else
            mboxlist_allmbox(args.mbox_prefix, archive, &archive_mark, 0);
    }

    if (args.do_expunge && (args.expunge_seconds >= 0 || args.expire_seconds || ctx.erock.do_userflags)) {
        /* xxx better way to determine a size for this table? */

        /* expire messages from mailboxes,
         * build a hash table of mailboxes in which we expired messages,
         * and perform a cleanup of expunged messages
         */
        if (args.expunge_seconds < 0) {
            ctx.erock.expunge_mark = 0;
        } else {
            ctx.erock.expunge_mark = time(0) - args.expunge_seconds;

            verbosep("Expunging deleted messages in mailboxes older than %0.2f days\n",
                           ((double)args.expunge_seconds/SECS_IN_A_DAY));
        }

        if (args.userid)
            mboxlist_usermboxtree(args.userid, expire, &ctx.erock, MBOXTREE_DELETED);
        else
            mboxlist_allmbox(args.mbox_prefix, expire, &ctx.erock, 0);

        syslog(LOG_NOTICE, "Expired %lu and expunged %lu out of %lu "
                            "messages from %lu mailboxes",
                           ctx.erock.messages_expired,
                           ctx.erock.messages_expunged,
                           ctx.erock.messages_seen,
                           ctx.erock.mailboxes_seen);
        verbosep("\nExpired %lu and expunged %lu out of %lu "
                       "messages from %lu mailboxes\n",
                       ctx.erock.messages_expired,
                       ctx.erock.messages_expunged,
                       ctx.erock.messages_seen,
                       ctx.erock.mailboxes_seen);

        if (ctx.erock.do_userflags) {
            syslog(LOG_NOTICE, "Expunged %lu user flags",
                           ctx.erock.userflags_expunged);
            verbosep("Expunged %lu user flags\n",
                           ctx.erock.userflags_expunged);
        }
    }

    if (sigquit)
        goto finish;

    if (args.do_cid_expire) {
        int cid_expire_seconds;

        cid_expire_seconds = config_getint(IMAPOPT_CONVERSATIONS_EXPIRE_DAYS) * SECS_IN_A_DAY;
        ctx.crock.expire_mark = time(0) - cid_expire_seconds;

        verbosep("Removing conversation entries older than %0.2f days\n",
                       (double)(cid_expire_seconds/SECS_IN_A_DAY));

        if (args.userid)
            mboxlist_usermboxtree(args.userid, expire_conversations, &ctx.crock, MBOXTREE_DELETED);
        else
            mboxlist_allmbox(args.mbox_prefix, expire_conversations, &ctx.crock, 0);

        syslog(LOG_NOTICE, "Expired %lu entries of %lu entries seen "
                            "in %lu conversation databases",
                            ctx.crock.msgids_expired,
                            ctx.crock.msgids_seen,
                            ctx.crock.databases_seen);
        verbosep("Expired %lu entries of %lu entries seen "
                       "in %lu conversation databases\n",
                       ctx.crock.msgids_expired,
                       ctx.crock.msgids_seen,
                       ctx.crock.databases_seen);
    }

    if (sigquit)
        goto finish;

    if ((args.delete_seconds >= 0) && mboxlist_delayed_delete_isenabled() &&
        config_getstring(IMAPOPT_DELETEDPREFIX)) {
        int count = 0;
        int i;

        verbosep("Removing deleted mailboxes older than %0.2f days\n",
                       ((double)args.delete_seconds/SECS_IN_A_DAY));

        ctx.drock.delete_mark = time(0) - args.delete_seconds;

        if (args.userid)
            mboxlist_usermboxtree(args.userid, delete, &ctx.drock, MBOXTREE_DELETED);
        else
            mboxlist_allmbox(args.mbox_prefix, delete, &ctx.drock, 0);

        for (i = 0 ; i < ctx.drock.to_delete.count ; i++) {
            char *name = ctx.drock.to_delete.data[i];

            if (sigquit)
                goto finish;

            verbosep("Removing: %s\n", name);

            r = mboxlist_deletemailbox(name, 1, NULL, NULL, NULL, 0, 0, 0);
            count++;
        }

        verbosep("Removed %d deleted mailboxes\n", count);

        syslog(LOG_NOTICE, "Removed %d deleted mailboxes", count);
    }

    if (sigquit)
        goto finish;

    /* purge deliver.db entries of expired messages */
    if (args.expire_seconds > 0)
        r = duplicate_prune(args.expire_seconds, &ctx.erock.table);

 finish:
    cyr_expire_cleanup();
    exit(r);
}
