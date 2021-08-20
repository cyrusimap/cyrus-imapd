/* cyr_expire.c -- Program to expire deliver.db entries and messages
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
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

/*
  NOTES:
  * Precedence of configuration in `cyr_expire`:
     Highest                       Lowest
     |----------------------------------|
     Annotation -> Command-line -> Config
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
#include <sysexits.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <libgen.h>

#include <sasl/sasl.h>

#include "annotate.h"
#include "duplicate.h"
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

    int do_cid_expire;

    /* bools */
    bool do_expunge;
    bool do_userflags;
    bool skip_annotate;

    const char *altconfig;
    const char *mbox_prefix;
    const char *userid;

    char *freeme; /* for mbox_prefix */
};

struct archive_rock {
    time_t archive_mark;
    unsigned long messages_archived;
    bool skip_annotate;
};

struct expire_rock {
    struct hash_table table;
    time_t expire_mark;
    time_t expunge_mark;
    time_t tombstone_mark;
    unsigned long mailboxes_seen;
    unsigned long messages_seen;
    unsigned long messages_expired;
    unsigned long messages_expunged;
    unsigned long userflags_expunged;
    bit32 userflags[MAX_USER_FLAGS/32];
    bool do_userflags;
    bool skip_annotate;
};

struct conversations_rock {
    struct hash_table seen;
    time_t expire_mark;
    unsigned long databases_seen;
    unsigned long msgids_seen;
    unsigned long msgids_expired;
};

struct delete_rock {
    time_t delete_mark;
    strarray_t to_delete;
    bool skip_annotate;
};

/* The global context */
struct cyr_expire_ctx {
    struct arguments args;
    struct archive_rock arock;
    struct conversations_rock crock;
    struct delete_rock drock;
    struct expire_rock erock;
};

static const struct cyr_expire_ctx zero_ctx;

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

static void cyr_expire_init(const char *progname, struct cyr_expire_ctx *ctx)
{
    struct sigaction action;

    /* Initialise signal handlers */
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    action.sa_handler = sighandler;
    if (sigaction(SIGQUIT, &action, NULL) < 0)
        fatal("unable to install signal handler for SIGQUIT", EX_TEMPFAIL);
    if (sigaction(SIGINT, &action, NULL) < 0)
        fatal("unable to install signal handler for SIGINT", EX_TEMPFAIL);
    if (sigaction(SIGTERM, &action, NULL) < 0)
        fatal("unable to install signal handler for SIGTERM", EX_TEMPFAIL);

    construct_hash_table(&ctx->erock.table, 10000, 1);
    strarray_init(&ctx->drock.to_delete);
    construct_hash_table(&ctx->crock.seen, 100, 1);

    cyrus_init(ctx->args.altconfig, progname, 0, 0);
    global_sasl_init(1, 0, NULL);

    ctx->erock.do_userflags = ctx->args.do_userflags;
    /* TODO: Ideally all the functions should just use the skip_annotate from
     *       args. But that would require a change in the callback signatures.
     *       So retaining it as is for now.
     */
    ctx->arock.skip_annotate = ctx->args.skip_annotate;
    ctx->erock.skip_annotate = ctx->args.skip_annotate;
    ctx->drock.skip_annotate = ctx->args.skip_annotate;
}

static void cyr_expire_cleanup(struct cyr_expire_ctx *ctx)
{
    if (ctx->args.freeme) free(ctx->args.freeme);

    free_hash_table(&ctx->erock.table, free);
    free_hash_table(&ctx->crock.seen, NULL);
    strarray_fini(&ctx->drock.to_delete);

    duplicate_done();
    sasl_done();
    cyrus_done();
}

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTIONS] {mailbox|users}\n", progname);
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

    fprintf(stderr, "\n");

    exit(EX_USAGE);
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

/*
 * Given an annotation, reads it, and converts it into 'seconds',
 * using `parse_duration`.
 *
 * On Success: Returns 1
 * On Failure: Returns 0
 */
static int get_annotation_value(const mbentry_t *mbentry,
                                const char *annot_entry,
                                int *secondsp, bool iterate)
{
    struct buf attrib = BUF_INITIALIZER;
    int ret = 0;
    /* mboxname needs to be copied since `mboxname_make_parent`
     * runs a strrchr() on it.
     */
    char *buf = xstrdup(mbentry->name);

    /*
     * Mailboxes inherit /vendo/cmu/cyrus-imapd/{expire, archive, delete},
     * so we need to iterate all the way up to "" (server entry).
     */
    do {
        buf_free(&attrib);
        ret = annotatemore_lookup_mbe(mbentry, annot_entry, "", &attrib);
        if (ret ||              /* error */
            attrib.s)           /* found an entry */
            break;
    } while (mboxname_make_parent(buf) && iterate);

    if (attrib.s && parse_duration(attrib.s, secondsp))
        ret = 1;
    else
        ret = 0;

    buf_free(&attrib);
    free(buf);

    syslog(LOG_DEBUG, "get_annotation_value: ret(%d):secondsp(%d)", ret, *secondsp);
    return ret;
}

static int expunge_userflags(struct mailbox *mailbox, struct expire_rock *erock)
{
    unsigned int i;
    int r;

    for (i = 0; i < MAX_USER_FLAGS; i++) {
        if (erock->userflags[i/32] & 1<<(i&31))
            continue;
        if (!mailbox->h.flagname[i])
            continue;
        verbosep("Expunging userflag %u (%s) from %s\n",
                        i, mailbox->h.flagname[i], mailbox_name(mailbox));
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
    struct archive_rock *arock = (struct archive_rock *) rock;
    struct mailbox *mailbox = NULL;
    int archive_seconds = -1;

    if (sigquit)
        return 1;

    if (mbentry->mbtype & MBTYPE_DELETED)
        goto done;

    if (mbentry->mbtype & MBTYPE_REMOTE)
        goto done;

    if (mailbox_open_iwl(mbentry->name, &mailbox))
        goto done;

    /* check /vendor/cmu/cyrus-imapd/archive */
    if (!arock->skip_annotate &&
        get_annotation_value(mbentry, IMAP_ANNOT_NS "archive",
                             &archive_seconds, false)) {
        arock->archive_mark = archive_seconds ?
            time(0) - archive_seconds : 0;
    }

    /* The default callback for mailbox_archive() is mailbox_should_archive()
     * in imap/mailbox.c. This one takes the arock->archive_mark as the
     * callback data.
     */
    mailbox_archive(mailbox, NULL, &arock->archive_mark, ITER_SKIP_EXPUNGED);

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
        if (mbentry->mtime < erock->tombstone_mark) {
            verbosep("Removing stale tombstone for %s\n", mbentry->name);
            syslog(LOG_NOTICE, "Removing stale tombstone for %s", mbentry->name);
            mboxlist_delete(mbentry->name);
        }
        goto done;
    }

    memset(erock->userflags, 0, sizeof(erock->userflags));

    r = mailbox_open_iwl(mbentry->name, &mailbox);
    if (r) {
        /* mailbox corrupt/nonexistent -- skip it */
        syslog(LOG_WARNING, "unable to open mailbox %s: %s",
               mbentry->name, error_message(r));
        goto done;
    }

    /* see if we need to expire messages.
     * since mailboxes inherit /vendor/cmu/cyrus-imapd/expire,
     * we need to iterate all the way up to "" (server entry)
     */
    if (!erock->skip_annotate &&
        get_annotation_value(mbentry, IMAP_ANNOT_NS "expire",
                             &expire_seconds, true)) {
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

    verbosep("cleaning up expunged messages in %s\n", mbentry->name);

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
    int delete_seconds = -1;

    if (sigquit)
        return 1;

    if (mbentry->mbtype & MBTYPE_DELETED)
        goto done;

    if (mbentry->mbtype & MBTYPE_REMOTE)
        goto done;

    /* check if this is a mailbox we want to examine */
    if (!mboxname_isdeletedmailbox(mbentry->name, &timestamp))
        goto done;

    /* check /vendor/cmu/cyrus-imapd/delete */
    if (!drock->skip_annotate &&
        get_annotation_value(mbentry, IMAP_ANNOT_NS "delete",
                             &delete_seconds, false)) {
        drock->delete_mark = delete_seconds ?
            time(0) - delete_seconds: 0;
    }

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

    if (mboxname_isdeletedmailbox(mbentry->name, NULL))
        goto done;

    filename = conversations_getmboxpath(mbentry->name);
    if (!filename)
        goto done;

    if (hash_lookup(filename, &crock->seen))
        goto done;

    verbosep("Pruning conversations from db %s\n", filename);

    if (!conversations_open_mbox(mbentry->name, 0/*shared*/, &state)) {
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

static int do_archive(struct cyr_expire_ctx *ctx)
{
    if (ctx->args.archive_seconds >= 0) {
        syslog(LOG_DEBUG, ">> do_archive: archive_seconds(%d) >= 0",
               ctx->args.archive_seconds);
        ctx->arock.archive_mark = time(0) - ctx->args.archive_seconds;

        if (ctx->args.userid)
            mboxlist_usermboxtree(ctx->args.userid, NULL, archive,
                                  &ctx->arock, MBOXTREE_DELETED);
        else
            mboxlist_allmbox(ctx->args.mbox_prefix, archive, &ctx->arock, 0);
    }

    return 0;
}

static int do_expunge(struct cyr_expire_ctx *ctx)
{
    if (ctx->args.do_expunge && (ctx->args.expunge_seconds >= 0 ||
                                 ctx->args.expire_seconds ||
                                 ctx->erock.do_userflags)) {
        /* XXX: better way to determine a size for this table? */

        /* expire messages from mailboxes,
         * build a hash table of mailboxes in which we expired messages,
         * and perform a cleanup of expunged messages
         */
        if (ctx->args.expunge_seconds < 0) {
            ctx->erock.expunge_mark = 0;
        } else {
            ctx->erock.expunge_mark = time(0) - ctx->args.expunge_seconds;

            verbosep("Expunging deleted messages in mailboxes older than %0.2f days\n",
                           ((double)ctx->args.expunge_seconds/SECS_IN_A_DAY));
        }

        /* XXX _ a control for this too? */
        ctx->erock.tombstone_mark = time(0) - SECS_IN_A_DAY*7;

        if (ctx->args.userid)
            mboxlist_usermboxtree(ctx->args.userid, NULL, expire,
                                  &ctx->erock, MBOXTREE_DELETED|MBOXTREE_TOMBSTONES);
        else
            mboxlist_allmbox(ctx->args.mbox_prefix, expire, &ctx->erock,
                             MBOXTREE_TOMBSTONES);

        syslog(LOG_NOTICE, "Expired %lu and expunged %lu out of %lu "
                            "messages from %lu mailboxes",
                           ctx->erock.messages_expired,
                           ctx->erock.messages_expunged,
                           ctx->erock.messages_seen,
                           ctx->erock.mailboxes_seen);
        verbosep("\nExpired %lu and expunged %lu out of %lu "
                       "messages from %lu mailboxes\n",
                       ctx->erock.messages_expired,
                       ctx->erock.messages_expunged,
                       ctx->erock.messages_seen,
                       ctx->erock.mailboxes_seen);

        if (ctx->erock.do_userflags) {
            syslog(LOG_NOTICE, "Expunged %lu user flags",
                           ctx->erock.userflags_expunged);
            verbosep("Expunged %lu user flags\n",
                           ctx->erock.userflags_expunged);
        }

    }

    return 0;
}

static int do_cid_expire(struct cyr_expire_ctx *ctx)
{
    if (ctx->args.do_cid_expire) {
        int cid_expire_seconds;

        cid_expire_seconds = config_getduration(IMAPOPT_CONVERSATIONS_EXPIRE_AFTER, 'd');
        ctx->crock.expire_mark = time(0) - cid_expire_seconds;

        verbosep("Removing conversation entries older than %0.2f days\n",
                       (double)(cid_expire_seconds/SECS_IN_A_DAY));

        if (ctx->args.userid)
            mboxlist_usermboxtree(ctx->args.userid, NULL, expire_conversations,
                                  &ctx->crock, MBOXTREE_DELETED);
        else
            mboxlist_allmbox(ctx->args.mbox_prefix, expire_conversations,
                             &ctx->crock, 0);

        syslog(LOG_NOTICE, "Expired %lu entries of %lu entries seen "
                            "in %lu conversation databases",
                            ctx->crock.msgids_expired,
                            ctx->crock.msgids_seen,
                            ctx->crock.databases_seen);
        verbosep("Expired %lu entries of %lu entries seen "
                       "in %lu conversation databases\n",
                       ctx->crock.msgids_expired,
                       ctx->crock.msgids_seen,
                       ctx->crock.databases_seen);
    }

    return 0;
}

static int do_delete(struct cyr_expire_ctx *ctx)
{
    int ret = 0;

    if ((ctx->args.delete_seconds >= 0) &&
        mboxlist_delayed_delete_isenabled() &&
        config_getstring(IMAPOPT_DELETEDPREFIX)) {
        int count = 0;
        int i;

        verbosep("Removing deleted mailboxes older than %0.2f days\n",
                 ((double)ctx->args.delete_seconds/SECS_IN_A_DAY));

        ctx->drock.delete_mark = time(0) - ctx->args.delete_seconds;

        if (ctx->args.userid)
            mboxlist_usermboxtree(ctx->args.userid, NULL, delete,
                                  &ctx->drock, MBOXTREE_DELETED|MBOXTREE_INTERMEDIATES);
        else
            mboxlist_allmbox(ctx->args.mbox_prefix, delete, &ctx->drock, MBOXTREE_INTERMEDIATES);

        for (i = 0 ; i < ctx->drock.to_delete.count ; i++) {
            char *name = ctx->drock.to_delete.data[i];

            if (sigquit)
                return ret;         /* return from here, will quit in main. */

            verbosep("Removing: %s\n", name);

            ret = mboxlist_deletemailboxlock(name, 1, NULL, NULL, NULL,
                                             MBOXLIST_DELETE_KEEP_INTERMEDIARIES);
            /* XXX: Ignoring the return from mboxlist_deletemailbox() ??? */
            count++;
        }

        verbosep("Removed %d deleted mailboxes\n", count);

        syslog(LOG_NOTICE, "Removed %d deleted mailboxes", count);
    }

    return ret;
}

static int do_duplicate_prune(struct cyr_expire_ctx *ctx)
{
    int ret = 0;
    if (ctx->args.expire_seconds > 0)
        ret = duplicate_prune(ctx->args.expire_seconds, &ctx->erock.table);

    return ret;
}

static int parse_args(int argc, char *argv[], struct arguments *args)
{
    extern char *optarg;
    int opt;

    args->archive_seconds = -1;
    args->delete_seconds = -1;
    args->expire_seconds = -1;
    args->expunge_seconds = -1;
    args->do_expunge = true;
    args->do_cid_expire = -1;

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
            args->skip_annotate = true;
            break;

        case 'c':
            args->do_cid_expire = 0;
            break;

        case 'p':
            if (args->userid) usage();
            args->mbox_prefix = optarg;
            break;

        case 't':
            args->do_userflags = true;
            break;

        case 'u':
            if (args->mbox_prefix) usage();
            args->userid = optarg;
            break;

        case 'v':
            verbose++;
            break;

        case 'x':
            args->do_expunge = false;
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
    struct cyr_expire_ctx ctx = zero_ctx;

    progname = basename(argv[0]);

    if (parse_args(argc, argv, &ctx.args) != 0)
        exit(EXIT_FAILURE);

    cyr_expire_init(progname, &ctx);

    /* do_cid_expire defaults to whatever IMAP options are set */
    if (ctx.args.do_cid_expire < 0)
        ctx.args.do_cid_expire = config_getswitch(IMAPOPT_CONVERSATIONS);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&expire_namespace, 1)) != 0) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EX_CONFIG);
    }

    mboxevent_setnamespace(&expire_namespace);

    /* now that we have a namespace, convert mbox_prefix to internal ns */
    if (ctx.args.mbox_prefix) {
        char *intname = mboxname_from_external(ctx.args.mbox_prefix,
                                               &expire_namespace, NULL);
        ctx.args.mbox_prefix = ctx.args.freeme = intname;
    }

    if (duplicate_init(NULL) != 0) {
        fprintf(stderr,
                "cyr_expire: unable to init duplicate delivery database\n");
        exit(1);
    }

    r = do_archive(&ctx);

    if (sigquit)
        goto finish;

    r = do_expunge(&ctx);

    if (sigquit)
        goto finish;

    r = do_cid_expire(&ctx);

    if (sigquit)
        goto finish;

    r = do_delete(&ctx);

    if (sigquit)
        goto finish;

    /* purge deliver.db entries of expired messages */
    r = do_duplicate_prune(&ctx);

 finish:
    cyr_expire_cleanup(&ctx);
    exit(r);
}
