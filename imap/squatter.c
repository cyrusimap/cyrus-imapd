/* squatter.c -- SQUAT-based message indexing tool
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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
  This is the tool that creates/updates search indexes for Cyrus mailboxes.

  Despite the name, it handles whichever search engine in configured
  by the 'search_engine' option in imapd.conf.
*/

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <errno.h>
#include <fcntl.h>
#include <sysexits.h>
#include <syslog.h>
#include <string.h>
#include <getopt.h>

#include "annotate.h"
#include "assert.h"
#include "bitvector.h"
#include "bsearch.h"
#include "mboxlist.h"
#include "global.h"
#include "search_engines.h"
#include "sync_log.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "ptrarray.h"
#include "tok.h"
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "index.h"
#include "message.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

extern char *optarg;
extern int optind;

/* current namespace */
static struct namespace squat_namespace;

static int verbose = 0;
static int skip_unmodified = -1;
static int incremental_mode = 0;
static int xapindexed_mode = 0;
static int recursive_flag = 0;
static int annotation_flag = 0;
static int sleepmicroseconds = 0;
static int allow_partials = 0;
static int allow_duplicateparts = 0;
static int reindex_partials = 0;
static int reindex_minlevel = 0;
static search_text_receiver_t *rx = NULL;

static strarray_t *skip_domains = NULL;
static strarray_t *skip_users = NULL;

static const char *name_starts_from = NULL;

static void shut_down(int code) __attribute__((noreturn));

__attribute__((noreturn)) static int usage(const char *name)
{
    fprintf(stderr,
            "usage: %s [mode] [options] [source]\n"
            "\n"
            "Mode flags: \n"
            "  none                         index [source] (default)\n"
            "  -a, --squat-annot            index [source] using /squat annotations\n"
            "  -r, --recursive              index [source] recursively\n"
            "  -f, --synclog=FILE           index from synclog file\n"
            "  -R, --rolling                start rolling indexer\n"
            "  -z, --compact=TIER           compact to TIER\n"
            "  -l, --list                   list paths\n"
            "  -A, --audit                  report unindexed messages\n"
            "\n"
            "Index mode options:\n"
            "  -i, --incremental            index incrementally\n"
            "  -p, --allow-partials         allow partially indexed messages\n"
            "  -P, --reindex-partials       reindex partially indexed messages (implies -Z)\n"
            "  -L, --reindex-minlevel=LEVEL reindex messages where indexlevel < LEVEL (implies -Z)\n"
            "  -N, --name=NAME              index mailbox names starting with NAME\n"
            "  -S, --sleep=SECONDS          sleep SECONDS between indexing mailboxes\n"
            "  -Z, --internalindex          Xapian: use internal index rather than cyrus.indexed.db\n"
            "  -s, --squat-skip[=DELTA]     skip unmodified mailboxes (requires squat backend)\n"
            "\n"
            "Index sources:\n"
            "  none                         all mailboxes (default)\n"
            "  mailbox...                   index mailboxes\n"
            "  -u, --user=USER...           index mailboxes of USER\n"
            "\n"
            "Rolling indexer options:\n"
            "  -n, --channel=CHANNEL        listen to CHANNEL\n"
            "  -d, --nodaemon               don't background process\n"
            "\n"
            "Compact mode options:\n"
            "  -t, --srctier=TIER,...       compact from TIER\n"
            "  -F, --filter                 filter during compaction\n"
            "  -T, --reindex-tier=TIER,...  reindex TIER\n"
            "  -X, --reindex                reindex during compaction\n"
            "  -o, --copydb                 copy db rather compacting\n"
            "  -U, --only-upgrade           only compact if re-indexing\n"
            " --B, --skip-locked            skip users that are locked by another process\n"
            "\n"
            "General options:\n"
            "  -v, --verbose                be verbose\n"
            "  -h, --help                   show usage\n",
        name);

    exit(EX_USAGE);
}

/* ====================================================================== */

static void become_daemon(void)
{
    pid_t pid;
    int nfds = getdtablesize();
    int nullfd;
    int fd;

    nullfd = open("/dev/null", O_RDWR, 0);
    if (nullfd < 0) {
        perror("/dev/null");
        exit(1);
    }
    dup2(nullfd, STDIN_FILENO);
    dup2(nullfd, STDOUT_FILENO);
    dup2(nullfd, STDERR_FILENO);
    for (fd = 3 ; fd < nfds ; fd++)
        close(fd);          /* this will close nullfd too */

    pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(1);
    }

    if (pid)
        exit(0); /* parent */
}

static int should_index(const char *name)
{
    // skip early users
    if (strcmpsafe(name, name_starts_from) < 0)
        return 0;

    int ret = 1;
    mbentry_t *mbentry = NULL;
    mbname_t *mbname = mbname_from_intname(name);
    /* Skip remote mailboxes */
    int r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) {
        /* Convert internal name to external */
        char *extname = mboxname_to_external(name, &squat_namespace, NULL);
        if (verbose) {
            printf("error looking up %s: %s\n",
                   extname, error_message(r));
        }
        syslog(LOG_INFO, "error looking up %s: %s",
               extname, error_message(r));

        free(extname);
        ret = 0;
        goto done;
    }

    // skip remote or not-real mailboxes
    if (mbentry->mbtype & (MBTYPE_REMOTE|MBTYPE_DELETED|MBTYPE_INTERMEDIATE)) {
        ret = 0;
        goto done;
    }

    // skip email submissions
    if (mboxname_issubmissionmailbox(mbentry->name, mbentry->mbtype)) {
        ret = 0;
        goto done;
    }

    // skip COLLECTION mailboxes (just files)
    if (mbtype_isa(mbentry->mbtype) == MBTYPE_COLLECTION) {
        ret = 0;
        goto done;
    }

    // skip deleted mailboxes
    if (mbname_isdeleted(mbname)) {
        ret = 0;
        goto done;
    }

    // skip listed domains
    if (mbname_domain(mbname) && skip_domains &&
        strarray_find(skip_domains, mbname_domain(mbname), 0) >= 0) {
        ret = 0;
        goto done;
    }

    // skip listed users
    if (mbname_userid(mbname) && skip_users &&
        strarray_find(skip_users, mbname_userid(mbname), 0) >= 0) {
        ret = 0;
        goto done;
    }

done:
    mbname_free(&mbname);
    mboxlist_entry_free(&mbentry);
    return ret;
}

/* ====================================================================== */

/* This is called once for each mailbox we're told to index. */
static int index_one(const char *name, int blocking)
{
    struct mailbox *mailbox = NULL;
    int r;
    int flags = SEARCH_UPDATE_BATCH;

    if (incremental_mode)
        flags |= SEARCH_UPDATE_INCREMENTAL;
    if (xapindexed_mode)
        flags |= SEARCH_UPDATE_XAPINDEXED;
    if (allow_partials)
        flags |= SEARCH_UPDATE_ALLOW_PARTIALS;
    if (reindex_partials)
        flags |= SEARCH_UPDATE_REINDEX_PARTIALS;
    if (allow_duplicateparts)
        flags |= SEARCH_UPDATE_ALLOW_DUPPARTS;

    /* Convert internal name to external */
    char *extname = mboxname_to_external(name, &squat_namespace, NULL);

    /* make sure the mailbox (or an ancestor) has
       /vendor/cmu/cyrus-imapd/squat set to "true" */
    if (annotation_flag) {
        char buf[MAX_MAILBOX_BUFFER] = "", *p;
        struct buf attrib = BUF_INITIALIZER;
        int domainlen = 0;

        if (config_virtdomains && (p = strchr(name, '!')))
            domainlen = p - name + 1;

        strlcpy(buf, name, sizeof(buf));

        /* since mailboxes inherit /vendor/cmu/cyrus-imapd/squat,
           we need to iterate all the way up to "" (server entry) */
        while (1) {
            r = annotatemore_lookup(buf, IMAP_ANNOT_NS "squat", "",
                                    &attrib);

            if (r ||                            /* error */
                attrib.s ||                     /* found an entry */
                !buf[0]) {                      /* done recursing */
                break;
            }

            p = strrchr(buf, '.');              /* find parent mailbox */

            if (p && (p - buf > domainlen))     /* don't split subdomain */
                *p = '\0';
            else if (!buf[domainlen])           /* server entry */
                buf[0] = '\0';
            else                                /* domain entry */
                buf[domainlen] = '\0';
        }

        if (r || !attrib.s || strcasecmp(attrib.s, "true")) {
            buf_free(&attrib);
            free(extname);
            return 0;
        }
        buf_free(&attrib);
    }

again:
    if (blocking)
        r = mailbox_open_irl(name, &mailbox);
    else
        r = mailbox_open_irlnb(name, &mailbox);

    if (r == IMAP_MAILBOX_LOCKED) {
        if (verbose) syslog(LOG_INFO, "mailbox %s locked, retrying", extname);
        free(extname);
        return r;
    }
    if (r) {
        if (verbose) {
            printf("error opening %s: %s\n", extname, error_message(r));
        }
        syslog(LOG_INFO, "error opening %s: %s", extname, error_message(r));
        free(extname);

        return r;
    }

    syslog(LOG_INFO, "indexing mailbox %s... ", extname);
    if (verbose > 0) {
        printf("Indexing mailbox %s... ", extname);
    }

    if (skip_unmodified >= 0) {
        const char *fname = mailbox_meta_fname(mailbox, META_SQUAT);
        struct stat sbuf;
        if (!stat(fname, &sbuf) &&
                skip_unmodified + mailbox->index_mtime < sbuf.st_mtime) {
            syslog(LOG_DEBUG, "Squat skipping mailbox %s", extname);
            if (verbose > 0) {
                printf("Skipping mailbox %s\n", extname);
            }
            mailbox_close(&mailbox);
            free(extname);
            return 0;
        }
    }

    r = search_update_mailbox(rx, mailbox, reindex_minlevel, flags);

    mailbox_close(&mailbox);

    /* in non-blocking (rolling) mode, only do one batch per mailbox at
     * a time for fairness [IRIS-2471].  The squatter will re-insert the
     * mailbox in the queue */
    if (blocking && r == IMAP_AGAIN) goto again;
    free(extname);

    return r;
}

static int addmbox(const mbentry_t *mbentry, void *rock)
{
    strarray_t *sa = (strarray_t *) rock;
    strarray_append(sa, mbentry->name);
    return 0;
}

static void expand_mboxnames(strarray_t *sa, int nmboxnames,
                             const char **mboxnames, int user_mode)
{
    int i;

    if (!nmboxnames) {
        assert(!recursive_flag);
        mboxlist_allmbox(NULL, addmbox, sa, 0);
    }

    for (i = 0; i < nmboxnames; i++) {
        if (user_mode) {
            mboxlist_usermboxtree(mboxnames[i], NULL, addmbox, sa, 0);
        }
        else {
            /* Translate any separators in mailboxname */
            char *intname = mboxname_from_external(mboxnames[i], &squat_namespace, NULL);
            int flags = recursive_flag ? 0 : MBOXTREE_SKIP_CHILDREN;
            mboxlist_mboxtree(intname, addmbox, sa, flags);
            free(intname);
        }

        /* sort mboxnames */
        strarray_sort(sa, cmpstringp_raw);
        /* and deduplicate */
        strarray_uniq(sa);
    }
}

static int do_indexer(const strarray_t *mboxnames)
{
    int r = 0;
    int i;

    rx = search_begin_update(verbose);
    if (rx == NULL)
        return 0;       /* no indexer defined */

    for (i = 0 ; i < strarray_size(mboxnames) ; i++) {
        const char *mboxname = strarray_nth(mboxnames, i);
        if (!should_index(mboxname)) continue;
        r = index_one(mboxname, /*blocking*/1);
        if (r == IMAP_MAILBOX_NONEXISTENT)
            r = 0;
        if (r == IMAP_MAILBOX_LOCKED)
            r = 0; /* XXX - try again? */
        if (r) break;
        if (sleepmicroseconds)
            usleep(sleepmicroseconds);
    }

    search_end_update(rx);

    return r;
}

static int squatter_build_query(search_builder_t *bx, const char *query)
{
    tok_t tok = TOK_INITIALIZER(query, NULL, 0);
    char *p;
    char *q;
    int r = 0;
    int part;
    charset_t utf8 = charset_lookupname("utf-8");

    while ((p = tok_next(&tok))) {
        if (!strncasecmp(p, "__begin:", 8)) {
            q = p + 8;
            if (!strcasecmp(q, "and"))
                bx->begin_boolean(bx, SEARCH_OP_AND);
            else if (!strcasecmp(q, "or"))
                bx->begin_boolean(bx, SEARCH_OP_OR);
            else if (!strcasecmp(q, "not"))
                bx->begin_boolean(bx, SEARCH_OP_NOT);
            else
                goto error;
            continue;
        }
        if (!strncasecmp(p, "__end:", 6)) {
            q = p + 6;
            if (!strcasecmp(q, "and"))
                bx->end_boolean(bx, SEARCH_OP_AND);
            else if (!strcasecmp(q, "or"))
                bx->end_boolean(bx, SEARCH_OP_OR);
            else if (!strcasecmp(q, "not"))
                bx->end_boolean(bx, SEARCH_OP_NOT);
            else
                goto error;
            continue;
        }

        /* everything else is a ->match() of some kind */
        q = strchr(p, ':');
        if (q) q++;
        if (!q) {
            part = SEARCH_PART_ANY;
            q = p;
        }
        else if (!strncasecmp(p, "to:", 3))
            part = SEARCH_PART_TO;
        else if (!strncasecmp(p, "from:", 5))
            part = SEARCH_PART_FROM;
        else if (!strncasecmp(p, "cc:", 3))
            part = SEARCH_PART_CC;
        else if (!strncasecmp(p, "bcc:", 4))
            part = SEARCH_PART_BCC;
        else if (!strncasecmp(p, "subject:", 8))
            part = SEARCH_PART_SUBJECT;
        else if (!strncasecmp(p, "listid:", 7))
            part = SEARCH_PART_LISTID;
        else if (!strncasecmp(p, "contenttype:", 12))
            part = SEARCH_PART_TYPE;
        else if (!strncasecmp(p, "header:", 7))
            part = SEARCH_PART_HEADERS;
        else if (!strncasecmp(p, "body:", 5))
            part = SEARCH_PART_BODY;
        else
            goto error;

        q = charset_convert(q, utf8, charset_flags);
        bx->match(bx, part, q);
        free(q);
    }
    r = 0;

out:
    charset_free(&utf8);
    tok_fini(&tok);
    return r;

error:
    syslog(LOG_ERR, "bad query expression at \"%s\"", p);
    r = IMAP_PROTOCOL_ERROR;
    goto out;
}

static int print_search_hit(const char *mboxname, uint32_t uidvalidity,
                            uint32_t uid,
                            const strarray_t *partids __attribute__((unused)),
                            void *rock)
{
    int single = *(int *)rock;

    if (single)
        printf("uid %u\n", uid);
    else
        printf("mailbox %s\nuidvalidity %u\nuid %u\n", mboxname, uidvalidity, uid);
    return 0;
}

static int do_list(const strarray_t *mboxnames)
{
    char *prev_userid = NULL;
    strarray_t files = STRARRAY_INITIALIZER;
    int i;
    int r = 0;

    for (i = 0; i < strarray_size(mboxnames); i++) {
        const char *mboxname = strarray_nth(mboxnames, i);
        char *userid = mboxname_to_userid(mboxname);
        if (!userid) continue;

        if (!strcmpsafe(prev_userid, userid)) {
            free(userid);
            continue;
        }

        r = search_list_files(userid, &files);
        if (r) break;

        int j;
        for (j = 0; j < strarray_size(&files); j++) {
            printf("%s\n", strarray_nth(&files, j));
        }

        strarray_truncate(&files, 0);

        free(prev_userid);
        prev_userid = userid;

        if (sleepmicroseconds)
            usleep(sleepmicroseconds);
    }

    strarray_fini(&files);
    free(prev_userid);
    return r;
}

static int compact_mbox(const char *userid, const strarray_t *reindextiers,
                        const strarray_t *srctiers,
                        const char *desttier, int flags)
{
    return search_compact(userid, reindextiers, srctiers, desttier, flags);
}

static int do_compact(const strarray_t *mboxnames, const strarray_t *reindextiers,
                      const strarray_t *srctiers,
                      const char *desttier, int flags)
{
    char *prev_userid = NULL;
    int i;

    for (i = 0; i < strarray_size(mboxnames); i++) {
        const char *mboxname = strarray_nth(mboxnames, i);
        if (!should_index(mboxname)) continue;
        char *userid = mboxname_to_userid(mboxname);
        if (!userid) continue;

        if (!strcmpsafe(prev_userid, userid)) {
            free(userid);
            continue;
        }

        int retry;
        for (retry = 1; retry <= 3; retry++) {
            int r = compact_mbox(userid, reindextiers, srctiers, desttier, flags);
            if (!r) break;
            xsyslog(LOG_ERR, "IOERROR: failed to compact",
                             "userid=<%s> retry=<%d> error=<%s>",
                             userid, retry, error_message(r));
        }

        free(prev_userid);
        prev_userid = userid;

        if (sleepmicroseconds)
            usleep(sleepmicroseconds);
    }

    free(prev_userid);
    return 0;
}

static int do_search(const char *query, int single, const strarray_t *mboxnames)
{
    struct mailbox *mailbox = NULL;
    int i;
    int r;
    search_builder_t *bx;
    int opts = SEARCH_VERBOSE(verbose);

    if (!single)
        opts |= SEARCH_MULTIPLE;

    for (i = 0 ; i < mboxnames->count ; i++) {
        const char *mboxname = mboxnames->data[i];
        if (!should_index(mboxname)) continue;

        r = mailbox_open_irl(mboxname, &mailbox);
        if (r) {
            fprintf(stderr, "Cannot open mailbox %s: %s\n",
                    mboxname, error_message(r));
            continue;
        }
        if (single)
            printf("mailbox %s\n", mboxname);

        bx = search_begin_search(mailbox, opts);
        if (bx) {
            r = squatter_build_query(bx, query);
            if (!r)
                bx->run(bx, print_search_hit, &single);
            search_end_search(bx);
        }

        mailbox_close(&mailbox);
    }

    return 0;
}

static strarray_t *read_sync_log_items(sync_log_reader_t *slr)
{
    const char *args[3];
    strarray_t *mboxnames = strarray_new();

    while (sync_log_reader_getitem(slr, args) == 0) {
        if (!strcmp(args[0], "APPEND")) {
            strarray_append(mboxnames, args[1]);
        }
        else if (!strcmp(args[0], "USER"))
            mboxlist_usermboxtree(args[1], NULL, addmbox, mboxnames, /*flags*/0);
    }

    return mboxnames;
}

static int do_synclogfile(const char *synclogfile)
{
    strarray_t *mboxnames = NULL;
    sync_log_reader_t *slr;
    int nskipped = 0;
    int i;
    int r;

    slr = sync_log_reader_create_with_filename(synclogfile);
    r = sync_log_reader_begin(slr);
    if (r) goto out;
    mboxnames = read_sync_log_items(slr);
    sync_log_reader_end(slr);

    /* sort mboxnames for locality of reference in file processing mode */
    strarray_sort(mboxnames, cmpstringp_raw);
    /* and deduplicate */
    strarray_uniq(mboxnames);

    signals_poll();

    /* have some due items in the queue, try to index them */
    rx = search_begin_update(verbose);
    if (NULL == rx) {
        r = 1;
        goto out;
    }
    for (i = 0; i < strarray_size(mboxnames); i++) {
        const char *mboxname = strarray_nth(mboxnames, i);
        if (!should_index(mboxname)) continue;
        if (verbose > 1)
            syslog(LOG_INFO, "do_synclogfile: indexing %s", mboxname);
        r = index_one(mboxname, /*blocking*/1);
        if (r == IMAP_MAILBOX_NONEXISTENT)
            r = 0;
        if (r == IMAP_MAILBOX_LOCKED || r == IMAP_AGAIN) {
            nskipped++;
            if (nskipped > 10000) {
                xsyslog(LOG_ERR, "IOERROR: skipped too many times",
                                 "mailbox=<%s>", mboxname);
                break;
            }
            r = 0;
            /* try again at the end */
            strarray_append(mboxnames, mboxname);
        }
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: failed to index",
                             "mailbox=<%s> error=<%s>",
                             mboxname, error_message(r));
            break;
        }
        if (sleepmicroseconds)
            usleep(sleepmicroseconds);
    }
    search_end_update(rx);
    rx = NULL;

out:
    strarray_free(mboxnames);
    sync_log_reader_free(slr);
    return r;
}

static void do_rolling(const char *channel)
{
    strarray_t *mboxnames = NULL;
    sync_log_reader_t *slr;
    int i;
    int r;

    slr = sync_log_reader_create_with_channel(channel);

    for (;;) {
        int sig = signals_poll();

        if (sig == SIGHUP && getenv("CYRUS_ISDAEMON")) {
            syslog(LOG_DEBUG, "received SIGHUP, shutting down gracefully");
            sync_log_reader_end(slr);
            shut_down(0);
        }

        if (shutdown_file(NULL, 0))
            shut_down(EX_TEMPFAIL);

        r = sync_log_reader_begin(slr);
        if (r) { /* including IMAP_AGAIN */
            usleep(100000);    /* 1/10th second */
            continue;
        }

        mboxnames = read_sync_log_items(slr);

        if (mboxnames->count) {
            /* sort mboxnames for locality of reference in file processing mode */
            strarray_sort(mboxnames, cmpstringp_raw);
            /* and deduplicate */
            strarray_uniq(mboxnames);

            /* have some due items in the queue, try to index them */
            rx = search_begin_update(verbose);
            if (NULL == rx) {
                /* XXX if xapian, probably don't have conversations enabled? */
                fatal("could not construct search text receiver", EX_CONFIG);
            }
            for (i = 0; i < strarray_size(mboxnames); i++) {
                const char *mboxname = strarray_nth(mboxnames, i);
                if (!should_index(mboxname)) continue;
                if (verbose > 1)
                    syslog(LOG_INFO, "do_rolling: indexing %s", mboxname);
                r = index_one(mboxname, /*blocking*/0);
                if (r == IMAP_AGAIN || r == IMAP_MAILBOX_LOCKED) {
                    /* XXX: alternative, just append to strarray_t *mboxnames ... */
                    sync_log_channel_append(channel, mboxname);
                }
                else if (r == IMAP_MAILBOX_NONEXISTENT) {
                    /* should_index() checked for this, but we lost a race.
                     * not an IOERROR, just annoying!
                     */
                    syslog(LOG_DEBUG, "skipping nonexistent mailbox: %s", mboxname);
                }
                else if (r) {
                    xsyslog(LOG_ERR, "IOERROR: failed to index and forgetting",
                                     "mailbox=<%s> error=<%s>",
                                     mboxname, error_message(r));
                }
                if (sleepmicroseconds)
                    usleep(sleepmicroseconds);
            }
            search_end_update(rx);
            rx = NULL;
        }

        strarray_free(mboxnames);
        mboxnames = NULL;
    }

    /* XXX - we don't really get here... */
    strarray_free(mboxnames);
    sync_log_reader_free(slr);
}

static int audit_one(const char *mboxname, bitvector_t *unindexed)
{
    int r2, r = 0;
    struct mailbox *mailbox = NULL;

    r = mailbox_open_irl(mboxname, &mailbox);
    if (r) goto done;

    r = rx->begin_mailbox(rx, mailbox, SEARCH_UPDATE_AUDIT);
    if (r) goto done;

    r = rx->audit_mailbox(rx, unindexed);
    if (r) goto done;

done:
    r2 = rx->end_mailbox(rx, mailbox);
    mailbox_close(&mailbox);
    if (!r) r = r2;
    return r;
}


static int do_audit(const strarray_t *mboxnames)
{
    rx = search_begin_update(verbose);
    if (rx == NULL)
        return 0;       /* no indexer defined */

    int r = 0;
    if (!rx->audit_mailbox) {
        syslog(LOG_ERR, "squatter: indexer does not support audits");
        r = IMAP_INTERNAL;
        goto done;
    }

    bitvector_t unindexed = BV_INITIALIZER;
    int i;
    for (i = 0 ; i < mboxnames->count ; i++) {
        const char *mboxname = strarray_nth(mboxnames, i);
        if (!should_index(mboxname)) continue;
        r = audit_one(mboxname, &unindexed);
        if (r == IMAP_MAILBOX_NONEXISTENT)
            r = 0;
        if (r == IMAP_MAILBOX_LOCKED)
            r = 0; /* XXX - try again? */
        if (r) break;
        if (sleepmicroseconds)
            usleep(sleepmicroseconds);

        if (bv_count(&unindexed)) {
            printf("Unindexed message(s) in %s: ", mboxname);
            int uid;
            for (uid = bv_next_set(&unindexed, 0);
                 uid != -1;
                 uid = bv_next_set(&unindexed, uid+1)) {
                printf("%d ", uid);
            }
            printf("\n");
        }
        bv_clearall(&unindexed);
    }
    bv_fini(&unindexed);

done:
    search_end_update(rx);
    return r;
}

static void shut_down(int code)
{
    seen_done();

    cyrus_done();

    index_text_extractor_destroy();

    exit(code);
}

int main(int argc, char **argv)
{
    int opt;
    char *alt_config = NULL;
    int r = IMAP_NOTFOUND;
    strarray_t mboxnames = STRARRAY_INITIALIZER;
    const char *query = NULL;
    int background = 1;
    const char *channel = "squatter";
    const char *synclogfile = NULL;
    int init_flags = CYRUSINIT_PERROR;
    int multi_folder = 0;
    int user_mode = 0;
    int compact_flags = 0;
    strarray_t *srctiers = NULL;
    strarray_t *reindextiers = NULL;
    const char *desttier = NULL;
    char *errstr = NULL;
    enum { UNKNOWN, INDEXER, SEARCH, ROLLING, SYNCLOG,
           COMPACT, AUDIT, LIST } mode = UNKNOWN;

    setbuf(stdout, NULL);

    /* Keep these in alphabetic order */
    static const char *short_options = "ABC:DFL:N:PRS:T:UXZade:f:hilmn:oprs:t:uvz:";

    /* Keep these ordered by mode */
    static struct option long_options[] = {
        /* audit-mode flags */
        {"audit",  no_argument, 0, 'A' },

        /* compact-mode flags */
        {"copydb", no_argument, 0, 'o' },
        {"filter", no_argument, 0, 'F' },
        {"skip-locked", no_argument, 0, 'B' },
        {"only-upgrade", no_argument, 0, 'U' },
        {"reindex-tier", required_argument, 0, 'T' },
        {"srctier", required_argument, 0, 't' },
        {"compact", required_argument, 0, 'z' },

        /* index-mode flags */
        {"index-duplicates", no_argument, 0, 'D' },
        {"incremental", no_argument, 0, 'i' },
        {"allow-partials", no_argument, 0, 'p' },
        {"name", required_argument, 0, 'N' },
        {"internalindex", no_argument, 0, 'Z' },
        {"user", no_argument, 0, 'u' },
        {"reindex", no_argument, 0, 'X' },
        {"reindex-minlevel", required_argument, 0, 'L' },
        {"reindex-partials", no_argument, 0, 'P' },

        /* list-mode flags */
        {"list", no_argument, 0, 'l' },

        /* rolling mode */
        {"rolling", no_argument, 0, 'R' },
        {"channel", required_argument, 0, 'n' },
        {"nodaemon", no_argument, 0, 'd' },

        /* search-mode flags */
        {"search-multifolder", no_argument, 0, 'm' },
        {"search-term", required_argument, 0, 'e' },

        /* squat flags */
        {"squat-annot", no_argument, 0, 'a' },
        {"squat-skip", optional_argument, 0, 's' },

        /* synclog-mode flags */
        {"synclog", required_argument, 0, 'f' },

        {"recursive", no_argument, 0, 'r' },
        {"sleep", required_argument, 0, 'S' },

        /* misc */
        {"help", no_argument, 0, 'h' },
        {"verbose", no_argument, 0, 'v' },
        // no long form for 'C' option

        {0, 0, 0, 0 }
    };

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != EOF) {
        switch (opt) {
        case 'A':
            if (mode != UNKNOWN) usage(argv[0]);
            mode = AUDIT;
            break;

        case 'B':
            compact_flags |= SEARCH_COMPACT_NONBLOCKING;
            break;

        case 'C':               /* alt config file */
            alt_config = optarg;
            break;

        case 'F':
            compact_flags |= SEARCH_COMPACT_FILTER;
            break;

        case 'X':
            compact_flags |= SEARCH_COMPACT_REINDEX;
            break;

        case 'L':
            reindex_minlevel = atoi(optarg);
            if (reindex_minlevel < 1 || reindex_minlevel > SEARCH_INDEXLEVEL_MAX) {
                fprintf(stderr, "%s: %s: invalid level argument\n", argv[0], optarg);
                exit(EX_USAGE);
            }
            xapindexed_mode = 1;
            break;

        case 'P':
            reindex_partials = 1;
            xapindexed_mode = 1;
            break;

        case 'Z':
            xapindexed_mode = 1;
            break;

        case 'p':
            allow_partials = 1;
            break;

        case 'D':
            allow_duplicateparts = 1;
            break;

        case 'N':
            name_starts_from = optarg;
            break;

        case 'R':               /* rolling indexer */
            if (mode != UNKNOWN) usage(argv[0]);
            mode = ROLLING;
            incremental_mode = 1; /* always incremental if rolling */
            break;

        case 'l':               /* list paths */
            if (mode != UNKNOWN) usage(argv[0]);
            mode = LIST;
            break;

        case 'S':               /* sleep time in seconds */
            sleepmicroseconds = (atof(optarg) * 1000000);
            break;

        case 'd':               /* foreground (with -R) */
            background = 0;
            break;

        /* This option is deliberately undocumented, for testing only */
        case 'e':               /* add a search term */
            if (mode != UNKNOWN && mode != SEARCH) usage(argv[0]);
            query = optarg;
            mode = SEARCH;
            break;

        case 'f': /* alternate synclogfile used in SYNCLOG mode */
            synclogfile = optarg;
            mode = SYNCLOG;
            break;

        /* This option is deliberately undocumented, for testing only */
        case 'm':               /* multi-folder in SEARCH mode */
            if (mode != UNKNOWN && mode != SEARCH) usage(argv[0]);
            multi_folder = 1;
            mode = SEARCH;
            break;

        case 'n':               /* sync channel name (with -R) */
            channel = optarg;
            break;

        case 'o':               /* copy one DB rather than compressing */
            compact_flags |= SEARCH_COMPACT_COPYONE;
            break;

        case 'U':
            compact_flags |= SEARCH_COMPACT_ONLYUPGRADE;
            break;

        case 'v':               /* verbose */
            verbose++;
            break;

        case 'r':               /* recurse */
            if (mode != UNKNOWN && mode != INDEXER && mode != AUDIT) usage(argv[0]);
            recursive_flag = 1;
            if (mode == UNKNOWN) mode = INDEXER;
            break;

        case 'i':               /* incremental mode */
            incremental_mode = 1;
            break;

        case 'a':               /* use /squat annotation */
            if (mode != UNKNOWN && mode != INDEXER) usage(argv[0]);
            annotation_flag = 1;
            mode = INDEXER;
            break;

        case 's':
            if (mode != UNKNOWN && mode != INDEXER) usage(argv[0]);
            if (optarg) {
                char *end;
                long val = strtol(optarg, &end, 10);
                if (val < 0 || val > INT_MAX || *end) {
                    usage(argv[0]);
                }
                skip_unmodified = (int) val;
            }
            else {
                skip_unmodified = 60;
            }
            mode = INDEXER;
            break;

        case 'z':
            if (mode != UNKNOWN && mode != COMPACT) usage(argv[0]);
            desttier = optarg;
            mode = COMPACT;
            break;

        case 't':
            if (mode != UNKNOWN && mode != COMPACT) usage(argv[0]);
            srctiers = strarray_split(optarg, ",", 0);
            mode = COMPACT;
            break;

        case 'T':
            if (mode != UNKNOWN && mode != COMPACT) usage(argv[0]);
            reindextiers = strarray_split(optarg, ",", 0);
            mode = COMPACT;
            break;

        case 'u':
            user_mode = 1;
            break;

        case 'h':
        default:
            usage("squatter");
        }
    }

    if (xapindexed_mode) {
        /* we have two different flag types for the two different modes,
         * set both of them even though only one will be used */
        compact_flags |= SEARCH_COMPACT_XAPINDEXED;
    }

    compact_flags |= SEARCH_VERBOSE(verbose);

    if (mode == UNKNOWN)
        mode = INDEXER;

    if (mode == COMPACT && (!desttier || !srctiers)) {
        /* need both src and dest for compact */
        usage("squatter");
    }

    cyrus_init(alt_config, "squatter", init_flags, CONFIG_NEED_PARTITION_DATA);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&squat_namespace, 1)) != 0) {
        fatal(error_message(r), EX_CONFIG);
    }

    /* make sure we're correctly configured */
    if ((r = search_check_config(&errstr))) {
        if (errstr)
            fatal(errstr, EX_CONFIG);
        else
            fatal(error_message(r), EX_CONFIG);
    }

    if (mode == ROLLING || mode == SYNCLOG) {
        signals_set_shutdown(&shut_down);
        signals_add_handlers(0);
    }

    index_text_extractor_init(NULL);

    const char *conf;
    conf = config_getstring(IMAPOPT_SEARCH_INDEX_SKIP_DOMAINS);
    if (conf) skip_domains = strarray_split(conf, " ", STRARRAY_TRIM);
    conf = config_getstring(IMAPOPT_SEARCH_INDEX_SKIP_USERS);
    if (conf) skip_users = strarray_split(conf, " ", STRARRAY_TRIM);

    switch (mode) {
    case UNKNOWN:
        break;
    case INDEXER:
        /* -r requires at least one mailbox */
        if (recursive_flag && optind == argc) usage(argv[0]);
        expand_mboxnames(&mboxnames, argc-optind, (const char **)argv+optind, user_mode);
        syslog(LOG_NOTICE, "indexing mailboxes");
        r = do_indexer(&mboxnames);
        syslog(LOG_NOTICE, "done indexing mailboxes");
        break;
    case SEARCH:
        if (recursive_flag && optind == argc) usage(argv[0]);
        expand_mboxnames(&mboxnames, argc-optind, (const char **)argv+optind, user_mode);
        r = do_search(query, !multi_folder, &mboxnames);
        break;
    case ROLLING:
        if (background && !getenv("CYRUS_ISDAEMON"))
            become_daemon();
        do_rolling(channel);
        /* never returns */
        break;
    case SYNCLOG:
        r = do_synclogfile(synclogfile);
        break;
    case COMPACT:
        if (recursive_flag && optind == argc) usage(argv[0]);
        expand_mboxnames(&mboxnames, argc-optind, (const char **)argv+optind, user_mode);
        r = do_compact(&mboxnames, reindextiers, srctiers, desttier, compact_flags);
        break;
    case AUDIT:
        if (recursive_flag && optind == argc) usage(argv[0]);
        expand_mboxnames(&mboxnames, argc-optind, (const char **)argv+optind, user_mode);
        r = do_audit(&mboxnames);
        break;
    case LIST:
        if (recursive_flag && optind == argc) usage(argv[0]);
        expand_mboxnames(&mboxnames, argc-optind, (const char **)argv+optind, user_mode);
        r = do_list(&mboxnames);
        break;
    }

    strarray_fini(&mboxnames);
    shut_down(r ? EX_TEMPFAIL : 0);
}
