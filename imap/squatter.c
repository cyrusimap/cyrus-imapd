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

const int SKIP_FUZZ = 60;

static int verbose = 0;
static int incremental_mode = 0;
static int batch_mode = 0;
static int xapindexed_mode = 0;
static int reindex_parts_mode = 0;
static int recursive_flag = 0;
static int annotation_flag = 0;
static int sleepmicroseconds = 0;
static const char *temp_root_dir = NULL;
static search_text_receiver_t *rx = NULL;

static const char *name_starts_from = NULL;

static void shut_down(int code) __attribute__((noreturn));

static int usage(const char *name)
{
    fprintf(stderr,
            "usage: %s [mode] [options] [source]\n"
            "\n"
            "Mode flags: \n"
            "  none        index [source] (default)\n"
            "  -a          index [source] using /squat annotations\n"
            "  -r          index [source] recursively\n"
            "  -f file     index from synclog file\n"
            "  -I file     index mbox/uids in file\n"
            "  -R          start rolling indexer\n"
            "  -z tier     compact to tier\n"
            "\n"
            "Index mode options:\n"
            "  -i          index incrementally\n"
            "  -N name     index mailbox names starting with name\n"
            "  -S seconds  sleep seconds between indexing mailboxes\n"
            "  -P          reindex body parts\n"
            "  -Z          Xapian: use internal index rather than cyrus.indexed.db\n"
            "\n"
            "Index sources:\n"
            "  none        all mailboxes (default)\n"
            "  mailbox...  index mailboxes\n"
            "  -u user...  index mailboxes of users\n"
            "\n"
            "Rolling indexer options:\n"
            "  -n channel  listen to channel\n"
            "  -d          don't background process\n"
            "\n"
            "Compact mode options:\n"
            "  -t tier...  compact from tiers\n"
            "  -F          filter during compaction\n"
            "  -T dir      use temporary directory dir during compaction\n"
            "  -X          reindex during compaction (including body parts)\n"
            "  -o          copy db rather compacting\n"
            "  -U          only compact if re-indexing\n"
            "\n"
            "General options:\n"
            "  -v          be verbose\n"
            "  -h          show usage\n",
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
    dup2(nullfd, 0);
    dup2(nullfd, 1);
    dup2(nullfd, 2);
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
    mbentry_t *mbentry = NULL;
    /* Skip remote mailboxes */
    int r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) {
        /* Convert internal name to external */
        char *extname = mboxname_to_external(name, &squat_namespace, NULL);
        if (verbose) {
            printf("error looking up %s: %s\n",
                   extname, error_message(r));
        }
        syslog(LOG_INFO, "error looking up %s: %s\n",
               extname, error_message(r));

        free(extname);
        return 0;
    }

    // skip remote or not-real mailboxes
    if (mbentry->mbtype & (MBTYPE_REMOTE|MBTYPE_DELETED|MBTYPE_INTERMEDIATE)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    // skip COLLECTION mailboxes (just files)
    if (mbentry->mbtype & MBTYPE_COLLECTION) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    mboxlist_entry_free(&mbentry);
    return 1;
}

/* ====================================================================== */

/* This is called once for each mailbox we're told to index. */
static int index_one(const char *name, int blocking)
{
    struct mailbox *mailbox = NULL;
    int r;
    int flags = 0;

    if (incremental_mode)
        flags |= SEARCH_UPDATE_INCREMENTAL;
    if (batch_mode)
        flags |= SEARCH_UPDATE_BATCH;
    if (xapindexed_mode)
        flags |= SEARCH_UPDATE_XAPINDEXED;
    if (reindex_parts_mode)
        flags |= SEARCH_UPDATE_REINDEX_PARTS;

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
        syslog(LOG_INFO, "error opening %s: %s\n", extname, error_message(r));
        free(extname);

        return r;
    }

    syslog(LOG_INFO, "indexing mailbox %s... ", extname);
    if (verbose > 0) {
        printf("Indexing mailbox %s... ", extname);
    }

    r = search_update_mailbox(rx, mailbox, flags);

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

    if (strcmpsafe(mbentry->name, name_starts_from) < 0)
        return 0;
    if (mboxname_isdeletedmailbox(mbentry->name, NULL))
        return 0;

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

static int compact_mbox(const char *userid, const strarray_t *srctiers,
                        const char *desttier, int flags)
{
    return search_compact(userid, temp_root_dir, srctiers, desttier, flags);
}

static int do_compact(const strarray_t *mboxnames, const strarray_t *srctiers,
                      const char *desttier, int flags)
{
    char *prev_userid = NULL;
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

        r = compact_mbox(userid, srctiers, desttier, flags);
        if (r) break;

        free(prev_userid);
        prev_userid = userid;

        if (sleepmicroseconds)
            usleep(sleepmicroseconds);
    }

    free(prev_userid);
    return r;
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
            if (!mboxname_isdeletedmailbox(args[1], NULL))
                strarray_add(mboxnames, args[1]);
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
                syslog(LOG_ERR, "IOERROR: skipped too many times at %s", mboxname);
                break;
            }
            r = 0;
            /* try again at the end */
            strarray_append(mboxnames, mboxname);
        }
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to index %s: %s",
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
            syslog(LOG_DEBUG, "received SIGHUP, shutting down gracefully\n");
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
    const char *desttier = NULL;
    char *errstr = NULL;
    enum { UNKNOWN, INDEXER, SEARCH, ROLLING, SYNCLOG,
           COMPACT, AUDIT } mode = UNKNOWN;

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:I:N:RUXPZT:S:Fde:f:mn:riavAz:t:ouh")) != EOF) {
        switch (opt) {
        case 'A':
            if (mode != UNKNOWN) usage(argv[0]);
            mode = AUDIT;
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

        case 'P':
            reindex_parts_mode = 1;
            break;

        case 'Z':
            /* we have two different flag types for the two different modes,
             * set both of them even though only one will be used */
            xapindexed_mode = 1;
            compact_flags |= SEARCH_COMPACT_XAPINDEXED;
            break;

        case 'N':
            name_starts_from = optarg;
            break;

        case 'R':               /* rolling indexer */
            if (mode != UNKNOWN) usage(argv[0]);
            mode = ROLLING;
            incremental_mode = 1; /* always incremental if rolling */
            batch_mode = 1;
            break;

        case 'S':               /* sleep time in seconds */
            sleepmicroseconds = (atof(optarg) * 1000000);
            break;

        case 'T':               /* temporary root directory for search */
            temp_root_dir = optarg;
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

        case 'u':
            user_mode = 1;
            break;

        case 'h':
        default:
            usage("squatter");
        }
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
        r = do_compact(&mboxnames, srctiers, desttier, compact_flags);
        break;
    case AUDIT:
        if (recursive_flag && optind == argc) usage(argv[0]);
        expand_mboxnames(&mboxnames, argc-optind, (const char **)argv+optind, user_mode);
        r = do_audit(&mboxnames);
        break;
    }

    strarray_fini(&mboxnames);
    shut_down(r ? EX_TEMPFAIL : 0);
}
