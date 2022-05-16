/* ipurge.c - delete mail from cyrus imap mailbox or partition
 *            based on date (or size?)
 *
 * includes support for ISPN virtual host extensions
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
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <sysexits.h>
#include <syslog.h>
#include <string.h>
#include <netinet/in.h>

/* cyrus includes */
#include "global.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* globals for callback functions */
static int days = -1;
static int size = -1;
static int exact = -1;
static int skipflagged = 0;
static int onlydeleted = 0;
static int use_sentdate = 1;
static int invertmatch = 0;

/* for statistical purposes */
typedef struct mbox_stats_s {
    uint64_t total;         /* total including those deleted */
    uint64_t total_bytes;
    uint64_t deleted;
    uint64_t deleted_bytes;
} mbox_stats_t;

static int dryrun = 0;
static int verbose = 0;
static int forceall = 0;

/* current namespace */
static struct namespace purge_namespace;

static int purge_findall(struct findall_data *, void *);
static unsigned purge_check(struct mailbox *mailbox,
                            const struct index_record *record,
                            void *rock);
static void expand_mboxnames(int nmboxnames, const char **mboxnames);
static int usage(const char *name);
static void print_record(struct mailbox *mailbox,
                         const struct index_record *record);
static void print_stats(mbox_stats_t *stats);

int main (int argc, char *argv[]) {
    char *alt_config = NULL;
    int matchmailbox = 0;
    int r, opt;

    /* keep this in alphabetical order */
    static const char *const short_options = "C:MXb:d:fhik:m:nosvx";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "no-recursive", no_argument, NULL, 'M' },
        { "delivery-time", no_argument, NULL, 'X' },
        { "bytes", required_argument, NULL, 'b' },
        { "days", required_argument, NULL, 'd' },
        { "include-user-mailboxes", no_argument, NULL, 'f' },
        { "invert-match", no_argument, NULL, 'i' },
        { "kbytes", required_argument, NULL, 'k' },
        { "mbytes", required_argument, NULL, 'm' },
        { "dry-run", no_argument, NULL, 'n' },
        { "only-deleted", no_argument, NULL, 'o' },
        { "skip-flagged", no_argument, NULL, 's' },
        { "verbose", no_argument, NULL, 'v' },
        { "exact-match", no_argument, NULL, 'x' },
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        case 'd':
            if (optarg == 0) {
                usage(argv[0]);
            }
            days = atoi(optarg) * 86400 /* nominal # of seconds in a 'day' */;
            break;
        case 'b':
            if (optarg == 0) {
                usage(argv[0]);
            }
            size = atoi(optarg);
            break;
        case 'k':
            if (optarg == 0) {
                usage(argv[0]);
            }
            size = atoi(optarg) * 1024; /* make it bytes */
            break;
        case 'm':
            if (optarg == 0) {
                usage(argv[0]);
            }
            size = atoi(optarg) * 1048576; /* 1024 * 1024 */
            break;
        case 'n':
            dryrun = 1;
            break;
        case 'v':
            verbose++;
            break;
        case 'x':
            exact = 1;
            break;
        case 'f':
            forceall = 1;
            break;
        case 's':
            skipflagged = 1;
            break;
        case 'M':
            matchmailbox = 1;
            break;
        case 'X':
            use_sentdate = 0;
            break;
        case 'i':
            invertmatch = 1;
            break;
        case 'o':
            onlydeleted = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }
    if ((days == -1 ) && (size == -1)) {
        printf("One of these must be specified -d, -b -k, -m\n");
        usage(argv[0]);
    }

    cyrus_init(alt_config, "ipurge", 0, CONFIG_NEED_PARTITION_DATA);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&purge_namespace, 1)) != 0) {
        fatal(error_message(r), EX_CONFIG);
    }
    mboxevent_setnamespace(&purge_namespace);

    if (optind == argc) { /* do the whole partition */
        mboxlist_findall(NULL, "*", 1, 0, 0, purge_findall, NULL);
    } else if (matchmailbox) {
        expand_mboxnames(argc-optind, (const char **)argv+optind);
    } else {
        /* do all matching mailboxes in one pass */
        strarray_t *array = strarray_new();
        for (; optind < argc; optind++) {
            strarray_append(array, argv[optind]);
        }
        if (array->count)
            mboxlist_findallmulti(NULL, array, 1, 0, 0, purge_findall, NULL);
        strarray_free(array);
    }

    cyrus_done();

    return 0;
}

static int usage(const char *name)
{
    printf("usage: %s [-f] [-s] [-C <alt_config>] [-x] [-X] [-i] [-o] [-n] {-d days | -b bytes|-k Kbytes|-m Mbytes}\n\t[mboxpattern1 ... [mboxpatternN]]\n", name);
    printf("\tthere are no defaults and at least one of -d, -b, -k, -m\n\tmust be specified\n");
    printf("\tif no mboxpattern is given %s works on all mailboxes\n", name);
    printf("\t -x specifies an exact match for days or size\n");
    printf("\t -f force also to delete mail below user.* and INBOX.*\n");
    printf("\t -s skip over messages that are flagged.\n");
    printf("\t -X use delivery time instead of date header for date matches.\n");
    printf("\t -i invert match logic: -x means not equal, date is for newer, size is for smaller.\n");
    printf("\t -M don't recurse mailboxes.\n");
    printf("\t -o only purge messages that are deleted.\n");
    printf("\t -n only print messages that would be deleted (dry run).\n");
    printf("\t -v enable verbose output/logging.\n");
    exit(0);
}

/* we don't check what comes in on matchlen and category, should we? */
static int purge_one(const mbname_t *mbname)
{
    struct mailbox *mailbox = NULL;
    int r;
    mbox_stats_t stats;
    const char *name = mbname_intname(mbname);

    if (!forceall) {
        /* DON'T purge INBOX* and user.* */
        if (mbname_userid(mbname))
            return 0;
    }

    memset(&stats, '\0', sizeof(mbox_stats_t));

    if (verbose) {
        printf("Working on %s...\n", name);
    }

    r = mailbox_open_iwl(name, &mailbox);
    if (r) { /* did we find it? */
        syslog(LOG_ERR, "Couldn't find %s, check spelling", name);
        return r;
    }

    mailbox_expunge(mailbox, purge_check, &stats, NULL, EVENT_MESSAGE_EXPUNGE);

    mailbox_close(&mailbox);

    print_stats(&stats);

    return 0;
}

static int purge_findall(struct findall_data *data, void *rock __attribute__((unused)))
{
    if (!data) return 0;
    if (!data->is_exactmatch) return 0;
    return purge_one(data->mbname);
}

static int purge_mbentry(const mbentry_t *mbentry, void *rock __attribute__((unused)))
{
    mbname_t *mbname = mbname_from_intname(mbentry->name);
    int r = purge_one(mbname);
    mbname_free(&mbname);
    return r;
}

static void expand_mboxnames(int nmboxnames, const char **mboxnames)
{
    int i;

    for (i = 0; i < nmboxnames; i++) {
        /* Translate any separators in mailboxname */
        char *intname = mboxname_from_external(mboxnames[i], &purge_namespace, NULL);
        mboxlist_mboxtree(intname, purge_mbentry, NULL, MBOXTREE_SKIP_CHILDREN);
        free(intname);
    }
}


static void deleteit(bit32 msgsize, mbox_stats_t *stats)
{
    stats->deleted++;
    stats->deleted_bytes += msgsize;
}

/* thumbs up routine, checks date & size and returns yes or no for deletion */
/* 0 = no, 1 = yes */
static unsigned purge_check(struct mailbox *mailbox,
                            const struct index_record *record,
                            void *deciderock)
{
    time_t my_time;
    time_t senttime;
    mbox_stats_t *stats = (mbox_stats_t *) deciderock;

    my_time = time(0);
    senttime = use_sentdate ? record->sentdate : record->internaldate;

    stats->total++;
    stats->total_bytes += record->size;

    if (skipflagged && record->system_flags & FLAG_FLAGGED)
        return 0;

    if (onlydeleted && !(record->system_flags & FLAG_DELETED))
        return 0;

    if (exact == 1) {
        if (days >= 0) {
            /* printf("comparing %ld :: %ld\n", my_time, the_record->sentdate); */
            if (((my_time - (time_t) senttime)/86400) == (days/86400)) {
                if (invertmatch) return 0;
                deleteit(record->size, stats);
                return dryrun ? (void)print_record(mailbox, record), 0 : 1;
            } else {
                if (!invertmatch) return 0;
                deleteit(record->size, stats);
                return dryrun ? (void)print_record(mailbox, record), 0 : 1;
            }
        }
        if (size >= 0) {
            /* check size */
            if (record->size == (unsigned)size) {
                if (invertmatch) return 0;
                deleteit(record->size, stats);
                return dryrun ? (void)print_record(mailbox, record), 0 : 1;
            } else {
                if (!invertmatch) return 0;
                deleteit(record->size, stats);
                return dryrun ? (void)print_record(mailbox, record), 0 : 1;
            }
        }
        return 0;
    } else {
        if (days >= 0) {
            /* printf("comparing %ld :: %ld\n", my_time, the_record->sentdate); */
            if (!invertmatch && ((my_time - (time_t) senttime) > days)) {
                deleteit(record->size, stats);
                return dryrun ? (void)print_record(mailbox, record), 0 : 1;
            }
            if (invertmatch && ((my_time - (time_t) senttime) < days)) {
                deleteit(record->size, stats);
                return dryrun ? (void)print_record(mailbox, record), 0 : 1;
            }
        }
        if (size >= 0) {
            /* check size */
            if (!invertmatch && ((int) record->size > size)) {
                deleteit(record->size, stats);
                return dryrun ? (void)print_record(mailbox, record), 0 : 1;
            }
                if (invertmatch && ((int) record->size < size)) {
                deleteit(record->size, stats);
                return dryrun ? (void)print_record(mailbox, record), 0 : 1;
            }
        }
        return 0;
    }
}

static void print_record(struct mailbox *mailbox,
                         const struct index_record *record)
{
    printf("UID: %u\n", record->uid);
    printf("\tSize: %u\n", record->size);
    printf("\tSent: %s", ctime(&record->sentdate));
    printf("\tRecv: %s", ctime(&record->internaldate));

    if (mailbox_cacherecord(mailbox, record)) {
        printf("\tERROR: cache record missing or corrupt, "
               "not printing cache details\n\n");
        return;
    }

    printf("\tFrom: %.*s\n", cacheitem_size(record, CACHE_FROM),
            cacheitem_base(record, CACHE_FROM));
    printf("\tTo  : %.*s\n", cacheitem_size(record, CACHE_TO),
            cacheitem_base(record, CACHE_TO));
    printf("\tCc  : %.*s\n", cacheitem_size(record, CACHE_CC),
            cacheitem_base(record, CACHE_CC));
    printf("\tBcc : %.*s\n", cacheitem_size(record, CACHE_BCC),
            cacheitem_base(record, CACHE_BCC));
    printf("\tSubj: %.*s\n\n", cacheitem_size(record, CACHE_SUBJECT),
            cacheitem_base(record, CACHE_SUBJECT));
}

static void print_stats(mbox_stats_t *stats)
{
    printf("Total messages    \t\t %llu\n", (long long unsigned)stats->total);
    printf("Total bytes       \t\t %llu\n", (long long unsigned)stats->total_bytes);
    printf("Deleted messages  \t\t %llu\n", (long long unsigned)stats->deleted);
    printf("Deleted bytes     \t\t %llu\n", (long long unsigned)stats->deleted_bytes);
    printf("Remaining messages\t\t %llu\n",
           (long long unsigned)stats->total - stats->deleted);
    printf("Remaining bytes   \t\t %llu\n",
           (long long unsigned)stats->total_bytes - stats->deleted_bytes);
}
