/* jmap_expire.c -- Program to clean up stale JMAP data
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

#include <config.h>

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <stdlib.h>
#include <sysexits.h>

#include "global.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define SECS_IN_A_MIN 60
#define SECS_IN_AN_HR (60 * SECS_IN_A_MIN)
#define SECS_IN_A_DAY (24 * SECS_IN_AN_HR)

#define LOCK_MINSECS 1
#define LOCK_MAXSECS SECS_IN_AN_HR

/* global state */
static int verbose = 0;
static const char *progname = NULL;
static struct namespace expire_namespace; /* current namespace */

struct args {
    const char *altconfig;
    int expire_seconds;
    int unlink_seconds;
    int lock_seconds;
    strarray_t userids;
};

#define VERBOSE_INFO  1
#define VERBOSE_TRACE 2
#define VERBOSE_DEBUG 3

/* verbosep - a wrapper to print if the 'verbose' option is
   turned on.  */
__attribute__((format(printf, 1, 2)))
static inline void verbosep(const char *fmt, ...)
{
    va_list params;

    if (!verbose) return;

    va_start(params, fmt);
    vfprintf(stderr, fmt, params);
    va_end(params);
    fputc('\n', stderr);
}

struct jmapnotif_rock {
    const struct args *args;
    time_t expire_before;
    time_t unlink_before;
    unsigned lock_millis;
    unsigned nexpired;
};

static unsigned expire_jmapnotifs_cb(struct mailbox *mailbox,
                                     const struct index_record *record,
                                     void *vrock)
{
    struct jmapnotif_rock *rock = vrock;

    /* we're expiring messages by sent date */
    if (record->gmtime < rock->expire_before) {
        if (verbose >= VERBOSE_TRACE) {
            verbosep("%s: expiring uid %d", mailbox_name(mailbox), record->uid);
        }
        rock->nexpired++;
        return 1;
    }

    return 0;
}

static void add_millis(struct timespec *t, unsigned ms)
{
    t->tv_sec += ms / 1000L;
    t->tv_nsec += (ms % 1000L) * 1000000L;
    if (t->tv_nsec >= 1000000000L) {
        t->tv_sec++;
        t->tv_nsec %= 1000000000L;
    }
}

static void print_lock(const char *mboxname,
                       struct timespec start,
                       struct timespec until)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        verbosep("%s: lock info: start=%lld.%ld until=%lld.%ld now=%lld.%ld",
                mboxname,
                (long long)start.tv_sec, start.tv_nsec / 1000000L,
                (long long)until.tv_sec, until.tv_nsec / 1000000L,
                (long long)now.tv_sec, now.tv_nsec / 1000000L);
    }
}

static int expire_jmapnotifs(const mbentry_t *mbentry, void *vrock)
{
    signals_poll();

    if (mbentry->mbtype & MBTYPE_DELETED)
        return 0;

    if (!mboxname_isjmapnotificationsmailbox(mbentry->name, mbentry->mbtype))
        return 0;

    struct jmapnotif_rock *rock = vrock;
    const struct args *args = rock->args;
    struct mailbox *mailbox = NULL;
    unsigned lock_millis = args->lock_seconds * 1000L;

    /* First, unlink previously expired notifications */

    if (args->unlink_seconds >= 0) {
        unsigned nunlinked = 0;
        struct timespec start = {0};
        struct timespec until = {0};

        int r = mailbox_open_iwl(mbentry->name, &mailbox);
        if (r) {
            verbosep("%s: can not open mailbox: %s",
                    mbentry->name, error_message(r));
            goto done;
        }

        if (verbose >= VERBOSE_TRACE) {
            verbosep("%s: expunging mailbox", mbentry->name);
        }

        struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, 0);
        if (lock_millis) {
            clock_gettime(CLOCK_MONOTONIC, &start);
            until = start;
            add_millis(&until, lock_millis);
            mailbox_iter_timer(iter, until, 1000);
        }
        r = mailbox_expunge_cleanup(mailbox, iter,
                rock->unlink_before, &nunlinked);
        if (r) {
            verbosep("%s: failed to unlink notifications %s",
                mbentry->name, error_message(r));
        }
        mailbox_iter_done(&iter);

        mailbox_close(&mailbox);

        if (lock_millis && verbose >= VERBOSE_TRACE) {
            print_lock(mbentry->name, start, until);
        }

        verbosep("%s: unlinked %u notifications", mbentry->name, nunlinked);

        libcyrus_run_delayed(); // TODO(rsto): this should support lock_millis
    }

    /* Next, expire stale notifications */

    if (args->expire_seconds >= 0) {
        rock->nexpired = 0;
        struct timespec start = {0};
        struct timespec until = {0};

        int r = mailbox_open_iwl(mbentry->name, &mailbox);
        if (r) {
            verbosep("%s: can not open mailbox: %s",
                    mbentry->name, error_message(r));
            goto done;
        }

        if (verbose >= VERBOSE_TRACE) {
            verbosep("%s: expiring mailbox", mbentry->name);
        }

        struct mailbox_iter *iter =
            mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
        if (lock_millis) {
            clock_gettime(CLOCK_MONOTONIC, &start);
            until = start;
            add_millis(&until, lock_millis);
            mailbox_iter_timer(iter, until, 1000);
        }
        r = mailbox_expunge(mailbox, iter, expire_jmapnotifs_cb,
                rock, NULL, EVENT_MESSAGE_EXPIRE);
        mailbox_iter_done(&iter);
        if (r) {
            verbosep("%s: failed to expire notifications: %s",
                mbentry->name, error_message(r));
        }

        mailbox_close(&mailbox);

        if (lock_millis && verbose >= VERBOSE_TRACE) {
            print_lock(mbentry->name, start, until);
        }

        verbosep("%s: expired %u notifications", mbentry->name, rock->nexpired);
    }

done:
    mailbox_close(&mailbox);
    return 0;
}

static void do_jmapnotifs(const struct args *args)
{
    struct jmapnotif_rock rock = {.args = args};

    if (args->expire_seconds >= 0) {
        rock.expire_before = time(0) - args->expire_seconds;
    }

    if (args->unlink_seconds >= 0) {
        rock.unlink_before = time(0) - args->unlink_seconds;
    }

    if (strarray_size(&args->userids)) {
        const char *folder = config_getstring(IMAPOPT_JMAPNOTIFICATIONFOLDER);
        if (!folder) {
            verbosep("no jmapnotificationfolder config found in imapd.conf");
            return;
        }

        for (int i = 0; i < strarray_size(&args->userids); i++) {
            const char *userid = strarray_nth(&args->userids, i);
            mbname_t *mbname = mbname_from_userid(userid);
            mbname_push_boxes(mbname, folder);
            mbentry_t *mbentry = NULL;
            int r = mboxlist_lookup_allow_all(mbname_intname(mbname), &mbentry, NULL);
            if (!r) {
                expire_jmapnotifs(mbentry, &rock);
                mboxlist_entry_free(&mbentry);
            }
            else if (r == IMAP_MAILBOX_NONEXISTENT) {
                if (verbose >= VERBOSE_TRACE) {
                    verbosep("%s: ignoring inexistent mailbox",
                            mbname_intname(mbname));
                }
            }
            else {
                verbosep("%s: can not open mailbox: %s",
                        mbname_intname(mbname), error_message(r));
            }
            mbname_free(&mbname);
        }
    }
    else {
        mboxlist_allmbox(NULL, expire_jmapnotifs, &rock, MBOXTREE_SKIP_ROOT);
    }
}

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", progname);
    fprintf(stderr, "Expire stale JMAP data\n");
    fprintf(stderr, "\n");
    fprintf(stderr,
        "Mandatory arguments (at least one required):\n"
        "-E --notif-expire=<dur>    expire notifications older than duration\n"
        "-X --notif-unlink=<dur>    unlink notifications older than duration\n"
        "\n"
        "Optional arguments:\n"
        "-C <config-file>          use <config-file> instead of config from imapd.conf\n"
        "-l, --lock=<duration>     lock mailboxes at most duration seconds\n"
        "-u --user=<userid>        process userid\n"
        "-v, --verbose             enable verbose output\n");
    fprintf(stderr, "\n");

    exit(EX_USAGE);
}

static int parse_args(int argc, char *argv[], struct args *args)
{
    int opt;

    /* keep this in alphabetical order */
    static const char *const short_options = "C:E:X:l:hu:v";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        {"notif-expire", required_argument, NULL, 'E'},
        {"notif-unlink", required_argument, NULL, 'X'},
        {"lock", required_argument, NULL, 'l'},
        {"user", required_argument, NULL, 'u'},
        {"verbose", no_argument, NULL, 'v'},
        {0, 0, 0, 0},
    };

    struct buf buf = BUF_INITIALIZER;
    int dur;

    while (-1 !=
           (opt = getopt_long(argc, argv, short_options, long_options, NULL))) {
        switch (opt) {
        case 'C':
            args->altconfig = optarg;
            break;

        case 'E':
            if (config_parseduration(optarg, 's', &dur) < 0 || dur < 0)
                usage();
            args->expire_seconds = dur;
            break;

        case 'X':
            if (config_parseduration(optarg, 's', &dur) < 0 || dur < 0)
                usage();
            args->unlink_seconds = dur;
            break;

        case 'l':
            if (config_parseduration(optarg, 's', &dur) < 0 || dur < 0)
                usage();
            if (dur < LOCK_MINSECS || dur > LOCK_MAXSECS)
                usage();
            args->lock_seconds = dur;
            break;

        case 'u':
            buf_setcstr(&buf, optarg);
            buf_trim(&buf);
            if (!buf_len(&buf)) {
                fprintf(stderr, "Invalid userid: %s\n", optarg);
                usage();
            }
            strarray_append(&args->userids, buf_cstring(&buf));
            break;

        case 'v':
            verbose++;
            break;

        case 'h':
        default:
            usage();
            break;
        }
    }

    if (args->expire_seconds  == -1 &&
        args->unlink_seconds == -1) {
        fprintf(stderr, "Missing mandatory arguments\n\n");
        usage();
        return -EINVAL;
    }

    buf_free(&buf);

    return 0;
}

static void init(const char *progname, struct args *args)
{
    signals_add_handlers(0);

    cyrus_init(args->altconfig, progname, 0, 0);
    global_sasl_init(1, 0, NULL);
}

static void fini(struct args *args)
{
    strarray_fini(&args->userids);
}

static void shut_down(int code) __attribute__((noreturn));
static void shut_down(int code)
{
    in_shutdown = 1;

    exit(code);
}

int main(int argc, char *argv[])
{
    int exitcode = 0;
    struct args args = {0};
    args.expire_seconds = -1;
    args.unlink_seconds = -1;

    progname = basename(argv[0]);
    if (parse_args(argc, argv, &args) != 0) exit(EXIT_FAILURE);

    init(progname, &args);

    /* Set namespace -- force standard (internal) */
    int r = mboxname_init_namespace(&expire_namespace, 1);
    if (r) {
        verbosep("can not initialize namespace: %s", error_message(r));
        exitcode = EX_CONFIG;
        goto done;
    }

    mboxevent_setnamespace(&expire_namespace);

    do_jmapnotifs(&args);

done:
    fini(&args);
    shut_down(exitcode);
}
