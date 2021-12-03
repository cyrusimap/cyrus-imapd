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
static struct sync_client_state sync_cs = SYNC_CLIENT_STATE_INITIALIZER;
static struct buf tagbuf = BUF_INITIALIZER;

static struct namespace   sync_namespace;

static unsigned flags      = 0;
static int verbose         = 0;
static int verbose_logging = 0;
static int connect_once    = 0;
static int sync_once       = 0;
static int background      = 0;
static int do_compress     = 0;
static int no_copyback     = 0;

static char *prev_userid;

static void shut_down(int code) __attribute__((noreturn));
static void shut_down(int code)
{
    in_shutdown = 1;

    libcyrus_run_delayed();

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
        r = sync_do_reader(&sync_cs, slr);

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

static int do_daemon_work(const char *sync_shutdown_file,
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
    slr = sync_log_reader_create_with_channel(sync_cs.channel);

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
        if ((timeout > 0) && !sync_once &&
            ((single_start - session_start) > (time_t) timeout)) {
            *restartp = RESTART_NORMAL;
            break;
        }

        r = sync_log_reader_begin(slr);
        if (r) {
            if (sync_once) {
                if (r == IMAP_AGAIN) r = 0;
                break;
            }
            /* including specifically r == IMAP_AGAIN */
            if (min_delta > 0) {
                sleep(min_delta);
            } else {
                usleep(100000);    /* 1/10th second */
            }
            continue;
        }

        /* Process the work log */
        if ((r=sync_do_reader(&sync_cs, slr))) {
            syslog(LOG_ERR,
                   "Processing sync log file %s failed: %s",
                   sync_log_reader_get_file_name(slr), error_message(r));
            break;
        }

        r = sync_log_reader_end(slr);
        if (r) break;

        // if we're only ever supposed to process the file once, break now
        if (sync_once) break;

        delta = time(NULL) - single_start;

        if (((unsigned) delta < min_delta) && ((min_delta-delta) > 0))
            sleep(min_delta-delta);
    }
    sync_log_reader_free(slr);

    if (*restartp == RESTART_NORMAL && !sync_once) {
        r = sync_do_restart(&sync_cs);
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

static void replica_connect(void)
{
    static int maxwait = 0;
    int wait;

    if (!maxwait)
        maxwait = config_getduration(IMAPOPT_SYNC_RECONNECT_MAXWAIT, 's');

    for (wait = 15;; wait *= 2) {
        int r = sync_connect(&sync_cs);
        if (r != IMAP_AGAIN) break;

        signals_poll();

        if (maxwait > 0 && wait > maxwait)
            wait = maxwait;

        fprintf(stderr,
                "Can not connect to server '%s', retrying in %d seconds\n",
                servername, wait);
        sleep(wait);
    }

    if (!sync_cs.backend) {
        fprintf(stderr, "Can not connect to server '%s'\n",
                servername);
        syslog(LOG_ERR, "Can not connect to server '%s'", servername);
        _exit(1);
    }

#ifdef HAVE_ZLIB
    if (do_compress && !sync_cs.backend->in->zstrm) {
        fprintf(stderr, "Failed to enable compression to server '%s'\n",
                servername);
        syslog(LOG_ERR, "Failed to enable compression to server '%s'",
                servername);
        _exit(1);
    }
#endif

    if (1) {
        /* Assume we support #sieve until we have in-protocol detection */
        sync_cs.flags |= SYNC_FLAG_SIEVE_MAILBOX;
    }

    if (verbose > 1) {
        prot_setlog(sync_cs.backend->in, fileno(stderr));
        prot_setlog(sync_cs.backend->out, fileno(stderr));
    }

    if (no_copyback) {
        const char *cmd = "FORCE";
        struct dlist *kl = dlist_newkvlist(NULL, cmd);
        struct dlist *kin = NULL;
        sync_send_apply(kl, sync_cs.backend->out);
        int r = sync_parse_response(cmd, sync_cs.backend->in, &kin);
        if (r) {
            syslog(LOG_ERR, "SYNCERROR: failed to enable force mode");
            _exit(1);
        }
        dlist_free(&kl);
        dlist_free(&kin);
    }
}

static void replica_disconnect(void)
{
    sync_disconnect(&sync_cs);
    free(sync_cs.backend);
    sync_cs.backend = NULL;
}

static void do_daemon(const char *sync_shutdown_file,
                      unsigned long timeout, unsigned long min_delta)
{
    int r = 0;
    int restart = 1;

    signal(SIGPIPE, SIG_IGN); /* don't fail on server disconnects */

    while (restart) {
        replica_connect();
        r = do_daemon_work(sync_shutdown_file,
                           timeout, min_delta, &restart);
        if (r && !sync_once) {
            /* See if we're still connected to the server.
             * If we are, we had some type of error, so we exit.
             * Otherwise, try reconnecting.
             */
            if (!backend_ping(sync_cs.backend, NULL)) restart = 1;
        }
        replica_disconnect();
        libcyrus_run_delayed();
    }
}

static int do_mailbox(const char *mboxname)
{
    struct sync_name_list *list = sync_name_list_create();
    int r;

    sync_name_list_add(list, mboxname);

    r = sync_do_mailboxes(&sync_cs, list, NULL, sync_cs.flags);

    sync_name_list_free(&list);

    return r;
}

static int cb_allmbox(const mbentry_t *mbentry, void *rock __attribute__((unused)))
{
    int r = 0;

    char *userid = mboxname_to_userid(mbentry->name);

    if (userid) {
        /* skip deleted mailboxes only because the are out of order, and you would
         * otherwise have to sync the user twice thanks to our naive logic */
        if (mboxname_isdeletedmailbox(mbentry->name, NULL))
            goto done;

        /* only sync if we haven't just done the user */
        if (strcmpsafe(userid, prev_userid)) {
            r = sync_do_user(&sync_cs, userid, NULL);
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
        r = do_mailbox(mbentry->name);
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

    while ((opt = getopt(argc, argv, "C:vlLS:F:f:w:t:d:n:rRumsozOAp:1")) != EOF) {
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

        case '1':  // sync once!
            sync_once = 1;
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

    sync_cs.servername = servername;
    sync_cs.channel = channel;
    sync_cs.flags = flags;

    switch (mode) {
    case MODE_USER:
        /* Open up connection to server */
        replica_connect();

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

                if (sync_do_user(&sync_cs, buf, partition)) {
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
            if (sync_do_user(&sync_cs, argv[i], partition)) {
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
        replica_connect();

        if (mboxlist_allmbox(optind < argc ? argv[optind] : NULL, cb_allmbox, &channel, 0))
            exit_rc = 1;

        replica_disconnect();
        break;

    case MODE_MAILBOX:
        /* Open up connection to server */
        replica_connect();

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
                sync_name_list_add(mboxname_list, intname);
                free(intname);
            }
            fclose(file);
        } else for (i = optind; i < argc; i++) {
            char *intname = mboxname_from_external(argv[i], &sync_namespace, NULL);
            sync_name_list_add(mboxname_list, intname);
            free(intname);
        }

        if (sync_do_mailboxes(&sync_cs, mboxname_list, partition, flags)) {
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
        replica_connect();

        for (i = optind; i < argc; i++) {
            if (sync_do_meta(&sync_cs, argv[i])) {
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
            replica_connect();

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

            do_daemon(sync_shutdown_file, timeout, min_delta);
        }

        break;

    default:
        if (verbose) fprintf(stderr, "Nothing to do!\n");
        break;
    }

    buf_free(&tagbuf);

    libcyrus_run_delayed();

    shut_down(exit_rc);
}
