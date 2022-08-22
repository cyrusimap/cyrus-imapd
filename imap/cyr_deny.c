/* cyr_deny.c - tool to manipulate the deny database
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

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <syslog.h>
#include <signal.h>

#include "global.h"
#include "libcyr_cfg.h"
#include "proc.h"
#include "userdeny.h"
#include "util.h"
#include "ptrarray.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

static void usage(void)
{
    fprintf(stderr, "Usage: cyr_deny [-C <altconfig>] [ -s services ] [ -m message ] user\n");
    fprintf(stderr, "       cyr_deny [-C <altconfig>] -a user\n");
    fprintf(stderr, "       cyr_deny [-C <altconfig>] -l\n");
    exit(EX_USAGE);
}

static int list_one(const char *user, const char *services,
                    const char *message,
                    void *rock __attribute__((unused)))
{
    printf("%-30s %-20s %s\n", user, services, message);
    return 0;
}

struct kill_rock
{
    const char *user;
    ptrarray_t pids;
};

/*
 * We use proc_foreach() to kill any existing servers which are serving
 * the user.  There are two problems with this approach.
 *
 * - proc_foreach() reads a directory full of files, which is inherently racy
 *
 * - the proc file does not contain the service identifier of the process that
 *   wrote it; the only mapping between those and pids is in those processes
 *   themselves and in the master process.
 *
 * The first problem we can live with, the raciness is no worse than
 * running 'cyr_info proc' and grepping the results.
 *
 * The second problem means that we have no way cleanly to support the
 * existing userdeny feature of denying users access to only some services.
 * Without a clear idea of which service a pid represents, we cannot helpfully
 * kill the existing processes for only some of the services. Instead we have
 * to kill all the processes for the user, and hope any others will reconnect.
 */
static int gather_one(pid_t pid,
                      const char *servicename __attribute__((unused)),
                      const char *clienthost __attribute__((unused)),
                      const char *userid,
                      const char *mailbox __attribute__((unused)),
                      const char *cmdname __attribute__((unused)),
                      void *rock)
{
    struct kill_rock *kr = (struct kill_rock *)rock;

    if (!strcmp(userid, kr->user))
        ptrarray_append(&kr->pids, xmemdup(&pid, sizeof(pid)));
    return 0;
}

static void kill_existing_services(const char *user)
{
    struct kill_rock kr = { NULL, PTRARRAY_INITIALIZER };
    int delay = 1;
    int i;
    int *pidp;
    int sig;
    int prejudice = 0;
    int probing = 0;
    int r;

    kr.user = user;
    proc_foreach(gather_one, &kr);

    /*
     * Send a graceful shutdown message to all the processes and wait
     * for them to die.  This is a poor approximation of the correct
     * behaviour, which can only be done in the master process (but we
     * currently have no way to tell it to do so).
     */
    for (;;) {

        /* send all the pids a signal */
        for (i = 0 ; i < kr.pids.count ; i++) {
            pidp = (int *)kr.pids.data[i];
            sig = (probing ? 0 : (prejudice ? SIGKILL : SIGTERM));
            r = kill(*pidp, sig);
            if (r < 0) {
                /* gone (yay!) or some error */
                ptrarray_remove(&kr.pids, i);
                free(pidp);
                continue;
            }
        }
        if (!kr.pids.count)
            break;

        probing = 1;

        sleep(delay);
        delay *= 2;
        if (delay > 8) {
            if (prejudice++) {
                syslog(LOG_ALERT, "cannot kill some processes even with SIGKILL");
                break;
            }
            delay = 1;
            probing = 0;
        }
    }

    ptrarray_fini(&kr.pids);
}

int main(int argc, char **argv)
{
    int opt;
    enum { DENY, ALLOW, LIST } mode = DENY;
    const char *alt_config = NULL;
    const char *user = NULL;
    const char *message = NULL;
    const char *services = NULL;
    int r;

    /* keep this in alphabetical order */
    static const char *const short_options = "C:alm:s:";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "allow", no_argument, NULL, 'a' },
        { "list", no_argument, NULL, 'l' },
        { "message", required_argument, NULL, 'm' },
        { "services", required_argument, NULL, 's' },
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'a':
            if (mode != DENY) usage();
            mode = ALLOW;
            break;

        case 'l':
            if (mode != DENY) usage();
            mode = LIST;
            break;

        case 'm':
            message = optarg;
            break;

        case 's':
            services = optarg;
            break;

        default:
            usage();
            break;
        }
    }
    if (mode != DENY && (message || services))
        usage();

    if (mode == LIST) {
        if (optind != argc)
            usage();
    }
    else {
        if (optind != argc-1)
            usage();
        user = argv[optind];
    }

    cyrus_init(alt_config, "cyr_deny", 0, 0);

    denydb_init(0);

    r = denydb_open(/*create*/(mode == DENY));
    if (r) {
        if (mode != DENY && r == IMAP_NOTFOUND)
            r = 0;
        else
            fprintf(stderr, "cyr_deny: failed to open deny db: %s\n",
                    error_message(r));
        goto out;
    }

    switch (mode) {
    case ALLOW:
        r = denydb_delete(user);
        if (r)
            fprintf(stderr, "cyr_deny: failed to allow access for %s: %s\n",
                    user, error_message(r));
        break;
    case DENY:
        r = denydb_set(user, services, message);
        if (r)
            fprintf(stderr, "cyr_deny: failed to deny access for %s: %s\n",
                    user, error_message(r));
        else
            kill_existing_services(user);
        break;
    case LIST:
        printf("%-30s %-20s %s\n", "Username", "Service(s)", "Message");
        r = denydb_foreach(list_one, NULL);
        if (r)
            fprintf(stderr, "cyr_deny: failed to list entries: %s\n",
                    error_message(r));
        break;
    }

    denydb_close();
out:
    denydb_done();
    return !!r;
}
