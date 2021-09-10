/* ptloader.c -- group loader daemon
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

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

#include "auth_pts.h"
#include "cyrusdb.h"
#include "imap/global.h"
#include "libconfig.h"
#include "retry.h"
#include "xmalloc.h"
#include "ptloader.h"

struct pts_module *pts_modules[] = {
#ifdef USE_HTTPPTS
    &pts_http,
#endif
#ifdef HAVE_LDAP
    &pts_ldap,
#endif
#ifdef HAVE_AFSKRB
    &pts_afskrb,
#endif
    NULL };

extern void setproctitle_init(int argc, char **argv, char **envp);

static struct pts_module *pts_fromname()
{
    int i;
    const char *name = config_getstring(IMAPOPT_PTS_MODULE);
    static struct pts_module *pts = NULL;

    if (pts)
        return pts;

    for (i = 0; pts_modules[i]; i++) {
        if (!strcmp(pts_modules[i]->name, name)) {
            pts = pts_modules[i]; break;
        }
    }

    if (!pts) {
        char errbuf[1024];
        snprintf(errbuf, sizeof(errbuf),
                 "PTS module %s not supported", name);
        fatal(errbuf, EX_CONFIG);
    }

    return pts;
}

void ptsmodule_init(void)
{
    struct pts_module *pts = pts_fromname();

    pts->init();
}

struct auth_state *ptsmodule_make_authstate(const char *identifier,
                                            size_t size,
                                            const char **reply, int *dsize)
{
    struct pts_module *pts = pts_fromname();

    return pts->make_authstate(identifier, size, reply, dsize);
}

/* config.c info (libimap) */
const int config_need_data = 0;

static char ptclient_debug = 0;
struct db *ptsdb = NULL;

int service_init(int argc, char *argv[], char **envp __attribute__((unused)))
{
    int r;
    int opt;
    extern char *optarg;
    const char *fname;
    char *tofree = NULL;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);
    setproctitle_init(argc, argv, envp);

    /* set signal handlers */
    signal(SIGPIPE, SIG_IGN);

    syslog(LOG_NOTICE, "starting: ptloader.c %s", PACKAGE_VERSION);

    while ((opt = getopt(argc, argv, "d:")) != EOF) {
        switch (opt) {
        case 'd':
            ptclient_debug = atoi(optarg);
            if (ptclient_debug < 1) {
                ptclient_debug = 1;
            }
            break;
        default:
            syslog(LOG_ERR, "invalid command line option specified");
            break;
            /* just pass through */
        }
    }

    fname = config_getstring(IMAPOPT_PTSCACHE_DB_PATH);
    if (!fname) {
        tofree = strconcat(config_dir, PTS_DBFIL, NULL);
        fname = tofree;
    }

    r = cyrusdb_open(config_ptscache_db, fname, CYRUSDB_CREATE, &ptsdb);
    if (r != 0) {
        syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
               cyrusdb_strerror(r));
        fatal("can't read pts database", EX_TEMPFAIL);
    }

    if (tofree) free(tofree);

    ptsmodule_init();

    return 0;
}

/* Called by service API to shut down the service */
void service_abort(int error)
{
    int r;

    r = cyrusdb_close(ptsdb);
    if (r) {
        syslog(LOG_ERR, "DBERROR: error closing ptsdb: %s",
               cyrusdb_strerror(r));
    }

    cyrusdb_done();

    exit(error);
}

/* we're a 'threaded' service, but since we never fork or create any
   threads, we're just one-person-at-a-time based */
int service_main_fd(int c, int argc __attribute__((unused)),
                    char **argv __attribute__((unused)),
                    char **envp __attribute__((unused)))
{
    const char *reply = NULL;
    char user[PTS_DB_KEYSIZE];
    int rc, dsize;
    size_t size;
    struct auth_state *newstate;

    (void)memset(&size, 0, sizeof(size));
    if (read(c, &size, sizeof(size_t)) < 0) {
        syslog(LOG_ERR, "socket (size): %m");
        reply = "Error reading request (size)";
        goto sendreply;
    }

    if (size > PTS_DB_KEYSIZE)  {
        syslog(LOG_ERR, "size sent %d is greater than buffer size %d",
               (int)size, PTS_DB_KEYSIZE);
        reply = "Error: invalid request size";
        goto sendreply;
    }

    if (size == 0) {
        syslog(LOG_ERR, "size sent is 0");
        reply = "Error: zero request size";
        goto sendreply;
    }

    memset(&user, 0, sizeof(user));
    if (read(c, &user, size) < 0) {
        syslog(LOG_ERR, "socket(user; size = %d): %m", (int)size);
        reply = "Error reading request (user)";
        goto sendreply;
    }

    if (ptclient_debug) {
        syslog(LOG_DEBUG, "user %s", user);
    }

    newstate = ptsmodule_make_authstate(user, size, &reply, &dsize);

    if(newstate) {
        /* Success! */
        rc = cyrusdb_store(ptsdb, user, size, (void *)newstate, dsize, NULL);
        (void)rc;
        free(newstate);

        /* and we're done */
        reply = "OK";
    } else {
        /* Failure */
        if ( reply == NULL ) {
            reply = "Error making authstate";
        }
    }

 sendreply:
    if (retry_write(c, reply, strlen(reply) + 1) <0) {
        syslog(LOG_WARNING, "retry_write: %m");
    }
    close(c);

    return 0;
}

/* we need to have this function here 'cause libcyrus.la
 * makes calls to this function.
 */
EXPORTED void fatal(const char *msg, int exitcode)
{
    syslog(LOG_ERR, "%s", msg);
    exit(exitcode);
}

