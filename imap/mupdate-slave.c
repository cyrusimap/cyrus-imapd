/* mupdate-slave.c -- cyrus murder database clients
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
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <sysexits.h>
#include <syslog.h>
#include <stdarg.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "prot.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "global.h"
#include "mpool.h"
#include "mupdate.h"
#include "mupdate-client.h"

/* Returns file descriptor of kick socket (or does not return) */
static int open_kick_socket(void)
{
    int r,s,len;
    char fnamebuf[2048];
    struct sockaddr_un srvaddr;
    mode_t oldumask;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
        syslog(LOG_ERR, "socket: %m");
        fatal("socket failed", EX_OSERR);
    }

    strlcpy(fnamebuf, config_dir, sizeof(fnamebuf));
    strlcat(fnamebuf, FNAME_MUPDATE_TARGET_SOCK, sizeof(fnamebuf));

    (void) unlink(fnamebuf);
    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strlcpy(srvaddr.sun_path, fnamebuf, sizeof(srvaddr.sun_path));
    len = strlen(srvaddr.sun_path) + sizeof(srvaddr.sun_family) + 1;
    oldumask = umask((mode_t) 0); /* for Linux */
    r = bind(s, (struct sockaddr *)&srvaddr, len);
    umask(oldumask); /* for Linux */
    chmod(fnamebuf, 0777); /* for DUX */
    if (r == -1) {
        syslog(LOG_ERR, "bind: %s: %m", fnamebuf);
        fatal("bind failed", EX_OSERR);
    }
    r = listen(s, 10);
    if (r == -1) {
        syslog(LOG_ERR, "listen: %m");
        fatal("listen failed", EX_OSERR);
    }

    return s;
}

/* Accept up to max_fds connections on kicksock, put the fds into
 * the array fd_list (atleast max_fds big), and the number of connections
 * into num_fds */
static int get_kick_fds(int kicksock,
                        int *fd_list, int *num_fds, int max_fds)
{
    fd_set read_set;
    int highest_fd = kicksock + 1;
    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    FD_ZERO(&read_set);
    FD_SET(kicksock, &read_set);

    *num_fds = 0;

    for (*num_fds = 0; *num_fds < max_fds; (*num_fds)++) {
        int gotdata;
        fd_set rset;

        rset = read_set;
        gotdata = select(highest_fd, &rset, NULL, NULL, &tv);

        if (gotdata == -1) {
          /* Select Error! */
          syslog(LOG_ERR, "kicksock select failed");
          return -1;
        } else if (gotdata != 0 && FD_ISSET(kicksock, &rset)) {
          struct sockaddr_un clientaddr;
          int len = sizeof(clientaddr);

          fd_list[*num_fds] = accept(kicksock,
                (struct sockaddr *)&clientaddr, (socklen_t *)&len);
          if (fd_list[*num_fds] == -1) {
            syslog(LOG_WARNING, "kicksock accept() failed: %m %d", kicksock);
            return -1;
          }
        } else {
          /* Timeout Expired, we're done! */
          break;
        }
    }

    return 0;
}

#define KICK_FDS_LEN 5

static void mupdate_listen(mupdate_handle *handle, int pingtimeout)
{
    int gotdata = 0;
    fd_set rset, read_set;
    int highest_fd, kicksock;
    int waiting_for_noop = 0;
    int kick_fds[KICK_FDS_LEN];
    int num_kick_fds = 0;
    struct mbent_queue remote_boxes;
    struct mpool *pool;
    int r;
    enum mupdate_cmd_response response;

    if (!handle || !handle->saslcompleted) return;

    pool = new_mpool(131072); /* Arbitrary, but large (128k) */

    /* first get the list of remote mailboxes from the mupdate master */
    r = mupdate_synchronize_remote(handle, &remote_boxes, pool);
    if (r) {
        free_mpool(pool);
        return;
    }

    /* don't handle connections (and drop current connections)
     * while we sync */
    mupdate_unready();

    /* Now, resync the database by comparing the remote mbox with our local*/
    r = mupdate_synchronize(&remote_boxes, pool);
    free_mpool(pool);
    if (r) return;

    mupdate_signal_db_synced();

    /* Okay, we're all set to go */
    mupdate_ready();

    kicksock = open_kick_socket();
    highest_fd = ((kicksock > handle->conn->sock) ? kicksock : handle->conn->sock) + 1;

    FD_ZERO(&read_set);
    FD_SET(handle->conn->sock, &read_set);
    FD_SET(kicksock, &read_set);

    /* Now just listen to the rest of the updates */
    while (1) {
        struct timeval tv;

        tv.tv_sec = pingtimeout;
        tv.tv_usec = 0;

        prot_flush(handle->conn->out);

        rset = read_set;

        gotdata = select(highest_fd, &rset, NULL, NULL, &tv);

        if (gotdata == -1) {
            /* Oops? */
            syslog(LOG_ERR, "select failed");
            break;
        } else if (gotdata != 0) {
            if (FD_ISSET(handle->conn->sock, &rset)) {
                /* If there is a fatal error, die, other errors ignore */
                response = MUPDATE_NONE;
                if ((r = mupdate_scarf(handle, cmd_change, NULL,
                                  waiting_for_noop, &response)) != 0) {
                    syslog(LOG_ERR, "mupdate_scarf: %d", r);
                    break;
                }

                /* If we were waiting on a noop, we no longer are.
                 * If we have been kicked, tell them we're done now */
                if (waiting_for_noop) {
                    if (response != MUPDATE_OK) {
                        syslog(LOG_ERR, "update/noop sync error %d", response);
                        break;
                    }
                    waiting_for_noop = 0;

                    for (; num_kick_fds; num_kick_fds--) {
                        if (write(kick_fds[num_kick_fds-1], "ok", 2) < 0) {
                            syslog(LOG_WARNING,
                                   "can't write to IPC socket (ignoring)");
                        }
                        (void)close(kick_fds[num_kick_fds-1]);
                    }
                }
            }

            if (waiting_for_noop == 0 && FD_ISSET(kicksock, &rset)) {
                /* We were kicked--collect outstanding kicks! */
                if (get_kick_fds(kicksock,
                                kick_fds, &num_kick_fds, KICK_FDS_LEN)) {
                    /* Nonzero return code -- Error */
                    break;
                }

                prot_printf(handle->conn->out, "N%u NOOP\r\n", handle->tagn++);
                if (prot_flush(handle->conn->out) == EOF) {
                    syslog(LOG_ERR, "connection to master failed.");
                    break;
                }
                waiting_for_noop = 1;
            }
        } else /* (gotdata == 0) */ {
            /* Timeout, send a NOOP */
            if (!waiting_for_noop) {
                prot_printf(handle->conn->out, "N%u NOOP\r\n", handle->tagn++);
                if (prot_flush(handle->conn->out) == EOF) {
                    syslog(LOG_ERR, "connection to master failed.");
                    break;
                }
                waiting_for_noop = 1;
            } else {
                /* We were already waiting on a noop! */
                syslog(LOG_ERR, "connection to master timed out.");
                break;
            }
        }
    } /* Loop */

    /* Don't leak the descriptors! */
    for (; num_kick_fds; num_kick_fds--) {
        (void)close(kick_fds[num_kick_fds-1]);
    }
    (void)close(kicksock);
    return;
}

void *mupdate_client_start(void *rock __attribute__((unused)))
{
    mupdate_handle *h = NULL;
    int retry_delay = 20, real_delay;
    int ret;

    srand(time(NULL) * getpid());

    if(!config_mupdate_server) {
        fatal("couldn't get mupdate server name", EX_UNAVAILABLE);
    }

    retry_delay = config_getint(IMAPOPT_MUPDATE_RETRY_DELAY);
    if(retry_delay < 0) {
        fatal("invalid value for mupdate_retry_delay", EX_UNAVAILABLE);
    }

    while(1) {
        ret = mupdate_connect(config_mupdate_server, NULL, &h, NULL);
        if(ret) {
            syslog(LOG_ERR,"couldn't connect to mupdate server");
            goto retry;
        }

        syslog(LOG_ERR, "successful mupdate connection to %s",
               config_mupdate_server);

        mupdate_listen(h, retry_delay);

    retry:
        /* Cleanup */
        mupdate_disconnect(&h);

        real_delay = retry_delay + (rand() % (retry_delay / 2));

        syslog(LOG_ERR,
               "retrying connection to mupdate server in %d seconds",
               real_delay);

        /* Wait before retrying */
        sleep(real_delay);
    }

    return NULL;
}

void *mupdate_placebo_kick_start(void *rock __attribute__((unused)))
{
    int kicksock, kickconn = -1;

    kicksock = open_kick_socket();

    /* Now just listen to the rest of the updates */
    while(1) {
        struct sockaddr_un clientaddr;
        int len;

        /* Only handle one kick at a time -- they're fast */
        len = sizeof(clientaddr);
        kickconn =
            accept(kicksock, (struct sockaddr *)&clientaddr, (socklen_t *)&len);

        if (kickconn == -1) {
          syslog(LOG_WARNING, "accept(): %m");
          break;
        } else {
          if (write(kickconn, "ok", 2) < 0) {
            syslog(LOG_WARNING, "can't write to IPC socket?");
          }
          close(kickconn);
          kickconn = -1;
        }
    } /* Loop */

    /* Don't leak the descriptor! */
    if(kickconn >= 0) close(kickconn);
    close(kicksock);

    return NULL;
}


