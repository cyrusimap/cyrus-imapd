/* proxy.c - proxy support functions
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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/un.h>

#include "backend.h"
#include "global.h"
#include "mupdate-client.h"
#include "proxy.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

EXPORTED void proxy_adddest(struct dest **dlist, const char *rcpt, int rcpt_num,
                   const char *server, const char *authas)
{
    struct dest *d;

    /* see if we currently have a 'mailboxdata->server'/'authas'
       combination. */
    for (d = *dlist; d != NULL; d = d->next) {
        if (!strcmp(d->server, server) &&
            !strcmp(d->authas, authas ? authas : "")) break;
    }

    if (d == NULL) {
        /* create a new one */
        d = xmalloc(sizeof(struct dest));
        strlcpy(d->server, server, sizeof(d->server));
        strlcpy(d->authas, authas ? authas : "", sizeof(d->authas));
        d->rnum = 0;
        d->to = NULL;
        d->next = *dlist;
        *dlist = d;
    }

    if (rcpt) {
        struct rcpt *new_rcpt = xmalloc(sizeof(struct rcpt));

        strlcpy(new_rcpt->rcpt, rcpt, sizeof(new_rcpt->rcpt));
        new_rcpt->rcpt_num = rcpt_num;

        /* add rcpt to d */
        d->rnum++;
        new_rcpt->next = d->to;
        d->to = new_rcpt;
    }
}

EXPORTED void proxy_downserver(struct backend *s)
{
    if (!s || (s->sock == -1)) {
        /* already disconnected */
        return;
    }

    /* need to logout of server */
    backend_disconnect(s);

    /* clear any references to this backend */
    if (s->inbox && (s == *(s->inbox))) *(s->inbox) = NULL;
    if (s->current && (s == *(s->current))) *(s->current) = NULL;
    s->inbox = s->current = NULL;

    /* remove the timeout */
    if (s->timeout) prot_removewaitevent(s->clientin, s->timeout);
    s->timeout = NULL;
    s->clientin = NULL;
}

static struct prot_waitevent *
backend_timeout(struct protstream *s __attribute__((unused)),
                struct prot_waitevent *ev, void *rock)
{
    struct backend *be = (struct backend *) rock;
    int is_active = (be->context ? *((int *) be->context) : 0);

    if ((!be->current || (be != *(be->current))) && !is_active) {
        /* server is not our current server, and idle too long.
         * down the backend server (removes the event as a side-effect)
         */
        proxy_downserver(be);
        return NULL;
    }
    else {
        /* it will timeout in IDLE_TIMEOUT seconds from now */
        ev->mark = time(NULL) + IDLE_TIMEOUT;
        return ev;
    }
}

/* return the connection to the server */
EXPORTED struct backend * proxy_findserver(const char *server,          /* hostname of backend */
                 struct protocol_t *prot,       /* protocol we're speaking */
                 const char *userid,            /* proxy as userid (ext form)*/
                 ptrarray_t *cache,             /* ptr to backend cache */
                 struct backend **current,      /* ptr to current backend */
                 struct backend **inbox,        /* ptr to inbox backend */
                 struct protstream *clientin)   /* protstream from client to
                                                   proxy (if non-NULL a timeout
                                                   will be setup) */
{
    int i = 0;
    struct backend *ret = NULL;

    if (current && *current && !strcmp(server, (*current)->hostname)
                && !strcmp(prot->service, (*current)->prot->service)) {
        /* this is our current backend */
        return *current;
    }

    /* check if we already a connection to this backend */
    if (cache) {
        for (i = 0; i < ptrarray_size(cache); i++) {
            struct backend *be = ptrarray_nth(cache, i);
            if ((!strcmp(server, be->hostname) &&
                 !strcmp(prot->service, be->prot->service))) {
                ret = be;
                /* ping/noop the server */
                if ((ret->sock != -1) && backend_ping(ret, userid)) {
                    backend_disconnect(ret);
                }
                break;
            }
        }
    }

    if (!ret || (ret->sock == -1)) {
        /* need to (re)establish connection to server or create one */
        ret = backend_connect(ret, server, prot, userid, NULL, NULL, -1);
        if (!ret) return NULL;

        if (clientin) {
            /* add the timeout */
            ret->clientin = clientin;
            ret->timeout = prot_addwaitevent(clientin,
                                             time(NULL) + IDLE_TIMEOUT,
                                             backend_timeout, ret);
        }
    }

    ret->current = current;
    ret->inbox = inbox;

    /* insert server in list of cache connections */
    if (cache) ptrarray_append(cache, ret);

    return ret;
}

/*
 * Check a protgroup for input.
 *
 * Input from serverin is sent to clientout.
 * If serverout is non-NULL:
 *   - input from clientin is sent to serverout.
 *   - returns -1 if clientin or serverin closed, otherwise returns 0.
 * If serverout is NULL:
 *   - returns 1 if input from clientin is pending, otherwise returns 0.
 */
EXPORTED int proxy_check_input(struct protgroup *protin,
                      struct protstream *clientin,
                      struct protstream *clientout,
                      struct protstream *serverin,
                      struct protstream *serverout,
                      unsigned long timeout_sec)
{
    struct protgroup *protout = NULL;
    struct timeval timeout = { timeout_sec, 0 };
    int n, ret = 0;

    n = prot_select(protin, PROT_NO_FD, &protout, NULL,
                    timeout_sec ? &timeout : NULL);
    if (n == -1 && errno != EINTR) {
        syslog(LOG_ERR, "prot_select() failed in proxy_check_input(): %m");
        fatal("prot_select() failed in proxy_check_input()", EX_TEMPFAIL);
    }

    if (n && protout) {
        /* see who has input */
        for (; n; n--) {
            struct protstream *pin = protgroup_getelement(protout, n-1);
            struct protstream *pout = NULL;

            if (pin == clientin) {
                /* input from client */
                if (serverout) {
                    /* stream it to server */
                    pout = serverout;
                } else {
                    /* notify the caller */
                    ret = 1;
                }
            }
            else if (pin == serverin) {
                /* input from server, stream it to client */
                pout = clientout;
            }
            else {
                /* XXX shouldn't get here !!! */
                fatal("unknown protstream returned by prot_select in proxy_check_input()",
                      EX_SOFTWARE);
            }

            if (pout) {
                const char *err;

                do {
                    char buf[4096];
                    int c = prot_read(pin, buf, sizeof(buf));

                    if (c == 0 || c < 0) break;
                    prot_write(pout, buf, c);
                } while (pin->cnt > 0);

                if ((err = prot_error(pin)) != NULL) {
                    if (serverout && !strcmp(err, PROT_EOF_STRING)) {
                        /* we're pipelining, and the connection closed */
                        ret = -1;
                    }
                    else {
                        /* uh oh, we're not happy */
                        fatal("Lost connection to input stream",
                              EX_UNAVAILABLE);
                    }
                }
                else {
                    return 0;
                }
            }
        }

        protgroup_free(protout);
    }

    return ret;
}

/* proxy mboxlist_lookup; on misses, it asks the listener for this
 * machine to make a roundtrip to the master mailbox server to make
 * sure it's up to date
 */
EXPORTED int proxy_mlookup(const char *name, mbentry_t **mbentryp,
                           void *tid, struct mbox_refer *refer)
{
    mbentry_t *mbentry = NULL;
    int r;

    /* do a local lookup and kick the slave if necessary */
    r = mboxlist_lookup(name, &mbentry, tid);
    if ((r == IMAP_MAILBOX_NONEXISTENT ||
         (!r && (mbentry->mbtype & MBTYPE_RESERVE))) &&
        config_mupdate_server) {
        /* It is not currently active, make sure we have the most recent
         * copy of the database */
        kick_mupdate();
        mboxlist_entry_free(&mbentry);
        r = mboxlist_lookup(name, &mbentry, tid);
    }
    if (r) goto done;
    if (mbentry->mbtype & MBTYPE_RESERVE) {
        r = IMAP_MAILBOX_RESERVED;
    }
    else if (mbentry->mbtype & MBTYPE_MOVING) {
        if (refer) {
            r = refer->proc(mbentry, refer->rock);
        }
        else {
            r = IMAP_MAILBOX_MOVED;
        }
    }
    else if (mbentry->mbtype & MBTYPE_DELETED) {
        r = IMAP_MAILBOX_NONEXISTENT;
    }

 done:
    if (!r && mbentryp) *mbentryp = mbentry;
    else mboxlist_entry_free(&mbentry);

    return r;
}
