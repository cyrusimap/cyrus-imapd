/*
 * proxy.c - proxy support functions
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    "This product includes software developed by Computing Services
 *    acknowledgment:
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
 * $Id: proxy.c,v 1.5 2007/02/05 18:41:48 jeaton Exp $
 */

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/un.h>

#include "backend.h"
#include "exitcodes.h"
#include "global.h"
#include "imap_err.h"
#include "mupdate-client.h"
#include "prot.h"
#include "proxy.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

void proxy_adddest(struct dest **dlist, const char *rcpt, int rcpt_num,
		   char *server, const char *authas)
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

void proxy_downserver(struct backend *s)
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
struct backend *
proxy_findserver(const char *server,		/* hostname of backend */
		 struct protocol_t *prot,	/* protocol we're speaking */
		 const char *userid,		/* proxy as userid (ext form)*/
		 struct backend ***cache,	/* ptr to backend cache */
		 struct backend **current,	/* ptr to current backend */
		 struct backend **inbox,	/* ptr to inbox backend */
		 struct protstream *clientin)	/* protstream from client to
						   proxy (if non-NULL a timeout
						   will be setup) */
{
    int i = 0;
    struct backend *ret = NULL;

    if (current && *current && !strcmp(server, (*current)->hostname)) {
	/* this is our current backend */
	return *current;
    }

    /* check if we already a connection to this backend */
    while (cache && *cache && (*cache)[i]) {
	if (!strcmp(server, ((*cache)[i])->hostname)) {
	    ret = (*cache)[i];
	    /* ping/noop the server */
	    if ((ret->sock != -1) && backend_ping(ret)) {
		backend_disconnect(ret);
	    }
	    break;
	}
	i++;
    }

    if (!ret || (ret->sock == -1)) {
	/* need to (re)establish connection to server or create one */
	ret = backend_connect(ret, server, prot, userid, NULL, NULL);
	if (!ret) return NULL;

	if (clientin) {
	    /* add the timeout */
	    ret->clientin = clientin;
	    ret->timeout = prot_addwaitevent(clientin,
					     time(NULL) + IDLE_TIMEOUT,
					     backend_timeout, ret);

	    ret->timeout->mark = time(NULL) + IDLE_TIMEOUT;
	}
    }

    ret->current = current;
    ret->inbox = inbox;

    /* insert server in list of cache connections */
    if (cache && (!*cache || !(*cache)[i])) {
	*cache = (struct backend **) 
	    xrealloc(*cache, (i + 2) * sizeof(struct backend *));
	(*cache)[i] = ret;
	(*cache)[i + 1] = NULL;
    }

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
int proxy_check_input(struct protgroup *protin,
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
	fatal("prot_select() failed in proxy_check_input()", EC_TEMPFAIL);
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
		      EC_SOFTWARE);
	    }

	    if (pout) {
		const char *err;
		char buf[4096];
		int c;

		do {
		    c = prot_read(pin, buf, sizeof(buf));

		    if (c == 0 || c < 0) break;
		    prot_write(pout, buf, c);
		} while (c == sizeof(buf));

		if ((err = prot_error(pin)) != NULL) {
		    if (serverout && !strcmp(err, PROT_EOF_STRING)) {
			/* we're pipelining, and the connection closed */
			ret = -1;
		    }
		    else {
			/* uh oh, we're not happy */
			fatal("Lost connection to input stream",
			      EC_UNAVAILABLE);
		    }
		}
	    }
	}

	protgroup_free(protout);
    }

    return ret;
}
