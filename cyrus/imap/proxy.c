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
 * $Id: proxy.c,v 1.1.2.2 2004/02/19 21:16:15 ken3 Exp $
 */

#include <config.h>

#include <assert.h>
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

#define IDLE_TIMEOUT (5 * 60)

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

    if (be != *(be->current)) {
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
	ret = backend_connect(ret, server, prot, userid, NULL);
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

void kick_mupdate(void)
{
    char buf[2048];
    struct sockaddr_un srvaddr;
    int s, r;
    int len;
    
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	syslog(LOG_ERR, "socket: %m");
	return;
    }

    strlcpy(buf, config_dir, sizeof(buf));
    strlcat(buf, FNAME_MUPDATE_TARGET_SOCK, sizeof(buf));
    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, buf);
    len = sizeof(srvaddr.sun_family) + strlen(srvaddr.sun_path) + 1;

    r = connect(s, (struct sockaddr *)&srvaddr, len);
    if (r == -1) {
	syslog(LOG_ERR, "kick_mupdate: can't connect to target: %m");
    }
    else {
	r = read(s, buf, sizeof(buf));
	if (r <= 0) {
	    syslog(LOG_ERR, "kick_mupdate: can't read from target: %m");
	}
    }

    close(s);
    return;
}
