/* mupdate-slave.c -- cyrus murder database clients
 *
 * $Id: mupdate-slave.c,v 1.5 2002/01/24 23:53:44 rjs3 Exp $
 * Copyright (c) 2001 Carnegie Mellon University.  All rights reserved.
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
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <syslog.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "prot.h"
#include "xmalloc.h"
#include "imapconf.h"
#include "assert.h"
#include "imparse.h"
#include "iptostring.h"
#include "mupdate.h"
#include "mupdate_err.h"
#include "exitcodes.h"

void mupdate_listen(mupdate_handle *handle, int pingtimeout)
{
    int gotdata = 0;
    fd_set read_set;
    int highest_fd;

    if (!handle || !handle->saslcompleted) return;

    highest_fd = handle->sock + 1;

    /* don't handle connections (and drop current connections)
     * while we sync */
    mupdate_unready();

    /* First, resync the database */
    if(mupdate_synchronize(handle)) return;

    /* Okay, we're all set to go */
    mupdate_ready();

    /* Now just listen to the rest of the updates */
    while(1) {
	struct timeval tv;

	tv.tv_sec = 15;
	tv.tv_usec = 0;

	prot_flush(handle->pout);
	
	FD_ZERO(&read_set);
	FD_SET(handle->sock, &read_set);

	gotdata = select(highest_fd, &read_set, NULL, NULL, &tv);

	if (gotdata > 0) {
	    /* If there is a fatal error, die, other errors ignore */
	    if(mupdate_scarf(handle, cmd_change, NULL, 0)) return;
	    continue;
	} else if(gotdata == 0) {
	    /* timed out, send a NOOP */
	    prot_printf(handle->pout, "N%u NOOP\r\n", handle->tag++);
	    prot_flush(handle->pout);

	    /* wait 'pingtimeout' seconds for response */
	    FD_ZERO(&read_set);
	    FD_SET(handle->sock, &read_set);

	    tv.tv_sec = pingtimeout;
	    tv.tv_usec = 0;
	    
	    gotdata = select(highest_fd, &read_set, NULL, NULL, &tv);
	    if(gotdata <= 0) {
		/* We died, reconnect */
		syslog(LOG_ERR, "master did not respond to NOOP in %d seconds",
		       pingtimeout);
		return;
	    }

	    /* Now that we recieved it, scarf up all data until the next OK */
	    if(mupdate_scarf(handle, cmd_change, NULL, 1)) return;
	} else {
	    syslog(LOG_ERR, "select failed");
	    return;
	}
    }
}

void *mupdate_client_start(void *rock __attribute__((unused)))
{
    const char *server, *port, *num;
    mupdate_handle *h = NULL;
    int connection_count = 0;
    int retries = 15;
    int retry_delay = 20;
    int ret;

    server = config_getstring("mupdate_server", NULL);
    if(server == NULL) {
	fatal("couldn't get mupdate server name", EC_UNAVAILABLE);
    }

    port = config_getstring("mupdate_port",NULL);

    num = config_getstring("mupdate_retry_count",NULL);
    if(num && imparse_isnumber(num)) {
	retries = atoi(num);
	if(retries < 0) {
	    fatal("invalid value for mupdate_retry_count", EC_UNAVAILABLE);
	}
    }

    num = config_getstring("mupdate_retry_delay",NULL);
    if(num && imparse_isnumber(num)) {
	retry_delay = atoi(num);
	if(retry_delay < 0) {
	    fatal("invalid value for mupdate_retry_delay", EC_UNAVAILABLE);
	}
    }
    
    while(1) {
	ret = mupdate_connect(server, port, &h, NULL);
	if(ret) {
	    syslog(LOG_ERR,"couldn't connect to mupdate server");
	    goto retry;
	}
   
	/* Successful Connection, reset counter: */
	connection_count = -1;
	syslog(LOG_ERR, "successful mupdate connection to %s", server);

	mupdate_listen(h, retry_delay);

    retry:
	/* Cleanup */
	if(h && h->pin) prot_free(h->pin);
	if(h && h->pout) prot_free(h->pout);
	close(h->sock);
	if(h->saslconn) sasl_dispose(&h->saslconn);
	free(h); h = NULL;
	
	/* Should we retry? */
	if(++connection_count < retries) {
	    syslog(LOG_ERR,
		   "retrying connection to mupdate server in %d seconds",
		   retry_delay);
	} else {
	    syslog(LOG_ERR,
		   "too many connection retries. dying.");
	    break;
	}
	
	/* Wait before retrying */
	sleep(retry_delay);
    }

    return NULL;
}


