/* mupdate-slave.c -- cyrus murder database clients
 *
 * $Id: mupdate-slave.c,v 1.13 2002/02/03 14:57:29 leg Exp $
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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
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

/* Returns file descriptor of kick socket (or does not return) */
static int open_kick_socket() 
{
    int r,s,len;
    char fnamebuf[2048];
    struct sockaddr_un srvaddr;
    mode_t oldumask;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	syslog(LOG_ERR, "socket: %m");
	fatal("socket failed", EC_OSERR);
    }

    strncpy(fnamebuf, config_dir, sizeof(fnamebuf));
    strncat(fnamebuf, FNAME_MUPDATE_TARGET_SOCK, sizeof(fnamebuf));

    (void) unlink(fnamebuf);
    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, fnamebuf);
    len = strlen(srvaddr.sun_path) + sizeof(srvaddr.sun_family) + 1;
    oldumask = umask((mode_t) 0); /* for Linux */
    r = bind(s, (struct sockaddr *)&srvaddr, len);
    umask(oldumask); /* for Linux */
    chmod(fnamebuf, 0777); /* for DUX */
    if (r == -1) {
	syslog(LOG_ERR, "bind: %s: %m", fnamebuf);
	fatal("bind failed", EC_OSERR);
    }
    r = listen(s, 10);
    if (r == -1) {
	syslog(LOG_ERR, "listen: %m");
	fatal("listen failed", EC_OSERR);
    }

    return s;
}

static void mupdate_listen(mupdate_handle *handle, int pingtimeout)
{
    int len, gotdata = 0;
    fd_set rset, read_set;
    int highest_fd, kicksock, kickconn = -1;
    int waiting_for_noop = 0;
    
    if (!handle || !handle->saslcompleted) return;

    /* don't handle connections (and drop current connections)
     * while we sync */
    mupdate_unready();

    /* First, resync the database */
    if(mupdate_synchronize(handle)) return;

    /* Okay, we're all set to go */
    mupdate_ready();

    kicksock = open_kick_socket();
    highest_fd = ((kicksock > handle->sock) ? kicksock : handle->sock) + 1;

    FD_ZERO(&read_set);
    FD_SET(handle->sock, &read_set);
    FD_SET(kicksock, &read_set);

    /* Now just listen to the rest of the updates */
    while(1) {
	struct timeval tv;

	tv.tv_sec = pingtimeout;
	tv.tv_usec = 0;

	prot_flush(handle->pout);

	rset = read_set;

	gotdata = select(highest_fd, &rset, NULL, NULL, &tv);

	if(gotdata == -1) {
	    /* Oops? */
	    syslog(LOG_ERR, "select failed");
	    break;
	} else if(gotdata != 0) {
	    if (FD_ISSET(handle->sock, &rset)) {
		/* If there is a fatal error, die, other errors ignore */
		if (mupdate_scarf(handle, cmd_change, NULL, 
				  waiting_for_noop, NULL) != 0) {
		    break;
		}
	    } 
	    
	    /* If we were waiting on a noop, we no longer are.
	     * If we have been kicked, tell them we're done now */
	    if(waiting_for_noop) {
		waiting_for_noop = 0;
		if(kickconn >= 0) {
		    if (write(kickconn, "ok", 2) < 0) {
			syslog(LOG_WARNING, "can't write to IPC socket?");
			break;
		    }
		    close(kickconn);
		    kickconn = -1;
		}
	    }
	    
	    if (FD_ISSET(kicksock, &rset)) {
		/* We got a kickme, force a NOOP */
		struct sockaddr_un clientaddr;
		
		/* Only handle one kick at a time */
		len = sizeof(clientaddr);
		kickconn =
		    accept(kicksock, (struct sockaddr *)&clientaddr, &len);
		
		if (kickconn == -1) {
		    syslog(LOG_WARNING, "accept(): %m");
		    break;
		}
		
		prot_printf(handle->pout, "N%u NOOP\r\n", handle->tagn++);
		prot_flush(handle->pout);
		waiting_for_noop = 1;
	    }
	} else /* (gotdata == 0) */ {
	    /* Timeout, send a NOOP */
	    if(!waiting_for_noop) {
		prot_printf(handle->pout, "N%u NOOP\r\n", handle->tagn++);
		prot_flush(handle->pout);
		waiting_for_noop = 1;
	    } else {
		/* We were already waiting on a noop! */
		syslog(LOG_ERR, "connection to master timed out.");
		break;
	    }
	}
    } /* Loop */

    /* Don't leak the descriptor! */
    if(kickconn >= 0) close(kickconn);
    close(kicksock);
}

void *mupdate_client_start(void *rock __attribute__((unused)))
{
    const char *server, *num;
    mupdate_handle *h = NULL;
    int connection_count = 0;
    int retries = 15;
    int retry_delay = 20;
    int ret;

    server = config_getstring("mupdate_server", NULL);
    if(server == NULL) {
	fatal("couldn't get mupdate server name", EC_UNAVAILABLE);
    }

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

    /* xxx open the kick socket here */
    
    while(1) {
	ret = mupdate_connect(server, NULL, &h, NULL);
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
	if(h) close(h->sock);
	if(h && h->saslconn) sasl_dispose(&h->saslconn);
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


