/*
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
 * smmapd.c -- sendmail socket map daemon
 *
 *
 * From Sendmail Operations Guide:
 *
 * The socket map uses a simple request/reply protocol over TCP or
 * UNIX domain sockets to query an external server.  Both requests and
 * replies are text based and encoded as netstrings, i.e., a string
 * "hello there" becomes:
 *
 * 11:hello there,
 *
 * Note: neither requests nor replies end with CRLF.
 *
 * The request consists of the database map name and the lookup key
 * separated by a space character:
 *
 * <mapname> ’ ’ <key>
 *
 * The server responds with a status indicator and the result (if any):
 *
 * <status> ’ ’ <result>
 *
 * The status indicator is one of the following upper case words:
 *
 * OK		the key was found, result contains the looked up value
 * NOTFOUND	the key was not found, the result is empty
 * TEMP		a temporary failure occured
 * TIMEOUT	a timeout occured on the server side
 * PERM		a permanent failure occured
 *
 * In case of errors (status TEMP, TIMEOUT or PERM) the result field
 * may contain an explanatory message.
 *
 *
 * $Id: smmapd.c,v 1.1.2.1 2003/12/19 18:33:38 ken3 Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <com_err.h>

#include "acl.h"
#include "append.h"
#include "mboxlist.h"
#include "global.h"
#include "exitcodes.h"
#include "imap_err.h"

const char *BB = "";

extern int optind;

struct protstream *map_in, *map_out;

/* current namespace */
static struct namespace map_namespace;

/* config.c info */
const int config_need_data = 0;

/* forward decls */
extern void setproctitle_init(int argc, char **argv, char **envp);
int begin_handling(void);

void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    if (map_in) prot_free(map_in);
    if (map_out) prot_free(map_out);

    cyrus_close_sock(0);
    cyrus_close_sock(1);
    cyrus_close_sock(2);

    mboxlist_close();
    mboxlist_done();
    cyrus_done();
    exit(code);
}

void fatal(const char* s, int code)
{
    static int recurse_code = 0;
    if (recurse_code) {
        /* We were called recursively. Just give up */
	exit(code);
    }
    recurse_code = code;
    syslog(LOG_ERR, "Fatal error: %s", s);

    shut_down(code);
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc, char **argv, char **envp)
{
    int r;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    setproctitle_init(argc, argv, envp);

    signals_set_shutdown(&shut_down);
    signals_add_handlers();
    signal(SIGPIPE, SIG_IGN);

    BB = config_getstring(IMAPOPT_POSTUSER);

    /* so we can do mboxlist operations */
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* Set namespace */
    if ((r = mboxname_init_namespace(&map_namespace, 1)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    return 0;
}

/* Called by service API to shut down the service */
void service_abort(int error)
{
    shut_down(error);
}

int service_main(int argc __attribute__((unused)),
		 char **argv __attribute__((unused)),
		 char **envp __attribute__((unused)))
{
    int r; 

    map_in = prot_new(0, 0);
    map_out = prot_new(1, 1);
    prot_setflushonread(map_in, map_out);
    prot_settimeout(map_in, 360);

    r = begin_handling();

    shut_down(r);
}

int verify_user(const char *user, long quotacheck,
		struct auth_state *authstate)
{
    char buf[MAX_MAILBOX_NAME+1];
    char *plus;
    int r = 0;
    int sl = strlen(BB);
    char *domain = NULL;
    int userlen = strlen(user), domainlen = 0;

    if ((domain = strchr(user, '@'))) {
	userlen = domain - user;
	domain++;
	/* ignore default domain */
	if (config_virtdomains &&
	    !(config_defdomain && !strcasecmp(config_defdomain, domain)))
	    domainlen = strlen(domain)+1;
    }

    /* check to see if mailbox exists and we can append to it */
    if (!strncmp(user, BB, sl) && user[sl] == '+') {
	/* special shared folder address */
	if (domainlen)
	    snprintf(buf, sizeof(buf),
		     "%s!%.*s", domain, userlen - sl - 1, user + sl + 1);
	else
	    snprintf(buf, sizeof(buf),
		     "%.*s", userlen - sl - 1, user + sl + 1);
	/* Translate any separators in user */
	mboxname_hiersep_tointernal(&map_namespace, buf+domainlen, 0);
	/* - must have posting privileges on shared folders
	   - don't care about message size (1 msg over quota allowed) */
	r = append_check(buf, MAILBOX_FORMAT_NORMAL, authstate,
			 ACL_POST, quotacheck > 0 ? 0 : quotacheck);
    } else {
	/* ordinary user */
	if (userlen > sizeof(buf)-10) {
	    r = IMAP_MAILBOX_NONEXISTENT;
	} else {
	    if (domainlen)
		snprintf(buf, sizeof(buf),
			 "%s!user.%.*s", domain, userlen, user);
	    else
		snprintf(buf, sizeof(buf), "user.%.*s", userlen, user);
	    plus = strchr(buf, '+');
	    if (plus) *plus = '\0';
	    /* Translate any separators in user */
	    mboxname_hiersep_tointernal(&map_namespace, buf+domainlen+5, 0);
	    /* - don't care about ACL on INBOX (always allow post)
	       - don't care about message size (1 msg over quota allowed) */
	    r = append_check(buf, MAILBOX_FORMAT_NORMAL, authstate,
			     0, quotacheck > 0 ? 0 : quotacheck);
	}
    }

    if (r) syslog(LOG_DEBUG, "append_check() of '%s' failed (%s)", buf,
		  error_message(r));

    return r;
}

#define MAXREQUEST 1024		/* XXX  is this reasonable? */

int begin_handling(void)
{
    int c;

    while ((c = prot_getc(map_in)) != EOF) {
	int r = 0, sawdigit = 0, len = 0, size = 0;
	struct auth_state *authstate = NULL;
	char request[MAXREQUEST+1];
	char *mapname, *key;
	const char *errstring = NULL;

	signals_poll();

	while (isdigit(c)) {
	    sawdigit = 1;
	    len = len*10 + c - '0';
            if (len > MAXREQUEST || len < 0) {
                /* we overflowed */
                fatal("string too big", EC_IOERR);
            }
	    c = prot_getc(map_in);
	}
	if (c == EOF) {
	    errstring = prot_error(map_in);
	    r = IMAP_IOERROR;
	}
	if (!sawdigit || c != ':') {
	    errstring = "missing length";
	    r = IMAP_PROTOCOL_ERROR;
	}
	if (!r && prot_read(map_in, request, len) != len) {
	    errstring = "request size doesn't match length";
	    r = IMAP_PROTOCOL_ERROR;
	}
	if (!r && (c = prot_getc(map_in)) != ',') {
	    errstring = "missing terminator";
	    r = IMAP_PROTOCOL_ERROR;
	}

	if (!r) {
	    request[len] = '\0';
	    mapname = request;
	    if (!(key = strchr(request, ' '))) {
		errstring = "missing key";
		r = IMAP_PROTOCOL_ERROR;
	    }
	}

	if (!r) {
	    *key++ = '\0';

	    r = verify_user(key, size, authstate);
	}

	switch (r) {
	case 0:
	    prot_printf(map_out, "%d:OK %s,", 3+strlen(key), key);
	    break;

	case IMAP_MAILBOX_NONEXISTENT:
	    prot_printf(map_out, "8:NOTFOUND,");
	    break;

	case IMAP_QUOTA_EXCEEDED:
	    if (!config_getswitch(IMAPOPT_LMTP_OVER_QUOTA_PERM_FAILURE)) {
		prot_printf(map_out, "%d:TEMP %s,", strlen(error_message(r))+5,
			    error_message(r));
		break;
	    }
	    /* fall through - permanent failure */

	default:
	    if (errstring)
		prot_printf(map_out, "%d:PERM %s (%s),",
			    5+strlen(error_message(r))+3+strlen(errstring),
			    error_message(r), errstring);
	    else
		prot_printf(map_out, "%d:PERM %s,",
			    5+strlen(error_message(r)), error_message(r));
	    break;
	}
    }

    return 0;
}

void printstring(const char *s __attribute__((unused)))
{
    /* needed to link against annotate.o */
    fatal("printstring() executed, but its not used for smmapd!",
	  EC_SOFTWARE);
}
