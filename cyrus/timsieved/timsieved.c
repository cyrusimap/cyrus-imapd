/* timsieved.c -- main file for timsieved (sieve script accepting program)
 * Tim Martin
 * 9/21/99
 * $Id: timsieved.c,v 1.40.4.8 2002/11/15 21:47:07 rjs3 Exp $
 */
/*
 * Copyright (c) 1999-2000 Carnegie Mellon University.  All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sasl/sasl.h> /* yay! sasl */

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/param.h>
#include <syslog.h>
#include <dirent.h>
#include <ctype.h>
#include <com_err.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include "prot.h"
#include "imapconf.h"
#include "xmalloc.h"
#include "exitcodes.h"
#include "iptostring.h"
#include "codes.h"
#include "actions.h"
#include "parser.h"
#include "lex.h"
#include "mystring.h"

#include "auth.h"
#include "acl.h"
#include "mboxlist.h"

/* global state */
const int config_need_data = 0;

static struct 
{
    char *ipremoteport;
    char *iplocalport;
} saslprops = {NULL,NULL};

sasl_conn_t *sieved_saslconn; /* the sasl connection context */

struct auth_state *sieved_authstate = 0;

struct sockaddr_in sieved_localaddr;
struct sockaddr_in sieved_remoteaddr;

struct protstream *sieved_out;
struct protstream *sieved_in;

int sieved_logfd = -1;

int sieved_haveaddr = 0;
char sieved_clienthost[250] = "[local]";

int sieved_userisadmin;
int sieved_domainfromip = 0;

/* the sasl proxy policy context */
static struct proxy_context sieved_proxyctx = {
    1, 1, &sieved_authstate, &sieved_userisadmin, NULL
};

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__ ((noreturn));
void shut_down(int code)
{
    /* close mailboxes */
    mboxlist_close();
    mboxlist_done();

    /* cleanup */
    if (sieved_out) {
	prot_flush(sieved_out);
	prot_free(sieved_out);
    }
    if (sieved_in) prot_free(sieved_in);

    if (sieved_logfd != -1) close(sieved_logfd);

    cyrus_done();
    
    /* done */
    exit(code);
}

void cmdloop()
{
    int ret = FALSE;
    
    chdir("/tmp/");

    capabilities(sieved_out, sieved_saslconn);

    /* initialize lexer */
    lex_init();

    while (ret != TRUE)
    {
	ret = parser(sieved_out, sieved_in);
    }

    /* done */
    shut_down(0);
}


void fatal(const char *s, int code)
{
    static int recurse_code = 0;

    if (recurse_code) {
	/* We were called recursively. Just give up */
	exit(recurse_code);
    }
    recurse_code = code;

    prot_printf(sieved_out, "NO Fatal error: %s\r\n", s);
    prot_flush(sieved_out);

    shut_down(EC_TEMPFAIL);
}

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &mysasl_proxy_policy, (void*) &sieved_proxyctx },
    { SASL_CB_CANON_USER, &mysasl_canon_user, (void*) &sieved_domainfromip },
    { SASL_CB_LIST_END, NULL, NULL }
};

int service_init(int argc, char **argv, char **envp)
{
    config_sasl_init(0, 1, mysasl_cb);

    /* open mailboxes */
    mboxlist_init(0);
    mboxlist_open(NULL);

    return 0;
}

void service_abort(int error)
{
    shut_down(error);
}

int service_main(int argc, char **argv, char **envp)
{
    socklen_t salen;
    struct hostent *hp;
    int timeout;
    int secflags = 0;
    char remoteip[60], localip[60];
    sasl_security_properties_t *secprops = NULL;

    /* set up the prot streams */
    sieved_in = prot_new(0, 0);
    sieved_out = prot_new(1, 1);

    timeout = config_getint(IMAPOPT_TIMEOUT);
    if (timeout < 10) timeout = 10;
    prot_settimeout(sieved_in, timeout * 60);
    prot_setflushonread(sieved_in, sieved_out);

    signal(SIGPIPE, SIG_IGN);

    if (geteuid() == 0) fatal("must run as the Cyrus user", -6);

    /* Find out name of client host */
    salen = sizeof(sieved_remoteaddr);
    if (getpeername(0, (struct sockaddr *)&sieved_remoteaddr, &salen) == 0 &&
	sieved_remoteaddr.sin_family == AF_INET) {
	if ((hp = gethostbyaddr((char *)&sieved_remoteaddr.sin_addr,
			       sizeof(sieved_remoteaddr.sin_addr), AF_INET))!=NULL) {
	    strncpy(sieved_clienthost, hp->h_name, sizeof(sieved_clienthost)-30);
	    sieved_clienthost[sizeof(sieved_clienthost)-30] = '\0';
	}
	else {
	    sieved_clienthost[0] = '\0';
	}
	strcat(sieved_clienthost, "[");
	strcat(sieved_clienthost, inet_ntoa(sieved_remoteaddr.sin_addr));
	strcat(sieved_clienthost, "]");
	salen = sizeof(sieved_localaddr);
	if (getsockname(0, (struct sockaddr *)&sieved_localaddr, &salen) == 0)
	{
	    sieved_haveaddr = 1;
	}
    }

    /* other params should be filled in */
    if (sasl_server_new(SIEVE_SERVICE_NAME, config_servername, NULL,
			NULL, NULL, NULL, SASL_SUCCESS_DATA,
			&sieved_saslconn) != SASL_OK)
	fatal("SASL failed initializing: sasl_server_new()", -1); 

    if(iptostring((struct sockaddr *)&sieved_remoteaddr,
		  sizeof(struct sockaddr_in), remoteip, 60) == 0) {
	sasl_setprop(sieved_saslconn, SASL_IPREMOTEPORT, remoteip);
	saslprops.ipremoteport = xstrdup(remoteip);
    }
    if(iptostring((struct sockaddr *)&sieved_localaddr,
		  sizeof(struct sockaddr_in), localip, 60) == 0) {
	sasl_setprop(sieved_saslconn, SASL_IPLOCALPORT, localip);
	saslprops.iplocalport = xstrdup(localip);
    }

    /* will always return something valid */
    /* should be configurable! */
    if (!config_getswitch(IMAPOPT_ALLOWPLAINTEXT)) {
	secflags |= SASL_SEC_NOPLAINTEXT;
    }
    secprops = mysasl_secprops(secflags);
    sasl_setprop(sieved_saslconn, SASL_SEC_PROPS, secprops);

    if (actions_init() != TIMSIEVE_OK)
      fatal("Error initializing actions",-1);

    cmdloop();

    /* never reaches */
    exit(EC_SOFTWARE);
}

/* Reset the given sasl_conn_t to a sane state */
int reset_saslconn(sasl_conn_t **conn, sasl_ssf_t ssf, char *authid)
{
    int ret = 0;
    int secflags = 0;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new(SIEVE_SERVICE_NAME, config_servername,
		          NULL, NULL, NULL,
			  NULL, SASL_SUCCESS_DATA, conn);
    if(ret != SASL_OK) return ret;

    if(saslprops.ipremoteport)
	ret = sasl_setprop(*conn, SASL_IPREMOTEPORT,
			   saslprops.ipremoteport);
    if(ret != SASL_OK) return ret;
    
    if(saslprops.iplocalport)
	ret = sasl_setprop(*conn, SASL_IPLOCALPORT,
			   saslprops.iplocalport);
    if(ret != SASL_OK) return ret;
    
    if (!config_getswitch(IMAPOPT_ALLOWPLAINTEXT)) {
	secflags |= SASL_SEC_NOPLAINTEXT;
    }
    secprops = mysasl_secprops(secflags);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;

    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if(ssf) {
	ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &ssf);
	if(ret != SASL_OK) return ret;
    }
    
    if(authid) {
	ret = sasl_setprop(*conn, SASL_AUTH_EXTERNAL, authid);
	if(ret != SASL_OK) return ret;
    }
    /* End TLS/SSL Info */

    return SASL_OK;
}
