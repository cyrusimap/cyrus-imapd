/* timsieved.c -- main file for timsieved (sieve script accepting program)
 * Tim Martin
 * 9/21/99
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

#include <sasl.h> /* yay! sasl */

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

#include "codes.h"
#include "actions.h"
#include "parser.h"
#include "lex.h"
#include "mystring.h"

#include "auth.h"


sasl_conn_t *sieved_saslconn; /* the sasl connection context */

struct auth_state *sieved_authstate = 0;

struct sockaddr_in sieved_localaddr;
struct sockaddr_in sieved_remoteaddr;

struct protstream *sieved_out;
struct protstream *sieved_in;

int sieved_haveaddr = 0;
char sieved_clienthost[250] = "[local]";

int sieved_userisadmin;

void cmdloop()
{
  chdir("/tmp/");

  capabilities(sieved_out, sieved_saslconn);

  /* initialize lexer */
  lex_init();

  while (1)
  {
    parser(sieved_out, sieved_in);
  }
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

    exit(1);

}

/* should we allow users to proxy?  return SASL_OK if yes,
   SASL_BADAUTH otherwise */
static int mysasl_authproc(void *context,
			   const char *auth_identity,
			   const char *requested_user,
			   const char **user,
			   const char **errstr)
{
    const char *val;
    char *canon_authuser, *canon_requser;
    char *realm;
    static char replybuf[100];

    canon_authuser = (char *) auth_canonifyid(auth_identity);
    if (!canon_authuser) {
	*errstr = "bad userid authenticated";
	return SASL_BADAUTH;
    }
    canon_authuser = xstrdup(canon_authuser);

    if (!requested_user) requested_user = auth_identity;
    canon_requser = (char *) auth_canonifyid(requested_user);
    if (!canon_requser) {
	*errstr = "bad userid requested";
	return SASL_BADAUTH;
    }
    canon_requser = xstrdup(canon_requser);

    /* check if remote realm */
    if ((realm = strchr(canon_authuser, '@'))!=NULL) {
	realm++;
	val = (const char *) config_getstring("loginrealms", "");
	while (*val) {
	    if (!strncasecmp(val, realm, strlen(realm)) &&
		(!val[strlen(realm)] || isspace((int) val[strlen(realm)]))) {
		break;
	    }
	    /* not this realm, try next one */
	    while (*val && !isspace((int) *val)) val++;
	    while (*val && isspace((int) *val)) val++;
	}
	if (!*val) {
	    snprintf(replybuf, 100, "cross-realm login %s denied", 
		     canon_authuser);
	    *errstr = replybuf;
	    return SASL_BADAUTH;
	}
    }

    sieved_authstate = auth_newstate(canon_authuser, NULL);

    /* ok, is auth_identity an admin? */
    sieved_userisadmin = authisa(sieved_authstate, "sieve", "admins");

    /* we want to authenticate as a different user: ok if we're an admin or
     a proxy server */
    if (strcmp(canon_authuser, canon_requser)) {
	if (sieved_userisadmin || authisa(sieved_authstate, "sieve", 
					  "proxyservers")) {
	    sieved_userisadmin = 0; /* no longer admin */
	    auth_freestate(sieved_authstate);
	    
	    sieved_authstate = auth_newstate(canon_requser, NULL);
	} else {
	    *errstr = "user is not allowed to proxy";
	    
	    free(canon_authuser);
	    free(canon_requser);
	    auth_freestate(sieved_authstate);

	    return SASL_BADAUTH;
	}
    }

    free(canon_authuser);
    *user = canon_requser;
    *errstr = NULL;
    return SASL_OK;
}

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &mysasl_authproc, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

int service_init(int argc, char **argv, char **envp)
{
    return 0;
}

void service_abort(void)
{
    return;
}

int service_main(int argc, char **argv, char **envp)
{
    socklen_t salen;
    struct hostent *hp;
    int timeout;
    sasl_security_properties_t *secprops = NULL;

    /* set up the prot streams */
    sieved_in = prot_new(0, 0);
    sieved_out = prot_new(1, 1);

    config_changeident("timsieved");
    timeout = config_getint("timeout", 10);
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
	if (getsockname(0, (struct sockaddr *)&sieved_localaddr, &salen) == 0) {
	    sieved_haveaddr = 1;
	}
    }

    /* set the SASL allocation functions */
    sasl_set_alloc((sasl_malloc_t *) &xmalloc, 
		   (sasl_calloc_t *) &calloc, 
		   (sasl_realloc_t *) &xrealloc, 
		   (sasl_free_t *) &free);

    /* Make a SASL connection and setup some properties for it */
    if (sasl_server_init(mysasl_cb, "Cyrus") != SASL_OK)
	fatal("SASL failed initializing: sasl_server_init()", -1); 

    /* other params should be filled in */
    if (sasl_server_new("imap", NULL, NULL, 
			NULL, SASL_SECURITY_LAYER, &sieved_saslconn)
	   != SASL_OK)
	fatal("SASL failed initializing: sasl_server_new()", -1); 

    /* will always return something valid */
    /* should be configurable! */
    secprops = mysasl_secprops(SASL_SEC_NOANONYMOUS);
    sasl_setprop(sieved_saslconn, SASL_SEC_PROPS, secprops);
    
    sasl_setprop(sieved_saslconn, SASL_IP_REMOTE, &sieved_remoteaddr);  
    sasl_setprop(sieved_saslconn, SASL_IP_LOCAL, &sieved_localaddr);  

    if (actions_init() != TIMSIEVE_OK)
      fatal("Error initializing actions",-1);

    cmdloop();

    /* never reaches */
    exit(-99);
}


