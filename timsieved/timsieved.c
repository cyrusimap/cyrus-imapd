/* timsieved.c -- main file for timsieved (sieve script accepting program)
 * Tim Martin
 * 9/21/99
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/


#include <sasl.h> /* yay! sasl */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "prot.h"
#include "xmalloc.h"

#include "lex.h"
#include "mystring.h"

#include "codes.h"

sasl_conn_t *sieved_saslconn; /* the sasl connection context */

struct sockaddr_in sieved_localaddr;
struct sockaddr_in sieved_remoteaddr;

struct protstream *sieved_out;
struct protstream *sieved_in;

int sieved_haveaddr = 0;
char sieved_clienthost[250] = "[local]";

int sieved_userisadmin;

void cmdloop()
{
  unsigned int mechcount;
  char *sasllist;

  chdir("/tmp/");

  prot_printf(sieved_out, "\"" SIEVED_IDENT " " SIEVED_VERSION "\"");

  if (sasl_listmech(sieved_saslconn, NULL, 
		    " \"SASL={", ", ", "}\"",
		    &sasllist,
		    NULL, &mechcount) == SASL_OK && mechcount > 0)
    {
      prot_printf(sieved_out,"%s",sasllist);
    }
    
  prot_printf(sieved_out,"\r\n");

  /* initialize lexer */
  lex_init();

  while (1)
  {
    timparse(sieved_in);
  }
}


void
fatal(s, code)
const char *s;
int code;
{
    static int recurse_code = 0;

    if (recurse_code) {
	/* We were called recursively. Just give up */
	exit(recurse_code);
    }
    recurse_code = code;
    prot_printf(sieved_out, "* BYE Fatal error: %s\r\n", s);
    prot_flush(sieved_out);
}

/* This creates a structure that defines the allowable
 *   security properties 
 */
static sasl_security_properties_t *make_secprops(int min,int max)
{
  sasl_security_properties_t *ret=
    (sasl_security_properties_t *) xmalloc(sizeof(sasl_security_properties_t));

  ret->maxbufsize = 4000;
  ret->min_ssf = min;		/* minimum allowable security strength */
  ret->max_ssf = max;		/* maximum allowable security strength */

  ret->security_flags = 0;
  if (!config_getswitch("allowplaintext", 1)) {
      ret->security_flags |= SASL_SEC_NOPLAINTEXT;
  }
  if (!config_getswitch("allowanonymouslogin", 0)) {
      ret->security_flags |= SASL_SEC_NOANONYMOUS;
  }
  ret->property_names = NULL;
  ret->property_values = NULL;

  return ret;
}

/* this is a wrapper to call the cyrus configuration from SASL */
static int mysasl_config(void *context, 
			 const char *plugin_name,
			 const char *option,
			 const char **result,
			 unsigned *len)
{
    char opt[1024];

    if (strcmp(option, "srvtab")) { /* we don't transform srvtab! */
	int sl = 5 + (plugin_name ? strlen(plugin_name) + 1 : 0);

	strncpy(opt, "sasl_", 1024);
	if (plugin_name) {
	    strncat(opt, plugin_name, 1019);
	    strncat(opt, "_", 1024 - sl);
	}
 	strncat(opt, option, 1024 - sl - 1);
	opt[1023] = '\0';
    } else {
	strncpy(opt, option, 1024);
    }

    *result = (const char *) config_getstring(opt, NULL);
    if (*result != NULL) {
	if (len) { *len = strlen(*result); }
	return SASL_OK;
    }
   
    return SASL_FAIL;
}

/* returns true if imapd_authstate is in "item";
   expected: item = admins or proxyservers */
static int authisa(const char *item)
{
  /* xxx i don't understand larry's code that goes here yet */
    return 0;
}

/* should we allow users to proxy?  return SASL_OK if yes,
   SASL_BADAUTH otherwise */
static mysasl_authproc(void *context,
		       const char *auth_identity,
		       const char *requested_user,
		       const char **user,
		       const char **errstr)
{
    char *p;
    const char *val;
    char *canon_authuser, *canon_requser;
    char *username=NULL, *realm;
    static char replybuf[100];

    canon_authuser = (char *) auth_canonifyid(auth_identity);
    if (!canon_authuser) {
	*errstr = "bad userid authenticated";
	return SASL_BADAUTH;
    }
    canon_authuser = xstrdup(canon_authuser);

    canon_requser = (char *) auth_canonifyid(requested_user);
    if (!canon_requser) {
	*errstr = "bad userid requested";
	return SASL_BADAUTH;
    }
    canon_requser = xstrdup(canon_requser);

    /* check if remote realm */
    if (realm = strchr(canon_authuser, '@')) {
	realm++;
	val = (const char *) config_getstring("loginrealms", "");
	while (*val) {
	    if (!strncasecmp(val, realm, strlen(realm)) &&
		(!val[strlen(realm)] || isspace(val[strlen(realm)]))) {
		break;
	    }
	    /* not this realm, try next one */
	    while (*val && !isspace(*val)) val++;
	    while (*val && isspace(*val)) val++;
	}
	if (!*val) {
	    snprintf(replybuf, 100, "cross-realm login %s denied", 
		     canon_authuser);
	    *errstr = replybuf;
	    return SASL_BADAUTH;
	}
    }

    /* ok, is auth_identity an admin? */
    sieved_userisadmin = authisa("admins");

    if (strcmp(canon_authuser, canon_requser)) {
	/* we want to authenticate as a different user; we'll allow this
	   if we're an admin or if we've allowed ACL proxy logins */
	int use_acl = config_getswitch("loginuseacl", 0);

	if (sieved_userisadmin)
	{	    
	    
	    /* proxy ok! */

	    sieved_userisadmin = 0;	/* no longer admin */
	    
	} else {
	    *errstr = "user is not allowed to proxy";
	    
	    free(canon_authuser);
	    free(canon_requser);
	    
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

main(argc, argv, envp)
int argc;
char **argv;
char **envp;
{
    int salen;
    struct hostent *hp;
    int timeout;
    char hostname[MAXHOSTNAMELEN+1];
    sasl_security_properties_t *secprops = NULL;

    if (gethostname(hostname, MAXHOSTNAMELEN)!=0)
      fatal("gethostname failed\n",-5);

    config_init("timsieved");

    /* set up the prot streams */
    sieved_in = prot_new(0, 0);
    sieved_out = prot_new(1, 1);
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
	if (hp = gethostbyaddr((char *)&sieved_remoteaddr.sin_addr,
			       sizeof(sieved_remoteaddr.sin_addr), AF_INET)) {
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
    if (sasl_server_new("imap", hostname, NULL, NULL, SASL_SECURITY_LAYER, 
			&sieved_saslconn)
	   != SASL_OK)
	fatal("SASL failed initializing: sasl_server_new()", -1); 

    /* will always return something valid */
    /* should be configurable! */
    secprops = make_secprops(0, 2000);
    sasl_setprop(sieved_saslconn, SASL_SEC_PROPS, secprops);
    
    sasl_setprop(sieved_saslconn, SASL_IP_REMOTE, &sieved_remoteaddr);  
    sasl_setprop(sieved_saslconn, SASL_IP_LOCAL, &sieved_localaddr);  

    if (actions_init() != TIMSIEVE_OK)
      fatal("Error initializing actions",-1);

    cmdloop();
}


