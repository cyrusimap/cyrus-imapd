/* global.c -- Configuration routines
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
 */

/* $Id: global.c,v 1.1.2.7 2003/03/19 19:00:37 rjs3 Exp $ */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <com_err.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>

#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>

#include "acl.h"
#include "exitcodes.h"
#include "gmtoff.h"
#include "hash.h"
#include "imap_err.h"
#include "global.h"
#include "libconfig.h"
#include "libcyr_cfg.h"
#include "mboxlist.h"
#include "mupdate_err.h"
#include "mutex.h"
#include "prot.h" /* for PROT_BUFSIZE */
#include "util.h"
#include "xmalloc.h"

static enum {
    NOT_RUNNING = 0,
    RUNNING = 1,
    DONE = 2
} cyrus_init_run = NOT_RUNNING;

int config_implicitrights;        /* "lca" */

/* Called before a cyrus application starts (but after command line parameters
 * are read) */
int cyrus_init(const char *alt_config, const char *ident)
{
    char *p;
    const char *val;
    const char *prefix;
    int umaskval = 0;

    if(cyrus_init_run != NOT_RUNNING) {
	fatal("cyrus_init called twice!", EC_CONFIG);
    } else {
	cyrus_init_run = RUNNING;
    }

    initialize_imap_error_table();
    initialize_mupd_error_table();

    if(!ident)
	fatal("service name was not specified to cyrus_init", EC_CONFIG);

    config_ident = ident;
    
    /* xxx we lose here since we can't have the prefix until we load the
     * config file */
    openlog(config_ident, LOG_PID, SYSLOG_FACILITY);

    /* Load configuration file.  This will set config_dir when it finds it */
    config_read(alt_config);

    prefix = config_getstring(IMAPOPT_SYSLOG_PREFIX);

    /* Reopen the log with the new prefix, if needed  */    
    if(prefix) {
	int size = strlen(prefix) + 1 + strlen(ident) + 1;
	char *ident_buf = xmalloc(size);
	
	strlcpy(ident_buf, prefix, size);
	strlcat(ident_buf, "/", size);
	strlcat(ident_buf, ident, size);

	closelog();
	openlog(ident_buf, LOG_PID, SYSLOG_FACILITY);

	/* don't free the openlog() string! */
    }

    /* Look up default partition */
    config_defpartition = config_getstring(IMAPOPT_DEFAULTPARTITION);
    for (p = (char *)config_defpartition; *p; p++) {
	if (!isalnum((unsigned char) *p))
	  fatal("defaultpartition option contains non-alphanumeric character",
		EC_CONFIG);
	if (isupper((unsigned char) *p)) *p = tolower((unsigned char) *p);
    }

    /* Look up umask */
    val = config_getstring(IMAPOPT_UMASK);
    while (*val) {
	if (*val >= '0' && *val <= '7') umaskval = umaskval*8 + *val - '0';
	val++;
    }
    umask(umaskval);

    /* look up and canonify the implicit rights of mailbox owners */
    config_implicitrights =
	cyrus_acl_strtomask(config_getstring(IMAPOPT_IMPLICIT_OWNER_RIGHTS));

    /* configure libcyrus as needed */
    libcyrus_config_setstring(CYRUSOPT_CONFIG_DIR, config_dir);
    libcyrus_config_setswitch(CYRUSOPT_AUTH_UNIX_GROUP_ENABLE,
			      config_getswitch(IMAPOPT_UNIX_GROUP_ENABLE));
    libcyrus_config_setswitch(CYRUSOPT_USERNAME_TOLOWER,
			      config_getswitch(IMAPOPT_USERNAME_TOLOWER));
    libcyrus_config_setswitch(CYRUSOPT_SKIPLIST_UNSAFE,
			      config_getswitch(IMAPOPT_SKIPLIST_UNSAFE));
    libcyrus_config_setstring(CYRUSOPT_TEMP_PATH,
			      config_getstring(IMAPOPT_TEMP_PATH));
    libcyrus_config_setint(CYRUSOPT_PTS_CACHE_TIMEOUT,
			   config_getint(IMAPOPT_PTSCACHE_TIMEOUT));

    /* Not until all configuration parameters are set! */
    libcyrus_init();
    
    return 0;
}

void global_sasl_init(int client, int server, const sasl_callback_t *callbacks)
{
    static int called_already = 0;
    
    assert(client || server);
    assert(!called_already);
    
    called_already = 1;

    /* set the SASL allocation functions */
    sasl_set_alloc((sasl_malloc_t *) &xmalloc, 
		   (sasl_calloc_t *) &calloc, 
		   (sasl_realloc_t *) &xrealloc, 
		   (sasl_free_t *) &free);

    /* set the SASL mutex functions */
    sasl_set_mutex((sasl_mutex_alloc_t *) &cyrus_mutex_alloc,
                   (sasl_mutex_lock_t *) &cyrus_mutex_lock,
                   (sasl_mutex_unlock_t *) &cyrus_mutex_unlock,
                   (sasl_mutex_free_t *) &cyrus_mutex_free);

    if(client && sasl_client_init(callbacks)) {
	fatal("could not init sasl (client)", EC_SOFTWARE);
    }

    if(server && sasl_server_init(callbacks, "Cyrus")) {
	fatal("could not init sasl (client)", EC_SOFTWARE);
    }
}

/* this is a wrapper to call the cyrus configuration from SASL */
int mysasl_config(void *context __attribute__((unused)), 
		  const char *plugin_name,
		  const char *option,
		  const char **result,
		  unsigned *len)
{
    char opt[1024];

    if (!strcmp(option, "srvtab")) { 
	/* we don't transform srvtab! */
	*result = config_getstring(IMAPOPT_SRVTAB);
    } else {
	*result = NULL;

	if (plugin_name) {
	    /* first try it with the plugin name */
	    strlcpy(opt, "sasl_", sizeof(opt));
	    strlcat(opt, plugin_name, sizeof(opt));
	    strlcat(opt, "_", sizeof(opt));
	    strlcat(opt, option, sizeof(opt));
	    *result = config_getoverflowstring(opt, NULL);
	}

	if (*result == NULL) {
	    /* try without the plugin name */
	    strlcpy(opt, "sasl_", sizeof(opt));
	    strlcat(opt, option, sizeof(opt));
	    *result = config_getoverflowstring(opt, NULL);
	}
    }

    if (*result != NULL) {
	if (len) { *len = strlen(*result); }
	return SASL_OK;
    }
   
    return SASL_FAIL;
}

/* This creates a structure that defines the allowable
 *   security properties 
 */
sasl_security_properties_t *mysasl_secprops(int flags)
{
    static sasl_security_properties_t ret;

    ret.maxbufsize = PROT_BUFSIZE;
    ret.min_ssf = config_getint(IMAPOPT_SASL_MINIMUM_LAYER);	
				/* minimum allowable security strength */
    ret.max_ssf = config_getint(IMAPOPT_SASL_MAXIMUM_LAYER);
				/* maximum allowable security strength */

    ret.security_flags = flags;
    /* ret.security_flags |= SASL_SEC_NOPLAINTEXT; */
    if (!config_getswitch(IMAPOPT_ALLOWANONYMOUSLOGIN)) {
	ret.security_flags |= SASL_SEC_NOANONYMOUS;
    }
    ret.property_names = NULL;
    ret.property_values = NULL;

    return &ret;
}

/* true if 'authstate' is in 'opt' */
int global_authisa(struct auth_state *authstate, enum imapopt opt)
{
    char buf[1024];
    const char *val = config_getstring(opt);

    /* Is the option defined? */
    if(!val) return 0;

    while (*val) {
	char *p;
	
	for (p = (char *) val; *p && !isspace((int) *p); p++);
	memcpy(buf, val, p-val);
	buf[p-val] = 0;

	if (auth_memberof(authstate, buf)) {
	    return 1;
	}
	val = p;
	while (*val && isspace((int) *val)) val++;
    }

    return 0;
}

char *canonify_userid(char *user, char *loginid, int *domain_from_ip)
{
    char *domain = NULL;
    int len = strlen(user);
    char buf[81];

    /* check for domain */
    if (config_virtdomains &&
	((domain = strrchr(user, '@')) || (domain = strrchr(user, '%')))) {
	*domain = '@';
	len = domain - user;
    }

    /* check for global identifiers */
    if (len == 9 && strncasecmp(user, "anonymous", len) == 0) {
	return "anonymous";
    }
    else if ((len == 7 && strncasecmp(user, "anybody", len) == 0) ||
	     (len == 6 && strncasecmp(user, "anyone", len) == 0)) {
	return "anyone";
    }

    if (config_virtdomains) {
	if (domain) {
	    if (config_defdomain && !strcasecmp(config_defdomain, domain+1)) {
		*domain = '\0'; /* trim the default domain */
	    }
	}
	else if (loginid) { /* used for LISTRIGHTS */
	    if ((domain = strrchr(loginid, '@'))) {
		/* append the domain from the login id */
		snprintf(buf, sizeof(buf), "%s@%s", user, domain+1);
		user = buf;
	    }
	}
	else {
	    socklen_t salen;
	    int error;
	    struct sockaddr_storage localaddr;
	    char hbuf[NI_MAXHOST];
	    
	    salen = sizeof(localaddr);
	    if (getsockname(0, (struct sockaddr *)&localaddr, &salen) == 0) {
		error = getnameinfo((struct sockaddr *)&localaddr, salen,
				    hbuf, sizeof(hbuf), NULL, 0,
				    NI_NAMEREQD | NI_WITHSCOPEID);
		if (error == 0 && (domain = strchr(hbuf, '.')) &&
		    !(config_defdomain && !strcasecmp(config_defdomain, domain+1))) {
		    /* append the domain from our IP */
		    snprintf(buf, sizeof(buf), "%s@%s", user, domain+1);
		    user = buf;
		    
		    if (domain_from_ip) *domain_from_ip = 1;
		}
	    }
	}
    }

    return auth_canonifyid(user, 0);
}

int mysasl_canon_user(sasl_conn_t *conn,
		      void *context,
		      const char *user, unsigned ulen,
		      unsigned flags __attribute__((unused)),
		      const char *user_realm __attribute__((unused)),
		      char *out,
		      unsigned out_max, unsigned *out_ulen)
{
    char *canonuser = NULL;

    if (ulen > out_max) {
	sasl_seterror(conn, 0, "buffer overflow while canonicalizing");
	return SASL_BUFOVER;
    }
    memcpy(out, user, ulen);
    out[ulen] = '\0';

    canonuser = canonify_userid(out, NULL, (int*) context);
    if (!canonuser) {
	sasl_seterror(conn, 0, "bad userid authenticated");
	return SASL_BADAUTH;
    }
    *out_ulen = strlen(canonuser);
    if (*out_ulen > out_max) {
	sasl_seterror(conn, 0, "buffer overflow while canonicalizing");
	return SASL_BUFOVER;
    }
    
    strncpy(out, canonuser, out_max);

    return SASL_OK;
}

/*
 * acl_ok() checks to see if the the inbox for 'user' grants the 'a'
 * right to 'authstate'. Returns 1 if so, 0 if not.
 */
/* Note that we do not determine if the mailbox is remote or not */
static int acl_ok(const char *user, struct auth_state *authstate)
{
    struct namespace namespace;
    char *acl;
    char bufuser[MAX_MAILBOX_NAME], inboxname[MAX_MAILBOX_NAME];
    int r;

    /* Set namespace */
    if ((r = mboxname_init_namespace(&namespace, 0)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }
    
    strlcpy(bufuser, user, sizeof(bufuser));

    /* Translate any separators in userid */
    mboxname_hiersep_tointernal(&namespace, bufuser,
				config_virtdomains ?
				strcspn(bufuser, "@") : 0);

    if (!r)
	r = (*namespace.mboxname_tointernal)(&namespace, "INBOX",
					     bufuser, inboxname);

    if (r || !authstate ||
	mboxlist_lookup(inboxname, NULL, &acl, NULL)) {
	r = 0;  /* Failed so assume no proxy access */
    }
    else {
	r = (cyrus_acl_myrights(authstate, acl) & ACL_ADMIN) != 0;
    }
    return r;
}

/* should we allow users to proxy?  return SASL_OK if yes,
   SASL_BADAUTH otherwise */
int mysasl_proxy_policy(sasl_conn_t *conn,
			void *context,
			const char *requested_user, unsigned rlen,
			const char *auth_identity, unsigned alen,
			const char *def_realm __attribute__((unused)),
			unsigned urlen __attribute__((unused)),
			struct propctx *propctx __attribute__((unused)))
{
    struct proxy_context *ctx = (struct proxy_context *) context;
    const char *val = config_getstring(IMAPOPT_LOGINREALMS);
    struct auth_state *authstate;
    int userisadmin = 0;
    char *realm;

    /* check if remote realm */
    if ((!config_virtdomains || *val) &&
	(realm = strchr(auth_identity, '@'))!=NULL) {
	realm++;
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
	    sasl_seterror(conn, 0, "cross-realm login %s denied",
			  auth_identity);
	    return SASL_BADAUTH;
	}
    }

    authstate = auth_newstate(auth_identity);

    /* ok, is auth_identity an admin? */
    userisadmin = global_authisa(authstate, IMAPOPT_ADMINS);

    if (!ctx) {
	/* for now only admins are allowed */
	auth_freestate(authstate);
    
	if (!userisadmin) {
	    sasl_seterror(conn, 0, "only admins may authenticate");
	    return SASL_BADAUTH;
	}

	return SASL_OK;
    }

    if (alen != rlen || strncmp(auth_identity, requested_user, alen)) {
	/* we want to authenticate as a different user; we'll allow this
	   if we're an admin or if we've allowed ACL proxy logins */
	int use_acl = ctx->use_acl && config_getswitch(IMAPOPT_LOGINUSEACL);

	if (userisadmin ||
	    (use_acl && acl_ok(requested_user, authstate)) ||
	    (ctx->proxy_servers &&
	     global_authisa(authstate, IMAPOPT_PROXYSERVERS))) {
	    /* proxy ok! */

	    userisadmin = 0;	/* no longer admin */
	    auth_freestate(authstate);
	    
	    authstate = auth_newstate(requested_user);

	    /* are we a proxy admin? */
	    if (ctx->userisproxyadmin)
		*(ctx->userisproxyadmin) =
		    global_authisa(authstate, IMAPOPT_ADMINS);
	} else {
	    sasl_seterror(conn, 0, "user %s is not allowed to proxy",
			  auth_identity);

	    auth_freestate(authstate);

	    return SASL_BADAUTH;
	}
    }

    if (ctx->authstate)
	*(ctx->authstate) = authstate;
    else 
	auth_freestate(authstate);
    if (ctx->userisadmin) *(ctx->userisadmin) = userisadmin;

    return SASL_OK;
}

/* covert a time_t date to an IMAP-style date
 * datebuf needs to be >= 30 bytes */
void cyrus_ctime(time_t date, char *datebuf) 
{
    struct tm *tm = localtime(&date);
    long gmtoff = gmtoff_of(tm, date);
    int gmtnegative = 0;
    static const char *monthname[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    if (date == 0 || tm->tm_year < 69) {
	abort();
    }

    if (gmtoff < 0) {
	gmtoff = -gmtoff;
	gmtnegative = 1;
    }
    gmtoff /= 60;
    sprintf(datebuf,
	    "%2u-%s-%u %.2u:%.2u:%.2u %c%.2lu%.2lu",
	    tm->tm_mday, monthname[tm->tm_mon], tm->tm_year+1900,
	    tm->tm_hour, tm->tm_min, tm->tm_sec,
	    gmtnegative ? '-' : '+', gmtoff/60, gmtoff%60);
}

/* call before a cyrus application exits */
void cyrus_done() 
{
    if(cyrus_init_run != RUNNING) return;
    cyrus_init_run = DONE;
    
    libcyrus_done();
}

/*
 * Returns 1 if we have a shutdown file, with the first line in buf.
 * Otherwise returns 0, and the contents of buf is undefined.
 */
int shutdown_file(char *buf, int size)
{
    FILE *f;
    static char shutdownfilename[1024] = "";
    char *p;
    
    if (!shutdownfilename[0])
	snprintf(shutdownfilename, sizeof(shutdownfilename), 
		 "%s/msg/shutdown", config_dir);
    if ((f = fopen(shutdownfilename, "r")) == NULL) return 0;

    fgets(buf, size, f);
    if ((p = strchr(buf, '\r')) != NULL) *p = 0;
    if ((p = strchr(buf, '\n')) != NULL) *p = 0;

    syslog(LOG_WARNING, "%s, closing connection", buf);

    return 1;
}
