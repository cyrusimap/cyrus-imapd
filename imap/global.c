/* global.c -- Configuration routines
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
 *
 * $Id: global.c,v 1.35 2010/04/22 17:29:53 murch Exp $
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>

#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>

#include "acl.h"
#include "charset.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "gmtoff.h"
#include "hash.h"
#include "imap_err.h"
#include "iptostring.h"
#include "global.h"
#include "libconfig.h"
#include "libcyr_cfg.h"
#include "mboxlist.h"
#include "mkgmtime.h"
#include "mupdate_err.h"
#include "mutex.h"
#include "prot.h" /* for PROT_BUFSIZE */
#include "strarray.h"
#include "userdeny.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

static enum {
    NOT_RUNNING = 0,
    RUNNING = 1,
    DONE = 2
} cyrus_init_run = NOT_RUNNING;

static int cyrus_init_nodb = 0;

int in_shutdown = 0;

int config_fulldirhash;				/* 0 */
int config_implicitrights;			/* "lkxa" */
unsigned long config_metapartition_files;	/* 0 */
const char *config_mboxlist_db;
const char *config_quota_db;
const char *config_subscription_db;
const char *config_annotation_db;
const char *config_seenstate_db;
const char *config_mboxkey_db;
const char *config_duplicate_db;
const char *config_tlscache_db;
const char *config_ptscache_db;
const char *config_statuscache_db;
const char *config_userdeny_db;
int charset_flags;

#define MAX_SESSIONID_SIZE 256
char session_id_buf[MAX_SESSIONID_SIZE];
int session_id_time = 0;
int session_id_count = 0;

strarray_t *suppressed_capabilities = NULL;

/* Called before a cyrus application starts (but after command line parameters
 * are read) */
int cyrus_init(const char *alt_config, const char *ident, unsigned flags)
{
    char *p;
    const char *val;
    const char *prefix;
    int umaskval = 0;
    int syslog_opts = LOG_PID;

    if(cyrus_init_run != NOT_RUNNING) {
	fatal("cyrus_init called twice!", EC_CONFIG);
    } else {
	cyrus_init_run = RUNNING;
    }

    cyrus_init_nodb = (flags & CYRUSINIT_NODB);
#ifdef LOG_PERROR
    if ((flags & CYRUSINIT_PERROR))
	syslog_opts |= LOG_PERROR;
#endif

    initialize_imap_error_table();
    initialize_mupd_error_table();

    if(!ident)
	fatal("service name was not specified to cyrus_init", EC_CONFIG);

    config_ident = ident;
    
    /* xxx we lose here since we can't have the prefix until we load the
     * config file */
    openlog(config_ident, syslog_opts, SYSLOG_FACILITY);

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
	openlog(ident_buf, syslog_opts, SYSLOG_FACILITY);

	/* don't free the openlog() string! */
    }

    /* allow debug logging */
    if (!config_debug)
	setlogmask(~LOG_MASK(LOG_DEBUG));

    /* Look up default partition */
    config_defpartition = config_getstring(IMAPOPT_DEFAULTPARTITION);
    for (p = (char *)config_defpartition; p && *p; p++) {
	if (!Uisalnum(*p))
	  fatal("defaultpartition option contains non-alphanumeric character",
		EC_CONFIG);
	if (Uisupper(*p)) *p = tolower((unsigned char) *p);
    }

    /* Look up umask */
    val = config_getstring(IMAPOPT_UMASK);
    while (*val) {
	if (*val >= '0' && *val <= '7') umaskval = umaskval*8 + *val - '0';
	val++;
    }
    umask(umaskval);

    config_fulldirhash = config_getswitch(IMAPOPT_FULLDIRHASH);

    /* look up and canonify the implicit rights of mailbox owners */
    config_implicitrights =
	cyrus_acl_strtomask(config_getstring(IMAPOPT_IMPLICIT_OWNER_RIGHTS));

    config_metapartition_files = config_getbitfield(IMAPOPT_METAPARTITION_FILES);

    val = config_getstring(IMAPOPT_SUPPRESS_CAPABILITIES);
    if (val)
	suppressed_capabilities = strarray_split(val, NULL);
    if (config_getswitch(IMAPOPT_SEARCH_SKIPDIACRIT))
	charset_flags |= CHARSET_SKIPDIACRIT;

    switch (config_getenum(IMAPOPT_SEARCH_WHITESPACE)) {
	case IMAP_ENUM_SEARCH_WHITESPACE_MERGE:
	    charset_flags |= CHARSET_MERGESPACE;
	    break;
	case IMAP_ENUM_SEARCH_WHITESPACE_SKIP:
	    charset_flags |= CHARSET_SKIPSPACE;
	    break;
	default:
	    break;
    }

    if (!cyrus_init_nodb) {
	/* lookup the database backends */
	config_mboxlist_db = config_getstring(IMAPOPT_MBOXLIST_DB);
	config_quota_db = config_getstring(IMAPOPT_QUOTA_DB);
	config_subscription_db = config_getstring(IMAPOPT_SUBSCRIPTION_DB);
	config_annotation_db = config_getstring(IMAPOPT_ANNOTATION_DB);
	config_seenstate_db = config_getstring(IMAPOPT_SEENSTATE_DB);
	config_mboxkey_db = config_getstring(IMAPOPT_MBOXKEY_DB);
	config_duplicate_db = config_getstring(IMAPOPT_DUPLICATE_DB);
	config_tlscache_db = config_getstring(IMAPOPT_TLSCACHE_DB);
	config_ptscache_db = config_getstring(IMAPOPT_PTSCACHE_DB);
	config_statuscache_db = config_getstring(IMAPOPT_STATUSCACHE_DB);
	config_userdeny_db = config_getstring(IMAPOPT_USERDENY_DB);

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
	libcyrus_config_setswitch(CYRUSOPT_FULLDIRHASH,
				  config_getswitch(IMAPOPT_FULLDIRHASH));
	libcyrus_config_setstring(CYRUSOPT_PTSCACHE_DB,
				  config_getstring(IMAPOPT_PTSCACHE_DB));
	libcyrus_config_setstring(CYRUSOPT_PTSCACHE_DB_PATH,
				  config_getstring(IMAPOPT_PTSCACHE_DB_PATH));
	libcyrus_config_setstring(CYRUSOPT_PTLOADER_SOCK,
				  config_getstring(IMAPOPT_PTLOADER_SOCK));
	libcyrus_config_setswitch(CYRUSOPT_VIRTDOMAINS,
				  config_getenum(IMAPOPT_VIRTDOMAINS));
	libcyrus_config_setint(CYRUSOPT_BERKELEY_CACHESIZE,
			       config_getint(IMAPOPT_BERKELEY_CACHESIZE));
	libcyrus_config_setstring(CYRUSOPT_AUTH_MECH,
				  config_getstring(IMAPOPT_AUTH_MECH));
	libcyrus_config_setint(CYRUSOPT_BERKELEY_LOCKS_MAX,
			       config_getint(IMAPOPT_BERKELEY_LOCKS_MAX));
	libcyrus_config_setint(CYRUSOPT_BERKELEY_TXNS_MAX,
			       config_getint(IMAPOPT_BERKELEY_TXNS_MAX));
	libcyrus_config_setstring(CYRUSOPT_DELETERIGHT,
				  config_getstring(IMAPOPT_DELETERIGHT));
	libcyrus_config_setstring(CYRUSOPT_SQL_DATABASE,
				  config_getstring(IMAPOPT_SQL_DATABASE));
	libcyrus_config_setstring(CYRUSOPT_SQL_ENGINE,
				  config_getstring(IMAPOPT_SQL_ENGINE));
	libcyrus_config_setstring(CYRUSOPT_SQL_HOSTNAMES,
				  config_getstring(IMAPOPT_SQL_HOSTNAMES));
	libcyrus_config_setstring(CYRUSOPT_SQL_USER,
				  config_getstring(IMAPOPT_SQL_USER));
	libcyrus_config_setstring(CYRUSOPT_SQL_PASSWD,
				  config_getstring(IMAPOPT_SQL_PASSWD));
	libcyrus_config_setswitch(CYRUSOPT_SQL_USESSL,
				  config_getswitch(IMAPOPT_SQL_USESSL));
	libcyrus_config_setswitch(CYRUSOPT_SKIPLIST_ALWAYS_CHECKPOINT,
				  config_getswitch(IMAPOPT_SKIPLIST_ALWAYS_CHECKPOINT));

	/* Not until all configuration parameters are set! */
	libcyrus_init();
    }
    
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
		   (sasl_calloc_t *) &xcalloc,
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
	fatal("could not init sasl (server)", EC_SOFTWARE);
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
    if (!config_getswitch(IMAPOPT_ALLOWPLAINTEXT)) {
	ret.security_flags |= SASL_SEC_NOPLAINTEXT;
    }
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
    size_t len;

    /* Is the option defined? */
    if(!val) return 0;

    while (*val) {
	char *p;
	
	for (p = (char *) val; *p && !Uisspace(*p); p++);
	len = p-val;
	if(len >= sizeof(buf))
	    len = sizeof(buf) - 1;
	memcpy(buf, val, len);
	buf[len] = '\0';

	if (auth_memberof(authstate, buf)) {
	    return 1;
	}
	val = p;
	while (*val && Uisspace(*val)) val++;
    }

    return 0;
}

/* Note: This function is not idempotent! Only call it once for a given ID
 * or you will be unhappy (think IP hosting). */
const char *canonify_userid(char *user, const char *loginid,
			    int *domain_from_ip)
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
    if (is_userid_anonymous(user)) {
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
	else if (config_virtdomains != IMAP_ENUM_VIRTDOMAINS_USERID) {
	    socklen_t salen;
	    int error;
	    struct sockaddr_storage localaddr;
	    char hbuf[NI_MAXHOST];
	    
	    salen = sizeof(localaddr);
	    if (getsockname(0, (struct sockaddr *)&localaddr, &salen) == 0) {
		error = getnameinfo((struct sockaddr *)&localaddr, salen,
				    hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD);
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
    const char *canonuser = NULL;

    if (ulen+1 > out_max) {
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
    if (*out_ulen >= out_max) {
	sasl_seterror(conn, 0, "buffer overflow while canonicalizing");
	return SASL_BUFOVER;
    }
    
    strcpy(out, canonuser);

    return SASL_OK;
}

int is_userid_anonymous(const char *user) 
{
    int len = strlen(user);
    const char *domain;

    assert(user);

    /* check for domain */
    if (config_virtdomains &&
	((domain = strrchr(user, '@')) || (domain = strrchr(user, '%')))) {
	len = domain - user;
    }

    /* check if we are anonymous */
    if (len == 9 && strncasecmp(user, "anonymous", len) == 0) {
	return 1;
    } else {
	return 0;
    }
}

/*
 * acl_ok() checks to see if the the inbox for 'user' grants the 'a'
 * right to 'authstate'. Returns 1 if so, 0 if not.
 */
/* Note that we do not determine if the mailbox is remote or not */
static int acl_ok(const char *user, struct auth_state *authstate)
{
    struct namespace namespace;
    struct mboxlist_entry *mbentry = NULL;
    char bufuser[MAX_MAILBOX_BUFFER], inboxname[MAX_MAILBOX_BUFFER];
    int r;

    /* Set namespace */
    if ((r = mboxname_init_namespace(&namespace, 0)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
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
	mboxlist_lookup(inboxname, &mbentry, NULL)) {
	r = 0;  /* Failed so assume no proxy access */
    }
    else {
	r = (cyrus_acl_myrights(authstate, mbentry->acl) & ACL_ADMIN) != 0;
    }
    mboxlist_entry_free(&mbentry);
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
		(!val[strlen(realm)] || Uisspace(val[strlen(realm)]))) {
		break;
	    }
	    /* not this realm, try next one */
	    while (*val && !Uisspace(*val)) val++;
	    while (*val && Uisspace(*val)) val++;
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
	    syslog(LOG_ERR, "%s is not an admin", auth_identity);
	    sasl_seterror(conn, SASL_NOLOG, "only admins may authenticate");
	    return SASL_BADAUTH;
	}

	return SASL_OK;
    }

    /* is requested_user denied access?  authenticated admins are exempt */
    if (!userisadmin && userdeny(requested_user, config_ident, NULL, 0)) {
	syslog(LOG_ERR, "user '%s' denied access to service '%s'",
	       requested_user, config_ident);
	sasl_seterror(conn, SASL_NOLOG,
		      "user '%s' is denied access to service '%s'",
		      requested_user, config_ident);

	auth_freestate(authstate);

	return SASL_NOAUTHZ;
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


/* call before a cyrus application exits */
void cyrus_done(void)
{
    if (cyrus_init_run != RUNNING)
	return;
    cyrus_init_run = DONE;

    if (!cyrus_init_nodb)
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

    f = fopen(shutdownfilename, "r");
    if (!f) return 0;

    if (!fgets(buf, size, f)) {
	*buf = '\0';

	syslog(LOG_DEBUG, "Shutdown file exists with no contents");
    }
    else {
	if ((p = strchr(buf, '\r')) != NULL) *p = 0;
	if ((p = strchr(buf, '\n')) != NULL) *p = 0;

	syslog(LOG_DEBUG, "Shutdown file: %s, closing connection", buf);
    }

    fclose(f);

    return 1;
}

struct part_stats {
    char name[MAX_PARTITION_LEN+1]; /* name of part with most space */
    unsigned long avail;	/* 1k free blocks on freeest part */
    unsigned long tavail;	/* total 1k free blocks on server */
    unsigned long fsid[512];	/* array of file system IDs */
    unsigned nfsid;		/* number of file system IDs */
};

/*
 * config_foreachoverflowstring() callback which finds spool partition
 * with the most available space and totals the space available on
 * all partitions.
 */
static void get_part_stats(const char *key, const char *val, void *rock)
{
    struct part_stats *stats = (struct part_stats *) rock;
    struct statvfs s;
    unsigned long avail;
    unsigned i;

    /* not a partition-* config option */
    if (strncmp("partition-", key, 10)) return;

    /* can't stat the given path */
    if (statvfs(val, &s)) return;

    /* eliminate duplicate filesystems */
    for (i = 0; i < stats->nfsid; i++) {
	if (s.f_fsid == stats->fsid[i]) return;
    }
    stats->fsid[stats->nfsid++] = s.f_fsid;

    /* calculate avail space in 1k blocks */
    avail = (unsigned long) (s.f_bavail * (s.f_frsize / 1024.0));

    /* add to total */
    stats->tavail += avail;

    if (avail > stats->avail) {
	/* this part has the most avail space */
	stats->avail = avail;
	strlcpy(stats->name, key+10, MAX_PARTITION_LEN);
    }
}

/*
 * Returns the name of the spool partition with the most available space.
 * Optionally returns the total amount of available space on the server
 * (all partitions) in 1k blocks.
 */
char *find_free_partition(unsigned long *tavail)
{
    static struct part_stats stats;

    memset(&stats, 0, sizeof(struct part_stats));
    config_foreachoverflowstring(get_part_stats, &stats);

    if (tavail) *tavail = stats.tavail;
    return stats.name;
}

/* Set up the Session ID Buffer */
void session_new_id(void)
{
    const char *base;
    int now = time(NULL);
    if (now != session_id_time) {
        session_id_time = now;
        session_id_count = 0;
    }
    ++session_id_count;
    base = config_getstring(IMAPOPT_SYSLOG_PREFIX);
    if (!base) base = config_servername;
    snprintf(session_id_buf, MAX_SESSIONID_SIZE, "%.128s-%d-%d-%d",
             base, getpid(), session_id_time, session_id_count);
}

/* Return the session id */
const char *session_id(void)
{
    if (!session_id_count) 
        session_new_id();
    return (const char *)session_id_buf;
}

int capa_is_disabled(const char *str)
{
    if (!suppressed_capabilities) return 0;

    return (strarray_find_case(suppressed_capabilities, str, 0) >= 0);
}


/* Find a message-id looking thingy in a string.  Returns a pointer to the
 * alloc'd id and the remaining string is returned in the **loc parameter.
 *
 * This is a poor-man's way of finding the message-id.  We simply look for
 * any string having the format "< ... @ ... >" and assume that the mail
 * client created a properly formatted message-id.
 */
#define MSGID_SPECIALS "<> @\\"

char *find_msgid(char *str, char **rem)
{
    char *msgid, *src, *dst, *cp;

    if (!str) return NULL;

    msgid = NULL;
    src = str;

    /* find the start of a msgid (don't go past the end of the header) */
    while ((cp = src = strpbrk(src, "<\r")) != NULL) {

	/* check for fold or end of header
	 *
	 * Per RFC 2822 section 2.2.3, a long header may be folded by
	 * inserting CRLF before any WSP (SP and HTAB, per section 2.2.2).
	 * Any other CRLF is the end of the header.
	 */
	if (*cp++ == '\r') {
	    if (*cp++ == '\n' && !(*cp == ' ' || *cp == '\t')) {
		/* end of header, we're done */
		break;
	    }

	    /* skip fold (or junk) */
	    src++;
	    continue;
	}

	/* see if we have (and skip) a quoted localpart */
	if (*cp == '\"') {
	    /* find the endquote, making sure it isn't escaped */
	    do {
		++cp; cp = strchr(cp, '\"');
	    } while (cp && *(cp-1) == '\\');

	    /* no endquote, so bail */
	    if (!cp) {
		src++;
		continue;
	    }
	}

	/* find the end of the msgid */
	if ((cp = strchr(cp, '>')) == NULL)
	    return NULL;

	/* alloc space for the msgid */
	dst = msgid = (char*) xrealloc(msgid, cp - src + 2);

	*dst++ = *src++;

	/* quoted string */
	if (*src == '\"') {
	    src++;
	    while (*src != '\"') {
		if (*src == '\\') {
		    src++;
		}
		*dst++ = *src++;
	    }
	    src++;
	}
	/* atom */
	else {
	    while (!strchr(MSGID_SPECIALS, *src))
		*dst++ = *src++;
	}

	if (*src != '@' || *(dst-1) == '<') continue;
	*dst++ = *src++;

	/* domain atom */
	while (!strchr(MSGID_SPECIALS, *src))
	    *dst++ = *src++;

	if (*src != '>' || *(dst-1) == '@') continue;
	*dst++ = *src++;
	*dst = '\0';

	if (rem) *rem = src;
	return msgid;
    }

    if (msgid) free(msgid);
    return NULL;
}

/*
 * Get name of client host on socket 's'.
 * Also returns local IP port and remote IP port on inet connections.
 */
const char *get_clienthost(int s, const char **localip, const char **remoteip)
{
#define IPBUF_SIZE (NI_MAXHOST+NI_MAXSERV+2)
    socklen_t salen;
    struct sockaddr_storage localaddr, remoteaddr;
    static struct buf clientbuf = BUF_INITIALIZER;
    static char lipbuf[IPBUF_SIZE], ripbuf[IPBUF_SIZE];
    char hbuf[NI_MAXHOST];
    int niflags;

    buf_reset(&clientbuf);
    *localip = *remoteip = NULL;

    /* determine who we're talking to */
    salen = sizeof(remoteaddr);
    if (getpeername(s, (struct sockaddr *)&remoteaddr, &salen) == 0 &&
	(remoteaddr.ss_family == AF_INET ||
	 remoteaddr.ss_family == AF_INET6)) {
	/* connected to an internet socket */
	if (getnameinfo((struct sockaddr *)&remoteaddr, salen,
			hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == 0) {
	    buf_printf(&clientbuf, "%s ", hbuf);
	}

	niflags = NI_NUMERICHOST;
#ifdef NI_WITHSCOPEID
	if (((struct sockaddr *)&remoteaddr)->sa_family == AF_INET6)
	    niflags |= NI_WITHSCOPEID;
#endif
	if (getnameinfo((struct sockaddr *)&remoteaddr, salen,
			hbuf, sizeof(hbuf), NULL, 0, niflags) != 0) {
	    strlcpy(hbuf, "unknown", sizeof(hbuf));
	}
	buf_printf(&clientbuf, "[%s]", hbuf);

	salen = sizeof(localaddr);
	if (getsockname(s, (struct sockaddr *)&localaddr, &salen) == 0) {
	    /* set the ip addresses here */
	    if (iptostring((struct sockaddr *)&localaddr, salen,
			  lipbuf, sizeof(lipbuf)) == 0) {
		*localip = lipbuf;
            }
            if (iptostring((struct sockaddr *)&remoteaddr, salen,
			  ripbuf, sizeof(ripbuf)) == 0) {
		*remoteip = ripbuf;
            }
	} else {
	    fatal("can't get local addr", EC_SOFTWARE);
	}
    } else {
	/* we're not connected to a internet socket! */
	buf_setcstr(&clientbuf, UNIX_SOCKET);
    }

    return buf_cstring(&clientbuf);
}
