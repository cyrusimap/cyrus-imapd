/* config.c -- Configuration routines
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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

/* $Id: config.c,v 1.62 2003/02/05 20:43:00 ken3 Exp $ */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <com_err.h>
#include <sys/types.h>
#include <sys/stat.h>

#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>

#include "acl.h"
#include "imapconf.h"
#include "exitcodes.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "util.h"
#include "imap_err.h"
#include "mupdate_err.h"
#include "hash.h"
#include "prot.h" /* for PROT_BUFSIZE */

#define CONFIG_FILENAME "/etc/imapd.conf"

#define CONFIGHASHSIZE 200 /* > 2x # of options */
static struct hash_table confighash;

/* cached configuration variables accessible to the external world */
const char *config_filename;     /* filename of configuration file */
const char *config_dir;		           /* ie /var/imap */
const char *config_defpartition;           /* /var/spool/imap */
const char *config_newsspool;	           /* /var/spool/news */
const char *config_servername;	           /* gethostname() */
const char *config_mupdate_server;         /* NULL */
int config_hashimapspool;	           /* f */

static void config_read(const char *alt_config);

int config_init(const char *alt_config, const char *ident)
{
    char buf[100];
    char *p;
    const char *val;
    int umaskval = 0;

    initialize_imap_error_table();
    initialize_mupd_error_table();

    openlog(ident, LOG_PID, LOG_LOCAL6);

    if(!construct_hash_table(&confighash, CONFIGHASHSIZE, 1)) {
	fatal("could not construct configuration hash table", EC_CONFIG);
    }

    config_read(alt_config);

    /* Look up configdirectory config option */
    config_dir = config_getstring("configdirectory", (char *)0);
    if (!config_dir) {
	fatal("configdirectory option not specified in configuration file",
	      EC_CONFIG);
    }

    /* Look up default partition */
    config_defpartition = config_getstring("defaultpartition", "default");
    for (p = (char *)config_defpartition; *p; p++) {
	if (!isalnum((unsigned char) *p))
	  fatal("defaultpartition option contains non-alphanumeric character",
		EC_CONFIG);
	if (isupper((unsigned char) *p)) *p = tolower((unsigned char) *p);
    }
    if (!config_partitiondir(config_defpartition)) {
	snprintf(buf, sizeof(buf),
		"partition-%s option not specified in configuration file",
		config_defpartition);
	fatal(buf, EC_CONFIG);
    }

    /* Look up umask */
    val = config_getstring("umask", "077");
    while (*val) {
	if (*val >= '0' && *val <= '7') umaskval = umaskval*8 + *val - '0';
	val++;
    }
    umask(umaskval);

    /* Look up news spool */
    config_newsspool = config_getstring("newsspool", 0);

    /* look up mailbox hashing */
    config_hashimapspool = config_getswitch("hashimapspool", 0);

    /* look up the hostname we should present to the user */
    config_servername = config_getstring("servername", 0);
    if (!config_servername) {
	config_servername = xmalloc(sizeof(char) * 256);
	gethostname((char *) config_servername, 256);
    }

    config_mupdate_server = config_getstring("mupdate_server", NULL);

    return 0;
}

int config_changeident(const char *ident)
{
    closelog();
    openlog(ident, LOG_PID, LOG_LOCAL6);
    return 0;
}

const char *config_getstring(const char *key, const char *def)
{
    char *ret;

    ret = hash_lookup(key, &confighash);

    return ret ? ret : def;
}

int config_getint(const char *key, int def)
{
    const char *val = config_getstring(key, (char *)0);

    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) 
	return def;
    return atoi(val);
}

int config_getswitch(const char *key, int def)
{
    const char *val = config_getstring(key, (char *)0);

    if (!val) return def;

    if (*val == '0' || *val == 'n' ||
	(*val == 'o' && val[1] == 'f') || *val == 'f') {
	return 0;
    }
    else if (*val == '1' || *val == 'y' ||
	     (*val == 'o' && val[1] == 'n') || *val == 't') {
	return 1;
    }
    return def;
}

const char *config_partitiondir(const char *partition)
{
    char buf[80];

    if (strlen(partition) > 70) return 0;
    strcpy(buf, "partition-");
    strcat(buf, partition);

    return config_getstring(buf, (char *)0);
}

static void config_read(const char *alt_config)
{
    FILE *infile;
    int lineno = 0;
    char buf[4096];
    char *p, *q, *key, *val, *newval;

    if(alt_config) config_filename = xstrdup(alt_config);
    else config_filename = xstrdup(CONFIG_FILENAME);

    infile = fopen(alt_config ? alt_config : CONFIG_FILENAME, "r");
    if (!infile) {
	strcpy(buf, CYRUS_PATH);
	strcat(buf, alt_config ? alt_config : CONFIG_FILENAME);
	infile = fopen(buf, "r");
    }
    if (!infile) {
	snprintf(buf, sizeof(buf), "can't open configuration file %s: %s",
		alt_config ? alt_config : CONFIG_FILENAME,
		error_message(errno));
	fatal(buf, EC_CONFIG);
    }
    
    while (fgets(buf, sizeof(buf), infile)) {
	lineno++;

	if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
	for (p = buf; *p && isspace((int) *p); p++);
	if (!*p || *p == '#') continue;

	key = p;
	while (*p && (isalnum((int) *p) || *p == '-' || *p == '_')) {
	    if (isupper((unsigned char) *p)) *p = tolower((unsigned char) *p);
	    p++;
	}
	if (*p != ':') {
	    snprintf(buf, sizeof(buf),
		    "invalid option name on line %d of configuration file",
		    lineno);
	    fatal(buf, EC_CONFIG);
	}
	*p++ = '\0';

	while (*p && isspace((int) *p)) p++;

	/* remove trailing whitespace */
	for (q = p + strlen(p) - 1; q > p && isspace((int) *q); q--) {
	    *q = '\0';
	}
	
	if (!*p) {
	    snprintf(buf, sizeof(buf),
		    "empty option value on line %d of configuration file",
		    lineno);
	    fatal(buf, EC_CONFIG);
	}

	newval = xstrdup(p);
	val = hash_insert(key, newval, &confighash);
	if(val != newval) {
	    char errbuf[4096];
	    snprintf(errbuf, sizeof(errbuf), 
		    "option '%s' was specified twice in config file", key);
	    fatal(errbuf, EC_CONFIG);
	}
    }
    fclose(infile);
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
	*result = config_getstring(option, NULL);
    } else {
	*result = NULL;

	if (plugin_name) {
	    /* first try it with the plugin name */
	    strlcpy(opt, "sasl_", sizeof(opt));
	    strlcat(opt, plugin_name, sizeof(opt));
	    strlcat(opt, "_", sizeof(opt));
	    strlcat(opt, option, sizeof(opt));
	    *result = config_getstring(opt, NULL);
	}

	if (*result == NULL) {
	    /* try without the plugin name */
	    strlcpy(opt, "sasl_", sizeof(opt));
	    strlcat(opt, option, sizeof(opt));
	    *result = config_getstring(opt, NULL);
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
    ret.min_ssf = config_getint("sasl_minimum_layer", 0);	
				/* minimum allowable security strength */
    ret.max_ssf = config_getint("sasl_maximum_layer", 256);
				/* maximum allowable security strength */

    ret.security_flags = flags;
    /* ret.security_flags |= SASL_SEC_NOPLAINTEXT; */
    if (!config_getswitch("allowanonymouslogin", 0)) {
	ret.security_flags |= SASL_SEC_NOANONYMOUS;
    }
    ret.property_names = NULL;
    ret.property_values = NULL;

    return &ret;
}

/* true if 'authstate' is in 'val' */
static int isa(struct auth_state *authstate, const char *opt)
{
    char buf[1024];
    const char *val = config_getstring(opt, "");

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

/* 
 * check 'service_class' and 'class'
 */
int authisa(struct auth_state *authstate, 
	    const char *service, 
	    const char *class)
{
    char buf[512];

    if (!authstate) {
	/* not authenticated? */
	return 0;
    }

    /* 'class' */
    if (isa(authstate, class)) {
	return 1;
    }

    /* 'service_class' */
    snprintf(buf, sizeof(buf), "%s_%s", service, class);
    if (isa(authstate, buf)) {
	return 1;
    }
    
    return 0;
}

#if HAS_SASL_2_1
int mysasl_canon_user(sasl_conn_t *conn,
		      void *context __attribute__((unused)),
		      const char *user, unsigned ulen,
		      unsigned flags __attribute__((unused)),
		      const char *user_realm __attribute__((unused)),
		      char *out,
		      unsigned out_max, unsigned *out_ulen)
{
    char *canonuser = NULL;

    canonuser = auth_canonifyid(user, ulen);
    if (!canonuser) {
	sasl_seterror(conn, 0, "bad userid authenticated");
	return SASL_BADAUTH;
    }
    *out_ulen = strlen(canonuser);
    if(*out_ulen > out_max) {
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
    char inboxname[1024];
    int r;

    /* Set namespace */
    if ((r = mboxname_init_namespace(&namespace, 0)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }
    
    mboxname_hiersep_tointernal(&namespace, user);

    if (!r)
	r = (*namespace.mboxname_tointernal)(&namespace, "INBOX",
					     user, inboxname);

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
    const char *val;
    struct auth_state *authstate;
    int userisadmin = 0;
    char *realm;

    /* check if remote realm */
    if ((realm = strchr(auth_identity, '@'))!=NULL) {
	realm++;
	val = config_getstring("loginrealms", "");
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

    authstate = auth_newstate(auth_identity, NULL);

    /* ok, is auth_identity an admin? */
    userisadmin = authisa(authstate, "imap", "admins");

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
	int use_acl = ctx->use_acl && config_getswitch("loginuseacl", 0);

	if (userisadmin ||
	    (use_acl && acl_ok(requested_user, authstate)) ||
	    (ctx->proxy_servers &&
	     authisa(authstate, "imap", "proxyservers"))) {
	    /* proxy ok! */

	    userisadmin = 0;	/* no longer admin */
	    auth_freestate(authstate);
	    
	    authstate = auth_newstate(requested_user, NULL);

	    /* are we a proxy admin? */
	    if (ctx->userisproxyadmin)
		*(ctx->userisproxyadmin) =
		    authisa(authstate, "imap", "admins");
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
#else /* SASL 2.0 */
int mysasl_canon_user(sasl_conn_t *conn,
                      void *context,
                      const char *user, unsigned ulen,
                      const char *authid, unsigned alen,
                      unsigned flags,
                      const char *user_realm,
                      char *out_user,
                      unsigned out_max, unsigned *out_ulen,
                      char *out_authid,
                      unsigned out_amax, unsigned *out_alen)
{
    char *canon_authuser = NULL, *canon_requser = NULL;
        
    canon_authuser = auth_canonifyid(authid, alen);
    if (!canon_authuser) {
	sasl_seterror(conn, 0, "bad userid authenticated");
	return SASL_BADAUTH;
    }
    *out_alen = strlen(canon_authuser);
    if(*out_alen > out_amax) {
	sasl_seterror(conn, 0, "buffer overflow while canonicalizing");
	return SASL_BUFOVER;
    }
                      
    strncpy(out_authid, canon_authuser, out_amax);
                      
    if (!user) {
	/* don't bother calling auth_canonifyid twice */
	canon_requser = canon_authuser;
    } else {
	canon_requser = auth_canonifyid(user, ulen);
    }
        
    if (!canon_requser) {   
 	sasl_seterror(conn, 0, "bad userid requested");
 	return SASL_BADAUTH;
    }
    *out_ulen = strlen(canon_requser);
    if(*out_ulen > out_max) {
	sasl_seterror(conn, 0, "buffer overflow while canonicalizing");
	return SASL_BUFOVER;
    }
                      
    strncpy(out_user, canon_requser, out_max);
        
    return SASL_OK;
}
#endif
