/* ldap.c - LDAP Backend to ptloader */
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
 */

static char rcsid[] __attribute__((unused)) = 
      "$Id: ldap.c,v 1.5 2004/02/25 16:36:31 rjs3 Exp $";

#include <config.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <com_err.h>

#include <ldap.h>
#include <lber.h>

/* libimap */
#include "global.h"

/* libconfig */
#include "libconfig.h"

/* libcyrus */
#include "auth_pts.h"
#include "exitcodes.h"
#include "strhash.h"
#include "xmalloc.h"

/* xxx this just uses the UNIX canonicalization semantics, which is
 * most likely wrong */

/* Map of which characters are allowed by auth_canonifyid.
 * Key: 0 -> not allowed (special, ctrl, or would confuse Unix or imapd)
 *      1 -> allowed, but requires an alpha somewhere else in the string
 *      2 -> allowed, and is an alpha
 *
 * At least one character must be an alpha.
 *
 * This may not be restrictive enough.
 * Here are the reasons for the restrictions:
 *
 * &	forbidden because of MUTF-7.  (This could be fixed.)
 * :    forbidden because it's special in /etc/passwd
 * /    forbidden because it can't be used in a mailbox name
 * * %  forbidden because they're IMAP magic in the LIST/LSUB commands
 * ?    it just scares me
 * ctrl chars, DEL
 *      can't send them as IMAP characters in plain folder names, I think
 * 80-FF forbidden because you can't send them in IMAP anyway
 *       (and they're forbidden as folder names). (This could be fixed.)
 *
 * + and - are *allowed* although '+' is probably used for userid+detail
 * subaddressing and qmail users use '-' for subaddressing.
 *
 * Identifiers don't require a digit, really, so that should probably be
 * relaxed, too.
 */
static char allowedchars[256] = {
 /* 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 00-0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 10-1F */
    1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, /* 20-2F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, /* 30-3F */

    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 40-4F */
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, /* 50-5F */
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 60-6F */
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 0, /* 70-7F */

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

typedef struct _ptsm {
    const char   *uri;
    int    version;
    struct timeval timeout;
    int    size_limit;
    int    time_limit;
    int    deref;
    int    referrals;
    int    restart;
    int    scope;
    const char   *base;
    int    sasl;
    const char   *id;
    const char   *bind_dn;
    const char   *password;
    const char   *authz;
    const char   *mech;
    const char   *realm;
    const char   *filter;
    const char   *sasl_secprops;
    int    start_tls;
    int    tls_check_peer;
    const char   *tls_cacert_file;
    const char   *tls_cacert_dir;
    const char   *tls_ciphers;
    const char   *tls_cert;
    const char   *tls_key;
    int    member_method;
    const char   *member_attribute;
    const char   *member_filter;
    const char   *member_base;
    int    member_scope;
    const char   *group_filter;
    const char   *group_base;
    int    group_scope;
    LDAP   *ld;
} t_ptsm;

#define PTSM_OK 0
#define PTSM_FAIL -1
#define PTSM_NOMEM -2
#define PTSM_RETRY -3

#define PTSM_MEMBER_METHOD_ATTRIBUTE 0
#define PTSM_MEMBER_METHOD_FILTER 1

#define ISSET(x)  ((x != NULL) && (*(x) != '\0'))
#define EMPTY(x)  ((x == NULL) || (*(x) == '\0'))

static t_ptsm *ptsm = NULL;

static int ptsmodule_interact(
	LDAP *ld, 
	unsigned flags __attribute__((unused)), 
	void *def, 
	void *inter)
{
	sasl_interact_t *in = inter;
	const char *p;
	t_ptsm *ptsmdef = def;

	for (;in->id != SASL_CB_LIST_END;in++) {
		p = NULL;
		switch(in->id) {
			case SASL_CB_AUTHNAME:
				if (ISSET(ptsmdef->id))
					p = ptsmdef->id;
				break;
			case SASL_CB_USER:
				if (ISSET(ptsmdef->authz))
					p = ptsmdef->authz;
				break;
			case SASL_CB_GETREALM:
				if (ISSET(ptsmdef->realm))
					p = ptsmdef->realm;
				break;          
			case SASL_CB_PASS:
				if (ISSET(ptsmdef->password))
					p = ptsmdef->password;
				break;
		}

		in->result = p ? p : "";
		in->len = strlen(in->result);
	}

	return LDAP_SUCCESS;
}

/*
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 *
 * XXX If any of the characters marked with 0 are valid and are cropping up,
 * the right thing to do is probably to canonicalize the identifier to two
 * representations: one for getpwent calls and one for folder names.  The
 * latter canonicalizes to a MUTF7 representation.
 */
static char *ptsmodule_canonifyid(const char *identifier, size_t len)
{
    static char retbuf[81];
    char sawalpha;
    char *p;
    int username_tolower = 0;
    int i = 0;

    if(!len) len = strlen(identifier);
    if(len >= sizeof(retbuf)) return NULL;

    memcpy(retbuf, identifier, len);
    retbuf[len] = '\0';

    if (!strncmp(retbuf, "group:", 6))
        i = 6;

    /* Copy the string and look up values in the allowedchars array above.
     * If we see any we don't like, reject the string.
     * Lowercase usernames if requested.
     */
    username_tolower = config_getswitch(IMAPOPT_USERNAME_TOLOWER);
    sawalpha = 0;
    for(p = retbuf+i; *p; p++) {
        if (username_tolower && isupper((unsigned char)*p))
            *p = tolower((unsigned char)*p);

        switch (allowedchars[*(unsigned char*) p]) {
        case 0:
            return NULL;
            
        case 2:
            sawalpha = 1;
            /* FALL THROUGH */
            
        default:
            ;
        }
    }

    if (!sawalpha) return NULL;  /* has to be one alpha char */

    return retbuf;
}


static int ptsmodule_connect(void) 
{
	int rc = 0;

	if (ptsm == NULL)  // Sanity Check
		return PTSM_FAIL;

	if (ptsm->ld != NULL)
		return PTSM_OK;

	if (ISSET(ptsm->tls_cacert_file)) {
		rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTFILE, ptsm->tls_cacert_file);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING, "Unable to set LDAP_OPT_X_TLS_CACERTFILE (%s).", ldap_err2string (rc));
		}
	}

	if (ISSET(ptsm->tls_cacert_dir)) {
		rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTDIR, ptsm->tls_cacert_dir);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING, "Unable to set LDAP_OPT_X_TLS_CACERTDIR (%s).", ldap_err2string (rc));
		}
	}

	if (ptsm->tls_check_peer != 0) {
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &ptsm->tls_check_peer);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING, "Unable to set LDAP_OPT_X_TLS_REQUIRE_CERT (%s).", ldap_err2string (rc));
		}
	}

	if (ISSET(ptsm->tls_ciphers)) {
		/* set cipher suite, certificate and private key: */
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CIPHER_SUITE, ptsm->tls_ciphers);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING, "Unable to set LDAP_OPT_X_TLS_CIPHER_SUITE (%s).", ldap_err2string (rc));
		}
	}

	if (ISSET(ptsm->tls_cert)) {
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE, ptsm->tls_cert);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING, "Unable to set LDAP_OPT_X_TLS_CERTFILE (%s).", ldap_err2string (rc));
		}
	}

	if (ISSET(ptsm->tls_key)) {
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE, ptsm->tls_key);
		if (rc != LDAP_SUCCESS) {
			syslog (LOG_WARNING, "Unable to set LDAP_OPT_X_TLS_KEYFILE (%s).", ldap_err2string (rc));
		}
	}

	rc = ldap_initialize(&ptsm->ld, ptsm->uri);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ERR, "ldap_initialize failed (%s)", ptsm->uri);
		return PTSM_FAIL;
	}

	rc = ldap_set_option(ptsm->ld, LDAP_OPT_PROTOCOL_VERSION, &(ptsm->version));
	if (rc != LDAP_OPT_SUCCESS) {

		if (ptsm->sasl ||
		    ptsm->start_tls) {
			syslog(LOG_ERR, "Failed to set LDAP_OPT_PROTOCOL_VERSION %d, required for ldap_start_tls and ldap_sasl.", ptsm->version);
			ldap_unbind(ptsm->ld);
            ptsm->ld = NULL;
			return PTSM_FAIL;
		} else
			syslog(LOG_WARNING, "Unable to set LDAP_OPT_PROTOCOL_VERSION %d.", ptsm->version);

		ptsm->version = LDAP_VERSION2;
	}

	rc = ldap_set_option(ptsm->ld, LDAP_OPT_NETWORK_TIMEOUT, &(ptsm->timeout));
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING, "Unable to set LDAP_OPT_NETWORK_TIMEOUT %d.%d.", ptsm->timeout.tv_sec, ptsm->timeout.tv_usec);
	}

	rc = ldap_set_option(ptsm->ld, LDAP_OPT_TIMELIMIT, &(ptsm->time_limit));
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING, "Unable to set LDAP_OPT_TIMELIMIT %d.", ptsm->time_limit);
	}

	rc = ldap_set_option(ptsm->ld, LDAP_OPT_DEREF, &(ptsm->deref));
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING, "Unable to set LDAP_OPT_DEREF %d.", ptsm->deref);
	}

	rc = ldap_set_option(ptsm->ld, LDAP_OPT_REFERRALS, ptsm->referrals ? LDAP_OPT_ON : LDAP_OPT_OFF);
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING, "Unable to set LDAP_OPT_REFERRALS.");
	}

	rc = ldap_set_option(ptsm->ld, LDAP_OPT_SIZELIMIT, &(ptsm->size_limit));
	if (rc != LDAP_OPT_SUCCESS)
		syslog(LOG_WARNING, "Unable to set LDAP_OPT_SIZELIMIT %d.", ptsm->size_limit);

	rc = ldap_set_option(ptsm->ld, LDAP_OPT_RESTART, ptsm->restart ? LDAP_OPT_ON : LDAP_OPT_OFF);
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_WARNING, "Unable to set LDAP_OPT_RESTART.");
	}

	if (ptsm->start_tls) {

		rc = ldap_start_tls_s(ptsm->ld, NULL, NULL);
		if (rc != LDAP_SUCCESS) {
			syslog(LOG_ERR, "start tls failed (%s).", ldap_err2string(rc));
			ldap_unbind(ptsm->ld);
            ptsm->ld = NULL;
			return PTSM_FAIL;
		}
	}
	
	if (ptsm->sasl) {

		if (EMPTY(ptsm->mech))
			ldap_get_option(ptsm->ld, LDAP_OPT_X_SASL_MECH, &(ptsm->mech));

		if (EMPTY(ptsm->realm))
			ldap_get_option(ptsm->ld, LDAP_OPT_X_SASL_REALM, &(ptsm->realm));

		if (ISSET(ptsm->sasl_secprops)) {
			rc = ldap_set_option(ptsm->ld, LDAP_OPT_X_SASL_SECPROPS, (void *) ptsm->sasl_secprops);
			if( rc != LDAP_OPT_SUCCESS ) {
				syslog(LOG_ERR, "Unable to set LDAP_OPT_X_SASL_SECPROPS.");
				ldap_unbind(ptsm->ld);
                ptsm->ld = NULL;
				return PTSM_FAIL;
			}
		}

		rc = ldap_sasl_interactive_bind_s(
			ptsm->ld, 
			ptsm->bind_dn,
			ptsm->mech, 
			NULL, 
			NULL, 
			LDAP_SASL_QUIET, 
			ptsmodule_interact, 
			ptsm);
	} else
		rc = ldap_simple_bind_s(ptsm->ld, ptsm->bind_dn, ptsm->password);

    if (rc != LDAP_SUCCESS) {
        syslog(LOG_ERR,
               (ptsm->sasl ? "ldap_sasl_interactive_bind() failed %d (%s)." : "ldap_simple_bind() failed %d (%s)."), rc, ldap_err2string(rc));
        ldap_unbind(ptsm->ld);
        ptsm->ld = NULL;
        return (rc == LDAP_SERVER_DOWN ? PTSM_RETRY : PTSM_FAIL);
	}

	return PTSM_OK;
}

/* API */
const char *ptsmodule_name = "ldap";

void ptsmodule_init(void) 
{
    const char *p = NULL;

    if (ptsm)
        return; // Already configured

    ptsm = xmalloc(sizeof(t_ptsm));
    if (ptsm == NULL) {
        fatal("xmalloc() failed", EC_CONFIG);
    }

    ptsm->uri = (config_getstring(IMAPOPT_LDAP_URI) ? 
        config_getstring(IMAPOPT_LDAP_URI) : config_getstring(IMAPOPT_LDAP_SERVERS));
    ptsm->version = (config_getint(IMAPOPT_LDAP_VERSION) == 2 ? LDAP_VERSION2 : LDAP_VERSION3);
    ptsm->timeout.tv_sec = config_getint(IMAPOPT_LDAP_TIME_LIMIT);
    ptsm->timeout.tv_usec = 0;
    ptsm->restart = config_getswitch(IMAPOPT_LDAP_RESTART);
    p = config_getstring(IMAPOPT_LDAP_DEREF);
    if (!strcasecmp(p, "search")) {
        ptsm->deref = LDAP_DEREF_SEARCHING;
    } else if (!strcasecmp(p, "find")) {
        ptsm->deref = LDAP_DEREF_FINDING;
    } else if (!strcasecmp(p, "always")) {
        ptsm->deref = LDAP_DEREF_ALWAYS;
    } else {
        ptsm->deref = LDAP_DEREF_NEVER;
    }
    ptsm->referrals = config_getswitch(IMAPOPT_LDAP_REFERRALS);
    ptsm->size_limit = config_getint(IMAPOPT_LDAP_SIZE_LIMIT);
    ptsm->time_limit = config_getint(IMAPOPT_LDAP_TIME_LIMIT);
    p = config_getstring(IMAPOPT_LDAP_SCOPE);
    if (!strcasecmp(p, "one")) {
        ptsm->scope = LDAP_SCOPE_ONELEVEL;
    } else if (!strcasecmp(p, "base")) {
        ptsm->scope = LDAP_SCOPE_BASE;
    } else {
        ptsm->scope = LDAP_SCOPE_SUBTREE;
    }
    ptsm->bind_dn = config_getstring(IMAPOPT_LDAP_BIND_DN);
    ptsm->sasl = config_getswitch(IMAPOPT_LDAP_SASL);
    ptsm->id = (config_getstring(IMAPOPT_LDAP_ID) ? 
        config_getstring(IMAPOPT_LDAP_ID) : config_getstring(IMAPOPT_LDAP_SASL_AUTHC));
    ptsm->authz = (config_getstring(IMAPOPT_LDAP_AUTHZ) ? 
        config_getstring(IMAPOPT_LDAP_AUTHZ) : config_getstring(IMAPOPT_LDAP_SASL_AUTHZ));
    ptsm->mech = (config_getstring(IMAPOPT_LDAP_MECH) ? 
        config_getstring(IMAPOPT_LDAP_MECH) : config_getstring(IMAPOPT_LDAP_SASL_MECH));
    ptsm->realm = (config_getstring(IMAPOPT_LDAP_REALM) ? 
        config_getstring(IMAPOPT_LDAP_REALM) : config_getstring(IMAPOPT_LDAP_SASL_REALM));
    ptsm->password = (config_getstring(IMAPOPT_LDAP_PASSWORD) ? 
        config_getstring(IMAPOPT_LDAP_PASSWORD) : config_getstring(IMAPOPT_LDAP_SASL_PASSWORD));
    ptsm->start_tls = config_getswitch(IMAPOPT_LDAP_START_TLS);
    ptsm->tls_check_peer = config_getswitch(IMAPOPT_LDAP_TLS_CHECK_PEER);
    ptsm->tls_cacert_file = config_getstring(IMAPOPT_LDAP_TLS_CACERT_FILE);
    ptsm->tls_cacert_dir = config_getstring(IMAPOPT_LDAP_TLS_CACERT_DIR);
    ptsm->tls_ciphers = config_getstring(IMAPOPT_LDAP_TLS_CIPHERS);
    ptsm->tls_cert = config_getstring(IMAPOPT_LDAP_TLS_CERT);
    ptsm->tls_key = config_getstring(IMAPOPT_LDAP_TLS_KEY);
    p = config_getstring(IMAPOPT_LDAP_MEMBER_METHOD);
    if (!strcasecmp(p, "filter")) {
        ptsm->member_method = PTSM_MEMBER_METHOD_FILTER;
    } else {
        ptsm->member_method = PTSM_MEMBER_METHOD_ATTRIBUTE;
    }
    p = config_getstring(IMAPOPT_LDAP_MEMBER_SCOPE);
    if (!strcasecmp(p, "one")) {
        ptsm->member_scope = LDAP_SCOPE_ONELEVEL;
    } else if (!strcasecmp(p, "base")) {
        ptsm->member_scope = LDAP_SCOPE_BASE;
    } else {
        ptsm->member_scope = LDAP_SCOPE_SUBTREE;
    }
    ptsm->member_filter = config_getstring(IMAPOPT_LDAP_MEMBER_FILTER);
    ptsm->member_base = config_getstring(IMAPOPT_LDAP_MEMBER_BASE);
    ptsm->member_attribute = (config_getstring(IMAPOPT_LDAP_MEMBER_ATTRIBUTE) ?
        config_getstring(IMAPOPT_LDAP_MEMBER_ATTRIBUTE) : config_getstring(IMAPOPT_LDAP_MEMBER_ATTRIBUTE));
    p = config_getstring(IMAPOPT_LDAP_GROUP_SCOPE);
    if (!strcasecmp(p, "one")) {
        ptsm->group_scope = LDAP_SCOPE_ONELEVEL;
    } else if (!strcasecmp(p, "base")) {
        ptsm->group_scope = LDAP_SCOPE_BASE;
    } else {
        ptsm->group_scope = LDAP_SCOPE_SUBTREE;
    }
    ptsm->group_filter = config_getstring(IMAPOPT_LDAP_GROUP_FILTER);
    ptsm->group_base = config_getstring(IMAPOPT_LDAP_GROUP_BASE);
    ptsm->filter = config_getstring(IMAPOPT_LDAP_FILTER);
    ptsm->base = config_getstring(IMAPOPT_LDAP_BASE);

	if (ptsm->version != LDAP_VERSION3 && 
	    (ptsm->sasl ||
	     ptsm->start_tls))
	    ptsm->version = LDAP_VERSION3;

    ptsm->ld = NULL;
}

/*
 * Note: calling function must free memory.
 */
static int ptsmodule_escape(
	const char *s, 
	const unsigned int n, 
	char **result) 
{
	char *buf;
	char *end, *ptr, *temp;

	if (n > strlen(s))  // Sanity check, just in case
		return PTSM_FAIL;

	buf = xmalloc(n * 5 + 1);
	if (buf == NULL) {
		return PTSM_NOMEM;
	}

	buf[0] = '\0';
	ptr = (char *)s;
	end = ptr + n;

	while (((temp = strpbrk(ptr, "*()\\\0"))!=NULL) && (temp<end)) {

		if (temp>ptr)
			strncat(buf, ptr, temp-ptr);

		switch (*temp) {
			case '*':
				strcat(buf, "\\2a");
				break;
			case '(':
				strcat(buf, "\\28");
				break;
			case ')':
				strcat(buf, "\\29");
				break;
			case '\\':
				strcat(buf, "\\5c");
				break;
			case '\0':
				strcat(buf, "\\00");
				break;
		}
		ptr=temp+1;
	}
	if (ptr<end)
		strncat(buf, ptr, end-ptr);

	*result = buf;

	return PTSM_OK;
}

static int ptsmodule_tokenize_domains(
	const char *d, 
	int n, 
	char **result)
{
	char *s, *s1;
	char *lasts;
	int nt, i;

	*result = NULL;

	if (d == NULL || n < 1 || n > 9)
		return PTSM_FAIL;

	s = strdup(d);
	if (s == NULL)
		return PTSM_NOMEM;

	for( nt=0, s1=s; *s1; s1++ )
		if( *s1 == '.' ) nt++;
	nt++;

	if (n > nt) {
		free(s);
		return PTSM_FAIL;
	}

	i = nt - n;
	s1 = (char *)strtok_r(s, ".", &lasts);
	while(s1) {
		if (i == 0) {
			*result = strdup(s1);
			free(s);
			return (*result == NULL ? PTSM_NOMEM : PTSM_OK);
		}
		s1 = (char *)strtok_r(NULL, ".", &lasts);
		i--;
	}

	free(s);
	return PTSM_FAIL;
}

#define PTSM_MAX(a,b) (a>b?a:b)

/*
 * ptsmodule_expand_tokens
 * Parts with the strings provided.
 *   %%   = %
 *   %u   = user
 *   %U   = user part of %u
 *   %d   = domain part of %u if available, othwise same as %r
 *   %1-9 = domain tokens (%1 = tld, %2 = domain when %d = domain.tld)
 *   %D   = user DN
 * Note: calling function must free memory.
 */
static int ptsmodule_expand_tokens(
	const char *pattern,
	const char *username, 
	const char *dn,
	char **result) 
{
	char *buf; 
	char *end, *ptr, *temp;
	char *ebuf, *user;
	char *domain;
	int rc;

	/* to permit multiple occurences of username and/or realm in filter */
	/* and avoid memory overflow in filter build [eg: (|(uid=%u)(userid=%u)) ] */
	int percents, user_len, dn_len, maxparamlength;
	
	if (pattern == NULL) {
		syslog(LOG_ERR, "filter pattern not setup");
		return PTSM_FAIL;
	}

	/* find the longest param of username and realm, 
	   do not worry about domain because it is always shorter 
	   then username                                           */
	user_len=username ? strlen(username) : 0;
	dn_len=dn ? strlen(dn) : 0;

	maxparamlength = PTSM_MAX(user_len, dn_len);

	/* find the number of occurences of percent sign in filter */
	for( percents=0, buf=(char *)pattern; *buf; buf++ ) {
		if( *buf == '%' ) percents++;
	}

	/* percents * 3 * maxparamlength because we need to account for
         * an entirely-escaped worst-case-length parameter */
	buf=xmalloc(strlen(pattern) + (percents * 3 * maxparamlength) +1);
	if(buf == NULL)
		return PTSM_NOMEM;
	buf[0] = '\0';
	
	ptr = (char *)pattern;
	end = ptr + strlen(ptr);

	while ((temp=strchr(ptr,'%'))!=NULL ) {

		if ((temp-ptr) > 0)
			strncat(buf, ptr, temp-ptr);

		if ((temp+1) >= end) {
			syslog(LOG_DEBUG, "Incomplete lookup substitution format");
			break;
		}

		switch (*(temp+1)) {
			case '%':
				strncat(buf,temp+1,1);
				break;
			case 'u':
				if (ISSET(username)) {
					rc=ptsmodule_escape(username, strlen(username), &ebuf);
					if (rc == PTSM_OK) {
						strcat(buf,ebuf);
						free(ebuf);
					}
				} else
					syslog(LOG_DEBUG, "Username not available.");
				break;
			case 'U':
				if (ISSET(username)) {
					
					user = strchr(username, '@');
					rc=ptsmodule_escape(username, (user ? user - username : strlen(username)), &ebuf);
					if (rc == PTSM_OK) {
						strcat(buf,ebuf);
						free(ebuf);
					}
				} else
					syslog(LOG_DEBUG, "Username not available.");
				break;
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				if (ISSET(username) && (domain = strchr(username, '@')) && domain[1]!='\0') {
					rc=ptsmodule_tokenize_domains(domain+1, (int) *(temp+1)-48, &ebuf);
					if (rc == PTSM_OK) {
						strcat(buf,ebuf);
						free(ebuf);
					}
				} else
					syslog(LOG_DEBUG, "Domain tokens not available.");
				break;
			case 'd':
				if (ISSET(username) && (domain = strchr(username, '@')) && domain[1]!='\0') {
					rc=ptsmodule_escape(domain+1, strlen(domain+1), &ebuf);
					if (rc == PTSM_OK) {
						strcat(buf,ebuf);
						free(ebuf);
					}
					break;
				} 
			case 'D':
				if (ISSET(dn)) {
					rc = ptsmodule_escape(dn, strlen(dn), &ebuf);
					if (rc == PTSM_OK) {
						strcat(buf,ebuf);
						free(ebuf);
					}
				} else
					syslog(LOG_DEBUG, "dn not available.");
				break;
			default:
				break;
		}
		ptr=temp+2;
	}
	if (temp<end)
		strcat(buf, ptr);

	*result = buf;

	return PTSM_OK;
}


static int ptsmodule_get_dn(
    const char *canon_id,
    size_t size,
    char **ret)
{
    int rc;

#if LDAP_VENDOR_VERSION >= 20125
    struct berval *dn = NULL;
    LDAPControl c;
    LDAPControl *ctrl[2];
    char *authzid;
#else
    char *base = NULL, *filter = NULL;
    char *attrs[] = {NULL};
    LDAPMessage *res;
    LDAPMessage *entry;
    char *attr, **vals;
    BerElement *ber;
#endif

    *ret = NULL;

    if (ptsm->ld == NULL)
        return PTSM_FAIL;

#if LDAP_VENDOR_VERSION >= 20125

    authzid = xmalloc(size + sizeof("u:"));
    if (authzid == NULL)
        return PTSM_NOMEM;

    strcpy(authzid, "u:");
    strcpy(authzid+2, canon_id);
    c.ldctl_oid = LDAP_CONTROL_PROXY_AUTHZ;
    c.ldctl_value.bv_val = authzid;
    c.ldctl_value.bv_len = size + 2;
    c.ldctl_iscritical = 1;

    ctrl[0] = &c;
    ctrl[1] = NULL;
    rc = ldap_whoami_s(ptsm->ld, &dn, ctrl, NULL);
    free(authzid);
    if ( rc != LDAP_SUCCESS || !dn ) {
        if (rc == LDAP_SERVER_DOWN) {
            ldap_unbind(ptsm->ld);
            ptsm->ld = NULL;
            return PTSM_RETRY;
        }
        return PTSM_FAIL;
    }

    if ( dn->bv_val &&
        !strncmp(dn->bv_val, "dn:", 3) )
        *ret = strdup(dn->bv_val+3);
    ber_bvfree(dn);

#else

    rc = ptsmodule_expand_tokens(ptsm->filter, canon_id, NULL, &filter);
    if (rc != PTSM_OK)
        return rc;

    rc = ptsmodule_expand_tokens(ptsm->base, canon_id, NULL, &base);
    if (rc != PTSM_OK)
        return rc;

    rc = ldap_search_st(ptsm->ld, base, ptsm->scope, filter, attrs, 0, &(ptsm->timeout), &res);
    free(filter);
    free(base);
    if (rc != LDAP_SUCCESS) {
        if (rc == LDAP_SERVER_DOWN) {
            ldap_unbind(ptsm->ld);
            ptsm->ld = NULL;
            return PTSM_RETRY;
        }
        return PTSM_FAIL;
    }

    if ( (entry = ldap_first_entry(ptsm->ld, res)) != NULL )
        *ret = ldap_get_dn(ptsm->ld, entry);

    ldap_msgfree(res);
    res = NULL;

#endif

    return (*ret ? PTSM_OK : PTSM_FAIL);
}


static int ptsmodule_make_authstate_attribute(
    const char *canon_id,
    size_t size,
    const char **reply, 
    int *dsize,
    struct auth_state **newstate) 
{
    char *dn = NULL;
    LDAPMessage *res;
    LDAPMessage *entry;
    char *attr, **vals;
    BerElement *ber;
    int rc;
    char *attrs[] = {(char *)ptsm->member_attribute,NULL};

    rc = ptsmodule_connect();
    if (rc != PTSM_OK) {
        *reply = "ptsmodule_connect() failed";
        return rc;
    }

    rc = ptsmodule_get_dn(canon_id, size, &dn);
    if (rc != PTSM_OK) {
        *reply = "identifier not found";
        goto done;
    }

    rc = ldap_search_st(ptsm->ld, dn, LDAP_SCOPE_BASE, "(objectclass=*)", attrs, 0, &(ptsm->timeout), &res);
    if ( rc != LDAP_SUCCESS ) {
        *reply = "ldap_search(attribute) failed";
        if ( rc == LDAP_SERVER_DOWN ) {
            ldap_unbind(ptsm->ld);
            ptsm->ld = NULL;
            rc = PTSM_RETRY;
        } else
            rc = PTSM_FAIL;
        goto done;
    }

    if ((entry = ldap_first_entry(ptsm->ld, res)) != NULL) {
        for (attr = ldap_first_attribute(ptsm->ld, entry, &ber); attr != NULL; 
            attr = ldap_next_attribute(ptsm->ld, entry, ber)) {
            int i, numvals;

            vals = ldap_get_values(ptsm->ld, entry, attr);
            if (vals == NULL)
                continue;

            for (i = 0; vals[i] != NULL; i++)
                numvals = i;
            numvals++;

            *dsize = sizeof(struct auth_state) +
                     (numvals * sizeof(struct auth_ident));
            *newstate = xmalloc(*dsize);
            if (*newstate == NULL) {
                *reply = "no memory";
                rc = PTSM_FAIL;
                goto done;
            }
            (*newstate)->ngroups = numvals;

            for (i = 0; vals[i] != NULL; i++) {
                strlcpy((*newstate)->groups[i].id, vals[i], 
                    sizeof((*newstate)->groups[i].id));
                (*newstate)->groups[i].hash = strhash((*newstate)->groups[i].id);
            }

            ldap_value_free(vals);
            vals = NULL;
            ldap_memfree(attr);
            attr = NULL;
        }
    }

    if(!*newstate) {
        *dsize = sizeof(struct auth_state);
        *newstate = xmalloc(*dsize);
        if (*newstate == NULL) {
            *reply = "no memory";
            rc = PTSM_FAIL;
            goto done;
        }
        (*newstate)->ngroups = 0;
    }
    
    /* fill in the rest of our new state structure */
    strcpy((*newstate)->userid.id, canon_id);
    (*newstate)->userid.hash = strhash(canon_id);
    (*newstate)->mark = time(0);

    rc = PTSM_OK;

done:;

    if (res)
        ldap_msgfree(res);
    if (vals)
        ldap_value_free(vals);
    if (attr)
        ldap_memfree(attr);
    if (ber)
        ber_free(ber, 0);
    if (dn)
        free(dn);

    return rc;
}

static int ptsmodule_make_authstate_filter(
    const char *canon_id,
    size_t size,
    const char **reply, 
    int *dsize,
    struct auth_state **newstate) 
{
    char *base = NULL, *filter = NULL;
    int rc;
    int i; int n;
    LDAPMessage *res = NULL;
    LDAPMessage *entry;
    char *attr, **vals;
    BerElement *ber = NULL;
    char *attrs[] = {(char *)ptsm->member_attribute,NULL};
    char *dn = NULL;

    rc = ptsmodule_connect();
    if (rc != PTSM_OK) {
        *reply = "ptsmodule_connect() failed";
        return rc;
    }

    rc = ptsmodule_get_dn(canon_id, size, &dn);
    if (rc != PTSM_OK) {
        *reply = "identifier not found";
        return rc;
    }

    rc = ptsmodule_expand_tokens(ptsm->member_filter, canon_id, dn, &filter);
    if (rc != PTSM_OK) {
        *reply = "ptsmodule_expand_tokens() failed for member filter";
        goto done;
    }

    rc = ptsmodule_expand_tokens(ptsm->member_base, canon_id, dn, &base);
    if (rc != PTSM_OK) {
        *reply = "ptsmodule_expand_tokens() failed for member search base";
        goto done;
    }

    rc = ldap_search_st(ptsm->ld, base, ptsm->member_scope, filter, attrs, 0, &(ptsm->timeout), &res);
    if (rc != LDAP_SUCCESS) {
        *reply = "ldap_search(filter) failed";
        if (rc == LDAP_SERVER_DOWN) {
            ldap_unbind(ptsm->ld);
            ptsm->ld = NULL;
            rc = PTSM_RETRY;
        } else
            rc = PTSM_FAIL;
        goto done;
    }

    n = ldap_count_entries(ptsm->ld, res);
    if (n < 0) {
        *reply = "ldap_count_entries() failed";
        rc = PTSM_FAIL;
        goto done;
    }

    *dsize = sizeof(struct auth_state) +
             (n * sizeof(struct auth_ident));
    *newstate = xmalloc(*dsize);
    if (*newstate == NULL) {
        *reply = "no memory";
        rc = PTSM_FAIL;
        goto done;
    }
    (*newstate)->ngroups = n;
    strcpy((*newstate)->userid.id, canon_id);
    (*newstate)->userid.hash = strhash(canon_id);
    (*newstate)->mark = time(0);

    for (i = 0, entry = ldap_first_entry(ptsm->ld, res); entry != NULL;
         i++, entry = ldap_next_entry(ptsm->ld, entry)) {
        for (attr = ldap_first_attribute(ptsm->ld, entry, &ber); attr != NULL; 
            attr = ldap_next_attribute(ptsm->ld, entry, ber)) {

            vals = ldap_get_values(ptsm->ld, entry, attr);
            if (vals == NULL)
                continue;

            strlcpy((*newstate)->groups[i].id, vals[0], 
                sizeof((*newstate)->groups[i].id));
            (*newstate)->groups[i].hash = strhash((*newstate)->groups[i].id);

            ldap_value_free(vals);
            vals = NULL;
            ldap_memfree(attr);
            attr = NULL;
        }
    }

    rc = PTSM_OK;

done:;

    if (res)
        ldap_msgfree(res);
    if (ber)
        ber_free(ber, 0);
    ber = NULL;
    if (dn)
        free(dn);
    if (filter)
        free(filter);
    if (base)
        free(base);

    return rc;
}

static int ptsmodule_make_authstate_group(
    const char *canon_id,
    size_t size,
    const char **reply, 
    int *dsize,
    struct auth_state **newstate) 
{
    char *base = NULL, *filter = NULL;
    int rc;
    int i; int n;
    LDAPMessage *res;
    LDAPMessage *entry;
    char *attr, **vals;
    char *attrs[] = {NULL};

    if (strncmp(canon_id, "group:", 6))  { // Sanity check
        *reply = "not a group identifier";
        return PTSM_FAIL;
    }

    rc = ptsmodule_connect();
    if (rc != PTSM_OK) {
        *reply = "ptsmodule_connect() failed";
        return rc;
    }

    rc = ptsmodule_expand_tokens(ptsm->group_filter, canon_id+6, NULL, &filter);
    if (rc != PTSM_OK) {
        *reply = "ptsmodule_expand_tokens() failed for group filter";
        goto done;
    }

    rc = ptsmodule_expand_tokens(ptsm->group_base, canon_id+6, NULL, &base);
    if (rc != PTSM_OK) {
        *reply = "ptsmodule_expand_tokens() failed for group search base";
        goto done;
    }

    rc = ldap_search_st(ptsm->ld, base, ptsm->group_scope, filter, attrs, 0, &(ptsm->timeout), &res);
    if (rc != LDAP_SUCCESS) {
        *reply = "ldap_search(group) failed";
        if (rc == LDAP_SERVER_DOWN) {
            ldap_unbind(ptsm->ld);
            ptsm->ld = NULL;
            rc = PTSM_RETRY;
        } else
            rc = PTSM_FAIL;
        goto done;
    }

    n = ldap_count_entries(ptsm->ld, res);
    if (n != 1) {
        *reply = "group identifier not found";
        rc = PTSM_FAIL;
        goto done;
    }

    *dsize = sizeof(struct auth_state) +
             (n * sizeof(struct auth_ident));
    *newstate = xmalloc(*dsize);
    if (*newstate == NULL) {
        *reply = "no memory";
        rc = PTSM_FAIL;
        goto done;
    }
    (*newstate)->ngroups = 0;
    strcpy((*newstate)->userid.id, canon_id);
    (*newstate)->userid.hash = strhash(canon_id);
    (*newstate)->mark = time(0);

    rc = PTSM_OK;

done:;

    if (res)
        ldap_msgfree(res);
    if (filter)
        free(filter);
    if (base)
        free(base);

    return rc;
}

struct auth_state *ptsmodule_make_authstate(
    const char *identifier,
    size_t size,
    const char **reply, 
    int *dsize) 
{
    const char *canon_id;
    struct auth_state *newstate = NULL;
    int rc;
    int retries = 1;

    canon_id = ptsmodule_canonifyid(identifier, size);
    if (EMPTY(canon_id)) {
        *reply = "ptsmodule_canonifyid() failed";
        return NULL;
    }
    size = strlen(canon_id);

retry:;

    *reply = NULL;

    if (!strncmp(canon_id, "group:", 6))
        rc = ptsmodule_make_authstate_group(canon_id, size, reply, dsize, &newstate);
    else {
        if (ptsm->member_method == PTSM_MEMBER_METHOD_ATTRIBUTE)
            rc = ptsmodule_make_authstate_attribute(canon_id, size, reply, dsize, &newstate);
        else
            rc = ptsmodule_make_authstate_filter(canon_id, size, reply, dsize, &newstate);
    }
    if (rc == PTSM_RETRY &&
        retries) {
        retries--;
        goto retry;
    }

    return newstate;
}
