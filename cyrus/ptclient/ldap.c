/* ldap.c - LDAP Backend to ptloader */
/*
 * Copyright (c) 1996-2000 Carnegie Mellon University.  All rights reserved.
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
      "$Id: ldap.c,v 1.1.2.3 2003/02/06 22:41:05 rjs3 Exp $";

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
#include <krb.h>

#include <ldap.h>
#include <lber.h>

/* xxx autoconf checks for these? */
#include <lutil.h>
#include <lutil_ldap.h>

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
char *ldap_canonifyid(const char *identifier, size_t len)
{
    static char retbuf[81];
    char sawalpha;
    char *p;

    if(!len) len = strlen(identifier);
    if(len >= sizeof(retbuf)) return NULL;

    memcpy(retbuf, identifier, len);
    retbuf[len] = '\0';

    /* Copy the string and look up values in the allowedchars array above.
     * If we see any we don't like, reject the string.
     */
    sawalpha = 0;
    for(p = retbuf; *p; p++) {
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

static LDAP *ld = NULL; /* the LDAP handle */

static int do_ldap_bind() 
{
    int rc;


    /* Initilization */
    if(config_getswitch(IMAPOPT_LDAP_SASL))
    {
	struct berval passwd = { 0, NULL };
	const char *sasl_password =
	    config_getstring(IMAPOPT_LDAP_SASL_PASSWORD);
	const char *sasl_mech = config_getstring(IMAPOPT_LDAP_SASL_MECH);
	const char *sasl_realm = config_getstring(IMAPOPT_LDAP_SASL_REALM);
	const char *sasl_authc_id = config_getstring(IMAPOPT_LDAP_SASL_AUTHC);
	const char *sasl_authz_id = config_getstring(IMAPOPT_LDAP_SASL_AUTHZ);
	unsigned sasl_flags = LDAP_SASL_AUTOMATIC;
	
	void *defaults;

	passwd.bv_val = sasl_password;
	if(passwd.bv_val) passwd.bv_len = strlen(passwd.bv_val);
	
	/* xxx security properties */
	syslog(LOG_DEBUG, "making LDAP defaults");
	defaults = lutil_sasl_defaults( ld,
					(char *)sasl_mech,
					(char *)sasl_realm,
					(char *)sasl_authc_id,
					passwd.bv_val,
					(char *)sasl_authz_id );

	syslog(LOG_DEBUG, "doing LDAP SASL bind");
	rc = ldap_sasl_interactive_bind_s( ld, NULL /* binddn */,
					   sasl_mech, NULL, NULL,
					   sasl_flags, lutil_sasl_interact,
					   defaults );
    } else {
	/* xxx we should probably also allow simple non-anonymous binds */
	syslog(LOG_DEBUG, "doing LDAP SIMPLE [anonymous] bind");
	rc = ldap_simple_bind_s(ld, "", "");
    }
    
    return rc;
}

int ptsmodule_ldap_connect(void) 
{
    int ldap_version = LDAP_VERSION2;
    int rc;
    
    rc = ldap_initialize(&ld, config_getstring(IMAPOPT_LDAP_SERVERS));
    if (rc != LDAP_SUCCESS) {
	syslog(LOG_ERR, "ldap_initialize failed");
	return rc;
    }

    syslog(LOG_DEBUG, "seting LDAP version");

    if(config_getswitch(IMAPOPT_LDAP_SASL))
	    ldap_version = LDAP_VERSION3;

    rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
    
    if(rc != LDAP_OPT_SUCCESS)
    {
	syslog(LOG_ERR, "could not set LDAP_OPT_PROTOCOL_VERSION");
	return rc;
    }

    syslog(LOG_DEBUG, "binding LDAP");

    rc = do_ldap_bind();
    if(rc != LDAP_SUCCESS) {
	syslog(LOG_ERR, "do_ldap_bind() failed: (%s)", ldap_err2string(rc));
    }

    return rc;
}


/* API */
const char *ptsmodule_name = "ldap";

void ptsmodule_init(void) 
{
    syslog(LOG_DEBUG, "initing LDAP");

    if(!config_getstring(IMAPOPT_LDAP_SERVERS)) {
	fatal("no LDAP servers defined", EC_CONFIG);
    }

    if(!config_getstring(IMAPOPT_LDAP_BASE))
    {
	fatal("LDAP search BASE not defined", EC_CONFIG);
    }

    if(!config_getstring(IMAPOPT_LDAP_FILTER))
    {
	fatal("LDAP search FILTER not defined", EC_CONFIG);
    }

    if(ptsmodule_ldap_connect() != LDAP_SUCCESS)
    {
	fatal("failed initial LDAP connection", EC_CONFIG);
    }
}

/*
 * Note: calling function must free memory.
 */
static int ldap_escape(const char *s, char **result) 
{
	char *buf;
	char *end, *ptr, *temp;

	buf = xmalloc(strlen(s) * 3 + 1);
	buf[0] = '\0';
	ptr = (char *)s;
	end = ptr + strlen(ptr);

	while (((temp = strpbrk(ptr, "*()\\\0"))!=NULL) && (temp < end)) {
		if ((temp-ptr) > 0)
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
	if (temp<end)
	    strcat(buf, ptr);

	*result = buf;

	return 0;
}

/*
 * build_filter
 * Parts with the strings provided.
 *   %% = %
 *   %u = user
 *   %r = realm
 * Note: calling function must free memory.
 */
static int build_filter(const char *filter,
			const char *username,
			const char *realm,
			char **result) 
{
    char *buf; 
    const char *ptr, *end, *temp;
    char *ebuf;
    int rc;

    /* to permit multiple occurences of username and/or realm in filter */
    /* and avoid memory overflow in filter build
     * [eg: (|(uid=%u)(userid=%u)) ] */
    int percents, maxparamlength;
    int realm_len=0, user_len=0;
	
    /* find the longest param of username and realm */
    if(username) user_len=strlen(username);
    if(realm) realm_len=strlen(realm);
    if( user_len > realm_len )
	maxparamlength = user_len;
    else
        maxparamlength = realm_len;

    /* find the number of occurences of percent sign in filter */
    for(percents=0, buf=filter; *buf; buf++ ) {
	if( *buf == '%' ) percents++;
    }

    /* percents * 3 * maxparamlength because we need to account for
     * an entirely-escaped worst-case-length parameter */
    buf=xmalloc(strlen(filter) + (percents * 3 * maxparamlength) +1);
    buf[0] = '\0';
	
    ptr=filter;
    end = ptr + strlen(ptr);

    while ((temp=strchr(ptr,'%'))!=NULL ) {
	if ((temp-ptr) > 0)
	    strncat(buf, ptr, temp-ptr);

	if ((temp+1) >= end) {
	    syslog(LOG_WARNING, "Incomplete lookup substitution format");
	    break;
	}
	switch (*(temp+1)) {
	case '%':
		strncat(buf,temp+1,1);
		break;
	case 'u':
		if (username!=NULL) {
		    rc=ldap_escape(username, &ebuf);
		    if (!rc) {
		        strcat(buf,ebuf);
		        free(ebuf);
		    }
		} else {
		    syslog(LOG_WARNING, "Username not available.");
		    return 1;
		}
		break;
	case 'r':
		if (realm!=NULL) {
	    	    rc = ldap_escape(realm, &ebuf);
	    	    if (!rc) {
	    	        strcat(buf,ebuf);
		        free(ebuf);
	    	    }
		} else {
		    syslog(LOG_WARNING, "Realm not available.");
		    return 1;
		}
		break;
	default:
		break;
	}
	ptr=temp+2;
    }
    if (temp<end)
	strcat(buf, ptr);
    
    *result = buf;
    
    return 0;
}

struct auth_state *ptsmodule_make_authstate(const char *identifier,
					    size_t size,
					    const char **reply, int *dsize) 
{
    const char *membership_att =
	    config_getstring(IMAPOPT_LDAP_MEMBER_ATTRIBUTE);
    const char *ldap_search_base =
	    config_getstring(IMAPOPT_LDAP_BASE);
    const char *ldap_filter =
	    config_getstring(IMAPOPT_LDAP_FILTER);

    char *fetch_attrs[] = {membership_att,NULL};
    
    const char *canon_id = ldap_canonifyid(identifier, size);
    int rc;
    char *name_buf;
    struct auth_state *newstate = NULL;
    struct timeval timeout;
    LDAPMessage *res;

    /* attribute traversal */
    LDAPMessage *entry;
    char *attr, **vals;
    BerElement *ber;

    static time_t down_until = 0;
    int retries = 4;

    syslog(LOG_DEBUG, "doing LDAP lookup of user %s", canon_id);

    if(down_until && down_until > time(NULL)) return NULL;
    else if(down_until > 0) {
	if(ld) ldap_unbind(ld);
	ld = NULL;
	
	down_until = 0;
    }

 retry: 
    if(--retries == 0) {
	down_until = time(NULL)+60; /* xxx configurable */
	return NULL;
    } else if (ld == NULL) {
	rc = ptsmodule_ldap_connect();
	if(rc != LDAP_SUCCESS) {
	    sleep(2);
	    goto retry;
	}
    }
    
    /* Initilization */
    timeout.tv_sec = 5; /* xxx configurable */
    timeout.tv_usec = 0;

    *reply = NULL;
    size = strlen(canon_id);

    /* Do Search */
    /* xxx realm name */
    if(build_filter(ldap_filter,canon_id,NULL,&name_buf)) {
	return NULL;
    }

    syslog(LOG_DEBUG, "using filter %s", name_buf);

    rc = ldap_search_st(ld, ldap_search_base,
			LDAP_SCOPE_SUBTREE,
			name_buf, fetch_attrs, 0, &timeout, &res);

    free(name_buf);

    /* Search Result? */
    switch (rc) {
      case LDAP_SUCCESS:
      case LDAP_NO_SUCH_OBJECT:
	  break;
      case LDAP_TIMEOUT:
      case LDAP_TIMELIMIT_EXCEEDED:
      case LDAP_BUSY:
	  /*  We do not need to re-connect to the LDAP server 
	      under these conditions */
	  goto retry;
	  break;
      case LDAP_UNAVAILABLE:
      case LDAP_INSUFFICIENT_ACCESS:
	  /*  We do not need to re-connect to the LDAP server 
	      under these conditions */
	  syslog(LOG_ERR|LOG_AUTH, "ldap_search_st() failed: %s", ldap_err2string(rc));
	  ldap_msgfree(res);
	  *reply = "LDAP configuration error";
	  return NULL;
    case LDAP_SERVER_DOWN:
	  syslog(LOG_WARNING|LOG_AUTH,
		 "ldap_search_st() failed: %s. Trying to reconnect.",
		 ldap_err2string(rc));
	  ldap_msgfree(res);

	  ldap_unbind(ld);
	  ld = NULL;

	  goto retry;
      default:
	syslog(LOG_ERR|LOG_AUTH,
	       "ldap_search_st() failed: %s", ldap_err2string(rc));
	ldap_msgfree(res);
	*reply = "LDAP search error";
	return NULL;
    }

    /* xxx only does one entry */
    entry = ldap_first_entry(ld, res);
    if(!entry) {
	*reply = "NO Entries";
	return NULL;
    }
    
    for (attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; 
	 attr = ldap_next_attribute(ld, entry, ber)) {
	int i, numvals;

	if(strcmp(attr, membership_att)) continue;

	vals = ldap_get_values(ld, entry, attr);
	if (vals == NULL) continue;

	for (i = 0; vals[i] != NULL; i++);
	numvals = i;
 
	*dsize = sizeof(struct auth_state) +
	    (numvals * sizeof(struct auth_ident));
	newstate = xmalloc(*dsize);
	newstate->ngroups = numvals;
	
	for (i = 0; vals[i] != NULL; i++)
	{
	    strlcpy(newstate->groups[i].id, vals[i],
		    sizeof(newstate->groups[i].id));
	    newstate->groups[i].hash = strhash(newstate->groups[i].id);
	}
	
	ldap_value_free(vals);
	ldap_memfree(attr);
    }

    ldap_msgfree(res);

    if(!newstate) {
	*dsize = sizeof(struct auth_state);
	newstate = xmalloc(*dsize);
	newstate->ngroups = 0;
    }
    
    /* fill in the rest of our new state structure */
    strcpy(newstate->userid.id, canon_id);
    newstate->userid.hash = strhash(canon_id);
    newstate->mark = time(0);

    return newstate;
}
