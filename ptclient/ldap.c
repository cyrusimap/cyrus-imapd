/* ldap.c - LDAP Backend to ptloader
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
 */

#include <sysexits.h>
#include <syslog.h>
#include <config.h>
#include "ptloader.h"
#include "util.h"
#include "assert.h"

#ifdef HAVE_LDAP

#include <ctype.h>
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

/* Functions like ldap_bind() have been deprecated in OpenLDAP 2.3 */
#define LDAP_DEPRECATED 1

#include <ldap.h>
#include <lber.h>

/* libimap */
#include "imap/global.h"

/* libconfig */
#include "libconfig.h"

/* libcyrus */
#include "auth_pts.h"
#include "strhash.h"
#include "xmalloc.h"
#include "xstrlcat.h"

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
 * &    forbidden because of MUTF-7.  (This could be fixed.)
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
    const char      *uri;
    int             version;
    struct timeval  timeout;
    int             size_limit;
    int             time_limit;
    int             deref;
    int             referrals;
    int             restart;
    int             scope;
    const char      *base;
    int             sasl;
    const char      *id;
    const char      *bind_dn;
    const char      *password;
    const char      *authz;
    const char      *mech;
    const char      *realm;
    const char      *filter;
    const char      *sasl_secprops;
    int             start_tls;
    int             tls_check_peer;
    const char      *tls_cacert_file;
    const char      *tls_cacert_dir;
    const char      *tls_ciphers;
    const char      *tls_cert;
    const char      *tls_key;
    int             member_method;
    const char      *user_attribute;
    const char      *member_attribute;
    const char      *member_filter;
    const char      *member_base;
    int             member_scope;
    const char      *group_filter;
    const char      *group_base;
    int             group_scope;

    /* Used for domain name space -> root dn discovery */
    const char      *domain_base_dn;
    const char      *domain_filter;
    const char      *domain_name_attribute;
    int             domain_scope;
    const char      *domain_result_attribute;

    LDAP            *ld;
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
    LDAP *ld __attribute__((unused)),
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
        if (username_tolower && Uisupper(*p))
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
                        syslog(LOG_WARNING, "Unable to set LDAP_OPT_X_TLS_CACERTFILE (%s).", ldap_err2string (rc));
                }
        }

        if (ISSET(ptsm->tls_cacert_dir)) {
                rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTDIR, ptsm->tls_cacert_dir);
                if (rc != LDAP_SUCCESS) {
                        syslog(LOG_WARNING, "Unable to set LDAP_OPT_X_TLS_CACERTDIR (%s).", ldap_err2string (rc));
                }
        }

        if (ptsm->tls_check_peer != 0) {
                rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &ptsm->tls_check_peer);
                if (rc != LDAP_SUCCESS) {
                        syslog(LOG_WARNING, "Unable to set LDAP_OPT_X_TLS_REQUIRE_CERT (%s).", ldap_err2string (rc));
                }
        }

        if (ISSET(ptsm->tls_ciphers)) {
                /* set cipher suite, certificate and private key: */
                rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CIPHER_SUITE, ptsm->tls_ciphers);
                if (rc != LDAP_SUCCESS) {
                        syslog(LOG_WARNING, "Unable to set LDAP_OPT_X_TLS_CIPHER_SUITE (%s).", ldap_err2string (rc));
                }
        }

        if (ISSET(ptsm->tls_cert)) {
                rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE, ptsm->tls_cert);
                if (rc != LDAP_SUCCESS) {
                        syslog(LOG_WARNING, "Unable to set LDAP_OPT_X_TLS_CERTFILE (%s).", ldap_err2string (rc));
                }
        }

        if (ISSET(ptsm->tls_key)) {
                rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE, ptsm->tls_key);
                if (rc != LDAP_SUCCESS) {
                        syslog(LOG_WARNING, "Unable to set LDAP_OPT_X_TLS_KEYFILE (%s).", ldap_err2string (rc));
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
                syslog(LOG_WARNING, "Unable to set LDAP_OPT_NETWORK_TIMEOUT %ld.%06d.",
                       (long)ptsm->timeout.tv_sec, (int)ptsm->timeout.tv_usec);
        }

        rc = ldap_set_option(ptsm->ld, LDAP_OPT_SIZELIMIT, &(ptsm->size_limit));
        if (rc != LDAP_OPT_SUCCESS) {
                syslog(LOG_WARNING, "Unable to set LDAP_OPT_SIZELIMIT %d.", ptsm->size_limit);
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

static void myinit(void)
{
    const char *p = NULL;

    if (ptsm)
        return; // Already configured

    ptsm = xmalloc(sizeof(t_ptsm));
    if (ptsm == NULL) {
        fatal("xmalloc() failed", EX_CONFIG);
    }

    ptsm->uri = config_getstring(IMAPOPT_LDAP_URI);

    ptsm->version = (config_getint(IMAPOPT_LDAP_VERSION) == 2 ? LDAP_VERSION2 : LDAP_VERSION3);
    ptsm->timeout.tv_sec = config_getduration(IMAPOPT_LDAP_TIMEOUT, 's');
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
    ptsm->time_limit = config_getduration(IMAPOPT_LDAP_TIME_LIMIT, 's');

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
    ptsm->id = config_getstring(IMAPOPT_LDAP_ID);
    ptsm->authz = config_getstring(IMAPOPT_LDAP_AUTHZ);
    ptsm->mech = config_getstring(IMAPOPT_LDAP_MECH);
    ptsm->realm = config_getstring(IMAPOPT_LDAP_REALM);
    ptsm->password = config_getstring(IMAPOPT_LDAP_PASSWORD);
    ptsm->start_tls = config_getswitch(IMAPOPT_LDAP_START_TLS);
    ptsm->tls_check_peer = config_getswitch(IMAPOPT_LDAP_VERIFY_PEER);
    ptsm->tls_cacert_file = config_getstring(IMAPOPT_LDAP_CA_FILE);
    ptsm->tls_cacert_dir = config_getstring(IMAPOPT_LDAP_CA_DIR);
    ptsm->tls_ciphers = config_getstring(IMAPOPT_LDAP_CIPHERS);
    ptsm->tls_cert = config_getstring(IMAPOPT_LDAP_CLIENT_CERT);
    ptsm->tls_key = config_getstring(IMAPOPT_LDAP_CLIENT_KEY);

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

    ptsm->user_attribute = (config_getstring(IMAPOPT_LDAP_USER_ATTRIBUTE) ?
        config_getstring(IMAPOPT_LDAP_USER_ATTRIBUTE) : config_getstring(IMAPOPT_LDAP_USER_ATTRIBUTE));

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

    if (ptsm->version != LDAP_VERSION3 && (ptsm->sasl || ptsm->start_tls))
        ptsm->version = LDAP_VERSION3;

    ptsm->domain_base_dn = config_getstring(IMAPOPT_LDAP_DOMAIN_BASE_DN);
    ptsm->domain_filter = config_getstring(IMAPOPT_LDAP_DOMAIN_FILTER);
    ptsm->domain_name_attribute = config_getstring(IMAPOPT_LDAP_DOMAIN_NAME_ATTRIBUTE);

    p = config_getstring(IMAPOPT_LDAP_DOMAIN_SCOPE);

    if (!strcasecmp(p, "one")) {
        ptsm->domain_scope = LDAP_SCOPE_ONELEVEL;
    } else if (!strcasecmp(p, "base")) {
        ptsm->domain_scope = LDAP_SCOPE_BASE;
    } else {
        ptsm->domain_scope = LDAP_SCOPE_SUBTREE;
    }

    ptsm->domain_result_attribute = config_getstring(IMAPOPT_LDAP_DOMAIN_RESULT_ATTRIBUTE);

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

static int ptsmodule_standard_root_dn(const char *domain, const char **result)
{
    const char *dc_sep = ",dc=";
    char *domain_copy;
    char *part, *tok_state;
    struct buf buf = BUF_INITIALIZER;

    assert(domain != NULL && domain[0] != '\0');

    syslog(LOG_DEBUG, "ptsmodule_standard_root_dn called for domain %s", domain);

    /* Each dot is to be replaced with ',dc='.
     * We also need a leading 'dc=' at the start.
     */
    domain_copy = xstrdup(domain);
    part = strtok_r(domain_copy, ".", &tok_state);
    buf_setcstr(&buf, "dc=");

    while (part != NULL) {
        syslog(LOG_DEBUG, "Root DN now %s", buf_cstring(&buf));

        buf_appendcstr(&buf, part);
        syslog(LOG_DEBUG, "Root DN now %s", buf_cstring(&buf));

        part = strtok_r(NULL, ".", &tok_state);

        if (part != NULL)
            buf_appendcstr(&buf, dc_sep);
    }

    free(domain_copy);

    syslog(LOG_DEBUG, "Root DN now %s", buf_cstring(&buf));

    *result = buf_release(&buf);

    syslog(LOG_DEBUG, "Root DN now %s", *result);

    return PTSM_OK;
}

static int ptsmodule_tokenize_domains(
    const char *d,
    int n,
    char **result)
{
    char *s, *s1;
    char *lasts;
    int nt, i, rc;

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
            rc = ptsmodule_escape(s1, strlen(s1), result);
            free(s);
            return rc;
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
 *   %d   = domain part of %u if available, otherwise same as %R
 *   %R   = prepend '@' to domain
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
    user_len = username ? strlen(username) : 0;
    dn_len = dn ? strlen(dn) : 0;

    maxparamlength = PTSM_MAX(user_len+1, dn_len); /* +1 for %R when '@' is prepended */

    /* find the number of occurences of percent sign in filter */
    for (percents=0, buf=(char *)pattern; *buf; buf++) {
        if (*buf == '%') percents++;
    }

    /* percents * 3 * maxparamlength because we need to account for
         * an entirely-escaped worst-case-length parameter */
    buf = xmalloc(strlen(pattern) + (percents * 3 * maxparamlength) +1);
    if (buf == NULL)
        return PTSM_NOMEM;

    buf[0] = '\0';

    ptr = (char *)pattern;
    end = ptr + strlen(ptr);

    while ((temp=strchr(ptr,'%')) != NULL) {

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
                    rc = ptsmodule_escape(username, strlen(username), &ebuf);
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
                    rc = ptsmodule_escape(username, (user ? (unsigned char)(user - username) : strlen(username)), &ebuf);
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
            case 'R':
            case 'd':
                if (ISSET(username) && (domain = strchr(username, '@')) && domain[1]!='\0') {
                    rc=ptsmodule_escape(domain+1, strlen(domain+1), &ebuf);
                    if (rc == PTSM_OK) {
                        if (*(temp+1) == 'R')
                            strcat(buf,"@");
                        strcat(buf,ebuf);
                        free(ebuf);
                    }
                    break;
                }
                break;
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
#endif
    char *base = NULL, *filter = NULL;
    char *domain = NULL;
    char domain_filter[1024];
    char *attrs[] = {LDAP_NO_ATTRS,NULL}; //do not return all attrs!
    char *domain_attrs[] = {(char *)ptsm->domain_name_attribute,(char *)ptsm->domain_result_attribute,NULL};
    LDAPMessage *res;
    LDAPMessage *entry;
    char **vals;
    /* unused: BerElement *ber; */

    *ret = NULL;

    if (ptsm->ld == NULL)
        return PTSM_FAIL;

#if LDAP_VENDOR_VERSION >= 20125

    if (ptsm->sasl) {

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

    } else

#endif

    {
        rc = ptsmodule_expand_tokens(ptsm->filter, canon_id, NULL, &filter);
        if (rc != PTSM_OK)
            goto done;

        if (ptsm->domain_base_dn && ptsm->domain_base_dn[0] != '\0' && (strrchr(canon_id, '@') == NULL)) {
            syslog(LOG_DEBUG, "collecting all domains from %s", ptsm->domain_base_dn);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
            /* Format string comes from imapd.conf.  Not ideal, but it's what
             * we've got...
             */
            snprintf(domain_filter, sizeof(domain_filter), ptsm->domain_filter, "*");
#pragma GCC diagnostic pop

            syslog(LOG_DEBUG, "Domain filter: %s", domain_filter);

            rc = ldap_search_st(ptsm->ld, ptsm->domain_base_dn, ptsm->domain_scope, domain_filter, domain_attrs, 0, &(ptsm->timeout), &res);

            if (rc != LDAP_SUCCESS) {
                if (rc == LDAP_SERVER_DOWN) {
                    syslog(LOG_ERR, "LDAP not available: %s", ldap_err2string(rc));
                    ldap_unbind(ptsm->ld);
                    ptsm->ld = NULL;
                    rc = PTSM_RETRY;
                    goto done;
                }

                syslog(LOG_ERR, "LDAP search for domain failed: %s", ldap_err2string(rc));
                rc = PTSM_FAIL;
                goto done;
            }
            if (ldap_count_entries(ptsm->ld, res) < 1) {
                syslog(LOG_ERR, "No domain found");
                rc = PTSM_FAIL;
                goto done;
            } else if (ldap_count_entries(ptsm->ld, res) >= 1) {
                int count_matches = 0;
                char *temp_base = NULL;
                LDAPMessage *res2;
                for (entry = ldap_first_entry(ptsm->ld, res); entry != NULL; entry = ldap_next_entry(ptsm->ld, entry)) {
                    if ((vals = ldap_get_values(ptsm->ld, entry, ptsm->domain_name_attribute)) != NULL) {
                        syslog(LOG_DEBUG, "we have a domain %s", vals[0]);
                        ptsmodule_standard_root_dn(vals[0], (const char **) &temp_base);
                        rc = ldap_search_st(ptsm->ld, temp_base, ptsm->scope, filter, attrs, 0, &(ptsm->timeout), &res2);
                        if (rc == LDAP_SUCCESS && ldap_count_entries(ptsm->ld, res2) == 1) {
                            syslog(LOG_DEBUG, "Found %s in %s", canon_id, temp_base);
                            base = temp_base;
                            count_matches++;
                        }
                    }
                }

                if (count_matches > 1) {
                    syslog(LOG_ERR, "LDAP search for %s failed because it matches multiple accounts.", canon_id);
                    rc = PTSM_FAIL;
                    goto done;
                } else if (count_matches == 0) {
                    syslog(LOG_ERR, "LDAP search for %s failed because it does not match any account in all domains.", canon_id);
                    rc = PTSM_FAIL;
                    goto done;
                }

                syslog(LOG_DEBUG, "we have found %s in %s", canon_id, base);
            }
        }
        else if (ptsm->domain_base_dn && ptsm->domain_base_dn[0] != '\0' && (strrchr(canon_id, '@') != NULL)) {
            syslog(LOG_DEBUG, "Attempting to get domain for %s from %s", canon_id, ptsm->domain_base_dn);

            /* Get the base dn to search from domain_base_dn searched on domain_scope with
                domain_filter */
            domain = strrchr(canon_id, '@');

            /* Strip the first character which is a '@' */
            domain = domain+1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
            /* Format string comes from imapd.conf.  Not ideal, but it's what
             * we've got...
             */
            snprintf(domain_filter, sizeof(domain_filter), ptsm->domain_filter, domain);
#pragma GCC diagnostic pop

            syslog(LOG_DEBUG, "Domain filter: %s", domain_filter);

            rc = ldap_search_st(ptsm->ld, ptsm->domain_base_dn, ptsm->domain_scope, domain_filter, domain_attrs, 0, &(ptsm->timeout), &res);

            if (rc != LDAP_SUCCESS) {
                if (rc == LDAP_SERVER_DOWN) {
                    ldap_unbind(ptsm->ld);
                    ptsm->ld = NULL;
                    syslog(LOG_ERR, "LDAP not available: %s", ldap_err2string(rc));
                    rc = PTSM_RETRY;
                    goto done;
                }

                syslog(LOG_ERR, "LDAP search for domain failed: %s", ldap_err2string(rc));
                rc = PTSM_FAIL;
                goto done;
            }

            if (ldap_count_entries(ptsm->ld, res) < 1) {
                syslog(LOG_ERR, "No domain %s found", domain);
                rc = PTSM_FAIL;
                goto done;
            } else if (ldap_count_entries(ptsm->ld, res) > 1) {
                syslog(LOG_ERR, "Multiple domains %s found", domain);
                rc = PTSM_FAIL;
                goto done;
            } else {
                if ((entry = ldap_first_entry(ptsm->ld, res)) != NULL) {
                    if ((vals = ldap_get_values(ptsm->ld, entry, ptsm->domain_result_attribute)) != NULL) {
                        syslog(LOG_DEBUG, "Root DN for domain %s is %s", domain, vals[0]);
                        ptsm->base = vals[0];
                        rc = PTSM_OK;
                    } else if ((vals = ldap_get_values(ptsm->ld, entry, ptsm->domain_name_attribute)) != NULL) {
                        syslog(LOG_DEBUG, "Domain %s is an alias domain for parent domain %s", domain, vals[0]);
                        rc = ptsmodule_standard_root_dn(vals[0], &ptsm->base);
                    } else {
                        rc = ptsmodule_standard_root_dn(domain, &ptsm->base);
                    }

                    if (rc != PTSM_OK) {
                        goto done;
                    } else {
                        base = xstrdup(ptsm->base);
                        syslog(LOG_DEBUG, "Continuing with ptsm->base: %s", ptsm->base);
                    }
                }
            }

        } else {
            rc = ptsmodule_expand_tokens(ptsm->base, canon_id, NULL, &base);
            if (rc != PTSM_OK)
                goto done;
        }

        rc = ldap_search_st(ptsm->ld, base, ptsm->scope, filter, attrs, 0, &(ptsm->timeout), &res);

        if (rc != LDAP_SUCCESS) {
            syslog(LOG_DEBUG, "Searching %s with %s failed", base, filter);

            if (rc == LDAP_SERVER_DOWN) {
                ldap_unbind(ptsm->ld);
                ptsm->ld = NULL;
                rc = PTSM_RETRY;
                goto done;
            }

            rc = PTSM_FAIL;
            goto done;
        }

        free(filter);
        free(base);

        /*
         * We don't want to return the *first* entry found, we want to return
         * the *only* entry found.
         */
        if (ldap_count_entries(ptsm->ld, res) < 1) {
            syslog(LOG_ERR, "No entries found");
        } else if (ldap_count_entries(ptsm->ld, res) > 1) {
            syslog(LOG_ERR, "Multiple entries found: %d", ldap_count_entries(ptsm->ld, res));
        } else {
/*      if ( ldap_count_entries(ptsm->ld, res) == 1 ) { */
            if ((entry = ldap_first_entry(ptsm->ld, res)) != NULL) {
                *ret = ldap_get_dn(ptsm->ld, entry);
            }
        }

        ldap_msgfree(res);
        res = NULL;
    }

    return (*ret ? PTSM_OK : PTSM_FAIL);

 done:
    if (filter)
        free(filter);
    if (base)
        free(base);
    return rc;
}


static int ptsmodule_make_authstate_attribute(
    const char *canon_id,
    size_t size,
    const char **reply,
    int *dsize,
    struct auth_state **newstate)
{
    char *dn = NULL;
    LDAPMessage *res = NULL;
    LDAPMessage *entry = NULL;
    char **vals = NULL;
    char **rdn = NULL;
    int rc;
    char *attrs[] = {(char *)ptsm->member_attribute,(char *)ptsm->user_attribute,NULL};

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
        int i, numvals;

        vals = ldap_get_values(ptsm->ld, entry, (char *)ptsm->member_attribute);
        if (vals != NULL) {
            numvals = ldap_count_values(vals);

            *dsize = sizeof(struct auth_state) +
                (numvals * sizeof(struct auth_ident));
            *newstate = xmalloc(*dsize);
            if (*newstate == NULL) {
                *reply = "no memory";
                rc = PTSM_FAIL;
                goto done;
            }

            (*newstate)->ngroups = numvals;
            (*newstate)->userid.id[0] = '\0';
            for (i = 0; i < numvals; i++) {
                unsigned int j;
                strcpy((*newstate)->groups[i].id, "group:");
                rdn = ldap_explode_rdn(vals[i],1);
                for (j = 0; j < strlen(rdn[0]); j++) {
                    if (Uisupper(rdn[0][j]))
                        rdn[0][j]=tolower(rdn[0][j]);
                }
                strlcat((*newstate)->groups[i].id, rdn[0], sizeof((*newstate)->groups[i].id));
                (*newstate)->groups[i].hash = strhash((*newstate)->groups[i].id);
            }

            ldap_value_free(rdn);
            ldap_value_free(vals);
            vals = NULL;
        }

        if ((char *)ptsm->user_attribute) {
            vals = ldap_get_values(ptsm->ld, entry, (char *)ptsm->user_attribute);
            if (vals != NULL) {
                numvals = ldap_count_values(vals);

                if (numvals == 1) {
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

                    size=strlen(vals[0]);
                    strcpy((*newstate)->userid.id, ptsmodule_canonifyid(vals[0],size));
                    (*newstate)->userid.hash = strhash((*newstate)->userid.id);
                }

                ldap_value_free(vals);
                vals = NULL;
            }
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
        (*newstate)->userid.id[0] = '\0';
    }

    /* fill in the rest of our new state structure */
    if ((*newstate)->userid.id[0]=='\0') {
        strcpy((*newstate)->userid.id, canon_id);
        (*newstate)->userid.hash = strhash(canon_id);
    }
    (*newstate)->mark = time(0);

    rc = PTSM_OK;

done:;

    if (res)
        ldap_msgfree(res);
    if (vals)
        ldap_value_free(vals);
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
    LDAPMessage *entry = NULL;
    char **vals = NULL;
    char *attrs[] = {(char *)ptsm->member_attribute,NULL};
    char *dn = NULL;
    char *errdn = NULL;

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

    rc = ptsmodule_expand_tokens(ptsm->group_base, canon_id, dn, &base);
    if (rc != PTSM_OK) {
        *reply = "ptsmodule_expand_tokens() failed for member search base";
        goto done;
    }

    rc = ldap_search_st(ptsm->ld, base, ptsm->group_scope, filter, attrs, 0, &(ptsm->timeout), &res);
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

    *dsize = sizeof(struct auth_state) + (n * sizeof(struct auth_ident));

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
        unsigned int j;

        if (errdn) ldap_memfree(errdn);
        errdn = ldap_get_dn(ptsm->ld, entry);

        vals = ldap_get_values(ptsm->ld, entry, (char *)ptsm->member_attribute);
        if (vals == NULL) {
            syslog(LOG_ERR, "Multiple values for attribute '%s' on entry '%s'",
                            ptsm->member_attribute,
                            errdn);
            continue;
        }

        if (ldap_count_values(vals) < 1 ) {
            syslog(LOG_ERR, "No values for attribute '%s' on entry '%s'",
                            ptsm->member_attribute,
                            errdn);
            *reply = "no values";
            rc = PTSM_FAIL;
            ldap_value_free(vals);
            vals = NULL;
            goto done;
        } else if (ldap_count_values(vals) > 1) {
            syslog(LOG_ERR, "Too many values for attribute '%s' on entry '%s'",
                            ptsm->member_attribute,
                            errdn);
            *reply = "too many values";
            rc = PTSM_FAIL;
            ldap_value_free(vals);
            vals = NULL;
            goto done;
        }

        strcpy((*newstate)->groups[i].id, "group:");

        for (j =0; j < strlen(vals[0]); j++) {
            if(Uisupper(vals[0][j]))
                vals[0][j]=tolower(vals[0][j]);
        }

        strlcat((*newstate)->groups[i].id, vals[0], sizeof((*newstate)->groups[i].id));
        (*newstate)->groups[i].hash = strhash((*newstate)->groups[i].id);

        ldap_value_free(vals);
        vals = NULL;

        if (errdn) ldap_memfree(errdn);
        errdn = NULL;
    }

    rc = PTSM_OK;

done:

    if (res)
        ldap_msgfree(res);
    if (dn)
        free(dn);
    if (filter)
        free(filter);
    if (base)
        free(base);
    if (errdn)
        ldap_memfree(errdn);

    return rc;
}

static int ptsmodule_make_authstate_group(
    const char *canon_id,
    size_t size __attribute__((unused)),
    const char **reply,
    int *dsize,
    struct auth_state **newstate)
{
    char *base = NULL, *filter = NULL;
    char *domain = NULL;
    char domain_filter[1024];
    char *domain_attrs[] = {(char *)ptsm->domain_name_attribute,(char *)ptsm->domain_result_attribute,NULL};
    int rc;
    int n;
    LDAPMessage *res = NULL;
    LDAPMessage *entry = NULL;
    char **vals = NULL;
    char *attrs[] = {NULL};

    if (strncmp(canon_id, "group:", 6))  { // Sanity check
        *reply = "not a group identifier";
        rc = PTSM_FAIL;
        goto done;
    }

    rc = ptsmodule_connect();
    if (rc != PTSM_OK) {
        *reply = "ptsmodule_connect() failed";
        goto done;
    }

    rc = ptsmodule_expand_tokens(ptsm->group_filter, canon_id+6, NULL, &filter);
    if (rc != PTSM_OK) {
        *reply = "ptsmodule_expand_tokens() failed for group filter";
        goto done;
    }

    if (ptsm->domain_base_dn && (strrchr(canon_id, '@') != NULL)) {
        syslog(LOG_DEBUG, "(groups) Attempting to get domain for %s from %s", canon_id, ptsm->domain_base_dn);

        /* Get the base dn to search from domain_base_dn searched on domain_scope with
            domain_filter */
        domain = strrchr(canon_id, '@');

        syslog(LOG_DEBUG, "(groups) Input domain would be %s", domain);

        /* Strip the first character which is a '@' AM: assuming ASCII */
        domain = domain+1;

        syslog(LOG_DEBUG, "(groups) Input domain would be %s", domain);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
            /* Format string comes from imapd.conf.  Not ideal, but it's what
             * we've got...
             */
        snprintf(domain_filter, sizeof(domain_filter), ptsm->domain_filter, domain);
#pragma GCC diagnostic pop

        syslog(LOG_DEBUG, "(groups) Domain filter: %s", domain_filter);

        rc = ldap_search_st(ptsm->ld, ptsm->domain_base_dn, ptsm->domain_scope, domain_filter, domain_attrs, 0, &(ptsm->timeout), &res);

        if (rc != LDAP_SUCCESS) {
            syslog(LOG_DEBUG, "(groups) Result from domain query not OK");
            goto done;
        } else {
            syslog(LOG_DEBUG, "(groups) Result from domain query OK");
        }

        if (ldap_count_entries(ptsm->ld, res) < 1) {
            syslog(LOG_ERR, "(groups) No domain %s found", domain);
            rc = PTSM_FAIL;
            goto done;
        } else if (ldap_count_entries(ptsm->ld, res) > 1) {
            syslog(LOG_ERR, "(groups) Multiple domains %s found", domain);
            rc = PTSM_FAIL;
            goto done;
        } else {
            syslog(LOG_DEBUG, "(groups) Domain %s found", domain);
            if ((entry = ldap_first_entry(ptsm->ld, res)) != NULL) {
                if ((vals = ldap_get_values(ptsm->ld, entry, ptsm->domain_result_attribute)) != NULL) {
                    ptsm->group_base = vals[0];
                    rc = PTSM_OK;
                } else if ((vals = ldap_get_values(ptsm->ld, entry, ptsm->domain_name_attribute)) != NULL) {
                    char *new_domain = xstrdup(vals[0]);
                    syslog(LOG_DEBUG, "(groups) Domain %s is now domain %s", domain, new_domain);
                    rc = ptsmodule_standard_root_dn(new_domain, &ptsm->group_base);
                    free(new_domain);
                } else {
                    rc = ptsmodule_standard_root_dn(domain, &ptsm->group_base);
                }

                if (rc != PTSM_OK) {
                    goto done;
                } else {
                    base = xstrdup(ptsm->group_base);
                    syslog(LOG_DEBUG, "Continuing with ptsm->group_base: %s", ptsm->group_base);
                }
            }
        }
    } else {
        rc = ptsmodule_expand_tokens(ptsm->group_base, canon_id, NULL, &base);
        if (rc != PTSM_OK)
            goto done;
    }

    syslog(LOG_DEBUG, "(groups) about to search %s for %s", base, filter);


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

static struct auth_state *myauthstate(
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

#else /* HAVE_LDAP */

static void myinit(void)
{
    fatal("PTS module (ldap) not compiled in", EX_CONFIG);
}

static struct auth_state *myauthstate(
    const char *identifier __attribute__((unused)),
    size_t size __attribute__((unused)),
    const char **reply __attribute__((unused)),
    int *dsize __attribute__((unused)))
{
    fatal("PTS module (ldap) not compiled in", EX_CONFIG);
}

#endif /* HAVE_LDAP */

struct pts_module pts_ldap =
{
    "ldap",        /* name */

    &myinit,
    &myauthstate,
};
