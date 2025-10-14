/* afskrb.c - AFS PTS Group (Kerberos Canonicalization) Backend to ptloader
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
#include <config.h>
#include <ctype.h>
#include <sysexits.h>
#include <syslog.h>
#include "ptloader.h"
#include "util.h"
#include "xmalloc.h"

#ifdef HAVE_AFSKRB
# include <string.h>
# include <stdio.h>
# include <stdlib.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/types.h>
# include <sys/param.h>
# include <fcntl.h>
# include <sys/socket.h>
# include <sys/un.h>
# include <sys/uio.h>

# include <krb5.h>

# include "auth_pts.h"
# include "libconfig.h"
# include "strhash.h"

/* AFS stuff */
# include <lock.h>
# include <afs/ptserver.h>
# include <afs/pterror.h>
# include <afs/cellconfig.h>
# include <rx/rxkad.h>
# include <afs/auth.h>

/* blame transarc i've been told */
# ifndef AFSCONF_CLIENTNAME
#  include <afs/dirpath.h>
#  define AFSCONF_CLIENTNAME AFSDIR_CLIENT_ETC_DIRPATH
# endif

/* Sanity Check */
# if PTS_DB_KEYSIZE < PR_MAXNAMELEN
#  error PTS_DB_KEYSIZE is smaller than PR_MAXNAMELEN
# endif

static const char *localrealms = NULL;

int is_local_realm(const char *realm)
{
    const char *val = localrealms;

    if (!val || !realm) {
        return 0;
    }

    while (*val) {
        char buf[1024];
        size_t len;
        char *p;

        for (p = (char *) val; *p && !Uisspace(*p); p++)
            ;
        len = p - val;
        if (len >= sizeof(buf)) {
            len = sizeof(buf) - 1;
        }
        memcpy(buf, val, len);
        buf[len] = '\0';

        if (!strcasecmp(realm, buf)) {
            return 1;
        }
        val = p;
        while (*val && Uisspace(*val)) {
            val++;
        }
    }

    return 0;
}

/*
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 */
static char *afspts_canonifyid(const char *identifier, size_t len)
{
    static char *retbuf = NULL;
    char *tmp = NULL;
    krb5_context context;
    krb5_principal princ, princ_dummy;
    char *realm;
    char *realmbegin;
    int striprealm = 0;
    char *identifier2;

    if (retbuf) {
        free(retbuf);
    }
    retbuf = NULL;

    if (!identifier) {
        return NULL;
    }
    if (!len) {
        len = strlen(identifier);
    }

    if (strcasecmp(identifier, "anonymous") == 0) {
        return "anonymous";
    }

    if (strcasecmp(identifier, "anyone") == 0) {
        return "anyone";
    }

    identifier2 = strdup(identifier);
    if (tmp = strchr(identifier2, '+')) {
        syslog(LOG_DEBUG, "afspts_canonifyid stripping: %s", identifier2);
        tmp[0] = 0;
        syslog(LOG_DEBUG, "afspts_canonifyid stripped: %s", identifier2);
    }

    if (krb5_init_context(&context)) {
        syslog(LOG_ERR, "afspts_canonifyid krb5_init_context failed");
        return NULL;
    }

    if (krb5_parse_name(context, identifier2, &princ)) {
        krb5_free_context(context);
        free(identifier2);
        syslog(LOG_ERR, "afspts_canonifyid krb5_parse_name failed");
        return NULL;
    }
    free(identifier2);

    if (config_getswitch(IMAPOPT_PTSKRB5_STRIP_DEFAULT_REALM)) {
        /* get local realm */
        if (krb5_get_default_realm(context, &realm)) {
            krb5_free_principal(context, princ);
            krb5_free_context(context);
            syslog(LOG_ERR, "afspts_canonifyid krb5_get_default_realm failed");
            return NULL;
        }

        /* build dummy princ to compare realms */
        if (krb5_build_principal(context,
                                 &princ_dummy,
                                 strlen(realm),
                                 realm,
                                 "dummy",
                                 0))
        {
            krb5_free_principal(context, princ);
            krb5_free_context(context);
            free(realm);
            syslog(LOG_ERR, "afspts_canonifyid krb5_build_principal failed");
            return NULL;
        }

        /* is this principal local ? */
        if (krb5_realm_compare(context, princ, princ_dummy)) {
            striprealm = 1;
        }

        /* done w/ dummy princ free it & realm */
        krb5_free_principal(context, princ_dummy);
        free(realm);
    }

    if (config_getswitch(IMAPOPT_PTSKRB5_CONVERT524)) {
        char nbuf[64], ibuf[64], rbuf[64];

        if (krb5_524_conv_principal(context, princ, nbuf, ibuf, rbuf)) {
            krb5_free_principal(context, princ);
            krb5_free_context(context);
            return NULL;
        }

        retbuf = xmalloc(3 * 64 + 3);
        sprintf(retbuf,
                "%s%s%s%s%s",
                nbuf,
                ibuf[0] ? "." : "",
                ibuf,
                rbuf[0] ? "@" : "",
                rbuf);
    }
    else {
        /* get the text version of princ */
        if (krb5_unparse_name(context, princ, &retbuf)) {
            krb5_free_principal(context, princ);
            krb5_free_context(context);
            syslog(LOG_ERR, "afspts_canonifyid krb5_unparse_name failed");
            return NULL;
        }
    }

    /* we have the canonical name pointed to by p -- strip realm if local */
    realmbegin = strrchr(retbuf, '@');
    if (realmbegin) {
        if (!striprealm) {
            realm = realmbegin + 1;
            if (is_local_realm(realm)) {
                striprealm = 1;
            }
        }

        if (striprealm) {
            *realmbegin = '\0';
        }
        else {
            /* Force realm to uppercase */
            while (*(++realmbegin)) {
                *realmbegin = toupper(*realmbegin);
            }
        }
    }

    krb5_free_principal(context, princ);
    krb5_free_context(context);
    return retbuf;
}

/* API */

static void myinit(void)
{
    int r = pr_Initialize(1L,
                          AFSCONF_CLIENTNAME,
                          config_getstring(IMAPOPT_AFSPTS_MYCELL));
    if (r) {
        syslog(LOG_DEBUG, "pr_Initialize failed: %d", r);
        fatal("pr_initialize failed", EX_TEMPFAIL);
    }

    localrealms = config_getstring(IMAPOPT_AFSPTS_LOCALREALMS);

    return;
}

static struct auth_state *myauthstate(const char *identifier,
                                      size_t size,
                                      const char **reply,
                                      int *dsize)
{
    const char *canon_id = afspts_canonifyid(identifier, size);
    char canon_id_tmp[PTS_DB_KEYSIZE + 1];
    namelist groups;
    int i, rc;
    struct auth_state *newstate;

    if (canon_id == NULL) {
        syslog(LOG_ERR, "afspts_canonifyid failed for %s", identifier);
        return NULL;
    }

    *reply = NULL;
    size = strlen(canon_id);

    memset(&groups, 0, sizeof(groups));
    groups.namelist_len = 0;
    groups.namelist_val = NULL;

    /* canon_id_tmp is used because AFS would otherwise trample
     * on our nice canonical user id */
    strlcpy(canon_id_tmp, canon_id, sizeof(canon_id_tmp));
    if ((rc = pr_ListMembers(canon_id_tmp, &groups))) {
        /* Failure may indicate that we need new tokens */
        pr_End();
        rc = pr_Initialize(1L,
                           AFSCONF_CLIENTNAME,
                           config_getstring(IMAPOPT_AFSPTS_MYCELL));
        if (rc) {
            syslog(LOG_DEBUG, "pr_Initialize failed: %d", rc);
            fatal("pr_Initialize failed", EX_TEMPFAIL);
        }
        /* Okay, rerun it now */
        rc = pr_ListMembers(canon_id_tmp, &groups);
    }

    /* Don't die because of afs, but log the error */
    if (rc) {
        syslog(LOG_ERR, "pr_ListMembers %s: %s", canon_id, error_message(rc));
    }

    /* fill in our new state structure */
    *dsize = sizeof(struct auth_state)
             + (groups.namelist_len * sizeof(struct auth_ident));
    newstate = (struct auth_state *) xzmalloc(*dsize);

    strcpy(newstate->userid.id, canon_id);
    newstate->userid.hash = strhash(canon_id);

    /* If we get a permission error, assume it may be temporary
       authentication problem, and cache only for a minute.
       Should negative cache time be configurable? */
    if (rc == PRPERM) {
        int ptscache_timeout =
            config_getduration(IMAPOPT_PTSCACHE_TIMEOUT, 's');
        if (ptscache_timeout < 60) {
            ptscache_timeout = 60;
        }
        newstate->mark = time(0) + 60 - ptscache_timeout;
    }
    else {
        newstate->mark = time(0);
    }

    newstate->ngroups = groups.namelist_len;
    /* store group list in contiguous array for easy storage in the database */
    memset(newstate->groups, 0, newstate->ngroups * sizeof(struct auth_ident));
    for (i = 0; i < newstate->ngroups; i++) {
        strlcpy(newstate->groups[i].id,
                groups.namelist_val[i],
                sizeof(newstate->groups[i].id));
        newstate->groups[i].hash = strhash(groups.namelist_val[i]);
        /* don't free groups.namelist_val[i]. Something else currently
         * takes care of that data.
         */
    }
    if (groups.namelist_val != NULL) {
        free(groups.namelist_val);
    }

    return newstate;
}

#else /* HAVE_AFSKRB */

static void myinit(void)
{
    fatal("PTS module (afskrb) not compiled in", EX_CONFIG);
}

static struct auth_state *myauthstate(const char *identifier
                                      __attribute__((unused)),
                                      size_t size __attribute__((unused)),
                                      const char **reply
                                      __attribute__((unused)),
                                      int *dsize __attribute__((unused)))
{
    fatal("PTS module (afskrb) not compiled in", EX_CONFIG);
    return NULL;
}

#endif /* HAVE_AFSKRB */

struct pts_module pts_afskrb = {
    "afskrb", /* name */

    &myinit,
    &myauthstate,
};
