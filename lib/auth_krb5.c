/* auth_krb5.c - Kerberos V authorization for Cyrus IMAP */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>

#include "auth.h"
#include "xmalloc.h"

#ifdef HAVE_GSSAPI_H

#include <limits.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>

#include <krb5.h>

struct auth_state {
    char *userid; /* Canonified Userid */
};

/*
 * Determine if the user is a member of 'identifier'
 * Returns one of:
 *      0       User does not match identifier
 *      1       identifier matches everybody
 *      2       User is in the group that is identifier
 *      3       User is identifer
 */
static int mymemberof(const struct auth_state *auth_state, const char *identifier)
{
    const char *ident;
    int ret=0;

    if (strcmp(identifier,"anyone") == 0) return 1;
    if (!auth_state && !strcmp(identifier, "anonymous")) return 3;
    else if(!auth_state) return 0;
    if (strcmp(identifier,auth_state->userid) == 0) return 3;
    if (strcmp(auth_state->userid,"anonymous") == 0) return 0;

    ident = auth_canonifyid(identifier,0);

    if (!strcmp(ident, auth_state->userid)) {
        ret = 3;
    }

    return ret;
}

/*
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 */
static const char *mycanonifyid(const char *identifier, size_t len)
{
    static char *retbuf = NULL;
    krb5_context context;
    krb5_principal princ, princ_dummy;
    char *realm;
    int striprealm = 0;

    if(retbuf) free(retbuf);
    retbuf = NULL;

    if(!identifier) return NULL;
    if(!len) len = strlen(identifier);

    if (strcasecmp(identifier, "anonymous") == 0)
        return "anonymous";

    if (strcasecmp(identifier, "anyone") == 0)
        return "anyone";

    if (krb5_init_context(&context))
        return NULL;

    if (krb5_parse_name(context,identifier,&princ))
    {
        krb5_free_context(context);
        return NULL;
    }

    /* get local realm */
    if (krb5_get_default_realm(context,&realm))
    {
        krb5_free_principal(context,princ);
        krb5_free_context(context);
        return NULL;
    }

    /* build dummy princ to compare realms */
    if (krb5_build_principal(context,&princ_dummy,
                             strlen(realm),realm,"dummy",NULL))
    {
        krb5_free_principal(context,princ);
        krb5_free_context(context);
        free(realm);
        return NULL;
    }

    /* is this principal local ? */
    if (krb5_realm_compare(context,princ,princ_dummy))
    {
        striprealm = 1;
    }

    /* done w/ dummy princ free it & realm */
    krb5_free_principal(context,princ_dummy);
    free(realm);

    /* get the text version of princ */
    if (krb5_unparse_name(context,princ,&retbuf))
    {
        krb5_free_principal(context,princ);
        krb5_free_context(context);
        return NULL;
    }

    /* we have the canonical name pointed to by p -- strip realm if local */
    if (striprealm)
    {
        char *realmbegin = strrchr(retbuf, '@');
        if(realmbegin) *realmbegin = '\0';
    }

    krb5_free_principal(context,princ);
    krb5_free_context(context);
    return retbuf;
}

/*
 * Set the current user to 'identifier'.
 */
static struct auth_state *mynewstate(const char *identifier)
{
    struct auth_state *newstate;
    const char *ident;

    ident = auth_canonifyid(identifier, 0);
    if (!ident) return NULL;

    newstate = (struct auth_state *)xmalloc(sizeof(struct auth_state));
    newstate->userid = xstrdup(ident);

    return newstate;
}

static void myfreestate(struct auth_state *auth_state)
{
    if(!auth_state) return;

    free(auth_state->userid);
    free(auth_state);
}

static strarray_t *mygroups(const struct auth_state *auth_state __attribute__((unused)))
{
    syslog(LOG_WARNING, "Authentication mechanism (krb5) does not support groups");
    return NULL;
}

#else /* HAVE_GSSAPI_H */

static int mymemberof(
    const struct auth_state *auth_state __attribute__((unused)),
    const char *identifier __attribute__((unused)))
{
        fatal("Authentication mechanism (krb5) not compiled in", EX_CONFIG);
        return 0;
}

static const char *mycanonifyid(
    const char *identifier __attribute__((unused)),
    size_t len __attribute__((unused)))
{
        fatal("Authentication mechanism (krb5) not compiled in", EX_CONFIG);
        return NULL;
}

static struct auth_state *mynewstate(
    const char *identifier __attribute__((unused)))
{
        fatal("Authentication mechanism (krb5) not compiled in", EX_CONFIG);
        return NULL;
}

static void myfreestate(
    struct auth_state *auth_state __attribute__((unused)))
{
        fatal("Authentication mechanism (krb5) not compiled in", EX_CONFIG);
}

static strarray_t *mygroups(
    const struct auth_state *auth_state __attribute__((unused)))
{
        fatal("Authentication mechanism (krb5) not compiled in", EX_CONFIG);
}

#endif

HIDDEN struct auth_mech auth_krb5 =
{
    "krb5",             /* name */

    &mycanonifyid,
    &mymemberof,
    &mynewstate,
    &myfreestate,
    &mygroups,
    NULL, /* refresh */
};
