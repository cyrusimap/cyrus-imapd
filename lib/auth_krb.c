/* auth_krb.c -- Kerberos authorization
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
#include <stdlib.h>
#include <sysexits.h>

#include "auth.h"
#include "xmalloc.h"
#include "util.h"

#ifdef HAVE_KRB

#include <limits.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>

#include <krb.h>
#ifdef HAVE_BDB
#ifdef HAVE_DB_185_H
#include <db_185.h>
#else
#include <db.h>
#endif
#else
#include <ndbm.h>
#endif
#include <krb.h>

#ifndef KRB_MAPNAME
#define KRB_MAPNAME (SYSCONF_DIR "/krb.equiv")
#endif

struct auth_state {
    char userid[MAX_K_NAME_SZ+1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
};

static struct auth_state auth_anonymous = {
    "anonymous", "anonymous", "", ""
};



static int parse_krbequiv_line (const char *src,
                                  char *principal, char *localuser);
static char *auth_map_krbid (const char *real_aname, const char *real_inst,
                             const char *real_realm);

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
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];

    if (!auth_state) auth_state = &auth_anonymous;

    if (strcmp(identifier, "anyone") == 0) return 1;

    if (strcmp(identifier, auth_state->userid) == 0) return 3;

    /* "anonymous" is not a member of any group */
    if (strcmp(auth_state->userid, "anonymous") == 0) return 0;

    aname[0] = inst[0] = realm[0] = '\0';
    if (kname_parse(aname, inst, realm, (char *) identifier) != 0) {
        return 0;
    }

    if (strcmp(aname, auth_state->aname) != 0 && strcmp(aname, "*") != 0) {
        return 0;
    }
    if (strcmp(inst, auth_state->inst) != 0 && strcmp(inst, "*") != 0) {
        return 0;
    }
    if (strcmp(realm, auth_state->realm) != 0 && strcmp(realm, "*") != 0) {
        return 0;
    }
    return 2;
}

/*
 * Parse a line 'src' from an /etc/krb.equiv file.
 * Sets the buffer pointed to by 'principal' to be the kerberos
 * identity and sets the buffer pointed to by 'localuser' to
 * be the local user.  Both buffers must be of size one larger than
 * MAX_K_NAME_SZ.  Returns 1 on success, 0 on failure.
 */
static int
parse_krbequiv_line(const char *src, char *principal, char *localuser)
{
    int i;

    while (Uisspace(*src)) src++;
    if (!*src) return 0;

    for (i = 0; *src && !Uisspace(*src); i++) {
        if (i >= MAX_K_NAME_SZ) return 0;
        *principal++ = *src++;
    }
    *principal = 0;

    if (!Uisspace(*src)) return 0; /* Need at least one separator */
    while (Uisspace(*src)) src++;
    if (!*src) return 0;

    for (i = 0; *src && !Uisspace(*src); i++) {
        if (i >= MAX_K_NAME_SZ) return 0;
        *localuser++ = *src++;
    }
    *localuser = 0;
    return 1;
}

/*
 * Map a remote kerberos principal to a local username.  If a mapping
 * is found, a pointer to the local username is returned.  Otherwise,
 * a NULL pointer is returned.
 * Eventually, this may be more sophisticated than a simple file scan.
 */
static char *auth_map_krbid(real_aname, real_inst, real_realm)
const char *real_aname;
const char *real_inst;
const char *real_realm;
{
    static char localuser[MAX_K_NAME_SZ + 1];
    char principal[MAX_K_NAME_SZ + 1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char lrealm[REALM_SZ];
    char krbhst[256];
    char *p;
    char buf[1024];
    FILE *mapfile;

    if (!(mapfile = fopen(KRB_MAPNAME, "r"))) {
        /* If the file can't be opened, don't do mappings */
        return 0;
    }

    for (;;) {
        if (!fgets(buf, sizeof(buf), mapfile)) break;
        if (parse_krbequiv_line(buf, principal, localuser) == 0 ||
            kname_parse(aname, inst, realm, principal) != 0) {
            /* Ignore badly formed lines */
            continue;
        }
        if (!strcmp(aname, real_aname) && !strcmp(inst, real_inst) &&
            !strcmp(realm, real_realm)) {
            fclose(mapfile);

            aname[0] = inst[0] = realm[0] = '\0';
            if (kname_parse(aname, inst, realm, localuser) != 0) {
                return 0;
            }

            /* Upcase realm name */
            for (p = realm; *p; p++) {
                if (Uislower(*p)) *p = toupper(*p);
            }

            if (*realm) {
                if (krb_get_lrealm(lrealm,1) == 0 &&
                    strcmp(lrealm, realm) == 0) {
                    *realm = 0;
                }
                else if (krb_get_krbhst(krbhst, realm, 1)) {
                    return 0;           /* Unknown realm */
                }
            }

            strcpy(localuser, aname);
            if (*inst) {
                strcat(localuser, ".");
                strcat(localuser, inst);
            }
            if (*realm) {
                strcat(localuser, "@");
                strcat(localuser, realm);
            }

            return localuser;
        }
    }

    fclose(mapfile);
    return 0;
}

/*
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 */
static const char *mycanonifyid(const char *identifier, size_t len)
{
    static char retbuf[MAX_K_NAME_SZ+1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char lrealm[REALM_SZ];
    char krbhst[256];
    char *canon_buf;
    char *p;

    if(!len) len = strlen(identifier);

    canon_buf = malloc(len + 1);
    if(!canon_buf) return 0;
    memcpy(canon_buf, identifier, len);
    canon_buf[len] = '\0';

    aname[0] = inst[0] = realm[0] = '\0';
    if (kname_parse(aname, inst, realm, canon_buf) != 0) {
        free(canon_buf);
        return 0;
    }

    free(canon_buf);

    /* Upcase realm name */
    for (p = realm; *p; p++) {
        if (Uislower(*p)) *p = toupper(*p);
    }

    if (*realm) {
        if (krb_get_lrealm(lrealm,1) == 0 &&
            strcmp(lrealm, realm) == 0) {
            *realm = 0;
        }
        else if (krb_get_krbhst(krbhst, realm, 1)) {
            return 0;           /* Unknown realm */
        }
    }

    /* Check for krb.equiv remappings. */
    if ((p = auth_map_krbid(aname, inst, realm)) ) {
        strcpy(retbuf, p);
        return retbuf;
    }

    strcpy(retbuf, aname);
    if (*inst) {
        strcat(retbuf, ".");
        strcat(retbuf, inst);
    }
    if (*realm) {
        strcat(retbuf, "@");
        strcat(retbuf, realm);
    }

    return retbuf;
}

/*
 * Set the current user to 'identifier'.  'cacheid', if non-null,
 * points to a 16-byte binary key to cache identifier's information
 * with.
 */
static struct auth_state *mynewstate(const char *identifier)
{
    struct auth_state *newstate;

    identifier = auth_canonifyid(identifier, 0);
    if (!identifier) return 0;

    newstate = (struct auth_state *)xmalloc(sizeof(struct auth_state));

    strcpy(newstate->userid, identifier);
    newstate->aname[0] = newstate->inst[0] = newstate->realm[0] = '\0';
    kname_parse(newstate->aname, newstate->inst, newstate->realm, (char *) identifier);

    return newstate;
}

static void myfreestate(struct auth_state *auth_state)
{
    free((char *)auth_state);
}

static char *make_krb_wildcard(const char *aname, const char *inst, const char *realm)
{
    return strconcat(
        (aname ? aname : "*"),
        ".",
        (inst ? inst : "*"),
        "@",
        (realm ? realm : "*"),
        NULL
    );
}

/* KRB4 groups are just principals with wildcarded components.
 * XXX This hasn't even been so much as compile-tested for lack of
 * a kerberos test environment!  If you use this, please provide
 * feedback.
 */
static strarray_t *mygroups(const struct auth_state *auth_state)
{
    strarray_t *sa = strarray_new();
    char *tmp = NULL;

    /* *.*@* */
    tmp = make_krb_wildcard(NULL, NULL, NULL);
    strarray_appendm(sa, tmp);

    /* *.*@realm */
    if (auth_state->realm) {
        tmp = make_krb_wildcard(NULL, NULL, auth_state->realm);
        strarray_appendm(sa, tmp);
    }

    /* *.inst@* */
    if (auth_state->inst) {
        tmp = make_krb_wildcard(NULL, auth_state->inst, NULL);
        strarray_appendm(sa, tmp);
        if (auth_state->realm) {
            tmp = make_krb_wildcard(NULL, auth_state->inst, auth_state->realm);
            strarray_appendm(sa, tmp);
        }
    }

    /* aname.*@* */
    if (auth_state->aname) {
        tmp = make_krb_wildcard(auth_state->aname, NULL, NULL);
        strarray_appendm(sa, tmp);
        if (auth_state->realm) {
            tmp = make_krb_wildcard(auth_state->aname, NULL, auth_state->realm);
            strarray_appendm(sa, tmp);
        }
        if (auth_state->inst) {
            tmp = make_krb_wildcard(auth_state->aname, auth_state->inst, NULL);
            strarray_appendm(sa, tmp);
        }
        /* n.b. non-wildcard "aname.inst@realm" is NOT a group! */
    }

    return sa;
}

#else /* HAVE_KRB */

static int mymemberof(
    const struct auth_state *auth_state __attribute__((unused)),
    const char *identifier __attribute__((unused)))
{
        fatal("Authentication mechanism (krb) not compiled in", EX_CONFIG);
}

static const char *mycanonifyid(
    const char *identifier __attribute__((unused)),
    size_t len __attribute__((unused)))
{
        fatal("Authentication mechanism (krb) not compiled in", EX_CONFIG);
        return NULL;
}

static struct auth_state *mynewstate(
    const char *identifier __attribute__((unused)))
{
        fatal("Authentication mechanism (krb) not compiled in", EX_CONFIG);
        return NULL;
}

static void myfreestate(
    struct auth_state *auth_state __attribute__((unused)))
{
        fatal("Authentication mechanism (krb) not compiled in", EX_CONFIG);
}

static strarray_t *mygroups(
    const struct auth_state *auth_state __attribute__((unused)))
{
        fatal("Authentication mechanism (krb) not compiled in", EX_CONFIG);
}

#endif

HIDDEN struct auth_mech auth_krb =
{
    "krb",              /* name */

    &mycanonifyid,
    &mymemberof,
    &mynewstate,
    &myfreestate,
    &mygroups,
};
