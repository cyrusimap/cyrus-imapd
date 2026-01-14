/* auth_mboxgroups.c - Mailboxes.db groups authentication */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"
#include "libcyr_cfg.h"
#include "xmalloc.h"
#include "strarray.h"
#include "util.h"

static int (*our_mboxlookup)(const char *userid, strarray_t *sa);

struct auth_state {
    char userid[81];
    strarray_t groups;
};

static struct auth_state auth_anonymous = {
    "anonymous", STRARRAY_INITIALIZER
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
    if (!auth_state) auth_state = &auth_anonymous;

    if (strcmp(identifier, "anyone") == 0) return 1;

    if (strcmp(identifier, auth_state->userid) == 0) return 3;

    if (strarray_contains(&auth_state->groups, identifier)) return 2;

    return 0;
}

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
// clang-format: off
static const char allowedchars[256] = {
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
// clang-format: on

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
static const char *mycanonifyid(const char *identifier, size_t len)
{
    static char retbuf[81];
    char *p;
    int username_tolower = 0;

    if (!len) len = strlen(identifier);
    if (len >= sizeof(retbuf)) return NULL;

    memmove(retbuf, identifier, len);
    retbuf[len] = '\0';

    /* This used to be far more restrictive, but many sites seem to ignore the
     * ye olde Unix conventions of username.  Specifically, we used to
     * - drop case on the buffer
     * - disallow lots of non-alpha characters ('-', '_', others)
     * Now we do neither of these, but impose a very different policy based on
     * the character map above.
     */

    if (!strncmp(retbuf, "group:", 6)) {
        return retbuf;
    }

    /* Copy the string and look up values in the allowedchars array above.
     * If we see any we don't like, reject the string.
     * Lowercase usernames if requested.
     */
    username_tolower = libcyrus_config_getswitch(CYRUSOPT_USERNAME_TOLOWER);
    for (p = retbuf; *p; p++) {
        if (username_tolower && Uisupper(*p))
            *p = tolower((unsigned char)*p);

        switch (allowedchars[*(unsigned char*) p]) {
        case 0:
            return NULL;
        default:
            break;
        }
    }

    return retbuf;
}

/*
 * Set the current user to 'identifier' and loads any related groups.
 */
static struct auth_state *mynewstate(const char *identifier)
{
    struct auth_state *newstate;

    identifier = mycanonifyid(identifier, 0);
    if (!identifier) return NULL;

    newstate = (struct auth_state *)xzmalloc(sizeof(struct auth_state));

    strcpy(newstate->userid, identifier);
    strarray_init(&newstate->groups);

    if (our_mboxlookup) our_mboxlookup(identifier, &newstate->groups);

    return newstate;
}

static void myfreestate(struct auth_state *auth_state)
{
    strarray_fini(&auth_state->groups);
    free(auth_state);
}

static strarray_t *mygroups(const struct auth_state *auth_state)
{
    return strarray_dup(&auth_state->groups);
}

/* reloads groups */
static void myrefresh(struct auth_state *auth_state)
{
    if (!auth_state) return;
    strarray_truncate(&auth_state->groups, 0);
    if (our_mboxlookup) our_mboxlookup(auth_state->userid, &auth_state->groups);
}

EXPORTED void register_mboxgroups_cb(int (*l)(const char *, strarray_t *))
{
    our_mboxlookup = l;
}

HIDDEN struct auth_mech auth_mboxgroups =
{
    "mboxgroups",             /* name */

    &mycanonifyid,
    &mymemberof,
    &mynewstate,
    &myfreestate,
    &mygroups,
    &myrefresh,
};
