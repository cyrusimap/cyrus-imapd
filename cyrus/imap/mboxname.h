/* mboxname.h -- Mailbox list manipulation routines
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
 * $Id: mboxname.h,v 1.17 2008/03/24 17:09:18 murch Exp $
 */

#ifndef INCLUDED_MBOXNAME_H
#define INCLUDED_MBOXNAME_H

#include "auth.h"

#define MAX_NAMESPACE_PREFIX 40

/* placeholder character for '.' in mailboxnames */
#define DOTCHAR '^'

/* list of our namespaces */
enum { NAMESPACE_INBOX = 0, 
       NAMESPACE_USER = 1, 
       NAMESPACE_SHARED = 2 };

/* structure holding server namespace info */
struct namespace {
    char hier_sep;
    int isalt;  /* are we using the alternate namespace? */
    int isadmin; /* current user is an admin */
    char prefix[3][MAX_NAMESPACE_PREFIX+1];
    /* Convert the external mailbox 'name' to an internal name. */
    int (*mboxname_tointernal)(struct namespace *namespace, const char *name,
			       const char *userid, char *result);
    /* Convert the internal mailbox 'name' to an external name. */
    int (*mboxname_toexternal)(struct namespace *namespace, const char *name,
			       const char *userid, char *result);
    int (*mboxlist_findall)(struct namespace *namespace,
			    const char *pattern, int isadmin, char *userid, 
			    struct auth_state *auth_state, int (*proc)(),
			    void *rock);
    int (*mboxlist_findsub)(struct namespace *namespace,
			    const char *pattern, int isadmin, char *userid, 
			    struct auth_state *auth_state, int (*proc)(),
			    void *rock, int force);
};

/* Create namespace based on config options. */
int mboxname_init_namespace(struct namespace *namespace, int isadmin);

/*
 * Translate separator charactors in a mailboxname from its external
 * representation to its internal representation '.'.
 * If using the unixhierarchysep '/', all '.'s get translated to DOTCHAR.
 * length is the length of the string to translate (0 = strlen(name)).
 */
char *mboxname_hiersep_tointernal(struct namespace *namespace, char *name,
				  int length);

/*
 * Translate separator charactors in a mailboxname from its internal
 * representation '.' to its external representation.
 * If using the unixhierarchysep '/', all DOTCHAR get translated to '.'.
 * length is the length of the string to translate (0 = strlen(name)).
 */
char *mboxname_hiersep_toexternal(struct namespace *namespace, char *name,
                                  int length);

/* Return nonzero if 'userid' owns the (internal) mailbox 'name'. */
int mboxname_userownsmailbox(const char *userid, const char *name);

/*
 * If (internal) mailbox 'name' is a user's mailbox (optionally INBOX),
 * returns a pointer to the userid, otherwise returns NULL.
 */
char *mboxname_isusermailbox(const char *name, int isinbox);

/*
 * If (internal) mailbox 'name' is in the DELETED namespace
 * returns boolean
 */
int mboxname_isdeletedmailbox(const char *name);

/*
 * Translate (internal) inboxname into corresponding userid.
 */
char *mboxname_inbox_touserid(const char *inboxname);

/*
 * Return nonzero if (internal) mailbox 'name' consists of legal characters.
 * If using the unixhierarchysep '/', DOTCHAR ('.' placeholder) is allowed.
 */
int mboxname_policycheck(char *name);

int mboxname_netnewscheck(char *name);

#endif
