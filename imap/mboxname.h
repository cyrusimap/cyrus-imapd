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
 */

#ifndef INCLUDED_MBOXNAME_H
#define INCLUDED_MBOXNAME_H

#include "auth.h"
#include "strarray.h"
#include "util.h"

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
    int accessible[3];
};

#define NAMESPACE_INITIALIZER { '.', 0, 0, \
                                { "INBOX.", "user.", "" }, \
                                { 0, 0, 0, } }

struct mboxlock {
    char *name;
    int lock_fd;
    int locktype;       /* LOCK_NONE or LOCK_SHARED or LOCK_EXCLUSIVE */
};

struct mbname_parts;

typedef struct mbname_parts mbname_t;

const char *mbname_userid(const mbname_t *mbname);
const char *mbname_intname(const mbname_t *mbname);
const char *mbname_extname(const mbname_t *mbname, const struct namespace *ns, const char *userid);
const char *mbname_domain(const mbname_t *mbname);
const char *mbname_localpart(const mbname_t *mbname);
const strarray_t *mbname_boxes(const mbname_t *mbname);
time_t mbname_isdeleted(const mbname_t *mbname);

mbname_t *mbname_from_userid(const char *userid);
mbname_t *mbname_from_localdom(const char *localpart, const char *domain);
mbname_t *mbname_from_intname(const char *intname);
mbname_t *mbname_from_extname(const char *extname, const struct namespace *ns, const char *userid);

void mbname_set_localpart(mbname_t *mbname, const char *localpart);
void mbname_set_domain(mbname_t *mbname, const char *domain);
void mbname_set_isdeleted(mbname_t *mbname, time_t del);
void mbname_push_boxes(mbname_t *mbname, const char *item);
char *mbname_pop_box(mbname_t *mbname); /* free it yourself punk */
void mbname_truncate_boxes(mbname_t *mbname, size_t len);
void mbname_free(mbname_t **mbnamep);

char *mboxname_from_external(const char *extname, const struct namespace *ns, const char *userid);
char *mboxname_to_external(const char *intname, const struct namespace *ns, const char *userid);


int mboxname_lock(const char *mboxname, struct mboxlock **mboxlockptr,
                  int locktype);
void mboxname_release(struct mboxlock **mboxlockptr);

/* Create namespace based on config options. */
int mboxname_init_namespace(struct namespace *namespace, int isadmin);

struct namespace *mboxname_get_adminnamespace();

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
 * If (internal) mailbox 'name' is in the DELETED namespace.
 * If timestampp is not NULL, the delete timestamp encoded in
 * the name is parsed and filled in.
 * returns boolean
 */
int mboxname_isdeletedmailbox(const char *name, time_t *timestampp);

/*
 * If (internal) mailbox 'name' is a CALENDAR mailbox
 * returns boolean
 */
int mboxname_iscalendarmailbox(const char *name, int mbtype);

/*
 * If (internal) mailbox 'name' is a ADDRESSBOOK mailbox
 * returns boolean
 */
int mboxname_isaddressbookmailbox(const char *name, int mbtype);

/* If (internal) mailbox is a user's top-level Notes mailbox,
 * returns boolean
 */
int mboxname_isnotesmailbox(const char *name, int mbtype);

/* check if one mboxname is a parent or same as the other */
int mboxname_is_prefix(const char *longstr, const char *shortstr);

void mboxname_hash(char *buf, size_t buf_len,
                   const char *root,
                   const char *name) ;

/*
 * Translate (internal) inboxname into corresponding userid,
 * and vice-versa.
 */
/* returns a malloc'd mailbox */
char *mboxname_to_userid(const char *mboxname);
char *mboxname_user_mbox(const char *userid, const char *subfolder);
char *mboxname_abook(const char *userid, const char *collection);
char *mboxname_cal(const char *userid, const char *collection);

/*
 * Check whether two mboxnames have the same userid.
 */
int mbname_same_userid(const mbname_t *a, const mbname_t *b);
int mboxname_same_userid(const char *mboxname1, const char *mboxname2);


/*
 * Access files (or directories by leaving last parameter
 * zero) for a particular mailbox on partition.
 */
char *mboxname_datapath(const char *partition,
                        const char *mboxname,
                        const char *uniqueid,
                        unsigned long uid);

char *mboxname_archivepath(const char *partition,
                           const char *mboxname,
                           const char *uniqueid,
                           unsigned long uid);

char *mboxname_metapath(const char *partition,
                        const char *mboxname,
                        const char *uniqueid,
                        int metafile, int isnew);

char *mboxname_lockpath(const char *mboxname);
char *mboxname_lockpath_suffix(const char *mboxname, const char *suffix);

/*
 * Return nonzero if (internal) mailbox 'name' consists of legal characters.
 * If using the unixhierarchysep '/', DOTCHAR ('.' placeholder) is allowed.
 */
int mboxname_policycheck(const char *name);

void mboxname_todeleted(const char *name, char *result, int withtime);

/*
 * Given a writable buffer containing an internal mbox name,
 * convert that buffer in-place to be the name of the mbox'
 * parent (by truncating off the last component).
 * Returns 0 if no more truncation is possible, 1 otherwise.
 */
int mboxname_make_parent(char *namebuf);

char *mboxname_conf_getpath(const mbname_t *mbname,
                            const char *suffix);

/* ======================== COUNTERS ==================== */

struct mboxname_counters {
    uint32_t generation;
    uint32_t version;
    modseq_t highestmodseq;
    modseq_t mailmodseq;
    modseq_t caldavmodseq;
    modseq_t carddavmodseq;
    modseq_t notesmodseq;
    uint32_t uidvalidity;
};

int mboxname_read_counters(const char *mboxname, struct mboxname_counters *vals);
modseq_t mboxname_readmodseq(const char *mboxname);
modseq_t mboxname_nextmodseq(const char *mboxname, modseq_t last, int mbtype);
modseq_t mboxname_setmodseq(const char *mboxname, modseq_t val, int mbtype);
uint32_t mboxname_readuidvalidity(const char *mboxname);
uint32_t mboxname_nextuidvalidity(const char *mboxname, uint32_t last, int mbtype);
uint32_t mboxname_setuidvalidity(const char *mboxname, uint32_t val, int mbtype);

#endif
