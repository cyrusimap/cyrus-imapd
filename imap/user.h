/* user.h - User manipulation routines */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_USER_H
#define INCLUDED_USER_H

#include "auth.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "ptrarray.h"

#define FNAME_SUBSSUFFIX     "sub"
#define FNAME_COUNTERSSUFFIX "counters"

#define USER_COMPACT_EMAILIDS(cstate) \
    (cstate && cstate->version >= 2 && cstate->compact_emailids)

struct usernamespacelocks {
    ptrarray_t locks;   /* struct mboxlock *, in the order taken */
};

typedef struct usernamespacelocks user_nslock_t;

/* check if this user should be treated as being on a replica (for user moves,
 * or for actual replicas */
int user_isreplicaonly(const char *userid);

/* path to user's sieve directory */
const char *user_sieve_path(const char *user);

/* Delete meta-data (seen state, subscriptions, ACLs, quotaroots,
 * sieve scripts) for 'user'.
 *
 * wipe-user says to delete seen state also (remove the user from the murder)
 */
int user_deletedata(const mbentry_t *mbentry, int wipe_user);

/* Rename/copy user meta-data (seen state, subscriptions, sieve scripts)
 * from 'olduser' to 'newuser'.
 */
int user_renamedata(const char *olduser, const char *newuser);

/* Rename ACL for 'olduser' to 'newuser' on mailbox 'name'. */
int user_renameacl(const struct namespace *namespace, const char *name,
                   const char *olduser, const char *newuser);

/* Copy a quotaroot from mailbox 'oldname' to 'newname' */
int user_copyquotaroot(const char *oldname, const char *newname);

/* Delete all quotaroots for 'user' */
int user_deletequotaroots(const char *user);

/* find the subscriptions file for user */
char *user_hash_subs(const char *user);

/* find any sort of file for the user */
char *user_hash_meta(const char *userid, const char *suffix);

/* find xapian search dir for the user */
char *user_hash_xapian(const char *userid, const char *root);
char *user_hash_xapian_byname(const mbname_t *mbname, const char *root);
char *user_hash_xapian_byid(const char *mboxid, const char *root);

/* every user namespace lock name starts with this */
#define USER_NAMELOCK_PREFIX "*U*"

user_nslock_t *user_nslock_lock_full(const char *userid, int locktype,
                                     const char *caller);
#define user_nslock_lock(u, t) user_nslock_lock_full((u), (t), __func__)
user_nslock_t *user_nslock_lockdouble(const char *userid1, const char *userid2, int locktype);

/* lock all of these users at once, in a fixed order, so two overlapping calls
   can't deadlock.  Requires knowing the whole set before the first lock */
user_nslock_t *user_nslock_lockmulti(const strarray_t *userids, int locktype);
user_nslock_t *user_nslock_bymboxname_full(const char *mboxname1,
                                           const char *mboxname2,
                                           int locktype, const char *caller);
#define user_nslock_bymboxname(m1, m2, t) \
    user_nslock_bymboxname_full((m1), (m2), (t), __func__)
#define user_nslock_lock_w(u) user_nslock_lock(u, LOCK_EXCLUSIVE)
#define user_nslock_lockmb_w(m) user_nslock_bymboxname(m, NULL, LOCK_EXCLUSIVE)
void user_nslock_release(user_nslock_t **ptr);
int user_nslock_islocked(const char *userid);
int user_nslock_islockedmb(const char *mboxname);

/* default to exclusive lock! */
/* NULL is a legit value for lock_full, so use a flag value instead */
int user_run_with_lock(const char *userid, int (*cb)(void *), void *rock);

int user_sharee_renameacls(const struct namespace *namespace,
                           const char *olduser, const char *newuser);

#endif
