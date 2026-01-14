/* mboxkey.h - abstract interface for URLAUTH mailbox keys */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MBOXKEY_H
#define MBOXKEY_H

struct mboxkey;

#define FNAME_MBOXKEYSUFFIX "mboxkey" /* per user mailbox key extension */

#define MBOXKEY_CREATE 0x01

/* get a database handle corresponding to user pair */
int mboxkey_open(const char *user,
                 int flags,
                 struct mboxkey **mboxkeydbptr);

/* read an entry from 'mboxkeydb' */
int mboxkey_read(struct mboxkey *mboxkeydb, const char *mailbox,
                 const char **mboxkey, size_t *mboxkeylen);

/* read an entry from 'mboxkeydb' and leave that record (or some superset
   of it) locked for update */
int mboxkey_lockread(struct mboxkey *mboxkeydb, const char *mailbox,
                     const char **mboxkey, size_t *mboxkeylen);

/* write an entry to 'mboxkeydb' */
int mboxkey_write(struct mboxkey *mboxkeydb, const char *mailbox,
                  const char *mboxkey, size_t mboxkeylen);

/* close this handle */
int mboxkey_close(struct mboxkey *mboxkeydb);

/* discard lock on handle */
int mboxkey_unlock(struct mboxkey *mboxkeydb);

/* called on user operations */
int mboxkey_delete_user(const char *user);

/* done with all mboxkey operations for this process */
int mboxkey_done(void);

/* Return a path to the mboxkey database for the given user */
char *mboxkey_getpath(const char *userid);

/* Merge tmpfile into tgtfile */
int mboxkey_merge(const char *tmpfile, const char *tgtfile);

#endif /* MBOXKEY_H */
