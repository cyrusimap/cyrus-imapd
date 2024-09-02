/* mboxkey.h -- abstract interface for URLAUTH mailbox keys
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
