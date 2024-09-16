/* seen.h -- abstract interface for /Recent and /Seen information
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

#ifndef SEEN_H
#define SEEN_H

struct seen;

#define FNAME_SEENSUFFIX "seen" /* per user seen state extension */

#define SEEN_CREATE 0x01
#define SEEN_SILENT 0x02

struct seendata {
    time_t lastread;
    uint32_t lastuid;
    time_t lastchange;
    char *seenuids;
};

#define SEENDATA_INITIALIZER {0, 0, 0, NULL}

typedef int seenproc_t(const char *uniqueid, struct seendata *sd,
                       void *rock);

void seen_freedata(struct seendata *data);

/* get a database handle corresponding to user pair */
int seen_open(const char *user,
              int flags,
              struct seen **seendbptr);

int seen_foreach(struct seen *db, seenproc_t *func, void *rock);

/* read an entry from 'seendb' */
int seen_read(struct seen *seendb, const char *uniqueid,
              struct seendata *data);

/* read an entry from 'seendb' and leave that record (or some superset
   of it) locked for update */
int seen_lockread(struct seen *seendb, const char *uniqueid,
                  struct seendata *data);

/* write an entry to 'seendb'; should have been already locked by
   seen_lockread() */
int seen_write(struct seen *seendb, const char *uniqueid,
               struct seendata *data);

/* close this handle */
int seen_close(struct seen **seendb);

/* called on mailbox operations */
int seen_create_mailbox(const char *userid, struct mailbox *mailbox);
int seen_delete_mailbox(const char *userid, struct mailbox *mailbox);
int seen_copy(const char *userid, struct mailbox *oldmailbox, struct mailbox *newmailbox);

/* called on user operations */
int seen_create_user(const char *user);
int seen_delete_user(const char *user);
int seen_rename_user(const char *olduser, const char *newuser);

/* done with all seen operations for this process */
int seen_done(void);

/* compare seendata = returns 1 if match */
int seen_compare(struct seendata *a, struct seendata *b);

/* merge another .seen file (same format) into
 * the current seendb */
int seen_merge(struct seen *seendb, const char *newfile);

char *seen_getpath(const char *userid);

#endif /* SEEN_LOCAL_H */
