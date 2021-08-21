/* annotate.h -- Annotation manipulation routines
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

#ifndef ANNOTATE_H
#define ANNOTATE_H

#include "auth.h"
#include "charset.h" /* for comp_pat */
#include "imapd.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "util.h"
#include "strarray.h"

#define FNAME_GLOBALANNOTATIONS "/annotations.db"

#define IMAP_ANNOT_NS           "/vendor/cmu/cyrus-imapd/"
#define DAV_ANNOT_NS            "/vendor/cmu/cyrus-httpd/"

/* List of strings, for fetch and search argument blocks */
struct strlist {
    char *s;                   /* String */
    struct strlist *next;
};

typedef struct annotate_db annotate_db_t;

/* List of attrib-value pairs */
struct attvaluelist {
    char *attrib;
    struct buf value;
    struct attvaluelist *next;
};

/* entry-attribute(s) struct */
struct entryattlist {
    char *entry;
    struct attvaluelist *attvalues;
    struct entryattlist *next;
};

#define ANNOTATE_FLAG_DELETED (1<<0)

struct annotate_metadata
{
    modseq_t modseq;
    unsigned char flags; /* read-only */
};

typedef struct annotate_state annotate_state_t;

annotate_state_t *annotate_state_new(void);
/* either of these close */
void annotate_state_abort(annotate_state_t **statep);
int annotate_state_commit(annotate_state_t **statep);
void annotate_state_begin(annotate_state_t *state);
void annotate_state_set_auth(annotate_state_t *state,
                             int isadmin, const char *userid,
                             const struct auth_state *auth_state);
int annotate_state_set_server(annotate_state_t *state);
int annotate_state_set_mailbox(annotate_state_t *state,
                               struct mailbox *mailbox);
int annotate_state_set_mailbox_mbe(annotate_state_t *state,
                                   const mbentry_t *);
int annotate_state_set_message(annotate_state_t *state,
                               struct mailbox *mailbox,
                               unsigned int uid);

/* String List Management */
void appendstrlist(struct strlist **l, char *s);
void freestrlist(struct strlist *l);

/* Attribute Management (also used by ID) */
void appendattvalue(struct attvaluelist **l, const char *attrib,
                    const struct buf *value);
void dupattvalues(struct attvaluelist **dst,
                  const struct attvaluelist *src);
void freeattvalues(struct attvaluelist *l);

/* Entry Management */
void appendentryatt(struct entryattlist **l, const char *entry,
                    struct attvaluelist *attvalues);
void setentryatt(struct entryattlist **l, const char *entry,
                 const char *attrib, const struct buf *value);
void clearentryatt(struct entryattlist **l, const char *entry,
                   const char *attrib);
void dupentryatt(struct entryattlist **l,
                 const struct entryattlist *);
size_t sizeentryatts(const struct entryattlist *);
char *dumpentryatt(const struct entryattlist *l);
void freeentryatts(struct entryattlist *l);

/* initialize database structures */
void annotate_init(
                       int (*fetch_func)(const char *, const char *,
                                         const strarray_t *, const strarray_t *),
                       int (*store_func)(const char *, const char *,
                                         struct entryattlist *));

/* open the annotation db */
void annotatemore_open(void);

typedef int (*annotatemore_find_proc_t)(const char *mailbox,
                    uint32_t uid,
                    const char *entry, const char *userid,
                    const struct buf *value,
                    const struct annotate_metadata *mdata,
                    void *rock);

/* For findall(), matches any non-zero uid */
#define ANNOTATE_ANY_UID    ((unsigned int)~0)

/* For findall() matches also tombstones */
#define ANNOTATE_TOMBSTONES  (1<<0)

/* 'proc'ess all annotations matching 'mailbox' and 'entry'.
 * if 'mailbox' is NULL, then 'pattern' is a pattern for
 * mboxlist_findall and will return all matching entries.. */
EXPORTED int annotatemore_findall_mailbox(const struct mailbox *mailbox,
                         uint32_t uid, const char *entry,
                         modseq_t since_modseq,
                         annotatemore_find_proc_t proc, void *rock,
                         int flags);
EXPORTED int annotatemore_findall_pattern(const char *pattern,
                         uint32_t uid, const char *entry,
                         modseq_t since_modseq,
                         annotatemore_find_proc_t proc, void *rock,
                         int flags);

/* fetch annotations and output results */
typedef void (*annotate_fetch_cb_t)(const char *mboxname, /* internal */
                                    uint32_t uid,
                                    const char *entry,
                                    struct attvaluelist *,
                                    void *rock);
int annotate_state_fetch(annotate_state_t *state,
                         const strarray_t *entries, const strarray_t *attribs,
                         annotate_fetch_cb_t callback, void *rock);

/* write a single annotation, avoiding all ACL checks and etc */
int annotatemore_write(const char *mboxname, const char *entry,
                       const char *userid, const struct buf *value);
/* same but write to shared if the user own the mailbox */
int annotatemore_writemask(const char *mboxname, const char *entry,
                           const char *userid, const struct buf *value);
/* flat out ignore modseq and quota and everything */
int annotatemore_rawwrite(const char *mboxname, const char *entry,
                       const char *userid, const struct buf *value);


/* lookup a single annotation and return result */
int annotatemore_lookup(const char *mboxname, const char *entry,
                        const char *userid, struct buf *value);
/* same but check shared if per-user doesn't exist */
int annotatemore_lookupmask(const char *mboxname, const char *entry,
                            const char *userid, struct buf *value);
/* lookup a single per-message annotation and return result */
int annotatemore_msg_lookup(const struct mailbox *mailbox,
                            uint32_t uid, const char *entry,
                            const char *userid, struct buf *value);
int annotatemore_lookup_mbe(const mbentry_t *mbentry, const char *entry,
                            const char *userid, struct buf *value);
int annotatemore_lookup_mbox(const struct mailbox *mailbox, const char *entry,
                             const char *userid, struct buf *value);
/* same but check shared if per-user doesn't exist */
int annotatemore_msg_lookupmask(const struct mailbox *mailbox,
                                uint32_t uid, const char *entry,
                                const char *userid, struct buf *value);
int annotatemore_lookupmask_mbe(const mbentry_t *mbentry, const char *entry,
                                const char *userid, struct buf *value);
int annotatemore_lookupmask_mbox(const struct mailbox *mailbox,
                                 const char *entry,
                                 const char *userid, struct buf *value);

/* store annotations.  Requires an open transaction */
int annotate_state_store(annotate_state_t *state, struct entryattlist *l);

/* low-level interface for use by mbdump routines.
 * Requires an open transaction. */
int annotate_state_write(annotate_state_t *, const char *entry,
                         const char *userid, const struct buf *value);
/* same but write to shared if the user owns the mailbox */
int annotate_state_writemask(annotate_state_t *, const char *entry,
                             const char *userid, const struct buf *value);
/* same but call mailbox_annot_changed with the silent flag set */
int annotate_state_writesilent(annotate_state_t *, const char *entry,
                               const char *userid, const struct buf *value);
/* same but set annotation metadata (flags field is ignored) */
int annotate_state_writemdata(annotate_state_t *state, const char *entry,
                              const char *userid, const struct buf *value,
                              const struct annotate_metadata *mdata);

/* rename the annotations for 'oldmboxname' to 'newmboxname'
 * if 'olduserid' is non-NULL then the private annotations
 * for 'olduserid' are renamed to 'newuserid'
 * Uses its own transaction.
 */
int annotate_rename_mailbox(struct mailbox *oldmailbox,
                            struct mailbox *newmailbox);
/* Handle a message COPY, by copying all the appropriate
 * per-message annotations. */
int annotate_msg_copy(struct mailbox *oldmailbox, uint32_t olduid,
                      struct mailbox *newmailbox, uint32_t newuid,
                      const char *userid);
/* delete the annotations for the given message */
int annotate_msg_cleanup(struct mailbox *mailbox, uint32_t uid);

/* delete the annotations for 'mailbox'
 * Uses its own transaction. */
int annotate_delete_mailbox(struct mailbox *mailbox);

/*
 * Annotation DB transactions used to be opened and closed explicitly.
 * Now they're opened whenever they're needed as a side effect of
 * calling an API function which needs to modify the database.  Closing
 * the transaction, however, is now a lot more complicated:
 *
 * scope   | to commit                  | to abort
 * --------+----------------------------+----------------------------
 * global  | annotate_state_commit()    | annotate_state_abort()
 *         |                            |
 * mailbox | annotate_state_commit()    | annotate_state_abort()
 *         |                            |
 * message | mailbox_unlock() or        | annotate_state_abort(
 *         | mailbox_commit()           |     &mailbox->annot_state)
 * --------+----------------------------+----------------------------
 */

/* close the database */
void annotatemore_close(void);

/* done with database stuff */
void annotate_done(void);

/* These APIs allow calling code to hold an extra reference to a
 * per-message database for an extended period of time, which can be a
 * useful performance optimisation when doing lots of annotate
 * operations that might otherwise spend a lot of time opening and
 * closing databases. Also, if annotate_getdb() does not returns zero
 * (success) then calling code can assume there are no per-message
 * annotations at all on the mailbox. These APIs are for performance
 * optimisations only; the other annotate APIs will manage their own
 * references internally. */
int annotate_getdb(const struct mailbox *mailbox, annotate_db_t **dbp);
void annotate_putdb(annotate_db_t **dbp);

/* Maybe this isn't the right place - move later */
int specialuse_validate(const char *mboxname, const char *userid,
                        const char *src, struct buf *dest, int allow_dups);

int annotatemore_upgrade(void);

#endif /* ANNOTATE_H */
