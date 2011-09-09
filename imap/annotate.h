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
 *
 * $Id: annotate.h,v 1.13 2010/01/06 17:01:30 murch Exp $
 */

#ifndef ANNOTATE_H
#define ANNOTATE_H

#include "charset.h" /* for comp_pat */
#include "imapd.h"
#include "mailbox.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "prot.h"
#include "util.h"
#include "strarray.h"

#define FNAME_GLOBALANNOTATIONS "/annotations.db"

/* List of strings, for fetch and search argument blocks */
struct strlist {
    char *s;                   /* String */
    comp_pat *p;               /* Compiled pattern, for search */
    struct strlist *next;
};

typedef struct annotate_db annotate_db_t;
struct annotate_db
{
    annotate_db_t *next;
    int refcount;
    char *mboxname;
    char *filename;
    struct db *db;
    struct txn *txn;
};


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

typedef struct annotate_state annotate_state_t;

annotate_state_t *annotate_state_new(void);
void annotate_state_free(annotate_state_t **statep);
void annotate_state_set_auth(annotate_state_t *state,
			     struct namespace *namespace,
		             int isadmin, const char *userid,
		             struct auth_state *auth_state);
void annotate_state_set_server(annotate_state_t *state);
void annotate_state_set_mailbox(annotate_state_t *state,
				const char *mboxpatt);
void annotate_state_set_message(annotate_state_t *state,
				struct mailbox *mailbox,
				unsigned int uid);

/* String List Management */
void appendstrlist(struct strlist **l, char *s);
void appendstrlistpat(struct strlist **l, char *s);
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
void freeentryatts(struct entryattlist *l);

/* initialize database structures */
void annotatemore_init(
		       int (*fetch_func)(const char *, const char *,
					 const strarray_t *, const strarray_t *),
		       int (*store_func)(const char *, const char *,
					 struct entryattlist *));

/* open the annotation db */
void annotatemore_open(void);

typedef int (*annotatemore_find_proc_t)(const char *mailbox,
		    uint32_t uid,
		    const char *entry, const char *userid,
		    const struct buf *value, void *rock);

/* 'proc'ess all annotations matching 'mailbox' and 'entry' */
int annotatemore_findall(const char *mailbox, uint32_t uid, const char *entry,
			 annotatemore_find_proc_t proc, void *rock);

/* fetch annotations and output results */
typedef void (*annotate_fetch_cb_t)(const char *mboxname,
				    uint32_t uid,
				    const char *entry,
				    struct attvaluelist *,
				    void *rock);
int annotate_state_fetch(annotate_state_t *state,
		         const strarray_t *entries, const strarray_t *attribs,
		         annotate_fetch_cb_t callback, void *rock,
		         int *maxsizeptr);

/* lookup a single annotation and return result */
int annotatemore_lookup(const char *mboxname, const char *entry,
			const char *userid, struct buf *value);
/* lookup a single per-message annotation and return result */
int annotatemore_msg_lookup(const char *mboxname, uint32_t uid, const char *entry,
			    const char *userid, struct buf *value);

/* store annotations.  Requires an open transaction */
int annotate_state_store(annotate_state_t *state, struct entryattlist *l);

/* low-level interface for use by mbdump routines.
 * Requires an open transaction. */
int annotate_state_write(annotate_state_t *, const char *entry,
			 const char *userid, const struct buf *value);

/* rename the annotations for 'oldmboxname' to 'newmboxname'
 * if 'olduserid' is non-NULL then the private annotations
 * for 'olduserid' are renamed to 'newuserid'
 * Uses its own transaction.
 */
int annotatemore_rename(const char *oldmboxname, const char *newmboxname,
			const char *olduserid, const char *newuserid);
/* Handle a message COPY, by copying all the appropriate
 * per-message annotations. Requires an open transaction. */
int annotate_msg_copy(const char *oldmboxname, uint32_t olduid,
		      const char *newmboxname, uint32_t newuid,
		      const char *userid);

/* delete the annotations for 'mbentry'
 * Uses its own transaction. */
int annotatemore_delete(const struct mboxlist_entry *mbentry);

/* Open a new transaction. Any currently open transaction
 * is aborted. */
int annotatemore_begin(void);
/* Abort the current transaction */
void annotatemore_abort(void);
/* Commit the current transaction */
int annotatemore_commit(void);

/* close the database */
void annotatemore_close(void);

/* done with database stuff */
void annotatemore_done(void);

/* per use DBs */
int annotate_getmailboxdb(const char *mboxname,
			  int dbflags,
			  annotate_db_t **dbp);
void annotate_putdb(annotate_db_t **dbp);

#endif /* ANNOTATE_H */
