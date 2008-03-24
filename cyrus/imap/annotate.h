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
 * $Id: annotate.h,v 1.11 2008/03/24 17:09:16 murch Exp $
 */

#ifndef ANNOTATE_H
#define ANNOTATE_H

#include "charset.h" /* for comp_pat */
#include "imapd.h"
#include "mboxname.h"
#include "prot.h"
#include "cyrusdb.h"

/* List of strings, for fetch and search argument blocks */
struct strlist {
    char *s;                   /* String */
    comp_pat *p;               /* Compiled pattern, for search */
    void *rock;                /* Associated metadata */
    struct strlist *next;
};

/* List of attrib-value pairs */
struct attvaluelist {
    char *attrib;
    char *value;
    struct attvaluelist *next;
};

/* entry-attribute(s) struct */
struct entryattlist {
    char *entry;
    struct attvaluelist *attvalues;
    struct entryattlist *next;
};

/* String List Management */
void appendstrlist(struct strlist **l, char *s);
void appendstrlistpat(struct strlist **l, char *s);
void appendstrlist_withdata(struct strlist **l, char *s, void *d, size_t size);
void freestrlist(struct strlist *l);

/* Attribute Management (also used by ID) */
void appendattvalue(struct attvaluelist **l, char *attrib, const char *value);
void freeattvalues(struct attvaluelist *l);

/* Entry Management */
void appendentryatt(struct entryattlist **l, char *entry,
		    struct attvaluelist *attvalues);
void freeentryatts(struct entryattlist *l);

/* name of the annotation database */
#define FNAME_ANNOTATIONS "/annotations.db"

/* initialize database structures */
#define ANNOTATE_SYNC (1 << 1)
void annotatemore_init(int myflags,
		       int (*fetch_func)(const char *, const char *,
					 struct strlist *, struct strlist *),
		       int (*store_func)(const char *, const char *,
					 struct entryattlist *));

/* open the annotation db */
void annotatemore_open(char *name);

/* 'proc'ess all annotations matching 'mailbox' and 'entry' */
int annotatemore_findall(const char *mailbox, const char *entry,
			 int (*proc)(), void *rock, struct txn **tid);

/* fetch annotations and output results */
int annotatemore_fetch(char *mailbox,
		       struct strlist *entries, struct strlist *attribs,
		       struct namespace *namespace, int isadmin, char *userid,
		       struct auth_state *auth_state, struct protstream *pout);

struct annotation_data {
    const char *value;
    size_t size;
    time_t modifiedsince;
    const char *contenttype;
};

/* lookup a single annotation and return result */
int annotatemore_lookup(const char *mboxname, const char *entry,
			const char *userid, struct annotation_data *attrib);

/* store annotations */
int annotatemore_store(char *mailbox,
		       struct entryattlist *l, struct namespace *namespace,
		       int isadmin, char *userid,
		       struct auth_state *auth_state);

/* low-level interface for use by mbdump routines */
int annotatemore_write_entry(const char *mboxname, const char *entry,
			     const char *userid,
			     const char *value, const char *contenttype,
			     size_t size, time_t modifiedsince,
			     struct txn **tid);

/* rename the annotations for 'oldmboxname' to 'newmboxname'
 * if 'olduserid' is non-NULL then the private annotations
 * for 'olduserid' are renamed to 'newuserid'
 */
int annotatemore_rename(const char *oldmboxname, const char *newmboxname,
			const char *olduserid, const char *newuserid);

/* delete the annotations for 'mboxname' */
int annotatemore_delete(const char *mboxname);

/* close the database */
void annotatemore_close(void);

/* done with database stuff */
void annotatemore_done(void);

#endif /* ANNOTATE_H */
