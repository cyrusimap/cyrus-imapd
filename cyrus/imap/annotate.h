/* 
 * annotate.h -- Annotation manipulation routines
 *
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 * $Id: annotate.h,v 1.2.6.4 2002/11/15 21:46:55 rjs3 Exp $
 */

#ifndef ANNOTATE_H
#define ANNOTATE_H

#include "charset.h" /* for comp_pat */
#include "imapd.h"
#include "mboxname.h"
#include "prot.h"

/* List of strings, for fetch and search argument blocks */
struct strlist {
    char *s;                   /* String */
    comp_pat *p;               /* Compiled pattern, for search */
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
void annotatemore_init(int flags, int (*func)(const char *, const char *,
					      struct strlist *));

/* open the annotation db */
void annotatemore_open(char *name);

/* fetch annotations */
int annotatemore_fetch(struct strlist *entries, struct strlist *attribs,
		       struct namespace *namespace, int isadmin, char *userid,
		       struct auth_state *auth_state, struct protstream *pout);

/* store annotations */
int annotatemore_store(struct entryattlist *l, struct namespace *namespace,
		       int isadmin, char *userid,
		       struct auth_state *auth_state);

/* close the database */
void annotatemore_close(void);

/* done with database stuff */
void annotatemore_done(void);

#endif /* ANNOTATE_H */
