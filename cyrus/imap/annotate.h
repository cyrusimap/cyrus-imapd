/* 
 * annotate.h -- Annotation manipulation routines
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 * $Id: annotate.h,v 1.3 2003/02/13 20:15:23 rjs3 Exp $
 */

#ifndef ANNOTATE_H
#define ANNOTATE_H

#include "imapd.h"
#include "mboxname.h"

/* entry-attribute(s) struct */
struct entryattlist {
    char *entry;
    struct attvaluelist *attvalues;
    struct entryattlist *next;
};

void appendentryatt(struct entryattlist **l, char *entry,
		    struct attvaluelist *attvalues);
void freeentryatts(struct entryattlist *l);

/* name of the annotation database */
#define FNAME_ANNOTATIONS "/annotations.db"

/* initialize database structures */
#define ANNOTATE_RECOVER 0x01
#define ANNOTATE_SYNC 0x01
void annotatemore_init(int flags);

/* open the annotation db */
void annotatemore_open(char *name);

/* fetch annotations */
int annotatemore_fetch(struct strlist *entries, struct strlist *attribs,
		       struct namespace *namespace, int isadmin, char *userid,
		       struct auth_state *auth_state, struct entryattlist **l);

/* store annotations */
int annotatemore_store(struct entryattlist *l, struct namespace *namespace,
		       int isadmin, char *userid,
		       struct auth_state *auth_state);

/* close the database */
void annotatemore_close(void);

/* done with database stuff */
void annotatemore_done(void);

#endif /* ANNOTATE_H */
