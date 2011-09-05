/* quota.h -- Quota format definitions
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
 * $Id: quota.h,v 1.5 2010/01/06 17:01:39 murch Exp $
 */

#ifndef INCLUDED_QUOTA_H
#define INCLUDED_QUOTA_H

#include "cyrusdb.h"
#include <config.h>

#define FNAME_QUOTADB "/quotas.db"

/* Define the proper quota type, which is 64 bit and signed */
typedef long long int quota_t;
#define QUOTA_T_FMT      "%lld"
#define QUOTA_REPORT_FMT "%8llu"

extern struct db *qdb;

enum quota_resource {
    QUOTA_STORAGE	=0,
    QUOTA_ANNOTSTORAGE	=1,
#define QUOTA_NUMRESOURCES  (QUOTA_ANNOTSTORAGE+1)
};

struct quota {
    const char *root;

    /* Information in quota entry */
    quota_t useds[QUOTA_NUMRESOURCES];
    int limits[QUOTA_NUMRESOURCES];		/* in QUOTA_UNITS */
};

/* special value to indicate no limit applies */
#define QUOTA_UNLIMITED	    (-1)

extern const char * const quota_names[QUOTA_NUMRESOURCES];
extern const int quota_units[QUOTA_NUMRESOURCES];
int quota_name_to_resource(const char *str);

typedef int quotaproc_t(struct quota *quota, void *rock);

extern int quota_read(struct quota *quota, struct txn **tid, int wrlock);

extern int quota_check(const struct quota *quota,
		       enum quota_resource res, quota_t delta);
extern void quota_use(struct quota *quota,
		      enum quota_resource res, quota_t delta);

extern void quota_commit(struct txn **tid);

extern void quota_abort(struct txn **tid);

extern int quota_write(struct quota *quota, struct txn **tid);

extern int quota_update_used(const char *quotaroot, enum quota_resource, quota_t diff);

extern int quota_deleteroot(const char *quotaroot);

extern int quota_findroot(char *ret, size_t retlen, const char *name);

extern int quota_foreach(const char *prefix, quotaproc_t *proc, void *rock);

/* open the quotas db */
void quotadb_open(const char *fname);

/* close the database */
void quotadb_close(void);

/* initialize database structures */
#define QUOTADB_SYNC 0x02
void quotadb_init(int flags);

/* done with database stuff */
void quotadb_done(void);

#endif /* INCLUDED_QUOTA_H */
