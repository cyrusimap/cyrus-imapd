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
 */

#ifndef INCLUDED_QUOTA_H
#define INCLUDED_QUOTA_H

#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#elif defined(HAVE_STDINT_H)
# include <stdint.h>
#endif

#include "cyrusdb.h"
#include "util.h"
#include <config.h>

#define FNAME_QUOTADB "/quotas.db"

/* Define the proper quota type, which is 64 bit and signed */
typedef long long int quota_t;
#define QUOTA_T_FMT "%lld"

enum quota_resource {
    QUOTA_STORAGE = 0,
    QUOTA_MESSAGE = 1,
    QUOTA_ANNOTSTORAGE = 2,
    QUOTA_NUMFOLDERS = 3,
#define QUOTA_NUMRESOURCES (QUOTA_NUMFOLDERS + 1)
};

#define QUOTA_DIFFS_INITIALIZER { 0, 0, 0, 0 }
#define QUOTA_DIFFS_DONTCARE_INITIALIZER { -1, -1, -1, -1 }

struct quota
{
    char *root;

    /* Information in quota entry */
    quota_t useds[QUOTA_NUMRESOURCES];
    quota_t limits[QUOTA_NUMRESOURCES]; /* in QUOTA_UNITS */

    /* information for scanning */
    char *scanmbox;
    quota_t scanuseds[QUOTA_NUMRESOURCES];

    /* inforation for changes */
    int dirty;
    modseq_t modseq;
};

/* special value to indicate no limit applies */
#define QUOTA_UNLIMITED (-1)

extern const char *const quota_names[QUOTA_NUMRESOURCES];
extern const char *const legacy_quota_names[QUOTA_NUMRESOURCES];
extern const quota_t quota_units[QUOTA_NUMRESOURCES];
int quota_name_to_resource(const char *str);

typedef int quotaproc_t(struct quota *quota, void *rock);

extern int quota_changelock(void);
extern void quota_changelockrelease(void);

extern void quota_init(struct quota *quota, const char *root);
extern void quota_free(struct quota *quota);

extern int quota_read_withconversations(struct quota *quota);
extern int quota_read(struct quota *quota, struct txn **tid, int wrlock);

extern int quota_check(const struct quota *quota,
                       enum quota_resource res,
                       quota_t delta);
extern void quota_use(struct quota *quota,
                      enum quota_resource res,
                      quota_t delta);

extern void quota_commit(struct txn **tid);

extern void quota_abort(struct txn **tid);

extern int quota_write(struct quota *quota, int silent, struct txn **tid);

extern int quota_update_useds(const char *quotaroot,
                              const quota_t diff[QUOTA_NUMRESOURCES],
                              const char *mboxname,
                              int silent);
extern int quota_check_useds(const char *quotaroot,
                             const quota_t diff[QUOTA_NUMRESOURCES]);

extern int quota_deleteroot(const char *quotaroot, int silent);

extern int quota_findroot(char *ret, size_t retlen, const char *name);

#define QUOTA_USE_CONV (1 << 0)

extern int quota_foreach(const char *prefix,
                         quotaproc_t *proc,
                         void *rock,
                         struct txn **,
                         unsigned flags);

/* open the quotas db */
void quotadb_open(const char *fname);

/* iterate all entries starting with prefix */
extern int quotadb_foreach(const char *prefix,
                           size_t prefixlen,
                           foreach_p *p,
                           foreach_cb *cb,
                           void *rock);

/* close the database */
void quotadb_close(void);

/* initialize database structures */
void quotadb_init(void);

/* done with database stuff */
void quotadb_done(void);

int quota_is_overquota(const struct quota *quota,
                       enum quota_resource res,
                       quota_t newquotas[QUOTA_NUMRESOURCES]);
#endif /* INCLUDED_QUOTA_H */
