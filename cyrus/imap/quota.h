/* quota.h -- Quota format definitions
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
 * $Id: quota.h,v 1.1.2.1 2004/01/27 23:13:50 ken3 Exp $
 */

#ifndef INCLUDED_QUOTA_H
#define INCLUDED_QUOTA_H

#include "cyrusdb.h"

#define FNAME_QUOTADB "/quotas.db"

#define QUOTA_UNITS (1024)

extern struct db *qdb;

struct quota {
    char *root;

    /* Information in quota entry */
    unsigned long used;
    int limit;			/* in QUOTA_UNITS */
};

extern int quota_read(struct quota *quota, struct txn **tid, int wrlock);

extern void quota_commit(struct txn **tid);

extern int quota_write(struct quota *quota, struct txn **tid);

extern int quota_delete(struct quota *quota, struct txn **tid);

extern int quota_findroot(char *ret, size_t retlen, const char *name);

/* open the quotas db */
void quotadb_open(char *name);

/* close the database */
void quotadb_close(void);

/* initialize database structures */
#define QUOTADB_SYNC 0x02
void quotadb_init(int flags);

/* done with database stuff */
void quotadb_done(void);

#endif /* INCLUDED_QUOTA_H */
