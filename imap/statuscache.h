/* statuscache.h -- Status caching routines
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

#ifndef STATUSCACHE_H
#define STATUSCACHE_H

#include "mailbox.h"
#include "mboxlist.h"

/* name of the statuscache database */
#define FNAME_STATUSCACHEDB "/statuscache.db"
#define STATUSCACHE_VERSION 10

/* fill a statuscache entry */
extern void status_fill_mbentry(const mbentry_t *mbentry, struct statusdata *sdata);
extern void status_fill_mailbox(struct mailbox *mailbox, struct statusdata *sdata);
extern void status_fill_seen(const char *userid, struct statusdata *sdata,
                             unsigned numrecent, unsigned numunseen);

/* lookup a single statuscache entry or open the mailbox and calculate it */
extern int status_lookup_mboxname(const char *mboxname, const char *userid,
                                  unsigned statusitems, struct statusdata *sdata);
extern int status_lookup_mbname(const mbname_t *mbname, const char *userid,
                                unsigned statusitems, struct statusdata *sdata);
extern int status_lookup_mbentry(const mbentry_t *mbentry, const char *userid,
                                 unsigned statusitems, struct statusdata *sdata);
extern int status_lookup_mailbox(struct mailbox *mailbox, const char *userid,
                                 unsigned statusitems, struct statusdata *sdata);

/* invalidate (delete) statuscache entry for the mailbox,
   optionally writing the data for one user in the same transaction */
extern int statuscache_invalidate(const char *mboxname,
                                  struct statusdata *sdata);

/* wipe all statuscache records for a prefix */
extern int statuscache_wipe_prefix(const char *prefix);
#endif /* STATUSCACHE_H */
