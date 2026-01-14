/* statuscache.h - Status caching routines */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
