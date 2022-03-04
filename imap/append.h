/* append.h -- Description of messages to be copied
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

#ifndef INCLUDED_APPEND_H
#define INCLUDED_APPEND_H

#include "mailbox.h"
#include "mboxevent.h"
#include "message.h"
#include "prot.h"
#include "seqset.h"
#include "strarray.h"
#include "annotate.h"
#include "conversations.h"

/* it's ridiculous i have to expose this structure if i want to allow
   clients to stack-allocate it */
struct appendstate {
    /* mailbox we're appending to */
    struct mailbox *mailbox;
    /* do we own it? */
    int close_mailbox_when_done:1;
    int myrights;
    char userid[MAX_MAILBOX_BUFFER];

    enum { APPEND_READY, APPEND_DONE } s;
                                /* current state of append */

    int nummsg;    /* number of messages appended pending commit.
                      from as->baseuid ... m.baseuid + nummsg - 1 */
    unsigned baseuid;

    /* set seen on these message on commit */
    int internalseen;
    seqset_t *seen_seq;

    /* for annotations */
    const struct namespace *namespace;
    const struct auth_state *auth_state;
    int isadmin;

    /* one event notification to send per appended message */
    enum event_type event_type;
    struct mboxevent *mboxevents;
};

/* add helper function to determine uid range appended? */

struct stagemsg;

extern int append_check(const char *name,
                        struct auth_state *auth_state,
                        long aclcheck,
                        const quota_t quotacheck[QUOTA_NUMRESOURCES]);

/* appendstate must be allocated by client */
extern int append_setup(struct appendstate *as, const char *name,
                        const char *userid, const struct auth_state *auth_state,
                        long aclcheck,
                        const quota_t quotacheck[QUOTA_NUMRESOURCES],
                        const struct namespace *, int isadmin, enum event_type event_type);
extern int append_setup_mbox(struct appendstate *as, struct mailbox *mailbox,
                             const char *userid,
                             const struct auth_state *auth_state,
                             long aclcheck,
                             const quota_t quotacheck[QUOTA_NUMRESOURCES],
                             const struct namespace *namespace,
                             int isadmin, enum event_type event_type);

extern uint32_t append_uidvalidity(struct appendstate *as);

extern int append_commit(struct appendstate *as);
extern int append_abort(struct appendstate *as);

/* creates a new stage and returns stage file corresponding to mailboxname */
extern FILE *append_newstage_full(const char *mailboxname, time_t internaldate,
                                  int msgnum, struct stagemsg **stagep,
                                  const char *sourcefile);
#define append_newstage(m, i, n, s) append_newstage_full((m), (i), (n), (s), NULL)

/* adds a new mailbox to the stage initially created by append_newstage() */
extern int append_fromstage_full(struct appendstate *mailbox, struct body **body,
                                 struct stagemsg *stage,
                                 time_t internaldate, time_t savedate,
                                 modseq_t createdmodseq,
                                 const strarray_t *flags, int nolink,
                                 struct entryattlist **annotations);
#define append_fromstage(m, b, s, i, c, f, n, a) \
  append_fromstage_full((m), (b), (s), (i), 0, (c), (f), (n), (a))

/* removes the stage (frees memory, deletes the staging files) */
extern int append_removestage(struct stagemsg *stage);

extern int append_fromstream(struct appendstate *as, struct body **body,
                             struct protstream *messagefile,
                             unsigned long size, time_t internaldate,
                             const strarray_t *flags);

extern int append_copy(struct mailbox *mailbox,
                       struct appendstate *append_mailbox,
                       ptrarray_t *msgrecs,
                       int nolink, int is_same_user);

extern int append_collectnews(struct appendstate *mailbox,
                              const char *group, unsigned long feeduid);

#define append_getuidvalidity(as) ((as)->m.uidvalidity)
#define append_getlastuid(as) ((as)->m.last_uid)

extern int append_run_annotator(struct appendstate *as,
                                msgrecord_t *msgrec);

extern const char *append_stagefname(struct stagemsg *stage);

#endif /* INCLUDED_APPEND_H */
