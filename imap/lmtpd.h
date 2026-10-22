/* lmtpd.h - Program to deliver mail to a mailbox */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef LMTPD_H
#define LMTPD_H

#include "append.h"
#include "auth.h"
#include "lmtpengine.h"
#include "mboxname.h"
#include "message.h"
#include "jmap_mail_query.h"

/* data per message */
typedef struct deliver_data {
    message_data_t *m;
    struct message_content *content;

    int cur_rcpt;

    struct stagemsg *stage;     /* staging location for single instance
                                   store */
    char *notifyheader;
    const char *temp[2];        /* used to avoid extra indirection in
                                   getenvelope() */

    char *authuser;             /* user who submitted message */
    const struct namespace *ns;
    const struct auth_state *authstate;
} deliver_data_t;

struct imap4flags {
    const strarray_t *flags;
    const struct auth_state *authstate;
};

/* forward declarations */
extern struct namespace lmtpd_namespace;

extern int fuzzy_match(mbname_t *mbname);

enum {
    ACTION_NO_SIEVE =   0,
    ACTION_SIEVE_ERROR,
    ACTION_IMPLICIT,
    ACTION_KEEP,
    ACTION_FILEINTO,
    ACTION_SNOOZE,
    TARGET_PLUS_ADDR =  (1<<4),
    TARGET_FUZZY =      (1<<5),
    TARGET_SET =        (1<<6),
};

#define ACTION_MASK  0xF

/**
 * Append a message to a mailbox.
 *
 * @param authuser   the identity the append is made as
 * @param authstate  the auth state checked against the mailbox's ACL
 * @param aclcheck   the ACL_* rights authstate must hold on mailboxname,
 *                   or 0 to skip the check
 * @return 0 on success (including a suppressed duplicate), or an IMAP_* error
 */
extern int deliver_mailbox(FILE *f,
                           struct message_content *content,
                           struct stagemsg *stage,
                           unsigned size,
                           struct imap4flags *imap4flags,
                           struct entryattlist *annotations,
                           const char *authuser,
                           const struct auth_state *authstate,
                           char *id,
                           const char *user,
                           char *notifyheader,
                           unsigned mode,
                           const char *mailboxname,
                           char *date,
                           time_t savedate,
                           int quotaoverride,
                           long aclcheck);

#endif /* LMTPD_H */
