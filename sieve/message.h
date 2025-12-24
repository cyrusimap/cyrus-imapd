/* message.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MESSAGE_H
#define MESSAGE_H

#include "sieve_interface.h"    /* for action contexts */
#include "tree.h"

typedef struct Action action_list_t;

typedef enum {
    ACTION_NULL = -1,
    ACTION_NONE = 0,
    ACTION_REJECT,
    ACTION_EREJECT,
    ACTION_FILEINTO,
    ACTION_SNOOZE,
    ACTION_KEEP,
    ACTION_REDIRECT,
    ACTION_DISCARD,
    ACTION_VACATION,
    ACTION_SETFLAG,
    ACTION_ADDFLAG,
    ACTION_REMOVEFLAG,
    ACTION_MARK,
    ACTION_UNMARK,
    ACTION_ENOTIFY,
    ACTION_NOTIFY,
    ACTION_DENOTIFY,
} action_t;

/* information */
action_list_t *new_action_list(void);
void free_action_list(action_list_t *actions);

/* invariant: always have a dummy element when free_action_list, param
   and vac_subj are freed.  none of the others are automatically freed.

   the do_action() functions should copy param */
struct Action {
    action_t a;
    int cancel_keep;
    union {
        sieve_reject_context_t rej;
        sieve_snooze_context_t snz;
        sieve_fileinto_context_t fil;
        sieve_keep_context_t keep;
        sieve_redirect_context_t red;
        struct {
            /* addr, fromaddr, subj - freed! */
            sieve_send_response_context_t send;
            sieve_autorespond_context_t autoresp;
        } vac;
        struct {
            const char *flag;
        } fla;
    } u;
    char *param;                /* freed! */
    struct Action *next;
    char *vac_subj;             /* freed! */
    char *vac_msg;
    int vac_days;
};

typedef struct notify_list_s {
    int isactive;
    const char *id;
    const char *from;
    const char *method;
    strarray_t *options;
    const char *priority;
    const char *message;
    struct notify_list_s *next;
} notify_list_t;

notify_list_t *new_notify_list(void);
void free_notify_list(notify_list_t *n);

typedef struct duptrack_list_s {
    char *id;
    int seconds;
    struct duptrack_list_s *next;
} duptrack_list_t;

duptrack_list_t *new_duptrack_list(void);
void free_duptrack_list(duptrack_list_t *d);

#define IMPLICIT_KEEP   (1<<0)
#define CANCEL_KEEP     (1<<1)
#define CREATE_MAILBOX  (1<<2)

/* actions; return negative on failure.
 * these don't actually perform the actions, they just add it to the
 * action list */
int do_reject(action_list_t *m, int action, const char *msg);
int do_fileinto(sieve_interp_t *i, void *sc,
                action_list_t *a, const char *mbox, const char *specialuse,
                unsigned flags, const char *mailboxid,
                strarray_t *imapflags, struct buf *headers);
int do_redirect(action_list_t *a, const char *addr, char *deliverby,
                const char *dsn_notify, const char *dsn_ret,
                int is_ext_list, int cancel_keep, struct buf *headers);
int do_keep(sieve_interp_t *i, void *sc, unsigned flags,
            action_list_t *m, strarray_t *imapflags, struct buf *headers);
int do_discard(action_list_t *m);
int do_vacation(action_list_t *m, char *addr, char *fromaddr, char *subj,
                const char *msg, int seconds, int mime, const char *handle,
                const sieve_fileinto_context_t *fcc);
int do_setflag(action_list_t *m);
int do_addflag(action_list_t *m, const char *flag);
int do_removeflag(action_list_t *m, const char *flag);
int do_mark(action_list_t *m);
int do_unmark(action_list_t *m);
int do_notify(notify_list_t *n, const char *id, const char *from,
              const char *method, strarray_t *options,
              const char *priority, const char *message);
int do_denotify(notify_list_t *n, comparator_t *comp, const void *pat,
                strarray_t *match_vars, void *comprock, const char *priority);
int do_duptrack(duptrack_list_t *d, sieve_duplicate_context_t *dc);
int do_snooze(action_list_t *a, const char *awaken_mbox, const char *awaken_mboxid,
              const char *awaken_spluse, int do_create,
              strarray_t *addflags, strarray_t *removeflags, const char *tzid,
              unsigned char days, arrayu64_t *times,
              strarray_t *imapflags, struct buf *headers);

#endif
