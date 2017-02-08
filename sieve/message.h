/* message.h
 * Larry Greenfield
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
    ACTION_DENOTIFY
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
    const char **options;
    const char *priority;
    const char *message;
    struct notify_list_s *next;
} notify_list_t;

notify_list_t *new_notify_list(void);
void free_notify_list(notify_list_t *n);

/* actions; return negative on failure.
 * these don't actually perform the actions, they just add it to the
 * action list */
int do_reject(action_list_t *m, int action, const char *msg);
int do_fileinto(action_list_t *m, const char *mbox, int cancel_keep, int do_create,
                strarray_t *imapflags);
int do_redirect(action_list_t *m, const char *addr,
                int is_ext_list, int cancel_keep);
int do_keep(action_list_t *m, int cancel_keep, strarray_t *imapflags);
int do_discard(action_list_t *m);
int do_vacation(action_list_t *m, char *addr, char *fromaddr,
                char *subj, const char *msg, int seconds, int mime,
                const char *handle);
int do_setflag(action_list_t *m);
int do_addflag(action_list_t *m, const char *flag);
int do_removeflag(action_list_t *m, const char *flag);
int do_mark(action_list_t *m);
int do_unmark(action_list_t *m);
int do_notify(notify_list_t *n, const char *id, const char *from,
              const char *method, const char **options,
              const char *priority, const char *message);
int do_denotify(notify_list_t *n, comparator_t *comp, const void *pat,
                strarray_t *match_vars, void *comprock, const char *priority);


#endif
