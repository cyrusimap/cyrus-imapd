/* message.c -- message parsing functions
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "md5.h"
#include "sieve_interface.h"
#include "interp.h"
#include "message.h"
#include "xmalloc.h"
#include "util.h"

/* [e]reject message m with message msg
 *
 * incompatible with: fileinto, redirect
 */
int do_reject(action_list_t *a, int action, const char *msg)
{
    action_list_t *b = NULL;

    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
        b = a;
        if (a->a == ACTION_FILEINTO ||
            a->a == ACTION_KEEP ||
            a->a == ACTION_REDIRECT ||
            a->a == ACTION_REJECT ||
            a->a == ACTION_EREJECT ||
            a->a == ACTION_VACATION ||
            a->a == ACTION_SETFLAG ||
            a->a == ACTION_ADDFLAG ||
            a->a == ACTION_REMOVEFLAG ||
            a->a == ACTION_MARK ||
            a->a == ACTION_UNMARK
            )
            return SIEVE_RUN_ERROR;
        a = a->next;
    }

    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
        return SIEVE_NOMEM;
    a->a = action;
    a->cancel_keep = 1;
    a->u.rej.msg = msg;
    a->u.rej.is_extended = (action == ACTION_EREJECT);
    b->next = a;
    a->next =  NULL;
    return 0;
}

/* fileinto message m into mailbox
 *
 * incompatible with: [e]reject
 */
int do_fileinto(action_list_t *a, const char *mbox, int cancel_keep, int do_create,
                strarray_t *imapflags)
{
    action_list_t *b = NULL;

    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
        if (a->a == ACTION_REJECT || a->a == ACTION_EREJECT)
            return SIEVE_RUN_ERROR;
        if (a->a == ACTION_FILEINTO && !strcmp(a->u.fil.mailbox, mbox)) {
            /* don't bother doing it twice */
            /* check that we have a valid action */
            if (b == NULL) {
                return SIEVE_INTERNAL_ERROR;
            }
            /* cut this action out of the list */
            b->next = a->next;
            a->next = NULL;
            /* find the end of the list */
            while (b->next != NULL) {
                b = b-> next;
            }
            /* add the action to the end of the list */
            b->next = a;
            break;
        }
        b = a;
        a = a->next;
    }

    if (a == NULL) {
        /* add to the action list */
        a = new_action_list();
        if (a == NULL)
            return SIEVE_NOMEM;
        b->next = a;
    }
    a->a = ACTION_FILEINTO;
    a->cancel_keep |= cancel_keep;
    a->u.fil.mailbox = mbox;
    a->u.fil.imapflags = imapflags;
    a->u.fil.do_create = do_create;
    return 0;
}

/* redirect message m to to addr
 *
 * incompatible with: [e]reject
 */
int do_redirect(action_list_t *a, const char *addr, int cancel_keep)
{
    action_list_t *b = NULL;

    /* xxx we should validate addr */

    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
        b = a;
        if (a->a == ACTION_REJECT || a->a == ACTION_EREJECT)
            return SIEVE_RUN_ERROR;
        a = a->next;
    }

    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
        return SIEVE_NOMEM;
    a->a = ACTION_REDIRECT;
    a->cancel_keep = cancel_keep;
    a->u.red.addr = addr;
    a->next = NULL;
    b->next = a;
    return 0;
}

/* keep message
 *
 * incompatible with: [e]reject
 */
int do_keep(action_list_t *a, int cancel_keep, strarray_t *imapflags)
{
    action_list_t *b = NULL;

    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
        if (a->a == ACTION_REJECT || a->a == ACTION_EREJECT)
            return SIEVE_RUN_ERROR;
        if (a->a == ACTION_KEEP) {
            /* don't bother doing it twice */
            /* check that we have a valid action */
            if (b == NULL) {
                return SIEVE_INTERNAL_ERROR;
            }
            /* cut this action out of the list */
            b->next = a->next;
            a->next = NULL;
            /* find the end of the list */
            while (b->next != NULL) {
                b = b-> next;
            }
            /* add the action to the end of the list */
            b->next = a;
            break;
        }
        b = a;
        a = a->next;
    }

    if(a == NULL) {
        /* add to the action list */
        a = new_action_list();
        if (a == NULL)
            return SIEVE_NOMEM;
        a->next = NULL;
        b->next = a;
    }
    a->a = ACTION_KEEP;
    a->cancel_keep |= cancel_keep;
    a->u.keep.imapflags = imapflags;
    return 0;
}

/* discard message m
 *
 * incompatible with: nothing---it doesn't cancel any actions
 */
int do_discard(action_list_t *a)
{
    action_list_t *b = NULL;

    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
        b = a;
        if (a->a == ACTION_DISCARD) /* don't bother doing twice */
            return 0;
        a = a->next;
    }

    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
        return SIEVE_NOMEM;
    a->a = ACTION_DISCARD;
    a->cancel_keep = 1;
    a->next = NULL;
    b->next = a;
    return 0;
}

static int makehash(unsigned char hash[],
                    const char *s1, const char *s2, const char *s3)
{
    MD5_CTX ctx;

    MD5Init(&ctx);
    MD5Update(&ctx, s1, strlen(s1));
    MD5Update(&ctx, s2, strlen(s2));
    if (s3) MD5Update(&ctx, s3, strlen(s3));
    MD5Final(hash, &ctx);

    return SIEVE_OK;
}

int do_vacation(action_list_t *a, char *addr, char *fromaddr,
                char *subj, const char *msg, int seconds,
                int mime, const char *handle)
{
    action_list_t *b = NULL;

    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
        b = a;
        if (a->a == ACTION_REJECT || a->a == ACTION_EREJECT ||
            a->a == ACTION_VACATION) /* vacation can't be used twice */
            return SIEVE_RUN_ERROR;
        a = a->next;
    }

    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
        return SIEVE_NOMEM;
    a->a = ACTION_VACATION;
    a->cancel_keep = 0;
    a->u.vac.send.addr = addr;
    a->u.vac.send.fromaddr = fromaddr;
    a->u.vac.send.subj = subj;  /* user specified subject */
    a->u.vac.send.msg = msg;
    a->u.vac.send.mime = mime;
    if (handle)
        makehash(a->u.vac.autoresp.hash, addr, handle, NULL);
    else
        makehash(a->u.vac.autoresp.hash, addr, fromaddr, msg);
    a->u.vac.autoresp.seconds = seconds;
    a->next = NULL;
    b->next = a;
    return 0;
}

/* mark message m
 *
 * incompatible with: [e]reject
 */
int do_mark(action_list_t *a)
{
    action_list_t *b = NULL;

    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
        b = a;
        if (a->a == ACTION_REJECT || a->a == ACTION_EREJECT)
            return SIEVE_RUN_ERROR;
        a = a->next;
    }

    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
        return SIEVE_NOMEM;
    a->a = ACTION_MARK;
    a->cancel_keep = 0;
    b->next = a;
    a->next = NULL;
    return 0;
}


/* unmark message m
 *
 * incompatible with: [e]reject
 */
int do_unmark(action_list_t *a)
{

    action_list_t *b = NULL;
    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
        b = a;
        if (a->a == ACTION_REJECT || a->a == ACTION_EREJECT)
            return SIEVE_RUN_ERROR;
        a = a->next;
    }

    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
        return SIEVE_NOMEM;
    a->a = ACTION_UNMARK;
    a->cancel_keep = 0;
    b->next = a;
    a->next = NULL;
    return 0;
}

/* notify
 *
 * incompatible with: none
 */
int do_notify(notify_list_t *a, const char *id,
              const char *method, const char **options,
              const char *priority, const char *message)
{
    notify_list_t *b = NULL;

    /* find the end of the notify list */
    while (a != NULL) {
        b = a;
        a = a->next;
    }

    /* add to the notify list */
    a = (notify_list_t *) xmalloc(sizeof(notify_list_t));
    if (a == NULL)
        return SIEVE_NOMEM;

    b->next = a;
    a->isactive = 1;
    a->id = id;
    a->method = method;
    a->options = options;
    a->priority = priority;
    a->message = message;
    a->next = NULL;
    return 0;
}

/* denotify
 *
 * incomaptible with: none
 */
int do_denotify(notify_list_t *n, comparator_t *comp, const void *pat,
                void *comprock, const char *priority)
{
    while (n != NULL) {
        if (n->isactive &&
            (!priority || !strcasecmp(n->priority, priority)) &&
            (!comp || (n->id && comp(n->id, strlen(n->id), pat, comprock)))) {
            n->isactive = 0;
        }
        n = n->next;
    }

    return 0;
}

notify_list_t *new_notify_list(void)
{
    notify_list_t *ret = xmalloc(sizeof(notify_list_t));

    if (ret != NULL) {
        ret->isactive = 0;
        ret->id       = NULL;
        ret->method   = NULL;
        ret->options  = NULL;
        ret->priority = NULL;
        ret->message  = NULL;
        ret->next     = NULL;
    }
    return ret;
}

void free_notify_list(notify_list_t *n)
{
    while (n) {
        notify_list_t *b = n->next;
        free(n->options); /* strings live in bytecode, only free the array */
        free(n);
        n = b;
    }
}

action_list_t *new_action_list(void)
{
    action_list_t *ret = xmalloc(sizeof(action_list_t));

    if (ret != NULL) {
        ret->a = ACTION_NONE;
        ret->param = NULL;
        ret->next = NULL;
        ret->cancel_keep = 0;
    }
    return ret;
}

void free_action_list(action_list_t *a)
{
    while (a) {
        action_list_t *b = a->next;

        if(a->a == ACTION_VACATION) {
            if(a->u.vac.send.subj) free(a->u.vac.send.subj);
            if(a->u.vac.send.addr) free(a->u.vac.send.addr);
            if(a->u.vac.send.fromaddr) free(a->u.vac.send.fromaddr);
        }

        free(a);
        a = b;
    }
}

