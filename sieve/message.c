/* message.c -- message parsing functions
 * Larry Greenfield
 * $Id: message.c,v 1.25 2002/05/14 16:51:50 ken3 Exp $
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "sieve_interface.h"
#include "interp.h"
#include "message.h"
#include "parseaddr.h"
#include "xmalloc.h"
#include "util.h"

/* reject message m with message msg
 *
 * incompatible with: fileinto, redirect
 */
int do_reject(action_list_t *a, char *msg)
{
    action_list_t *b = NULL;

    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
	b = a;
	if (a->a == ACTION_FILEINTO ||
	    a->a == ACTION_KEEP ||
	    a->a == ACTION_REDIRECT ||
	    a->a == ACTION_REJECT ||
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
    a->a = ACTION_REJECT;
    a->u.rej.msg = msg;
    b->next = a;
    a->next =  NULL;
    return 0;
}

/* fileinto message m into mailbox 
 *
 * incompatible with: reject
 */
int do_fileinto(action_list_t *a, char *mbox, sieve_imapflags_t *imapflags)
{
    action_list_t *b = NULL;

    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
	b = a;
	if (a->a == ACTION_REJECT)
	    return SIEVE_RUN_ERROR;
	a = a->next;
    }

    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
	return SIEVE_NOMEM;
    a->a = ACTION_FILEINTO;
    a->u.fil.mailbox = mbox;
    a->u.fil.imapflags = imapflags;
    b->next = a;
    a->next = NULL;
    return 0;
}

/* redirect message m to to addr
 *
 * incompatible with: reject
 */
int do_redirect(action_list_t *a, char *addr)
{
    action_list_t *b = NULL;

    /* xxx we should validate addr */

    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
	b = a;
	if (a->a == ACTION_REJECT)
	    return SIEVE_RUN_ERROR;
	a = a->next;
    }

    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
	return SIEVE_NOMEM;
    a->a = ACTION_REDIRECT;
    a->u.red.addr = addr;
    a->next = NULL;
    b->next = a;
    return 0;
}

/* keep message
 *
 * incompatible with: reject
 */
int do_keep(action_list_t *a, sieve_imapflags_t *imapflags)
{
    action_list_t *b = NULL;

    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
	b = a;
	if (a->a == ACTION_REJECT)
	    return SIEVE_RUN_ERROR;
	if (a->a == ACTION_KEEP) /* don't bother doing it twice */
	    return 0;
	a = a->next;
    }

    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
	return SIEVE_NOMEM;
    a->a = ACTION_KEEP;
    a->u.keep.imapflags = imapflags;
    a->next = NULL;
    b->next = a;
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
    a->next = NULL;
    b->next = a;
    return 0;
}

int do_vacation(action_list_t *a, char *addr, char *fromaddr,
		char *subj, char *msg, int days,
		int mime)
{
    action_list_t *b = NULL;

    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
	b = a;
	if (a->a == ACTION_REJECT ||
	    a->a == ACTION_VACATION) /* vacation can't be used twice */
	    return SIEVE_RUN_ERROR;
	a = a->next;
    }

    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
	return SIEVE_NOMEM;
    a->a = ACTION_VACATION;
    a->u.vac.send.addr = addr;
    a->u.vac.send.fromaddr = fromaddr;
    a->u.vac.send.subj = subj;	/* user specified subject */
    a->u.vac.send.msg = msg;
    a->u.vac.send.mime = mime;
    a->u.vac.autoresp.days = days;
    a->next = NULL;
    b->next = a;
    return 0;
}

/* setflag f on message m
 *
 * incompatible with: reject
 */
int do_setflag(action_list_t *a, char *flag)
{
    action_list_t *b = NULL;
 
    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
	b = a;
	if (a->a == ACTION_REJECT)
	    return SIEVE_RUN_ERROR;
	a = a->next;
    }
 
    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
	return SIEVE_NOMEM;
    a->a = ACTION_SETFLAG;
    a->u.fla.flag = flag;
    b->next = a;
    a->next = NULL;
    return 0;
}

/* addflag f on message m
 *
 * incompatible with: reject
 */
int do_addflag(action_list_t *a, char *flag)
{
    action_list_t *b = NULL;
 
    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
	b = a;
	if (a->a == ACTION_REJECT)
	    return SIEVE_RUN_ERROR;
	a = a->next;
    }
 
    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
	return SIEVE_NOMEM;
    a->a = ACTION_ADDFLAG;
    a->u.fla.flag = flag;
    b->next = a;
    a->next = NULL;
    return 0;
}

/* removeflag f on message m
 *
 * incompatible with: reject
 */
int do_removeflag(action_list_t *a, char *flag)
{
    action_list_t *b = NULL;
 
    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
	b = a;
	if (a->a == ACTION_REJECT)
	    return SIEVE_RUN_ERROR;
	a = a->next;
    }
 
    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
	return SIEVE_NOMEM;
    a->a = ACTION_REMOVEFLAG;
    a->u.fla.flag = flag;
    b->next = a;
    a->next = NULL;
    return 0;
}


/* mark message m
 *
 * incompatible with: reject
 */
int do_mark(action_list_t *a)
{
    action_list_t *b = NULL;
 
    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
	b = a;
	if (a->a == ACTION_REJECT)
	    return SIEVE_RUN_ERROR;
	a = a->next;
    }
 
    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
	return SIEVE_NOMEM;
    a->a = ACTION_MARK;
    b->next = a;
    a->next = NULL;
    return 0;
}


/* unmark message m
 *
 * incompatible with: reject
 */
int do_unmark(action_list_t *a)
{
    action_list_t *b = NULL;
 
    /* see if this conflicts with any previous actions taken on this message */
    while (a != NULL) {
	b = a;
	if (a->a == ACTION_REJECT)
	    return SIEVE_RUN_ERROR;
	a = a->next;
    }
 
    /* add to the action list */
    a = (action_list_t *) xmalloc(sizeof(action_list_t));
    if (a == NULL)
	return SIEVE_NOMEM;
    a->a = ACTION_UNMARK;
    b->next = a;
    a->next = NULL;
    return 0;
}

/* notify
 *
 * incompatible with: none
 */
int do_notify(notify_list_t *a, char *id,
	      char *method, stringlist_t **options,
	      const char *priority, char *message)
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
int do_denotify(notify_list_t *n, comparator_t *comp, void *pat,
		void *comprock, const char *priority)
{
    while (n != NULL) {
	if (n->isactive && 
	    (!priority || !strcasecmp(n->priority, priority)) &&
	    (!comp || (n->id && comp(n->id, pat, comprock)))) {
	    n->isactive = 0;
	}
	n = n->next;
    }

    return 0;
}



/* given a header, extract an address out of it.  if marker points to NULL,
   extract the first address.  otherwise, it's an index into the header to
   say where to start extracting */
struct addr_marker {
    struct address *where;
    char *freeme;
};

int parse_address(const char *header, void **data, void **marker)
{
    struct addr_marker *am = (struct addr_marker *) *marker;

    parseaddr_list(header, (struct address **) data);
    am = (void *) xmalloc(sizeof(struct addr_marker));
    am->where = *data;
    am->freeme = NULL;
    *marker = am;
    return SIEVE_OK;
}

char *get_address(address_part_t addrpart,
		  void **data __attribute__((unused)),
		  void **marker,
		  int canon_domain)
{
    char *ret = NULL;
    struct address *a;
    struct addr_marker *am = *marker;

    a = am->where;
    if (am->freeme) {
	free(am->freeme);
	am->freeme = NULL;
    }

    if (a == NULL) {
	ret = NULL;
    } else {
	if (canon_domain && a->domain)
	    lcase(a->domain);

	switch (addrpart) { 
	case ADDRESS_ALL:
#define U_DOMAIN "unspecified-domain"
#define U_USER "unknown-user"
	    if (a->mailbox || a->domain) {
		char *m = a->mailbox ? a->mailbox : U_USER;
		char *d = a->domain ? a->domain : U_DOMAIN;
		am->freeme = (char *) xmalloc(strlen(m) + strlen(d) + 2);

		sprintf(am->freeme, "%s@%s", m, d);
		ret = am->freeme;
	    } else {
		ret = NULL;
	    }
	    break;

	case ADDRESS_LOCALPART:
	    ret = a->mailbox;
	    break;
	    
	case ADDRESS_DOMAIN:
	    ret = a->domain;
	    break;

	case ADDRESS_USER:
	    if (a->mailbox) {
		char *p = strchr(a->mailbox, '+');
		int len = p ? p - a->mailbox : strlen(a->mailbox);

		am->freeme = (char *) xmalloc(len + 1);
		strncpy(am->freeme, a->mailbox, len);
		am->freeme[len] = '\0';
		ret = am->freeme;
	    } else {
		ret = NULL;
	    }
	    break;

	case ADDRESS_DETAIL:
	    if (a->mailbox) {
		char *p = strchr(a->mailbox, '+');
		ret = (p ? p + 1 : NULL);
	    } else {
		ret = NULL;
	    }
	    break;
	}
	a = a->next;
	am->where = a;
    }
    *marker = am;
    return ret;
}

int free_address(void **data, void **marker)
{
    struct addr_marker *am = (struct addr_marker *) *marker;

    if (*data)
	parseaddr_free((struct address *) *data);
    *data = NULL;
    if (am->freeme) free(am->freeme);
    free(am);
    *marker = NULL;
    return SIEVE_OK;
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
    }
    return ret;
}

void free_action_list(action_list_t *a)
{
    while (a) {
	action_list_t *b = a->next;
	switch (a->a) {
	case ACTION_VACATION:
	    if (a->u.vac.send.addr) free(a->u.vac.send.addr);
	    if (a->u.vac.send.fromaddr) free(a->u.vac.send.fromaddr);
	    if (a->u.vac.send.subj) free(a->u.vac.send.subj);
	    break;

	default:
	    break;
	}
	free(a);
	a = b;
    }
}

