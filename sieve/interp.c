/* interp.c -- sieve script interpretor builder
 * Larry Greenfield
 * $Id: interp.c,v 1.7 2000/01/28 22:09:55 leg Exp $
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

#include <stdlib.h>

#include "xmalloc.h"

#include "sieve_interface.h"
#include "interp.h"

const char *sieve_version = "cmu-sieve 1.3";

/* build a sieve interpretor */
int sieve_interp_alloc(sieve_interp_t **interp, void *interp_context)
{
    sieve_interp_t *i;

    *interp = NULL;
    i = (sieve_interp_t *) xmalloc(sizeof(sieve_interp_t));
    if (i == NULL) {
	return SIEVE_NOMEM;
    }

    i->redirect = i->discard = i->reject = i->fileinto = i->keep = NULL;
    i->setflag = i->addflag = i->removeflag = i->mark = i->unmark = NULL;
    i->getsize = NULL;
    i->getheader = NULL;
    i->getenvelope = NULL;
    i->vacation = NULL;

    i->interp_context = interp_context;
    i->err = NULL;

    *interp = i;
    return SIEVE_OK;
}

int sieve_interp_free(sieve_interp_t **interp)
{
    free(*interp);
    
    return SIEVE_OK;
}

/* add the callbacks */
int sieve_register_redirect(sieve_interp_t *interp, sieve_callback *f)
{
    interp->redirect = f;

    return SIEVE_OK;
}

int sieve_register_discard(sieve_interp_t *interp, sieve_callback *f)
{
    interp->discard = f;

    return SIEVE_OK;
}

int sieve_register_reject(sieve_interp_t *interp, sieve_callback *f)
{
    interp->reject = f;

    return SIEVE_OK;
}

int sieve_register_fileinto(sieve_interp_t *interp, sieve_callback *f)
{
    interp->fileinto = f;

    return SIEVE_OK;
}

int sieve_register_keep(sieve_interp_t *interp, sieve_callback *f)
{
    interp->keep = f;
 
    return SIEVE_OK;
}
 
int sieve_register_setflag(sieve_interp_t *interp, sieve_callback *f)
{
    interp->setflag = f;
 
    return SIEVE_OK;
}
 
int sieve_register_addflag(sieve_interp_t *interp, sieve_callback *f)
{
    interp->addflag = f;
 
    return SIEVE_OK;
}
 
int sieve_register_removeflag(sieve_interp_t *interp, sieve_callback *f)
{
    interp->removeflag = f;
 
    return SIEVE_OK;
}
 
int sieve_register_mark(sieve_interp_t *interp, sieve_callback *f)
{
    interp->mark = f;
 
    return SIEVE_OK;
}
 
int sieve_register_unmark(sieve_interp_t *interp, sieve_callback *f)
{
    interp->unmark = f;

    return SIEVE_OK;
}

int sieve_register_notify(sieve_interp_t *interp, sieve_notify_callback *f)
{
    interp->notify = f;
 
    return SIEVE_OK;
}

int sieve_register_denotify(sieve_interp_t *interp, sieve_callback *f)
{
    interp->denotify = f;
 
    return SIEVE_OK;
}

/* add the callbacks for messages. again, undefined if used after
   sieve_script_parse */
int sieve_register_size(sieve_interp_t *interp, sieve_get_size *f)
{
    interp->getsize = f;
    return SIEVE_OK;
}

int sieve_register_header(sieve_interp_t *interp, sieve_get_header *f)
{
    interp->getheader = f;
    return SIEVE_OK;
}

int sieve_register_envelope(sieve_interp_t *interp, sieve_get_envelope *f)
{
    interp->getenvelope = f;
    return SIEVE_OK;
}

int sieve_register_vacation(sieve_interp_t *interp, sieve_vacation_t *v)
{
    if (!interp->getenvelope) {
	return SIEVE_NOT_FINALIZED; /* we need envelope for vacation! */
    }

    if (v->min_response == 0) v->min_response = 3;
    if (v->max_response == 0) v->max_response = 90;
    if (v->min_response < 0 || v->max_response < 7 || !v->autorespond
	|| !v->send_response) {
	return SIEVE_FAIL;
    }

    interp->vacation = v;
    return SIEVE_OK;
}

int sieve_register_parse_error(sieve_interp_t *interp, sieve_parse_error *f)
{
    interp->err = f;
    return SIEVE_OK;
}

int interp_verify(sieve_interp_t *i)
{
    if (i->redirect && i->keep && i->getsize && i->getheader) {
	return SIEVE_OK;
    } else {
	return SIEVE_NOT_FINALIZED;
    }
}
