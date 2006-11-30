/* interp.c -- sieve script interpretor builder
 * Larry Greenfield
 * $Id: interp.c,v 1.24 2006/11/30 17:11:24 murch Exp $
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
#include <string.h>

#include "xmalloc.h"

#include "sieve_interface.h"
#include "interp.h"
#include "libconfig.h"

/* build a sieve interpretor */
int sieve_interp_alloc(sieve_interp_t **interp, void *interp_context)
{
    sieve_interp_t *i;
    static int initonce;

    if (!initonce) {
	initialize_siev_error_table();
	initonce = 1;
    }

    *interp = NULL;
    i = (sieve_interp_t *) xmalloc(sizeof(sieve_interp_t));
    if (i == NULL) {
	return SIEVE_NOMEM;
    }

    i->redirect = i->discard = i->reject = i->fileinto = i->keep = NULL;
    i->getsize = NULL;
    i->getheader = NULL;
    i->getenvelope = NULL;
    i->getbody = NULL;
    i->getinclude = NULL;
    i->vacation = NULL;
    i->notify = NULL;

    i->markflags = NULL;

    i->interp_context = interp_context;
    i->err = NULL;

    *interp = i;
    return SIEVE_OK;
}

const char *sieve_listextensions(sieve_interp_t *i)
{
    static int done = 0;
    static char extensions[4096] = "";

    if (!done++) {
	unsigned long config_sieve_extensions =
	    config_getbitfield(IMAPOPT_SIEVE_EXTENSIONS);

	/* add comparators */
	strlcat(extensions, "comparator-i;ascii-numeric", sizeof(extensions));

	/* add actions */
	if (i->fileinto &&
	    (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_FILEINTO))
	    strlcat(extensions, " fileinto", sizeof(extensions));
	if (i->reject &&
	    (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_REJECT))
	    strlcat(extensions, " reject", sizeof(extensions));
	if (i->vacation &&
	    (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_VACATION))
	    strlcat(extensions, " vacation", sizeof(extensions));
	if (i->markflags &&
	    (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_IMAPFLAGS))
	    strlcat(extensions, " imapflags", sizeof(extensions));
	if (i->notify &&
	    (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_NOTIFY))
	    strlcat(extensions, " notify", sizeof(extensions));
	if (i->getinclude &&
	    (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_INCLUDE))
	    strlcat(extensions, " include", sizeof(extensions));

	/* add tests */
	if (i->getenvelope &&
	    (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_ENVELOPE))
	    strlcat(extensions, " envelope", sizeof(extensions));
	if (i->getbody &&
	    (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_BODY))
	    strlcat(extensions, " body", sizeof(extensions));

	/* add match-types */
	if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_RELATIONAL)
	    strlcat(extensions, " relational", sizeof(extensions));
#ifdef ENABLE_REGEX
	if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_REGEX)
	    strlcat(extensions, " regex", sizeof(extensions));
#endif

	/* add misc extensions */
	if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_SUBADDRESS)
	    strlcat(extensions, " subaddress", sizeof(extensions));
	if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_COPY)
	    strlcat(extensions, " copy", sizeof(extensions));
    }

    return extensions;
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

static char *default_markflags[] = { "\\flagged" };
static sieve_imapflags_t default_mark = { default_markflags, 1 };

int sieve_register_imapflags(sieve_interp_t *interp, sieve_imapflags_t *mark)
{
    interp->markflags =
	(mark && mark->flag && mark->nflags) ? mark : &default_mark;

    return SIEVE_OK;
}

int sieve_register_notify(sieve_interp_t *interp, sieve_callback *f)
{
    interp->notify = f;
 
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

int sieve_register_include(sieve_interp_t *interp, sieve_get_include *f)
{
    interp->getinclude = f;
    return SIEVE_OK;
}

int sieve_register_body(sieve_interp_t *interp, sieve_get_body *f)
{
    interp->getbody = f;
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

int sieve_register_execute_error(sieve_interp_t *interp, sieve_execute_error *f)
{
    interp->execute_err = f;
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
