/* interp.c -- sieve script interpretor builder
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

#include "xmalloc.h"
#include "xstrlcat.h"

#include "sieve_interface.h"
#include "interp.h"
#include "libconfig.h"
#include "times.h"

#define EXT_LEN 4096

/* build a sieve interpretor */
EXPORTED sieve_interp_t *sieve_interp_alloc(void *interp_context)
{
    sieve_interp_t *i;
    static int initonce;

    if (!initonce) {
        initialize_siev_error_table();
        initonce = 1;
    }

    i = (sieve_interp_t *) xzmalloc(sizeof(sieve_interp_t));

    i->interp_context = interp_context;
    i->extensions[0] = '\0';

    i->time = time(NULL);

    return i;
}

EXPORTED const char *sieve_listextensions(sieve_interp_t *i)
{
    if (i->extensions[0] == '\0') {
        unsigned long config_sieve_extensions =
            config_getbitfield(IMAPOPT_SIEVE_EXTENSIONS);

        /* add comparators */
        strlcat(i->extensions, "comparator-i;ascii-numeric", EXT_LEN);

        /* add actions */
        if (i->fileinto &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_FILEINTO))
            strlcat(i->extensions, " fileinto", EXT_LEN);
        if (i->reject &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_REJECT))
            strlcat(i->extensions, " reject ereject", EXT_LEN);
        if (i->vacation &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_VACATION_SECONDS))
            strlcat(i->extensions, " vacation vacation-seconds", EXT_LEN);
        else if (i->vacation &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_VACATION))
            strlcat(i->extensions, " vacation", EXT_LEN);
        if (i->markflags &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_IMAPFLAGS))
            strlcat(i->extensions, " imapflags", EXT_LEN);
        if (i->notify &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_NOTIFY))
            strlcat(i->extensions, " notify", EXT_LEN);
        if (i->getinclude &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_INCLUDE))
            strlcat(i->extensions, " include", EXT_LEN);
        if (i->addheader &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_EDITHEADER))
            strlcat(i->extensions, " editheader", EXT_LEN);

        /* add tests */
        if (i->getenvelope &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_ENVELOPE))
            strlcat(i->extensions, " envelope", EXT_LEN);
        if (i->getbody &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_BODY))
            strlcat(i->extensions, " body", EXT_LEN);
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_IMAP4FLAGS)
            strlcat(i->extensions, " imap4flags", EXT_LEN);
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_DATE)
            strlcat(i->extensions, " date", EXT_LEN);
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_MAILBOX)
            strlcat(i->extensions, " mailbox", EXT_LEN);
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_MBOXMETADATA)
            strlcat(i->extensions, " mboxmetadata", EXT_LEN);
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_SERVERMETADATA)
            strlcat(i->extensions, " servermetadata", EXT_LEN);

        /* add match-types */
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_RELATIONAL)
            strlcat(i->extensions, " relational", EXT_LEN);
#ifdef ENABLE_REGEX
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_REGEX)
            strlcat(i->extensions, " regex", EXT_LEN);
#endif
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_EXTLISTS)
            strlcat(i->extensions, " extlists", EXT_LEN);

        /* add misc extensions */
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_SUBADDRESS)
            strlcat(i->extensions, " subaddress", EXT_LEN);
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_COPY)
            strlcat(i->extensions, " copy", EXT_LEN);
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_INDEX)
            strlcat(i->extensions, " index", EXT_LEN);
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_VARIABLES)
            strlcat(i->extensions, " variables", EXT_LEN);
    }

    return i->extensions;
}

EXPORTED int sieve_interp_free(sieve_interp_t **interp)
{
    if (*interp) {
        free((*interp)->lastitem);
        free(*interp);
        *interp = NULL;
    }

    return SIEVE_OK;
}

/* add the callbacks */
EXPORTED void sieve_register_redirect(sieve_interp_t *interp, sieve_callback *f)
{
    interp->redirect = f;
}

EXPORTED void sieve_register_discard(sieve_interp_t *interp, sieve_callback *f)
{
    interp->discard = f;
}

EXPORTED void sieve_register_reject(sieve_interp_t *interp, sieve_callback *f)
{
    interp->reject = f;
}

EXPORTED void sieve_register_fileinto(sieve_interp_t *interp, sieve_callback *f)
{
    interp->fileinto = f;
}

EXPORTED void sieve_register_keep(sieve_interp_t *interp, sieve_callback *f)
{
    interp->keep = f;
}

EXPORTED void sieve_register_imapflags(sieve_interp_t *interp, const strarray_t *mark)
{
    static strarray_t default_mark = STRARRAY_INITIALIZER;

    if (!default_mark.count)
        strarray_append(&default_mark, "\\flagged");

    interp->markflags =
        (mark && mark->data && mark->count) ? mark : &default_mark;
}

EXPORTED void sieve_register_notify(sieve_interp_t *interp, sieve_callback *f)
{
    interp->notify = f;
}

/* add the callbacks for messages. again, undefined if used after
   sieve_script_parse */
EXPORTED void sieve_register_size(sieve_interp_t *interp, sieve_get_size *f)
{
    interp->getsize = f;
}

EXPORTED void sieve_register_mailboxexists(sieve_interp_t *interp, sieve_get_mailboxexists *f)
{
    interp->getmailboxexists = f;
}

EXPORTED void sieve_register_metadata(sieve_interp_t *interp, sieve_get_metadata *f)
{
    interp->getmetadata = f;
}

EXPORTED void sieve_register_header(sieve_interp_t *interp, sieve_get_header *f)
{
    interp->getheader = f;
}

EXPORTED void sieve_register_addheader(sieve_interp_t *interp, sieve_add_header *f)
{
    interp->addheader = f;
}

EXPORTED void sieve_register_deleteheader(sieve_interp_t *interp, sieve_delete_header *f)
{
    interp->deleteheader = f;
}

EXPORTED void sieve_register_fname(sieve_interp_t *interp, sieve_get_fname *f)
{
    interp->getfname = f;
}

EXPORTED void sieve_register_envelope(sieve_interp_t *interp, sieve_get_envelope *f)
{
    interp->getenvelope = f;
}

EXPORTED void sieve_register_include(sieve_interp_t *interp, sieve_get_include *f)
{
    interp->getinclude = f;
}

EXPORTED void sieve_register_body(sieve_interp_t *interp, sieve_get_body *f)
{
    interp->getbody = f;
}

EXPORTED int sieve_register_vacation(sieve_interp_t *interp, sieve_vacation_t *v)
{
    if (!interp->getenvelope) {
        return SIEVE_NOT_FINALIZED; /* we need envelope for vacation! */
    }

    if (v->min_response == 0)
        v->min_response = config_getint(IMAPOPT_SIEVE_VACATION_MIN_RESPONSE);
    if (v->max_response == 0)
        v->max_response = config_getint(IMAPOPT_SIEVE_VACATION_MAX_RESPONSE);
    if (v->min_response < 0 || v->max_response < 7 * DAY2SEC || !v->autorespond
        || !v->send_response) {
        return SIEVE_FAIL;
    }

    interp->vacation = v;
    return SIEVE_OK;
}

EXPORTED void sieve_register_listcompare(sieve_interp_t *interp, sieve_list_comparator *f)
{
    interp->listcompare = f;
}

EXPORTED void sieve_register_parse_error(sieve_interp_t *interp, sieve_parse_error *f)
{
    interp->err = f;
}

EXPORTED void sieve_register_execute_error(sieve_interp_t *interp, sieve_execute_error *f)
{
    interp->execute_err = f;
}

int interp_verify(sieve_interp_t *i)
{
    if (i->redirect && i->keep && i->getsize && i->getheader) {
        return SIEVE_OK;
    } else {
        return SIEVE_NOT_FINALIZED;
    }
}
