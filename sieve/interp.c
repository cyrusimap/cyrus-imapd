/* interp.c -- sieve script interpreter builder
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

/* build a sieve interpreter */
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
    i->extensions = NULL;

    i->time = time(NULL);

    return i;
}

EXPORTED strarray_t *sieve_listextensions(sieve_interp_t *i)
{
    if (i->extensions == NULL) {
        unsigned long config_sieve_extensions =
            config_getbitfield(IMAPOPT_SIEVE_EXTENSIONS);
        struct buf buf = BUF_INITIALIZER;

        /* strarray of ManageSieve capability/value pairs */
        i->extensions = strarray_new();
        
        /* Add EXTLISTS capability */
        strarray_append(i->extensions, "SIEVE");

        /* add comparators */
        buf_setcstr(&buf, "comparator-i;ascii-numeric");

        /* add actions */
        if (i->fileinto &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_FILEINTO))
            buf_appendcstr(&buf, " fileinto");
        if (i->reject &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_REJECT))
            buf_appendcstr(&buf, " reject ereject");
        if (i->vacation &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_VACATION_SECONDS))
            buf_appendcstr(&buf, " vacation vacation-seconds");
        else if (i->vacation &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_VACATION))
            buf_appendcstr(&buf, " vacation");
        if (i->markflags &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_IMAPFLAGS))
            buf_appendcstr(&buf, " imapflags");
        if (i->notify &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_NOTIFY))
            buf_appendcstr(&buf, " notify enotify");
        if (i->getinclude &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_INCLUDE))
            buf_appendcstr(&buf, " include");
        if (i->addheader &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_EDITHEADER))
            buf_appendcstr(&buf, " editheader");
        if ((config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_IHAVE))
            buf_appendcstr(&buf, " ihave");

        /* add tests */
        if (i->getenvelope &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_ENVELOPE))
            buf_appendcstr(&buf, " envelope");
        if (i->getbody &&
            (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_BODY))
            buf_appendcstr(&buf, " body");
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_IMAP4FLAGS)
            buf_appendcstr(&buf, " imap4flags");
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_DATE)
            buf_appendcstr(&buf, " date");
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_MAILBOX)
            buf_appendcstr(&buf, " mailbox");
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_MBOXMETADATA)
            buf_appendcstr(&buf, " mboxmetadata");
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_SERVERMETADATA)
            buf_appendcstr(&buf, " servermetadata");
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_DUPLICATE)
            buf_appendcstr(&buf, " duplicate");

        /* add match-types */
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_RELATIONAL)
            buf_appendcstr(&buf, " relational");
#ifdef ENABLE_REGEX
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_REGEX)
            buf_appendcstr(&buf, " regex");
#endif
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_EXTLISTS)
            buf_appendcstr(&buf, " extlists");

        /* add misc extensions */
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_SUBADDRESS)
            buf_appendcstr(&buf, " subaddress");
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_COPY)
            buf_appendcstr(&buf, " copy");
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_INDEX)
            buf_appendcstr(&buf, " index");
        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_VARIABLES)
            buf_appendcstr(&buf, " variables");

        strarray_appendm(i->extensions, buf_release(&buf));

        if (config_sieve_extensions & IMAP_ENUM_SIEVE_EXTENSIONS_EXTLISTS) {
            /* Add EXTLISTS capability */
            strarray_append(i->extensions, "EXTLISTS");
            strarray_append(i->extensions, "urn:ietf:params:sieve:addrbook");
        }
    }

    return i->extensions;
}

EXPORTED int sieve_interp_free(sieve_interp_t **interp)
{
    if (*interp) {
        free((*interp)->lastitem);
        strarray_free((*interp)->extensions);
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

EXPORTED void sieve_register_specialuseexists(sieve_interp_t *interp, sieve_get_specialuseexists *f)
{
    interp->getspecialuseexists = f;
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

EXPORTED void sieve_register_listvalidator(sieve_interp_t *interp, sieve_list_validator *f)
{
    interp->isvalidlist = f;
}

EXPORTED void sieve_register_listcompare(sieve_interp_t *interp, sieve_list_comparator *f)
{
    interp->listcompare = f;
}

EXPORTED int sieve_register_duplicate(sieve_interp_t *interp,
                                      sieve_duplicate_t *d)
{
    if (!interp->getheader) {
        return SIEVE_NOT_FINALIZED; /* we need header for duplicate! */
    }

    if (!(d->check && d->track)) {
        return SIEVE_FAIL;
    }

    if (d->max_expiration > 7776000) d->max_expiration = 7776000;  /* 90 days */

    interp->duplicate = d;
    return SIEVE_OK;
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

/* Array of Sieve capabilities */
static const struct sieve_capa_t {
    const char *str;
    unsigned long long flag;
} sieve_capabilities[] =
{
    /* Sieve "base" - RFC 5228 */
    { "comparator-i;octet",         SIEVE_CAPA_BASE },
    { "comparator-i;ascii-casemap", SIEVE_CAPA_BASE },
    { "comparator-i;ascii-numeric", SIEVE_CAPA_COMP_NUMERIC },

    { "encoded-character", SIEVE_CAPA_ENCODE_CHAR },
    { "envelope",          SIEVE_CAPA_ENVELOPE },
    { "fileinto",          SIEVE_CAPA_FILEINTO },

    /* Regular Expressions - draft-ietf-sieve-regex */
    { "regex", SIEVE_CAPA_REGEX },

    /* Copy - RFC 3894 */
    { "copy", SIEVE_CAPA_COPY },

    /* Body - RFC 5173 */
    { "body", SIEVE_CAPA_BODY },

    /* Environment - RFC 5183 */
    { "environment", SIEVE_CAPA_ENVIRONMENT },

    /* Variables - RFC 5229 */
    { "variables", SIEVE_CAPA_VARIABLES },

    /* Vacation - RFC 5230 */
    { "vacation", SIEVE_CAPA_VACATION },

    /* Relational - RFC 5231 */
    { "relational", SIEVE_CAPA_RELATIONAL },

    /* IMAP4 Flags - RFC 5232 */
    { "imap4flags", SIEVE_CAPA_IMAP4FLAGS },
    { "imapflags",  SIEVE_CAPA_IMAPFLAGS }, /* draft-melnikov-sieve-imapflags-04 */

    /* Subaddress - RFC 5233 */
    { "subaddress", SIEVE_CAPA_SUBADDRESS },

    /* Spamtest & Virustest - RFC 5235 */
    { "spamtest",     SIEVE_CAPA_SPAM },
    { "spamtestplus", SIEVE_CAPA_SPAMPLUS },
    { "virustest",    SIEVE_CAPA_VIRUS },

    /* Date & Index - RFC 5260 */
    { "date",  SIEVE_CAPA_DATE },
    { "index", SIEVE_CAPA_INDEX },

    /* Editheader - RFC 5293 */
    { "editheader", SIEVE_CAPA_EDITHEADER },

    /* [Extended] Reject - RFC 5429 */
    { "ereject", SIEVE_CAPA_EREJECT },
    { "reject",  SIEVE_CAPA_REJECT },

    /* Notifications - RFC 5435 */
    { "enotify", SIEVE_CAPA_ENOTIFY },
    { "notify",  SIEVE_CAPA_NOTIFY }, /* draft-martin-sieve-notify-01 */

    /* Ihave - RFC 5463 */
    { "ihave", SIEVE_CAPA_IHAVE },

    /* Mailbox & Metadata - RFC 5490 */
    { "mailbox",        SIEVE_CAPA_MAILBOX },
    { "mboxmetadata",   SIEVE_CAPA_MBOXMETA },
    { "servermetadata", SIEVE_CAPA_SERVERMETA },

    /* MIME Part Handling - RFC 5703 */
    { "enclose",      SIEVE_CAPA_ENCLOSE },
    { "extracttest",  SIEVE_CAPA_EXTRACT },
    { "foreverypart", SIEVE_CAPA_FOREVERYPART },
    { "mime",         SIEVE_CAPA_MIME },
    { "replace",      SIEVE_CAPA_REPLACE },

    /* DSN & Deliver-By - RFC 6009 */
    { "envelope-deliverby", SIEVE_CAPA_ENV_DELBY },
    { "envelope-dsn",       SIEVE_CAPA_ENV_DSN },
    { "redirect-deliverby", SIEVE_CAPA_REDIR_DELBY },
    { "redirect-dsn",       SIEVE_CAPA_REDIR_DSN },

    /* Vacation :seconds - RFC 6131 */
    { "vacation-seconds", SIEVE_CAPA_VACATION_SEC },

    /* External Lists - RFC 6134 */
    { "extlists", SIEVE_CAPA_EXTLISTS },

    /* Convert - RFC 6558 */
    { "convert", SIEVE_CAPA_CONVERT },

    /* Include - RFC 6609 */
    { "include", SIEVE_CAPA_INCLUDE },

    /* IMAP Events - RFC 6785 */
    { "imapsieve", SIEVE_CAPA_IMAP },

    /* Duplicate - RFC 7352 */
    { "duplicate", SIEVE_CAPA_DUPLICATE },

    /* Special-Use - draft-bosch-sieve-special-use */
    { "special-use", SIEVE_CAPA_SPECIAL_USE },

    /* Fcc - draft-murchison-sieve-fcc */
    { "fcc", SIEVE_CAPA_FCC },

    { NULL, 0 }
};
    

unsigned long long lookup_capability(const char *str)
{
    const struct sieve_capa_t *capa;

    for (capa = sieve_capabilities; capa->str; capa++) {
        if (!strcmp(str, capa->str)) return capa->flag;
    }

    return 0;
}

unsigned long long extension_isactive(sieve_interp_t *interp, const char *str)
{
    unsigned long config_ext = config_getbitfield(IMAPOPT_SIEVE_EXTENSIONS);
    unsigned long long capa = lookup_capability(str);

    switch (capa) {
    case SIEVE_CAPA_BASE:
    case SIEVE_CAPA_COMP_NUMERIC:
        /* always enabled */
        break;

    case SIEVE_CAPA_ENVELOPE:
        if (!(interp->getenvelope &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_ENVELOPE))) capa = 0;
        break;

    case SIEVE_CAPA_FILEINTO:
        if (!(interp->fileinto &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_FILEINTO))) capa = 0;
        break;

    case SIEVE_CAPA_REGEX:
        if (!(config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_REGEX)) capa = 0;
        break;

    case SIEVE_CAPA_COPY:
        if (!(config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_COPY)) capa = 0;
        break;

    case SIEVE_CAPA_BODY:
        if (!(interp->getbody &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_BODY))) capa = 0;
        break;

    case SIEVE_CAPA_VARIABLES:
        if (!(config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_VARIABLES)) capa = 0;
        break;
        
    case SIEVE_CAPA_VACATION:
        if (!(interp->vacation &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_VACATION))) capa = 0;
        break;

    case SIEVE_CAPA_RELATIONAL:
        if (!(config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_RELATIONAL)) capa = 0;
        break;

    case SIEVE_CAPA_IMAP4FLAGS:
        if (!(config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_IMAP4FLAGS)) capa = 0;
        break;
        
    case SIEVE_CAPA_IMAPFLAGS:
        if (!(interp->markflags->count &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_IMAPFLAGS))) capa = 0;
        break;

    case SIEVE_CAPA_SUBADDRESS:
        if (!(config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_SUBADDRESS)) capa = 0;
        break;

    case SIEVE_CAPA_DATE:
        if (!(config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_DATE)) capa = 0;
        break;

    case SIEVE_CAPA_INDEX:
        if (!(config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_INDEX)) capa = 0;
        break;

    case SIEVE_CAPA_EDITHEADER:
        if (!(interp->addheader && interp->deleteheader &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_EDITHEADER))) capa = 0;
        break;

    case SIEVE_CAPA_EREJECT:
    case SIEVE_CAPA_REJECT:
        if (!(interp->reject &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_REJECT))) capa = 0;
        break;

    case SIEVE_CAPA_ENOTIFY:
    case SIEVE_CAPA_NOTIFY:
        if (!(interp->notify &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_NOTIFY))) capa = 0;
        break;

    case SIEVE_CAPA_IHAVE:
        if (!(config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_IHAVE)) capa = 0;
        break;

    case SIEVE_CAPA_MAILBOX:
        if (!(interp->getmailboxexists &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_MAILBOX))) capa = 0;
        break;

    case SIEVE_CAPA_MBOXMETA:
        if (!(interp->getmetadata &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_MBOXMETADATA))) capa = 0;
        break;

    case SIEVE_CAPA_SERVERMETA:
        if (!(interp->getmetadata &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_SERVERMETADATA))) capa = 0;
        break;

    case SIEVE_CAPA_VACATION_SEC:
        if (!(interp->vacation &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_VACATION_SECONDS))) {
            capa = 0;
        } else {
            /* Note that "vacation-seconds" implies "vacation", and a script
             * with "vacation-seconds" in a "require" list MAY omit "vacation"
             * from that list. */
            capa |= SIEVE_CAPA_VACATION;
        }
        break;

    case SIEVE_CAPA_EXTLISTS:
        if (!(interp->isvalidlist && interp->listcompare &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_EXTLISTS) &&
              (config_getbitfield(IMAPOPT_HTTPMODULES) & IMAP_ENUM_HTTPMODULES_CARDDAV)))
            capa = 0;
        break;

    case SIEVE_CAPA_INCLUDE:
        if (!(interp->getinclude &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_INCLUDE))) capa = 0;
        break;

    case SIEVE_CAPA_DUPLICATE:
        if (!(interp->duplicate &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_DUPLICATE))) capa = 0;
        break;

    case SIEVE_CAPA_SPECIAL_USE:
        if (!(interp->getspecialuseexists &&
              (config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_SPECIAL_USE))) capa = 0;
        break;

    case SIEVE_CAPA_FCC:
        if (!(config_ext & IMAP_ENUM_SIEVE_EXTENSIONS_FCC)) capa = 0;
        break;

    default:
        /* not supported */
        capa = 0;
        break;
    }

    return (capa);
}
