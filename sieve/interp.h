/* interp.h -- interpreter definition
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

#ifndef SIEVE_INTERP_H
#define SIEVE_INTERP_H

#include "sieve_interface.h"

struct sieve_interp {
    /* standard callbacks for actions */
    sieve_callback *redirect, *discard, *reject, *fileinto, *keep;
    sieve_callback *notify;
    sieve_vacation_t *vacation;

    sieve_get_size *getsize;
    sieve_get_header *getheader;
    sieve_add_header *addheader;
    sieve_delete_header *deleteheader;
    sieve_get_envelope *getenvelope;
    sieve_get_body *getbody;
    sieve_get_include *getinclude;
    sieve_get_fname *getfname;
    sieve_get_mailboxexists *getmailboxexists;
    sieve_get_specialuseexists *getspecialuseexists;
    sieve_get_metadata *getmetadata;

    sieve_list_validator *isvalidlist;
    sieve_list_comparator *listcompare;

    sieve_duplicate_t *duplicate;

    sieve_parse_error *err;

    /* site-specific imapflags for mark/unmark */
    const strarray_t *markflags;

    sieve_execute_error *execute_err;

    char *lastitem;

    /* context to pass along */
    void *interp_context;
    strarray_t *extensions;

    /* time when allocated */
    time_t time;
};


/* Sieve capabilities bitmask */
enum sieve_capa_flag {
    /* Sieve "base" - RFC 5228 */
    SIEVE_CAPA_BASE         = 1LL<<0,
    SIEVE_CAPA_COMP_NUMERIC = 1LL<<1,
    SIEVE_CAPA_ENCODE_CHAR  = 0LL<<2, /* currently unsupported */
    SIEVE_CAPA_ENVELOPE     = 1LL<<3,
    SIEVE_CAPA_FILEINTO     = 1LL<<4,

    /* Regular Expressions - draft-ietf-sieve-regex */
#ifdef ENABLE_REGEX
    SIEVE_CAPA_REGEX        = 1LL<<5,
#else
    SIEVE_CAPA_REGEX        = 0LL<<5, /* disabled at compile-time */
#endif

    /* Copy - RFC 3894 */
    SIEVE_CAPA_COPY         = 1LL<<6,

    /* Body - RFC 5173 */
    SIEVE_CAPA_BODY         = 1LL<<7,

    /* Environment - RFC 5183 */
    SIEVE_CAPA_ENVIRONMENT  = 0LL<<8, /* currently unsupported */

    /* Variables - RFC 5229 */
    SIEVE_CAPA_VARIABLES    = 1LL<<9,

    /* Vacation - RFC 5230 */
    SIEVE_CAPA_VACATION     = 1LL<<10,

    /* Relational - RFC 5231 */
    SIEVE_CAPA_RELATIONAL   = 1LL<<11,

    /* IMAP4 Flags - RFC 5232 */
    SIEVE_CAPA_IMAP4FLAGS   = 1LL<<12,
    SIEVE_CAPA_IMAPFLAGS    = 1LL<<13, /* draft-melnikov-sieve-imapflags-04 */

    /* Subaddress - RFC 5233 */
    SIEVE_CAPA_SUBADDRESS   = 1LL<<14,

    /* Spamtest & Virustest - RFC 5235 */
    SIEVE_CAPA_SPAM         = 0LL<<15, /* currently unsupported */
    SIEVE_CAPA_SPAMPLUS     = 0LL<<16, /* currently unsupported */
    SIEVE_CAPA_VIRUS        = 0LL<<17, /* currently unsupported */

    /* Date & Index - RFC 5260 */
    SIEVE_CAPA_DATE         = 1LL<<18,
    SIEVE_CAPA_INDEX        = 1LL<<19,

    /* Editheader - RFC 5293 */
    SIEVE_CAPA_EDITHEADER   = 1LL<<20,

    /* [Extended] Reject - RFC 5429 */
    SIEVE_CAPA_EREJECT      = 1LL<<21,
    SIEVE_CAPA_REJECT       = 1LL<<22,

    /* Notifications - RFC 5435 */
    SIEVE_CAPA_ENOTIFY      = 1LL<<23,
    SIEVE_CAPA_NOTIFY       = 1LL<<24, /* draft-martin-sieve-notify-01 */

    /* Ihave - RFC 5463 */
    SIEVE_CAPA_IHAVE        = 1LL<<25,

    /* Mailbox & Metadata - RFC 5490 */
    SIEVE_CAPA_MAILBOX      = 1LL<<26,
    SIEVE_CAPA_MBOXMETA     = 1LL<<27,
    SIEVE_CAPA_SERVERMETA   = 1LL<<28,

    /* MIME Part Handling - RFC 5703 */
    SIEVE_CAPA_ENCLOSE      = 0LL<<29, /* currently unsupported */
    SIEVE_CAPA_EXTRACT      = 0LL<<30, /* currently unsupported */
    SIEVE_CAPA_FOREVERYPART = 0LL<<31, /* currently unsupported */
    SIEVE_CAPA_MIME         = 0LL<<32, /* currently unsupported */
    SIEVE_CAPA_REPLACE      = 0LL<<33, /* currently unsupported */

    /* DSN & Deliver-By - RFC 6009 */
    SIEVE_CAPA_ENV_DELBY    = 0LL<<34, /* currently unsupported */
    SIEVE_CAPA_ENV_DSN      = 0LL<<35, /* currently unsupported */
    SIEVE_CAPA_REDIR_DELBY  = 0LL<<36, /* currently unsupported */
    SIEVE_CAPA_REDIR_DSN    = 0LL<<37, /* currently unsupported */

    /* Vacation :seconds - RFC 6131 */
    SIEVE_CAPA_VACATION_SEC = 1LL<<38,

    /* External Lists - RFC 6134 */
    SIEVE_CAPA_EXTLISTS     = 1LL<<39,

    /* Convert - RFC 6558 */
    SIEVE_CAPA_CONVERT      = 0LL<<40, /* currently unsupported */

    /* Include - RFC 6609 */
    SIEVE_CAPA_INCLUDE      = 1LL<<41,

    /* IMAP Events - RFC 6785 */
    SIEVE_CAPA_IMAP         = 0LL<<42, /* currently unsupported */

    /* Duplicate - RFC 7352 */
    SIEVE_CAPA_DUPLICATE    = 1LL<<43,

    /* Special-Use - draft-bosch-sieve-special-use */
    SIEVE_CAPA_SPECIAL_USE  = 1LL<<44,

    /* Fcc - draft-murchison-sieve-fcc */
    SIEVE_CAPA_FCC          = 1LL<<45,
};

#define SIEVE_CAPA_ALL (SIEVE_CAPA_BASE           \
                        | SIEVE_CAPA_COMP_NUMERIC \
                        | SIEVE_CAPA_ENCODE_CHAR  \
                        | SIEVE_CAPA_ENVELOPE     \
                        | SIEVE_CAPA_FILEINTO     \
                        | SIEVE_CAPA_REGEX        \
                        | SIEVE_CAPA_COPY         \
                        | SIEVE_CAPA_BODY         \
                        | SIEVE_CAPA_ENVIRONMENT  \
                        | SIEVE_CAPA_VARIABLES    \
                        | SIEVE_CAPA_VACATION     \
                        | SIEVE_CAPA_RELATIONAL   \
                        | SIEVE_CAPA_IMAP4FLAGS   \
                        | SIEVE_CAPA_IMAPFLAGS    \
                        | SIEVE_CAPA_SUBADDRESS   \
                        | SIEVE_CAPA_SPAM         \
                        | SIEVE_CAPA_SPAMPLUS     \
                        | SIEVE_CAPA_VIRUS        \
                        | SIEVE_CAPA_DATE         \
                        | SIEVE_CAPA_INDEX        \
                        | SIEVE_CAPA_EDITHEADER   \
                        | SIEVE_CAPA_EREJECT      \
                        | SIEVE_CAPA_REJECT       \
                        | SIEVE_CAPA_ENOTIFY      \
                        | SIEVE_CAPA_NOTIFY       \
                        | SIEVE_CAPA_IHAVE        \
                        | SIEVE_CAPA_MAILBOX      \
                        | SIEVE_CAPA_MBOXMETA     \
                        | SIEVE_CAPA_SERVERMETA   \
                        | SIEVE_CAPA_ENCLOSE      \
                        | SIEVE_CAPA_EXTRACT      \
                        | SIEVE_CAPA_FOREVERYPART \
                        | SIEVE_CAPA_MIME         \
                        | SIEVE_CAPA_REPLACE      \
                        | SIEVE_CAPA_ENV_DELBY    \
                        | SIEVE_CAPA_ENV_DSN      \
                        | SIEVE_CAPA_REDIR_DELBY  \
                        | SIEVE_CAPA_REDIR_DSN    \
                        | SIEVE_CAPA_VACATION_SEC \
                        | SIEVE_CAPA_EXTLISTS     \
                        | SIEVE_CAPA_CONVERT      \
                        | SIEVE_CAPA_INCLUDE      \
                        | SIEVE_CAPA_IMAP         \
                        | SIEVE_CAPA_DUPLICATE    \
                        | SIEVE_CAPA_SPECIAL_USE  \
                        | SIEVE_CAPA_FCC          \
                        )

#define SIEVE_CAPA_IHAVE_INCOMPAT (SIEVE_CAPA_ENCODE_CHAR | SIEVE_CAPA_VARIABLES)

unsigned long long lookup_capability(const char *str);
unsigned long long extension_isactive(sieve_interp_t *interp, const char *str);
int interp_verify(sieve_interp_t *interp);

#endif
