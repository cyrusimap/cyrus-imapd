/* interp.h -- interpretor definition
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
    sieve_get_metadata *getmetadata;

    sieve_list_validator *isvalidlist;
    sieve_list_comparator *listcompare;

    sieve_parse_error *err;

    /* site-specific imapflags for mark/unmark */
    const strarray_t *markflags;

    sieve_execute_error *execute_err;

    char *lastitem;

    /* context to pass along */
    void *interp_context;
    char extensions[4096];//the number comes from interp.c EXT_LEN

    /* time when allocated */
    time_t time;
};

int interp_verify(sieve_interp_t *interp);

#endif
