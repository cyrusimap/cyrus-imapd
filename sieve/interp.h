/* interp.h -- interpretor definition
 * Larry Greenfield
 * $Id: interp.h,v 1.7.4.1 2003/02/27 18:13:52 rjs3 Exp $
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
*****************************************************************/

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
    sieve_get_envelope *getenvelope;

    sieve_parse_error *err;

    /* site-specific imapflags for mark/unmark */
    sieve_imapflags_t *markflags;

    sieve_execute_error *execute_err;

    /* context to pass along */
    void *interp_context;
};

int interp_verify(sieve_interp_t *interp);

#endif
