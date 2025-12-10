/* imapparse.h -- Header for IMAP parsing functions
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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

#ifndef __CYRUS_IMAP_PARSE_H__
#define __CYRUS_IMAP_PARSE_H__

#include "libconfig.h"
#include "prot.h"
#include "index.h"

/* imap parsing functions (imapparse.c) */
int getword(struct protstream *in, struct buf *buf);

/* Flags for getxstring() */
/* IMAP_BIN_ASTRING is an IMAP_ASTRING that does not perform the
 * does-not-contain-a-NULL check (in the case of a literal) */
enum getxstring_flags {
    GXS_ATOM    = (1<<0),   /* result may be a bare atom */
    GXS_QUOTED  = (1<<1),   /* result may be "quoted" */
    GXS_LITERAL = (1<<2),   /* result may be {N}literal */
    GXS_NIL     = (1<<3),   /* result may be the special atom NIL */
    GXS_BINARY  = (1<<4),   /* result may contain embedded NULs */
    GXS_MUPDATE = (1<<5),   /* (non-IMAP) accept LITERAL+ as client */

    IMAP_ASTRING = GXS_ATOM|GXS_QUOTED|GXS_LITERAL,
    IMAP_BIN_ASTRING = IMAP_ASTRING|GXS_BINARY,
    IMAP_NSTRING = GXS_NIL|GXS_QUOTED|GXS_LITERAL,
    IMAP_BIN_NSTRING = IMAP_NSTRING|GXS_BINARY,
    IMAP_QSTRING = GXS_QUOTED,
    IMAP_STRING = GXS_QUOTED|GXS_LITERAL,

    /* note: there's some consistency issues here... the special
     * value "NIL" must be quoted to get returned as a string */
    IMAP_NASTRING = GXS_NIL|GXS_ATOM|GXS_QUOTED|GXS_LITERAL,

    MUPDATE_STRING = IMAP_STRING|GXS_MUPDATE,
};

int getxstring(struct protstream *pin, struct protstream *pout,
               struct buf *buf, enum getxstring_flags);
#define getastring(pin, pout, buf) getxstring((pin), (pout), (buf), IMAP_ASTRING)
#define getbastring(pin, pout, buf) getxstring((pin), (pout), (buf), IMAP_BIN_ASTRING)
#define getnstring(pin, pout, buf) getxstring((pin), (pout), (buf), IMAP_NSTRING)
#define getbnstring(pin, pout, buf) getxstring((pin), (pout), (buf), IMAP_BIN_NSTRING)
#define getqstring(pin, pout, buf) getxstring((pin), (pout), (buf), IMAP_QSTRING)
#define getstring(pin, pout, buf) getxstring((pin), (pout), (buf), IMAP_STRING)
#define getnastring(pin, pout, buf) getxstring((pin), (pout), (buf), IMAP_NASTRING)
#define getmstring(pin, pout, buf) getxstring((pin), (pout), (buf), MUPDATE_STRING)
#define getcharset(pin, pout, buf) getxstring((pin), (pout), (buf), GXS_ATOM|GXS_QUOTED)
int getint32(struct protstream *pin, int *num);
int getint64(struct protstream *pin, int64_t *num);
int getsint32(struct protstream *pin, int *num);
int getsint64(struct protstream *pin, int64_t *num);
int getuint32(struct protstream *pin, unsigned int *num);
int getuint64(struct protstream *pin, uint64_t *num);
int getmodseq(struct protstream *pin, modseq_t *num);

void eatline(struct protstream *pin, int c);

int get_search_program(struct protstream *pin, struct protstream *pout,
                       unsigned client_quirks, struct searchargs *searchargs);
int get_search_return_opts(struct protstream *pin, struct protstream *pout,
                           struct searchargs *searchargs);

#endif /* __CYRUS_IMAP_PARSE_H__ */
