/* imapparse.h - Header for IMAP parsing functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
