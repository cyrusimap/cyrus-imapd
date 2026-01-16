/* lex.h - lexer for timsieved */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _LEX_H_
#define _LEX_H_

#include "prot.h"
#include "util.h"

#define LEXER_STATE_RECOVER     61
#define LEXER_STATE_RECOVER_CR  62
#define LEXER_STATE_CR          63
#define LEXER_STATE_QSTR        64
#define LEXER_STATE_LITERAL     65
#define LEXER_STATE_NUMBER      66
#define LEXER_STATE_NORMAL      67
#define LEXER_STATE_ATOM        68


/* possible tokens */

#define SPACE 32

/* these must be above 255 */
#define EOL          300
#define STRING       301
#define NUMBER       302

#define AUTHENTICATE 400
#define LOGOUT       401
#define GETSCRIPT    402
#define PUTSCRIPT    403
#define SETACTIVE    404
#define LISTSCRIPTS  405
#define DELETESCRIPT 406
#define CAPABILITY   407
#define HAVESPACE    408
#define STARTTLS     409
#define NOOP         410
#define UNAUTHENTICATE 411
#define CHECKSCRIPT  412
#define RENAMESCRIPT 413


void lex_init(void);

int timlex(struct buf *outstr, unsigned long *outnum,  struct protstream *stream);

void lex_setrecovering(void);

#endif
