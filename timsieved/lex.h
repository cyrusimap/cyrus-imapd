/* lex.h -- lexer for timsieved
 * Tim Martin
 * 9/21/99
 * $Id: lex.h,v 1.6 2000/01/28 22:09:56 leg Exp $
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


#ifndef _LEX_H_
#define _LEX_H_

#include "prot.h"
#include "mystring.h"

#define LEXER_STATE_TAG         60
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
#define AUTHENTICATE 302
#define LOGOUT       304
#define GETSCRIPT    305
#define PUTSCRIPT    306
#define SETACTIVE    307
#define LISTSCRIPTS  308
#define DELETESCRIPT 309


int lex_init(void);

int timlex(mystring_t **outstr,   struct protstream *stream);

void lex_setrecovering(void);

#endif
