/* lex.h -- lexer for timsieved
 * Tim Martin
 * 9/21/99
 * $Id: lex.h,v 1.10 2001/10/14 13:58:17 ken3 Exp $
 */
/*
 * Copyright (c) 1999-2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 */


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


int lex_init(void);

int timlex(mystring_t **outstr, unsigned long *outnum,  struct protstream *stream);

void lex_setrecovering(void);

#endif
