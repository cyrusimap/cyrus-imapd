/* lex.h
 * Tim Martin
 * 9/21/99
 */
/*
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

#ifndef _LEX_H_
#define _LEX_H_

#include "util.h"

typedef struct lexstate_s
{
    char *str;
    int number;

} lexstate_t;

int yylex(lexstate_t *lvalp, void *client);

enum {
    TAG = 258,
    EOL = 259,
    STRING = 260,
    NUMBER = 261,

    TOKEN_OK = 280,
    TOKEN_NO = 281,
    TOKEN_BYE = 282,

    TOKEN_ACTIVE = 291,

    TOKEN_REFERRAL = 301,
    TOKEN_SASL = 302,
    RESP_CODE_QUOTA = 303,
    RESP_CODE_QUOTA_MAXSCRIPTS = 304,
    RESP_CODE_QUOTA_MAXSIZE = 305,
    RESP_CODE_TRANSITION_NEEDED = 306,
    RESP_CODE_TRYLATER = 307,
    RESP_CODE_NONEXISTENT = 308,
    RESP_CODE_ALREADYEXISTS = 309,
    RESP_CODE_WARNINGS = 310,
    RESP_CODE_TAG = 311
};

enum {
    LEXER_STATE_TAG = 60,
    LEXER_STATE_RECOVER,
    LEXER_STATE_RECOVER_CR,
    LEXER_STATE_CR,
    LEXER_STATE_QSTR,
    LEXER_STATE_LITERAL,
    LEXER_STATE_NUMBER,
    LEXER_STATE_NORMAL,
    LEXER_STATE_ATOM
};

#endif /* _LEX_H_ */
