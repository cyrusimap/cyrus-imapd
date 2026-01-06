/* lex.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _LEX_H_
#define _LEX_H_

#include "util.h"

typedef struct lexstate_s {
  char *str;
  int number;

} lexstate_t;

int yylex(lexstate_t * lvalp, void * client);

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
