
#ifndef _LEX_H_
#define _LEX_H_

#include "mystring.h"

typedef struct lexstate_s {
  string_t *str;
  int number;

} lexstate_t;


#define	TAG	258
#define	EOL	259
#define	STRING	260
#define NUMBER  261

#define TOKEN_OK      280
#define TOKEN_NO      281

#define LEXER_STATE_TAG         60
#define LEXER_STATE_RECOVER     61
#define LEXER_STATE_RECOVER_CR  62
#define LEXER_STATE_CR          63
#define LEXER_STATE_QSTR        64
#define LEXER_STATE_LITERAL     65
#define LEXER_STATE_NUMBER      66
#define LEXER_STATE_NORMAL      67
#define LEXER_STATE_ATOM        68



#endif
