/* lex.c - lexers for command line script installer */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "prot.h"
#include "xmalloc.h"
#include "perl/sieve/lib/codes.h"
#include "perl/sieve/lib/lex.h"

/* current state the lexer is in */
static int lexer_state = LEXER_STATE_NORMAL;

#define ACAP_MAX_QSTR_LEN 4096

#define ERR() {                                                         \
                lexer_state=LEXER_STATE_RECOVER;                        \
                return SIEVE_FAIL;                                       \
              }

#define ERR_PUSHBACK() {                                \
                prot_ungetc(ch, stream);                \
                ERR();                                  \
              }

static int token_lookup(const char *str)
{
  if (strcmp(str,"ok")==0) return TOKEN_OK;
  if (strcmp(str,"no")==0) return TOKEN_NO;
  if (strcmp(str,"bye")==0) return TOKEN_BYE;
  if (strcmp(str,"active")==0) return TOKEN_ACTIVE;
  if (strcmp(str,"referral")==0) return TOKEN_REFERRAL;
  if (strcmp(str,"sasl")==0) return TOKEN_SASL;
  if (strcmp(str,"quota/maxscripts")==0) return RESP_CODE_QUOTA_MAXSCRIPTS;
  if (strcmp(str,"quota/maxsize")==0) return RESP_CODE_QUOTA_MAXSIZE;
  if (strcmp(str,"quota")==0) return RESP_CODE_QUOTA;
  if (strcmp(str,"transition-needed")==0) return RESP_CODE_TRANSITION_NEEDED;
  if (strcmp(str,"trylater")==0) return RESP_CODE_TRYLATER;
  if (strcmp(str,"nonexistent")==0) return RESP_CODE_NONEXISTENT;
  if (strcmp(str,"alreadyexists")==0) return RESP_CODE_ALREADYEXISTS;
  if (strcmp(str,"warning")==0) return RESP_CODE_WARNINGS;
  if (strcmp(str,"tag")==0) return RESP_CODE_TAG;

  return -1;
}

int yylex(lexstate_t * lvalp, void * client)
{
  int ch;
  char buffer[ACAP_MAX_QSTR_LEN];       /* big enough for everything */

  char *buff_ptr = buffer; /* ptr into the buffer */
  char *buff_end = buffer + ACAP_MAX_QSTR_LEN -1;

  unsigned long count=0;

  int result = SIEVE_OK;

  struct protstream *stream=(struct protstream *) client;

  while (1)
  {

    /* get a character
       this may block on a read if there is nothing
       in the buffer */

    ch = prot_getc(stream);

    if (ch == -1)
        return SIEVE_FAIL;

    switch (lexer_state)
    {


    case LEXER_STATE_RECOVER:
      if (ch == '\r')
        lexer_state=LEXER_STATE_RECOVER_CR;
      break;
    case LEXER_STATE_RECOVER_CR:
      if (ch == '\n')
        lexer_state=LEXER_STATE_NORMAL;
      return EOL;
    case LEXER_STATE_CR:
      if (ch == '\n') {
        lexer_state=LEXER_STATE_NORMAL;
        return EOL;
      }
      /* otherwise, life is bad */
      ERR_PUSHBACK();
    case LEXER_STATE_QSTR:
      if (ch == '\"') {
        /* End of the string */
        lvalp->str = xstrndup(buffer, buff_ptr - buffer);
        lexer_state=LEXER_STATE_NORMAL;
        return STRING;
      }
      if (ch == '\0'
          || 0x7F < ((unsigned char)ch))
        ERR_PUSHBACK();
      /* Otherwise, we're appending a character */
      if (buff_end <= buff_ptr)
        ERR_PUSHBACK();         /* too long! */
      if (ch == '\\') {
        ch=prot_getc(stream);

        if (result != SIEVE_OK)
          ERR();
        if (ch != '\"' && ch != '\\')
          ERR_PUSHBACK();
      }
      *buff_ptr++ = ch;
      break;
    case LEXER_STATE_LITERAL:
      if (('0' <= ch) && (ch <= '9')) {
        unsigned long   newcount = count * 10 + (ch - '0');

        if (newcount < count)
          ERR_PUSHBACK();       /* overflow */

        count = newcount;
        break;
      }

      if (ch != '}')
        ERR_PUSHBACK();
      ch=prot_getc(stream);
      if (ch < 0)
        ERR();
      if (ch != '\r')
        ERR_PUSHBACK();
      ch=prot_getc(stream);
      if (ch < 0)
        ERR();
      if (ch != '\n')
        ERR_PUSHBACK();

      lvalp->str = (char *)xmalloc(count+1);
      /* there is a literal string on the wire. let's read it */
      {
        char           *it = lvalp->str,
                       *end = it + count;

        while (it < end) {
          *it=prot_getc(stream);
          it++;
        }
        *it = '\0';
      }
      lexer_state=LEXER_STATE_NORMAL;
      return STRING;
    case LEXER_STATE_NUMBER:
      if (('0' <= ch) && (ch <= '9')) {
        unsigned long   newcount = count * 10 + (ch - '0');

        if (newcount < count)
          ERR_PUSHBACK();       /* overflow */
        count = newcount;
      } else {
        lvalp->number = count;
        lexer_state=LEXER_STATE_NORMAL;
        prot_ungetc(ch, stream);
        return NUMBER;
      }
      break;
    case LEXER_STATE_NORMAL:
      if (isalpha((unsigned char) ch)) {
        lexer_state=LEXER_STATE_ATOM;
        *buff_ptr++ = tolower(ch);
        break;
      }
      switch (ch) {
      case '(':
        return '(';
      case ')':
        return ')';
      case ' ':
        return ' ';
      case '\"':
        lexer_state=LEXER_STATE_QSTR;
        break;
      case '*':
        return '*';
      case '0': /* fall through all numbers */
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        count = ch - '0';
        lexer_state=LEXER_STATE_NUMBER;
        break;
      case '{':
        count = 0;
        lexer_state=LEXER_STATE_LITERAL;
        break;
      case '\r':
        lexer_state=LEXER_STATE_CR;
        break;
      case '\n':
        lexer_state=LEXER_STATE_NORMAL;
        return EOL;
        break;
      default:
        ERR_PUSHBACK();
      }
      break;
    case LEXER_STATE_ATOM:
      if (!(isalpha((unsigned char) ch) || ch == '/')) {
        int token;

        *buff_ptr = '\0';

        /* We've got the atom. */
        token = token_lookup(buffer);

        if (token!=-1) {
          lexer_state=LEXER_STATE_NORMAL;
          prot_ungetc(ch, stream);

          return token;
        } else
          ERR_PUSHBACK();
      }
      if (buff_end <= buff_ptr)
        ERR_PUSHBACK();         /* atom too long */
      *buff_ptr++ = tolower(ch);
      break;
    }

  } /* while (1) */

  /* never reached */
}
