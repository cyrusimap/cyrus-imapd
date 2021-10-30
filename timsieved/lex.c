/* lex.c -- lexer for timsieved
 * Tim Martin
 * 9/21/99
 *
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "libconfig.h"
#include "xmalloc.h"
#include "imap/global.h"
#include "imap/tls.h"
#include "timsieved/codes.h"
#include "timsieved/lex.h"

static int token_lookup(const char *str)
{
    switch (*str) {
    case 'a':
        if (strcmp(str, "authenticate")==0) return AUTHENTICATE;
        break;

    case 'c':
        if (strcmp(str, "capability")==0) return CAPABILITY;
        if (strcmp(str, "checkscript")==0) return CHECKSCRIPT;
        break;

    case 'd':
        if (strcmp(str, "deletescript")==0) return DELETESCRIPT;
        break;

    case 'g':
        if (strcmp(str, "getscript")==0) return GETSCRIPT;
        break;

    case 'h':
        if (strcmp(str, "havespace")==0) return HAVESPACE;
        break;

    case 'l':
        if (strcmp(str, "listscripts")==0) return LISTSCRIPTS;
        if (strcmp(str, "logout")==0) return LOGOUT;
        break;

    case 'n':
        if (strcmp(str, "noop")==0) return NOOP;
        break;

    case 'p':
        if (strcmp(str, "putscript")==0) return PUTSCRIPT;
        break;

    case 'r':
        if (strcmp(str, "renamescript")==0) return RENAMESCRIPT;
        break;

    case 's':
        if (strcmp(str, "setactive")==0) return SETACTIVE;
        if (strcmp(str, "starttls")==0 && tls_enabled())
            return STARTTLS;
        break;

    case 'u':
        if (strcmp(str, "unauthenticate")==0) return UNAUTHENTICATE;
        break;
    }

    /* error, nothing matched */
    return -1;
}

/* current state the lexer is in */
static int lexer_state = LEXER_STATE_NORMAL;
HIDDEN unsigned long maxscriptsize = 0;
static char *buffer;

#define ERR() {                                                         \
                lexer_state=LEXER_STATE_RECOVER;                        \
                return TIMSIEVE_FAIL;                                   \
              }

#define ERR_PUSHBACK() {                                \
                prot_ungetc(ch, stream);                \
                ERR();                                  \
              }

void lex_setrecovering(void)
{
  lexer_state = LEXER_STATE_RECOVER;
}

void lex_init(void)
{
  maxscriptsize = config_getint(IMAPOPT_SIEVE_MAXSCRIPTSIZE) * 1024;

  buffer = (char *) xmalloc(maxscriptsize);
}

/**
 * if outstr is NULL it isn't filled in
 */

int timlex(struct buf *outstr, unsigned long *outnum,  struct protstream *stream)
{

  int ch;

  char *buff_ptr;
  char *buff_end;
  unsigned long tmpnum = 0;
  unsigned long count=0;

  int result = TIMSIEVE_OK;


  buff_ptr = buffer; /* ptr into the buffer */
  buff_end = buffer + maxscriptsize - 10; /* ptr to end of buffer */


  while (1)
  {

    /* get a character
       this may block on a read if there is nothing
       in the buffer */

    ch=prot_getc(stream);

    if (ch==EOF) {
        /* Lost connection */
        return EOF;
    }

    switch (lexer_state)
    {


    case LEXER_STATE_RECOVER:
      if (ch == '\n') {
        lexer_state=LEXER_STATE_NORMAL;
      }
      if (ch == '\r')
        lexer_state=LEXER_STATE_RECOVER_CR;
      break;
    case LEXER_STATE_RECOVER_CR:
      if (ch == '\n')
        lexer_state=LEXER_STATE_NORMAL;
      break;
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
          /*} */
        if (outstr) {
            buf_appendmap(outstr, buffer, buff_ptr-buffer);
            buf_cstring(outstr);
        }
        lexer_state=LEXER_STATE_NORMAL;
        return STRING;
      }
      /* illegal character */
      if (ch == '\0'
          || ch == '\r'
          || ch == '\n'
          || 0x7F < ((unsigned char)ch))
      {
        ERR_PUSHBACK();
      }

      /* Otherwise, we're appending a character */
      if (buff_end <= buff_ptr)
        ERR_PUSHBACK();         /* too long! */
      if (ch == '\\') {
        ch=prot_getc(stream);

        if (result != TIMSIEVE_OK)
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
        /*
         * XXX This should be fatal if non-synchronizing.
         */
        count = newcount;
        break;
      }
      if (ch != '+')
        ERR_PUSHBACK();
      ch=prot_getc(stream);
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

      if (count > maxscriptsize) {
          /* too big, eat the input */
          for(;count > 0;count--) {
              if(prot_getc(stream)==EOF)
                  break;
          }

          ERR();
      }

      /* there is a literal string on the wire. let's read it */
      if (outstr) {
          for (;count > 0;count--) {
              ch = prot_getc(stream);
              if (ch == EOF)
                    break;
              buf_putc(outstr, ch);
          }
          buf_cstring(outstr);
      } else {
        /* just read the chars and throw them away */
        unsigned long lup;

        for (lup=0;lup<count;lup++)
          (void)prot_getc(stream);
      }
      lexer_state=LEXER_STATE_NORMAL;
      return STRING;
    case LEXER_STATE_NUMBER:

        if (Uisdigit(ch)) {
            unsigned long   newcount = tmpnum * 10 + (ch - '0');

            if (newcount < tmpnum)
                ERR_PUSHBACK(); /* overflow */
            tmpnum = newcount;
        } else {
            lexer_state=LEXER_STATE_NORMAL;
            prot_ungetc(ch, stream);

            if (outnum) *outnum = tmpnum;

            return NUMBER;
        }

        break;
    case LEXER_STATE_NORMAL:
      if (Uisalpha(ch)) {
        lexer_state=LEXER_STATE_ATOM;
        *buff_ptr++ = tolower(ch);
        break;
      }
      if (Uisdigit(ch)) {
        lexer_state=LEXER_STATE_NUMBER;
        tmpnum = ch -'0';
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
      default:
        return ch;
      }
      break;
    case LEXER_STATE_ATOM:
      if (!Uisalpha(ch)) {
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
