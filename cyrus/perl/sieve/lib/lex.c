/* lex.c -- lexers for command line script installer
 * Tim Martin
 * $Id: lex.c,v 1.6.4.1 2003/02/13 20:33:28 rjs3 Exp $
 */
/*
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "prot.h"

#include "lex.h"

#include "codes.h"

/* current state the lexer is in */
int lexer_state = LEXER_STATE_NORMAL;

#define ACAP_MAX_QSTR_LEN 4096

#define ERR() {								\
		lexer_state=LEXER_STATE_RECOVER;                        \
		return SIEVE_FAIL;                                       \
  	      }

#define ERR_PUSHBACK() {				\
    		prot_ungetc(ch, stream);                \
		ERR();					\
  	      }

int token_lookup(char *str, int len)
{
  if (strcmp(str,"ok")==0) return TOKEN_OK;
  if (strcmp(str,"no")==0) return TOKEN_NO;
  if (strcmp(str,"bye")==0) return TOKEN_BYE;
  if (strcmp(str,"active")==0) return TOKEN_ACTIVE;
  if (strcmp(str,"referral")==0) return TOKEN_REFERRAL;
  if (strcmp(str,"sasl")==0) return TOKEN_SASL;
  
  return -1;
}

int yylex(lexstate_t * lvalp, void * client)
{
  int ch;
  char buffer[ACAP_MAX_QSTR_LEN];	/* big enough for everything */

  char *buff_ptr = buffer; /* ptr into the buffer */
  char *buff_end = buffer + ACAP_MAX_QSTR_LEN -1;

  unsigned long count=0;

  int result = SIEVE_OK;

  int synchronizing;  /* wheather we are in the process of reading a
			 synchronizing string or not */

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
	lvalp->str = NULL;
	result = string_allocate(buff_ptr - buffer, buffer, &lvalp->str);
	if (result != SIEVE_OK)
	    ERR_PUSHBACK();
	lexer_state=LEXER_STATE_NORMAL;
	return STRING;
      }
      if (ch == '\0'
	  || 0x7F < ((unsigned char)ch))
	ERR_PUSHBACK();
      /* Otherwise, we're appending a character */
      if (buff_end <= buff_ptr)
	ERR_PUSHBACK();		/* too long! */
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
	  ERR_PUSHBACK();	/* overflow */
	/*
	 * XXX This should be fatal if non-synchronizing.
	 */
	count = newcount;
	break;
      }
      synchronizing = FALSE;

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

      lvalp->str = NULL;
      result = string_allocate(count, NULL, &lvalp->str);
      if (result != SIEVE_OK)
	ERR_PUSHBACK();

      /* there is a literal string on the wire. let's read it */
      {
	char           *it = string_DATAPTR(lvalp->str),
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
	  ERR_PUSHBACK();	/* overflow */
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
	synchronizing = TRUE;
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
      if (!isalpha((unsigned char) ch)) {
	int token;

	buffer[ buff_ptr - buffer] = '\0';

	/* We've got the atom. */
	token = token_lookup((char *) buffer, (int) (buff_ptr - buffer));

	if (token!=-1) {
	  lexer_state=LEXER_STATE_NORMAL;
	  prot_ungetc(ch, stream);

	  return token;
	} else
	  ERR_PUSHBACK();
      }
      if (buff_end <= buff_ptr)
	ERR_PUSHBACK();		/* atom too long */
      *buff_ptr++ = tolower(ch);
      break;
    }



  } /* while (1) */

  return 0;
}


