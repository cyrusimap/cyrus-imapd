/* lex.c -- lexer for timsieved
 * Tim Martin
 * 9/21/99
 * $Id: lex.c,v 1.19.4.2 2002/10/04 20:47:26 ken3 Exp $
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "prot.h"
#include "tls.h"
#include "lex.h"
#include "codes.h"
#include "mystring.h"
#include "actions.h"
#include "imapconf.h"
#include "xmalloc.h"

int token_lookup (char *str, int len __attribute__((unused)))
{
    switch (*str) {
    case 'a':
	if (strcmp(str, "authenticate")==0) return AUTHENTICATE;
	break;

    case 'c':
	if (strcmp(str, "capability")==0) return CAPABILITY;
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

    case 'p':
	if (strcmp(str, "putscript")==0) return PUTSCRIPT;
	break;

    case 's':
	if (strcmp(str, "setactive")==0) return SETACTIVE;
	if (strcmp(str, "starttls")==0 && tls_enabled())
	    return STARTTLS;
	break;
    }

    /* error, nothing matched */
    return -1;
}

/* current state the lexer is in */
int lexer_state = LEXER_STATE_NORMAL;

extern struct protstream *sieved_out;

#define ERR() {								\
		lexer_state=LEXER_STATE_RECOVER;                        \
		return TIMSIEVE_FAIL;                                   \
  	      }

#define ERR_PUSHBACK() {				\
    		prot_ungetc(ch, stream);                \
		ERR();					\
  	      }

int lex_reset(void)
{
  lexer_state = LEXER_STATE_NORMAL;

  return 0;
}

void lex_setrecovering(void)
{
  lexer_state = LEXER_STATE_RECOVER;
}

int maxscriptsize=0;
char *buffer;

int lex_init(void)
{
  maxscriptsize = config_getint(IMAPOPT_SIEVE_MAXSCRIPTSIZE);
  maxscriptsize *= 1024;

  buffer = (char *) xmalloc(maxscriptsize);

  return 0;
}

/**
 * if outstr is NULL it isn't filled in
 */

int timlex(mystring_t **outstr, unsigned long *outnum,  struct protstream *stream)
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
	/* Lost conenction -- treat like a logout */
	return LOGOUT;
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
	if (outstr!=NULL)
	{
	  *outstr = NULL;
	  result = string_allocate(buff_ptr - buffer, buffer, outstr);
	  if (result != TIMSIEVE_OK)
	    ERR_PUSHBACK();
	}
	  /*} */
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
	ERR_PUSHBACK();		/* too long! */
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
	  ERR_PUSHBACK();	/* overflow */
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
	  ERR();
      }

      if (outstr!=NULL)
      {
	*outstr = NULL;
	result = string_allocate(count, NULL, outstr);
	if (result != TIMSIEVE_OK)
	  ERR_PUSHBACK();
      }

      /* there is a literal string on the wire. let's read it */
      if (outstr!=NULL) {
	char           *it = string_DATAPTR(*outstr),
	               *end = it + count;

	while (it < end) {
	  *it=prot_getc(stream);
	  it++;
	}
      } else {
	/* just read the chars and throw them away */
	int lup;

	for (lup=0;lup<count;lup++)
	  prot_getc(stream);
      }
      lexer_state=LEXER_STATE_NORMAL;
      return STRING;
    case LEXER_STATE_NUMBER:

	if (isdigit((unsigned char) ch)) {
	    unsigned long   newcount = tmpnum * 10 + (ch - '0');

	    if (newcount < tmpnum)
		ERR_PUSHBACK();	/* overflow */
	    tmpnum = newcount;
	} else {
	    lexer_state=LEXER_STATE_NORMAL;
	    prot_ungetc(ch, stream);

	    if (outnum) *outnum = tmpnum;

	    return NUMBER;
	}
	
	break;
    case LEXER_STATE_NORMAL:
      if (isalpha((unsigned char) ch)) {
	lexer_state=LEXER_STATE_ATOM;
	*buff_ptr++ = tolower(ch);
	break;
      }
      if (isdigit((unsigned char) ch)) {
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
	break;
      default:
	return ch;
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


