#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "prot.h"

#include "lex.h"

#include "codes.h"


#include "parse.tab.h"

/* current state the lexer is in */
int lexer_state = LEXER_STATE_NORMAL;

extern struct protstream *sieved_out;

#define ACAP_MAX_QSTR_LEN 4096

#define ERR() {								\
		lexer_state=LEXER_STATE_RECOVER;                        \
		return TIMSIEVE_FAIL;                                       \
                /*  (result == DAEMON_ERR_EOF ? EOF : ERROR);*/	        \
  	      }

#define ERR_PUSHBACK() {				\
    		prot_ungetc(ch, stream);                \
		ERR();					\
  	      }

int lex_reset(void)
{
  lexer_state = LEXER_STATE_NORMAL;
}

int timlex(YYSTYPE * lvalp, void * client)
{
  int ch;
  char buffer[ACAP_MAX_QSTR_LEN];	/* big enough for everything */

  char *buff_ptr = buffer; /* ptr into the buffer */
  char *buff_end = buffer + ACAP_MAX_QSTR_LEN -1;

  unsigned long count;

  int result;

  int synchronizing=TRUE;  /* wheather we are in the process of reading a
			      synchronizing string or not */

  FILE *foo;

  struct protstream *stream=(struct protstream *) client;
  
  while (1)
  {

    /* get a character
       this may block on a read if there is nothing
       in the buffer */

    ch=prot_getc(stream);

    if (ch==-1) return TIMSIEVE_FAIL;

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
	/*	if (! client->recovering) { */
	  result = string_allocate(buff_ptr - buffer, buffer, &lvalp->str);
	  if (result != TIMSIEVE_OK)
	    ERR_PUSHBACK();
	  /*} */
	lexer_state=LEXER_STATE_NORMAL;
	return STRING;
      }
      if (ch == '\0'
	  || ch == '\r'
	  || ch == '\n'
	  || 0x7F < ((unsigned char)ch))
	ERR_PUSHBACK();
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
      if (ch == '+') {
	synchronizing = FALSE;
	ch=prot_getc(stream);
	if (ch < 0)
	  ERR();
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
      if (synchronizing==TRUE) {
	static const char sync_reply[] = "\"Ready for data\"\r\n";

	prot_printf(sieved_out, sync_reply);
	prot_flush(sieved_out);
      }

      if (count > config_getint("maxscriptsize",32000))
	ERR();

      lvalp->str = NULL;
      result = string_allocate(count, NULL, &lvalp->str);
      if (result != TIMSIEVE_OK)
	ERR_PUSHBACK();

      /* there is a literal string on the wire. let's read it */
      {
	char           *it = string_DATAPTR(lvalp->str),
	               *end = it + count;

	while (it < end) {
	  *it=prot_getc(stream);
	  it++;
	}
      }
      lexer_state=LEXER_STATE_NORMAL;
      return STRING;
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


