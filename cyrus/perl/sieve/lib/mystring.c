/* mystring.c -- string utility
 * Tim Martin
 * 9/21/99
 * $Id: mystring.c,v 1.6 2002/05/25 19:57:50 leg Exp $
 */
/*
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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

#include "mystring.h"
#include "codes.h"

#include <stdlib.h>
#include <string.h>

int string_allocate(int length,
		    const char *buf,	/* NULL => no copy */
		    mystring_t ** str)
{
  *str=(mystring_t *) malloc(sizeof(mystring_t)+length+3);

  (*str)->len=length;
  ((char *) (*str))[sizeof(mystring_t)+length]='\0';

  if (buf==NULL) return SIEVE_OK;

  /* copy the data into the string object */
  memcpy(((char *)(*str))+sizeof(mystring_t), buf, length);
  ((char *) (*str))[sizeof(mystring_t)+length]='\0';

  return SIEVE_OK;
}


int string_copy(mystring_t *oldstr,
		mystring_t **newstr)
{
  int result;


  result=string_allocate(oldstr->len,
			 string_DATAPTR(oldstr),
			 newstr);

  return result;
}


void string_free(mystring_t **str)
{
  free(*str);
}


int string_compare(mystring_t *str1, mystring_t *str2)
{
  char *data1;
  char *data2;
  int lup;

  if (str1->len!=str2->len) return SIEVE_FAIL;

  data1=string_DATAPTR(str1);
  data2=string_DATAPTR(str2);

  for (lup=0;lup<str1->len;lup++)
    if (data1[lup]!=data2[lup])
      return SIEVE_FAIL;

  return SIEVE_OK;
}

int string_compare_with(mystring_t *str1, mystring_t *str2, mystring_t *comp)
{
  char *data1;
  char *data2;
  int lup;

  int len1=str1->len;
  int len2=str2->len;

  int low=len1;
  if (len2<len1)
    low=len2;

  /*  printf("comparing %s and %s\n",string_DATAPTR(str1),
      string_DATAPTR(str2));*/

  data1=string_DATAPTR(str1);
  data2=string_DATAPTR(str2);

  for (lup=0;lup<low;lup++)
    if (data1[lup]<data2[lup])
    {
      return -1;
    } else if (data1[lup]>data2[lup]) {
      return 1;
    } else {
      /* continue */
    }
  
  if (len1==len2) return 0;

  if (len1<len2)
    return -1;

  return 1;
}

int string_comparestr(mystring_t *str1, char *str2)
{
  int str2len=strlen(str2);
  char *data1;
  char *data2;
  int lup;

  if (str1->len!=str2len) return SIEVE_FAIL;

  data1=string_DATAPTR(str1);
  data2=str2;

  for (lup=0;lup<str1->len;lup++)
    if (data1[lup]!=data2[lup])
      return SIEVE_FAIL;

  return SIEVE_OK;
}
/*
eq_result_t
string_equal_cstr(const mystring_t * str, const char *cstr)
{
  int        len;

  I(str);
  I(cstr);

  len = strlen(cstr);
  if (len != str->len)
    return EQ_NOT_EQUAL;

  if (memcmp(string_DATAPTR(str), cstr, len)==0)
    return EQ_IS_EQUAL;


  return EQ_NOT_EQUAL; 
}
*/

int safe_to_use_quoted(char *str, int len)
{
  char *end=str+len;

  if (len > 4096)
    return FALSE;

  while (str < end) {
    if (*str == '\0'		/* check illegal chars... */
	|| *str == '\r'
	|| *str == '\n'

#ifdef __CHAR_UNSIGNED__
	|| 0x7F < *str
#else
	|| *str < 0
#endif

      )
      return FALSE;
    if (*str == '\"'		/* check len, with \ escapes... */
	|| *str == '\\')
      if (4096 < ++len)
	return FALSE;
    ++str;
  }
  return TRUE;
}
