/* mystring.h
 * Tim Martin
 * 9/21/99
 * $Id: mystring.h,v 1.4 2002/05/25 19:57:50 leg Exp $
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

#include "codes.h"


#ifndef INCLUDED_MYSTRING_H
#define INCLUDED_MYSTRING_H

typedef struct {
  int        len;
  /* Data immediately following... */
}  mystring_t;


int string_allocate(int length,
		    const char *buf,	/* NULL => no copy */
		    mystring_t ** str);

int string_copy(mystring_t *oldstr,
		mystring_t **newstr);

void string_free(mystring_t **str);

int string_compare(mystring_t *str1, mystring_t *str2);

int string_comparestr(mystring_t *str1, char *str2);

int string_compare_with(mystring_t *str1, mystring_t *str2, mystring_t *comp);

/*eq_result_t
  string_equal_cstr(const mystring_t * str, const char *cstr);*/

#define string_DATAPTR(s) (s ? (((char *) s)+sizeof(mystring_t)) : 0)

int safe_to_use_quoted(char *str, int len);


#endif /* INCLUDED_MYSTRING_H */
