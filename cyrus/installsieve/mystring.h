/* mystring.h
 * Tim Martin
 * 9/21/99
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

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

#define string_DATAPTR(s) (((char *) s)+sizeof(mystring_t))

int safe_to_use_quoted(char *str, int len);


#endif /* INCLUDED_MYSTRING_H */
