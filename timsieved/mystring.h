/* mystring.h -- base datatype used by timsieved
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


#ifndef _STRING_H_
#define _STRING_H_

typedef struct {
  int        len;
  /* Data immediately following... */
}  string_t;


int string_allocate(int length,
		    const char *buf,	/* NULL => no copy */
		    string_t ** str);

int string_copy(string_t *oldstr,
		string_t **newstr);

void string_free(string_t **str);

int string_compare(string_t *str1, string_t *str2);

int string_comparestr(string_t *str1, char *str2);

int string_compare_with(string_t *str1, string_t *str2, string_t *comp);

/*eq_result_t
  string_equal_cstr(const string_t * str, const char *cstr);*/

#define string_DATAPTR(s) (((char *) s)+sizeof(string_t))

int safe_to_use_quoted(char *str, int len);


#endif /* _STRING__H */
