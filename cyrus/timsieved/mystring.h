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
