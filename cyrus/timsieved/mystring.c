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
  *str=(mystring_t *) malloc(sizeof(mystring_t)+length+1);

  (*str)->len=length;

  if (buf==NULL) return TIMSIEVE_OK;

  /* copy the data into the string object */
  memcpy(((char *)(*str))+sizeof(mystring_t), buf, length);
  ((char *) (*str))[sizeof(mystring_t)+length]='\0';

  return TIMSIEVE_OK;
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

  if (str1->len!=str2->len) return TIMSIEVE_FAIL;

  data1=string_DATAPTR(str1);
  data2=string_DATAPTR(str2);

  for (lup=0;lup<str1->len;lup++)
    if (data1[lup]!=data2[lup])
      return TIMSIEVE_FAIL;

  return TIMSIEVE_OK;
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

  if (str1->len!=str2len) return TIMSIEVE_FAIL;

  data1=string_DATAPTR(str1);
  data2=str2;

  for (lup=0;lup<str1->len;lup++)
    if (data1[lup]!=data2[lup])
      return TIMSIEVE_FAIL;

  return TIMSIEVE_OK;
}

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
