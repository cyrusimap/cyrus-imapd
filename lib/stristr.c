/* +++Date last modified: 05-Jul-1997 */
/*
** Designation:  StriStr
**
** Call syntax:  char *stristr(char *String, char *Pattern)
**
** Description:  This function is an ANSI version of strstr() with
**               case insensitivity.
**
** Return item:  char *pointer if Pattern is found in String, else
**               pointer to 0
**
** Rev History:  07/04/95  Bob Stout  ANSI-fy
**               02/03/94  Fred Cole  Original
**
** Hereby donated to public domain.
**
** Modified for use with libcyrus by Ken Murchison 06/01/00.
*/

#include <string.h>
#include <ctype.h>

#include "config.h"

#if defined(__cplusplus) && __cplusplus
 extern "C" {
#endif

EXPORTED char *strinstr(const char *String, size_t StringLen, const char *Pattern)
{
      char *pptr, *sptr, *start;
      size_t slen = StringLen;
      size_t plen = strlen(Pattern);

      if (!plen) return (char *)String;
      if (!slen) return NULL;

      for (start = (char *)String;
           /* while string length not shorter than pattern length */
           slen >= plen;
           start++, slen--)
      {
            /* find start of pattern in string */
            while (toupper(*start) != toupper(*Pattern))
            {
                  start++;
                  slen--;

                  /* if pattern longer than string */

                  if (slen < plen)
                        return(NULL);
            }

            sptr = start;
            pptr = (char *)Pattern;

            while (toupper(*sptr) == toupper(*pptr))
            {
                  sptr++;
                  pptr++;

                  /* if end of pattern then pattern was found */

                  if ('\0' == *pptr)
                        return (start);
            }
      }
      return(NULL);
}

EXPORTED char *stristr(const char *String, const char *Pattern)
{
      return strinstr(String, strlen(String), Pattern);
}

#if defined(__cplusplus) && __cplusplus
 }
#endif
