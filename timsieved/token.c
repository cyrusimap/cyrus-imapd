#include "mystring.h"

#include "parse.tab.h"


int token_lookup (char *str, int len)
{
  if (strcmp(str, "authenticate")==0) return AUTHENTICATE;
  if (strcmp(str, "noop")==0) return NOOP;
  if (strcmp(str, "logout")==0) return LOGOUT;
  if (strcmp(str, "getscript")==0) return GETSCRIPT;
  if (strcmp(str, "putscript")==0) return PUTSCRIPT;
  if (strcmp(str, "deletescript")==0) return DELETESCRIPT;
  if (strcmp(str, "listscripts")==0) return LISTSCRIPTS;
  if (strcmp(str, "setactive")==0) return SETACTIVE;

  /* error */

  return -1;

}
