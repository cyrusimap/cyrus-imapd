/* token.c -- decodes atoms
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


#include "mystring.h"

#include "y.tab.h"


/* xxx this is ugly. fix sometime */

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
