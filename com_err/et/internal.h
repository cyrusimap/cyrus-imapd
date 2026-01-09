/*
 * Copyright 1988 by the Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * For copyright info, see mit-sipb-copyright.h.
 */

#include "mit-sipb-copyright.h"

#include <errno.h>

#ifdef NEED_SYS_ERRLIST
extern char const * const sys_errlist[];
extern int sys_nerr;
#endif

#if defined(__STDC__) && !defined(HDR_HAS_PERROR) && !defined(_WINDOWS)
void perror (const char *);
#endif
