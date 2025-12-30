/* internal include file for com_err package */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include "mit-sipb-copyright.h"

#include <errno.h>

#ifdef NEED_SYS_ERRLIST
extern char const * const sys_errlist[];
extern int sys_nerr;
#endif

#if defined(__STDC__) && !defined(HDR_HAS_PERROR) && !defined(_WINDOWS)
void perror (const char *);
#endif
