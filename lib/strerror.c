/* strerror.c -- replacement strerror() routine */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

extern int sys_nerr;
extern char **sys_errlist;

char *strerror(int errnum)
{
    if (errnum < 0 || errnum > sys_nerr) return 0;
    return sys_errlist[errnum];
}

