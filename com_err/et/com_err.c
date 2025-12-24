/* com_err.c */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#define IN_COM_ERR
#include <config.h>

#include <stdio.h>
#include <string.h>
#include "mit-sipb-copyright.h"

#if defined(HAVE_STDARG_H) || defined(_WINDOWS)
#include <stdarg.h>
#else
#include <varargs.h>
#define VARARGS
#endif

#include "error_table.h"
#include "internal.h"

EXPORTED struct et_list * _et_list = (struct et_list *) NULL;

#ifdef notdef
/*
 * Protect us from header version (externally visible) of com_err, so
 * we can survive in a <varargs.h> environment.  I think.
 */
#define com_err com_err_external
#include "com_err.h"
#undef com_err
#endif

/* We have problems with varargs definitions if we include com_err.h */

/*
 * XXX for now, we define error_message by hand.  Ultimately, we
 * should fix up com_err.h so that it's safe to #include here
 * directly.
 */
#if defined(__STDC__) || defined(_WINDOWS)
extern char const * INTERFACE error_message (long);
#else
extern char * INTERFACE error_message ();
#endif

static void
__attribute__((format(printf, 3, 0)))
#if defined(__STDC__) || defined(_WINDOWS)
    default_com_err_proc (const char *whoami, long code, const char *fmt, va_list args)
#else
    default_com_err_proc (whoami, code, fmt, args)
    const char *whoami;
    long code;
    const char *fmt;
    va_list args;
#endif
{
    static char errbuf[1024];                   /* For those w/o stdio */

    *errbuf = '\0';
    if (whoami) {
        strcat (errbuf, whoami);
        strcat (errbuf, ": ");
    }
    if (code) {
        strcat (errbuf, error_message(code));
        strcat (errbuf, " ");
    }
    if (fmt) {
        vsprintf (errbuf + strlen (errbuf), fmt, args);
    }
#ifdef _WINDOWS
    MessageBox (NULL, errbuf, "Kerberos", MB_ICONEXCLAMATION);
#else
    fputs (errbuf, stderr);
    /* should do this only on a tty in raw mode */
    putc('\r', stderr);
    putc('\n', stderr);
    fflush(stderr);
#endif
}

#if defined(__STDC__) || defined(_WINDOWS)
typedef void (*errf) (const char *, long, const char *, va_list)
                     __attribute__((format(printf, 3, 0)));
#else
typedef void (*errf) ();
#endif

errf com_err_hook = default_com_err_proc;

void
__attribute__((format(printf, 3, 0)))
com_err_va (const char *whoami,
            long code,
            const char *fmt,
            va_list args)
{
    (*com_err_hook) (whoami, code, fmt, args);
}

#ifndef VARARGS
EXPORTED void
__attribute__((format(printf, 3, 4)))
INTERFACE_C com_err (const char *whoami,
                     long code,
                     const char *fmt, ...)
{
#else
EXPORTED void INTERFACE_C com_err (va_alist)
    va_dcl
{
    const char *whoami, *fmt;
    long code;
#endif
    va_list pvar;

    if (!com_err_hook)
        com_err_hook = default_com_err_proc;
#ifdef VARARGS
    va_start (pvar);
    whoami = va_arg (pvar, const char *);
    code = va_arg (pvar, long);
    fmt = va_arg (pvar, const char *);
#else
    va_start(pvar, fmt);
#endif
    com_err_va (whoami, code, fmt, pvar);
    va_end(pvar);
}

errf set_com_err_hook (errf new_proc)
{
    errf x = com_err_hook;

    if (new_proc)
        com_err_hook = new_proc;
    else
        com_err_hook = default_com_err_proc;

    return x;
}

errf reset_com_err_hook () {
    errf x = com_err_hook;
    com_err_hook = default_com_err_proc;
    return x;
}
