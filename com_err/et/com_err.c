/*
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Copyright 1987, 1988 by MIT Student Information Processing Board.
 *
 * For copyright info, see mit-sipb-copyright.h.
 */

#define IN_COM_ERR
#include <config.h>

#include <stdio.h>
#include <string.h>
#include "mit-sipb-copyright.h"

/* N.B.:  GCC does not implement varargs.h (since 3.3 and newer) */
#include <stdarg.h>

#include "com_err.h"
#include "internal.h"

EXPORTED struct et_list * _et_list = (struct et_list *) NULL;

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
#if defined(__STDC__) || defined(_WINDOWS)
com_err_va (const char *whoami, long code, const char *fmt, va_list args)
#else
com_err_va (whoami, code, fmt, args)
    const char *whoami;
    long code;
    const char *fmt;
    va_list args;
#endif
{
    (*com_err_hook) (whoami, code, fmt, args);
}

EXPORTED void
__attribute__((format(printf, 3, 4)))
INTERFACE_C com_err (const char *whoami,
                     long code,
                     const char *fmt, ...)
{
    va_list pvar;

    if (!com_err_hook)
        com_err_hook = default_com_err_proc;
    va_start(pvar, fmt);
    com_err_va (whoami, code, fmt, pvar);
    va_end(pvar);
}

errf set_com_err_hook (new_proc)
    errf new_proc;
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
