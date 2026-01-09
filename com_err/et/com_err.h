/*
 * Header file for common error description library.
 *
 * Copyright 1988, Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * Copyright 1995 by Cygnus Support.
 *
 * For copyright and distribution info, see the documentation supplied
 * with this package.
 */

#ifndef __COM_ERR_H

#ifndef HAVE_STDARG_H
/* End-user programs may need this -- oh well */
#if defined(__STDC__) || defined(_WINDOWS)
#define HAVE_STDARG_H 1
#endif
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "error_table.h"

/* This should be part of k5-config.h but many application
 * programs are not including that file. We probably want to
 * come up with a better way of handling this problem.
 */
#ifndef INTERFACE
#ifdef _WINDOWS
#define INTERFACE   __far __export __pascal
#define INTERFACE_C __far __export __cdecl
#else
#define INTERFACE
#define INTERFACE_C
#endif
#endif
#ifndef FAR
#define FAR
#endif

#if defined(__STDC__) || defined(_WINDOWS)
/* ANSI C -- use prototypes etc */
extern void INTERFACE_C com_err (const char FAR *, long, const char FAR *, ...)
                                __attribute__((format(printf, 3, 4)));
extern char const FAR * INTERFACE error_message (long);
extern void (*com_err_hook) (const char *, long, const char *, va_list);
extern void (*set_com_err_hook (void (*) (const char *, long, const char *, va_list)))
    (const char *, long, const char *, va_list);
extern void (*reset_com_err_hook ()) (const char *, long, const char *, va_list);
#else
/* no prototypes */
extern void INTERFACE_C com_err ();
extern char * INTERFACE error_message ();
extern void (*com_err_hook) ();
extern void (*set_com_err_hook ()) ();
extern void (*reset_com_err_hook ()) ();
#endif

#define __COM_ERR_H
#endif /* ! defined(__COM_ERR_H) */
