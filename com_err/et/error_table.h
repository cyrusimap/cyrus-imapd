/*
 * Copyright 1988 by the Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * For copyright info, see mit-sipb-copyright.h.
 */

#ifndef _ET_H

/* This directory doesn't really know about the krb5 world. The following
   windows defines are usually hidden in k5-config.h. For now I'll just
   place here what is needed from that file. Later we may decide to do
   it differently.
*/
#ifdef _WINDOWS
#define INTERFACE             __far __export __pascal
#define INTERFACE_C           __far __export __cdecl
#define sys_nerr              _sys_nerr
#define sys_errlist           _sys_errlist
int __far __pascal MessageBox (void __far *, const char __far*, const char __far*, unsigned int);
#define MB_ICONEXCLAMATION    0x0030
#else
#define INTERFACE
#define INTERFACE_C
#include <errno.h>
#endif

struct error_table {
    char const * const * msgs;
    long base;
    int n_msgs;
};
struct et_list {
    struct et_list *next;
    const struct error_table *table;
};
extern struct et_list * _et_list;

#define ERRCODE_RANGE   8       /* # of bits to shift table number */
#define BITS_PER_CHAR   6       /* # bits to shift per character in name */

#if defined(__STDC__) || defined(KRB5_PROVIDE_PROTOTYPES) || defined(_WINDOWS)
extern const char *error_table_name (long);
#else
extern const char *error_table_name ();
#endif

#define _ET_H
#endif
