/* imparse.h -- IMxP client-side parsing routines */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_IMPARSE_H
#define INCLUDED_IMPARSE_H

#include <stdint.h>
typedef struct {
    uint32_t low;
    uint32_t high;
    u_char   is_last : 1;
} range_t;

extern int imparse_word (char **s, char **retval);
extern int imparse_astring (char **s, char **retval);
extern int imparse_isnatom (const char *s, int len);
extern int imparse_isatom (const char *s);
extern int imparse_issequence (const char *s);
extern int imparse_isnumber (const char *s);
extern int imparse_istag (const char *s, unsigned command_count);
extern int imparse_range (const char *s, range_t *range);

#endif /* INCLUDED_IMPARSE_H */
