/* css3_color.h - Routines for handling css3 colors */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef CSS3_COLOR_H
#define CSS3_COLOR_H

#include <stdbool.h>
#include <stdint.h>

/* unit tests need to know this struct */
#define CSS3_COLOR_T_NAME_LEN (29)
struct css3_color_t {
    /* The longest current color name is "lightgoldenrodyellow" at 20 chars, so
     * name[] must be at least 21 bytes.  Rounding up to 29 makes this struct
     * 32 bytes wide, which gives us a neat 2 records per 64 byte cache line.
     *
     * If name[] were 21 bytes it would still be fine.  The struct would be 24
     * bytes wide, which is still both 4- and 8-byte aligned; but it would no
     * longer evenly subdivide cache lines.  That shouldn't cause problems, but
     * I'm being cautious.
     */
    char name[CSS3_COLOR_T_NAME_LEN];
    uint8_t r;
    uint8_t g;
    uint8_t b;
};

extern const char *css3_color_hex_to_name(const char *hexstr);

extern bool is_css3_color(const char *s);

#endif /* CSS3_COLOR_H */
