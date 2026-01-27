/* css3_color.h - Routines for handling css3 colors */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef CSS3_COLOR_H
#define CSS3_COLOR_H

const char *css3_color_hex_to_name(const char *hexstr);

int is_css3_color(const char *s);

#endif /* CSS3_COLOR_H */
