/* css3_color.c - Routines for handling css3 colors */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "css3_color_array.h"
#include "util.h"

struct diff_rock {
    struct {
        uint8_t r, g, b;
    } C;
    unsigned long best;
    const char *name;
};

static int diff_cb(const css3_color_t *c, void *rock)
{
    struct diff_rock *drock = rock;
    int dR = c->r - drock->C.r;
    int dG = c->g - drock->C.g;
    int dB = c->b - drock->C.b;

    if (dR == 0 && dG == 0 && dB == 0) {
        drock->name = c->name;
        return 0;
    }

    unsigned dR2 = dR * dR;
    unsigned dG2 = dG * dG;
    unsigned dB2 = dB * dB;
    unsigned long dC = 2*dR2 + 4*dG2 + 3*dB2;

    unsigned r = (c->r + drock->C.r) / 2;
    dC += (r * (dR2 - dB2)) / 256;

    if (dC < drock->best) {
        drock->best = dC;
        drock->name = c->name;
    }

    return 1;
}

/* Take a hex value for a color and find best matching css3 color name using:
   https://en.wikipedia.org/wiki/Color_difference */
EXPORTED const char *css3_color_hex_to_name(const char *hexstr)
{
    if (!hexstr || hexstr[0] != '#') return NULL;

    size_t hexlen = strlen(hexstr);

    if (hexlen != 7 && hexlen != 9) return NULL;

    /* Convert hex encoded color into separate RGB */
    long hex = strtol(hexstr+1, NULL, 16);
    if (hexlen == 9) hex >>= 8;  /* drop last 2 digits */

    struct diff_rock drock = { { 0 }, ULONG_MAX, NULL };

    drock.C.b = (hex & 0x0000ff);
    hex >>= 8;
    drock.C.g = (hex & 0x00ff);
    hex >>= 8;
    drock.C.r = (hex & 0xff);

    css3_color_foreach(&diff_cb, &drock);

    return drock.name;
}

EXPORTED bool is_css3_color(const char *s)
{
    return !!css3_color_lookup(s, strlen(s));
}

EXPORTED void css3_color_foreach(int (*cb)(const css3_color_t *c, void *rock),
                                 void *rock)
{
    unsigned i;

    for (i = CSS3_COLOR_MIN_HASH_VALUE; i <= CSS3_COLOR_MAX_HASH_VALUE; i++) {
        const css3_color_t *c = &css3_colors[i];

        if (!c->name[0]) continue;

        if (!cb(c, rock)) break;
    }
}
