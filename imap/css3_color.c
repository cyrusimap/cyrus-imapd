/* css3_color.c -- Routines for handling css3 colors
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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
 */

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "util.h"

struct css3_color_t {
    const char *name;
    unsigned char r;
    unsigned char g;
    unsigned char b;
};

static const struct css3_color_t css3_colors[] = {
    { "aliceblue",            240, 248, 255 },
    { "antiquewhite",         250, 235, 215 },
    { "aqua",                   0, 255, 255 },
    { "aquamarine",           127, 255, 212 },
    { "azure",                240, 255, 255 },
    { "beige",                245, 245, 220 },
    { "bisque",               255, 228, 196 },
    { "black",                  0,   0,   0 },
    { "blanchedalmond",       255, 235, 205 },
    { "blue",                   0,   0, 255 },
    { "blueviolet",           138,  43, 226 },
    { "brown",                165,  42,  42 },
    { "burlywood",            222, 184, 135 },
    { "cadetblue",             95, 158, 160 },
    { "chartreuse",           127, 255,   0 },
    { "chocolate",            210, 105,  30 },
    { "coral",                255, 127,  80 },
    { "cornflowerblue",       100, 149, 237 },
    { "cornsilk",             255, 248, 220 },
    { "crimson",              220,  20,  60 },
    { "cyan",                   0, 255, 255 },
    { "darkblue",               0,   0, 139 },
    { "darkcyan",               0, 139, 139 },
    { "darkgoldenrod",        184, 134,  11 },
    { "darkgray",             169, 169, 169 },
    { "darkgreen",              0, 100,   0 },
    { "darkgrey",             169, 169, 169 },
    { "darkkhaki",            189, 183, 107 },
    { "darkmagenta",          139,   0, 139 },
    { "darkolivegreen",        85, 107,  47 },
    { "darkorange",           255, 140,   0 },
    { "darkorchid",           153,  50, 204 },
    { "darkred",              139,   0,   0 },
    { "darksalmon",           233, 150, 122 },
    { "darkseagreen",         143, 188, 143 },
    { "darkslateblue",         72 , 61, 139 },
    { "darkslategray",         47,  79,  79 },
    { "darkslategrey",         47,  79,  79 },
    { "darkturquoise",          0, 206, 209 },
    { "darkviolet",           148,   0, 211 },
    { "deeppink",             255,  20, 147 },
    { "deepskyblue",            0, 191, 255 },
    { "dimgray",              105, 105, 105 },
    { "dimgrey",              105, 105, 105 },
    { "dodgerblue",            30, 144, 255 },
    { "firebrick",            178,  34,  34 },
    { "floralwhite",          255, 250, 240 },
    { "forestgreen",           34, 139,  34 },
    { "fuchsia",              255,   0, 255 },
    { "gainsboro",            220, 220, 220 },
    { "ghostwhite",           248, 248, 255 },
    { "gold",                 255, 215,   0 },
    { "goldenrod",            218, 165,  32 },
    { "gray",                 128, 128, 128 },
    { "green",                  0, 128,   0 },
    { "greenyellow",          173, 255,  47 },
    { "grey",                 128, 128, 128 },
    { "honeydew",             240, 255, 240 },
    { "hotpink",              255, 105, 180 },
    { "indianred",            205,  92,  92 },
    { "indigo",                75,   0, 130 },
    { "ivory",                255, 255, 240 },
    { "khaki",                240, 230, 140 },
    { "lavender",             230, 230, 250 },
    { "lavenderblush",        255, 240, 245 },
    { "lawngreen",            124, 252,   0 },
    { "lemonchiffon",         255, 250, 205 },
    { "lightblue",            173, 216, 230 },
    { "lightcoral",           240, 128, 128 },
    { "lightcyan",            224, 255, 255 },
    { "lightgoldenrodyellow", 250, 250, 210 },
    { "lightgray",            211, 211, 211 },
    { "lightgreen",           144, 238, 144 },
    { "lightgrey",            211, 211, 211 },
    { "lightpink",            255, 182, 193 },
    { "lightsalmon",          255, 160, 122 },
    { "lightseagreen",         32, 178, 170 },
    { "lightskyblue",         135, 206, 250 },
    { "lightslategray",       119, 136, 153 },
    { "lightslategrey",       119, 136, 153 },
    { "lightsteelblue",       176, 196, 222 },
    { "lightyellow",          255, 255, 224 },
    { "lime",                   0, 255,   0 },
    { "limegreen",             50, 205,  50 },
    { "linen",                250, 240, 230 },
    { "magenta",              255,   0, 255 },
    { "maroon",               128,   0,   0 },
    { "mediumaquamarine",     102, 205, 170 },
    { "mediumblue",             0,   0, 205 },
    { "mediumorchid",         186,  85, 211 },
    { "mediumpurple",         147, 112, 219 },
    { "mediumseagreen",        60, 179, 113 },
    { "mediumslateblue",      123, 104, 238 },
    { "mediumspringgreen",      0, 250, 154 },
    { "mediumturquoise",       72, 209, 204 },
    { "mediumvioletred",      199,  21, 133 },
    { "midnightblue",          25,  25, 112 },
    { "mintcream",            245, 255, 250 },
    { "mistyrose",            255, 228, 225 },
    { "moccasin",             255, 228, 181 },
    { "navajowhite",          255, 222, 173 },
    { "navy",                   0,   0, 128 },
    { "oldlace",              253, 245, 230 },
    { "olive",                128, 128,   0 },
    { "olivedrab",            107, 142,  35 },
    { "orange",               255, 165,   0 },
    { "orangered",            255,  69,   0 },
    { "orchid",               218, 112, 214 },
    { "palegoldenrod",        238, 232, 170 },
    { "palegreen",            152, 251, 152 },
    { "paleturquoise",        175, 238, 238 },
    { "palevioletred",        219, 112, 147 },
    { "papayawhip",           255, 239, 213 },
    { "peachpuff",            255, 218, 185 },
    { "peru",                 205, 133,  63 },
    { "pink",                 255, 192, 203 },
    { "plum",                 221, 160, 221 },
    { "powderblue",           176, 224, 230 },
    { "purple",               128,   0, 128 },
    { "red",                  255,   0,   0 },
    { "rosybrown",            188, 143, 143 },
    { "royalblue",             65, 105, 225 },
    { "saddlebrown",          139,  69,  19 },
    { "salmon",               250, 128, 114 },
    { "sandybrown",           244, 164,  96 },
    { "seagreen",              46, 139,  87 },
    { "seashell",             255, 245, 238 },
    { "sienna",               160,  82,  45 },
    { "silver",               192, 192, 192 },
    { "skyblue",              135, 206, 235 },
    { "slateblue",            106,  90, 205 },
    { "slategray",            112, 128, 144 },
    { "slategrey",            112, 128, 144 },
    { "snow",                 255, 250, 250 },
    { "springgreen",            0, 255, 127 },
    { "steelblue",             70, 130, 180 },
    { "tan",                  210, 180, 140 },
    { "teal",                   0, 128, 128 },
    { "thistle",              216, 191, 216 },
    { "tomato",               255,  99,  71 },
    { "turquoise",             64, 224, 208 },
    { "violet",               238, 130, 238 },
    { "wheat",                245, 222, 179 },
    { "white",                255, 255, 255 },
    { "whitesmoke",           245, 245, 245 },
    { "yellow",               255, 255,   0 },
    { "yellowgreen",          154, 205,  50 },
    { NULL,                     0,   0,   0 }
};

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

    struct {
        unsigned char r, g, b;
    } C;

    C.b = (hex & 0x0000ff);
    hex >>= 8;
    C.g = (hex & 0x00ff);
    hex >>= 8;
    C.r = (hex & 0xff);

    const struct css3_color_t *css;
    unsigned long best = ULONG_MAX;
    const char *name = NULL;

    for (css = css3_colors; css->name; css++) {
        int dR = css->r - C.r;
        int dG = css->g - C.g;
        int dB = css->b - C.b;

        if (dR == 0 && dG == 0 && dB == 0) return css->name;

        unsigned dR2 = dR * dR;
        unsigned dG2 = dG * dG;
        unsigned dB2 = dB * dB;
        unsigned long dC = 2*dR2 + 4*dG2 + 3*dB2;

        unsigned r = (css->r + C.r) / 2;
        dC += (r * (dR2 - dB2)) / 256;

        if (dC < best) {
            best = dC;
            name = css->name;
        }
    }

    return name;
}

EXPORTED int is_css3_color(const char *s)
{
    const struct css3_color_t *c;

    for (c = css3_colors; c->name && strcasecmp(s, c->name); c++);

    return (c->name != NULL);
}
