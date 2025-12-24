/* Internal routines used by SQUAT. */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include "config.h"
#include "assert.h"
#include "squat_internal.h"

static int last_err = SQUAT_ERR_OK;

EXPORTED char const squat_index_file_header[] = "SQUAT 1\n";

EXPORTED void squat_set_last_error(int err)
{
    last_err = err;
}

EXPORTED int squat_get_last_error(void)
{
    return last_err;
}

EXPORTED SquatInt32 squat_decode_32(char const* s)
{
    unsigned char* v = (unsigned char*)s;
    return ((SquatInt32)v[0] << 24) | ((SquatInt32)v[1] << 16) |
           ((SquatInt32)v[2] << 8) | (SquatInt32)v[3];
}

EXPORTED char *squat_encode_32(char* s, SquatInt32 v)
{
    s[0] = (unsigned char)(v >> 24);
    s[1] = (unsigned char)(v >> 16);
    s[2] = (unsigned char)(v >> 8);
    s[3] = (unsigned char)v;
    return s + 4;
}

EXPORTED SquatInt64 squat_decode_64(char const *s)
{
    unsigned char* v = (unsigned char*)s;
    return ((SquatInt64)v[0] << 56) | ((SquatInt64)v[1] << 48) |
           ((SquatInt64)v[2] << 40) | ((SquatInt64)v[3] << 32) |
           ((SquatInt64)v[4] << 24) | ((SquatInt64)v[5] << 16) |
           ((SquatInt64)v[6] << 8) | (SquatInt64)v[7];
}

EXPORTED char *squat_encode_64(char* s, SquatInt64 v)
{
    s[0] = (unsigned char)(v >> 56);
    s[1] = (unsigned char)(v >> 48);
    s[2] = (unsigned char)(v >> 40);
    s[3] = (unsigned char)(v >> 32);
    s[4] = (unsigned char)(v >> 24);
    s[5] = (unsigned char)(v >> 16);
    s[6] = (unsigned char)(v >> 8);
    s[7] = (unsigned char)v;
    return s + 8;
}

EXPORTED SquatInt64 squat_decode_I(char const** s)
{
    int ch;
    SquatInt64 r;

    ch = (unsigned char)*(*s)++;
    r = ch;
    while ((ch & 0x80) != 0) {
        ch = (unsigned char)**s;
        ++(*s);
        r = ((r - 0x80) << 7) + ch;
    }
    return r;
}

HIDDEN char const *squat_decode_skip_I(char const* s, int num_to_skip)
{
    while (num_to_skip > 0) {
        while ((*s & 0x80) != 0) {
            s++;
        }
        s++;
        num_to_skip--;
    }

    return s;
}

EXPORTED int squat_count_encode_I(SquatInt64 v64)
{
    int v = (int)v64;
    int shift = 56;
    int result;

    assert(v64 >= 0);

    if (v == v64) {
        if (v < (1 << 7)) {
            return 1;
        } else if (v < (1 << 14)) {
            return 2;
        } else if (v < (1 << 21)) {
            return 3;
        } else if (v < (1 << 28)) {
            return 4;
        }
    }

    while ((int)(v64 >> shift) == 0) {
        shift -= 7;
    }

    result = 0;
    while (shift >= 0) {
        shift -= 7;
        result++;
    }

    return result;
}

EXPORTED char *squat_encode_I(char* s, SquatInt64 v64)
{
    int v = (int)v64;
    int shift = 56;
    int v64_shifted;

    assert(v64 >= 0);

    if (v == v64) {
        if (v < (1 << 7)) {
            s[0] = (unsigned char)v;
            return s + 1;
        } else if (v < (1 << 14)) {
            s[0] = (unsigned char)((v >> 7) | 0x80);
            s[1] = (unsigned char)(v & 0x7F);
            return s + 2;
        } else if (v < (1 << 21)) {
            s[0] = (unsigned char)((v >> 14) | 0x80);
            s[1] = (unsigned char)(((v >> 7) & 0x7F) | 0x80);
            s[2] = (unsigned char)(v & 0x7F);
            return s + 3;
        } else if (v < (1 << 28)) {
            s[0] = (unsigned char)((v >> 21) | 0x80);
            s[1] = (unsigned char)(((v >> 14) & 0x7F) | 0x80);
            s[2] = (unsigned char)(((v >> 7) & 0x7F) | 0x80);
            s[3] = (unsigned char)(v & 0x7F);
            return s + 4;
        }
    }

    while ((v64_shifted = (int)(v64 >> shift)) == 0) {
        shift -= 7;
    }
    while (shift > 7) {
        *s++ = (unsigned char)((v64_shifted & 0x7F) | 0x80);
        shift -= 7;
        v64_shifted = (int)(v64 >> shift);
    }
    s[0] = (unsigned char)((v64_shifted & 0x7F) + 0x80);
    s[1] = (unsigned char)(v & 0x7F);
    return s + 2;
}

