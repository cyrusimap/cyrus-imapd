/*
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 * $Id: squat_internal.c,v 1.2 2003/02/13 20:15:31 rjs3 Exp $
 */

/*
  Internal routines used by SQUAT.
  Robert O'Callahan
*/

#include <assert.h>

#include "squat_internal.h"

static int last_err = SQUAT_ERR_OK;

char const squat_index_file_header[8] = "SQUAT 1\n";

void squat_set_last_error(int err) {
  last_err = err;
}

int squat_get_last_error(void) {
  return last_err;
}

SquatInt32 squat_decode_32(char const* s) {
  unsigned char* v = (unsigned char*)s;
  return ((SquatInt32)v[0] << 24) | ((SquatInt32)v[1] << 16)
       | ((SquatInt32)v[2] << 8) | (SquatInt32)v[3];  
}

char* squat_encode_32(char* s, SquatInt32 v) {
  s[0] = (unsigned char)(v >> 24);
  s[1] = (unsigned char)(v >> 16);
  s[2] = (unsigned char)(v >> 8);
  s[3] = (unsigned char)v;
  return s + 4;
}

SquatInt64 squat_decode_64(char const* s) {
  unsigned char* v = (unsigned char*)s;
  return ((SquatInt64)v[0] << 56) | ((SquatInt64)v[1] << 48)
       | ((SquatInt64)v[2] << 40) | ((SquatInt64)v[3] << 32)
       | (((SquatInt32)v[4] << 24) | ((SquatInt32)v[5] << 16)
       | ((SquatInt32)v[6] << 8) | (SquatInt32)v[7]);
}

char* squat_encode_64(char* s, SquatInt64 v) {
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

SquatInt64 squat_decode_I(char const** s) {
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

char const* squat_decode_skip_I(char const* s, int num_to_skip) {
  while (num_to_skip > 0) {
    while ((*s & 0x80) != 0) {
      s++;
    }
    s++;
    num_to_skip--;
  }

  return s;
}

int squat_count_encode_I(SquatInt64 v64) {
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

char* squat_encode_I(char* s, SquatInt64 v64) {
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

