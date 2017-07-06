/* times-private.h -- Time/date utility routines
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
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
 */

#ifndef __CYRUS__TIMES_PRIVATE_H__
#define __CYRUS__TIMES_PRIVATE_H__

#include <time.h>
#include <sys/time.h>

#define EOB (-99999)            /* End Of Buffer */

static const char special[256] = {
    [' ']  = 1,
    ['\t'] = 1,
    ['\r'] = 1,
    ['\n'] = 1,
};

static const char separators[256] = {
    [' ']  = 1,
    [',']  = 1,
    ['-']  = 1,
    ['+']  = 1,
    [':']  = 1,
};

enum {
    Alpha = 1,              /* Alphabet */
    UAlpha = 2,             /* Uppercase Alphabet */
    LAlpha = 4,             /* Lowercase Alphabet */
    Digit = 8,              /* Digits/Numbers */
    TZSign = 16,            /* Timzone sign +/- */
};

static const long charset[257] = {
    ['0' + 1 ... '9' + 1] = Digit,
    ['A' + 1 ... 'Z' + 1] = Alpha | UAlpha,
    ['a' + 1 ... 'z' + 1] = Alpha | LAlpha,
    ['+' + 1] = TZSign,
    ['-' + 1] = TZSign
};

struct rfc822dtbuf {
    const char *str;
    int len;
    int offset;
};

#endif  /* __CYRUS__TIMES_PRIVATE_H__ */
