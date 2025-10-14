/*
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "cunit/unit-timezones.h"

extern int verbose;

#define MAX_TZ_STACK 5
static int n_tz_stack = 0;
static char *tz_stack[MAX_TZ_STACK];

static inline void xxputenv(char *s, const char *f)
{
    if (verbose > 1) {
        fprintf(stderr, "\n%s:putenv(\"%s\")\n", f, s);
    }
    putenv(s);
}
#define putenv(s) xxputenv((s), __FUNCTION__)

static char *stash_tz(const char *tz)
{
    char *s = malloc(4 + (tz == NULL ? 0 : strlen(tz)));
    assert(s);
    sprintf(s, "TZ=%s", (tz == NULL ? "" : tz));
    assert(n_tz_stack < MAX_TZ_STACK - 1);
    return tz_stack[n_tz_stack++] = s;
}

void push_tz(const char *tz)
{
    if (n_tz_stack == 0) {
        stash_tz(getenv("TZ"));
    }
    putenv(stash_tz(tz));
    tzset();
}

void pop_tz(void)
{
    char *old;
    assert(n_tz_stack > 1);
    old = tz_stack[--n_tz_stack];
    putenv(tz_stack[n_tz_stack - 1]);
    tzset();
    free(old);
}

void restore_tz(void)
{
    while (n_tz_stack > 1) {
        pop_tz();
    }
}
