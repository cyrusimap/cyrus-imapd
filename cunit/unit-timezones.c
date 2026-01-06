/* unit-timezones.c */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "cunit/unit-timezones.h"

extern int verbose;

#define MAX_TZ_STACK    5
static int n_tz_stack = 0;
static char *tz_stack[MAX_TZ_STACK];

static inline void xxputenv(char *s, const char *f)
{
    if (verbose > 1)
        fprintf(stderr, "\n%s:putenv(\"%s\")\n", f, s);
    putenv(s);
}
#define putenv(s) xxputenv((s), __FUNCTION__)

static char *stash_tz(const char *tz)
{
    char *s = malloc(4+(tz == NULL ? 0 : strlen(tz)));
    assert(s);
    sprintf(s, "TZ=%s", (tz == NULL ? "" : tz));
    assert(n_tz_stack < MAX_TZ_STACK-1);
    return tz_stack[n_tz_stack++] = s;
}

void push_tz(const char *tz)
{
    if (n_tz_stack == 0)
        stash_tz(getenv("TZ"));
    putenv(stash_tz(tz));
    tzset();
}

void pop_tz(void)
{
    char *old;
    assert(n_tz_stack > 1);
    old = tz_stack[--n_tz_stack];
    putenv(tz_stack[n_tz_stack-1]);
    tzset();
    free(old);
}

void restore_tz(void)
{
    while (n_tz_stack > 1)
        pop_tz();
}
