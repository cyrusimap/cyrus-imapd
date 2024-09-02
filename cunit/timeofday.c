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
#include "timeofday.h"

extern int verbose;

#define MICROSEC_PER_SEC    (1000000)

struct trans
{
    /*
     * We transform time using the formula
     *
     * reported_time = (actual_time - start) * factor + epoch;
     *
     * where 'factor' is actually fractional.  Yes, I realise that
     * 'start' is mathematically redundant but it makes the code
     * marginally easier to write and read.
     */
    int64_t start;
    int64_t epoch;
    long factor_num;
    long factor_den;
};

static int real_gettimeofday(struct timeval *, ...);

#define MAX_TRANS_STACK 5
static int n_trans_stack = 0;
static struct trans trans_stack[MAX_TRANS_STACK];
static const struct trans identity = { 0, 0, 1, 1 };

/*
 * Basic time manipulation.
 *
 * Internal time format is microseconds since the Unix epoch
 * in a signed 64b integer which is convenient to use and
 * allows some headroom for scaling.
 */

static int64_t from_timeval(const struct timeval *tv)
{
    return (int64_t)tv->tv_usec + (int64_t)tv->tv_sec * MICROSEC_PER_SEC;
}

static void to_timeval(int64_t t, struct timeval *tv)
{
    tv->tv_sec = t / MICROSEC_PER_SEC;
    tv->tv_usec = t % MICROSEC_PER_SEC;
}

static int64_t from_time_t(time_t tt)
{
    return (int64_t)tt * MICROSEC_PER_SEC;
}

static time_t to_time_t(int64_t t)
{
    return t / MICROSEC_PER_SEC;
}

static int64_t now(void)
{
    struct timeval tv = { 0xffffffff, 0xffffffff };
    int r = real_gettimeofday(&tv, NULL);
    assert(r == 0);
    assert(tv.tv_sec != 0xffffffff);
    assert(tv.tv_usec != 0xffffffff);
    return from_timeval(&tv);
}

/*
 * Time transform stack handling.
 */

static const struct trans *trans_top(void)
{
    return (n_trans_stack ? &trans_stack[n_trans_stack-1] : &identity);
}

static int64_t transform(int64_t t)
{
    const struct trans *tr = trans_top();
    int64_t tt = ((t - tr->start) * tr->factor_num) / tr->factor_den + tr->epoch;
    return tt;
}

static void trans_push(const struct trans *tr)
{
    assert(n_trans_stack < MAX_TRANS_STACK);
    trans_stack[n_trans_stack++] = *tr;
}

/*
 * Make the reported time go faster or slower from now on.
 * Reported times are continuous across this function.
 */
void time_push_rate(long n, long d)
{
    struct trans tr = *trans_top();
    tr.start = now();
    tr.epoch = transform(tr.start);
    tr.factor_num *= n;
    tr.factor_den *= d;
    trans_push(&tr);
}

/*
 * Stop the flow of reported time
 */
void time_push_stop(void)
{
    time_push_rate(0, 1);
}

/*
 * Report a given fixed time
 */
void time_push_fixed(time_t fixed)
{
    struct trans tr = *trans_top();
    tr.start = 0;
    tr.epoch = from_time_t(fixed);
    tr.factor_num = 0;
    tr.factor_den = 1;
    trans_push(&tr);
}

void time_pop(void)
{
    assert(n_trans_stack > 0);
    --n_trans_stack;
}

void time_restore(void)
{
    n_trans_stack = 0;
}

/*
 * Platform-specific libc interception code
 */

#if defined(__GLIBC__)

/* XXX Annoyingly, we can't just include <config.h> in this file,
 * XXX because for whatever reason it breaks the gettimeofday
 * XXX replacement.  Assume we just have this flag for now, and
 * XXX define EXPORTED ourselves
 */
#define EXPORTED __attribute__((__visibility__("default")))

/* call the real libc function */
static int real_gettimeofday(struct timeval *tv, ...)
{
    extern int __gettimeofday(struct timeval *, ...);
    return __gettimeofday(tv, NULL);
}

/* provide a function to hide the libc weak alias */
EXPORTED int gettimeofday(struct timeval *tv, ...)
{
    to_timeval(transform(now()), tv);
    return 0;
}

EXPORTED time_t time(time_t *tp)
{
    time_t tt = to_time_t(transform(now()));
    if (tp) *tp = tt;
    return tt;
}

#else
#error "Don't know how to intercept gettimeofday for this libc"
#endif


/*
 * Tests - not usefully runnable, sorry.
 */
#if 0
static void test_time_speedup(void)
{
    time_t clock;

    time(&clock); fputs(ctime(&clock), stderr);

    fputs("time_push_rate(5, 1)\n", stderr);
    time_push_rate(10, 1);

    time(&clock); fputs(ctime(&clock), stderr);
    sleep(1);
    time(&clock); fputs(ctime(&clock), stderr);
    sleep(1);
    time(&clock); fputs(ctime(&clock), stderr);
    sleep(1);
    time(&clock); fputs(ctime(&clock), stderr);
    sleep(1);
    time(&clock); fputs(ctime(&clock), stderr);

    fputs("time_pop()\n", stderr);
    time_pop();

    time(&clock); fputs(ctime(&clock), stderr);
}

static void test_time_slowdown(void)
{
    time_t clock;
    int i;

    time(&clock); fputs(ctime(&clock), stderr);

    fputs("time_push_rate(1, 10)\n", stderr);
    time_push_rate(1, 5);

    for (i = 0 ; i < 20 ; i++) {
        time(&clock); fputs(ctime(&clock), stderr);
        sleep(1);
    }
    time(&clock); fputs(ctime(&clock), stderr);

    fputs("time_pop()\n", stderr);
    time_pop();

    time(&clock); fputs(ctime(&clock), stderr);
}

static void test_time_fixed(void)
{
    time_t clock;

    time(&clock); fputs(ctime(&clock), stderr);

    fputs("time_push_fixed(1354928400)\n", stderr);
    time_push_fixed(1354928400);

    time(&clock); fputs(ctime(&clock), stderr);
    sleep(1);
    time(&clock); fputs(ctime(&clock), stderr);
    sleep(1);
    time(&clock); fputs(ctime(&clock), stderr);
    sleep(1);
    time(&clock); fputs(ctime(&clock), stderr);
    sleep(1);
    time(&clock); fputs(ctime(&clock), stderr);

    fputs("time_pop()\n", stderr);
    time_pop();

    time(&clock); fputs(ctime(&clock), stderr);
}

static void test_time_fixed2(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL); fputs(ctime(&tv.tv_sec), stderr);

    fputs("time_push_fixed(1354928400)\n", stderr);
    time_push_fixed(1354928400);

    gettimeofday(&tv, NULL); fputs(ctime(&tv.tv_sec), stderr);
    sleep(1);
    gettimeofday(&tv, NULL); fputs(ctime(&tv.tv_sec), stderr);
    sleep(1);
    gettimeofday(&tv, NULL); fputs(ctime(&tv.tv_sec), stderr);
    sleep(1);
    gettimeofday(&tv, NULL); fputs(ctime(&tv.tv_sec), stderr);
    sleep(1);
    gettimeofday(&tv, NULL); fputs(ctime(&tv.tv_sec), stderr);

    fputs("time_pop()\n", stderr);
    time_pop();

    gettimeofday(&tv, NULL); fputs(ctime(&tv.tv_sec), stderr);
}
#endif

