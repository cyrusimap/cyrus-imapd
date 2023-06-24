/*
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <regex.h>
#include <memory.h>
#include <CUnit/CUnit.h>
#include "cunit-syslog.h"

extern int verbose;

struct slmatch
{
    const char *re;         /* NULL => disabled */
    unsigned int count;
    regex_t cre;            /* compiled regex */
};
#define MAX_SLMATCH 32
static unsigned int nslmatches = 0;
static struct slmatch slmatches[MAX_SLMATCH];

#if !defined(va_copy)
#    if defined(__va_copy)
#        define va_copy __va_copy
#    else
#        define va_copy(d,s) (d) = (s)
#    endif
#endif

static char *match_error(struct slmatch *sl, int r)
{
    static char buf[2048];
    int n;

    buf[0] = '\0';
    if (sl->re)
        snprintf(buf, sizeof(buf)-100, "/%s/: ", sl->re);

    n = strlen(buf);
    regerror(r, &sl->cre, buf+n, sizeof(buf)-n-1);
    strcat(buf, "\n");

    return buf;
}

static void
__attribute__((format(printf, 2, 0)))
vlog(int prio, const char *fmt, va_list args)
{
    if (nslmatches) {
        int e = errno;      /* save errno Just In Case */
        va_list args2;
        unsigned int i;
        int r;
        char line[2048];

        /* This only works for all cases because of the glibc
         * extension which supports %m in printf() */
        va_copy(args2, args);
        vsnprintf(line, sizeof(line), fmt, args2);
        va_end(args2);

        for (i = 0 ; i < MAX_SLMATCH ; i++) {
            if (!slmatches[i].re)
                continue; /* empty slot */
            r = regexec(&slmatches[i].cre, line, 0, NULL, 0);
            if (!r) {
                /* found */
                if (verbose >= 2)
                    fprintf(stderr, "\nSYSLOG matched /%s/\n", slmatches[i].re);
                slmatches[i].count++;
                break;
            } else {
                /* don't naively report mismatches when we're looking for multiple patterns */
                if (nslmatches == 1 || verbose >= 2)
                    fprintf(stderr, "\nSYSLOG didn't match '%s' against '%s'\n", line, slmatches[i].re);
            }

            if (r != REG_NOMATCH) {
                /* error */
                const char *msg = match_error(&slmatches[i], r);
                CU_assertImplementation(0, __LINE__, msg, __FILE__, NULL, CU_TRUE);
                /* NOTREACHED */
                break;
            }
        }

        errno = e;
    }

    /* glibc handles %m in vfprintf() so we don't need to do
     * anything special to simulate that feature of syslog() */
     /* TODO: find and expand %m on non-glibc platforms */

    if (verbose < 2)
        return;
    fprintf(stderr, "\nSYSLOG %d[", prio & LOG_PRIMASK);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "]\n");
    fflush(stderr);
}

#if defined(__GLIBC__)
/* Under some but not all combinations of options, glibc
 * defines syslog() as an inline that calls this function */
EXPORTED void
__attribute__((format(printf, 3, 4)))
__syslog_chk(int prio, int whatever __attribute__((unused)),
             const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vlog(prio, fmt, args);
    va_end(args);
}

/* glibc might define a syslog() macro, which is not wanted here */
#ifdef syslog
#undef syslog
#endif
#endif

EXPORTED void syslog(int prio, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vlog(prio, fmt, args);
    va_end(args);
}

unsigned int CU_syslogMatchBegin(const char *re, const char *filename,
                                 unsigned int lineno)
{
    unsigned int i;
    int r;

    /* find an empty slot */
    for (i = 0 ; i < MAX_SLMATCH ; i++) {
        if (!slmatches[i].re) {
            /* found */
            slmatches[i].re = re;
            slmatches[i].count = 0;
            r = regcomp(&slmatches[i].cre, re, REG_EXTENDED|REG_ICASE|REG_NOSUB);
            if (r) {
                const char *msg = match_error(&slmatches[i], r);
                memset(&slmatches[i], 0, sizeof(slmatches[i]));
                CU_assertImplementation(0, lineno, msg, filename, NULL, CU_TRUE);
                /* NOTREACHED */
                return 0;
            }
            nslmatches++;
            return i+1;
        }
    }
    CU_assertImplementation(0, lineno, "No free syslog match slots", filename, NULL, CU_TRUE);
    /* NOTREACHED */
    return 0;
}

unsigned int CU_syslogMatchEnd(unsigned int match, const char **sp)
{
    unsigned int i;
    unsigned int count = 0;
    const char *s = NULL;

    for (i = 0 ; i < MAX_SLMATCH ; i++) {
        if (!slmatches[i].re)
            continue; /* empty slot */
        if (match && match != i+1)
            continue; /* not the slot for @match */

        if (!s)
            s = slmatches[i].re;
        else
            s = "(multiple matches)";

        count += slmatches[i].count;
        regfree(&slmatches[i].cre);
        memset(&slmatches[i], 0, sizeof(slmatches[i]));
        nslmatches--;
        if (match)
            break;      /* only looking for a single slot */
    }

    if (match && !s) {
        s = "invalid match number";
        count = ~0U;
    }

    if (sp)
        *sp = s;
    return count;
}

/* Meta-test code for CU_*SYSLOG* macros. */

#if 0
static void test_syslog(void)
{
    int m1, m2;

//     /* invalid regular expression, 1st macro fails */
//     CU_SYSLOG_MATCH("[foo");
//     syslog(LOG_ERR, "fnarp");
//     CU_ASSERT_SYSLOG(/*all*/0, 0);

//     /* no syslog messages => count is 0 */
//     CU_SYSLOG_MATCH("foo.*baz");
//     CU_ASSERT_SYSLOG(/*all*/0, 0);

//     /* one syslog message which doesn't match => count is 0,
//      * both macros succeed */
//     CU_SYSLOG_MATCH("foo.*baz");
//     syslog(LOG_ERR, "fnarp");
//     CU_ASSERT_SYSLOG(/*all*/0, 0);

//     /* one syslog message which does match => count is 1,
//      * both macros succeed */
//     CU_SYSLOG_MATCH("foo.*baz");
//     syslog(LOG_ERR, "foo bar baz");
//     CU_ASSERT_SYSLOG(/*all*/0, 1);

//     /* one syslog message which does match => count is 1,
//      * we check for 5, 2nd macro fails */
//     CU_SYSLOG_MATCH("foo.*baz");
//     syslog(LOG_ERR, "foo bar baz");
//     CU_ASSERT_SYSLOG(/*all*/0, 5);

//     /* one syslog message with multiple matches => count is 1,
//      * all 3 macros succeed */
//     CU_SYSLOG_MATCH("fuu.*bas");
//     CU_SYSLOG_MATCH("bleah");
//     syslog(LOG_ERR, "fuu bleah bas");
//     CU_ASSERT_SYSLOG(/*all*/0, 1);

//     /* one syslog message with multiple matches which are tracked
//      * separately => count is 1,  all 4 macros succeed */
//     m1 = CU_SYSLOG_MATCH("fuu.*bas");
//     m2 = CU_SYSLOG_MATCH("bleah");
//     syslog(LOG_ERR, "fuu bleah bas");
//     CU_ASSERT_SYSLOG(m1, 1);
//     CU_ASSERT_SYSLOG(m2, 0);
}
#endif
