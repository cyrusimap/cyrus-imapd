/*
 * Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
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
#include <unistd.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif
#include <setjmp.h>
#include "timeout.h"
#include "cyrunit.h"
#include "util.h"
#include "xmalloc.h"

#include "lib/retry.h"
#include "lib/libconfig.h"

/* generated headers are not necessarily in current directory */
#include "cunit/registers.h"

int verbose = 0;
int num_testspecs = 0;
const char **testspecs;
enum { RUN, LIST } mode = RUN;
int xml_flag = 0;
int timeouts_flag = 1;

#if HAVE_VALGRIND_VALGRIND_H
#define log1(fmt, a1) \
    VALGRIND_PRINTF_BACKTRACE(fmt"\n", (a1))
#define log2(fmt, a1, a2) \
    VALGRIND_PRINTF_BACKTRACE(fmt"\n", (a1), (a2))
#else
#define log1(fmt, a1) \
    fprintf(stderr, "\nunit: "fmt"\n", (a1))
#define log2(fmt, a1, a2) \
    fprintf(stderr, "\nunit: "fmt"\n", (a1), (a2))
#endif

jmp_buf fatal_jbuf;
int fatal_expected;
char *fatal_string = NULL;
int fatal_code;

EXPORTED void fatal(const char *s, int code)
{
    if (fatal_expected) {
        if (verbose) {
            log1("fatal(%s)", s);
        }
        fatal_expected = 0;
        fatal_string = xstrdupnull(s);
        fatal_code = code;
        longjmp(fatal_jbuf, code);
    }
    else {
        log1("fatal(%s)", s);
        exit(1);
    }
}

/* Each test gets a maximum of 20 seconds. */
#define TEST_TIMEOUT_MS (20*1000)

static jmp_buf jbuf;
static const char *code;
static enum { IDLE, INTEST, INFIXTURE } running = IDLE;
static struct cunit_param *current_params;

void exit(int status)
{
    switch (running) {
    case IDLE:
        break;
    case INTEST:
        log2("code under test (%s) exited with status %d", code, status);
        running = IDLE;
        CU_FAIL_FATAL("Code under test exited");
        break;
    case INFIXTURE:
        log2("fixture code (%s) exited with status %d", code, status);
        running = IDLE;
        longjmp(jbuf, status);
        break;
    }
    /* had atexit() handlers? stiff! */
    _exit(status);
}

static void handle_timeout(void)
{
    switch (running) {
    case INTEST:
        log1("code under test (%s) timed out", code);
        running = IDLE;
        CU_FAIL_FATAL("Code under test timed out");
        break;
    case INFIXTURE:
        log1("fixture code (%s) timed out", code);
        running = IDLE;
        longjmp(jbuf, -1);
        break;
    default:
        log1("unexpected timeout running=%d", running);
        _exit(1);
    }
}

void __cunit_wrap_test(const char *name, void (*fn)(void))
{
    code = name;
    running = INTEST;
    if (timeouts_flag && timeout_begin(TEST_TIMEOUT_MS) < 0)
        exit(1);
    fn();
    if (timeouts_flag && timeout_end() < 0)
        exit(1);
    running = IDLE;
}

int __cunit_wrap_fixture(const char *name, int (*fn)(void))
{
    int r = setjmp(jbuf);
    if (r)
        return r;
    code = name;
    running = INFIXTURE;
    if (timeouts_flag && timeout_begin(TEST_TIMEOUT_MS) < 0)
        exit(1);
    r = fn();
    if (timeouts_flag && timeout_end() < 0)
        exit(1);
    running = IDLE;
    return r;
}

static void describe_params(const struct cunit_param *params,
                            char *buf, int maxlen)
{
    const struct cunit_param *p;
    int n;

    if (maxlen <= 4)
        return;
    if (!params || !params->name)
        return;

    for (p = params ; p->name ; p++) {
        n = snprintf(buf, maxlen, "%s%s=%s",
                     (p == params ? "" : ","),
                     p->name, p->values[p->idx]);
        if (n >= maxlen) {
            /* truncated */
            strcpy(buf+maxlen-4, "...");
            return;
        }
        buf += n;
        maxlen -= n;
    }
}

static void params_assign(struct cunit_param *params)
{
    struct cunit_param *p;

    for (p = params ; p->name ; p++)
        *(p->variable) = p->values[p->idx];

    if (verbose) {
        char buf[1024];
        buf[0] = '\0';
        describe_params(params, buf, sizeof(buf));
        fprintf(stderr, "[%s] ", buf);
        fflush(stderr);
    }
}

void __cunit_params_begin(struct cunit_param *params)
{
    struct cunit_param *p;

    if (!params || !params[0].name)
        return;

    if (!params[0].values) {
        /* first call: split the original value of the
         * variable up into the ->values[] array */
        for (p = params ; p->name ; p++) {
            char *v;
            static const char sep[] = ",";
            p->freeme1 = xstrdup(*(p->variable));
            for (v = strtok(p->freeme1, sep) ;
                 v ;
                 v = strtok(NULL, sep)) {
                p->values = (p->nvalues ?
                             xrealloc(p->values, sizeof(char*) * (p->nvalues+1)) :
                             xmalloc(sizeof(char *)));
                p->values[p->nvalues++] = v;
            }
        }
    }
    for (p = params ; p->name ; p++)
        p->idx = 0;
    params_assign(params);
    current_params = params;
}

int __cunit_params_next(struct cunit_param *params)
{
    struct cunit_param *p;

    if (!params || !params[0].name)
        return 0;

    for (p = params ; p->name ; p++) {
        if (++p->idx < p->nvalues)
            break;
        p->idx = 0;
    }
    if (!p->name)
        return 0;       /* incremented off the end */
    params_assign(params);
    return 1;
}

void __cunit_params_end(void)
{
    current_params = NULL;
}


CU_BOOL CU_assertFormatImplementation(
    CU_BOOL bValue,
    unsigned int uiLine,
    char strFile[],
    char strFunction[],
    CU_BOOL bFatal,
    char strConditionFormat[],
    ...)
{
    va_list args;
    char buf[1024];

    va_start(args, strConditionFormat);
    vsnprintf(buf, sizeof(buf), strConditionFormat, args);
    va_end(args);

    if (current_params) {
        strncat(buf, " [", sizeof(buf)-strlen(buf)-1);
        describe_params(current_params, buf+strlen(buf), sizeof(buf)-strlen(buf)-1);
        strncat(buf, "]", sizeof(buf)-strlen(buf)-1);
        buf[sizeof(buf)-1] = '\0';
    }

    if (verbose > 1 && bValue)
        fprintf(stderr, "    %s:%u %s\n", strFile, uiLine, buf);

    return CU_assertImplementation(bValue, uiLine, buf, strFile, strFunction, bFatal);
}

EXPORTED void config_read_string(const char *s)
{
    char *fname = xstrdup("/tmp/cyrus-cunit-configXXXXXX");
    int fd = mkstemp(fname);
    retry_write(fd, s, strlen(s));
    config_reset();
    config_read(fname, 0);
    unlink(fname);
    free(fname);
    close(fd);
}

static void run_tests(void)
{
    int i;
    CU_Suite *suite;
    CU_Test *test;
    CU_ErrorCode err;
    char *testname;
    char suitename[256];

    /* Setup to catch long-running tests.  This seems to be
     * particularly a problem on CentOS 5.5. */
    if (timeouts_flag && timeout_init(handle_timeout) < 0)
        exit(1);

    if (xml_flag) {
        if (num_testspecs == 0) {
            /* not specified: run all tests in order listed */
            CU_automated_run_tests();
            if (timeouts_flag)
                timeout_fini();
            return;
        }
        fprintf(stderr, "unit: test specifications not "
                        "supported in XML mode, sorry\n");
        exit(1);
    }

    if (verbose)
        CU_basic_set_mode(CU_BRM_VERBOSE);

    if (num_testspecs == 0) {
        /* not specified: run all tests in order listed */
        err = CU_basic_run_tests();
        running = IDLE; /* Just In Case */
        if (timeouts_flag)
            timeout_fini();
        if (err != CUE_SUCCESS || CU_get_run_summary()->nAssertsFailed)
            exit(1);
        return;
    }

    /*
     * Run the specified suites and/or tests.
     *
     * bail on the first failure
     */

    for (i = 0 ; i < num_testspecs ; i++) {
        xstrncpy(suitename, testspecs[i], sizeof(suitename));
        if ((testname = strchr(suitename, ':')) != NULL) {
            *testname++ = '\0';
            if (*testname == '\0')
                testname = NULL;
        }

        suite = CU_get_suite_by_name(suitename, CU_get_registry());
        if (suite == NULL) {
            fprintf(stderr, "unit: no such suite \"%s\"\n", suitename);
            exit(1);
        }

        if (testname == NULL) {
            err = CU_basic_run_suite(suite);
            running = IDLE; /* Just In Case */
        } else {
            /* run the named test in the named suite */
            test = CU_get_test_by_name(testname, suite);
            if (test == NULL) {
                fprintf(stderr, "unit: no such test \"%s\" in suite \"%s\"\n",
                        testname, suitename);
                exit(1);
            }
            err = CU_basic_run_test(suite, test);
            running = IDLE; /* Just In Case */
        }
        if (err != CUE_SUCCESS || CU_get_run_summary()->nAssertsFailed)
            exit(1);
    }

    if (timeouts_flag)
        timeout_fini();
}

static void list_tests(void)
{
    CU_Suite *suite;
    CU_Test *test;

    for (suite = CU_get_registry()->pSuite ;
         suite != NULL ;
         suite = suite->pNext) {
        for (test = suite->pTest ;
             test != NULL ;
             test = test->pNext) {
            printf("%s:%s\n", suite->pName, test->pName);
        }
    }
}

static void usage(int ec)
    __attribute__((noreturn));

static void usage(int ec)
{
    static const char usage_str[] =
"Usage: cunit/unit [options] [suite|suite:test ...]\n"
"options are:\n"
"    -l      list all tests\n"
"    -t      disable per-test timeouts\n"
"    -v      be more verbose\n"
"    -h      print this message\n"
    ;

    fputs(usage_str, stderr);
    fflush(stderr);

    exit(ec);
}

static void parse_args(int argc, char **argv)
{
    int c;

    while ((c = getopt(argc, argv, "hltvx")) > 0)
    {
        switch (c)
        {
        case 'h':
            usage(0);
            break;
        case 'l':
            mode = LIST;
            break;
        case 't':
            timeouts_flag = 0;
            break;
        case 'v':
            verbose++;
            break;
        case 'x':
            xml_flag = 1;
            break;
        case '?':
            usage(1);
            exit(1);
        }
    }
    num_testspecs = argc - optind;
    testspecs = (const char **)(argv + optind);
}

int main(int argc, char **argv)
{
    CU_initialize_registry();
    register_cunit_suites();
    parse_args(argc, argv);
    switch (mode) {
    case RUN:
        run_tests();
        break;
    case LIST:
        list_tests();
        break;
    }
    return 0;
}

