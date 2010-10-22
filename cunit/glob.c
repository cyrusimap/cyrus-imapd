#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "cunit/cunit.h"
#include "glob.h"

static void test_star(void)
{
    glob *g;
    int r;

    g = glob_init("fo*", GLOB_HIERARCHY);
    CU_ASSERT_PTR_NOT_EQUAL_FATAL(g, NULL);

    r = glob_test(g, "foo", 0, NULL);
    CU_ASSERT_EQUAL(r, 3);

    r = glob_test(g, "meh", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "mofoo", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "fnarp", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "fod", 0, NULL);
    CU_ASSERT_EQUAL(r, 3);

    r = glob_test(g, "foonly", 0, NULL);
    CU_ASSERT_EQUAL(r, 6);

    r = glob_test(g, "foon.ly", 0, NULL);
    CU_ASSERT_EQUAL(r, 7);

    r = glob_test(g, "fo.only", 0, NULL);
    CU_ASSERT_EQUAL(r, 7);

    r = glob_test(g, "f.oonly", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    glob_free(&g);
}

static void test_percent(void)
{
    glob *g;
    int r;

    g = glob_init("fo%", GLOB_HIERARCHY);
    CU_ASSERT_PTR_NOT_EQUAL_FATAL(g, NULL);

    r = glob_test(g, "foo", 0, NULL);
    CU_ASSERT_EQUAL(r, 3);

    r = glob_test(g, "meh", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "fnarp", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "fod", 0, NULL);
    CU_ASSERT_EQUAL(r, 3);

    r = glob_test(g, "foonly", 0, NULL);
    CU_ASSERT_EQUAL(r, 6);

    r = glob_test(g, "foon.ly", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "fo.only", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "f.oonly", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    glob_free(&g);
}

static void test_percent_percent(void)
{
    glob *g;
    int r;

    g = glob_init("fo%.%", GLOB_HIERARCHY);
    CU_ASSERT_PTR_NOT_EQUAL_FATAL(g, NULL);

    r = glob_test(g, "foonly", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "foon.ly", 0, NULL);
    CU_ASSERT_EQUAL(r, 7);

    r = glob_test(g, "fo.only", 0, NULL);
    CU_ASSERT_EQUAL(r, 7);

    r = glob_test(g, "f.oonly", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    glob_free(&g);
}

static void test_questionmark(void)
{
    glob *g;
    int r;

    g = glob_init("fo?", 0);
    CU_ASSERT_PTR_NOT_EQUAL_FATAL(g, NULL);

    r = glob_test(g, "foo", 0, NULL);
    CU_ASSERT_EQUAL(r, 3);

    r = glob_test(g, "meh", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "fnarp", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "fod", 0, NULL);
    CU_ASSERT_EQUAL(r, 3);

    r = glob_test(g, "foonly", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    glob_free(&g);
}

static void test_star_substring(void)
{
    glob *g;
    int r;

    g = glob_init("fo*", GLOB_SUBSTRING|GLOB_HIERARCHY);
    CU_ASSERT_PTR_NOT_EQUAL_FATAL(g, NULL);

    r = glob_test(g, "foo", 0, NULL);
    CU_ASSERT_EQUAL(r, 3);

    r = glob_test(g, "meh", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "mofoo", 0, NULL);
    CU_ASSERT_EQUAL(r, 5);

    r = glob_test(g, "fnarp", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "fod", 0, NULL);
    CU_ASSERT_EQUAL(r, 3);

    r = glob_test(g, "foonly", 0, NULL);
    CU_ASSERT_EQUAL(r, 6);

    r = glob_test(g, "foon.ly", 0, NULL);
    CU_ASSERT_EQUAL(r, 7);

    r = glob_test(g, "fo.only", 0, NULL);
    CU_ASSERT_EQUAL(r, 7);

    r = glob_test(g, "f.oonly", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "mo.foo", 0, NULL);
    CU_ASSERT_EQUAL(r, 6);

    glob_free(&g);
}

static void test_star_icase(void)
{
    glob *g;
    int r;

    g = glob_init("fo*", GLOB_ICASE|GLOB_HIERARCHY);
    CU_ASSERT_PTR_NOT_EQUAL_FATAL(g, NULL);

    r = glob_test(g, "foo", 0, NULL);
    CU_ASSERT_EQUAL(r, 3);

    r = glob_test(g, "meh", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "FOO", 0, NULL);
    CU_ASSERT_EQUAL(r, 3);

    r = glob_test(g, "MEH", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    r = glob_test(g, "Foo", 0, NULL);
    CU_ASSERT_EQUAL(r, 3);

    r = glob_test(g, "Meh", 0, NULL);
    CU_ASSERT_EQUAL(r, -1);

    glob_free(&g);
}

