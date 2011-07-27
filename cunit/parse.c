#include "config.h"
#include "cunit/cunit.h"
#include "xmalloc.h"
#include "prot.h"
#include "global.h"

#define CANARY		0xdeadbeef
#define CANARY64	0xdeadbeefcafebabe

int wrap_getint32(const char *s, int32_t *valp)
{
    struct protstream *prot;
    char *b;
    int c;

    b = xstrdup(s);	/* work around bug in prot_ungetc */
    prot = prot_readmap(b, strlen(b));
    *valp = CANARY;
    c = getint32(prot, valp);
    free(b);
    prot_free(prot);

    return c;
}

static void test_getint32(void)
{
    static const char STR1[] = "0 ";
    static const int32_t VAL1 = 0;
    static const char STR2[] = "1234567890 ";
    static const int32_t VAL2 = 1234567890;
//     static const char STR3[] = "12345678901234567890 ";
    static const char STR4[] = "123)";
    static const int32_t VAL4 = 123;
    static const char STR5[] = "y&+123 ";
    static const char STR6[] = "123";
    static const int32_t VAL6 = 123;
    static const char STR7[] = "-123 ";
    static const char STR8[] = "+123 ";
    int32_t val;
    int c;

    /* test a valid zero value */
    c = wrap_getint32(STR1, &val);
    CU_ASSERT_EQUAL(c, ' ');
    CU_ASSERT_EQUAL(val, VAL1);

    /* test a valid value with all the digits */
    c = wrap_getint32(STR2, &val);
    CU_ASSERT_EQUAL(c, ' ');
    CU_ASSERT_EQUAL(val, VAL2);

// This test fatal()s which we cannot catch for now
//     /* test a string with too many digits */
//     c = wrap_getint32(STR3, &val);
//     CU_ASSERT_EQUAL(c, EOF);
//     CU_ASSERT_EQUAL(val, CANARY);

    /* test a valid value with a different terminator */
    c = wrap_getint32(STR4, &val);
    CU_ASSERT_EQUAL(c, ')');
    CU_ASSERT_EQUAL(val, VAL4);

    /* test an invalid string */
    c = wrap_getint32(STR5, &val);
    CU_ASSERT_EQUAL(c, EOF);
    /* sadly, val is undefined at this point */

    /* test the corner case where we encounter EOF
     * at the end of a valid string of digits */
    c = wrap_getint32(STR6, &val);
    CU_ASSERT_EQUAL(c, EOF);
    CU_ASSERT_EQUAL(val, VAL6);

    /* test a leading - */
    c = wrap_getint32(STR7, &val);
    /* this would have succeeded if getint32() weren't broken */
    CU_ASSERT_EQUAL(c, EOF);
    /* sadly, val is undefined at this point */

    /* test a leading + */
    c = wrap_getint32(STR8, &val);
    /* this would have succeeded if getint32() weren't broken */
    CU_ASSERT_EQUAL(c, EOF);
    /* sadly, val is undefined at this point */
}

int wrap_getsint32(const char *s, int32_t *valp)
{
    struct protstream *prot;
    char *b;
    int c;

    b = xstrdup(s);	/* work around bug in prot_ungetc */
    prot = prot_readmap(b, strlen(b));
    *valp = CANARY;
    c = getsint32(prot, valp);
    free(b);
    prot_free(prot);

    return c;
}

static void test_getsint32(void)
{
    static const char STR1[] = "0 ";
    static const int32_t VAL1 = 0;
    static const char STR2[] = "1234567890 ";
    static const int32_t VAL2 = 1234567890;
//     static const char STR3[] = "12345678901234567890 ";
    static const char STR4[] = "123)";
    static const int32_t VAL4 = 123;
    static const char STR5[] = "y&+123 ";
    static const char STR6[] = "123";
    static const int32_t VAL6 = 123;
    static const char STR7[] = "-123 ";
    static const int32_t VAL7 = -123;
    static const char STR8[] = "+123 ";
    static const int32_t VAL8 = 123;
    int32_t val;
    int c;

    /* test a valid zero value */
    c = wrap_getsint32(STR1, &val);
    CU_ASSERT_EQUAL(c, ' ');
    CU_ASSERT_EQUAL(val, VAL1);

    /* test a valid value with all the digits */
    c = wrap_getsint32(STR2, &val);
    CU_ASSERT_EQUAL(c, ' ');
    CU_ASSERT_EQUAL(val, VAL2);

// This test fatal()s which we cannot catch for now
//     /* test a string with too many digits */
//     c = wrap_getsint32(STR3, &val);
//     CU_ASSERT_EQUAL(c, EOF);
//     CU_ASSERT_EQUAL(val, CANARY);

    /* test a valid value with a different terminator */
    c = wrap_getsint32(STR4, &val);
    CU_ASSERT_EQUAL(c, ')');
    CU_ASSERT_EQUAL(val, VAL4);

    /* test an invalid string */
    c = wrap_getsint32(STR5, &val);
    CU_ASSERT_EQUAL(c, EOF);
    /* sadly, val is undefined at this point */

    /* test the corner case where we encounter EOF
     * at the end of a valid string of digits */
    c = wrap_getsint32(STR6, &val);
    CU_ASSERT_EQUAL(c, EOF);
    CU_ASSERT_EQUAL(val, VAL6);

    /* test a leading - */
    c = wrap_getsint32(STR7, &val);
    CU_ASSERT_EQUAL(c, ' ');
    CU_ASSERT_EQUAL(val, VAL7);

    /* test a leading + */
    c = wrap_getsint32(STR8, &val);
    CU_ASSERT_EQUAL(c, ' ');
    CU_ASSERT_EQUAL(val, VAL8);
}

int wrap_getmodseq(const char *s, modseq_t *valp)
{
    struct protstream *prot;
    char *b;
    int c;

    b = xstrdup(s);	/* work around bug in prot_ungetc */
    prot = prot_readmap(b, strlen(b));
    *valp = CANARY64;
    c = getmodseq(prot, valp);
    free(b);
    prot_free(prot);

    return c;
}

static void test_getmodseq(void)
{
    static const char STR1[] = "0 ";
    static const modseq_t VAL1 = 0;
    static const char STR2[] = "1234567890 ";
    static const modseq_t VAL2 = 1234567890;
    static const char STR3[] = "12345678901234567890 ";
    static const modseq_t VAL3 = 12345678901234567890ULL;
    static const char STR3a[] = "123456789012345678901234567890 ";
    static const char STR4[] = "123)";
    static const modseq_t VAL4 = 123;
    static const char STR5[] = "y&+123 ";
    static const char STR6[] = "123";
    static const modseq_t VAL6 = 123;
    static const char STR7[] = "-123 ";
    static const char STR8[] = "+123 ";
    modseq_t val;
    int c;

    /* test a valid zero value */
    c = wrap_getmodseq(STR1, &val);
    CU_ASSERT_EQUAL(c, ' ');
    CU_ASSERT_EQUAL(val, VAL1);

    /* test a valid value with all the digits */
    c = wrap_getmodseq(STR2, &val);
    CU_ASSERT_EQUAL(c, ' ');
    CU_ASSERT_EQUAL(val, VAL2);

    /* test a valid value >32b */
    c = wrap_getmodseq(STR3, &val);
    CU_ASSERT_EQUAL(c, ' ');
    CU_ASSERT_EQUAL(val, VAL3);

// This test fatal()s which we cannot catch for now
//     /* test a string with too many digits */
//     c = wrap_getmodseq(STR3a, &val);
//     CU_ASSERT_EQUAL(c, EOF);
//     CU_ASSERT_EQUAL(val, CANARY64);

    /* test a valid value with a different terminator */
    c = wrap_getmodseq(STR4, &val);
    CU_ASSERT_EQUAL(c, ')');
    CU_ASSERT_EQUAL(val, VAL4);

    /* test an invalid string */
    c = wrap_getmodseq(STR5, &val);
    CU_ASSERT_EQUAL(c, EOF);
    /* sadly, val is undefined at this point */

    /* test the corner case where we encounter EOF
     * at the end of a valid string of digits */
    c = wrap_getmodseq(STR6, &val);
    CU_ASSERT_EQUAL(c, EOF);
    CU_ASSERT_EQUAL(val, VAL6);

    /* test a leading - */
    c = wrap_getmodseq(STR7, &val);
    CU_ASSERT_EQUAL(c, EOF);
    /* sadly, val is undefined at this point */

    /* test a leading + */
    c = wrap_getmodseq(STR8, &val);
    CU_ASSERT_EQUAL(c, EOF);
    /* sadly, val is undefined at this point */
}

