#include "config.h"
#include "cunit/cunit.h"
#include "prot.h"
#include "xmalloc.h"
#include "util.h"

static void test_simple(void)
{
#define WORD0	"lorem"
#define WORD1	"ipsum"
    struct buf b = BUF_INITIALIZER;
    const char *s;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    buf_appendcstr(&b, WORD0);
    buf_putc(&b, ' ');
    buf_appendcstr(&b, WORD1);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0)-1+sizeof(WORD1)-1+1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);

    s = buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0)-1+sizeof(WORD1)-1+1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_STRING_EQUAL(s, WORD0" "WORD1);

    buf_free(&b);

#undef WORD0
#undef WORD1
}

static void test_map(void)
{
#define WORD0	"lorem"
#define WORD1	"ipsum"
    struct buf b = BUF_INITIALIZER;
    const char *map;
    int len;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    buf_appendmap(&b, WORD0, sizeof(WORD0)-1);
    buf_putc(&b, ' ');
    buf_appendmap(&b, WORD1, 2);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0)+2);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);

    map = (void *)0xdeadbeef;
    len = 42;
    buf_getmap(&b, &map, &len);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0)+2);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_EQUAL(len, b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_PTR_NOT_NULL(map);
    CU_ASSERT(!memcmp(map, WORD0" ip", sizeof(WORD0)+2));

    buf_free(&b);

#undef WORD0
#undef WORD1
}

static void test_long(void)
{
    struct buf b = BUF_INITIALIZER;
    int i;
    char *exp;
#define SZ  6
#define N 10000
    char tt[SZ+1];

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    for (i = 0 ; i < N ; i++) {
	snprintf(tt, sizeof(tt), "%c%05d", 'A'+(i%26), i);
	buf_appendcstr(&b, tt);
    }
    buf_cstring(&b);

    CU_ASSERT_EQUAL(b.len, SZ*N);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);

    exp = xmalloc(SZ*N+1);
    for (i = 0 ; i < N ; i++)
	snprintf(exp+SZ*i, SZ+1, "%c%05d", 'A'+(i%26), i);
    CU_ASSERT(!strcmp(b.s, exp));
    free(exp);

    buf_free(&b);
#undef N
#undef SZ
}

static void test_setcstr(void)
{
#define WORD0	"lorem"
    struct buf b = BUF_INITIALIZER;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    buf_setcstr(&b, WORD0);
    buf_cstring(&b);

    CU_ASSERT_EQUAL(b.len, sizeof(WORD0)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0);

    buf_free(&b);
#undef WORD0
}

static void test_setmap(void)
{
#define WORD1	"ipsum"
    struct buf b = BUF_INITIALIZER;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    buf_setmap(&b, WORD1, sizeof(WORD1)-1);
    buf_cstring(&b);

    CU_ASSERT_EQUAL(b.len, sizeof(WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD1);

    buf_free(&b);
#undef WORD1
}

static void test_append(void)
{
#define WORD0	"lorem"
#define WORD1	"ipsum"
    struct buf b = BUF_INITIALIZER;
    struct buf b2 = BUF_INITIALIZER;
    const char *s;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    CU_ASSERT_EQUAL(b2.len, 0);
    CU_ASSERT(b2.alloc >= b2.len);
    CU_ASSERT_EQUAL(buf_len(&b2), b2.len);
    CU_ASSERT_PTR_NULL(b2.s);

    buf_setmap(&b, WORD0, sizeof(WORD0)-1);
    buf_setmap(&b2, WORD1, sizeof(WORD1)-1);
    buf_append(&b, &b2);

    CU_ASSERT_EQUAL(b.len, sizeof(WORD0)-1+sizeof(WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    s = buf_cstring(&b);
    CU_ASSERT_STRING_EQUAL(s, WORD0""WORD1);

    CU_ASSERT_EQUAL(b2.len, sizeof(WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b2), b2.len);
    CU_ASSERT(b2.alloc >= b2.len);
    CU_ASSERT_PTR_NOT_NULL(b2.s);
    s = buf_cstring(&b2);
    CU_ASSERT_STRING_EQUAL(s, WORD1);

    buf_free(&b);
    buf_free(&b2);
#undef WORD0
#undef WORD1
}

static void test_appendbit32(void)
{
#define HEX0	0xcafebabe
#define HEX1	0xdeadbeef
    static const unsigned char HEX[8] = {
	0xca, 0xfe, 0xba, 0xbe,
	0xde, 0xad, 0xbe, 0xef
    };
    struct buf b = BUF_INITIALIZER;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    buf_appendbit32(&b, HEX0);
    buf_appendbit32(&b, HEX1);

    CU_ASSERT_EQUAL(b.len, 8);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT(!memcmp(b.s, HEX, sizeof(HEX)));

    buf_free(&b);
#undef HEX0
#undef HEX1
}

static void test_reset(void)
{
#define WORD0	"lorem"
#define WORD1	"ipsum"
    struct buf b = BUF_INITIALIZER;
    const char *s;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    buf_appendcstr(&b, WORD0);
    buf_reset(&b);
    buf_appendcstr(&b, WORD1);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);

    s = buf_cstring(&b);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_STRING_EQUAL(s, WORD1);

    buf_free(&b);

#undef WORD0
#undef WORD1
}

static void test_copy(void)
{
#define WORD0	"lorem"
#define WORD1	"ipsum"
    struct buf b = BUF_INITIALIZER;
    struct buf b2 = BUF_INITIALIZER;
    const char *s;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    CU_ASSERT_EQUAL(b2.len, 0);
    CU_ASSERT(b2.alloc >= b2.len);
    CU_ASSERT_EQUAL(buf_len(&b2), b2.len);
    CU_ASSERT_PTR_NULL(b2.s);

    buf_setmap(&b, WORD0, sizeof(WORD0)-1);
    buf_setmap(&b2, WORD1, sizeof(WORD1)-1);
    buf_copy(&b, &b2);

    CU_ASSERT_EQUAL(b.len, sizeof(WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    s = buf_cstring(&b);
    CU_ASSERT_STRING_EQUAL(s, WORD1);

    CU_ASSERT_EQUAL(b2.len, sizeof(WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b2), b2.len);
    CU_ASSERT(b2.alloc >= b2.len);
    CU_ASSERT_PTR_NOT_NULL(b2.s);
    s = buf_cstring(&b2);
    CU_ASSERT_STRING_EQUAL(s, WORD1);

    buf_free(&b);
    buf_free(&b2);
#undef WORD0
#undef WORD1
}

static void test_move(void)
{
#define WORD0	"lorem"
#define WORD1	"ipsummma"
    struct buf b = BUF_INITIALIZER;
    struct buf b2 = BUF_INITIALIZER;
    const char *s;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    CU_ASSERT_EQUAL(b2.len, 0);
    CU_ASSERT(b2.alloc >= b2.len);
    CU_ASSERT_EQUAL(buf_len(&b2), b2.len);
    CU_ASSERT_PTR_NULL(b2.s);

    buf_setmap(&b, WORD0, sizeof(WORD0)-1);
    buf_setmap(&b2, WORD1, sizeof(WORD1)-1);
    buf_move(&b, &b2);

    CU_ASSERT_EQUAL(b.len, sizeof(WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    s = buf_cstring(&b);
    CU_ASSERT_STRING_EQUAL(s, WORD1);

    CU_ASSERT_EQUAL(b2.len, 0);
    CU_ASSERT_EQUAL(buf_len(&b2), b2.len);
    CU_ASSERT_EQUAL(b2.alloc, 0);
    CU_ASSERT_PTR_NULL(b2.s);

    buf_free(&b);
    buf_free(&b2);
#undef WORD0
#undef WORD1
}

static void test_printf(void)
{
#define WORD0	"lorem"
#define WORD1	"ipsum"
#define DEC0	31337
#define HEX0	0xcafebabe
    struct buf b = BUF_INITIALIZER;
    const char *s;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    buf_printf(&b, WORD0" %s 0x%x %d", WORD1, HEX0, DEC0);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0)+sizeof(WORD1)+16);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);

    s = buf_cstring(&b);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_STRING_EQUAL(s, WORD0" "WORD1" 0xcafebabe 31337");

    buf_free(&b);
#undef WORD0
#undef WORD1
#undef DEC0
#undef HEX0
}

/*
 * This test exercises an important feature of buf_printf, namely
 * formatting a result which is longer than the size that buf_printf()
 * initially guesses it will need.  That feature relies on vsnprintf()
 * correctly realizing that it's about to overrun the buffer provided,
 * and returning the correct formatted size.  Experiment shows that
 * vsnprintf() behaves correctly (at least in glibc 2.11 on Ubuntu) but
 * something really bad happens in Valgrind (version
 * 1:3.6.0~svn20100724-0ubuntu2).  I suspect a bug in Valgrind's
 * replacement mempcpy() routine.  Until Valgrind is fixed, let's just
 * disable this test.
 */

// static void test_long_printf(void)
// {
//     struct buf b = BUF_INITIALIZER;
//     int i;
//     const char *s;
//     char *exp;
// #define SZ  6
// #define N 10000
// 
//     CU_ASSERT_EQUAL(b.len, 0);
//     CU_ASSERT(b.alloc >= b.len);
//     CU_ASSERT_EQUAL(buf_len(&b), b.len);
//     CU_ASSERT_PTR_NULL(b.s);
// 
//     exp = xmalloc(SZ*N+1);
//     for (i = 0 ; i < N ; i++)
// 	snprintf(exp+SZ*i, SZ+1, "%c%05d", 'A'+(i%26), i);
// 
//     buf_printf(&b, "x%sy", exp);
//     s = buf_cstring(&b);
// 
//     CU_ASSERT_EQUAL(b.len, SZ*N+2);
//     CU_ASSERT_EQUAL(buf_len(&b), b.len);
//     CU_ASSERT(b.alloc >= b.len);
//     CU_ASSERT_PTR_NOT_NULL(b.s);
// 
//     CU_ASSERT_PTR_NOT_NULL(s);
//     CU_ASSERT_EQUAL(s[0], 'x');
//     CU_ASSERT(!memcmp(s+1, exp, SZ*N));
//     CU_ASSERT_EQUAL(s[SZ*N+1], 'y');
// 
//     buf_free(&b);
//     free(exp);
// #undef N
// #undef SZ
// }

static void test_replace_all(void)
{
#define WORD0	"lorem"
#define WORD0REP "LAUREN BACALL"
#define WORD0REP2 "L0R3M"
#define WORD0REP3 "LRM"
#define WORD0REP4 "XloremY"
#define WORD1	"ipsum"
#define WORD1	"ipsum"
#define WORD2	"dolor"
#define WORD3	"sit"
#define WORD4	"amet"
    struct buf b = BUF_INITIALIZER;
    unsigned int n;
    char *buf_s;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    /* simple test: a single replacement */
    buf_reset(&b);
    buf_appendcstr(&b, WORD0" "WORD1);
    buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0" "WORD1);

    n = buf_replace_all(&b, WORD0, WORD0REP);
    CU_ASSERT_EQUAL(n, 1);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0REP" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0REP" "WORD1);

    /* simple test: failure to match */
    buf_reset(&b);
    buf_appendcstr(&b, WORD0" "WORD1);
    buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0" "WORD1);

    n = buf_replace_all(&b, WORD4, WORD0REP);
    CU_ASSERT_EQUAL(n, 0);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0" "WORD1);

    /* a replacement which doesn't change the size */
    buf_reset(&b);
    buf_appendcstr(&b, WORD0" "WORD1);
    buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0" "WORD1);

    buf_s = b.s;
    n = buf_replace_all(&b, WORD0, WORD0REP2);
    CU_ASSERT_EQUAL(n, 1);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0REP2" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_PTR_EQUAL(b.s, buf_s);  /* no size change => no realloc */
    CU_ASSERT_STRING_EQUAL(b.s, WORD0REP2" "WORD1);

    /* a replacement which shrinks the size */
    buf_reset(&b);
    buf_appendcstr(&b, WORD0" "WORD1);
    buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0" "WORD1);

    /* a replacement with an empty string */
    buf_reset(&b);
    buf_appendcstr(&b, WORD0" "WORD1);
    buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0" "WORD1);

    buf_s = b.s;
    n = buf_replace_all(&b, WORD0, "");
    CU_ASSERT_EQUAL(n, 1);
    CU_ASSERT_EQUAL(b.len, sizeof(" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_PTR_EQUAL(b.s, buf_s);  /* no size change => no realloc */
    CU_ASSERT_STRING_EQUAL(b.s, " "WORD1);

    /* a replacement with a NULL string */
    buf_reset(&b);
    buf_appendcstr(&b, WORD0" "WORD1);
    buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0" "WORD1);

    buf_s = b.s;
    n = buf_replace_all(&b, WORD0, NULL);
    CU_ASSERT_EQUAL(n, 1);
    CU_ASSERT_EQUAL(b.len, sizeof(" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_PTR_EQUAL(b.s, buf_s);  /* no size change => no realloc */
    CU_ASSERT_STRING_EQUAL(b.s, " "WORD1);

    /* multiple replacements, including abutted ones */
    buf_reset(&b);
    buf_appendcstr(&b, WORD0" "WORD1" "WORD2" "WORD0" "WORD3" "WORD0""WORD0" "WORD4);
    buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0" "WORD1" "WORD2" "WORD0" "WORD3" "WORD0""WORD0" "WORD4)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0" "WORD1" "WORD2" "WORD0" "WORD3" "WORD0""WORD0" "WORD4);

    n = buf_replace_all(&b, WORD0, WORD0REP2);
    CU_ASSERT_EQUAL(n, 4);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0REP2" "WORD1" "WORD2" "WORD0REP2" "WORD3" "WORD0REP2""WORD0REP2" "WORD4)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0REP2" "WORD1" "WORD2" "WORD0REP2" "WORD3" "WORD0REP2""WORD0REP2" "WORD4);

    /* multiple replacements with a replacement which contains the match */
    buf_reset(&b);
    buf_appendcstr(&b, WORD0" "WORD1" "WORD2" "WORD0" "WORD3" "WORD0""WORD0" "WORD4);
    buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0" "WORD1" "WORD2" "WORD0" "WORD3" "WORD0""WORD0" "WORD4)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0" "WORD1" "WORD2" "WORD0" "WORD3" "WORD0""WORD0" "WORD4);

    n = buf_replace_all(&b, WORD0, WORD0REP4);
    CU_ASSERT_EQUAL(n, 4);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0REP4" "WORD1" "WORD2" "WORD0REP4" "WORD3" "WORD0REP4""WORD0REP4" "WORD4)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0REP4" "WORD1" "WORD2" "WORD0REP4" "WORD3" "WORD0REP4""WORD0REP4" "WORD4);

    buf_free(&b);

#undef WORD0
#undef WORD0REP
#undef WORD0REP2
#undef WORD0REP3
#undef WORD0REP4
#undef WORD1
#undef WORD2
#undef WORD3
#undef WORD4
}

static void test_truncate(void)
{
#define WORD0	"lorem"
#define WORD1	"ipsum"
    struct buf b = BUF_INITIALIZER;
    unsigned int i;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    /* buf_truncate() which shortens the buffer */
    buf_reset(&b);
    buf_appendcstr(&b, WORD0" "WORD1);
    buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0" "WORD1);

    buf_truncate(&b, sizeof(WORD0)-1);
    buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0);

    /* buf_truncate() which extends and zero-fills the buffer */
    buf_reset(&b);
    buf_appendcstr(&b, WORD0" "WORD1);
    buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0" "WORD1)-1);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0" "WORD1);

    buf_truncate(&b, sizeof(WORD0" "WORD1)-1+2048);
    buf_cstring(&b);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0" "WORD1)-1+2048);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_STRING_EQUAL(b.s, WORD0" "WORD1);
    for (i=sizeof(WORD0" "WORD1)-1; i<sizeof(WORD0" "WORD1)-1+2048 ; i++)
	if (b.s[i] != 0)
	    break;
    CU_ASSERT_EQUAL(i, sizeof(WORD0" "WORD1)-1+2048);

    buf_free(&b);

#undef WORD0
#undef WORD1
}

static void test_cmp(void)
{
/* words chosen to be in alphabetical order */
#define WORD0		"alpha"
#define WORD0SUB	"alp"
#define WORD1		"omega"
    struct buf a = BUF_INITIALIZER;
    struct buf b = BUF_INITIALIZER;
    int d;

    /* compare two empty (null) bufs */
    CU_ASSERT_PTR_NULL(a.s);
    CU_ASSERT_EQUAL(a.len, 0);
    CU_ASSERT_PTR_NULL(b.s);
    CU_ASSERT_EQUAL(b.len, 0);
    d = buf_cmp(&a, &b);
    CU_ASSERT_EQUAL(d, 0);
    d = buf_cmp(&b, &a);
    CU_ASSERT_EQUAL(d, 0);

    /* compare empty (null) vs empty (zero-length) */
    buf_appendcstr(&b, "foo");
    buf_truncate(&b, 0);
    CU_ASSERT_PTR_NULL(a.s);
    CU_ASSERT_EQUAL(a.len, 0);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_EQUAL(b.len, 0);
    d = buf_cmp(&a, &b);
    CU_ASSERT_EQUAL(d, 0);
    d = buf_cmp(&b, &a);
    CU_ASSERT_EQUAL(d, 0);

    /* compare identical strings */
    buf_reset(&a);
    buf_appendcstr(&a, WORD0);
    buf_reset(&b);
    buf_appendcstr(&b, WORD0);
    CU_ASSERT_PTR_NOT_NULL(a.s);
    CU_ASSERT_EQUAL(a.len, sizeof(WORD0)-1);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0)-1);
    d = buf_cmp(&a, &b);
    CU_ASSERT_EQUAL(d, 0);
    d = buf_cmp(&b, &a);
    CU_ASSERT_EQUAL(d, 0);

    /* compare different strings */
    buf_reset(&a);
    buf_appendcstr(&a, WORD0);
    buf_reset(&b);
    buf_appendcstr(&b, WORD1);
    CU_ASSERT_PTR_NOT_NULL(a.s);
    CU_ASSERT_EQUAL(a.len, sizeof(WORD0)-1);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD1)-1);
    d = buf_cmp(&a, &b);
    CU_ASSERT(d < 0);
    d = buf_cmp(&b, &a);
    CU_ASSERT(d > 0);

    /* compare different strings where one is
     * an initial subset of the other */
    buf_reset(&a);
    buf_appendcstr(&a, WORD0SUB);
    buf_reset(&b);
    buf_appendcstr(&b, WORD0);
    CU_ASSERT_PTR_NOT_NULL(a.s);
    CU_ASSERT_EQUAL(a.len, sizeof(WORD0SUB)-1);
    CU_ASSERT_PTR_NOT_NULL(b.s);
    CU_ASSERT_EQUAL(b.len, sizeof(WORD0)-1);
    d = buf_cmp(&a, &b);
    CU_ASSERT(d < 0);
    d = buf_cmp(&b, &a);
    CU_ASSERT(d > 0);

    buf_free(&a);
    buf_free(&b);
#undef WORD0
#undef WORD0SUB
#undef WORD1
}

static void test_cow(void)
{
    static const char DATA0[] = "LoRem";
    struct buf b = BUF_INITIALIZER;

    CU_ASSERT_EQUAL(b.len, 0);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NULL(b.s);

    buf_init_ro(&b, DATA0, sizeof(DATA0)-1);
    CU_ASSERT_EQUAL(b.len, sizeof(DATA0)-1);
    CU_ASSERT_EQUAL(b.alloc, 0);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_EQUAL(b.s, (char *)DATA0);

    buf_putc(&b, 'X');
    CU_ASSERT_EQUAL(b.len, sizeof(DATA0)-1+1);
    CU_ASSERT(b.alloc >= b.len);
    CU_ASSERT_EQUAL(buf_len(&b), b.len);
    CU_ASSERT_PTR_NOT_EQUAL(b.s, (char *)DATA0);

    buf_free(&b);
}

static void test_bufprint(void)
{
    struct buf b = BUF_INITIALIZER;
    struct protstream *outstream;
    int i;

    outstream = prot_writebuf(&b);

    for (i = 0; i < 5000; i++) {
	prot_putc('.', outstream);
    }

    prot_flush(outstream);
    prot_free(outstream);

    CU_ASSERT_EQUAL(b.len, 5000);

    buf_free(&b);
}

/* TODO: test the Copy-On-Write feature of buf_ensure()...if anyone
 * actually uses it */
