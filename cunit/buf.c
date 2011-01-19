#include "cunit/cunit.h"
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
