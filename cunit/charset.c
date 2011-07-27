#include "cunit/cunit.h"
#include "xmalloc.h"
#include "charset.h"

#define UTF8_REPLACEMENT    "\357\277\275"

static void test_lookupname(void)
{
    int cs, cs2;

    /* us-ascii must exist */
    cs = charset_lookupname("us-ascii");
    CU_ASSERT(cs >= 0);

    /* names are case-insensitive */
    cs2 = charset_lookupname("US-ASCII");
    CU_ASSERT(cs2 >= 0);
    CU_ASSERT_EQUAL(cs, cs2);

    cs2 = charset_lookupname("Us-AsCiI");
    CU_ASSERT(cs2 >= 0);
    CU_ASSERT_EQUAL(cs, cs2);

    /* some others must also exist */
    cs = charset_lookupname("utf-8");
    CU_ASSERT(cs >= 0);

    cs = charset_lookupname("utf-7");
    CU_ASSERT(cs >= 0);

    cs = charset_lookupname("iso-8859-1");
    CU_ASSERT(cs >= 0);
}

static void test_to_utf8(void)
{
    int cs;
    char *s;
    static const char ASCII_1[] = "Hello World";
    static const char ASCII_2[] = "Hello W\370rld";
    static const char UTF8_2[] = "Hello W" UTF8_REPLACEMENT "rld";
    static const char BASE64_3[] = "SGVsbG8gV29ybGQ=";
    static const char QP_4[] =
"If you believe that truth=3Dbeauty, then surely=20=\r\n"
"mathematics is the most beautiful branch of philosophy.\r\n";
    static const char ASCII_4[] =
"If you believe that truth=beauty, then surely "
"mathematics is the most beautiful branch of philosophy.\r\n";

    cs = charset_lookupname("us-ascii");
    CU_ASSERT(cs >= 0);

    /* zero length input */
    s = charset_to_utf8("", 0, cs, ENCODING_NONE);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_STRING_EQUAL(s, "");
    free(s);

    /* invalid encoding */
    s = charset_to_utf8(ASCII_1, sizeof(ASCII_1), cs, 0xdeadbeef);
    CU_ASSERT_PTR_NULL(s);

    /* invalid charset */
    s = charset_to_utf8(ASCII_1, sizeof(ASCII_1), 0xdeadbeef, ENCODING_NONE);
    CU_ASSERT_PTR_NULL(s);

    /* simple ASCII string */
    s = charset_to_utf8(ASCII_1, sizeof(ASCII_1)-1, cs, ENCODING_NONE);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_STRING_EQUAL(s, ASCII_1);
    free(s);

    /* ASCII string with an invalid character */
    s = charset_to_utf8(ASCII_2, sizeof(ASCII_2)-1, cs, ENCODING_NONE);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_STRING_EQUAL(s, UTF8_2);
    free(s);

    /* base64 encoding */
    s = charset_to_utf8(BASE64_3, sizeof(BASE64_3)-1, cs, ENCODING_BASE64);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_STRING_EQUAL(s, ASCII_1);
    free(s);

    /* Quoted-printable encoding */
    s = charset_to_utf8(QP_4, sizeof(QP_4)-1, cs, ENCODING_QP);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_STRING_EQUAL(s, ASCII_4);
    free(s);
}

static void test_decode_mimeheader(void)
{
    char *s;
    static const char ASCII_1[] = "Lorem IPSUM dolor \t \t  sit amet";
    static const char SEARCH_1[] = "lorem ipsum dolor sit amet";
    static const char ASCII_B64_2[] = "Lorem =?us-ascii?q?ipsum?= dolor "
				      "=?US-ASCII?Q?sit amet?=";
    static const char ASCII_B64_3[] = "Lorem =?iso-8859-1?q?ips=fcm?= \t"
				      "DOLOR =?iso-8859-1?Q?s=eft am=ebt?=";
    static const char SEARCH_3[] = "lorem ipsum dolor sit amet";

    s = charset_decode_mimeheader(NULL);
    CU_ASSERT_PTR_NULL(s);

    s = charset_decode_mimeheader("");
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_STRING_EQUAL(s, "");
    free(s);

    s = charset_decode_mimeheader(ASCII_1);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_STRING_EQUAL(s, SEARCH_1);
    free(s);

    s = charset_decode_mimeheader(ASCII_B64_2);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_STRING_EQUAL(s, SEARCH_1);
    free(s);

    s = charset_decode_mimeheader(ASCII_B64_3);
    CU_ASSERT_PTR_NOT_NULL(s);
    CU_ASSERT_STRING_EQUAL(s, SEARCH_3);
    free(s);
}
