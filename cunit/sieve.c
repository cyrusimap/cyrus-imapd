/* Unit test for sieve */
#include "cunit/cunit.h"
#include "bytecode.h"
#include "comparator.h"

#define TESTCASE(_comp, _mode, _pat, _text, _result)		\
    comprock = NULL;						\
    c = lookup_comp(_comp, _mode, -1, &comprock);		\
    CU_ASSERT_PTR_NOT_NULL(c);					\
    if (c) {							\
	res = c(_text, strlen(_text), _pat, comprock);		\
	CU_ASSERT_EQUAL(res, _result);				\
    }

static void test_comparator(void)
{
    void *comprock;
    comparator_t *c;
    int res;

    TESTCASE( B_OCTET, B_IS, "", "", 1 );
    TESTCASE( B_OCTET, B_IS, "a", "", 0 );
    TESTCASE( B_OCTET, B_IS, "", "a", 0 );
    TESTCASE( B_OCTET, B_IS, "a", "a", 1 );
    TESTCASE( B_OCTET, B_IS, "a", "A", 0 );

    TESTCASE( B_ASCIICASEMAP, B_IS, "", "", 1 );
    TESTCASE( B_ASCIICASEMAP, B_IS, "a", "", 0 );
    TESTCASE( B_ASCIICASEMAP, B_IS, "", "a", 0 );
    TESTCASE( B_ASCIICASEMAP, B_IS, "a", "a", 1 );
    TESTCASE( B_ASCIICASEMAP, B_IS, "a", "A", 1 );

    TESTCASE( B_ASCIINUMERIC, B_IS, "123", "123", 1 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "123", "-123", 0 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "abc", "123", 0 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "abc", "abc", 1 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "12345678900", "3755744308", 0 );    /* test for 32bit overflow */
    TESTCASE( B_ASCIINUMERIC, B_IS, "1567", "1567pounds", 1 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "", "", 1 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "123456789", "567", 0 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "567", "123456789", 0 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "123456789", "00000123456789", 1 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "102", "1024", 0 );
    TESTCASE( B_ASCIINUMERIC, B_IS, "1567M", "1567 arg", 1 );

    TESTCASE( B_OCTET, B_CONTAINS, "", "", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "", "a", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "", 0 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "a", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "ab", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "ba", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "aba", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "bab", 1 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "bb", 0 );
    TESTCASE( B_OCTET, B_CONTAINS, "a", "bbb", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "", "", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "", "a", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "a", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "ab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "aba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a", "bbb", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "*", "", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*", "a", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "a", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "ab", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "ba", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "aba", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "bab", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "*a*", "bbb", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "*a", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "a", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "ab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "ba", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "aba", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "*a", "bbb", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "a*", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "a", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "ab", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "aba", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*", "bbb", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "a*b", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "a", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "ab", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "aba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "bbb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "abbb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "acb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*b", "acbc", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "a?b", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "a", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "ab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "aba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "bbb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "abbb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "acb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a?b", "acbc", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "a", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "ab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "aba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "bbb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "abbb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "acb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?b", "acbc", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "a", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "ab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "aba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "bbb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "abbb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "acb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a?*b", "acbc", 0 );

    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "a", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "ab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "ba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "aba", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "bab", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "bb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "bbb", 0 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "abbb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b", "acb", 1 );
    TESTCASE( B_OCTET, B_MATCHES, "a*?*b?", "acbc", 1 );

    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "a", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "ab", 1 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "ba", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "aba", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "bab", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "bb", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "bbb", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "abbb", 1 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "acb", 1 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "acbc", 0 );

    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "A", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "Ab", 1 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "BA", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "ABA", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "BAb", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "BB", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "BBB", 0 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "aBBB", 1 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "ACB", 1 );
    TESTCASE( B_ASCIICASEMAP, B_MATCHES, "a*b", "ACBC", 0 );
}
