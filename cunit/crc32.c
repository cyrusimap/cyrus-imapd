/* Unit test for lib/crc32.c */
#include "cunit/cunit.h"
#include "crc32.h"

static void test_map(void)
{
    static const char TEXT[] = "lorem ipsum";
    static uint32_t CRC32 = 0x72d7748e;
    uint32_t c;

    c = crc32_map(TEXT, sizeof(TEXT)-1);
    CU_ASSERT_EQUAL(c, CRC32);
}

static void test_iovec(void)
{
    static const char TEXT1[] = "lorem";
    static const char TEXT2[] = " ipsum";
    static uint32_t CRC32 = 0x72d7748e;
    uint32_t c;
    struct iovec iov[2];

    memset(iov, 0, sizeof(iov));
    iov[0].iov_base = (char *)TEXT1;
    iov[0].iov_len = sizeof(TEXT1)-1;
    iov[1].iov_base = (char *)TEXT2;
    iov[1].iov_len = sizeof(TEXT2)-1;

    c = crc32_iovec(iov, 2);
    CU_ASSERT_EQUAL(c, CRC32);
}
