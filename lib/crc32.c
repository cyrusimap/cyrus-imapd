/* crc32.h
 */

#include <config.h>
#include "crc32.h"

#ifdef HAVE_ZLIB

#include <zlib.h>
#include "string.h"

uint32_t crc32_buf(const unsigned char *buf, unsigned bytes)
{
    uint32_t crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, buf, bytes);
    return crc;
}

uint32_t crc32_cstring(const unsigned char *buf)
{
    return crc32_buf(buf, strlen(buf));
}

uint32_t crc32_iovec(struct iovec *iov, int iovcnt)
{
    int n;
    uint32_t crc = crc32(0L, Z_NULL, 0);
    for (n = 0; n < iovcnt; n++) {
	if (iov[n].iov_len)
	    crc = crc32(crc, iov[n].iov_base, iov[n].iov_len);
    }
    return crc;
}

#else

/* STUB */
uint32_t crc32_buf(const unsigned char *buf, unsigned bytes)
{
    return 0;
}

/* STUB */
uint32_t crc32_cstring(const unsigned char *buf)
{
    return 0;
}

/* STUB */
uint32_t crc32_iovec(struct iovec *iov, int iovcnt)
{
    return 0;
}

#endif
