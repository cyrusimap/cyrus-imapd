/* crc32.h
 */

#include <config.h>
#include "crc32.h"
#include "util.h"

#ifdef HAVE_ZLIB

#include <zlib.h>
#include "string.h"

uint32_t crc32_map(const char *base, unsigned len)
{
    uint32_t crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const unsigned char *)base, len);
    return crc;
}

uint32_t crc32_buf(struct buf *buf)
{
    return crc32_map(buf->s, buf->len);
}

uint32_t crc32_cstring(const char *buf)
{
    return crc32_map(buf, strlen(buf));
}

uint32_t crc32_iovec(struct iovec *iov, int iovcnt)
{
    int n;
    uint32_t crc = crc32(0L, Z_NULL, 0);
    for (n = 0; n < iovcnt; n++) {
	if (iov[n].iov_len)
	    crc = crc32(crc, (const unsigned char *)iov[n].iov_base, iov[n].iov_len);
    }
    return crc;
}

#else

/* STUB */
uint32_t crc32_map(const char *buf, unsigned bytes)
{
    return 0;
}

/* STUB */
uint32_t crc32_cstring(const char *buf)
{
    return 0;
}

/* STUB */
uint32_t crc32_iovec(struct iovec *iov, int iovcnt)
{
    return 0;
}

#endif
