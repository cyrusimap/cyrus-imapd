/* crc32.h
 */

#ifndef CRC32_H
#define CRC32_H
#include "util.h"
#include <sys/uio.h>
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#elif defined(HAVE_STDINT_H)
# include <stdint.h>
#endif

#define crc32_map(buf, len) crc32_impl((const unsigned char *)(buf), (size_t)(len))
uint32_t crc32_impl(const unsigned char *buf, size_t len);
uint32_t crc32_buf(const struct buf *buf);
uint32_t crc32_cstring(const char *buf);
uint32_t crc32_iovec(struct iovec *iov, int iovcnt);

#endif
