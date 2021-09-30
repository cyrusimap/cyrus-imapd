/* gzuncat.c - read individual members from concatenated gzip files
 *
 * Copyright (c) 2015 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <zlib.h>

#include "lib/xmalloc.h"

#include "lib/gzuncat.h"

/*
 * current_offset, next_offset, and member_eof together indicate the state of
 * the reader:
 *
 * when not reading a member (after gzuc_new or gzuc_member_end):
 *
 *     current_offset = -1
 *     next_offset = start point for next call to gzuc_start()
 *     member_eof = undefined
 *
 * when reading a member (after gzuc_member_start):
 *
 *     current_offset = file offset of the start of the member being read
 *     next_offset = -1
 *     member_eof = 0
 *
 * when reaching the end of a member (before gzuc_member_end):
 *
 *     current_offset = file offset of the start of the member being read
 *     next_offset = -1
 *     member_eof = 1
 */

static const size_t default_in_buf_size = 16 * 1024;

struct gzuncat {
    int   fd;
    off_t current_offset;
    off_t next_offset;
    int   member_eof;
    int   file_eof;
    z_stream strm;
    unsigned char *in_buf;
    size_t in_buf_size;
    size_t bytes_read;
};

EXPORTED struct gzuncat *gzuc_new(int fd)
{
    struct gzuncat *gz;

    if (fd < 0) return NULL;

    gz = xmalloc(sizeof(*gz));

    gz->fd = fd;
    gz->current_offset = -1;
    gz->next_offset = 0;
    gz->member_eof = -1;
    gz->file_eof = 0;
    gz->in_buf = NULL;
    gz->in_buf_size = default_in_buf_size;
    gz->bytes_read = 0;

    return gz;
}

EXPORTED int gzuc_set_bufsize(struct gzuncat *gz, size_t size)
{
    if (gz->in_buf) return -1;
    if (!size) return -1;

    gz->in_buf_size = size;

    return 0;
}

static int _inflate_init(z_stream *strm, unsigned char *in_buf)
{
    strm->zalloc = Z_NULL;
    strm->zfree = Z_NULL;
    strm->opaque = Z_NULL;
    strm->avail_in = 0;
    strm->next_in = in_buf;

    // 15 = support maximum window size
    // 16 = decode gzip format
    return inflateInit2(strm, 15 + 16);
}

EXPORTED int gzuc_member_start_from(struct gzuncat *gz, off_t offset)
{
    off_t p;
    int r;

    if (gz->current_offset >= 0 || offset < 0) {
        errno = EINVAL;
        return Z_ERRNO;
    }

    if (!gz->in_buf)
        gz->in_buf = xmalloc(gz->in_buf_size);

    memset(gz->in_buf, 0, gz->in_buf_size);

    p = lseek(gz->fd, offset, SEEK_SET);
    if (p < 0) return Z_ERRNO;

    r = _inflate_init(&gz->strm, gz->in_buf);
    if (r) return r;

    // anything else to initialise?

    gz->current_offset = offset;
    gz->next_offset = -1;
    gz->member_eof = 0;
    gz->file_eof = 0;
    gz->bytes_read = 0;

    return 0;
}

EXPORTED int gzuc_member_start(struct gzuncat *gz)
{
    return gzuc_member_start_from(gz, gz->next_offset);
}

EXPORTED int gzuc_member_end(struct gzuncat *gz, off_t *offset)
{
    int r = 0;

    if (gz->next_offset >= 0) return -1;

    if (gz->file_eof) goto done;

    if (gz->current_offset >= 0) {
        char discard[16 * 1024];
        while ((r = gzuc_read(gz, discard, sizeof(discard))) > 0);

        /* don't set next_offset if we're at end of underlying file */
        if (gz->file_eof) goto done;
        /* nor if there was an error */
        if (r < 0) goto done;
    }

    /* we're now at the start of the next member */
    gz->next_offset = lseek(gz->fd, 0, SEEK_CUR);

done:
    inflateEnd(&gz->strm);
    gz->current_offset = -1;
    gz->member_eof = -1;
    gz->bytes_read = 0;
    if (!r && offset) *offset = gz->next_offset;
    return r;
}

EXPORTED void gzuc_free(struct gzuncat **gzp)
{
    struct gzuncat *gz;

    if (!gzp) return;
    if (!*gzp) return;

    gz = *gzp;
    *gzp = NULL;

    if (gz->current_offset >= 0)
        inflateEnd(&gz->strm);

    if (gz->in_buf) {
        free(gz->in_buf);
    }

    free(gz);
}

EXPORTED int gzuc_member_eof(struct gzuncat *gz)
{
    if (gz->member_eof == 1) return 1;
    if (gz->current_offset < 0) return 1;
    if (gz->strm.avail_in) return 0;
    return gz->file_eof;
}

EXPORTED int gzuc_eof(struct gzuncat *gz)
{
    return gz->file_eof;
}

EXPORTED ssize_t gzuc_read(struct gzuncat *gz, void *buf, size_t count)
{
    ssize_t uncompressed = 0;
    int r = 0;

    if (gz->current_offset < 0) return -1;
    if (gz->member_eof == 1) return 0;
    if (gz->file_eof == 1) return 0;

    gz->strm.avail_out = count;
    gz->strm.next_out = buf;

    memset(buf, 0, count);

    do {
        // read some more input if we need it
        if (!gz->strm.avail_in) {
            r = read(gz->fd, gz->in_buf, gz->in_buf_size);

            if (r < 0) {
                syslog(LOG_ERR, "IOERROR: %s: read %d: %m", __func__, gz->fd);
                return r;
            }
            else if (r == 0) {
                gz->file_eof = 1;
                break;
            }
            else {
                gz->strm.avail_in = r;
                gz->strm.next_in = gz->in_buf;
            }
        }

        r = inflate(&gz->strm, Z_SYNC_FLUSH /* FIXME what */);
        uncompressed = count - gz->strm.avail_out;

        if (r == Z_OK) {
            continue;
        }
        else if (r == Z_STREAM_END) {
            // if we get to the end of the gzip member, and there's still data avail_in the stream
            // object, then we've read too much (we're starting to see the next section of the file)
            // so we need to seek back to the right spot and update next_offset
            if (gz->strm.avail_in) {
                off_t p = lseek(gz->fd, 0 - (off_t) gz->strm.avail_in, SEEK_CUR);
                if (p < 0) {
                    syslog(LOG_ERR, "IOERROR: %s: lseek %d: %m", __func__, gz->fd);
                    return -1;
                }
                gz->strm.avail_in = 0;
                gz->strm.next_in = gz->in_buf;
            }

            gz->member_eof = 1;
            break;
        }
        else {
            syslog(LOG_DEBUG, "IOERROR: gzuc_read: returning %i (%s)", r, gz->strm.msg);
            return r;
        }
    } while (gz->strm.avail_out); // keep going while we haven't filled the buffer

    gz->bytes_read += uncompressed;
    return uncompressed;
}

EXPORTED int gzuc_skip(struct gzuncat *gz, size_t len)
{
    if (gzuc_member_eof(gz)) return -1;

    while (len) {
        unsigned char discard[16 * 1024];
	ssize_t got;

        size_t want = len;
        if (want > sizeof(discard)) want = sizeof(discard);

        got = gzuc_read(gz, discard, want);
        if (got == 0) return -1;
        if (got < 0) return got;

        len -= got;
    }

    return 0;
}

/* n.b. not a conventional seek function - only seeks to absolute position
 * it's also pretty expensive if the position is earlier than the
 * current position, so try to keep your reads in order
 */
EXPORTED int gzuc_seekto(struct gzuncat *gz, size_t pos)
{
    if (gz->current_offset < 0) return -1;

    gz->member_eof = 0;
    gz->file_eof = 0;

    if (pos == gz->bytes_read) return 0;

    if (pos < gz->bytes_read) {
        int r;
        off_t p = lseek(gz->fd, gz->current_offset, SEEK_SET);
        if (p < 0) return -1;

        inflateEnd(&gz->strm);
        r = _inflate_init(&gz->strm, gz->in_buf);
        if (r) return r;

        gz->bytes_read = 0;
    }

    return gzuc_skip(gz, pos - gz->bytes_read);
}

EXPORTED off_t gzuc_member_offset(struct gzuncat *gz)
{
    return gz->current_offset;
}

EXPORTED size_t gzuc_member_bytes_read(struct gzuncat *gz)
{
    return gz->bytes_read;
}
