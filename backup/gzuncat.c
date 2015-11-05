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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "gzuncat.h"

/*
 * current_offset and next_offset together indicate the state of the reader:
 *
 * when not reading a member (after gzuc_open or gzuc_member_end):
 *
 *     current_offset = -1
 *     next_offset = start point for next call to gzuc_start()
 *
 * when reading a member (after gzuc_member_start):
 *
 *     current_offset = file offset of the start of the member being read
 *     next_offset = -1
 *
 * when reaching the end of a member (before gzuc_member_end):
 *
 *     current_offset = -1
 *     next_offset = -1
 */

static const size_t default_in_buf_size = 16 * 1024;

struct gzuncat {
    FILE *file;
    off_t current_offset;
    off_t next_offset;
    z_stream strm;
    unsigned char *in_buf;
    size_t in_buf_size;
    size_t bytes_read;
};

EXPORTED struct gzuncat *gzuc_open(int fd)
{
    struct gzuncat *gz = malloc(sizeof(*gz));
    if (!gz) return NULL;

    gz->file = fdopen(dup(fd), "rb");
    if (!gz->file) goto error;

    gz->current_offset = -1;
    gz->next_offset = 0;
    gz->in_buf = NULL;
    gz->in_buf_size = default_in_buf_size;
    gz->bytes_read = 0;

    return gz;

error:
    free(gz);
    return NULL;
}

EXPORTED int gzuc_set_bufsize(struct gzuncat *gz, size_t size)
{
    if (gz->in_buf) return -1;
    if (!size) return -1;

    gz->in_buf_size = size;

    return 0;
}

EXPORTED int gzuc_member_start_from(struct gzuncat *gz, off_t offset)
{
    if (gz->current_offset >= 0) return -1;
    if (offset < 0) return -1;

    if (!gz->in_buf) {
        gz->in_buf = malloc(gz->in_buf_size);
        if (!gz->in_buf) return -1;
    }

    memset(gz->in_buf, 0, gz->in_buf_size);

    int r = fseeko(gz->file, offset, SEEK_SET);
    if (r) return r;

    gz->strm.zalloc = Z_NULL;
    gz->strm.zfree = Z_NULL;
    gz->strm.opaque = Z_NULL;
    gz->strm.avail_in = 0;
    gz->strm.next_in = gz->in_buf;

    // 15 = support maximum window size
    // 16 = decode gzip format
    r = inflateInit2(&gz->strm, 15 + 16);
    if (r) return r;

    // anything else to initialise?

    gz->current_offset = offset;
    gz->next_offset = -1;
    gz->bytes_read = 0;

    return 0;
}

EXPORTED int gzuc_member_start(struct gzuncat *gz)
{
    return gzuc_member_start_from(gz, gz->next_offset);
}

EXPORTED int gzuc_member_end(struct gzuncat *gz, off_t *offset)
{
    if (gz->next_offset >= 0) return -1;

    int r = 0;

    if (feof(gz->file)) goto done;

    if (gz->current_offset >= 0) {
        char discard[16 * 1024];
        while ((r = gzuc_read(gz, discard, sizeof(discard))) > 0);
        if (feof(gz->file)) goto done;
        if (r < 0) goto done;
    }

    gz->next_offset = ftello(gz->file);

done:
    inflateEnd(&gz->strm);
    gz->current_offset = -1;
    gz->bytes_read = 0;
    if (!r && offset) *offset = gz->next_offset;
    return r;
}

EXPORTED void gzuc_close(struct gzuncat **gzp)
{
    if (!gzp) return;
    if (!*gzp) return;

    struct gzuncat *gz = *gzp;
    *gzp = NULL;

    inflateEnd(&gz->strm);

    if (gz->in_buf) {
        free(gz->in_buf);
    }

    if (gz->file) {
        fclose(gz->file);
    }

    free(gz);
}

EXPORTED int gzuc_member_eof(struct gzuncat *gz)
{
    if (gz->current_offset < 0) return 1;
    if (gz->strm.avail_in) return 0;
    return feof(gz->file);
}

EXPORTED int gzuc_eof(struct gzuncat *gz)
{
    return feof(gz->file);
}

EXPORTED ssize_t gzuc_read(struct gzuncat *gz, void *buf, size_t count)
{
    if (gz->current_offset < 0) return 0;

    gz->strm.avail_out = count;
    gz->strm.next_out = buf;

    ssize_t uncompressed = 0;
    int r = 0;

    memset(buf, 0, count);

    do {
        // read some more input if we need it
        if (!gz->strm.avail_in) {
            gz->strm.avail_in = fread(gz->in_buf, 1, gz->in_buf_size, gz->file);

            r = ferror(gz->file);
            if (r) return r;

            if (gz->strm.avail_in == 0)
                break;

            gz->strm.next_in = gz->in_buf;
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
                r = fseeko(gz->file, 0 - (off_t) gz->strm.avail_in, SEEK_CUR);
                if (r) return r;
                gz->strm.avail_in = 0;
                gz->strm.next_in = gz->in_buf;
            }

            gz->current_offset = -1;
            break;
        }
        else {
            return r;
        }
    } while (gz->strm.avail_out); // keep going while we haven't filled the buffer

    gz->bytes_read += uncompressed;
    return uncompressed;
}

EXPORTED int gzuc_skip(struct gzuncat *gz, size_t len)
{
    if (gz->current_offset < 0) return -1;
    if (feof(gz->file)) return -1;

    while (len) {
        unsigned char discard[16 * 1024];

        size_t want = len;
        if (want > sizeof(discard)) want = sizeof(discard);

        ssize_t got = gzuc_read(gz, discard, want);
        if (got <= 0) return -1;

        len -= got;
    }

    return 0;
}

EXPORTED off_t gzuc_member_offset(struct gzuncat *gz)
{
    return gz->current_offset;
}

EXPORTED size_t gzuc_member_bytes_read(struct gzuncat *gz)
{
    return gz->bytes_read;
}
