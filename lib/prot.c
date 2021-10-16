/* prot.c -- stdio-like module that handles SASL protection mechanisms
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
#include <errno.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <signal.h>
#include <stdarg.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "assert.h"
#include "imparse.h"
#include "libcyr_cfg.h"
#include "map.h"
#include "nonblock.h"
#include "prot.h"
#include "signals.h"
#include "util.h"
#include "xmalloc.h"

/* Transparent protgroup structure */
struct protgroup
{
    size_t nalloced; /* Number of nodes in the group */
    size_t next_element; /* Node number of next group member */
    struct protstream **group;
};

/*
 * Create a new protection stream for file descriptor 'fd'.  Stream
 * will be used for writing iff 'write' is nonzero.
 */
EXPORTED struct protstream *prot_new(int fd, int write)
{
    struct protstream *newstream;

    newstream = (struct protstream *) xzmalloc(sizeof(struct protstream));
    newstream->buf = (unsigned char *)
        xmalloc(sizeof(char) * (PROT_BUFSIZE));
    newstream->buf_size = PROT_BUFSIZE;
    newstream->ptr = newstream->buf;
    newstream->maxplain = PROT_BUFSIZE;
    newstream->fd = fd;
    newstream->write = write;
    newstream->logfd = PROT_NO_FD;
    newstream->big_buffer = PROT_NO_FD;
    if(write)
        newstream->cnt = PROT_BUFSIZE;

    return newstream;
}

EXPORTED struct protstream *prot_writebuf(struct buf *buf)
{
    struct protstream *newstream;

    newstream = (struct protstream *) xzmalloc(sizeof(struct protstream));
    /* dodgy, but the alternative is two pointers */
    newstream->buf = (unsigned char *)
        xmalloc(sizeof(char) * (PROT_BUFSIZE));
    newstream->buf_size = PROT_BUFSIZE;
    newstream->ptr = newstream->buf;
    newstream->cnt = PROT_BUFSIZE;
    newstream->maxplain = PROT_BUFSIZE;
    newstream->write = 1;
    newstream->writetobuf = buf;
    newstream->fd = PROT_NO_FD;
    newstream->logfd = PROT_NO_FD;
    newstream->big_buffer =  PROT_NO_FD;
    /* there's no way to wait for + go ahead here! */
    newstream->isclient = 1;

    return newstream;
}

/* Create a protstream which is just an interface to a mapped piece of
 * memory, allowing prot commands to be used to read from it */
EXPORTED struct protstream *prot_readmap(const char *base, uint32_t len)
{
    struct protstream *newstream;

    newstream = (struct protstream *) xzmalloc(sizeof(struct protstream));
    /* dodgy, but the alternative is two pointers */
    newstream->ptr = (unsigned char *)base;
    newstream->cnt = len;
    newstream->fixedsize = 1;
    newstream->fd = PROT_NO_FD;
    newstream->logfd = PROT_NO_FD;
    newstream->big_buffer = PROT_NO_FD;

    return newstream;
}

/*
 * Create a protstream for reading whose data is supplied by a callback rather
 * than a file descriptor.
 *
 * The callback interface is similar to read(2):
 *
 *      typedef ssize_t prot_fillcallback_t(unsigned char *buf, size_t len, void *rock)
 *
 *      Read up to len bytes into the buffer buf.  On success, return the
 *      number of bytes read, or 0 if there is no more data.  On error, set
 *      errno to an appropriate value and return -1.
 */
EXPORTED struct protstream *prot_readcb(prot_fillcallback_t *proc, void *rock)
{
    struct protstream *newstream;

    newstream = (struct protstream *) xzmalloc(sizeof(struct protstream));
    newstream->buf = (unsigned char *)
        xmalloc(sizeof(char) * (PROT_BUFSIZE));
    newstream->buf_size = PROT_BUFSIZE;
    newstream->ptr = newstream->buf;
    newstream->maxplain = PROT_BUFSIZE;
    newstream->fd = PROT_NO_FD;
    newstream->logfd = PROT_NO_FD;
    newstream->big_buffer = PROT_NO_FD;

    newstream->fillcallback_proc = proc;
    newstream->fillcallback_rock = rock;

    return newstream;
}

/*
 * Free a protection stream
 */
EXPORTED int prot_free(struct protstream *s)
{
    if (s->error) free(s->error);
    free(s->buf);

    if(s->big_buffer != PROT_NO_FD) {
        map_free(&(s->bigbuf_base), &(s->bigbuf_siz));
        close(s->big_buffer);
    }

#ifdef HAVE_ZLIB
    if (s->zstrm) {
        if (s->write) deflateEnd(s->zstrm);
        else inflateEnd(s->zstrm);
        free(s->zstrm);
    }
    if (s->zbuf) free(s->zbuf);
#endif

    free(s);

    return 0;
}

/*
 * Set the logging file descriptor for stream 's' to be 'fd'.
 */
EXPORTED int prot_setlog(struct protstream *s, int fd)
{
    s->logfd = fd;
    return 0;
}

EXPORTED int prot_setisclient(struct protstream *s, int val)
{
    s->isclient = val;
    return 0;
}

#ifdef HAVE_SSL

/*
 * Turn on TLS for this connection
 */

EXPORTED int prot_settls(struct protstream *s, SSL *tlsconn)
{
    s->tls_conn = tlsconn;

    /* Make nonblocking stuff to work similar to write() */
    SSL_set_mode(tlsconn,
                 SSL_MODE_ENABLE_PARTIAL_WRITE
                 | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    return 0;
}

#endif /* HAVE_SSL */

/*
 * Decode data sent via a SASL security layer. Returns EOF on error.
 */
static int prot_sasldecode(struct protstream *s, int n)
{
    int result;
    const char *out;
    unsigned outlen;

    assert(!s->write);

    /* decode the input */
    result = sasl_decode(s->conn, (const char *) s->buf, n,
                         &out, &outlen);

    if (result != SASL_OK) {
        char errbuf[256];
        const char *ed = sasl_errdetail(s->conn);

        snprintf(errbuf, 256, "decoding error: %s; %s",
                 sasl_errstring(result, NULL, NULL),
                 ed ? ed : "no detail");
        s->error = xstrdup(errbuf);
        return EOF;
    }

    if (outlen > 0) {
      /* The contents of 'out' is static until next call to
         sasl_decode(), so serve data directly from 'out' */
        s->ptr = (unsigned char *) out;
        s->cnt = outlen;
    } else {            /* didn't decode anything */
        s->cnt = 0;
    }

    return 0;
}

/*
 * Turn on SASL for this connection
 */

EXPORTED int prot_setsasl(struct protstream *s, sasl_conn_t *conn)
{
    const void *ssfp;
    int result;

    if (s->write && s->ptr != s->buf) {
        /* flush any pending output */
        if (prot_flush_internal(s, 0) == EOF)
            return EOF;
    }

    s->conn = conn;

    result = sasl_getprop(conn, SASL_SSF, &ssfp);
    if (result != SASL_OK) {
        return -1;
    }
    s->saslssf = *((const int *) ssfp);

    if (s->write) {
        const void *maxp;
        unsigned int max;

        /* ask SASL for layer max */
        result = sasl_getprop(conn, SASL_MAXOUTBUF, &maxp);
        max = *((const unsigned int *) maxp);
        if (result != SASL_OK) {
            return -1;
        }

        if (max == 0 || max > PROT_BUFSIZE) {
            /* max = 0 means unlimited, and we can't go bigger */
            max = PROT_BUFSIZE;
        }

        s->maxplain = max;
        s->cnt = max;
    }
    else if (s->cnt) {
        /* decode any pending input */
        if (prot_sasldecode(s, s->cnt) == EOF) return EOF;
    }

    return 0;
}

/*
 * Turn off SASL for this connection
 */

EXPORTED void prot_unsetsasl(struct protstream *s)
{
    s->conn = NULL;
    s->maxplain = PROT_BUFSIZE;
    s->saslssf = 0;
}

#ifdef HAVE_ZLIB

#define ZLARGE_DIFF_CHUNK (5120) /* 5K */

/* Wrappers for our memory management functions */
static voidpf zalloc(voidpf opaque __attribute__((unused)),
                     uInt items, uInt size)
{
    return (voidpf) xmalloc(items * size);
}

static void zfree(voidpf opaque __attribute__((unused)),
                  voidpf address)
{
    free(address);
}

/*
 * Turn on (de)compression for this connection
 * If its an output stream, initialize a compressor,
 * otherwise initialize a decompressor.
 */

EXPORTED int prot_setcompress(struct protstream *s)
{
    int zr = Z_OK;
    z_stream *zstrm = (z_stream *) xmalloc(sizeof(z_stream));

    zstrm->zalloc = zalloc;
    zstrm->zfree = zfree;
    zstrm->opaque = Z_NULL;

    if (s->write) {
        if (s->ptr != s->buf) {
            /* flush any pending output */
            if (prot_flush_internal(s, 0) == EOF)
                goto error;
        }

        s->zlevel = Z_DEFAULT_COMPRESSION;
        zr = deflateInit2(zstrm, s->zlevel, Z_DEFLATED,
                          -MAX_WBITS,           /* raw deflate */
                          MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
    }
    else {
        zstrm->next_in = Z_NULL;
        zstrm->avail_in = 0;
        zr = inflateInit2(zstrm, -MAX_WBITS);   /* raw inflate */
    }

    if (zr != Z_OK)
        goto error;

    /* RFC 1951 says:
     * A simple counting argument shows that no lossless compression
     * algorithm can compress every possible input data set.  For the
     * format defined here, the worst case expansion is 5 bytes per 32K-
     * byte block, i.e., a size increase of 0.015% for large data sets.
     *
     * We say: maxplain can never be bigger than PROT_BUFSIZE, which
     * is currently 4096, so adding 5 bytes will do it!
     *
     * Add another spare byte and we'll never totally fill the buffer,
     * which saves a loop.
     *
     * NOTE: we do double check and handle buffer filling gracefully
     * anyway, but starting with the right size is good.
     */
    s->zbuf_size = s->maxplain + 6;
    s->zbuf = (unsigned char *) xmalloc(sizeof(unsigned char) * s->zbuf_size);
    s->zstrm = zstrm;

    return 0;

error:
    syslog(LOG_NOTICE, "failed to start %scompression",
           s->write ? "" : "de");
    free(zstrm);
    return EOF;
}

EXPORTED void prot_unsetcompress(struct protstream *s)
{
    if (s->zstrm) {
        if (s->write) deflateEnd(s->zstrm);
        else inflateEnd(s->zstrm);

        free(s->zstrm);
        s->zstrm = NULL;
    }
    if (s->zbuf) {
        free(s->zbuf);
        s->zbuf = NULL;
    }
}

/* Table of incompressible file type signatures */
static struct file_sig {
    const char *type;
    size_t len;
    const char *sig;
} sig_tbl[] = {
    { "GIF87a", 6, "GIF87a" },
    { "GIF89a", 6, "GIF89a" },
    { "GZIP",   2, "\x1F\x8B" },
    { "JPEG",   4, "\xFF\xD8\xFF\xE0" },
    { "PNG",    8, "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A" },
    { NULL,     0, NULL }
};

/* Check if a chunk of data is incompressible */
static int is_incompressible(const char *p, size_t n)
{
    struct file_sig *sig = sig_tbl;

    /* is it worth checking? */
    if (n < ZLARGE_DIFF_CHUNK) return 0;

    while (sig->type) {
        if (n >= sig->len && !memcmp(p, sig->sig, sig->len)) {
            return 1;
        }
        sig++;
    }

    return 0;
}

#endif /* HAVE_ZLIB */

/* Tell the protstream that the type of data is about to change.
 * Since we might want to look at the data, we only set a flag and delay
 * any changes to the stream layers until the next prot_write().
 */
EXPORTED int prot_data_boundary(struct protstream *s __attribute__((unused)))
{
    // XXX - appears to be broken, so just don't set the boundary.  We'll
    // spend trivially more CPU when transferring binary parts.  Boo hoo
    // re-enable this once the bug is fixed
    //s->boundary = 1;
    return 0;
}

/*
 * Set the read timeout for the stream 's' to 'timeout' seconds.
 * 's' must have been created for reading.
 */
EXPORTED int prot_settimeout(struct protstream *s, int timeout)
{
    assert(!s->write);

    s->read_timeout = timeout;
    s->timeout_mark = time(NULL) + timeout;
    return 0;
}

/*
 * Reset the read timeout_mark for the stream 's'.
 * 'S' must have been created for reading.
 */
EXPORTED int prot_resettimeout(struct protstream *s)
{
    assert(!s->write);

    s->timeout_mark = time(NULL) + s->read_timeout;
    return 0;
}

/*
 * Set the stream 's' to flush the stream 'flushs' before
 * blocking for reading. 's' must have been created for reading,
 * 'flushs' for writing.
 */
EXPORTED int prot_setflushonread(struct protstream *s, struct protstream *flushs)
{
    assert(!s->write);
    if(flushs) assert(flushs->write);

    s->flushonread = flushs;
    return 0;
}

/*
 * Set on stream 's' the callback 'proc' and 'rock'
 * to make the next time we have to wait for input.
 */
int prot_setreadcallback(struct protstream *s,
                         prot_readcallback_t *proc, void *rock)
{
    assert(!s->write);

    s->readcallback_proc = proc;
    s->readcallback_rock = rock;
    return 0;
}

/*
 * Add an event on stream 's' so that the callback 'proc' taking
 * argument 'rock' will be called at 'mark' (in seconds) while
 * waiting for input.
 */
EXPORTED struct prot_waitevent *prot_addwaitevent(struct protstream *s, time_t mark,
                                         prot_waiteventcallback_t *proc,
                                         void *rock)
{
    struct prot_waitevent *new, *cur;

    /* if we aren't passed a callback function, don't bother */
    if (!proc) return s->waitevent;

    /* create new timer struct */
    new = (struct prot_waitevent *) xmalloc(sizeof(struct prot_waitevent));
    new->mark = mark;
    new->proc = proc;
    new->rock = rock;
    new->next = NULL;

    /* add the new event to the end of the list */
    if (!s->waitevent)
        s->waitevent = new;
    else {
        cur = s->waitevent;
        while (cur && cur->next) cur = cur->next;
        cur->next = new;
    }

    return new;
}

/*
 * Remove 'event' from stream 's'.
 */
EXPORTED void prot_removewaitevent(struct protstream *s, struct prot_waitevent *event)
{
    struct prot_waitevent *prev, *cur;

    prev = NULL;
    cur = s->waitevent;

    while (cur && cur != event) {
        prev = cur;
        cur = cur->next;
    }

    if (!cur) return;

    if (!prev)
        s->waitevent = cur->next;
    else
        prev->next = cur->next;

    free(cur);
}

/*
 * Return a pointer to a statically-allocated string describing the
 * error encountered on 's'.  If there is no error condition, return a
 * null pointer.
 */
EXPORTED const char *prot_error(struct protstream *s)
{
    if(!s) return "bad protstream passed to prot_error";
    else if(s->error) return s->error;
    else if(s->eof) return PROT_EOF_STRING;
    else return NULL;
}

/*
 * Rewind the stream 's'.  's' must have been created for reading.
 */
EXPORTED int prot_rewind(struct protstream *s)
{
    assert(!s->write);

    if (lseek(s->fd, 0L, 0) == -1) {
        s->error = xstrdup(strerror(errno));
        return EOF;
    }
    s->cnt = 0;
    s->error = 0;
    s->eof = 0;
    s->can_unget = 0;
    s->bytes_in = 0;
    return 0;
}

/*
 * Read data into the empty buffer for the stream 's' and return the
 * first character.  Returns EOF on EOF or error.
 */
EXPORTED int prot_fill(struct protstream *s)
{
    int n;
    unsigned char *ptr;
    int left;
    int r;
    struct timeval timeout;
    fd_set rfds;
    int haveinput;
    time_t read_timeout;
    struct prot_waitevent *event, *next;

    assert(!s->write);

    /* Zero errno just in case */
    errno = 0;

    if (s->fixedsize) s->eof = 1;
    if (s->eof || s->error) return EOF;

    do {
#ifdef HAVE_ZLIB
        /* check if there's anything in the zlib buffer already */
        if (s->zstrm && s->zstrm->avail_in) {
            /* Decompress the data */
            int zr = Z_OK;

            s->zstrm->next_out = s->zbuf;
            s->zstrm->avail_out = s->zbuf_size;
            zr = inflate(s->zstrm, Z_SYNC_FLUSH);
            if (!(zr == Z_OK || zr == Z_BUF_ERROR || zr == Z_STREAM_END)) {
                /* Error decompressing */
                syslog(LOG_ERR, "zlib inflate error: %d %s", zr, s->zstrm->msg);
                s->error = xstrdup("Error decompressing data");
                return EOF;
            }

            if (s->zstrm->avail_out < s->zbuf_size) {
                /* inflated some data */
                s->ptr = s->zbuf;
                s->cnt = s->zbuf_size - s->zstrm->avail_out;

                /* drop straight to logging and returning the first char */
                break;
            }
        }
#endif

        /* wait until get input */
        haveinput = 0;

#ifdef HAVE_SSL
        /* maybe there's data stuck in the SSL buffer? */
        if (s->tls_conn != NULL) {
            haveinput = SSL_pending(s->tls_conn);
        }
#endif

        /* if we've promised to call something before blocking or
           flush an output stream, check to see if we're going to block */
        if (s->readcallback_proc ||
            (s->flushonread && s->flushonread->ptr != s->flushonread->buf)) {
            timeout.tv_sec = timeout.tv_usec = 0;
            FD_ZERO(&rfds);
            FD_SET(s->fd, &rfds);

            if (!haveinput &&
                (signals_select(s->fd + 1, &rfds, (fd_set *)0, (fd_set *)0,
                        &timeout) <= 0)) {
                if (s->readcallback_proc) {
                    (*s->readcallback_proc)(s, s->readcallback_rock);
                    s->readcallback_proc = 0;
                    s->readcallback_rock = 0;
                }
                /* Request a flush of the buffer.  If we are a blocking
                   read stream, force the flush */
                if (s->flushonread)
                    prot_flush_internal(s->flushonread, !s->dontblock);
            }
            else {
                haveinput = 1;
            }
        }

        if (!haveinput && (s->read_timeout || s->dontblock)) {
            time_t now = time(NULL);
            time_t sleepfor;

            read_timeout = s->dontblock ? now : s->timeout_mark;
            do {
                if (read_timeout < now)
                    sleepfor = 0;
                else
                    sleepfor = read_timeout - now;
                /* execute each callback that has timed out */
                for (event = s->waitevent; event; event = next)
                {
                    next = event->next;
                    if (now >= event->mark) {
                        event = (*event->proc)(s, event, event->rock);
                    }
                    /* if event == NULL, the callback has removed itself */
                    if (event && sleepfor > (event->mark - now)) {
                        sleepfor = event->mark - now;
                    }
                }

                /* check for input */
                timeout.tv_sec = sleepfor;
                timeout.tv_usec = 0;
                FD_ZERO(&rfds);
                FD_SET(s->fd, &rfds);
                r = signals_select(s->fd + 1, &rfds, (fd_set *)0, (fd_set *)0,
                           &timeout);
                now = time(NULL);
            } while ((r == 0 || (r == -1 && errno == EINTR && !signals_poll())) &&
                     (now < read_timeout));
            if ((r == 0) ||
                /* ignore EINTR if we've timed out */
                (r == -1 && errno == EINTR && !signals_poll() && now >= read_timeout)) {
                if (!s->dontblock) {
                    s->error = xstrdup("idle for too long");
                    return EOF;
                } else {
                    errno = EAGAIN;
                    return EOF;
                }
            }
            else if (r == -1) {
                syslog(LOG_ERR, "select() failed: %m");
                s->error = xstrdup(strerror(errno));
                return EOF;
            }
        }

        /* we have data, reset the timeout_mark */
        prot_resettimeout(s);

        do {
            cmdtime_netstart();
            if (s->fillcallback_proc != NULL) {
                n = (*s->fillcallback_proc)(s->buf, PROT_BUFSIZE, s->fillcallback_rock);
            }
#ifdef HAVE_SSL
            /* just do a SSL read instead if we're under a tls layer */
            else if (s->tls_conn != NULL) {
                n = SSL_read(s->tls_conn, (char *) s->buf, PROT_BUFSIZE);
            }
#endif /* HAVE_SSL */
            else {
                n = read(s->fd, s->buf, PROT_BUFSIZE);
            }
            cmdtime_netend();
        } while (n == -1 && errno == EINTR && !signals_poll());

        if (n <= 0) {
            if (n) s->error = xstrdup(strerror(errno));
            else s->eof = 1;
            return EOF;
        }

        if (s->saslssf) { /* decode it */
            if (prot_sasldecode(s, n) == EOF) return EOF;
        } else {
            /* No protection function, just use the raw data */
            s->ptr = s->buf;
            s->cnt = n;
        }

#ifdef HAVE_ZLIB
        if (s->zstrm) {
            /* transfer the data we have to the input of
             * the z_stream and loop to process it */

            s->zstrm->next_in = s->ptr;
            s->zstrm->avail_in = s->cnt;
            s->cnt = 0;
        }
#endif /* HAVE_ZLIB */
    } while (!s->cnt);

    if (s->logfd != -1) {
        time_t newtime;
        char timebuf[20];

        time(&newtime);
        snprintf(timebuf, sizeof(timebuf), "<" TIME_T_FMT "<", newtime);
        n = write(s->logfd, timebuf, strlen(timebuf));

        left = s->cnt;
        ptr = s->ptr;
        do {
            n = write(s->logfd, ptr, left);
            if (n == -1 && (errno != EINTR || signals_poll())) {
                break;
            }

            if (n > 0) {
                ptr += n;
                left -= n;
            }
        } while (left);
    }

    s->cnt--;           /* we return the first char */
    s->can_unget = 1;
    s->bytes_in++;
    return *s->ptr++;
}

/*
 * If 's' is an input stream, discard any pending/buffered data.  Otherwise,
 * Write out any buffered data in the stream 's'
 */
EXPORTED int prot_flush(struct protstream *s)
{
    if (!s->write) {
        int c, save_dontblock = s->dontblock;

        /* Set stream to nonblocking mode */
        if (!save_dontblock) nonblock(s->fd, (s->dontblock = 1));

        /* Ingest any pending input */
        while ((c = prot_fill(s)) != EOF);

        /* Reset stream to previous blocking mode */
        if (!save_dontblock) nonblock(s->fd, (s->dontblock = 0));

        /* Discard any buffered input */
        s->cnt = 0;
        s->can_unget = 0;

        return 0;
    }

    return prot_flush_internal(s, 1);
}

/* Do the logging part of prot_flush */
static void prot_flush_log(struct protstream *s)
{
    if(s->logfd != PROT_NO_FD) {
        unsigned char *ptr = s->buf;
        int left = s->ptr - s->buf;
        int n;
        time_t newtime;
        char timebuf[20];

        time(&newtime);
        snprintf(timebuf, sizeof(timebuf), ">" TIME_T_FMT ">", newtime);
        n = write(s->logfd, timebuf, strlen(timebuf));

        do {
            n = write(s->logfd, ptr, left);
            if (n == -1 && (errno != EINTR || signals_poll())) {
                break;
            }
            if (n > 0) {
                ptr += n;
                left -= n;
            }
        } while (left);

        /* we don't care THAT much about logs
         * (void)fsync(s->logfd);
         */
    }
}

/* Do the encoding part of prot_flush */
static int prot_flush_encode(struct protstream *s,
                             const char **output_buf,
                             unsigned *output_len)
{
    unsigned char *ptr = s->buf;
    int left = s->ptr - s->buf;

#ifdef HAVE_ZLIB
    if (s->zstrm) {
        /* Compress the data */
        int zr = Z_OK;

        s->zstrm->next_in = ptr;
        s->zstrm->avail_in = left;
        s->zstrm->next_out = s->zbuf;
        s->zstrm->avail_out = s->zbuf_size;

        do {
            /* should never be needed, but it's better to always check! */
            if (!s->zstrm->avail_out) {
                syslog(LOG_DEBUG, "growing compress buffer from %u to %u bytes",
                       s->zbuf_size, s->zbuf_size + PROT_BUFSIZE);

                s->zbuf = (unsigned char *)
                    xrealloc(s->zbuf, s->zbuf_size + PROT_BUFSIZE);
                s->zstrm->next_out = s->zbuf + s->zbuf_size;
                s->zstrm->avail_out = PROT_BUFSIZE;
                s->zbuf_size += PROT_BUFSIZE;
            }

            zr = deflate(s->zstrm, Z_SYNC_FLUSH);
            if (!(zr == Z_OK || zr == Z_STREAM_END || zr == Z_BUF_ERROR)) {
                /* something went wrong */
                syslog(LOG_ERR, "zlib deflate error: %d %s", zr, s->zstrm->msg);
                s->error = xstrdup("Error compressing data");
                return EOF;
            }

            /* http://www.zlib.net/manual.html says:
             * If deflate returns with avail_out == 0, this function must be
             * called again with the same value of the flush parameter and
             * more output space (updated avail_out), until the flush is
             * complete (deflate returns with non-zero avail_out).
             */
        } while (!s->zstrm->avail_out);

        ptr = s->zbuf;
        left = s->zbuf_size - s->zstrm->avail_out;
    }
#endif /* HAVE_ZLIB */

    if (s->saslssf != 0) {
        /* encode the data */
        int result = sasl_encode(s->conn, (char *) ptr, left,
                                 output_buf, output_len);
        if (result != SASL_OK) {
            char errbuf[256];
            const char *ed = sasl_errdetail(s->conn);

            snprintf(errbuf, 256, "encoding error: %s; %s",
                     sasl_errstring(result, NULL, NULL),
                     ed ? ed : "no detail");
            s->error = xstrdup(errbuf);

            return EOF;
        }
    } else {
        *output_buf = (char *) ptr;
        *output_len = left;
    }
    return 0;
}

/* A wrapper for write() that handles SSL and EINTR */
static int prot_flush_writebuffer(struct protstream *s,
                                  const char *buf, size_t len)
{
    int n;

    do {
        cmdtime_netstart();
#ifdef HAVE_SSL
        if (s->tls_conn != NULL) {
            n = SSL_write(s->tls_conn, (char *)buf, len);
        } else {
            n = write(s->fd, buf, len);
        }
#else  /* HAVE_SSL */
        n = write(s->fd, buf, len);
#endif /* HAVE_SSL */
        cmdtime_netend();
    } while (n == -1 && errno == EINTR && !signals_poll());

    return n;
}

int prot_flush_internal(struct protstream *s, int force)
{
    int n;
    int save_dontblock = s->dontblock;

    const char *ptr = (char *) s->buf; /* Memory buffer info */
    unsigned left = s->ptr - s->buf;

    assert(s->write);

    /* Is this protstream finished? */
    if (s->eof || s->error) {
        s->ptr = s->buf;
        s->cnt = 1;
        return EOF;
    }

    /* make sure that the main file descriptor is set up to
     * be blocking or nonblocking based on the configuration of the
     * protstream and the force flag */
    if(force)
        s->dontblock = 0;

    if(s->dontblock != s->dontblock_isset) {
        nonblock(s->fd,s->dontblock);
        s->dontblock_isset = s->dontblock;
    }

    /* end protstream setup */

    /* if writing to a buffer, just append the lot.  Always works */
    if (s->writetobuf) {
        buf_appendmap(s->writetobuf, ptr, left);
    }

    /* If we're doing a blocking write, flush the buffers, bigbuffer first */
    else if (!s->dontblock) {
        if(s->big_buffer != PROT_NO_FD) {
            /* Write the bigbuffer */
            do {
                n = prot_flush_writebuffer(s, s->bigbuf_base + s->bigbuf_pos,
                                           s->bigbuf_len - s->bigbuf_pos);
                if(n == -1) {
                    s->error = xstrdup(strerror(errno));
                    goto done;
                } else if (n > 0) {
                    s->bigbuf_pos += n;
                }
            } while(s->bigbuf_len != s->bigbuf_pos);

            /* Free the bigbuffer */
            map_free(&(s->bigbuf_base), &(s->bigbuf_siz));
            close(s->big_buffer);
            s->bigbuf_len = s->bigbuf_pos = 0;
            s->big_buffer = PROT_NO_FD;
        }

        /* Is there anything in the memory buffer? */
        if(!left) {
            goto done;
        }

        /* Do a regular write of whatever is left */

        /* Log and Encode it */
        prot_flush_log(s);

        if(prot_flush_encode(s, &ptr, &left) == EOF) {
            /* s->error set by prot_flush_encode */
            goto done;
        }

        /* Write it to descriptor */
        do {
            n = prot_flush_writebuffer(s, ptr, left);
            if(n == -1) {
                s->error = xstrdup(strerror(errno));
                goto done;
            } else if (n > 0) {
                ptr += n;
                left -= n;
            }
        } while(left);
    }

    /* Nonblocking */
    else {
        /* If we've been feeding a bigbuffer, write out from the current
         * position as much as we can */
        if (s->big_buffer != PROT_NO_FD) {
            /* Write what we can. */
            n = prot_flush_writebuffer(s, s->bigbuf_base + s->bigbuf_pos,
                                       s->bigbuf_len - s->bigbuf_pos);

            if(n == -1 && errno == EAGAIN) {
                /* No room in the pipe, but we don't care */
                n = 0;
            } else if(n == -1) {
                s->error = xstrdup(strerror(errno));
                goto done;
            }

            if (n > 0) {
                s->bigbuf_pos += n;
            }
        }

        /* If there isn't anything in the memory buffer, we're done now */
        if(!left) {
            goto done;
        }

        /* Prepare the data in the memory buffer */
        prot_flush_log(s);

        /* Encode it */
        if(prot_flush_encode(s, &ptr, &left) == EOF) {
            /* prot_flush_encode set s->error */
            goto done;
        }

        if(s->big_buffer == PROT_NO_FD || s->bigbuf_pos == s->bigbuf_len) {
            /* No bigbuffer currently open (or we've written the current
               one to its entirety), so write what we can from memory */

            n = prot_flush_writebuffer(s, ptr, left);

            if(n == -1 && errno == EAGAIN) {
                /* No room in the pipe, but we don't care */
                n = 0;
            } else if(n == -1) {
                s->error = xstrdup(strerror(errno));
                goto done;
            }

            if(n > 0) {
                ptr += n;
                left -= n;
            }
        }

        /* if there is data still to send, it needs to go to the bigbuffer */
        if(left) {
            struct stat sbuf;

            if(s->big_buffer == PROT_NO_FD) {
                /* open new bigbuffer */
                int fd = create_tempfile(libcyrus_config_getstring(CYRUSOPT_TEMP_PATH));
                if(fd == -1) {
                    s->error = xstrdup(strerror(errno));
                    goto done;
                }

                s->big_buffer = fd;
            }

            do {
                n = write(s->big_buffer, ptr, left);
                if (n == -1 && (errno != EINTR || signals_poll())) {
                    syslog(LOG_ERR, "write to protstream buffer failed: %s",
                           strerror(errno));

                    fatal("write to big buffer failed", EX_OSFILE);
                }
                if (n > 0) {
                    ptr += n;
                    left -= n;
                }
            } while (left);

            /* We did a write to the bigbuffer, refresh the memory map */
            if (fstat(s->big_buffer, &sbuf) == -1) {
                syslog(LOG_ERR, "IOERROR: fstating temp protlayer buffer: %m");
                fatal("failed to fstat protlayer buffer", EX_IOERR);
            }

            s->bigbuf_len = sbuf.st_size;

            map_refresh(s->big_buffer, 0, &(s->bigbuf_base), &(s->bigbuf_siz),
                        s->bigbuf_len, "temp protlayer buffer", NULL);
        }

    } /* end of blocking/nonblocking if statement */

    /* Reset the memory buffer -- should be done on EOF or on success. */
    s->ptr = s->buf;
    s->cnt = s->maxplain;

 done:
    /* are we done with the big buffer? If so, free it. This includes
     * when we exit with error */
    if (s->big_buffer != PROT_NO_FD &&
       (s->bigbuf_pos == s->bigbuf_len || s->error)) {
        map_free(&(s->bigbuf_base), &(s->bigbuf_siz));
        close(s->big_buffer);
        s->bigbuf_len = s->bigbuf_pos = 0;
        s->big_buffer = PROT_NO_FD;
    }

    if (force) {
        /* we don't need to call nonblock() again, because it will be
         * set correctly on the next prot_flush_internal() anyway */
        s->dontblock = save_dontblock;
    }

    /* If we are exiting with an error, we should clear our memory buffer
     * and set our return code */
    if(s->error) {
        s->ptr = s->buf;
        s->cnt = s->maxplain;
        return EOF;
    }

    return 0;
}

/*
 * Write to the output stream 's' the 'len' bytes of data at 'buf'
 */
EXPORTED int prot_write(struct protstream *s, const char *buf, unsigned len)
{
    assert(s->write);
    if(s->error || s->eof) return EOF;
    if(len == 0) return 0;

    /* Different type of data, adjust layers accordingly */
    if (s->boundary) {
#ifdef HAVE_ZLIB
        if (s->zstrm) {
            int zr = Z_OK;
            int zlevel = Z_DEFAULT_COMPRESSION;

            if (is_incompressible(buf, len))
                zlevel = Z_NO_COMPRESSION;

            if (zlevel != s->zlevel) {
                s->zlevel = zlevel;

                /* flush any pending data */
                if (s->ptr != s->buf) {
                    if (prot_flush_internal(s, 1) == EOF) return EOF;
                }

                /* Set new compression level */
                zr = deflateParams(s->zstrm, s->zlevel, Z_DEFAULT_STRATEGY);
                if (zr != Z_OK) {
                    s->error = xstrdup("Error setting compression level");
                    return EOF;
                }
            }
        }
#endif /* HAVE_ZLIB */

        s->boundary = 0;
    }

    while (len >= s->cnt) {
        /* XXX can we manage to write data from 'buf' without copying it
           to s->ptr ? */
        memcpy(s->ptr, buf, s->cnt);
        s->ptr += s->cnt;
        buf += s->cnt;
        len -= s->cnt;
        s->cnt = 0;
        if (prot_flush_internal(s,0) == EOF) return EOF;
    }
    memcpy(s->ptr, buf, len);
    s->ptr += len;
    s->cnt -= len;
    s->bytes_out += len;
    if (s->error || s->eof) return EOF;

    assert(s->cnt > 0);
    return 0;
}

EXPORTED int prot_putbuf(struct protstream *s, const struct buf *buf)
{
    return prot_write(s, buf->s, buf->len);
}

EXPORTED int prot_puts(struct protstream *s, const char *str)
{
    return prot_write(s, str, strlen(str));
}

/*
 * Version of printf() that works on protection streams.
 */
EXPORTED int prot_printf(struct protstream *s, const char *fmt, ...)
{
    va_list pvar;
    int r;

    va_start(pvar, fmt);
    r = prot_vprintf(s, fmt, pvar);
    va_end(pvar);

    return r;
}

EXPORTED int prot_vprintf(struct protstream *s, const char *fmt, va_list pvar)
{
    struct buf buf = BUF_INITIALIZER;

    assert(s->write);

    buf_vprintf(&buf, fmt, pvar);
    prot_puts(s, buf_cstring(&buf));
    buf_free(&buf);

    if (s->error || s->eof) return EOF;
    return 0;
}

EXPORTED int prot_printliteral(struct protstream *out, const char *s, size_t size)
{
    int r;
    if (out->isclient)
        r = prot_printf(out, "{" SIZE_T_FMT "+}\r\n", size);
    else
        r = prot_printf(out, "{" SIZE_T_FMT "}\r\n", size);
    if (r) return r;
    return prot_write(out, s, size);
}

#define isQCHAR(c) \
        (!((c) & 0x80 || *p == '\r' || (c) == '\n' \
            || (c) == '\"' || (c) == '%' || (c) == '\\'))
#define MAXQSTRING  1024

/*
 * Print 's' as a quoted-string or literal (but not an atom)
 */
EXPORTED int prot_printstring(struct protstream *out, const char *s)
{
    const char *p;

    if (!s) return prot_printf(out, "NIL");

    /* Look for any non-QCHAR characters */
    for (p = s; *p && (p-s) < MAXQSTRING; p++) {
        if (!isQCHAR(*p)) break;
    }

    /* if it's too long, literal it */
    if (*p || (p-s) >= MAXQSTRING) {
        return prot_printliteral(out, s, strlen(s));
    }

    return prot_printf(out, "\"%s\"", s);
}

/*
 * Print the @n bytes at @s as a quoted-string or literal.
 * Handles embedded NULs.
 */
EXPORTED int prot_printmap(struct protstream *out, const char *s, size_t n)
{
    const char *p;
    int r;

    if (!s) return prot_printf(out, "NIL");

    /* if it's too long, literal it */
    if (n >= MAXQSTRING)
        return prot_printliteral(out, s, n);

    /* Look for NULs or any non-QCHAR characters */
    for (p = s; (size_t)(p-s) < n; p++) {
        if (!*p || !isQCHAR(*p))
            return prot_printliteral(out, s, n);
    }

    prot_putc('"', out);
    r = prot_write(out, s, n);
    if (r < 0)
        return r;
    prot_putc('"', out);
    return r+2;
}

/*
 * Print the @n bytes at @s as an atom, quoted-string or literal.
 * Handles embedded NULs.
 */
EXPORTED int prot_printamap(struct protstream *out, const char *s, size_t n)
{
    const char *p;
    int r;

    if (!s) return prot_printf(out, "NIL");

    if (!n) {
        prot_putc('"', out);
        prot_putc('"', out);
        return 2;
    }

    if (imparse_isnatom(s, n) && (n != 3 || memcmp(s, "NIL", 3)))
        return prot_write(out, s, n);

    /* if it's too long, literal it */
    if (n >= MAXQSTRING)
        return prot_printliteral(out, s, n);

    /* Look for NULs or any non-QCHAR characters */
    for (p = s; (size_t)(p-s) < n; p++) {
        if (!*p || !isQCHAR(*p))
            return prot_printliteral(out, s, n);
    }

    prot_putc('"', out);
    r = prot_write(out, s, n);
    if (r < 0)
        return r;
    prot_putc('"', out);
    return r+2;
}

/*
 * Print 's' as an atom, quoted-string, or literal
 */
EXPORTED int prot_printastring(struct protstream *out, const char *s)
{
    if (!s) return prot_printf(out, "NIL");

    /* special cases for atoms */
    if (!*s) return prot_printf(out, "\"\"");
    if (imparse_isatom(s) && strcmp(s, "NIL"))
        return prot_printf(out, "%s", s);

    /* not an atom, so pass to printstring */
    return prot_printstring(out, s);
}

/*
 * Read from the protections stream 's' up to 'size' bytes into the buffer
 * 'buf'.  Returns the number of bytes read, or 0 for some error.
 */
EXPORTED int prot_read(struct protstream *s, char *buf, unsigned size)
{
    int c;

    assert(!s->write);

    if (!size) return 0;

    /* If no data in the input buffer, get some */
    if (!s->cnt) {
        c = prot_fill(s);
        if (c == EOF) return 0;
        prot_ungetc(c, s);
    }

    if (size > s->cnt) size = s->cnt;
    memcpy(buf, s->ptr, size);
    s->ptr += size;
    s->cnt -= size;
    s->can_unget += size;
    s->bytes_in += size;  /* prot_fill added the 1 already */
    return size;
}

/*
 * Read from the protections stream 's' up to 'size' bytes, and append them
 * to the buffer 'buf'.  Returns the number of bytes read, or 0 for some error.
 */
EXPORTED int prot_readbuf(struct protstream *s, struct buf *buf, unsigned size)
{
    buf_ensure(buf, size);
    size = prot_read(s, buf->s + buf->len, size);
    buf->len += size;
    return size;
}

/*
 * select() for protection streams, read only
 * Also supports selecting on an extra file descriptor
 *
 * returns # of protstreams with pending data (including the extra fd)
 *
 * Only works for readable protstreams
 */
EXPORTED int prot_select(struct protgroup *readstreams, int extra_read_fd,
                struct protgroup **out, int *extra_read_flag,
                struct timeval *timeout)
{
    struct protstream *s, *timeout_prot = NULL;
    struct protgroup *retval = NULL;
    int max_fd, found_fds = 0;
    unsigned i;
    fd_set rfds;
    int have_readtimeout = 0;
    struct timeval my_timeout;
    struct prot_waitevent *event;
    time_t now = time(NULL);
    time_t read_timeout = 0;

    assert(readstreams || extra_read_fd != PROT_NO_FD);
    assert(extra_read_fd == PROT_NO_FD || extra_read_flag);
    assert(out);

    /* Initialize things we might use */
    errno = 0;
    found_fds = 0;
    FD_ZERO(&rfds);

    /* If extra_read_fd is PROT_NO_FD, then the first protstream
     * will override it */
    max_fd = extra_read_fd;

    for(i = 0; i<readstreams->next_element; i++) {
        int have_thistimeout = 0; /* used to compute the minimal timeout for */
        time_t this_timeout = 0;  /* this stream */

        s = readstreams->group[i];
        if (!s) continue;

        assert(!s->write);

        /* scan for waitevent callbacks */
        for (event = s->waitevent; event; event = event->next)
        {
            if(!have_thistimeout || event->mark - now < this_timeout) {
                this_timeout = event->mark - now;
                have_thistimeout = 1;
            }
        }

        /* check the idle timeout on this one as well */
        if(s->read_timeout &&
           (!have_thistimeout || s->timeout_mark - now < this_timeout)) {
            this_timeout = s->timeout_mark - now;
            have_thistimeout = 1;
        }

        if(!s->dontblock && have_thistimeout &&
           (!have_readtimeout || now + this_timeout < read_timeout)) {
            read_timeout = now + this_timeout;
            have_readtimeout = 1;
            if(!timeout || this_timeout <= timeout->tv_sec)
                timeout_prot = s;
        }

        FD_SET(s->fd, &rfds);
        if(s->fd > max_fd)
            max_fd = s->fd;

        /* Is something currently pending in our protstream's buffer? */
        if(s->cnt > 0) {
            found_fds++;

            if(!retval)
                retval = protgroup_new(readstreams->next_element + 1);

            protgroup_insert(retval, s);

        }
#ifdef HAVE_SSL
        else if(s->tls_conn != NULL && SSL_pending(s->tls_conn)) {
            found_fds++;

            if(!retval)
                retval = protgroup_new(readstreams->next_element + 1);

            protgroup_insert(retval, s);
        }
#endif
    }

    /* xxx we should probably do a nonblocking select on the remaining
     * protstreams instead of skipping this part entirely */
    if(!retval) {
        time_t sleepfor;

        /* do a select */
        if(extra_read_fd != PROT_NO_FD) {
            /* max_fd started with atleast extra_read_fd */
            FD_SET(extra_read_fd, &rfds);
        }

        if(read_timeout < now)
            sleepfor = 0;
        else
            sleepfor = read_timeout - now;

        /* If we don't have a timeout structure, and we need one, use
         * a local version.  Otherwise, make sure that we are timing out
         * for the right reason */
        if(have_readtimeout &&
           (!timeout || sleepfor < timeout->tv_sec)) {
            if(!timeout) timeout = &my_timeout;
            timeout->tv_sec = sleepfor;
            timeout->tv_usec = 0;
        }

        if(signals_select(max_fd + 1, &rfds, NULL, NULL, timeout) == -1)
            return -1;

        /* Reset now */
        now = time(NULL);

        if(extra_read_fd != PROT_NO_FD && FD_ISSET(extra_read_fd, &rfds)) {
            *extra_read_flag = 1;
            found_fds++;
        } else if(extra_read_flag) {
            *extra_read_flag = 0;
        }

        for(i = 0; i<readstreams->next_element; i++) {
            s = readstreams->group[i];
            if (!s) continue;

            if(FD_ISSET(s->fd, &rfds)) {
                found_fds++;

                if(!retval)
                    retval = protgroup_new(readstreams->next_element + 1);

                protgroup_insert(retval, s);
            } else if(s == timeout_prot && now >= read_timeout) {
                /* If we timed out, be sure to add the protstream we were
                 * waiting for, even if it didn't show up */
                found_fds++;

                if(!retval)
                    retval = protgroup_new(readstreams->next_element + 1);

                protgroup_insert(retval, s);
            }
        }
    }

    *out = retval;
    return found_fds;
}

/*
 * Version of fgets() that works with protection streams.
 */
EXPORTED char *prot_fgets(char *buf, unsigned size, struct protstream *s)
{
    char *p = buf;
    int c;

    assert(!s->write);

    if (size < 2 || s->eof) return 0;
    size--;

    while (size && (c = prot_getc(s)) != EOF) {
        size--;
        *p++ = c;
        if (c == '\n') break;
    }
    if (p == buf) return 0;
    *p++ = '\0';
    return buf;
}

/* Handle protgroups */
/* Create a new protgroup of the given size, or 32 if size is 0 */
EXPORTED struct protgroup *protgroup_new(size_t size)
{
    struct protgroup *ret = xmalloc(sizeof(struct protgroup));

    if(!size) size = PROTGROUP_SIZE_DEFAULT;

    ret->nalloced = size;
    ret->next_element = 0;
    ret->group = xzmalloc(size * sizeof(struct protstream *));

    return ret;
}

struct protgroup *protgroup_copy(struct protgroup *src)
{
    struct protgroup *dest;
    assert(src);
    dest = protgroup_new(src->nalloced);
    if(src->next_element) {
        memcpy(dest->group, src->group,
               src->next_element * sizeof(struct protstream *));
    }
    return dest;
}

EXPORTED void protgroup_reset(struct protgroup *group)
{
    if(group) {
        memset(group->group, 0,
               group->nalloced * sizeof(struct protstream *));
        group->next_element = 0;
    }
}

EXPORTED void protgroup_free(struct protgroup *group)
{
    if(group) {
        assert(group->group);
        free(group->group);
        free(group);
    }
}

EXPORTED void protgroup_insert(struct protgroup *group, struct protstream *item)
{
    unsigned i, empty;

    assert(group);
    assert(item);

    /* See if we already have this protstream */
    for (i = 0, empty = group->next_element; i < group->next_element; i++) {
        if (!group->group[i]) empty = i;
        else if (group->group[i] == item) return;
    }
    /* Double size of the protgroup if we're at our limit */
    if (empty == group->next_element &&
        group->next_element++ == group->nalloced) {
        group->nalloced *= 2;
        group->group = xrealloc(group->group,
                                group->nalloced * sizeof(struct protstream *));
    }
    /* Insert the item at the empty location */
    group->group[empty] = item;
}

EXPORTED void protgroup_delete(struct protgroup *group, struct protstream *item)
{
    unsigned i;

    assert(group);
    assert(item);

    /* find the protstream */
    for (i = 0; i < group->next_element; i++) {
        if (group->group[i] == item) {
            /* slide all remaining elements down one slot */
            group->next_element--;
            for (; i < group->next_element; i++) {
                group->group[i] = group->group[i+1];
            }
            group->group[i] = NULL;
            return;
        }
    }
    syslog(LOG_ERR, "protgroup_delete(): can't find protstream in group");
}

EXPORTED struct protstream *protgroup_getelement(struct protgroup *group,
                                        size_t element)
{
    assert(group);

    if (element >= group->next_element)
        return NULL;

    return group->group[element];
}

#ifdef HAVE_DECLARE_OPTIMIZE
EXPORTED inline int prot_getc(struct protstream *s)
    __attribute__((always_inline,optimize("-O3")));
#endif
EXPORTED inline int prot_getc(struct protstream *s)
{
    assert(!s->write);

    if (s->cnt > 0) {
        --s->cnt;
        s->can_unget++;
        s->bytes_in++;
        return *(s->ptr)++;
    }

    return prot_fill(s);
}

EXPORTED size_t prot_lookahead(struct protstream *s,
                               const char *str,
                               size_t len,
                               int *sep)
{
    int short_match = 0;

    assert(!s->write);

    if (prot_peek(s) == EOF) return 0;

    if (len >= s->cnt) {
        len = s->cnt;
        short_match = 1;
    }

    if (0 == memcmp(str, s->ptr, len)) {
        if (!short_match) {
            *sep = (int) s->ptr[len];
            return len + 1;
        }
        return len;
    }

    return 0;
}

#ifdef HAVE_DECLARE_OPTIMIZE
EXPORTED inline int prot_ungetc(int c, struct protstream *s)
    __attribute__((always_inline,optimize("-O3")));
#endif
EXPORTED inline int prot_ungetc(int c, struct protstream *s)
{
    assert(!s->write);

    if (c == EOF) return EOF;

    if (!s->can_unget)
        fatal("Can't unwind any more", EX_SOFTWARE);

    s->cnt++;
    s->can_unget--;
    s->bytes_in--;
    s->ptr--;
    if (*s->ptr != c)
        fatal("Trying to unput wrong character", EX_SOFTWARE);

    return c;
}

EXPORTED int prot_putc(int c, struct protstream *s)
{
    assert(s->write);
    assert(s->cnt > 0);

    *s->ptr++ = c;

    s->bytes_out++;
    if (--s->cnt == 0)
        return prot_flush_internal(s,0);

    return 0;
}
