/* prot.h -- stdio-like module that handles buffering, SASL, and TLS
 *           details for I/O over sockets
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

#ifndef INCLUDED_PROT_H
#define INCLUDED_PROT_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <sasl/sasl.h>
#include <config.h>

#include <openssl/ssl.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* HAVE_ZLIB */

#include "util.h"

#define PROT_BUFSIZE 4096
/* #define PROT_BUFSIZE 8192 */

#define PROT_NO_FD -1

struct protstream;
struct prot_waitevent;

typedef void prot_readcallback_t(struct protstream *s, void *rock);
typedef ssize_t prot_fillcallback_t(unsigned char *buf, size_t len, void *rock);

struct protstream {
    /* The Buffer */
    unsigned char *buf;
    unsigned buf_size;
    unsigned char *ptr; /* The end of data in the buffer */
    unsigned cnt; /* Space Remaining in buffer */

    /* File Descriptors */
    int fd;         /* The Socket */
    int logfd;      /* The Telemetry Log (or PROT_NO_FD) */
    int big_buffer; /* The Big Buffer (or PROT_NO_FD) */

    /* SASL / TLS */
    sasl_conn_t *conn;
    int saslssf;
    int maxplain;
    SSL *tls_conn;

#ifdef HAVE_ZLIB
    /* (De)compress stream */
    z_stream *zstrm;
    /* (De)compress buffer */
    unsigned char *zbuf;
    unsigned int zbuf_size;
    /* Compress parameters */
    int zlevel;
    int zflush;
#endif /* HAVE_ZLIB */

    /* Big Buffer Information */
    const char *bigbuf_base;  /* Base Pointer */
    size_t bigbuf_siz; /* Overall Size of Buffer */
    size_t bigbuf_len; /* Length of mapped file */
    size_t bigbuf_pos; /* Current Position */

    /* Callback-fill information */
    prot_fillcallback_t *fillcallback_proc;
    void *fillcallback_rock;

    /* Status Flags */
    int eof;
    int boundary; /* Type of data is about to change */
    int fixedsize;
    char *error;

    /* Parameters */
    int write;
    int dontblock; /* Application requested nonblocking */
    int dontblock_isset; /* write only, we've fcntl(O_NONBLOCK)'d */
    int read_timeout;
    time_t timeout_mark;
    struct protstream *flushonread;
    /* hack to write to an in-memory-string */
    struct buf *writetobuf;
    /* for printf */
    struct buf vbuf;

    int can_unget;
    uint64_t bytes_in;
    uint64_t bytes_out;
    int isclient; /* read/write IMAP LITERAL+ */

    /* Events */
    prot_readcallback_t *readcallback_proc;
    void *readcallback_rock;
    struct prot_waitevent *waitevent;

    /* For use by applications */
    void *userdata;
};

typedef struct prot_waitevent *prot_waiteventcallback_t(struct protstream *s,
                                                        struct prot_waitevent *ev,
                                                        void *rock);

struct prot_waitevent {
    time_t mark;
    prot_waiteventcallback_t *proc;
    void *rock;
    struct prot_waitevent *next;
};

/* Not for use by applications directly, but needed by the macros. */
int prot_flush_internal(struct protstream *s, int force);

#define PROT_EOF_STRING "end of file reached"
#define PROTGROUP_SIZE_DEFAULT 32
struct protgroup; /* Opaque protgroup structure */

extern int prot_getc(struct protstream *s);
extern int prot_ungetc(int c, struct protstream *s);
extern int prot_putc(int c, struct protstream *s);

#define prot_peek(s) (prot_ungetc(prot_getc(s), s))

/* prot_lookahead checks whether the next several buffered bytes match
 * the string str (of length len).
 *
 * If there are enough buffered bytes available, and they match, then
 * sep will be set to the first byte following str, and the return
 * value will be equal to len+1.
 *
 * If there are not enough buffered bytes available, but those that
 * are there match, then sep will remain unset, and the return value
 * will be within 0 < x <= len, depending on how many matching bytes
 * were available.
 *
 * If there is no match, sep will remain unset and the return value
 * will be zero, regardless of how many bytes were available.
 *
 * The internal buffer will ONLY be filled if it is currently empty.
 */
extern size_t prot_lookahead(struct protstream *s,
                             const char *str,
                             size_t len,
                             int *sep);

/* The following two macros control the blocking nature of
 * the protstream.
 *
 * For a read stream, the non-blocking behavior is that for the
 * reading functions (prot_read, prot_getc, etc) we will return EOF and
 * set errno = EAGAIN if no data was pending.
 *
 * For a write stream, it's a bit more complicated.  When a nonblocking
 * write stream is flushed, a nonblocking write to the network is attempted.
 * if it cannot write all of its data, the remaining data is flushed to a
 * "bigbuffer" temporary file.  (When the next flush occurs, this temporary
 * buffer is flushed first, and additional data is appended to it if necessary)
 * Note that this means that in the telemetry logs, only the time of the
 * first prot_flush_internal() call is logged, not the call for when the data
 * actually is flushed to the network successfully.
 */

#define prot_BLOCK(s) ((s)->dontblock = 0)
#define prot_NONBLOCK(s) ((s)->dontblock = 1)
#define prot_IS_BLOCKING(s) ((s)->dontblock == 0)
#define prot_IS_EOF(s) ((s)->eof != 0)
#define prot_IS_ERROR(s) ((s)->error != NULL)

/* Allocate/free the protstream structure */
extern struct protstream *prot_new(int fd, int write);
extern struct protstream *prot_writebuf(struct buf *buf);
extern struct protstream *prot_readmap(const char *base, uint32_t len);
extern struct protstream *prot_readcb(prot_fillcallback_t *proc, void *rock);
extern int prot_free(struct protstream *s);

/* Set the telemetry logfile for a given protstream */
extern int prot_setlog(struct protstream *s, int fd);

/* Get traffic counts */
extern uint64_t prot_bytes_in(struct protstream *s);
extern uint64_t prot_bytes_out(struct protstream *s);
#define prot_bytes_in(s) ((s)->bytes_in)
#define prot_bytes_out(s) ((s)->bytes_out)

/* Set the SASL options for a protstream (requires authentication to
 * be complete for the given sasl_conn_t */
extern int prot_setsasl(struct protstream *s, sasl_conn_t *conn);
extern void prot_unsetsasl(struct protstream *s);

/* Set TLS options for a given protstream (requires a completed tls
 * negotiation */
extern int prot_settls(struct protstream *s, SSL *tlsconn);

/* Mark this protstream as a "client" for the purpose of generating
 * or consuming literals (thanks LITERAL+) */
int prot_setisclient(struct protstream *s, int val);

#ifdef HAVE_ZLIB
/* Enable (de)compression for a given protstream */
int prot_setcompress(struct protstream *s);

/* Disable (de)compression for a given protstream */
void prot_unsetcompress(struct protstream *s);
#endif /* HAVE_ZLIB */

/* Tell the protstream that the type of data is about to change. */
int prot_data_boundary(struct protstream *s);

/* Set a timeout for the connection (in seconds) */
extern int prot_settimeout(struct protstream *s, int timeout);

/* Reset the timeout timer for the connection (in seconds) */
extern int prot_resettimeout(struct protstream *s);

/* Connect two streams so that when you block on reading s, the layer
 * will automatically flush flushs */
extern int prot_setflushonread(struct protstream *s,
                               struct protstream *flushs);


int prot_setreadcallback(struct protstream *s,
                                prot_readcallback_t *proc, void *rock);
extern struct prot_waitevent *prot_addwaitevent(struct protstream *s,
                                                time_t mark,
                                                prot_waiteventcallback_t *proc,
                                                void *rock);
extern void prot_removewaitevent(struct protstream *s,
                                 struct prot_waitevent *event);

extern const char *prot_error(struct protstream *s);
extern int prot_rewind(struct protstream *s);

/* Fill the buffer for a read stream with waiting data (may block) */
extern int prot_fill(struct protstream *s);

/* Force a flush of an output stream */
extern int prot_flush(struct protstream *s);

/* These are protlayer versions of the specified functions */
extern int prot_write(struct protstream *s, const char *buf, unsigned len);
extern int prot_putbuf(struct protstream *s, const struct buf *buf);
extern int prot_puts(struct protstream *s, const char *str);
extern int prot_vprintf(struct protstream *, const char *, va_list)
    __attribute__((format(printf, 2, 0)));
extern int prot_printf(struct protstream *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
extern int prot_printliteral(struct protstream *out, const char *s,
                             size_t size);
extern int prot_printstring(struct protstream *out, const char *s);
extern int prot_printmap(struct protstream *out, const char *s, size_t n);
extern int prot_printamap(struct protstream *out, const char *s, size_t n);
extern int prot_printastring(struct protstream *out, const char *s);
extern int prot_read(struct protstream *s, char *buf, unsigned size);
extern int prot_readbuf(struct protstream *s, struct buf *buf, unsigned size);
extern char *prot_fgets(char *buf, unsigned size, struct protstream *s);

/* select() for protstreams */
extern int prot_select(struct protgroup *readstreams, int extra_read_fd,
                       struct protgroup **out, int *extra_read_flag,
                       struct timeval *timeout);

/* Protgroup manipulations */
/* Create a new protgroup of a certain size or as a copy of another
 * protgroup */
struct protgroup *protgroup_new(size_t size);
struct protgroup *protgroup_copy(struct protgroup *src);

/* Cleanup a protgroup but don't release the allocated memory (so it can
 * be reused) */
void protgroup_reset(struct protgroup *group);

/* Release memory for a protgroup */
void protgroup_free(struct protgroup *group);

/* Insert an element into a protgroup */
void protgroup_insert(struct protgroup *group, struct protstream *item);

/* Delete an element from a protgroup */
void protgroup_delete(struct protgroup *group, struct protstream *item);

/* Returns the protstream at that position in the protgroup, or NULL if
 * an invalid element is requested */
struct protstream *protgroup_getelement(struct protgroup *group,
                                        size_t element);

#endif /* INCLUDED_PROT_H */
