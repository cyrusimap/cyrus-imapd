/* prot.h -- stdio-like module that handles buffering, SASL, and TLS
 *           details for I/O over sockets
 *
 * $Id: prot.h,v 1.35.4.4 2002/08/05 17:07:07 rjs3 Exp $
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 */

#ifndef INCLUDED_PROT_H
#define INCLUDED_PROT_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <sasl/sasl.h>

#ifdef HAVE_SSL
#include <openssl/ssl.h>
#endif /* HAVE_SSL */

#define PROT_BUFSIZE 4096
/* #define PROT_BUFSIZE 8192 */

#define PROT_NO_FD -1

struct protstream;
struct prot_waitevent;

typedef void prot_readcallback_t(struct protstream *s, void *rock);

struct protstream {
    /* The Buffer */
    unsigned char *buf;
    int buf_size;
    unsigned char *ptr; /* The end of data in the buffer */
    int cnt; /* Space Remaining in buffer */

    /* File Descriptors */
    int fd;         /* The Socket */
    int logfd;      /* The Telemetry Log (or PROT_NO_FD) */
    int big_buffer; /* The Big Buffer (or PROT_NO_FD) */

    /* SASL / TLS */
    sasl_conn_t *conn;
    int saslssf;
    int maxplain;

#ifdef HAVE_SSL
    SSL *tls_conn;
#endif /* HAVE_SSL */

    /* Big Buffer Information */
    const char *bigbuf_base;  /* Base Pointer */
    unsigned long bigbuf_siz; /* Overall Size of Buffer */
    unsigned long bigbuf_len; /* Length of mapped file */
    unsigned long bigbuf_pos; /* Current Position */

    /* Status Flags */
    int eof;
    char *error;

    /* Parameters */
    int write;
    int dontblock; /* Application requested nonblocking */
    int dontblock_isset; /* write only, we've fcntl(O_NONBLOCK)'d */
    int read_timeout;
    struct protstream *flushonread;

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

/* Not for use by applications directly (but needed by macros) */
int prot_flush_internal(struct protstream *s, int force);

#define PROTGROUP_SIZE_DEFAULT 32
struct protgroup; /* Opaque protgroup structure */

extern int prot_getc(struct protstream *s);
extern int prot_ungetc(int c, struct protstream *s);
extern int prot_putc(int c, struct protstream *s);

#define prot_getc(s) ((s)->cnt-- > 0 ? (int)*(s)->ptr++ : prot_fill(s))
#define prot_ungetc(c, s) ((s)->cnt++, (*--(s)->ptr = (c)))
#define prot_putc(c, s) ((*(s)->ptr++ = (c)), --(s)->cnt == 0 ? prot_flush(s) : 0)

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

extern struct protstream *prot_new(int fd, int write);
extern int prot_free(struct protstream *s);
extern int prot_setlog(struct protstream *s, int fd);
extern int prot_setsasl(struct protstream *s, sasl_conn_t *conn);
#ifdef HAVE_SSL
extern int prot_settls(struct protstream *s, SSL *tlsconn);
#endif /* HAVE_SSL */
extern int prot_settimeout(struct protstream *s, int timeout);
extern int prot_setflushonread(struct protstream *s,
			       struct protstream *flushs);
extern int prot_setreadcallback(struct protstream *s,
				prot_readcallback_t *proc, void *rock);
extern struct prot_waitevent *prot_addwaitevent(struct protstream *s,
						time_t mark,
						prot_waiteventcallback_t *proc,
						void *rock);
extern void prot_removewaitevent(struct protstream *s,
				 struct prot_waitevent *event);
extern const char *prot_error(struct protstream *s);
extern int prot_rewind(struct protstream *s);
extern int prot_fill(struct protstream *s);
extern int prot_flush(struct protstream *s);
extern int prot_write(struct protstream *s, const char *buf, unsigned len);
extern int prot_printf(struct protstream *, const char *, ...)
    __attribute__ ((format (printf, 2, 3)));
extern int prot_read(struct protstream *s, char *buf, unsigned size);
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

/* Returns the protstream at that position in the protgroup, or NULL if
 * an invalid element is requested */
struct protstream *protgroup_getelement(struct protgroup *group,
					size_t element);

#endif /* INCLUDED_PROT_H */
