/* prot.h -- stdio-like module that handles IMAP protection mechanisms
 * $Id: prot.h,v 1.36 2003/01/06 19:40:36 rjs3 Exp $
 
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

struct protstream;
struct prot_waitevent;

typedef void prot_readcallback_t(struct protstream *s, void *rock);

struct protstream {
    unsigned char *ptr;
    int cnt;
    int fd;
    int write;
    int logfd;
    sasl_conn_t *conn;
    int saslssf;
    int maxplain;
    char *error;
    int eof;
    int dontblock;
    int read_timeout;
    struct protstream *flushonread;
    prot_readcallback_t *readcallback_proc;
    void *readcallback_rock;
    struct prot_waitevent *waitevent;
    int buf_size;
    unsigned char *buf;

#ifdef HAVE_SSL
    SSL *tls_conn;
#endif /* HAVE_SSL */
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

extern int prot_getc(struct protstream *s);
extern int prot_ungetc(int c, struct protstream *s);
extern int prot_putc(int c, struct protstream *s);

#define prot_getc(s) ((s)->cnt-- > 0 ? (int)*(s)->ptr++ : prot_fill(s))
#define prot_ungetc(c, s) ((s)->cnt++, (*--(s)->ptr = (c)))
#define prot_putc(c, s) (!((s)->error || (s)->eof) ? ((*(s)->ptr++ = (c)), --(s)->cnt == 0 ? prot_flush(s) : 0) : EOF)
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

#endif /* INCLUDED_PROT_H */
