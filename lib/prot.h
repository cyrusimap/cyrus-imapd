/* prot.h -- stdio-like module that handles IMAP protection mechanisms
 * $Id: prot.h,v 1.24 2000/01/28 22:09:55 leg Exp $
 
 #        Copyright 1998 by Carnegie Mellon University
 #
 #                      All Rights Reserved
 #
 # Permission to use, copy, modify, and distribute this software and its
 # documentation for any purpose and without fee is hereby granted,
 # provided that the above copyright notice appear in all copies and that
 # both that copyright notice and this permission notice appear in
 # supporting documentation, and that the name of CMU not be
 # used in advertising or publicity pertaining to distribution of the
 # software without specific, written prior permission.
 #
 # CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 # ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 # CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 # ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 # WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 # ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 # SOFTWARE.
 *
 */

#ifndef INCLUDED_PROT_H
#define INCLUDED_PROT_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <sasl.h>

#ifdef HAVE_SSL
#include <openssl/ssl.h>
#endif /* HAVE_SSL */

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

#define PROT_BUFSIZE 4096
/* #define PROT_BUFSIZE 8192 */

struct protstream;

typedef void prot_readcallback_t P((struct protstream *s, void *rock));

struct protstream {
    unsigned char *ptr;
    int cnt;
    int fd;
    int write;
    int logfd;
    sasl_conn_t *conn;
    int saslssf;
    time_t *log_timeptr;
    const char *(*func)();
    void *state;
    int maxplain;
    const char *error;
    int eof;
    int dontblock;
    int read_timeout;
    struct protstream *flushonread;
    prot_readcallback_t *readcallback_proc;
    void *readcallback_rock;
    int buf_size;
    unsigned char *buf;

#ifdef HAVE_SSL
    SSL *tls_conn;
#endif /* HAVE_SSL */
};

extern int prot_getc(struct protstream *s);
extern int prot_ungetc(int c, struct protstream *s);
extern int prot_putc(int c, struct protstream *s);

#if 0
#define prot_getc(s) ((s)->cnt-- > 0 ? (int)*(s)->ptr++ : prot_fill(s))
#define prot_ungetc(c, s) ((s)->cnt++, (*--(s)->ptr = (c)))
#define prot_putc(c, s) ((*(s)->ptr++ = (c)), --(s)->cnt == 0 ? prot_flush(s) : 0)
#endif

extern struct protstream *prot_new(int fd, int write);
extern int prot_free(struct protstream *s);
extern int prot_setlog(struct protstream *s, int fd);
extern int prot_setlogtime(struct protstream *s, time_t *ptr);
extern int prot_setsasl(struct protstream *s, sasl_conn_t *conn);
#ifdef HAVE_SSL
extern int prot_settls(struct protstream *s, SSL *tlsconn);
#endif /* HAVE_SSL */
extern int prot_settimeout(struct protstream *s, int timeout);
extern int prot_setflushonread(struct protstream *s,
			       struct protstream *flushs);
extern int prot_setreadcallback(struct protstream *s,
				prot_readcallback_t *proc, void *rock);
extern const char *prot_error(struct protstream *s);
extern int prot_rewind(struct protstream *s);
extern int prot_fill(struct protstream *s);
extern int prot_flush(struct protstream *s);
extern int prot_write(struct protstream *s, const char *buf, unsigned len);
extern int prot_printf(struct protstream *, const char *, ...);
extern int prot_read(struct protstream *s, char *buf, unsigned size);
extern char *prot_fgets(char *buf, unsigned size, struct protstream *s);

#endif /* INCLUDED_PROT_H */
