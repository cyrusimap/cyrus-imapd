/* prot.c -- stdio-like module that handles SASL protection mechanisms
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
 *
 */
/*
 * $Id: prot.c,v 1.68 2002/04/02 17:16:15 leg Exp $
 */

#include <config.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "prot.h"
#include "xmalloc.h"
#include "assert.h"

/*
 * Create a new protection stream for file descriptor 'fd'.  Stream
 * will be used for writing iff 'write' is nonzero.
 */
struct protstream *prot_new(fd, write)
int fd;
int write;
{
    struct protstream *newstream;

    newstream = (struct protstream *) xmalloc(sizeof(struct protstream));
    newstream->buf = (unsigned char *) 
	xmalloc(sizeof(char) * (PROT_BUFSIZE));
    newstream->buf_size = PROT_BUFSIZE;
    newstream->ptr = newstream->buf;
    newstream->cnt = write ? PROT_BUFSIZE : 0;
    newstream->maxplain = PROT_BUFSIZE;
    newstream->fd = fd;
    newstream->write = write;
    newstream->logfd = -1;
    newstream->error = 0;
    newstream->eof = 0;
    newstream->read_timeout = 0;
    newstream->dontblock = 0;
    newstream->flushonread = 0;
    newstream->readcallback_proc = 0;
    newstream->readcallback_rock = 0;
    newstream->waitevent = 0;
    newstream->conn = NULL;
    newstream->saslssf=0;

#ifdef HAVE_SSL
    newstream->tls_conn=NULL;
#endif /* HAVE_SSL */

    return newstream;
}

/*
 * Free a protection stream
 */
int prot_free(struct protstream *s)
{
    if (s->error) free(s->error);
    free(s->buf);
    free((char*)s);
    return 0;
}

/*
 * Set the logging file descriptor for stream 's' to be 'fd'.
 */
int prot_setlog(struct protstream *s, int fd)
{
    s->logfd = fd;
    return 0;
}

#ifdef HAVE_SSL

/*
 * Turn on TLS for this connection
 */

int prot_settls(struct protstream *s, SSL *tlsconn)
{
    s->tls_conn = tlsconn;

    return 0;
}

#endif /* HAVE_SSL */

/*
 * Turn on SASL for this connection
 */

int prot_setsasl(s, conn)
struct protstream *s;
sasl_conn_t *conn;
{
    const int *ssfp;
    int result;

    if (s->write && s->ptr != s->buf) {
	/* flush any pending output */
	prot_flush(s);
    }
   
    s->conn = conn;

    result = sasl_getprop(conn, SASL_SSF, (const void **) &ssfp);
    if (result != SASL_OK) {
	return -1;
    }
    s->saslssf = *ssfp;

    if (s->write) {
	int result;
	const int *maxp;
	int max;

	/* ask SASL for layer max */
	result = sasl_getprop(conn, SASL_MAXOUTBUF, (const void **) &maxp);
	max = *maxp;
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
	/* flush any pending input */
	s->cnt = 0;
    }

    return 0;
}

/*
 * Set the read timeout for the stream 's' to 'timeout' seconds.
 * 's' must have been created for reading.
 */
int prot_settimeout(struct protstream *s, int timeout)
{
    assert(!s->write);

    s->read_timeout = timeout;
    return 0;
}

/*
 * Set the stream 's' to flush the stream 'flushs' before
 * blocking for reading. 's' must have been created for reading,
 * 'flushs' for writing.
 */
int prot_setflushonread(struct protstream *s, struct protstream *flushs)
{
    assert(!s->write);

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
struct prot_waitevent *prot_addwaitevent(struct protstream *s, time_t mark,
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
void prot_removewaitevent(struct protstream *s, struct prot_waitevent *event)
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
const char *prot_error(struct protstream *s)
{
    return s->error;
}

/*
 * Rewind the stream 's'.  's' must have been created for reading.
 */
int prot_rewind(struct protstream *s)
{
    assert(!s->write);

    if (lseek(s->fd, 0L, 0) == -1) {
	s->error = xstrdup(strerror(errno));
	return EOF;
    }
    s->cnt = 0;
    s->error = 0;
    s->eof = 0;
    return 0;
}

/*
 * Read data into the empty buffer for the stream 's' and return the
 * first character.  Returns EOF on EOF or error.
 */
int prot_fill(struct protstream *s)
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

    if (s->eof || s->error) return EOF;

    do {
	/* wait until get input */
	haveinput = 0;

	/* if we've promised to call something before blocking or
	   flush an output stream, check to see if we're going to block */
	if (s->readcallback_proc ||
	    (s->flushonread && s->flushonread->ptr != s->flushonread->buf)) {
	    timeout.tv_sec = timeout.tv_usec = 0;
	    FD_ZERO(&rfds);
	    FD_SET(s->fd, &rfds);
	    if (select(s->fd + 1, &rfds, (fd_set *)0, (fd_set *)0,
		       &timeout) <= 0) {
		if (s->readcallback_proc) {
		    (*s->readcallback_proc)(s, s->readcallback_rock);
		    s->readcallback_proc = 0;
		    s->readcallback_rock = 0;
		}
		if (s->flushonread) prot_flush(s->flushonread);
	    }
	    else {
		haveinput = 1;
	    }
	}

	if (!haveinput && (s->read_timeout || s->dontblock)) {
	    time_t now = time(NULL);
	    time_t sleepfor;

	    read_timeout = now + (s->dontblock ? 0 : s->read_timeout);
	    do {
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
		r = select(s->fd + 1, &rfds, (fd_set *)0, (fd_set *)0,
			   &timeout);
		now = time(NULL);
	    } while ((r == 0 || (r == -1 && errno == EINTR)) &&
		     (now < read_timeout));
	    if (r == 0) {
		if (!s->dontblock) {
		    s->error = xstrdup("idle for too long");
		    return EOF;
		} else {
		    errno = EAGAIN;
		    return EOF;
		}
	    }
	}
	
	do {
#ifdef HAVE_SSL	  
	    /* just do a SSL read instead if we're under a tls layer */
	    if (s->tls_conn != NULL) {
		n = SSL_read(s->tls_conn, (char *) s->buf, PROT_BUFSIZE);
	    } else {
		n = read(s->fd, s->buf, PROT_BUFSIZE);
	    }
#else  /* HAVE_SSL */
	    n = read(s->fd, s->buf, PROT_BUFSIZE);
#endif /* HAVE_SSL */
	} while (n == -1 && errno == EINTR);
		
	if (n <= 0) {
	    if (n) s->error = xstrdup(strerror(errno));
	    else s->eof = 1;
	    return EOF;
	}
	
	if (s->saslssf) { /* decode it */
	    int result;
	    const char *out;
	    unsigned outlen;
	    
	    /* Decode the input token */
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
		/* XXX can we just serve data from 'out' without copying
		   it to s->buf ? */
		if (outlen > s->buf_size) {
		    s->buf = (unsigned char *) 
			xrealloc(s->buf, sizeof(char) * (outlen + 4));
		    s->buf_size = outlen;
		}
		memcpy(s->buf, out, outlen);
		s->ptr = s->buf + 1;
		s->cnt = outlen;
	    } else {		/* didn't decode anything */
		s->cnt = 0;
	    }
	    
	} else {
	    /* No protection function, just use the raw data */
	    s->ptr = s->buf+1;
	    s->cnt = n;
	}
	
	if (s->cnt > 0) {
	    if (s->logfd != -1) {
		time_t newtime;
		char timebuf[20];

		time(&newtime);
		sprintf(timebuf, "<%ld<", newtime);
		write(s->logfd, timebuf, strlen(timebuf));

		left = s->cnt;
		ptr = s->buf;
		do {
		    n = write(s->logfd, ptr, left);
		    if (n == -1 && errno != EINTR) {
			break;
		    }
		    if (n > 0) {
			ptr += n;
			left -= n;
		    }
		} while (left);
	    }

	    s->cnt--;		/* we return the first char */
	    return *s->buf;
	}
    } while (1);
}

/*
 * Write out any buffered data in the stream 's'
 */
int prot_flush(struct protstream *s)
{
    unsigned char *ptr = s->buf;
    int left = s->ptr - s->buf;
    int n;
    const char *encoded_output;

    assert(s->write);
    assert(s->cnt >= 0);

    if (s->eof || s->error) {
	s->ptr = s->buf;
	s->cnt = 1;
	return EOF;
    }
    if (!left) return 0;

    if (s->logfd != -1) {
	time_t newtime;
	char timebuf[20];

	time(&newtime);
	sprintf(timebuf, ">%ld>", newtime);
	write(s->logfd, timebuf, strlen(timebuf));

	do {
	    n = write(s->logfd, ptr, left);
	    if (n == -1 && errno != EINTR) {
		break;
	    }
	    if (n > 0) {
		ptr += n;
		left -= n;
	    }
	} while (left);
	left = s->ptr - s->buf;
	ptr = s->buf;
    }

    if (s->saslssf != 0) {
	/* encode the data */
	unsigned int outlen;
	int result;
	
	result = sasl_encode(s->conn, (char *) ptr, left, 
			     &encoded_output, &outlen);
	if (result != SASL_OK) {
	    char errbuf[256];
	    const char *ed = sasl_errdetail(s->conn);
	    
	    snprintf(errbuf, 256, "encoding error: %s; %s",
		     sasl_errstring(result, NULL, NULL),
		     ed ? ed : "no detail");
	    s->error = xstrdup(errbuf);
	    return EOF;
	}
	
	ptr = (unsigned char *) encoded_output;
	left = outlen;
    }

    /* Write out the data */
    do {
#ifdef HAVE_SSL
	if (s->tls_conn != NULL) {
	    n = SSL_write(s->tls_conn, (char *) ptr, left);
	} else {
	    n = write(s->fd, ptr, left);
	}
#else  /* HAVE_SSL */
	n = write(s->fd, ptr, left);
#endif /* HAVE_SSL */
	if (n == -1 && errno != EINTR) {
	    s->error = xstrdup(strerror(errno));
	    return EOF;
	}

	if (n > 0) {
	    ptr += n;
	    left -= n;
	}
    } while (left);

    /* Reset the output buffer */
    s->ptr = s->buf;
    s->cnt = s->maxplain;

    return 0;
}

/*
 * Write to the output stream 's' the 'len' bytes of data at 'buf'
 */
int prot_write(struct protstream *s, const char *buf, unsigned len)
{
    assert(s->write);

    while (len >= s->cnt) {
	/* XXX can we manage to write data from 'buf' without copying it
	   to s->ptr ? */
	memcpy(s->ptr, buf, s->cnt);
	s->ptr += s->cnt;
	buf += s->cnt;
	len -= s->cnt;
	s->cnt = 0;
	if (prot_flush(s) == EOF) return EOF;
    }
    memcpy(s->ptr, buf, len);
    s->ptr += len;
    s->cnt -= len;
    if (s->error || s->eof) return EOF;

    assert(s->cnt > 0);
    return 0;
}

/*
 * Stripped-down version of printf() that works on protection streams
 * Only understands '%ld', '%lu', '%d', %u', '%s', '%c', and '%%'
 * in the format string.
 */
int prot_printf(struct protstream *s, const char *fmt, ...)
{
    va_list pvar;
    char *percent, *p;
    long l;
    unsigned long ul;
    int i;
    unsigned u;
    char buf[30];
    va_start(pvar, fmt);

    assert(s->write);

    while ((percent = strchr(fmt, '%')) != 0) {
	prot_write(s, fmt, percent-fmt);
	switch (*++percent) {
	case '%':
	    prot_putc('%', s);
	    break;

	case 'l':
	    switch (*++percent) {
	    case 'd':
		l = va_arg(pvar, long);
		sprintf(buf, "%ld", l);
		prot_write(s, buf, strlen(buf));
		break;

	    case 'u':
		ul = va_arg(pvar, long);
		sprintf(buf, "%lu", ul);
		prot_write(s, buf, strlen(buf));
		break;

	    default:
		abort();
	    }
	    break;

	case 'd':
	    i = va_arg(pvar, int);
	    sprintf(buf, "%d", i);
	    prot_write(s, buf, strlen(buf));
	    break;

	case 'u':
	    u = va_arg(pvar, int);
	    sprintf(buf, "%u", u);
	    prot_write(s, buf, strlen(buf));
	    break;

	case 's':
	    p = va_arg(pvar, char *);
	    prot_write(s, p, strlen(p));
	    break;

	case 'c':
	    i = va_arg(pvar, int);
	    prot_putc(i, s);
	    break;

	default:
	    abort();
	}
	fmt = percent+1;
    }
    prot_write(s, fmt, strlen(fmt));
    va_end(pvar);
    if (s->error || s->eof) return EOF;
    return 0;
}

/*
 * Read from the protections stream 's' up to 'size' bytes into the buffer
 * 'buf'.  Returns the number of bytes read, or 0 for some error.
 */
int prot_read(struct protstream *s, char *buf, unsigned size)
{
    int c;

    assert(!s->write);

    if (!size) return 0;

    if (s->cnt) {
	/* Some data in the input buffer, return that */
	if (size > s->cnt) size = s->cnt;
	memcpy(buf, s->ptr, size);
	s->ptr += size;
	s->cnt -= size;
	return size;
    }

    c = prot_fill(s);
    if (c == EOF) return 0;
    buf[0] = c;
    if (--size > s->cnt) size = s->cnt;
    memcpy(buf+1, s->ptr, size);
    s->ptr += size;
    s->cnt -= size;
    return size+1;
}

/*
 * Version of fgets() that works with protection streams.
 */
char *prot_fgets(char *buf, unsigned size, struct protstream *s)
{
    char *p = buf;
    int c;

    assert(!s->write);

    if (size < 2) return 0;
    size -= 2;

    while (size && (c = prot_getc(s)) != EOF) {
	size--;
	*p++ = c;
	if (c == '\n') break;
    }
    if (p == buf) return 0;
    *p++ = '\0';
    return buf;
}

/* function versions of the macros */
#undef prot_getc
#undef prot_ungetc
#undef prot_putc

int prot_getc(struct protstream *s)
{
    assert(!s->write);

    if (s->cnt-- > 0) {
	return *(s->ptr)++;
    } else {
	return prot_fill(s);
    }
}

int prot_ungetc(int c, struct protstream *s)
{
    assert(!s->write);

    s->cnt++;
    *--(s->ptr) = c;

    return c;
}

int prot_putc(int c, struct protstream *s)
{
    assert(s->write);
    assert(s->cnt > 0);

    *s->ptr++ = c;
    if (--s->cnt == 0) {
	return prot_flush(s);
    } else {
	return 0;
    }
}


