/* prot.c -- stdio-like module that handles IMAP protection mechanisms
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <sys/types.h>
#include <netinet/in.h>

#include "prot.h"
#include "xmalloc.h"

/* Signal handler used for read timeouts */
static jmp_buf timeoutbuf;
static void
alarmhandler()
{
    longjmp(timeoutbuf, 1);
}

/*
 * Create a new protection stream for file descriptor 'fd'.  Stream
 * will be used for writing iff 'write' is nonzero.
 */
struct protstream *prot_new(fd, write)
int fd;
int write;
{
    struct protstream *newstream;

    newstream = (struct protstream *)xmalloc(sizeof(struct protstream));
    newstream->ptr = newstream->buf;
    newstream->cnt = write ? PROT_BUFSIZE : 0;
    newstream->leftcnt = 0;
    newstream->maxplain = PROT_BUFSIZE;
    newstream->fd = fd;
    newstream->write = write;
    newstream->logfd = -1;
    newstream->log_timeptr = 0;
    newstream->func = 0;
    newstream->state = 0;
    newstream->error = 0;
    newstream->eof = 0;
    newstream->read_timeout = 0;

    return newstream;
}

/*
 * Free a protection stream
 */
int prot_free(s)
struct protstream *s;
{
    free((char*)s);
    return 0;
}

/*
 * Set the logging file descriptor for stream 's' to be 'fd'.
 */
int prot_setlog(s, fd)
struct protstream *s;
int fd;
{
    s->logfd = fd;
    return 0;
}

/*
 * Start logging timing information for stream 's'.
 */
int prot_setlogtime(s, ptr)
struct protstream *s;
time_t *ptr;
{
    s->log_timeptr = ptr;
    time(s->log_timeptr);
    return 0;
}

/*
 * Set the protection function for stream 's' to be 'func'.  The opaque
 * object 'state' is passed to 'func' whenever it is called.  If the
 * stream is for writing, 'maxplain' is the maximum number of plaintext
 * bytes that will be given to 'func' at one time.
 */
int prot_setfunc(s, func, state, maxplain)
struct protstream *s;
const char *(*func)();
void *state;
int maxplain;
{
    if (s->write && s->ptr != s->buf) prot_flush(s);

    s->func = func;
    s->state = state;

    if (s->write) {
	s->maxplain = maxplain;
	s->cnt = maxplain;
    }
    else if (s->cnt) {
	s->leftptr = s->ptr;
	s->leftcnt = s->cnt;
	s->cnt = 0;
    }

    return 0;
}

/*
 * Set the read timeout for the stream 's' to 'timeout' seconds.
 * 's' must have been created for reading.
 */
int prot_settimeout(s, timeout)
struct protstream *s;
int timeout;
{
    s->read_timeout = timeout;
    signal(SIGALRM, alarmhandler);
    return 0;
}

/*
 * Return a pointer to a statically-allocated string describing the
 * error encountered on 's'.  If there is no error condition, return a
 * null pointer.
 */
const char *prot_error(s)
struct protstream *s;
{
    return s->error;
}

/*
 * Rewind the stream 's'.  's' must have been created for reading.
 */
int 
prot_rewind(s)
struct protstream *s;
{
    if (lseek(s->fd, 0L, 0) == -1) {
	s->error = strerror(errno);
	return EOF;
    }
    s->cnt = s->leftcnt = 0;
    s->error = 0;
    s->eof = 0;
    return 0;
}

/*
 * Read data into the empty buffer for the stream 's' and return the
 * first character.  Returns EOF on EOF or error.
 */
int 
prot_fill(s)
struct protstream *s;
{
    int n, cnt = 0;
    unsigned inputlen = 0;
    char *ptr;
    const char *err;
    int left;
    
    if (s->eof || s->error) return EOF;

    do {
	if (s->leftcnt) {
	    /* Crypttext left over from last fill, process it */
	    n = s->leftcnt;
	    memmove(s->buf, s->leftptr, n);
	    s->leftcnt = 0;
	}
	else {
	    if (s->read_timeout) {
		if (setjmp(timeoutbuf)) {
		    s->error = "idle for too long";
		    return EOF;
		}
		alarm(s->read_timeout);
	    }
	    do {
		n = read(s->fd, s->buf+cnt, sizeof(s->buf)-cnt);
	    } while (n == -1 && errno == EINTR);
	    if (s->read_timeout) alarm(0);
	}
    
	if (n <= 0) {
	    if (n) s->error = strerror(errno);
	    else s->eof = 1;
	    return EOF;
	}

	if (!s->func) {
	    /* No protection function, just use the raw data */
	    s->cnt = n-1;
	    s->ptr = s->buf+1;
	    if (s->logfd != -1) {
		time_t newtime;
		char timebuf[20];

		if (s->log_timeptr) {
		    time(&newtime);
		    sprintf(timebuf, "<%d<", newtime - *s->log_timeptr);
		    write(s->logfd, timebuf, strlen(timebuf));
		    *s->log_timeptr = newtime;
		}

		left = s->cnt+1;
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
	    return *s->buf;
	}
	cnt += n;
	/* First 4 bytes contain length of crypttext token */
	if (!inputlen && cnt >= 4) {
	    inputlen = ntohl(*(int *)s->buf);
	    if (inputlen > sizeof(s->buf) - 4) {
		s->error = "Input crypttext token too long";
		return EOF;
	    }
	}
    } while (cnt < 4 || cnt-4 < inputlen);

    /* Decode the input token */
    err = s->func(s->state, s->buf+4, inputlen, &s->ptr, &s->cnt);
    if (err) {
	strcpy(s->buf, "Decoding error: ");
	strcat(s->buf, err);
	s->error = s->buf;
	return EOF;
    }

    /* Save any left-over crypttext data for next time */
    if (cnt > inputlen + 4) {
	s->leftptr = s->buf + inputlen + 4;
	s->leftcnt = cnt - (inputlen + 4);
    }

    if (s->logfd != -1) {
	time_t newtime;
	char timebuf[20];

	if (s->log_timeptr) {
	    time(&newtime);
	    sprintf(timebuf, "<%d<", newtime - *s->log_timeptr);
	    write(s->logfd, timebuf, strlen(timebuf));
	    *s->log_timeptr = newtime;
	}

	left = s->cnt;
	ptr = s->ptr;
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

    s->cnt--;
    return *s->ptr++;
}

/*
 * Write out any buffered data in the stream 's'
 */
int prot_flush(s)
struct protstream *s;
{
    unsigned char outputbuf[PROT_BUFSIZE+4];
    unsigned char *ptr = s->buf;
    int left = s->ptr - s->buf;
    int n;

    if (s->eof || s->error) {
	s->ptr = s->buf;
	s->cnt = 1;
	return EOF;
    }
    if (!left) return 0;

    if (s->logfd != -1) {
	time_t newtime;
	char timebuf[20];

	if (s->log_timeptr) {
	    time(&newtime);
	    sprintf(timebuf, ">%d>", newtime - *s->log_timeptr);
	    write(s->logfd, timebuf, strlen(timebuf));
	}

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

    if (s->func) {
	/* Encode the data */
	if (s->func(s->state, ptr, left, outputbuf+4, &left)) {
	    s->error = "Encoding error";
	    if (s->log_timeptr) time(s->log_timeptr);
	    return EOF;
	}
	*(int *)outputbuf = htonl(left);
	ptr = outputbuf;
	left += 4;
    }

    /* Write out the data */
    do {
	n = write(s->fd, ptr, left);
	if (n == -1 && errno != EINTR) {
	    s->error = strerror(errno);
	    if (s->log_timeptr) time(s->log_timeptr);
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

    if (s->log_timeptr) time(s->log_timeptr);
    return 0;
}

/*
 * Write to the output stream 's' the 'len' bytes of data at 'buf'
 */
int prot_write(s, buf, len)
struct protstream *s;
const char *buf;
unsigned len;
{
    while (len >= s->cnt) {
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
    return 0;
}

/*
 * Stripped-down version of printf() that works on protection streams
 * Only understands '%d', '%s', '%c', and '%%' in the format string.
 */
#ifdef __STDC__
int prot_printf(struct protstream *s, const char *fmt, ...)
#else
int prot_printf(va_alist)
va_dcl
#endif
{
    va_list pvar;
    char *percent, *p;
    int i;
    unsigned u;
    char buf[30];
#ifdef __STDC__
    va_start(pvar, fmt);
#else
    struct protstream *s;
    char *fmt;

    va_start(pvar);
    s = va_arg(pvar, struct protstream *);
    fmt = va_arg(pvar, char *);
#endif

    while (percent = strchr(fmt, '%')) {
	prot_write(s, fmt, percent-fmt);
	switch (*++percent) {
	case '%':
	    prot_putc('%', s);
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
int
prot_read(s, buf, size)
struct protstream *s;
char *buf;
unsigned size;
{
    int c;

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
char *
prot_fgets(buf, size, s)
char *buf;
unsigned size;
struct protstream *s;
{
    char *p = buf;
    int c;

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
