/* prot.c -- stdio-like module that handles SASL protection mechanisms
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 * $Id: prot.c,v 1.72.4.17 2003/03/31 21:48:25 rjs3 Exp $
 */

#include <config.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
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
#include <sys/stat.h>
#include <netinet/in.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "assert.h"
#include "exitcodes.h"
#include "map.h"
#include "nonblock.h"
#include "prot.h"
#include "util.h"
#include "xmalloc.h"

/* Transparant protgroup structure */
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
struct protstream *prot_new(fd, write)
int fd;
int write;
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

/*
 * Free a protection stream
 */
int prot_free(struct protstream *s)
{
    if (s->error) free(s->error);
    free(s->buf);

    if(s->big_buffer != PROT_NO_FD) {
	map_free(&(s->bigbuf_base), &(s->bigbuf_siz));
	close(s->big_buffer);
    }

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

    /* Make nonblocking stuff to work similar to write() */
    SSL_set_mode(tlsconn,
		 SSL_MODE_ENABLE_PARTIAL_WRITE
		 | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

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
	if(prot_flush_internal(s,0) == EOF)
	    return EOF;
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
		(select(s->fd + 1, &rfds, (fd_set *)0, (fd_set *)0,
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
	    if ((r == 0) || 
                /* ignore EINTR if we've timed out */
                (r == -1 && errno == EINTR && now >= read_timeout)) {
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
		snprintf(timebuf, sizeof(timebuf), "<%ld<", newtime);
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
	snprintf(timebuf, sizeof(timebuf), ">%ld>", newtime);
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
    }
}

/* Do the encoding part of prot_flush */
static int prot_flush_encode(struct protstream *s,
			     const char **output_buf,
			     int *output_len) 
{
    unsigned char *ptr = s->buf;
    int left = s->ptr - s->buf;

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
	*output_buf = ptr;
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
#ifdef HAVE_SSL
	if (s->tls_conn != NULL) {
	    n = SSL_write(s->tls_conn, (char *)buf, len);
	} else {
	    n = write(s->fd, buf, len);
	}
#else  /* HAVE_SSL */
	n = write(s->fd, buf, len);
#endif /* HAVE_SSL */
    } while (n == -1 && errno == EINTR);

    return n;
}

int prot_flush_internal(struct protstream *s, int force)
{
    int n;
    int save_dontblock = s->dontblock;

    const char *ptr = s->buf; /* Memory buffer info */
    int left = s->ptr - s->buf;

    assert(s->write);
    assert(s->cnt >= 0);

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

    /* If we're doing a blocking write, flush the buffers, bigbuffer first */
    if(!s->dontblock) {
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
    } else { /* Nonblocking */
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
		int fd = create_tempfile();
		if(fd == -1) {
		    s->error = xstrdup(strerror(errno));
		    goto done;
		}

		s->big_buffer = fd;
	    }

	    do {
		n = write(s->big_buffer, ptr, left);
		if (n == -1 && errno != EINTR) {
		    syslog(LOG_ERR, "write to protstream buffer failed: %s",
			   strerror(errno));
		    
		    fatal("write to big buffer failed", EC_OSFILE);
		}
		if (n > 0) {
		    ptr += n;
		    left -= n;
		}
	    } while (left);

	    /* We did a write to the bigbuffer, refresh the memory map */
	    if (fstat(s->big_buffer, &sbuf) == -1) {
		syslog(LOG_ERR, "IOERROR: fstating temp protlayer buffer: %m");
		fatal("failed to fstat protlayer buffer", EC_IOERR);
	    }
	    
	    s->bigbuf_len = sbuf.st_size;

	    map_refresh(s->big_buffer, 0, &(s->bigbuf_base), &(s->bigbuf_siz),
			s->bigbuf_len, "temp protlayer buffer", NULL);
	}
	
    } /* end of blocking/nonblocking if statment */

    /* Reset the memory buffer -- should be done on EOF or on success. */
    s->ptr = s->buf;
    s->cnt = s->maxplain;
        
 done:
    /* are we done with the big buffer? If so, free it. This includes
     * when we exit with error */
    if(s->big_buffer != PROT_NO_FD &&
       (s->bigbuf_pos == s->bigbuf_len || s->error)) {
	map_free(&(s->bigbuf_base), &(s->bigbuf_siz));
	close(s->big_buffer);
	s->bigbuf_len = s->bigbuf_pos = 0;
	s->big_buffer = PROT_NO_FD;
    }

    if(force) {
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
int prot_write(struct protstream *s, const char *buf, unsigned len)
{
    assert(s->write);
    if(s->error || s->eof) return EOF;
    if(len == 0) return 0;
    
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
		snprintf(buf, sizeof(buf), "%ld", l);
		prot_write(s, buf, strlen(buf));
		break;

	    case 'u':
		ul = va_arg(pvar, long);
		snprintf(buf, sizeof(buf), "%lu", ul);
		prot_write(s, buf, strlen(buf));
		break;

	    default:
		abort();
	    }
	    break;

	case 'd':
	    i = va_arg(pvar, int);
	    snprintf(buf, sizeof(buf), "%d", i);
	    prot_write(s, buf, strlen(buf));
	    break;

	case 'u':
	    u = va_arg(pvar, int);
	    snprintf(buf, sizeof(buf), "%u", u);
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
 * select() for protection streams, read only
 * Also supports selecting on an extra file descriptor
 *
 * returns # of protstreams with pending data (including the extra fd)
 *
 * Only works for readable protstreams
 */ 
int prot_select(struct protgroup *readstreams, int extra_read_fd,
		struct protgroup **out, int *extra_read_flag,
		struct timeval *timeout) 
{
    struct protstream *s, *timeout_prot = NULL;
    struct protgroup *retval = NULL;
    int max_fd, found_fds = 0;
    int i;
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
	time_t this_timeout = 0;   /* this stream */
	
	s = readstreams->group[i];

	assert(!s->write);

	have_thistimeout = 0;
	
	/* scan for waitevent callbacks */
	for (event = s->waitevent; event; event = event->next)
	{
	    if(!have_thistimeout || event->mark - now < this_timeout) {
		this_timeout = event->mark - now;
		have_thistimeout = 1;
	    }
	}
	
	/* check the idle timeout on this one as well */
	if(!have_thistimeout || this_timeout > s->read_timeout)
	    this_timeout = s->read_timeout;

	if(!have_readtimeout && !s->dontblock) {
	    read_timeout = now + this_timeout;
	    have_readtimeout = 1;
	    if(!timeout || read_timeout <= timeout->tv_sec)
		timeout_prot = s;
	} else if(!s->dontblock) {
	    time_t new_timeout;
	    new_timeout = now + this_timeout;
	    if(new_timeout < read_timeout) {
		read_timeout = new_timeout;
		if(!timeout || read_timeout <= timeout->tv_sec)
		    timeout_prot = s;
	    }
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
	if((!timeout && have_readtimeout)
	   || (timeout && read_timeout < timeout->tv_sec)) {
	    if(!timeout)
		timeout = &my_timeout;
	    timeout->tv_sec = sleepfor;
	    timeout->tv_usec = 0;
	}

	if(select(max_fd + 1, &rfds, NULL, NULL, timeout) == -1)
	    return -1;

	/* Reset now */
	now = time(NULL);

	if(extra_read_fd != PROT_NO_FD && FD_ISSET(extra_read_fd, &rfds)) {
	    *extra_read_flag = 1;
	    found_fds++;
	} else {
	    *extra_read_flag = 0;
	}
	
	for(i = 0; i<readstreams->next_element; i++) {
	    s = readstreams->group[i];

	    if(FD_ISSET(s->fd, &rfds)) {
		found_fds++;

		if(!retval)
		    retval = protgroup_new(readstreams->next_element + 1);

		protgroup_insert(retval, s);
	    } else if(s == timeout_prot && now >= read_timeout) {
		/* If we timed out, be sure to add the protstream we were
		 * waiting for, even if it didn't show up */
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
char *prot_fgets(char *buf, unsigned size, struct protstream *s)
{
    char *p = buf;
    int c;

    assert(!s->write);

    if (size < 2) return 0;
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
struct protgroup *protgroup_new(size_t size) 
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

void protgroup_reset(struct protgroup *group) 
{
    if(group) {
	memset(group->group, 0,
	       group->next_element * sizeof(struct protstream *));
	group->next_element = 0;
    }
}

void protgroup_free(struct protgroup *group) 
{
    if(group) {
	assert(group->group);
	free(group->group);
	free(group);
    }
}

void protgroup_insert(struct protgroup *group, struct protstream *item) 
{
    assert(group);
    assert(item);
    /* Double size of the protgroup if we're at our limit */
    if(group->next_element == group->nalloced) {
	group->nalloced *= 2;
	group->group = xrealloc(group->group,
				group->nalloced * sizeof(struct protstream *));
    }
    /* Insert the item on the end of the group */
    group->group[group->next_element++] = item;
}

struct protstream *protgroup_getelement(struct protgroup *group,
					size_t element) 
{
    assert(group);
    if(element >= group->next_element) return NULL;
    else return group->group[element];
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
	return prot_flush_internal(s,0);
    } else {
	return 0;
    }
}
