/* imclient.c -- Streaming IMxP client library
 $Id: imclient.c,v 1.29 1999/07/31 21:49:37 leg Exp $
 
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
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include <sasl.h>

/*#include "sasl.h"*/
#include "exitcodes.h"
#include "xmalloc.h"
#include "imparse.h"
#include "imclient.h"
#include "nonblock.h"

extern int errno;

/* I/O buffer size */
#define IMCLIENT_BUFSIZE 4096

/* Command completion callback record */
struct imclient_cmdcallback {
    struct imclient_cmdcallback *next;
    long tag;			/* Command tag # */
    imclient_proc_t *proc;		/* Callback function */
    void *rock;			/* Callback rock */
};

/* Untagged data callback record */
struct imclient_callback {
    int flags;			/* Information about untagged data */
    char *keyword;		/* Untagged data protocol keyword */
    imclient_proc_t *proc;		/* Callback function */
    void *rock;			/* Callback rock */
};

/* Connection data */
struct imclient {
    /* TCP stream */
    int fd;
    char *servername;

    int flags;

    /* Data to be output to server */
    char outbuf[IMCLIENT_BUFSIZE];
    char *outptr;
    int outleft;
    char *outstart;
    char outcryptbuf[IMCLIENT_BUFSIZE+4];
    char *outcryptstart;
    int outcryptlen;

    /* Replies being received from server */
    char *replybuf;
    char *replystart;
    int replyliteralleft;
    int replylen;
    int replycryptstart;
    int replycryptend;
    int alloc_replybuf;
    
    /* Protection mechanism data */
  /*    struct sasl_client *mech;
    sasl_encodefunc_t *encodefunc;
    sasl_decodefunc_t *decodefunc;*/
    void *state;
    int maxplain;
    
    unsigned long gensym;	/* Tag value for previous command */

    unsigned long readytag;	/* Tag of command waiting for ready response */
				/* 0 if wait over or not pending */
    char *readytxt;		/* Text of ready response, NULL if got
				   tagged reply for command */

    /* Command callbacks */
    struct imclient_cmdcallback *cmdcallback;

    /* Untagged data callbacks */
    int callback_num;
    int callback_alloc;
    struct imclient_callback *callback;

  sasl_conn_t *saslconn;
  int saslcompleted;
};

/*
 * Syntactic class of a character
 * 0 - literal, 1 - quoted-string, 2 - atom
 */
static char charclass[256] = {
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, /*  00 -  0f */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /*  10 -  1f */
    1, 2, 0, 2, 2, 1, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, /* ' ' -  '/' */
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* '0' -  '?' */
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* '@' -  'O' */
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, /* 'P' -  '_' */
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* '`' -  'o' */
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, /* 'p' -  DEL */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*  80 -   8f */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*  90 -   9f */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*  a0 -   af */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*  b0 -   bf */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*  c0 -   cf */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*  d0 -   df */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*  e0 -   ef */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*  f0 -   ff */
};

/* Free list of command callback records */
static struct imclient_cmdcallback *cmdcallback_freelist;

/* Forward declarations */
static void imclient_write P((struct imclient *imclient,
			      const char *s, unsigned len));
static int imclient_writeastring P((struct imclient *imclient,
				     const char *str));
static void imclient_writebase64 P((struct imclient *imclient,
				    const char *output, unsigned len));
static void imclient_eof P((struct imclient *imclient));
static int imclient_decodebase64 P((char *input));

/*
 * Connect to server on 'host'.  Optional 'port' specifies the service
 * to use.  On success, returns zero and fills in the pointer pointed
 * to by 'imclient' with a newly allocated connection pointer. On
 * failure, returns errno if a system call failed, -1 if the hostname
 * was not found, or -2 if the service name was not found.
 */
int imclient_connect(imclient, host, port)
struct imclient **imclient;
const char *host;
const char *port;
{
    int s;
    struct hostent *hp;
    struct servent *sp;
    struct sockaddr_in addr;
    static struct imclient zeroimclient;

    hp = gethostbyname(host);
    if (!hp) return -1;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1) return errno;

    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, hp->h_addr, sizeof(addr.sin_addr));
    if (port && imparse_isnumber(port)) {
	addr.sin_port = htons(atoi(port));
    }
    else if (port) {
	sp = getservbyname(port, "tcp");
	if (!sp) return -2;
	addr.sin_port = sp->s_port;
    }
    else {
	addr.sin_port = htons(143);
    }
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
	return errno;
    }
    nonblock(s, 1);
    *imclient = (struct imclient *)xmalloc(sizeof(struct imclient));
    **imclient = zeroimclient;
    (*imclient)->fd = s;
    (*imclient)->saslconn = NULL;
    (*imclient)->saslcompleted = 0;
    (*imclient)->servername = xstrdup(hp->h_name);
    (*imclient)->outptr = (*imclient)->outstart = (*imclient)->outbuf;
    (*imclient)->outleft = (*imclient)->maxplain = sizeof((*imclient)->outbuf);
    imclient_addcallback(*imclient,
		 "", 0, (imclient_proc_t *) 0, (void *)0,
		 "OK", CALLBACK_NOLITERAL, (imclient_proc_t *)0, (void *)0,
		 "NO", CALLBACK_NOLITERAL, (imclient_proc_t *)0, (void *)0,
		 "BAD", CALLBACK_NOLITERAL, (imclient_proc_t *)0, (void *)0,
		 "BYE", CALLBACK_NOLITERAL, (imclient_proc_t *)0, (void *)0,
		 (char *)0);

    return 0;
}

/*
 * Close and free the connection 'imclient'
 */
void
imclient_close(imclient)
struct imclient *imclient;
{
    int i;

    imclient_eof(imclient);
    close(imclient->fd);
    free(imclient->servername);
    if (imclient->replybuf) free(imclient->replybuf);
    /*    if (imclient->state) imclient->mech->free_state(imclient->state);*/
    
    for (i = 0; i < imclient->callback_num; i++) {
	free(imclient->callback[i].keyword);
    }
    if (imclient->callback) free((char *)imclient->callback);
    free((char *)imclient);
}

void 
imclient_setflags(imclient, flags)
struct imclient *imclient;
int flags;
{
    imclient->flags |= flags;
}

void
imclient_clearflags(imclient, flags)
struct imclient *imclient;
int flags;
{
    imclient->flags &= ~flags;
}

char *
imclient_servername(imclient)
struct imclient *imclient;
{
    return imclient->servername;
}

#define CALLBACKGROW 2 /* XXX 30 */

/*
 * Add untagged data callbacks to a connection.
 * After the first argument 'imclient', there can be zero or more
 * 4-tuples of 'keyword', 'flags', 'proc', 'rock', each adding or changing
 * a single callback.  The last 4-tuple is terminated by a single null pointer.
 *
 * Each 4-tuple adds or changes the callback for 'keyword'.  'flags' specifies
 * information about the parsing of the untagged data.  'proc' and 'rock'
 * specify the callback function and rock to invoke when the untagged data
 * is received.  'proc' may be a null pointer, in which case no function is
 * invoked.
 *
 * The callback function may not call the functions imclient_close(),
 * imclient_send(), imclient_eof(), imclient_processoneevent(), or
 * imclient_authenticate() on the connection.  The callback function
 * may scribble on the text of the untagged data.
 * 
 */
#ifdef __STDC__
void imclient_addcallback(struct imclient *imclient, ...)
#else
void imclient_addcallback(va_alist)
va_dcl
#endif
{
    va_list pvar;
    char *keyword;
    int flags;
    imclient_proc_t *proc;
    void *rock;
    int i;
#ifdef __STDC__
    va_start(pvar, imclient);
#else
    struct imclient *imclient;

    va_start(pvar);
    imclient = va_arg(pvar, struct imclient *);
#endif

    while ((keyword = va_arg(pvar, char *))) {
	flags = va_arg(pvar, int);
	proc = va_arg(pvar, imclient_proc_t *);
	rock = va_arg(pvar, void *);
	
	/* Search for existing callback matching keyword and flags */
	for (i = 0; i < imclient->callback_num; i++) {
	    if (imclient->callback[i].flags == flags &&
		!strcmp(imclient->callback[i].keyword, keyword)) break;
	}

	/* If not found, allocate new callback entry */
	if (i == imclient->callback_num) {
	    if (imclient->callback_num == imclient->callback_alloc) {
		imclient->callback_alloc += CALLBACKGROW;
		imclient->callback = (struct imclient_callback *)
		  xrealloc((char *)imclient->callback,
		   imclient->callback_alloc*sizeof (struct imclient_callback));
	    }
	    imclient->callback_num++;
	    imclient->callback[i].keyword = xstrdup(keyword);
	    imclient->callback[i].flags = flags;
	}

	imclient->callback[i].proc = proc;
	imclient->callback[i].rock = rock;
    }
    va_end(pvar);
}

/*
 * Send a new command on the connection 'imclient'.
 *
 * 'finishproc' and 'finishrock' are the function and rock called when
 * the command completes.  'functionproc' may be a null pointer, in
 * which case no callback is made.  The callback function may not call
 * the functions imclient_close(), imclient_send(), imclient_eof(),
 * imclient_processoneevent(), or imclient_authenticate() on the
 * connection.  The callback function is guaranteed to be invoked, the
 * special result type "EOF" is used in the case where the connection
 * dies before a result is received from the server.
 *
 * 'fmt' is a printf-like specification of the command.  It must not
 * include the tag--that is automatically added by imclient_send().
 * The defined %-sequences are as follows:
 *
 *   %% -- %
 *   %a -- atom
 *   %s -- astring (will be quoted or literalized as needed)
 *   %d -- decimal
 *   %u -- unsigned decimal
 *   %v -- #astring (arg is an null-terminated array of (char *)
 *         which are written as space separated astrings)
 *   %B -- (internal use only) base64-encoded data at end of command line
 */ 
#ifdef __STDC__
void
imclient_send(struct imclient *imclient, void (*finishproc)(),
	      void *finishrock, const char *fmt, ...)
#else
void
imclient_send(va_alist)
va_dcl
#endif
{
    va_list pvar;
    struct imclient_cmdcallback *newcmdcallback;
    char buf[30];
    char *percent, *str, **v;
    int num;
    unsigned unum;
    int abortcommand = 0;
#ifdef __STDC__
    va_start(pvar, fmt);
#else
    struct imclient *imclient;
    imclient_proc_t *finishproc;
    void *finishrock;
    char *fmt;

    va_start(pvar);
    imclient = va_arg(pvar, struct imclient *);
    finishproc = va_arg(pvar, imclient_proc_t *);
    finishrock = va_arg(pvar, void *);
    fmt = va_arg(pvar, char *);
#endif

    imclient->gensym++;
    if (imclient->gensym <= 0) imclient->gensym = 1;

    /*
     * If there is a command completion callback, add it to the
     * command callback list of the imclient struct.
     */
    if (finishproc) {
	if (cmdcallback_freelist) {
	    newcmdcallback = cmdcallback_freelist;
	    cmdcallback_freelist = newcmdcallback->next;
	}
	else {
	    newcmdcallback = (struct imclient_cmdcallback *)
	      xmalloc(sizeof (struct imclient_cmdcallback));
	}
	newcmdcallback->next = imclient->cmdcallback;
	newcmdcallback->tag = imclient->gensym;
	newcmdcallback->proc = finishproc;
	newcmdcallback->rock = finishrock;
	imclient->cmdcallback = newcmdcallback;
    }
    
    /* Write the tag */
    sprintf(buf, "%lu ", imclient->gensym);
    imclient_write(imclient, buf, strlen(buf));

    /* Process the command format */
    while ((percent = strchr(fmt, '%'))) {
	imclient_write(imclient, fmt, percent-fmt);
	switch (*++percent) {
	case '%':
	    imclient_write(imclient, percent, 1);
	    break;

	case 'a':
	    str = va_arg(pvar, char *);
	    imclient_write(imclient, str, strlen(str));
	    break;

	case 's':
	    str = va_arg(pvar, char *);
	    abortcommand = imclient_writeastring(imclient, str);
	    if (abortcommand) goto fail;
	    break;
	    
	case 'd':
	    num = va_arg(pvar, int);
	    sprintf(buf, "%d", num);
	    imclient_write(imclient, buf, strlen(buf));
	    break;

	case 'u':
	    unum = va_arg(pvar, unsigned);
	    sprintf(buf, "%lu", (unsigned long)unum);
	    imclient_write(imclient, buf, strlen(buf));
	    break;

	case 'v':
	    v = va_arg(pvar, char **);
	    for (num = 0; v[num]; num++) {
		if (num) imclient_write(imclient, " ", 1);
		abortcommand = imclient_writeastring(imclient, v[num]);
		if (abortcommand) goto fail;
	    }
	    break;

	case 'B':
	    num = va_arg(pvar, int);
	    str = va_arg(pvar, char *);
	    imclient_writebase64(imclient, str, num);
	    /* KLUDGE ALERT: imclientwritebase64() spit out a CRLF
	     * so fake things up to prevent our spitting out a second CRLF.
	     */
	    abortcommand = 1;
	    goto fail;

	default:
	    fatal("internal error: invalid format specifier in imclient_send",
		  EC_SOFTWARE);
	}
	fmt = percent + 1;
    }
fail:
    va_end(pvar);

    if (!abortcommand) {
	imclient_write(imclient, fmt, strlen(fmt));
	imclient_write(imclient, "\r\n", 2);
    }
}

static int
imclient_writeastring(imclient, str)
struct imclient *imclient;
const char *str;
{
    const char *p;
    unsigned len = 0;
    int class = 2;
    char buf[30];

    for (p = str; *p; p++) {
	len++;
	if (class > charclass[(unsigned char)*p]) {
	    class = charclass[(unsigned char)*p];
	}
    }
    if (len >= 1024) class = 0;
    if (len && class == 2) {
	/* Atom */
	imclient_write(imclient, str, len);
    }
    else if (class) {
	/* Quoted-string */
	imclient_write(imclient, "\"", 1);
	imclient_write(imclient, str, len);
	imclient_write(imclient, "\"", 1);
    }
    else {
	/* Literal */
	if (imclient->flags & IMCLIENT_CONN_NONSYNCLITERAL) {
	    sprintf(buf, "{%u+}\r\n", len);
	    imclient_write(imclient, buf, strlen(buf));
	}
	else {
	    imclient->readytag = imclient->gensym;
	    sprintf(buf, "{%u}\r\n", len);
	    imclient_write(imclient, buf, strlen(buf));
	    while (imclient->readytag) {
		imclient_processoneevent(imclient);
	    }
	    if (!imclient->readytxt) return 1;
	}
	imclient_write(imclient, str, len);
    }
    return 0;
}

/*
 * Write to the connection 'imclient' the data 's', of length 'len'
 */
static void
imclient_write(imclient, s, len)
struct imclient *imclient;
const char *s;
unsigned len;
{
    /* If no data pending for output, reset the buffer */
    if (imclient->outptr == imclient->outstart) {
	imclient->outstart = imclient->outptr = imclient->outbuf;
	imclient->outleft = imclient->maxplain;
    }

    /* While we don't have room to buffer all the output */
    while (len > imclient->outleft) {
	/* Copy as much data as will fit in output buffer */
	memcpy(imclient->outptr, s, imclient->outleft);
	imclient->outptr += imclient->outleft;
	s += imclient->outleft;
	len -= imclient->outleft;
	imclient->outleft = 0;

	/* Process events until output buffer is flushed */
	while (imclient->outptr != imclient->outstart) {
	    imclient_processoneevent(imclient);
	}

	/* Reset the buffer */
	imclient->outstart = imclient->outptr = imclient->outbuf;
	imclient->outleft = imclient->maxplain;
    }

    /* Copy remaining data to output buffer */
    memcpy(imclient->outptr, s, len);
    imclient->outptr += len;
    imclient->outleft -= len;
}

/*
 * On the connection 'imclient', handle the input 'buf' of size 'len'
 * from the server.  Invoke callbacks as appropriate.
 */
#define REPLYSLACK 80		/* When growing, allocate this extra slack */
#define REPLYSHRINK (4096+500)	/* If more than this free, shrink buffer */
static void
imclient_input(imclient, buf, len)
struct imclient *imclient;
char *buf;
int len;
{
    long replytag;
    struct imclient_reply reply;
    char *endreply;
    char *p;
    int parsed;
    int literallen;
    int keywordlen;
    int keywordindex;
    struct imclient_cmdcallback **cmdcb, *cmdcbtemp;

    /* Ensure replybuf has enough space to take the input */
    if (imclient->replycryptend + len >= imclient->alloc_replybuf) {
	/* If there is unused space at the front, move the plaintext there */
	if (imclient->replystart != imclient->replybuf) {
	    imclient->replylen -= imclient->replystart - imclient->replybuf;
	    memmove(imclient->replybuf, imclient->replystart,
		    imclient->replylen);
	    imclient->replystart = imclient->replybuf;
	}
	/* If unused space between plaintext and crypttext, move crypttext */
	if (imclient->replycryptstart > imclient->replylen) {
	    if (imclient->replycryptend - imclient->replycryptstart) {
		memmove(imclient->replybuf + imclient->replylen,
			imclient->replybuf + imclient->replycryptstart,
			imclient->replycryptend - imclient->replycryptstart);
	    }
	    imclient->replycryptend -=
	      imclient->replycryptstart - imclient->replylen;
	    imclient->replycryptstart = imclient->replylen;

	    /* Shrink the reply buffer if it's too large */
	    if (imclient->replycryptend + len + REPLYSHRINK <
		imclient->alloc_replybuf) {
		imclient->alloc_replybuf = imclient->replycryptend + len
		  + REPLYSHRINK;
		imclient->replybuf = xrealloc(imclient->replybuf,
					      imclient->alloc_replybuf);
		imclient->replystart = imclient->replybuf;
	    }
	}

	/* If there still isn't enough room, grow the buffer */
	if (imclient->replycryptend + len >= imclient->alloc_replybuf) {
	    imclient->alloc_replybuf =
	      imclient->replycryptend + len + REPLYSLACK;
	    imclient->replybuf = xrealloc(imclient->replybuf,
					  imclient->alloc_replybuf);
	    imclient->replystart = imclient->replybuf;
	}
    }

    /* Copy the data to the buffer and NUL-terminate it */
    memcpy(imclient->replybuf + imclient->replycryptend, buf, len);
    imclient->replycryptend += len;

    /* Remember where new data starts */
    parsed = imclient->replylen;

    /* Decrypt the data */
    if (imclient->saslcompleted==1) {
	char lenbuf[4];
	int toklen, len;
	char *plainptr;
	unsigned int plainlen;

	for (;;) {
	    /* Make sure we have an entire token */

	    if (sasl_decode(imclient->saslconn,
			    imclient->replybuf + imclient->replycryptstart,
			   imclient->replycryptend - imclient->replycryptstart,
			    &plainptr, &plainlen) != SASL_OK) 
	      {
		(void) shutdown(imclient->fd, 0);
		break;
	      }

	    imclient->replycryptstart += imclient->replycryptend - imclient->replycryptstart;
	    if (plainlen==0) break; /* didn't get a whole token */

	    /* Copy the plaintext out, done with crypttext */
	    memcpy(imclient->replybuf + imclient->replylen,
		    plainptr, plainlen);
	    imclient->replylen += plainlen;

	    free(plainptr);
	}
    }
    else {
	/* No decryption necessary */
	imclient->replylen = imclient->replycryptstart =
	  imclient->replycryptend;
    }

    /* Process the new data */
    while (parsed < imclient->replylen) {
	/* If we're reading a literal, skip over it. */
	if (imclient->replyliteralleft) {
	    if (len > imclient->replyliteralleft) {
		len -= imclient->replyliteralleft;
		parsed += imclient->replyliteralleft;
		imclient->replyliteralleft = 0;
		continue;
	    }
	    else {
		parsed += len;
		imclient->replyliteralleft -= len;
		return;
	    }
	}

	/* Look for the end of the line and skip over to it. */
	endreply = (char *)memchr(imclient->replybuf + parsed, '\n',
				  imclient->replylen - parsed);

	/* Don't have a complete line */
	if (!endreply) return;

	parsed = endreply - imclient->replybuf + 1;


	/* parse tag */
	p = imclient->replystart;
	if (*p == '+' && p[1] == ' ') {
	    /* Ready response */
	    if (imclient->readytag) {
		imclient->readytag = 0;
		imclient->readytxt = p+2;
	    }
	    else {
		/* XXX Got junk from the server */
	    }
	    /* Start parsing the next reply */
	    imclient->replystart = endreply + 1;
	    continue;	    
	}
	else if (*p == '*' && p[1] == ' ') {
	    replytag = 0;
	    p += 2;
	}
	else {
	    replytag = 0;
	    while (isdigit(*p)) replytag = replytag * 10 + *p++ - '0';
	    if (*p++ != ' ') {
		/* XXX Got junk from the server */
		/* Start parsing the next reply */
		imclient->replystart = endreply + 1;
		continue;
	    }
	}

	/* parse num, if there */
	if (replytag == 0 && isdigit(*p)) {
	    reply.msgno = 0;
	    while (isdigit(*p)) reply.msgno = reply.msgno * 10 + *p++ - '0';
	    if (*p++ != ' ') {
		/* XXX Got junk from the server */
		/* Start parsing the next reply */
		imclient->replystart = endreply + 1;
		continue;
	    }
	}
	else {
	    reply.msgno = -1;
	}
	
	/* parse keyword */
	reply.keyword = p;
	while (*p != ' ' && *p != '\n') p++;
	keywordlen = p - reply.keyword;
	reply.text = p + 1;
	if (*p == '\n') {
	    if (keywordlen && p[-1] == '\r') {
	        keywordlen--;
		reply.text--;
	    }
	    reply.text--;
	}

	/* Handle tagged replies */
	if (replytag != 0) {
	    int iscompletion = 
		((keywordlen == 3 && reply.keyword[0] == 'B' &&
		     reply.keyword[1] == 'A' && reply.keyword[2] == 'D') ||
		    (keywordlen == 2 &&
		     ((reply.keyword[0] == 'O' && reply.keyword[1] == 'K') ||
		      (reply.keyword[0] == 'N' && reply.keyword[1] == 'O'))));


	    /* Scan back and see if the end of the line introduces a literal */
	    if (!iscompletion && endreply[-1] == '\r' && endreply[-2] == '}' &&
		isdigit(endreply[-3])) {
		p = endreply - 4;
		while (p > imclient->replystart && isdigit(*p)) p--;
		if (p > imclient->replystart + 2 && *p == '{' &&
		    charclass[(unsigned char)p[-1]] != 2) {

		    /* Parse the size of the literal */
		    literallen = 0;
		    p++;
		    while (isdigit(*p)) literallen = literallen*10 + *p++ -'0';

		    /* Do a continue to read literal & following line */
		    imclient->replyliteralleft = literallen;
		    continue;
		}
	    }

	    /* Start parsing the next reply */
	    imclient->replystart = endreply + 1;

	    if (replytag == imclient->readytag) {
		imclient->readytag = 0;
		imclient->readytxt = 0;
	    }

	    cmdcb = &imclient->cmdcallback;
	    while (*cmdcb && (*cmdcb)->tag != replytag) {
		cmdcb = &(*cmdcb)->next;
	    }
	    if ((cmdcbtemp = *cmdcb)) {
		if (iscompletion) {
		    /* Move callback struct to the freelist */
		    *cmdcb = cmdcbtemp->next;
		    cmdcbtemp->next = cmdcallback_freelist;
		    cmdcallback_freelist = cmdcbtemp;
		}
		
		/* Do the callback */
		endreply[-1] = '\0';
		reply.keyword[keywordlen] = '\0';
		(*cmdcbtemp->proc)(imclient, cmdcbtemp->rock, &reply);
	    }
	    
	    continue;
	}

	/* Must be an untagged reply, look up the keyword */
	for (keywordindex = 1; keywordindex < imclient->callback_num;
	     keywordindex++) {
	    if (imclient->callback[keywordindex].flags & CALLBACK_NUMBERED) {
		if (reply.msgno == -1) continue;
	    }
	    else {
		if (reply.msgno != -1) continue;
	    }
	    if (!strncmp(imclient->callback[keywordindex].keyword,
			 reply.keyword, keywordlen) &&
		imclient->callback[keywordindex].keyword[keywordlen] == '\0')
	      break;
	}

	/* Keyword index 0 is the default callback */
	if (keywordindex == imclient->callback_num) keywordindex = 0;

	/* Scan back and see if the end of the line introduces a literal */
	if (!(imclient->callback[keywordindex].flags & CALLBACK_NOLITERAL)) {
	    if (endreply[-1] == '\r' && endreply[-2] == '}' &&
		isdigit(endreply[-3])) {
		p = endreply - 4;
		while (p > imclient->replystart && isdigit(*p)) p--;
		if (p > imclient->replystart + 2 && *p == '{' &&
		    charclass[(unsigned char)p[-1]] != 2) {

		    /* Parse the size of the literal */
		    literallen = 0;
		    p++;
		    while (isdigit(*p)) literallen = literallen*10 + *p++ -'0';

		    /* Do a continue to read literal & following line */
		    imclient->replyliteralleft = literallen;
		    continue;
		}
	    }
	}

	/* Do the callback, if the proc is non-null  */
	if (imclient->callback[keywordindex].proc) {
	    endreply[-1] = '\0';
	    reply.keyword[keywordlen] = '\0';
	    (imclient->callback[keywordindex].proc)
	      (imclient, imclient->callback[keywordindex].rock, &reply);
	}

	/* Start parsing the next reply */
	imclient->replystart = endreply + 1;
    }
}

/*
 * Received an EOF on the connection 'imclient'
 * Issue appropriate callbacks.
 */
static void
imclient_eof(imclient)
struct imclient *imclient;
{
    struct imclient_cmdcallback *cmdcb;
    struct imclient_reply reply;

    imclient->readytag = 0;
    imclient->readytxt = 0;

    for (cmdcb = imclient->cmdcallback; cmdcb; cmdcb = cmdcb->next) {
	reply.keyword = "EOF";
	reply.msgno = -1;
	reply.text = "";
	(*cmdcb->proc)(imclient, cmdcb->rock, &reply);
	if (!cmdcb->next) {
	    cmdcb->next = cmdcallback_freelist;
	    cmdcallback_freelist = imclient->cmdcallback;
	    break;
	}
    }
    imclient->cmdcallback = 0;

    /* XXX make an untagged "EOF" callback? */
}

/*
 * Get information for calling select
 * 'fd' is filled in with file descriptor to select() for read
 * 'wanttowrite' is filled in with nonzero value iff should
 * select() for write as well.
 */
void
imclient_getselectinfo(imclient, fd, wanttowrite)
struct imclient *imclient;
int *fd;
int *wanttowrite;
{
    *fd = imclient->fd;
    *wanttowrite = imclient->outcryptlen ||
	imclient->outptr - imclient->outstart;
}

/*
 * Process one input or output event on the connection 'imclient'.
 */
void
imclient_processoneevent(imclient)
struct imclient *imclient;
{
    char buf[4+IMCLIENT_BUFSIZE];
    int n;
    int writelen;
    fd_set rfds, wfds;

    for (;;) {
	writelen = imclient->outptr - imclient->outstart;

	if ((imclient->saslcompleted==1) && (writelen>0)) {
	    unsigned int cryptlen=0;
	    char *cryptptr=NULL;

	  if (sasl_encode(imclient->saslconn, imclient->outstart, writelen,
			  &cryptptr,&cryptlen)!=SASL_OK)
	  {
	      /* XXX encoding error */
	      n=0;
	  }
	  
	  n = write(imclient->fd, cryptptr,
		    cryptlen);
	  
	  if (n > 0) {	    
	    free(cryptptr);
	    imclient->outstart += writelen;
	    return;
	  }


	  /* XXX Also EPIPE & the like? */
	  /* Make sure we select() for writing */

	}
	else if (writelen) {
	    /* No protection mechanism, just write the plaintext */
	    n = write(imclient->fd, imclient->outstart, writelen);
	    if (n > 0) {
		imclient->outstart += n;
		return;
	    }
	    /* XXX Also EPIPE & the like? */
	}

	n = read(imclient->fd, buf, sizeof(buf));
	if (n >= 0) {
	    if (n == 0) {
		imclient_eof(imclient);
	    }
	    else {
		imclient_input(imclient, buf, n);
	    }
	    return;
	}

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_SET(imclient->fd, &rfds);
	if (writelen) FD_SET(imclient->fd, &wfds);
	(void) select(imclient->fd + 1, &rfds, &wfds, (fd_set *)0, 0);
    }
}

enum replytype {replytype_inprogress, replytype_ok, replytype_no,
		  replytype_bad, replytype_prematureok};

struct authresult {
    enum replytype replytype;
    int r;
};

/* Command completion callback for imclient_authenticate */
static void 
authresult(imclient, rock, reply)
struct imclient *imclient;
void *rock;
struct imclient_reply *reply;
{
    char *userid;
    int protlevel;
    struct authresult *result = (struct authresult *)rock;

    if (!strcmp(reply->keyword, "OK")) {
	result->replytype = replytype_ok;
    }
    else if (!strcmp(reply->keyword, "NO")) {
	result->replytype = replytype_no;
    }
    else result->replytype = replytype_bad;
}




static sasl_security_properties_t *make_secprops(int min,int max)
{
  sasl_security_properties_t *ret=(sasl_security_properties_t *)
  malloc(sizeof(sasl_security_properties_t));

  ret->maxbufsize=1024;
  ret->min_ssf=min;
  ret->max_ssf=max;

  ret->security_flags=0;
  ret->property_names=NULL;
  ret->property_values=NULL;

  return ret;
}

void interaction (sasl_interact_t *t)
{
  char result[1024];

  printf("%s:",t->prompt);
  scanf("%s",&result);

  t->len=strlen(result);
  t->result=(char *) malloc(t->len+1);
  memset(t->result, 0, t->len+1);
  memcpy((char *) t->result, result, t->len);

}

void fillin_interactions(sasl_interact_t *tlist)
{
  while (tlist->id!=SASL_CB_LIST_END)
  {
    interaction(tlist);
    tlist++;
  }

}

/* callbacks we support */
static sasl_callback_t callbacks[] = {
  {
    SASL_CB_USER, NULL, NULL
  }, {
    SASL_CB_AUTHNAME, NULL, NULL
  }, {
    SASL_CB_PASS, NULL, NULL    
  }, {
    SASL_CB_LIST_END, NULL, NULL
  }
};

/*
 * Params:
 *  mechlist: list of mechanisms seperated by spaces
 *
 * Returns:
 *  0 - sucess
 *  1 - failure
 *  2 - severe failure?
 */

int imclient_authenticate(struct imclient *imclient, 
			  char *mechlist, 
			  char *service, 
			  char *user, 
			  int minssf, 
			  int maxssf)
{
  int saslresult;
  sasl_security_properties_t *secprops=NULL;
  int addrsize=sizeof(struct sockaddr_in);
  struct sockaddr_in *saddr_l=malloc(sizeof(struct sockaddr_in));
  struct sockaddr_in *saddr_r=malloc(sizeof(struct sockaddr_in));
  sasl_interact_t *client_interact=NULL;
  char *out;
  unsigned int outlen;
  char *in;
  int inlen;
  const char *mechusing;
  char inbase64[2048];
  int inbase64len;
  struct authresult result;

  /* attempt to start sasl */
  saslresult=sasl_client_init(callbacks);
  if (saslresult!=SASL_OK) return 1;

  /* client new connection */
  saslresult=sasl_client_new(service,
			     imclient->servername,
			     NULL,
			     0,
			     &(imclient->saslconn));
  if (saslresult!=SASL_OK) return 1;

  /*******
   * Now set the SASL properties
   *******/

  secprops=make_secprops(minssf,maxssf);
  if (secprops==NULL) return 1;

  saslresult=sasl_setprop(imclient->saslconn, SASL_SEC_PROPS, secprops);
  if (saslresult!=SASL_OK) return 1;
  free(secprops);

  if (getpeername(imclient->fd,(struct sockaddr *)saddr_r,&addrsize)!=0)
    return 1;

  /*  saddr_r->sin_port=htons(saddr_r->sin_port);	*/
  saslresult=sasl_setprop(imclient->saslconn, SASL_IP_REMOTE, saddr_r);
  if (saslresult!=SASL_OK) return 1;

  addrsize=sizeof(struct sockaddr_in);
  if (getsockname(imclient->fd,(struct sockaddr *)saddr_l,&addrsize)!=0)
    return 1;

  saddr_l->sin_port = saddr_r->sin_port; 
                    /* b/c getsockname is dumb and doesn't set it */

  /*  saddr_l->sin_port=htons(saddr_l->sin_port);	*/
  saslresult=sasl_setprop(imclient->saslconn,   SASL_IP_LOCAL, saddr_l);
  if (saslresult!=SASL_OK) return 1;

  free(saddr_l);
  free(saddr_r);

  /********
   * SASL is setup. Now try the actual authentication
   ********/
    
  saslresult=SASL_INTERACT;

  /* call sasl client start */
  while (saslresult==SASL_INTERACT)
  {
    saslresult=sasl_client_start(imclient->saslconn, mechlist,
				 NULL, &client_interact,
				 &out, &outlen,
				 &mechusing);
    if (saslresult==SASL_INTERACT)
      fillin_interactions(client_interact); /* fill in prompts */      

  }

  if ((saslresult!=SASL_OK) && (saslresult!=SASL_CONTINUE)) return saslresult;

  imclient_send(imclient, authresult, (void *)&result,
		"AUTHENTICATE %a", mechusing);

  while (1)
  {

    /* Wait for ready response or command completion */
    imclient->readytag = imclient->gensym;
    while (imclient->readytag) {
      imclient_processoneevent(imclient);
    }
    
    /* stop looping on command completion */
    if (!imclient->readytxt) break;

    if (isspace(*imclient->readytxt)) {
	inlen = 0;
    } else {
	inlen = imclient_decodebase64(imclient->readytxt);
    }

    /* perform a step */
    saslresult=SASL_INTERACT;
    while (saslresult==SASL_INTERACT)
    {
      saslresult=sasl_client_step(imclient->saslconn,
				  imclient->readytxt,
				  inlen, 
				  &client_interact,
				  &out,
				  &outlen);

      if (saslresult==SASL_INTERACT)
	  fillin_interactions(client_interact); /* fill in prompts */
    }

    /* send to server */
    /* Send our reply to the server */
    if ((saslresult==SASL_OK) || (saslresult==SASL_CONTINUE))
      imclient_writebase64(imclient, out, outlen);

    free(out);

  }
  
  imclient->saslcompleted=1;

  return 0;
}



#define XX 127
/*
 * Tables for encoding/decoding base64
 */
static const char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char index_64[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,XX,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};
#define CHAR64(c)  (index_64[(unsigned char)(c)])

/*
 * Decode in-place the base64 data in 'input'.  Returns the length
 * of the decoded data, or -1 if there was an error.
 */
static int 
imclient_decodebase64(input)
char *input;
{
    int len = 0;
    unsigned char *output = (unsigned char *)input;
    int c1, c2, c3, c4;

    while (*input) {
	c1 = *input++;
	if (CHAR64(c1) == XX) return -1;
	c2 = *input++;
	if (CHAR64(c2) == XX) return -1;
	c3 = *input++;
	if (c3 != '=' && CHAR64(c3) == XX) return -1; 
	c4 = *input++;
	if (c4 != '=' && CHAR64(c4) == XX) return -1;
	*output++ = (CHAR64(c1) << 2) | (CHAR64(c2) >> 4);
	++len;
	if (c3 == '=') break;
	*output++ = ((CHAR64(c2) << 4) & 0xf0) | (CHAR64(c3) >> 2);
	++len;
	if (c4 == '=') break;
	*output++ = ((CHAR64(c3) << 6) & 0xc0) | CHAR64(c4);
	++len;
    }

    return len;
}
	
/*
 * Write to the connection 'imclient' the base-64 encoded data
 * 'output', of (unencoded) length 'len'.
 */
static void
imclient_writebase64(imclient, output, len)
struct imclient *imclient;
const char *output;
unsigned len;
{
    char buf[1024];
    int buflen = 0;
    int c1, c2, c3;

    while (len) {
	if (buflen >= sizeof(buf)-4) {
	    imclient_write(imclient, buf, buflen);
	    buflen = 0;
	}
	
	c1 = (unsigned char)*output++;
	buf[buflen++] = basis_64[c1>>2];

	if (--len == 0) c2 = 0;
	else c2 = (unsigned char)*output++;
	buf[buflen++] = basis_64[((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)];

	if (len == 0) {
	    buf[buflen++] = '=';
	    buf[buflen++] = '=';
	    break;
	}

	if (--len == 0) c3 = 0;
	else c3 = (unsigned char)*output++;

	buf[buflen++] = basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)];
	if (len == 0) {
	    buf[buflen++] = '=';
	    break;
	}

	--len;
	buf[buflen++] = basis_64[c3 & 0x3F];
    }

    if (buflen >= sizeof(buf)-2) {
	imclient_write(imclient, buf, buflen);
	buflen = 0;
    }
    buf[buflen++] = '\r';
    buf[buflen++] = '\n';
    imclient_write(imclient, buf, buflen);
}

