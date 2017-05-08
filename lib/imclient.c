/* imclient.c -- Streaming IMxP client library
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
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include <sasl/sasl.h>

#ifdef HAVE_SSL
#include <openssl/lhash.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#else
#include <errno.h>
#endif /* HAVE_SSL */

#include "assert.h"
#include "exitcodes.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "strarray.h"
#include "imclient.h"
#include "nonblock.h"
#include "util.h"
#include "iptostring.h"

/* I/O buffer size */
#define IMCLIENT_BUFSIZE 4096

/* Command completion callback record */
struct imclient_cmdcallback {
    struct imclient_cmdcallback *next;
    unsigned long tag;          /* Command tag # */
    imclient_proc_t *proc;      /* Callback function */
    void *rock;                 /* Callback rock */
};

/* Untagged data callback record */
struct imclient_callback {
    int flags;                  /* Information about untagged data */
    char *keyword;              /* Untagged data protocol keyword */
    imclient_proc_t *proc;              /* Callback function */
    void *rock;                 /* Callback rock */
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
    size_t outleft;
    char *outstart;

    /* Replies being received from server */
    char *replybuf;
    char *replystart;
    size_t replyliteralleft;
    size_t replylen;
    size_t alloc_replybuf;

    /* Protection mechanism data */
    /* struct sasl_client *mech;
    sasl_encodefunc_t *encodefunc;
    sasl_decodefunc_t *decodefunc;*/
    void *state;
    int maxplain;

    unsigned long gensym;       /* Tag value for previous command */

    unsigned long readytag;     /* Tag of command waiting for ready response */
                                /* 0 if wait over or not pending */
    char *readytxt;             /* Text of ready response, NULL if got
                                   tagged reply for command */

    /* Command callbacks */
    struct imclient_cmdcallback *cmdcallback;

    /* Untagged data callbacks */
    int callback_num;
    int callback_alloc;
    struct imclient_callback *callback;

    strarray_t interact_results;

    sasl_conn_t *saslconn;
    int saslcompleted;

#ifdef HAVE_SSL
    SSL_CTX *tls_ctx;
    SSL *tls_conn;
    int tls_on; /* whether we are under a layer or not */
#endif /* HAVE_SSL */
};

/*
 * Syntactic class of a character
 * 0 - literal, 1 - quoted-string, 2 - atom
 */
static const char charclass[256] = {
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
static int imclient_writeastring(struct imclient *imclient, const char *str);
static void imclient_writebase64(struct imclient *imclient,
                                 const char *output, size_t len);
static void imclient_eof(struct imclient *imclient);
static int imclient_decodebase64(char *input);

/* callbacks we support */
static const sasl_callback_t callbacks[] = {
  { SASL_CB_USER, NULL, NULL },
  { SASL_CB_GETREALM, NULL, NULL },
  { SASL_CB_AUTHNAME, NULL, NULL },
  { SASL_CB_PASS, NULL, NULL },
  { SASL_CB_LIST_END, NULL, NULL }
};

/*
 * Connect to server on 'host'.  Optional 'port' specifies the service
 * to use.  On success, returns zero and fills in the pointer pointed
 * to by 'imclient' with a newly allocated connection pointer. On
 * failure, returns errno if a system call failed, -1 if the hostname
 * was not found, or -2 if the service name was not found.
 * use sasl callbacks 'cbs'
 */
EXPORTED int imclient_connect(struct imclient **imclient,
                     const char *host,
                     const char *port,
                     sasl_callback_t *cbs)
{
    int s = -1;
    struct addrinfo hints, *res0 = NULL, *res;
    int saslresult;
    static int didinit;

    assert(imclient);
    assert(host);

    if (!port)
        port = "143";
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    if (getaddrinfo(host, port, &hints, &res0))
        return -1;
    for (res = res0; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0)
            continue;
        if (connect(s, res->ai_addr, res->ai_addrlen) >= 0)
            break;
        close(s);
        s = -1;
    }
    if (s < 0)
        return errno;
    /*    nonblock(s, 1); */
    *imclient = (struct imclient *)xzmalloc(sizeof(struct imclient));
    (*imclient)->fd = s;
    (*imclient)->saslconn = NULL;
    (*imclient)->saslcompleted = 0;
    (*imclient)->servername = xstrdup(res0->ai_canonname ?
                                      res0->ai_canonname : host);
    freeaddrinfo(res0);
    (*imclient)->outptr = (*imclient)->outstart = (*imclient)->outbuf;
    (*imclient)->outleft = (*imclient)->maxplain = sizeof((*imclient)->outbuf);
    strarray_init(&(*imclient)->interact_results);
    imclient_addcallback(*imclient,
                 "", 0, (imclient_proc_t *) 0, (void *)0,
                 "OK", CALLBACK_NOLITERAL, (imclient_proc_t *)0, (void *)0,
                 "NO", CALLBACK_NOLITERAL, (imclient_proc_t *)0, (void *)0,
                 "BAD", CALLBACK_NOLITERAL, (imclient_proc_t *)0, (void *)0,
                 "BYE", CALLBACK_NOLITERAL, (imclient_proc_t *)0, (void *)0,
                 (char *)0);

#ifdef HAVE_SSL
    (*imclient)->tls_ctx=NULL;
    (*imclient)->tls_conn=NULL;
    (*imclient)->tls_on=0;
#endif /* HAVE_SSL */

    if (!didinit) {
        /* attempt to start sasl */
        saslresult = sasl_client_init(NULL);
        if (saslresult!=SASL_OK) return 1;
        didinit = 1;
    }

  /* client new connection */
  saslresult=sasl_client_new("imap", /* xxx ideally this should be configurable */
                             (*imclient)->servername,
                             NULL, NULL,
                             cbs ? cbs : callbacks,
                             0,
                             &((*imclient)->saslconn));
  if (saslresult!=SASL_OK) return 1;

    return 0;
}

/*
 * Close and free the connection 'imclient'
 */
void
EXPORTED imclient_close(struct imclient *imclient)
{
    int i;

    assert(imclient);

    imclient_eof(imclient);
    close(imclient->fd);
    free(imclient->servername);
    if (imclient->replybuf) free(imclient->replybuf);
    /*    if (imclient->state) imclient->mech->free_state(imclient->state);*/
    sasl_dispose(&(imclient->saslconn));
    for (i = 0; i < imclient->callback_num; i++) {
        free(imclient->callback[i].keyword);
    }
    if (imclient->callback) free(imclient->callback);

    strarray_fini(&imclient->interact_results);

    free(imclient);
}

EXPORTED void imclient_setflags(struct imclient *imclient, int flags)
{
    assert(imclient);
    imclient->flags |= flags;
}

EXPORTED void imclient_clearflags(struct imclient *imclient, int flags)
{
    assert(imclient);
    imclient->flags &= ~flags;
}

EXPORTED char *
imclient_servername(struct imclient *imclient)
{
    assert(imclient);
    return imclient->servername;
}

#define CALLBACKGROW 5

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
EXPORTED void imclient_addcallback(struct imclient *imclient, ...)
{
    va_list pvar;
    char *keyword;
    int flags;
    imclient_proc_t *proc;
    void *rock;
    int i;
    va_start(pvar, imclient);

    assert(imclient);

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
EXPORTED void
imclient_send(struct imclient *imclient, imclient_proc_t *finishproc,
              void *finishrock, const char *fmt, ...)
{
    va_list pvar;
    struct imclient_cmdcallback *newcmdcallback;
    char buf[30];
    char *percent, *str, **v;
    int num;
    unsigned unum;
    int abortcommand = 0;
    va_start(pvar, fmt);

    assert(imclient);

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
    snprintf(buf, sizeof(buf), "%lu ", imclient->gensym);
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
            snprintf(buf, sizeof(buf), "%d", num);
            imclient_write(imclient, buf, strlen(buf));
            break;

        case 'u':
            unum = va_arg(pvar, unsigned);
            snprintf(buf, sizeof(buf), "%lu", (unsigned long)unum);
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

static int imclient_writeastring(struct imclient *imclient, const char *str)
{
    const char *p;
    unsigned len = 0;
    int class = 2;
    char buf[30];

    assert(imclient);
    assert(str);

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
            snprintf(buf, sizeof(buf), "{%u+}\r\n", len);
            imclient_write(imclient, buf, strlen(buf));
        }
        else {
            imclient->readytag = imclient->gensym;
            snprintf(buf, sizeof(buf), "{%u}\r\n", len);
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
void imclient_write(struct imclient *imclient, const char *s, size_t len)
{
    assert(imclient);
    assert(s);

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
#define REPLYSLACK 80           /* When growing, allocate this extra slack */
#define REPLYSHRINK (4096+500)  /* If more than this free, shrink buffer */
static void imclient_input(struct imclient *imclient, char *buf, int len)
{
    unsigned long replytag;
    struct imclient_reply reply;
    char *endreply;
    const char *p;
    size_t parsed;
    uint32_t literallen;
    size_t keywordlen;
    int keywordindex;
    struct imclient_cmdcallback **cmdcb, *cmdcbtemp;
    const char *plainbuf;
    unsigned plainlen;
    int result;

    assert(imclient);
    assert(buf);

    if (imclient->saslcompleted == 1) {
        /* decrypt what we have */
        if ((result = sasl_decode(imclient->saslconn, buf, len,
                        &plainbuf, &plainlen)) != SASL_OK) {
            (void) shutdown(imclient->fd, 0);
        }

        if (plainlen == 0) return;
    } else {
        plainbuf = buf;
        plainlen = len;
    }

    /* Ensure replybuf has enough space to take the input */
    if (imclient->replylen + plainlen >= imclient->alloc_replybuf) {
        /* If there is unused space at the front, move the plaintext there */
        if (imclient->replystart != imclient->replybuf) {
            imclient->replylen -= imclient->replystart - imclient->replybuf;
            memmove(imclient->replybuf, imclient->replystart,
                    imclient->replylen);
            imclient->replystart = imclient->replybuf;
        }

        /* Shrink the reply buffer if it's too large */
        if (imclient->replylen + plainlen + REPLYSHRINK <
                imclient->alloc_replybuf) {
                imclient->alloc_replybuf = imclient->replylen + plainlen
                  + REPLYSHRINK;
                imclient->replybuf = xrealloc(imclient->replybuf,
                                              imclient->alloc_replybuf);
                imclient->replystart = imclient->replybuf;
            }

        /* If there still isn't enough room, grow the buffer */
        if (imclient->replylen + plainlen >= imclient->alloc_replybuf) {
            imclient->alloc_replybuf =
              imclient->replylen + plainlen + REPLYSLACK;
            imclient->replybuf = xrealloc(imclient->replybuf,
                                          imclient->alloc_replybuf);
            imclient->replystart = imclient->replybuf;
        }
    }

    /* Remember where new data starts */
    parsed = imclient->replylen;

    /* Copy the data to the buffer and NUL-terminate it */
    memcpy(imclient->replybuf + imclient->replylen, plainbuf, plainlen);
    imclient->replylen += plainlen;
    imclient->replybuf[imclient->replylen] = '\0';

    /* Process the new data (of length 'plainlen') */
    while (parsed < imclient->replylen) {
        /* If we're reading a literal, skip over it. */
        if (imclient->replyliteralleft) {
            size_t avail;

            avail = imclient->replylen - parsed;

            if (avail > imclient->replyliteralleft) {
                parsed += imclient->replyliteralleft;
                imclient->replyliteralleft = 0;
                continue;
            } else {
                parsed += avail;
                imclient->replyliteralleft -= avail;
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
                imclient->readytxt = (char *)p+2;
                *(endreply-1) = '\0';
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
            while (Uisdigit(*p)) {
                replytag = replytag * 10 + *p++ - '0';
            }
            if (*p++ != ' ') {
                /* XXX Got junk from the server */
                /* Start parsing the next reply */
                imclient->replystart = endreply + 1;
                continue;
            }
        }

        /* parse num, if there */
        if (replytag == 0 && Uisdigit(*p)) {
            reply.msgno = 0;
            while (Uisdigit(*p)) {
                reply.msgno = reply.msgno * 10 + *p++ - '0';
            }
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
        reply.keyword = (char *)p;
        while (*p && *p != ' ' && *p != '\n') p++;
        keywordlen = p - reply.keyword;
        reply.text = (char *)p + 1;
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
            if (!iscompletion && endreply > imclient->replystart+2 &&
                endreply[-1] == '\r' && endreply[-2] == '}' &&
                Uisdigit(endreply[-3])) {
                p = endreply - 4;
                while (p > imclient->replystart &&
                       Uisdigit(*p)) {
                    p--;
                }
                if (p > imclient->replystart + 2 && *p == '{' &&
                    charclass[(unsigned char)p[-1]] != 2) {

                    /* Parse the size of the literal */
                    if (parseuint32(p+1, &p, &literallen))
                        literallen = 0;

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
                imclient->callback[keywordindex].keyword[keywordlen] == '\0'
                && imclient->callback[keywordindex].proc)
              break;
        }

        /* Keyword index 0 is the default callback */
        if (keywordindex == imclient->callback_num) keywordindex = 0;

        /* Scan back and see if the end of the line introduces a literal */
        if (!(imclient->callback[keywordindex].flags & CALLBACK_NOLITERAL)) {
            if (endreply > imclient->replystart+2 &&
                endreply[-1] == '\r' && endreply[-2] == '}' &&
                Uisdigit(endreply[-3])) {
                p = endreply - 4;
                while (p > imclient->replystart &&
                       Uisdigit(*p)) {
                    p--;
                }
                if (p > imclient->replystart + 2 && *p == '{' &&
                    charclass[(unsigned char)p[-1]] != 2) {

                    /* Parse the size of the literal */
                    if (parseuint32(p+1, &p, &literallen))
                        literallen = 0;

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
static void imclient_eof(struct imclient *imclient)
{
    struct imclient_cmdcallback *cmdcb;
    struct imclient_reply reply;

    assert(imclient);

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
EXPORTED void imclient_getselectinfo(struct imclient *imclient, int *fd,
                            int *wanttowrite)
{
    assert(imclient);
    assert(fd);
    assert(wanttowrite);

    *fd = imclient->fd;
    *wanttowrite = imclient->outptr - imclient->outstart;
}

/*
 * Process one input or output event on the connection 'imclient'.
 */
EXPORTED void imclient_processoneevent(struct imclient *imclient)
{
    char buf[IMCLIENT_BUFSIZE];
    int n;
    int writelen;
    fd_set rfds, wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    assert(imclient);

    for (;;) {
        writelen = imclient->outptr - imclient->outstart;

        if ((imclient->saslcompleted==1) && (writelen>0)) {
            unsigned int cryptlen=0;
            const char *cryptptr=NULL;

          if (sasl_encode(imclient->saslconn, imclient->outstart, writelen,
                          &cryptptr,&cryptlen)!=SASL_OK)
          {
              /* XXX encoding error */
              n=0;
          }

#ifdef HAVE_SSL
          if (imclient->tls_on==1)
          {
            n = SSL_write(imclient->tls_conn, cryptptr, cryptlen);
          } else {
            n = write(imclient->fd, cryptptr, cryptlen);
          }
#else  /* HAVE_SSL */
          n = write(imclient->fd, cryptptr,
                    cryptlen);
#endif /* HAVE_SSL */

          if (n > 0) {
            imclient->outstart += writelen;
            return;
          }

          /* XXX Also EPIPE & the like? */
          /* Make sure we select() for writing */

        }
        else if (writelen) {

          /* No protection mechanism, just write the plaintext */

#ifdef HAVE_SSL
          if (imclient->tls_on==1)
          {
            n = SSL_write(imclient->tls_conn, imclient->outstart, writelen);
          } else {
            n = write(imclient->fd, imclient->outstart, writelen);
          }
#else  /* HAVE_SSL */
          n = write(imclient->fd, imclient->outstart, writelen);
#endif /* HAVE_SSL */


            if (n > 0) {
                imclient->outstart += n;
                return;
            }
            /* XXX Also EPIPE & the like? */
        }

        if (FD_ISSET(imclient->fd, &rfds))
        {
#ifdef HAVE_SSL
          /* just do a SSL read instead if we're under a tls layer */
          if (imclient->tls_on==1)
          {
            n = SSL_read(imclient->tls_conn, buf, sizeof(buf));

          } else {
            n = read(imclient->fd, buf, sizeof(buf));
          }

#else  /* HAVE_SSL */
          n = read(imclient->fd, buf, sizeof(buf));
#endif /* HAVE_SSL */

          if (n >= 0) {
            if (n == 0) {
              imclient_eof(imclient);
            }
            else {
              imclient_input(imclient, buf, n);
            }
            return;
          }
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
static void authresult(struct imclient *imclient __attribute__((unused)),
                       void *rock,
                       struct imclient_reply *reply)
{
    struct authresult *result = (struct authresult *)rock;

    assert(result);
    assert(reply);

    if (!strcmp(reply->keyword, "OK")) {
        result->replytype = replytype_ok;
    }
    else if (!strcmp(reply->keyword, "NO")) {
        result->replytype = replytype_no;
    }
    else result->replytype = replytype_bad;
}

/* Command completion for starttls */
#ifdef HAVE_SSL
static void tlsresult(struct imclient *imclient __attribute__((unused)),
                      void *rock,
                      struct imclient_reply *reply)
{
    struct authresult *result = (struct authresult *)rock;

    assert(result);
    assert(reply);

    if (!strcmp(reply->keyword, "OK")) {
        result->replytype = replytype_ok;
    }
    else if (!strcmp(reply->keyword, "NO")) {
        result->replytype = replytype_no;
    }
    else result->replytype = replytype_bad;
}
#endif /* HAVE_SSL */


static sasl_security_properties_t *make_secprops(int min,int max)
{
  sasl_security_properties_t *ret=
      (sasl_security_properties_t *)xzmalloc(sizeof(sasl_security_properties_t));

  ret->maxbufsize = IMCLIENT_BUFSIZE;
  ret->min_ssf = min;
  ret->max_ssf = max;

  return ret;
}

static void interaction(struct imclient *context, sasl_interact_t *t, char *user)
{
    char result[1024];
    char *str = NULL;

    assert(context);
    assert(t);

    if ((t->id == SASL_CB_USER || t->id == SASL_CB_AUTHNAME)
            && user && user[0]) {
        str = xstrdup(user);
    } else {
        printf("%s: ", t->prompt);
        if (t->id == SASL_CB_PASS) {
            char *ptr = cyrus_getpass("");
            strlcpy(result, ptr, sizeof(result));
        } else {
            if (!fgets(result, sizeof(result)-1, stdin))
                return;
        }
        str = xstrdup(result);
    }

    assert(str);
    t->result = str;
    t->len = strlen(str);
    strarray_appendm(&context->interact_results, str);
}

EXPORTED void fillin_interactions(struct imclient *context,
                         sasl_interact_t *tlist, char *user)
{
    assert(context);
    assert(tlist);

    while (tlist->id!=SASL_CB_LIST_END)
    {
        interaction(context, tlist, user);
        tlist++;
    }
}

/*
 * Params:
 *  mechlist: list of mechanisms separated by spaces
 *
 * Returns:
 *  0 - success
 *  1 - failure
 *  2 - severe failure?
 */
static int imclient_authenticate_sub(struct imclient *imclient,
                                     char *mechlist,
                                     char *user,
                                     int minssf,
                                     int maxssf,
                                     const char **mechusing)
{
  int saslresult;
  sasl_security_properties_t *secprops=NULL;
  socklen_t addrsize;
  struct sockaddr_storage saddr_l;
  struct sockaddr_storage saddr_r;
  char localip[60], remoteip[60];
  sasl_interact_t *client_interact=NULL;
  const char *out;
  unsigned int outlen;
  int inlen;
  struct authresult result;

  assert(imclient);
  assert(mechlist);

  /*******
   * Now set the SASL properties
   *******/
  secprops=make_secprops(minssf,maxssf);
  if (secprops==NULL) return 1;

  saslresult=sasl_setprop(imclient->saslconn, SASL_SEC_PROPS, secprops);
  if (saslresult!=SASL_OK) return 1;
  free(secprops);

  addrsize=sizeof(struct sockaddr_storage);
  if (getpeername(imclient->fd,(struct sockaddr *)&saddr_r,&addrsize)!=0)
      return 1;

  addrsize=sizeof(struct sockaddr_storage);
  if (getsockname(imclient->fd,(struct sockaddr *)&saddr_l,&addrsize)!=0)
      return 1;

  if(iptostring((const struct sockaddr *)&saddr_l, addrsize,
                localip, sizeof(localip)) != 0)
      return 1;

  if(iptostring((const struct sockaddr *)&saddr_r, addrsize,
                remoteip, sizeof(remoteip)) != 0)
      return 1;

  saslresult=sasl_setprop(imclient->saslconn, SASL_IPREMOTEPORT, remoteip);
  if (saslresult!=SASL_OK) return 1;

  saslresult=sasl_setprop(imclient->saslconn, SASL_IPLOCALPORT, localip);
  if (saslresult!=SASL_OK) return 1;

  /********
   * SASL is setup. Now try the actual authentication
   ********/

  saslresult=SASL_INTERACT;

  /* call sasl client start */
  while (saslresult==SASL_INTERACT)
  {
    saslresult=sasl_client_start(imclient->saslconn, mechlist,
                                 &client_interact,
                                 &out, &outlen,
                                 mechusing);
    if (saslresult==SASL_INTERACT) {
        fillin_interactions(imclient,
                            client_interact, user); /* fill in prompts */
    }
  }

  if ((saslresult!=SASL_OK) && (saslresult!=SASL_CONTINUE)) return saslresult;

  imclient_send(imclient, authresult, (void *)&result,
                "AUTHENTICATE %a", *mechusing);

  while (1) {
    /* Wait for ready response or command completion */
    imclient->readytag = imclient->gensym;
    while (imclient->readytag) {
      imclient_processoneevent(imclient);
    }

    /* stop looping on command completion */
    if (!imclient->readytxt) break;

    if (Uisspace(*imclient->readytxt)) {
        inlen = 0;
    } else {
        inlen = imclient_decodebase64(imclient->readytxt);
    }

    if (inlen == -1) {
        /* bad base64 string */
        return replytype_bad;
    }

    if (inlen == 0 && outlen > 0) {
        /* we have something from the initial thing to send */
    } else {
        /* perform a step */
        saslresult = SASL_INTERACT;
        while (saslresult == SASL_INTERACT) {
            saslresult=sasl_client_step(imclient->saslconn,
                                        imclient->readytxt,
                                        inlen,
                                        &client_interact,
                                        &out,
                                        &outlen);

            if (saslresult == SASL_INTERACT) {
                /* fill in prompts */
                fillin_interactions(imclient,
                                    client_interact, user);
            }
        }
    }

    /* send our reply to the server */
    if ((saslresult==SASL_OK) || (saslresult==SASL_CONTINUE)) {
        if (out == NULL || outlen == 0) {
            imclient_write(imclient, "\r\n", 2);
        } else {
            imclient_writebase64(imclient, out, outlen);
        }
    } else {
        imclient_write(imclient,"*\r\n", 3);
        return saslresult;
    }

    outlen = 0;
  }

  if(result.replytype == replytype_ok) imclient->saslcompleted = 1;

  return (result.replytype != replytype_ok);
}

/* xxx service is not needed here */
EXPORTED int imclient_authenticate(struct imclient *imclient,
                          char *mechlist,
                          char *service __attribute__((unused)),
                          char *user,
                          int minssf,
                          int maxssf)
{
    int r;
    char *mlist;
    const char *mtried;

    assert(imclient);
    assert(mechlist);

    mlist = xstrdup(mechlist);
    ucase(mlist);

    do {
        mtried = NULL;

        r = imclient_authenticate_sub(imclient,
                                      mlist,
                                      user,
                                      minssf,
                                      maxssf,
                                      &mtried);

        /* eliminate mtried (mechanism tried) from mlist */
        if (r != 0 && mtried) {
            char *newlist = xmalloc(strlen(mlist)+1);
            char *mtr = xstrdup(mtried);
            char *tmp;

            ucase(mtr);
            tmp = strstr(mlist,mtr);
            if(!tmp) {
                free(mtr);
                free(newlist);
                break;
            }
            *tmp = '\0';
            strcpy(newlist,mlist);

            /* Use tmp+1 here to skip the \0 we just put in.
             * this is safe because even if the mechs are one character
             * long there would still be another trailing \0 */
            tmp = strchr(tmp+1,' ');
            if (tmp) {
                tmp++; /* skip the space */
                strcat(newlist,tmp);
            }

            free(mtr);
            free(mlist);
            mlist = newlist;
        }
    } while ((r != 0) && (mtried));

    if (r == 0) {
        const void *maxp;
        unsigned int max;

        sasl_getprop(imclient->saslconn, SASL_MAXOUTBUF, &maxp);
        max = *((const unsigned int *) maxp);
        imclient->maxplain = max < IMCLIENT_BUFSIZE ? max : IMCLIENT_BUFSIZE;
    }

    free(mlist);

    return r;
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
static int imclient_decodebase64(char *input)
{
    int len = 0;
    unsigned char *output = (unsigned char *)input;
    int c1, c2, c3, c4;

    assert(input);

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
static void imclient_writebase64(struct imclient *imclient,
                                 const char *output,
                                 size_t len)
{
    char buf[1024];
    size_t buflen = 0;
    int c1, c2, c3;

    assert(imclient);
    assert(output);

    while (len) {
        if (buflen >= (size_t)(sizeof(buf)-4)) {
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


/*************** All these functions help do the starttls; these are copied from imtest.c ********/
#ifdef HAVE_SSL

static int verify_depth;
static int verify_error = X509_V_OK;

#define CCERT_BUFSIZ 256
static char peer_CN[CCERT_BUFSIZ];

/*
  * Set up the cert things on the server side. We do need both the
  * private key (in key_file) and the cert (in cert_file).
  * Both files may be identical.
  *
  * This function is taken from OpenSSL apps/s_cb.c
  */

static int set_cert_stuff(SSL_CTX * ctx, char *cert_file, char *key_file)
{
    if (cert_file != NULL) {
        if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0) {
          printf("[ unable to get certificate from '%s' ]\n", cert_file);
          return (0);
        }
        if (key_file == NULL)
            key_file = cert_file;
        if (SSL_CTX_use_PrivateKey_file(ctx, key_file,
                                        SSL_FILETYPE_PEM) <= 0) {
          printf("[ unable to get private key from '%s' ]\n", key_file);
          return (0);
        }
        /* Now we know that a key and cert have been set against
         * the SSL context */
        if (!SSL_CTX_check_private_key(ctx)) {
          printf("[ Private key does not match the certificate public key ]\n");
          return (0);
        }
    }
    return (1);
}

/* taken from OpenSSL apps/s_cb.c */

static int verify_callback(int ok, X509_STORE_CTX * ctx)
{
    char    buf[256];
    X509   *err_cert;
    int     err;
    int     depth;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof(buf));

    /*    if (verbose==1)
          printf("Peer cert verify depth=%d %s\n", depth, buf);*/

    if (!ok) {
      printf("verify error:num=%d:%s\n", err,
             X509_verify_cert_error_string(err));
        if (verify_depth >= depth) {
            ok = 1;
            verify_error = X509_V_OK;
        } else {
            ok = 0;
            verify_error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        }
    }
    switch (err) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        X509_NAME_oneline(X509_get_issuer_name(err_cert),
                          buf, sizeof(buf));
        printf("issuer= %s\n", buf);
        break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
      printf("cert not yet valid\n");
      break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
      printf("cert has expired\n");
      break;
    }

    /*    if (verbose==1)
          printf("verify return:%d\n", ok);*/

    return (ok);
}


#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* taken from OpenSSL apps/s_cb.c */
static RSA *tmp_rsa_cb(SSL *s __attribute__((unused)),
                       int export __attribute__((unused)),
                       int keylength)
{
    static RSA *rsa_tmp = NULL;

    if (rsa_tmp == NULL) {
        rsa_tmp = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
    }
    return (rsa_tmp);
}
#endif

/*
 * Seed the random number generator.
 */
static int tls_rand_init(void)
{
#ifdef EGD_SOCKET
    return (RAND_egd(EGD_SOCKET));
#else
    /* otherwise let OpenSSL do it internally */
    return 0;
#endif
}

 /*
  * This is the setup routine for the SSL client.
  *
  * The skeleton of this function is taken from OpenSSL apps/s_client.c.
  */

static int tls_init_clientengine(struct imclient *imclient,
                                 int verifydepth, char *var_tls_cert_file,
                                 char *var_tls_key_file,
                                 char *var_tls_CAfile,
                                 char *var_tls_CApath)
{
    int     off = 0;
    int     verify_flags = SSL_VERIFY_NONE;
    char   *CApath;
    char   *CAfile;
    char   *c_cert_file;
    char   *c_key_file;

    assert(imclient);

    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    if (tls_rand_init() == -1) {
        printf("[ TLS engine: cannot seed PRNG ]\n");
        return -1;
    }

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    imclient->tls_ctx = SSL_CTX_new(TLS_client_method());
#else
    imclient->tls_ctx = SSL_CTX_new(SSLv23_client_method());
#endif
    if (imclient->tls_ctx == NULL) {
        return -1;
    };

    off |= SSL_OP_ALL;            /* Work around all known bugs */
    off |= SSL_OP_NO_SSLv2;       /* Disable insecure SSLv2 */
    off |= SSL_OP_NO_SSLv3;       /* Disable insecure SSLv3 */
    off |= SSL_OP_NO_COMPRESSION; /* Disable TLS compression */
    SSL_CTX_set_options(imclient->tls_ctx, off);

    /* debugging   SSL_CTX_set_info_callback(imclient->tls_ctx, apps_ssl_info_callback); */

    if (var_tls_CAfile == NULL || strlen(var_tls_CAfile) == 0)
        CAfile = NULL;
    else
        CAfile = var_tls_CAfile;
    if (var_tls_CApath == NULL || strlen(var_tls_CApath) == 0)
        CApath = NULL;
    else
        CApath = var_tls_CApath;

    if (CAfile || CApath)
        if ((!SSL_CTX_load_verify_locations(imclient->tls_ctx, CAfile, CApath)) ||
            (!SSL_CTX_set_default_verify_paths(imclient->tls_ctx))) {
            printf("[ TLS engine: cannot load CA data ]\n");
            return -1;
        }
    if (var_tls_cert_file == NULL || strlen(var_tls_cert_file) == 0)
        c_cert_file = NULL;
    else
        c_cert_file = var_tls_cert_file;
    if (var_tls_key_file == NULL || strlen(var_tls_key_file) == 0)
        c_key_file = NULL;
    else
        c_key_file = var_tls_key_file;

    if (c_cert_file || c_key_file)
        if (!set_cert_stuff(imclient->tls_ctx, c_cert_file, c_key_file)) {
            printf("[ TLS engine: cannot load cert/key data, may be a cert/key mismatch]\n");
            return -1;
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_CTX_set_tmp_rsa_callback(imclient->tls_ctx, tmp_rsa_cb);
#endif

    verify_depth = verifydepth;
    SSL_CTX_set_verify(imclient->tls_ctx, verify_flags, verify_callback);

    return 0;
}

#if 0 /* Dead code only for debugging */
static int do_dump = 1;

/*
 * taken from OpenSSL crypto/bio/b_dump.c, modified to save a lot of strcpy
 * and strcat by Matti Aarnio.
 */

#define TRUNCATE
#define DUMP_WIDTH      16

static int tls_dump(const char *s, int len)
{
    int     ret = 0;
    char    buf[160 + 1];
    char    *ss;
    int     i;
    int     j;
    int     rows;
    int     trunc;
    unsigned char ch;

    trunc = 0;

#ifdef TRUNCATE
    for (; (len > 0) && ((s[len - 1] == ' ') || (s[len - 1] == '\0')); len--)
        trunc++;
#endif

    rows = (len / DUMP_WIDTH);
    if ((rows * DUMP_WIDTH) < len)
        rows++;

    for (i = 0; i < rows; i++) {
        buf[0] = '\0';                          /* start with empty string */
        ss = buf;

        sprintf(ss, "%04x ", i * DUMP_WIDTH);
        ss += strlen(ss);
        for (j = 0; j < DUMP_WIDTH; j++) {
            if (((i * DUMP_WIDTH) + j) >= len) {
                strcpy(ss, "   ");
            } else {
                ch = ((unsigned char) *((char *) (s) + i * DUMP_WIDTH + j))
                    & 0xff;
                sprintf(ss, "%02x[%c]%c", ch, ch, j == 7 ? '|' : ' ');
                ss += 6;
            }
        }
        ss += strlen(ss);
        *ss+= ' ';
        for (j = 0; j < DUMP_WIDTH; j++) {
            if (((i * DUMP_WIDTH) + j) >= len)
                break;
            ch = ((unsigned char) *((char *) (s) + i * DUMP_WIDTH + j)) & 0xff;
            *ss+= (((ch >= ' ') && (ch <= '~')) ? ch : '.');
            if (j == 7) *ss+= ' ';
        }
        *ss = 0;
        /*
         * if this is the last call then update the ddt_dump thing so that
         * we will move the selection point in the debug window
         */
        printf("%s\n", buf);
        ret += strlen(buf);
    }
#ifdef TRUNCATE
    if (trunc > 0) {
        sprintf(buf, "%04x - <SPACES/NULS>\n", len+ trunc);
        printf("%s\n", buf);
        ret += strlen(buf);
    }
#endif
    return (ret);
}

/* these next two taken from OpenSSL apps/s_cb.c */
static long bio_dump_cb(BIO * bio,
                        int cmd,
                        const char *argp,
                        int argi,
                        long argl __attribute__((unused)),
                        long ret)
{
    if (!do_dump)
        return (ret);

    if (cmd == (BIO_CB_READ | BIO_CB_RETURN)) {
        printf("read from %08X [%08lX] (%d bytes => %ld (0x%X))\n", (unsigned int) bio,
               (unsigned long) argp,
               argi, ret, (unsigned int) ret);
        tls_dump(argp, (int) ret);
        return (ret);
    } else if (cmd == (BIO_CB_WRITE | BIO_CB_RETURN)) {
        printf("write to %08X [%08lX] (%d bytes => %ld (0x%X))\n", (unsigned int) bio,
               (unsigned long) argp,
               argi, ret, (unsigned int) ret);
        tls_dump(argp, (int) ret);
    }
    return (ret);
}

static void apps_ssl_info_callback(SSL * s, int where, int ret)
{
    char   *str;
    int     w;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
        str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
        str = "SSL_accept";
    else
        str = "undefined";

    if (where & SSL_CB_LOOP) {
      printf("%s:%s\n", str, SSL_state_string_long(s));
    } else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        if ((ret & 0xff) != SSL3_AD_CLOSE_NOTIFY)
            printf("SSL3 alert %s:%s:%s\n", str,
                   SSL_alert_type_string_long(ret),
                   SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0)
            printf("%s:failed in %s\n",
                     str, SSL_state_string_long(s));
        else if (ret < 0) {
            printf("%s:error in %s %i\n",
                     str, SSL_state_string_long(s),ret);
        }
    }
}
#endif

EXPORTED int tls_start_clienttls(struct imclient *imclient,
                        unsigned *layer, char **authid, int fd)
{
    int sts;
    SSL_SESSION *session;
    const SSL_CIPHER *cipher;
    X509 *peer;
    int tls_cipher_usebits = 0;
    int tls_cipher_algbits = 0;
    char *tls_peer_CN = "";

    if (!imclient->tls_conn)
        imclient->tls_conn = (SSL *) SSL_new(imclient->tls_ctx);

    if (!imclient->tls_conn) {
        printf("Could not allocate 'con' with SSL_new()\n");
        return -1;
    }

    SSL_clear(imclient->tls_conn);

    if (!SSL_set_fd(imclient->tls_conn, fd)) {
        printf("SSL_set_fd failed\n");
        return -1;
    }

    /*
     * This is the actual handshake routine. It will do all the negotiations
     * and will check the client cert etc.
     */
    SSL_set_connect_state(imclient->tls_conn);

    /*
     * We do have an SSL_set_fd() and now suddenly a BIO_ routine is called?
     * Well there is a BIO below the SSL routines that is automatically
     * created for us, so we can use it for debugging purposes.
     */

    /* Dump the negotiation for loglevels 3 and 4 */

    sts = SSL_connect(imclient->tls_conn);
    if (sts <= 0) {
        printf("[ SSL_connect error %d ]\n", sts); /* xxx get string error? */
        session = SSL_get_session(imclient->tls_conn);
        if (session) {
            SSL_CTX_remove_session(imclient->tls_ctx, session);
            printf("[ SSL session removed ]\n");
        }
        if (imclient->tls_conn)
            SSL_free(imclient->tls_conn);
        imclient->tls_conn = NULL;
        return -1;
    }

    /*
     * Lets see, whether a peer certificate is available and what is
     * the actual information. We want to save it for later use.
     */
    peer = SSL_get_peer_certificate(imclient->tls_conn);
    if (peer) {
        X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
                                  NID_commonName, peer_CN, CCERT_BUFSIZ);
        tls_peer_CN = peer_CN;
    }

    cipher = SSL_get_current_cipher(imclient->tls_conn);
    tls_cipher_usebits = SSL_CIPHER_get_bits(cipher,
                                             &tls_cipher_algbits);

    if (layer)
        *layer = tls_cipher_usebits;

    if (authid)
        *authid = tls_peer_CN;

    return 0;
}
#endif /* HAVE_SSL */

EXPORTED int imclient_havetls(void)
{
#ifdef HAVE_SSL
    return 1;
#else
    return 0;
#endif
}

#ifdef HAVE_SSL
EXPORTED int imclient_starttls(struct imclient *imclient,
                             char *cert_file,
                             char *key_file,
                             char *CAfile,
                             char *CApath)
{
  int result;
  struct authresult theresult;
  sasl_ssf_t ssf;
  char *auth_id;

  imclient_send(imclient, tlsresult, (void *)&theresult,
                "STARTTLS");

  /* Wait for ready response or command completion */
  imclient->readytag = imclient->gensym;
  while (imclient->readytag) {
    imclient_processoneevent(imclient);
  }

  result=tls_init_clientengine(imclient, 10, cert_file, key_file,
                               CAfile, CApath);
  if (result!=0)
  {
    printf("[ TLS engine failed ]\n");
    return 1;
  } else {
    result=tls_start_clienttls(imclient, &ssf, &auth_id, imclient->fd);

    if (result!=0) {
      printf("[ TLS negotiation did not succeed ]\n");
      return 1;
    }
  }

  /* turn non-blocking i/o back on */


  /* TLS negotiation succeeded */

  imclient->tls_on = 1;

  auth_id=""; /* xxx this really should be peer_CN or
                 issuer_CN but I can't figure out which is
                 which at the moment */

  /* tell SASL about the negotiated layer */
  result=sasl_setprop(imclient->saslconn,
                      SASL_SSF_EXTERNAL,
                      &ssf);
  if (result!=SASL_OK) return 1;
  result=sasl_setprop(imclient->saslconn,
                      SASL_AUTH_EXTERNAL,
                      auth_id);
  if (result!=SASL_OK) return 1;

  return 0;
}
#else
EXPORTED int imclient_starttls(struct imclient *imclient __attribute__((unused)),
                             char *cert_file __attribute__((unused)),
                             char *key_file __attribute__((unused)),
                             char *CAfile __attribute__((unused)),
                             char *CApath __attribute__((unused)))
{
  printf("[ TLS support not present (imclient_starttls) ]\n");
  return 1;
}
#endif /* HAVE_SSL */
