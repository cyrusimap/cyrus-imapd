/* http_client.c - HTTP client-side support functions
 *
 * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
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
 *
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <syslog.h>

#include "http_err.h"
#include "http_client.h"
#include "prot.h"
#include "tok.h"


/* Compare Content-Types */
int is_mediatype(const char *pat, const char *type)
{
    const char *psep = strchr(pat, '/');
    const char *tsep = strchr(type, '/');
    size_t plen;
    size_t tlen;
    int alltypes;

    /* Check type */
    if (!psep || !tsep) return 0;
    plen = psep - pat;
    tlen = tsep - type;

    alltypes = !strncmp(pat, "*", plen);

    if (!alltypes && ((tlen != plen) || strncasecmp(pat, type, tlen))) return 0;

    /* Check subtype */
    pat = ++psep;
    plen = strcspn(pat, "; \r\n\0");
    type = ++tsep;
    tlen = strcspn(type, "; \r\n\0");

    return (!strncmp(pat, "*", plen) ||
	    (!alltypes && (tlen == plen) && !strncasecmp(pat, type, tlen)));
}


/*
 * Parse the framing of a request or response message.
 * Handles chunked, gzip, deflate TE only.
 * Handles close-delimited response bodies (no Content-Length specified) 
 */
int http_parse_framing(hdrcache_t hdrs, struct body_t *body,
		       const char **errstr)
{
    static unsigned max_msgsize = 0;
    const char **hdr;

    if (!max_msgsize) {
	max_msgsize = config_getint(IMAPOPT_MAXMESSAGESIZE);

	/* If max_msgsize is 0, allow any size */
	if (!max_msgsize) max_msgsize = INT_MAX;
    }

    body->framing = FRAMING_LENGTH;
    body->te = TE_NONE;
    body->len = 0;
    body->max = max_msgsize;

    /* Check for Transfer-Encoding */
    if ((hdr = spool_getheader(hdrs, "Transfer-Encoding"))) {
	for (; *hdr; hdr++) {
	    tok_t tok = TOK_INITIALIZER(*hdr, ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
	    char *token;

	    while ((token = tok_next(&tok))) {
		if (body->te & TE_CHUNKED) {
		    /* "chunked" MUST only appear once and MUST be last */
		    break;
		}
		else if (!strcasecmp(token, "chunked")) {
		    body->te |= TE_CHUNKED;
		    body->framing = FRAMING_CHUNKED;
		}
		else if (body->te & ~TE_CHUNKED) {
		    /* can't combine compression codings */
		    break;
		}
#ifdef HAVE_ZLIB
		else if (!strcasecmp(token, "deflate"))
		    body->te = TE_DEFLATE;
		else if (!strcasecmp(token, "gzip") ||
			 !strcasecmp(token, "x-gzip"))
		    body->te = TE_GZIP;
#endif
		else if (!(body->flags & BODY_DISCARD)) {
		    /* unknown/unsupported TE */
		    break;
		}
	    }
	    tok_fini(&tok);
	    if (token) break;  /* error */
	}

	if (*hdr) {
	    body->te = TE_UNKNOWN;
	    *errstr = "Specified Transfer-Encoding not implemented";
	    return HTTP_BAD_MEDIATYPE;
	}

	/* Check if this is a non-chunked response */
	else if (!(body->te & TE_CHUNKED)) {
	    if ((body->flags & BODY_RESPONSE) && (body->flags & BODY_CLOSE)) {
		body->framing = FRAMING_CLOSE;
	    }
	    else {
		body->te = TE_UNKNOWN;
		*errstr = "Final Transfer-Encoding MUST be \"chunked\"";
		return HTTP_BAD_MEDIATYPE;
	    }
	}
    }

    /* Check for Content-Length */
    else if ((hdr = spool_getheader(hdrs, "Content-Length"))) {
	if (hdr[1]) {
	    *errstr = "Multiple Content-Length header fields";
	    return HTTP_BAD_REQUEST;
	}

	body->len = strtoul(hdr[0], NULL, 10);
	if (body->len > max_msgsize) return HTTP_TOO_LARGE;

	body->framing = FRAMING_LENGTH;
    }
	
    /* Check if this is a close-delimited response */
    else if (body->flags & BODY_RESPONSE) {
	if (body->flags & BODY_CLOSE) body->framing = FRAMING_CLOSE;
	else return HTTP_LENGTH_REQUIRED;
    }

    return 0;
}


/*
 * Read the body of a request or response.
 * Handles chunked, gzip, deflate TE only.
 * Handles close-delimited response bodies (no Content-Length specified) 
 * Handles gzip and deflate CE only.
 */
int http_read_body(struct protstream *pin, struct protstream *pout,
		   hdrcache_t hdrs, struct body_t *body, const char **errstr)
{
    char buf[PROT_BUFSIZE];
    unsigned n;
    int r = 0;

    syslog(LOG_DEBUG, "read_body(%#x)", body->flags);

    if (body->flags & BODY_DONE) return 0;
    body->flags |= BODY_DONE;

    if (!(body->flags & BODY_DISCARD)) buf_reset(&body->payload);
    else if (body->flags & BODY_CONTINUE) {
	/* Don't care about the body and client hasn't sent it, we're done */
	return 0;
    }

    if (body->framing == FRAMING_UNKNOWN) {
	/* Get message framing */
	r = http_parse_framing(hdrs, body, errstr);
	if (r) return r;
    }

    if (body->flags & BODY_CONTINUE) {
	/* Tell client to send the body */
	prot_printf(pout, "%s %s\r\n\r\n",
		    HTTP_VERSION, error_message(HTTP_CONTINUE));
	prot_flush(pout);
    }

    /* Read and buffer the body */
    switch (body->framing) {
    case FRAMING_LENGTH:
	/* Read 'len' octets */
	for (; body->len; body->len -= n) {
	    if (body->flags & BODY_DISCARD)
		n = prot_read(pin, buf, MIN(body->len, PROT_BUFSIZE));
	    else
		n = prot_readbuf(pin, &body->payload, body->len);

	    if (!n) {
		syslog(LOG_ERR, "prot_read() error");
		*errstr = "Unable to read body data";
		goto read_failure;
	    }
	}

	break;

    case FRAMING_CHUNKED:
    {
	unsigned last = 0;

	/* Read chunks until last-chunk (zero chunk-size) */
	do {
	    unsigned chunk;

	    /* Read chunk-size */
	    if (!prot_fgets(buf, PROT_BUFSIZE, pin) ||
		sscanf(buf, "%x", &chunk) != 1) {
		*errstr = "Unable to read chunk size";
		goto read_failure;

		/* XXX  Do we need to parse chunk-ext? */
	    }
	    else if (chunk > body->max - body->len) return HTTP_TOO_LARGE;

	    if (!chunk) {
		/* last-chunk */
		last = 1;

		/* Read/parse any trailing headers */
		spool_fill_hdrcache(pin, NULL, hdrs, NULL);
	    }
	    
	    /* Read 'chunk' octets */ 
	    for (; chunk; chunk -= n) {
		if (body->flags & BODY_DISCARD)
		    n = prot_read(pin, buf, MIN(chunk, PROT_BUFSIZE));
		else
		    n = prot_readbuf(pin, &body->payload, chunk);
		
		if (!n) {
		    syslog(LOG_ERR, "prot_read() error");
		    *errstr = "Unable to read chunk data";
		    goto read_failure;
		}
		body->len += n;
	    }

	    /* Read CRLF terminating the chunk/trailer */
	    if (!prot_fgets(buf, sizeof(buf), pin)) {
		*errstr = "Missing CRLF following chunk/trailer";
		goto read_failure;
	    }

	} while (!last);

	body->te &= ~TE_CHUNKED;

	break;
    }

    case FRAMING_CLOSE:
	/* Read until EOF */
	do {
	    if (body->flags & BODY_DISCARD)
		n = prot_read(pin, buf, PROT_BUFSIZE);
	    else
		n = prot_readbuf(pin, &body->payload, PROT_BUFSIZE);

	    if (n > body->max - body->len) return HTTP_TOO_LARGE;
	    body->len += n;

	} while (n);

	if (!pin->eof) goto read_failure;

	break;

    default:
	/* XXX  Should never get here */
	*errstr = "Unknown length of read body data";
	goto read_failure;
    }


    if (!(body->flags & BODY_DISCARD) && buf_len(&body->payload)) {
#ifdef HAVE_ZLIB
	/* Decode the payload, if necessary */
	if (body->te == TE_DEFLATE)
	    r = buf_inflate(&body->payload, DEFLATE_ZLIB);
	else if (body->te == TE_GZIP)
	    r = buf_inflate(&body->payload, DEFLATE_GZIP);

	if (r) {
	    *errstr = "Error decoding payload";
	    return HTTP_BAD_REQUEST;
	}
#endif

	/* Decode the representation, if necessary */
	if (body->flags & BODY_DECODE) {
	    const char **hdr;

	    if (!(hdr = spool_getheader(hdrs, "Content-Encoding"))) {
		/* nothing to see here */
	    }

#ifdef HAVE_ZLIB
	    else if (!strcasecmp(hdr[0], "deflate")) {
		const char **ua = spool_getheader(hdrs, "User-Agent");

		/* Try to detect Microsoft's broken deflate */
		if (ua && strstr(ua[0], "; MSIE "))
		    r = buf_inflate(&body->payload, DEFLATE_RAW);
		else
		    r = buf_inflate(&body->payload, DEFLATE_ZLIB);
	    }
	    else if (!strcasecmp(hdr[0], "gzip") ||
		     !strcasecmp(hdr[0], "x-gzip"))
		r = buf_inflate(&body->payload, DEFLATE_GZIP);
#endif
	    else {
		*errstr = "Specified Content-Encoding not accepted";
		return HTTP_BAD_MEDIATYPE;
	    }

	    if (r) {
		*errstr = "Error decoding content";
		return HTTP_BAD_REQUEST;
	    }
	}
    }

    return 0;

  read_failure:
    if (strcmpsafe(prot_error(pin), PROT_EOF_STRING)) {
	/* client timed out */
	*errstr = prot_error(pin);
	syslog(LOG_WARNING, "%s, closing connection", *errstr);
	return HTTP_TIMEOUT;
    }
    else return HTTP_BAD_REQUEST;
}


/* Read a response from backend */
int http_read_response(struct backend *be, unsigned meth, unsigned *code,
		       const char **statline, hdrcache_t *hdrs,
		       struct body_t *body, const char **errstr)
{
    static char statbuf[2048];
    const char **conn;
    int c = EOF;

    if (statline) *statline = statbuf;
    *errstr = NULL;
    *code = HTTP_BAD_GATEWAY;

    if (*hdrs) spool_free_hdrcache(*hdrs);
    if (!(*hdrs = spool_new_hdrcache())) {
	*errstr = "Unable to create header cache for backend response";
	return HTTP_SERVER_ERROR;
    }
    if (!prot_fgets(statbuf, sizeof(statbuf), be->in) ||
	(sscanf(statbuf, HTTP_VERSION " %u ", code) != 1) ||
	spool_fill_hdrcache(be->in, NULL, *hdrs, NULL)) {
	*errstr = "Unable to read status-line/headers from backend";
	return HTTP_BAD_GATEWAY;
    }
    eatline(be->in, c); /* CRLF separating headers & body */

    /* 1xx (provisional) response - nothing else to do */
    if (*code < 200) return 0;

    /* Final response */
    if (!body) return 0;  /* body will be piped */
    if (!(body->flags & BODY_DISCARD)) buf_reset(&body->payload);

    /* Check connection persistence */
    if (!strncmp(statbuf, "HTTP/1.0 ", 9)) body->flags |= BODY_CLOSE;
    for (conn = spool_getheader(*hdrs, "Connection"); conn && *conn; conn++) {
	tok_t tok =
	    TOK_INITIALIZER(*conn, ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
	char *token;

	while ((token = tok_next(&tok))) {
	    if (!strcasecmp(token, "keep-alive")) body->flags &= ~BODY_CLOSE;
	    else if (!strcasecmp(token, "close")) body->flags |= BODY_CLOSE;
	}
	tok_fini(&tok);
    }

    /* Not expecting a body for 204/304 response or any HEAD response */
    switch (*code){
    case 204: /* No Content */
    case 304: /* Not Modified */
	break;

    default:
	if (meth == METH_HEAD) break;

	else {
	    body->flags |= BODY_RESPONSE;
	    body->framing = FRAMING_UNKNOWN;

	    if (http_read_body(be->in, be->out, *hdrs, body, errstr)) {
		return HTTP_BAD_GATEWAY;
	    }
	}
    }

    return 0;
}
