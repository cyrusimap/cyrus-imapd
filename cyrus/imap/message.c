/* message.c -- Message manipulation/parsing
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <syslog.h>

#include "imap_err.h"
#include "prot.h"
#include "mailbox.h"
#include "parseadd.h"
#include "charset.h"
#include "util.h"
#include "xmalloc.h"

extern PARSED_ADDRESS *AppendAddresses();

/* cyrus.cache file item buffer */
struct ibuf {
    char *start, *end, *last;
};
    
/*
 * Parsed form of a body-part
 */
struct body {
    /* Content-* header information */
    char *type;
    char *subtype;
    struct param *params;
    char *id;
    char *description;
    char *encoding;
    char *md5;

    /* Location/size information */
    long header_offset;
    long header_size;
    long header_lines;
    long content_offset;
    long content_size;
    long content_lines;
    long boundary_size;		/* Size of terminating boundary */
    long boundary_lines;

    int numparts;		/* For multipart types */
    struct body *subpart;	/* For message/rfc822 and multipart types */

    /*
     * Other header information.
     * Only meaningful for body-parts at top level or
     * enclosed in message/rfc-822
     */
    char *date;
    char *subject;
    PARSED_ADDRESS *from;
    PARSED_ADDRESS *sender;
    PARSED_ADDRESS *reply_to;
    PARSED_ADDRESS *to;
    PARSED_ADDRESS *cc;
    PARSED_ADDRESS *bcc;
    char *in_reply_to;
    char *message_id;

    /*
     * Cached headers.  Only filled in at top-level
     */
    struct ibuf cacheheaders;
};

/* List of Content-type parameters */
struct param {
    struct param *next;
    char *attribute;
    char *value;
};

/* List of pending multipart boundaries */
struct boundary {
    char **id;
    int count;
    int alloc;
};

/* (draft standard) MIME tspecials */
#define TSPECIALS "()<>@,;:\\\"/[]?="

/* Default MIME Content-type */
#define DEFAULT_CONTENT_TYPE "TEXT/PLAIN; CHARSET=us-ascii"

static int message_parse_body(), message_parse_headers();
static int message_parse_address(), message_parse_encoding();
static int message_parse_string(), message_parse_header();
static int message_parse_type(), message_parse_params();
static int message_parse_rfc822space(), message_parse_multipart();
static int message_parse_content();
static time_t message_parse_date();
static PendingBoundary();
static int message_write_cache(), message_write_envelope();
static int message_write_body(), message_write_address();
static int message_write_singleaddress(), message_write_nstring();
static int message_write_number(), message_write_section();
static int message_write_charset(), message_write_bit32();
static int message_write_searchaddr(), message_write_singlesearchaddr();
static int message_ibuf_init(), message_ibuf_ensure();
static int message_ibuf_write(), message_ibuf_free(), message_free_body();

/*
 * Copy a message from 'from' to 'to', converting bare LF characters to CRLF.
 */
int
message_copy_byline(from, to)
struct protstream *from;
FILE *to;
{
    char buf[4096], *p;

    while (prot_fgets(buf, sizeof(buf)-1, from)) {
	p = buf + strlen(buf) - 1;
	if (*p == '\n') {
	    if (p == buf || p[-1] != '\r') {
		p[0] = '\r';
		p[1] = '\n';
		p[2] = '\0';
	    }
	}
	else if (*p == '\r') {
	    /*
	     * We were unlucky enough to get a CR just before we ran
	     * out of buffer--put it back.
	     */
	    prot_ungetc('\r', from);
	    *p = '\0';
	}
	fputs(buf, to);
    }
    fflush(to);
    if (p = prot_error(from)) {
	syslog(LOG_ERR, "IOERROR: reading message: %s", p);
	return IMAP_IOERROR;
    }
    if (ferror(to) || fsync(fileno(to))) {
	syslog(LOG_ERR, "IOERROR: writing message: %m");
	return IMAP_IOERROR;
    }
    return 0;
}

/*
 * Copy a message of 'size' bytes from 'from' to 'to',
 * ensuring minimal RFC-822 compliance.
 */
int
message_copy_strict(from, to, size)
struct protstream *from;
FILE *to;
int size;
{
    char buf[4096+1];
    unsigned char *p;
    int r = 0;
    int n;
    int sawcr = 0, sawnl;

    while (size) {
	n = prot_read(from, buf, size > 4096 ? 4096 : size);
	if (!n) {
	    syslog(LOG_ERR, "IOERROR: reading message: %m");
	    return IMAP_IOERROR;
	}

	buf[n] = '\0';
	if (n != strlen(buf)) r = IMAP_MESSAGE_CONTAINSNULL;

	size -= n;
	if (r) continue;

	for (p = (unsigned char *)buf; *p; p++) {
	    if (*p == '\n') {
		if (!sawcr) r = IMAP_MESSAGE_CONTAINSNL;
		sawcr = 0;
	    }
	    else if (*p == '\r') {
		sawcr = 1;
	    }
	    else sawcr = 0;
	}

	fwrite(buf, 1, n, to);
    }

    if (r) return r;
    fflush(to);
    if (ferror(to) || fsync(fileno(to))) {
	syslog(LOG_ERR, "IOERROR: writing message: %m");
	return IMAP_IOERROR;
    }
    rewind(to);

    /* Go back and check headers */
    sawnl = 1;
    for (;;) {
	if (!fgets(buf, sizeof(buf), to)) return IMAP_MESSAGE_NOBLANKLINE;

	/* End of header section */
	if (sawnl && buf[0] == '\r') return 0;

	/* Check for valid header name */
	if (sawnl && buf[0] != ' ' && buf[0] != '\t') {
	    if (buf[0] == ':') return IMAP_MESSAGE_BADHEADER;
	    for (p = (unsigned char *)buf; *p != ':'; p++) {
		if (*p <= ' ') return IMAP_MESSAGE_BADHEADER;
	    }
	}

	/* Check for non-ASCII character */ 
	for (p = (unsigned char *)buf; *p; p++) {
	    if (*p >= 0x80) return IMAP_MESSAGE_CONTAINS8BIT;
	}

	sawnl = (p[-1] == '\n');
    }
}

/*
 * Parse the message 'infile' in 'mailbox'.  Appends the message's
 * cache information to the mailbox's cache file and fills in appropriate
 * information in the index record pointed to by 'message_index'.
 */
message_parse(infile, mailbox, message_index)
FILE *infile;
struct mailbox *mailbox;
struct index_record *message_index;
{
    struct body body;

    rewind(infile);
    message_parse_body(infile, mailbox->format, &body,
		       DEFAULT_CONTENT_TYPE, (struct boundary *)0);
    
    message_index->sentdate = message_parse_date(body.date);
    message_index->size = body.header_size + body.content_size;
    message_index->header_size = body.header_size;
    message_index->content_offset = body.content_offset;

    message_index->cache_offset = ftell(mailbox->cache);

    message_write_cache(mailbox->cache, &body);
    message_free_body(&body);

    if (ferror(mailbox->cache)) {
	syslog(LOG_ERR, "IOERROR: appending cache for %s: %m", mailbox->name);
	return IMAP_IOERROR;
    }

    return 0;
}

/*
 * Parse a body-part
 */
static 
message_parse_body(infile, format, body, defaultContentType, boundaries)
FILE *infile;
int format;
struct body *body;
char *defaultContentType;
struct boundary *boundaries;
{
    struct boundary newboundaries;
    static struct body zerobody;
    int sawboundary;

    *body = zerobody;
    newboundaries.id = 0;

    /* No passed-in boundary structure, create a new, empty one */
    if (!boundaries) {
	boundaries = &newboundaries;
	boundaries->alloc = boundaries->count = 0;
	/* We're at top-level--set up to store cached headers */
	message_ibuf_init(&body->cacheheaders);
    }

    sawboundary = message_parse_headers(infile, format, body,
					defaultContentType, boundaries);

    /* Recurse according to type */
    if (strcmp(body->type, "MULTIPART") == 0) {
	if (!sawboundary)
	  message_parse_multipart(infile, format, body, boundaries);
    }
    else if (strcmp(body->type, "MESSAGE") == 0 &&
	strcmp(body->subtype, "RFC822") == 0) {
	body->subpart = (struct body *)xmalloc(sizeof(struct body));

	if (sawboundary) {
	    *body->subpart = zerobody;
	    message_parse_type(DEFAULT_CONTENT_TYPE, body->subpart);
	}
	else {
	    message_parse_body(infile, format, body->subpart,
			       DEFAULT_CONTENT_TYPE, boundaries);
	}

	/* Calculate our size/lines information */
	body->content_size = body->subpart->header_size +
	  body->subpart->content_size;
	body->content_lines = body->subpart->header_lines +
	  body->subpart->content_lines;

	/* Move any enclosing boundary information up to our level */
	body->boundary_size = body->subpart->boundary_size;
	body->boundary_lines = body->subpart->boundary_lines;
    }
    else {
	if (!sawboundary)
	  message_parse_content(infile, format, body, boundaries);
    }

    /* Free up boundary storage if necessary */
    if (newboundaries.id) free(newboundaries.id);
}

/*
 * Parse the headers of a body-part
 */
#define HEADGROWSIZE 1000
static int
message_parse_headers(infile, format, body, defaultContentType, boundaries)
FILE *infile;
int format;
struct body *body;
char *defaultContentType;
struct boundary *boundaries;
{
    static int alloced = 0;
    static char *headers;
    int left, len;
    char *next;
    int sawboundary = 0;

    body->header_offset = ftell(infile);

    if (!alloced) {
	headers = xmalloc(alloced = HEADGROWSIZE);
    }

    next = headers;
    *next++ = '\n';		/* Leading newline to prime the pump */
    left = alloced - 3;		/* Allow for leading newline, added CR */
				/*  and trailing NUL */

    /* Slurp up all of the headers into 'headers' */
    while (fgets(next, left, infile) &&
	   (next[-1] != '\n' ||
	    (format == MAILBOX_FORMAT_NETNEWS ?
	     (*next != '\n') : (*next != '\r' || next[1] != '\n')))) {

	if (next[-1] == '\n' && *next == '-' &&
	    PendingBoundary(next, boundaries->id, &boundaries->count)) {
	    body->boundary_size = strlen(next)+(format==MAILBOX_FORMAT_NETNEWS);
	    body->boundary_lines++;
	    if (next - 1 > headers) {
		body->boundary_size += 2;
		body->boundary_lines++;
		next[-2] = '\0';
	    }
	    else {
		*next = '\0';
	    }
	    sawboundary = 1;
	    break;
	}

	len = strlen(next);
	left -= len;
	next += len;

	/* If reading netnews format, convert LF to CRLF */
	if (format == MAILBOX_FORMAT_NETNEWS && next[-1] == '\n') {
	    next[-1] = '\r';
	    *next++ = '\n';
	    *next = '\0';
	    left--;
	}

	/* Allocate more header space if necessary */
	if (left < 100) {
	    len = next - headers;
	    alloced += HEADGROWSIZE;
	    left += HEADGROWSIZE;
	    headers = xrealloc(headers, alloced);
	    next = headers + len;
	}
    }

    /* If reading netnews format, convert terminating LF to CRLF */
    if (format == MAILBOX_FORMAT_NETNEWS) {
	next = headers + strlen(headers);
	next[-1] = '\r';
	*next++ = '\n';
	*next = '\0';
    }
    
    body->content_offset = ftell(infile);
    body->header_size = strlen(headers+1);

    /* Scan over the slurped-up headers for interesting header information */
    body->header_lines = -1;	/* Correct for leading newline */
    for (next = headers; *next; next++) {
	if (*next == '\n') {
	    body->header_lines++;
	    switch (next[1]) {
	    case 'b':
	    case 'B':
		if (!strncasecmp(next+2, "cc:", 3)) {
		    message_parse_address(next+5, &body->bcc);
		}
		break;
		
	    case 'c':
	    case 'C':
		if (!strncasecmp(next+2, "c:", 2)) {
		    message_parse_address(next+4, &body->cc);
		}
		if (!strncasecmp(next+2, "ontent-", 7)) {
		    switch (next[9]) {
		    case 'd':
		    case 'D':
			if (!strncasecmp(next+10, "escription:", 11)) {
			    message_parse_string(next+21, &body->description);
			}
			break;

		    case 'i':
		    case 'I':
			if (!strncasecmp(next+10, "d:", 2)) {
			    message_parse_string(next+12, &body->id);
			}
			break;

		    case 'm':
		    case 'M':
			if (!strncasecmp(next+10, "d5:", 3)) {
			    message_parse_string(next+13, &body->md5);
			}
			break;

		    case 't':
		    case 'T':
			if (!strncasecmp(next+10, "ransfer-encoding:", 17)) {
			    message_parse_encoding(next+27, &body->encoding);
			}
			else if (!strncasecmp(next+10, "ype:", 4)) {
			    message_parse_type(next+14, body);
			}
			break;
		    }
		}
		break;

	    case 'd':
	    case 'D':
		if (!strncasecmp(next+2, "ate:", 4)) {
		    message_parse_string(next+6, &body->date);
		}
		break;

	    case 'f':
	    case 'F':
		if (!strncasecmp(next+2, "rom:", 4)) {
		    message_parse_address(next+6, &body->from);
		}
		break;

	    case 'i':
	    case 'I':
		if (!strncasecmp(next+2, "n-reply-to:", 11)) {
		    message_parse_string(next+13, &body->in_reply_to);
		}
		break;

	    case 'm':
	    case 'M':
		if (!strncasecmp(next+2, "essage-id:", 10)) {
		    message_parse_string(next+12, &body->message_id);
		}
		break;

	    case 'p':
	    case 'P':
		if (body->cacheheaders.start &&
		    !strncasecmp(next+2, "riority:", 8)) {
		    message_parse_header(next+1, &body->cacheheaders);
		}
		break;

	    case 'r':
	    case 'R':
		if (!strncasecmp(next+2, "eply-to:", 8)) {
		    message_parse_address(next+10, &body->reply_to);
		}
		else if (body->cacheheaders.start &&
			 !strncasecmp(next+2, "eferences:", 10)) {
		    message_parse_header(next+1, &body->cacheheaders);
		}
		break;

	    case 's':
	    case 'S':
		if (!strncasecmp(next+2, "ubject:", 7)) {
		    message_parse_string(next+9, &body->subject);
		}
		if (!strncasecmp(next+2, "ender:", 6)) {
		    message_parse_address(next+8, &body->sender);
		}
		break;

	    case 't':
	    case 'T':
		if (!strncasecmp(next+2, "o:", 2)) {
		    message_parse_address(next+4, &body->to);
		}
		break;
	    }
	}
    }

    /* If didn't find Content-Type: header, use the passed-in default type */
    if (!body->type) {
	message_parse_type(defaultContentType, body);
    }
    return sawboundary;
}

/*
 * Parse a list of RFC-822 addresses from a header, appending them
 * to the address list pointed to by 'addrp'.
 */
static 
message_parse_address(hdr, addrp)
char *hdr;
PARSED_ADDRESS **addrp;
{
    char *hdrend, hdrendchar;
    PARSED_ADDRESS *hdrlist;
    int r;

    /* Find end of header */
    hdrend = hdr;
    do {
	hdrend = strchr(hdrend+1, '\n');
    } while (hdrend && (hdrend[1] == ' ' || hdrend[1] == '\t'));

    /* Put a NUL character at the end of header */
    if (hdrend) {
	if (hdrend > hdr && hdrend[-1] == '\r') hdrend--;
	hdrendchar = *hdrend;
	*hdrend = '\0';
    }

    r = ParseAddressList(hdr, &hdrlist);

    /* Put character at end of header back */
    if (hdrend) *hdrend = hdrendchar;

    if (r) return;

    *addrp = AppendAddresses(*addrp, hdrlist);
}

/*
 * Parse a Content-Transfer-Encoding from a header.
 */
static 
message_parse_encoding(hdr, hdrp)
char *hdr;
char **hdrp;
{
    int len;
    char *p;

    /* Ignore if we already saw one of these headers */
    if (*hdrp) return;

    /* Skip leading whitespace, ignore header if blank */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Find end of encoding token */
    for (p = hdr; *p && !isspace(*p) && *p != '('; p++) {
	if (*p < ' ' || strchr(TSPECIALS, *p)) return;
    }
    len = p - hdr;

    /* Skip trailing whitespace, ignore header if trailing garbage */
    message_parse_rfc822space(&p);
    if (p) return;

    /* Save encoding token */
    *hdrp = xmalloc(len + 1);
    strncpy(*hdrp, hdr, len);
    (*hdrp)[len] = '\0';
    for (p = *hdrp; *p; p++) {
	if (islower(*p)) *p = toupper(*p);
    }
}
	
/*
 * Parse an uninterpreted header
 */
static 
message_parse_string(hdr, hdrp)
char *hdr;
char **hdrp;
{
    int len;
    char *hdrend;

    /* Ignore if we already saw one of these headers */
    if (*hdrp) return;

    /* Skip initial whitespace */
    while (*hdr == ' ' || *hdr == '\t') hdr++;

    /* Find end of header */
    hdrend = hdr;
    do {
	hdrend = strchr(hdrend+1, '\n');
    } while (hdrend && (hdrend[1] == ' ' || hdrend[1] == '\t'));
    if (hdrend) {
	if (hdrend > hdr && hdrend[-1] == '\r') hdrend--;
    }
    else {
	hdrend = hdr + strlen(hdr);
    }

    /* Save header value */
    len = hdrend - hdr;
    *hdrp = xmalloc(len + 1);
    strncpy(*hdrp, hdr, len);
    (*hdrp)[len] = '\0';
}

/*
 * Cache a header
 */
static 
message_parse_header(hdr, ibuf)
char *hdr;
struct ibuf *ibuf;
{
    int len;
    char *hdrend;

    /* Find end of header */
    hdrend = hdr;
    do {
	hdrend = strchr(hdrend+1, '\n');
    } while (hdrend && (hdrend[1] == ' ' || hdrend[1] == '\t'));
    if (hdrend) {
	if (hdrend > hdr && hdrend[-1] == '\r') hdrend--;
    }
    else {
	hdrend = hdr + strlen(hdr);
    }

    /* Save header value */
    len = hdrend - hdr;
    message_ibuf_ensure(ibuf, len+2);
    strncpy(ibuf->end, hdr, len);
    ibuf->end += len;
    *(ibuf->end)++ = '\r';
    *(ibuf->end)++ = '\n';
}

/*
 * Parse a Content-Type from a header.
 */
static 
message_parse_type(hdr, body)	    
char *hdr;
struct body *body;
{
    char *type;
    int typelen;
    char *subtype;
    int subtypelen;
    char *p;

    /* Ignore if we already saw one of these headers */
    if (body->type) return;

    /* Skip leading whitespace, ignore header if blank */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Find end of type token */
    type = hdr;
    for (; *hdr && !isspace(*hdr) && *hdr != '/' && *hdr != '('; hdr++) {
	if (*hdr < ' ' || strchr(TSPECIALS, *hdr)) return;
    }
    typelen = hdr - type;

    /* Skip whitespace after type */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Ignore header if no '/' character */
    if (*hdr++ != '/') return;

    /* Skip whitespace before subtype, ignore header if no subtype */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Find end of subtype token */
    subtype = hdr;
    for (; *hdr && !isspace(*hdr) && *hdr != ';' && *hdr != '('; hdr++) {
	if (*hdr < ' ' || strchr(TSPECIALS, *hdr)) return;
    }
    subtypelen = hdr - subtype;

    /* Skip whitespace after subtype */
    message_parse_rfc822space(&hdr);

    /* Ignore header if not at end of header or parameter delimiter */
    if (hdr && *hdr != ';') return;

    /* Save content type & subtype */
    body->type = xmalloc(typelen + 1);
    strncpy(body->type, type, typelen);
    body->type[typelen] = '\0';
    for (p = body->type; *p; p++) {
	if (islower(*p)) *p = toupper(*p);
    }
    body->subtype = xmalloc(subtypelen + 1);
    strncpy(body->subtype, subtype, subtypelen);
    body->subtype[subtypelen] = '\0';
    for (p = body->subtype; *p; p++) {
	if (islower(*p)) *p = toupper(*p);
    }

    /* Parse parameter list */
    if (hdr) {
	message_parse_params(hdr+1, &body->params);
    }
}

/*
 * Parse a parameter list from a header
 */
static 
message_parse_params(hdr, paramp)
char *hdr;
struct param **paramp;
{
    struct param *param;
    static struct param zeroparam;
    char *attribute;
    int attributelen;
    char *value;
    int valuelen;
    char *p;

    for (;;) {
	/* Skip over leading whitespace */
	message_parse_rfc822space(&hdr);
	if (!hdr) return;

	/* Find end of attribute */
	attribute = hdr;
	for (; *hdr && !isspace(*hdr) && *hdr != '=' && *hdr != '('; hdr++) {
	    if (*hdr < ' ' || strchr(TSPECIALS, *hdr)) return;
	}
	attributelen = hdr - attribute;

	/* Skip whitespace after attribute */
	message_parse_rfc822space(&hdr);
	if (!hdr) return;

	/* Ignore param if no '=' character */
	if (*hdr++ != '=') return;

	/* Skip whitespace before value */
	message_parse_rfc822space(&hdr);
	if (!hdr) return;

	/* Find end of value */
	value = hdr;
	if (*hdr == '\"') {
	    hdr++;
	    while (*hdr && *hdr != '\"') {
		if (*hdr == '\\') {
		    hdr++;
		    if (!*hdr) return;
		}
		if (*hdr == '\r') {
		    return;
		}
		hdr++;
	    }
	    if (!*hdr++) return;
	}
	else {
	    for (; *hdr && !isspace(*hdr) && *hdr != ';' && *hdr != '('; hdr++) {
		if (*hdr < ' ' || strchr(TSPECIALS, *hdr)) return;
	    }
	}
	valuelen = hdr - value;

	/* Skip whitespace after value */
	message_parse_rfc822space(&hdr);

	/* Ignore parameter if not at end of header or parameter delimiter */
	if (hdr && *hdr++ != ';') return;
		  
	/* Save attribute/value pair */
	*paramp = param = (struct param *)xmalloc(sizeof(struct param));
	*param = zeroparam;
	param->attribute = xmalloc(attributelen + 1);
	strncpy(param->attribute, attribute, attributelen);
	param->attribute[attributelen] = '\0';
	for (p = param->attribute; *p; p++) {
	    if (islower(*p)) *p = toupper(*p);
	}
	param->value = xmalloc(valuelen + 1);
	if (*value == '\"') {
	    p = param->value;
	    value++;
	    while (*value != '\"') {
		if (*value == '\\') value++;
		*p++ = *value++;
	    }
	    *p = '\0';
	}
	else {
	    strncpy(param->value, value, valuelen);
	    param->value[valuelen] = '\0';
	}

	/* Get ready to parse the next parameter */
	paramp = &param->next;
    }
}

/*
 * Skip over RFC-822 whitespace and comments
 */
static 
message_parse_rfc822space(s)
char **s;
{
    char *p = *s;
    int commentlevel = 0;

    if (!p) return;
    while (*p && (isspace(*p) || *p == '(')) {
	if (*p == '\n') {
	    p++;
	    if (*p != ' ' && *p != '\t') {
		*s = 0;
		return;
	    }
	}
	else if (*p == '(') {
	    p++;
	    commentlevel++;
	    while (commentlevel) {
		switch (*p) {
		case '\n':
		    p++;
		    if (*p == ' ' || *p == '\t') break;
		    /* FALL THROUGH */
		case '\0':
		    *s = 0;
		    return;
		    
		case '\\':
		    p++;
		    break;

		case '(':
		    commentlevel++;
		    break;

		case ')':
		    commentlevel--;
		    break;
		}
		p++;
	    }
	}
	else p++;
    }
    if (*p == 0) {
	*s = 0;
    }
    else {
	*s = p;
    }
}

/*
 * Parse the content of a MIME multipart body-part
 */
static 
message_parse_multipart(infile, format, body, boundaries)
FILE *infile;
int format;
struct body *body;
struct boundary *boundaries;
{
    struct body preamble, epilogue;
    static struct body zerobody;
    struct param *boundary;
    char *defaultContentType = DEFAULT_CONTENT_TYPE;
    int i, depth;

    preamble = epilogue = zerobody;
    if (strcmp(body->subtype, "DIGEST") == 0) {
	defaultContentType = "MESSAGE/RFC822";
    }

    /* Find boundary id */
    boundary = body->params;
    while(boundary && strcmp(boundary->attribute, "BOUNDARY") != 0) {
	boundary = boundary->next;
    }
    
    if (!boundary) {
	/* Invalid MIME--treat as zero-part multipart */
	message_parse_content(infile, format, body, boundaries);
	return;
    }

    /* Expand boundaries array if necessary */
    if (boundaries->count == boundaries->alloc) {
	boundaries->alloc += 20;
	boundaries->id = (char **)xrealloc((char *)boundaries->id,
					   boundaries->alloc * sizeof(char *));
    }
    
    /* Add the new boundary id */
    boundaries->id[boundaries->count++] = boundary->value;
    depth = boundaries->count;

    /* Parse preamble */
    message_parse_content(infile, format, &preamble, boundaries);

    /* Parse the component body-parts */
    while (boundaries->count == depth) {
	body->subpart = (struct body *)xrealloc((char *)body->subpart,
				 (body->numparts+1)*sizeof(struct body));
	message_parse_body(infile, format, &body->subpart[body->numparts++],
			   defaultContentType, boundaries);
    }

    if (boundaries->count == depth-1) {
	/* Parse epilogue */
	message_parse_content(infile, format, &epilogue, boundaries);
    }
    else if (body->numparts) {
	/*
	 * We hit the boundary of an enclosing multipart while parsing
	 * a component body-part.  Move the enclosing boundary information
	 * up to our level.
	 */
	body->boundary_size = body->subpart[body->numparts-1].boundary_size;
	body->boundary_lines = body->subpart[body->numparts-1].boundary_lines;
	body->subpart[body->numparts-1].boundary_size = 0;
	body->subpart[body->numparts-1].boundary_lines = 0;
    }
    else {
	/*
	 * We hit the boundary of an enclosing multipart while parsing
	 * the preamble.  Move the enclosing boundary information
	 * up to our level.
	 */
	body->boundary_size = preamble.boundary_size;
	body->boundary_lines = preamble.boundary_lines;
	preamble.boundary_size = 0;
	preamble.boundary_lines = 0;
    }

    /*
     * Calculate our size/lines information
     */
    body->content_size = preamble.content_size + preamble.boundary_size;
    body->content_lines = preamble.content_lines + preamble.boundary_lines;
    for (i=0; i< body->numparts; i++) {
	body->content_size += body->subpart[i].header_size +
	  body->subpart[i].content_size +
	  body->subpart[i].boundary_size;
	body->content_lines += body->subpart[i].header_lines +
	  body->subpart[i].content_lines +
	  body->subpart[i].boundary_lines;
    }
    body->content_size += epilogue.content_size;
    body->content_lines += epilogue.content_lines;

    /*
     * Move any enclosing boundary information up to our level.
     */
    body->boundary_size += epilogue.boundary_size;
    body->boundary_lines += epilogue.boundary_lines;
}

/*
 * Parse the content of a generic body-part
 */
static 
message_parse_content(infile, format, body, boundaries)
FILE *infile;
int format;
struct body *body;
struct boundary *boundaries;
{
    char buf[1024];
    int len, line_boundary = 1;

    while (fgets(buf, sizeof(buf), infile)) {
	if (line_boundary && *buf == '-' &&
	    PendingBoundary(buf, boundaries->id, &boundaries->count)) {
	    body->boundary_size = strlen(buf)+(format==MAILBOX_FORMAT_NETNEWS);
	    body->boundary_lines++;
	    if (body->content_lines) {
		body->content_lines--;
		body->boundary_lines++;
	    }
	    if (body->content_size) {
		body->content_size -= 2;
		body->boundary_size += 2;
	    }
	    return;
	}

	len = strlen(buf);
	body->content_size += len;

	if (line_boundary = (buf[len-1] == '\n')) {
	    body->content_lines++;
	    if (format == MAILBOX_FORMAT_NETNEWS) body->content_size++;
	}
    }
}

/*
 * Parse a RFC-822 date from a header.
 * Only parses to day granularity--ignores the time of day.
 */
static time_t
message_parse_date(hdr)
char *hdr;
{
    struct tm tm;
    static struct tm zerotm;
    char month[4];
    static char *monthname[] = {
	"jan", "feb", "mar", "apr", "may", "jun",
	"jul", "aug", "sep", "oct", "nov", "dec"
    };

    if (!hdr) goto baddate;

    tm = zerotm;

    message_parse_rfc822space(&hdr);

    if (isalpha(*hdr)) {
	/* Day name -- skip over it */
	hdr++;
	if (!isalpha(*hdr)) goto baddate;
	hdr++;
	if (!isalpha(*hdr)) goto baddate;
	hdr++;
	message_parse_rfc822space(&hdr);
	if (*hdr++ != ',') goto baddate;
	message_parse_rfc822space(&hdr);
    }

    if (!isdigit(*hdr)) goto baddate;
    tm.tm_mday = *hdr++ - '0';
    if (isdigit(*hdr)) {
	tm.tm_mday = tm.tm_mday*10 + *hdr++ - '0';
    }
    
    /* Parse month name */
    message_parse_rfc822space(&hdr);
    month[0] = *hdr++;
    if (!isalpha(month[0])) goto baddate;
    month[1] = *hdr++;
    if (!isalpha(month[1])) goto baddate;
    month[2] = *hdr++;
    if (!isalpha(month[2])) goto baddate;
    month[3] = '\0';
    lcase(month);
    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }
    if (tm.tm_mon == 12) goto baddate;
    
    /* Parse year */
    message_parse_rfc822space(&hdr);
    if (!isdigit(*hdr)) goto baddate;
    tm.tm_year = *hdr++ - '0';
    if (!isdigit(*hdr)) goto baddate;
    tm.tm_year = tm.tm_year * 10 + *hdr++ - '0';
    if (isdigit(*hdr)) {
	if (tm.tm_year < 19) goto baddate;
	tm.tm_year -= 19;
	tm.tm_year = tm.tm_year * 10 + *hdr++ - '0';
	if (!isdigit(*hdr)) goto baddate;
	tm.tm_year = tm.tm_year * 10 + *hdr++ - '0';
    }

    tm.tm_isdst = -1;
    tm.tm_hour = 12;

    return mktime(&tm);

 baddate:
    return time(0);
}

/*
 * Return nonzero if s is an enclosing boundary delimiter.
 * If we hit a terminating boundary, the integer pointed to by
 * 'BoundaryCt' is modified appropriately.
 */
static PendingBoundary(s, Boundaries, BoundaryCt)
char *s;
char **Boundaries;
int *BoundaryCt;
{
    int i, len;

    if (s[0] != '-' || s[1] != '-') return(0);
    s+=2;

    for (i=0; i < *BoundaryCt; ++i) {
	len = strlen(Boundaries[i]);
        if (!strncmp(s, Boundaries[i], len)) {
            if (s[len] == '-' && s[len+1] == '-') *BoundaryCt = i;
            return(1);
        }
    }
    return(0);
}

/*
 * Write the cache information for the message parsed to 'body'
 * to 'outfile'.
 */
static int message_write_cache(outfile, body)
FILE *outfile;
struct body *body;
{
    struct ibuf section, envelope, bodystructure, oldbody;
    struct ibuf from, to, cc, bcc, subject;
    struct body toplevel;

    toplevel.type = "MESSAGE";
    toplevel.subtype = "RFC822";
    toplevel.subpart = body;

    message_ibuf_init(&envelope);
    message_write_envelope(&envelope, body);

    message_ibuf_init(&bodystructure);
    message_write_body(&bodystructure, body, 1);

    message_ibuf_init(&oldbody);
    message_write_body(&oldbody, body, 0);

    message_ibuf_init(&section);
    message_write_section(&section, &toplevel);

    message_ibuf_init(&from);
    message_write_searchaddr(&from, body->from);

    message_ibuf_init(&to);
    message_write_searchaddr(&to, body->to);

    message_ibuf_init(&cc);
    message_write_searchaddr(&cc, body->cc);

    message_ibuf_init(&bcc);
    message_write_searchaddr(&bcc, body->bcc);

    message_ibuf_init(&subject);
    message_write_nstring(&subject, charset_decode1522(body->subject));


    message_ibuf_write(outfile, &envelope);
    message_ibuf_write(outfile, &bodystructure);
    message_ibuf_write(outfile, &oldbody);
    message_ibuf_write(outfile, &section);
    message_ibuf_write(outfile, &body->cacheheaders);
    message_ibuf_write(outfile, &from);
    message_ibuf_write(outfile, &to);
    message_ibuf_write(outfile, &cc);
    message_ibuf_write(outfile, &bcc);
    message_ibuf_write(outfile, &subject);

    message_ibuf_free(&envelope);
    message_ibuf_free(&bodystructure);
    message_ibuf_free(&oldbody);
    message_ibuf_free(&section);
    message_ibuf_free(&from);
    message_ibuf_free(&to);
    message_ibuf_free(&cc);
    message_ibuf_free(&bcc);
    message_ibuf_free(&subject);
}

/* Append character 'c' to 'ibuf' */
#define PUTIBUF(ibuf,c) (((ibuf)->end<(ibuf)->last || message_ibuf_ensure((ibuf),1)),(*((ibuf)->end)++ = (c)))

/*
 * Write the IMAP envelope for 'body' to 'ibuf'
 */
static 
message_write_envelope(ibuf, body)
struct ibuf *ibuf;
struct body *body;
{
    PUTIBUF(ibuf, '(');
    message_write_nstring(ibuf, body->date);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, body->subject);
    PUTIBUF(ibuf, ' ');
    message_write_address(ibuf, body->from);
    PUTIBUF(ibuf, ' ');
    message_write_address(ibuf, body->sender ? body->sender : body->from);
    PUTIBUF(ibuf, ' ');
    message_write_address(ibuf, body->reply_to ? body->reply_to : body->from);
    PUTIBUF(ibuf, ' ');
    message_write_address(ibuf, body->to);
    PUTIBUF(ibuf, ' ');
    message_write_address(ibuf, body->cc);
    PUTIBUF(ibuf, ' ');
    message_write_address(ibuf, body->bcc);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, body->in_reply_to);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, body->message_id);
    PUTIBUF(ibuf, ')');
}

/*
 * Write the BODY (if 'newformat' is zero) or BODYSTRUCTURE
 * (if 'newformat' is nonzero) for 'body' to 'ibuf'.
 */
static 
message_write_body(ibuf, body, newformat)
struct ibuf *ibuf;
struct body *body;
int newformat;
{
    struct param *param;

    if (strcmp(body->type, "MULTIPART") == 0) {
	int i;

	/* 0-part multiparts are illegal--convert to 0-len text parts */
	if (body->numparts == 0) {
	    static struct body zerotextbody;

	    if (!zerotextbody.type) {
		message_parse_type(DEFAULT_CONTENT_TYPE, &zerotextbody);
	    }
	    message_write_body(ibuf, &zerotextbody, newformat);
	    return;
	}

	/* Multipart types get a body_multipart */
	PUTIBUF(ibuf, '(');
	for (i = 0; i < body->numparts; i++) {
	    message_write_body(ibuf, &body->subpart[i], newformat);
	}
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, body->subtype);

	if (newformat) {
	    PUTIBUF(ibuf, ' ');
	    if (param = body->params) {
		PUTIBUF(ibuf, '(');
		while (param) {
		    message_write_nstring(ibuf, param->attribute);
		    PUTIBUF(ibuf, ' ');
		    message_write_nstring(ibuf, param->value);
		    if (param = param->next) {
			PUTIBUF(ibuf, ' ');
		    }
		}
		PUTIBUF(ibuf, ')');
	    }
	    else message_write_nstring(ibuf, (char *)0);
	}

	PUTIBUF(ibuf, ')');
	return;
    }

    PUTIBUF(ibuf, '(');
    message_write_nstring(ibuf, body->type);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, body->subtype);
    PUTIBUF(ibuf, ' ');

    if (param = body->params) {
	PUTIBUF(ibuf, '(');
	while (param) {
	    message_write_nstring(ibuf, param->attribute);
	    PUTIBUF(ibuf, ' ');
	    message_write_nstring(ibuf, param->value);
	    if (param = param->next) {
		PUTIBUF(ibuf, ' ');
	    }
	}
	PUTIBUF(ibuf, ')');
    }
    else message_write_nstring(ibuf, (char *)0);
    PUTIBUF(ibuf, ' ');

    message_write_nstring(ibuf, body->id);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, body->description);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, body->encoding ? body->encoding : "7BIT");
    PUTIBUF(ibuf, ' ');
    message_write_number(ibuf, body->content_size);

    if (strcmp(body->type, "TEXT") == 0) {
	/* Text types get a line count */
	PUTIBUF(ibuf, ' ');
	message_write_number(ibuf, body->content_lines);
    }
    else if (strcmp(body->type, "MESSAGE") == 0
	     && strcmp(body->subtype, "RFC822") == 0) {
	/* Message/rfc822 gets a body_msg */
	PUTIBUF(ibuf, ' ');
	message_write_envelope(ibuf, body->subpart);
	PUTIBUF(ibuf, ' ');
	message_write_body(ibuf, body->subpart, newformat);
	PUTIBUF(ibuf, ' ');
	message_write_number(ibuf, body->content_lines);
    }

    if (newformat) {
	/* Add additional fields for BODYSTRUCTURE */
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, body->md5);
    }

    PUTIBUF(ibuf, ')');
}

/*
 * Write the address list 'addrlist' to 'ibuf'
 */
static 
message_write_address(ibuf, addrlist)
struct ibuf *ibuf;
PARSED_ADDRESS *addrlist;
{
    int len = 0;

    /* If no addresses, write out NIL */
    if (!addrlist) {
	message_write_nstring(ibuf, (char *)0);
	return;
    }
    FOR_ALL_ADDRESSES(thisaddr, addrlist, len++;);
    if (!len) {
	message_write_nstring(ibuf, (char *)0);
	return;
    }	

    PUTIBUF(ibuf, '(');
    FOR_ALL_ADDRESSES(thisaddr, addrlist, message_write_singleaddress(ibuf, thisaddr););
    PUTIBUF(ibuf, ')');
}

/*
 * Write the single address 'addr' to 'ibuf'.
 */
static 
message_write_singleaddress(ibuf, addr)
struct ibuf *ibuf;
PARSED_ADDRESS *addr;
{
    int nhosts=0, adllen=0;
    char *name = 0, *adl = 0;
    static char myhostname[128];

    /* Recursively handle RFC-822 group addresses */
    if (addr->Kind == GROUP_ADDRESS) {
	PUTIBUF(ibuf, '(');
	message_write_nstring(ibuf, (char *)0);
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, (char *)0);
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, addr->LocalPart);
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, (char *)0);
	PUTIBUF(ibuf, ')');
	
	FOR_ALL_GROUP_MEMBERS(thisaddr, addr, message_write_singleaddress(ibuf, thisaddr););

	PUTIBUF(ibuf, '(');
	message_write_nstring(ibuf, (char *)0);
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, (char *)0);
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, (char *)0);
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, (char *)0);
	PUTIBUF(ibuf, ')');

	return;
    }
    
    /* If no route phrase, use first RFC-822 comment (without parens) */
    name = addr->RoutePhrase;
    if (!name && addr->Comments) {
	name = addr->Comments->Text+1;
	name[strlen(name)-1] = '\0';
    }
	
    /* Fid out my hostname if necessary */
    if (!addr->Hosts->Next->Name && !myhostname[0]) {
	gethostname(myhostname, sizeof(myhostname)-1);
    }

    /* Count number of hosts and build any necessary at-domain-list */
    FOR_ALL_REVERSE_HOSTS(h, addr, { nhosts++; adllen += 2+strlen(h->Name);});
    if (nhosts > 1) {
	adl = xmalloc(adllen);
	*adl = '\0';
	FOR_ALL_REVERSE_HOSTS(h, addr, {
	      if (--nhosts) {
		  if (*adl) strcat(adl, ",");
		  strcat(adl, "@");
		  strcat(adl, h->Name); }});
	nhosts = 1;
    }

    PUTIBUF(ibuf, '(');
    message_write_nstring(ibuf, name);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, adl);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, addr->LocalPart);
    PUTIBUF(ibuf, ' ');
    message_write_nstring(ibuf, nhosts ? addr->Hosts->Next->Name : myhostname);
    PUTIBUF(ibuf, ')');

    /* If we used a comment for a name, put back the close parenthesis */
    if (!addr->RoutePhrase && addr->Comments) {
	name[strlen(name)] = ')';
    }

    if (adl) free(adl);
}

/*
 * Write the nil-or-string 's' to 'ibuf'
 */
static 
message_write_nstring(ibuf, s)
struct ibuf *ibuf;
char *s;
{
    char *p;

    /* Write null pointer as NIL */
    if (!s) {
	message_ibuf_ensure(ibuf, 3);
	*(ibuf->end)++ = 'N';
	*(ibuf->end)++ = 'I';
	*(ibuf->end)++ = 'L';
	return;
    }

    /* Look for any non-QCHAR characters */
    for (p = s; *p; p++) {
	if (*p & 0x80 || *p == '\r' || *p == '\n'
	    || *p == '\"' || *p == '%' || *p == '\\') break;
    }

    if (*p) {
	/* Write out as literal */
	char buf[100];
	sprintf(buf, "{%d}\r\n", strlen(s));
	message_ibuf_ensure(ibuf, strlen(s)+strlen(buf));
	for (p = buf; *p; p++) *(ibuf->end)++ = *p;
	for (p = s; *p; p++) *(ibuf->end)++ = *p;
    }
    else {
	/* Write out as quoted string */
	message_ibuf_ensure(ibuf, strlen(s)+2);
	*(ibuf->end)++ = '\"';
	for (p = s; *p; p++) *(ibuf->end)++ = *p;
	*(ibuf->end)++ = '\"';
    }
}

/*
 * Write the text 's' to 'ibuf'
 */
static 
message_write_text(ibuf, s)
struct ibuf *ibuf;
char *s;
{
    char *p;

    message_ibuf_ensure(ibuf, strlen(s));
    for (p = s; *p; p++) *(ibuf->end)++ = *p;
}

/*
 * Write out the IMAP number 'n' to 'ibuf'
 */
static 
message_write_number(ibuf, n)
struct ibuf *ibuf;
int n;
{
    char buf[100], *p;

    sprintf(buf, "%d", n);

    message_ibuf_ensure(ibuf, strlen(buf));
    for (p = buf; *p; p++) *(ibuf->end)++ = *p;
}

/*
 * Write out the FETCH BODY[section] location/size information to 'ibuf'.
 */
static 
message_write_section(ibuf, body)
struct ibuf *ibuf;
struct body *body;
{
    int part;

    if (strcmp(body->type, "MESSAGE") == 0
	&& strcmp(body->subtype, "RFC822") == 0) {
	if (body->subpart->numparts) {
	    /*
	     * Part 0 of a message/rfc822 is the message header.
	     * Nested parts of a message/rfc822 containing a multipart
	     * are the sub-parts of the multipart.
	     */
	    message_write_bit32(ibuf, body->subpart->numparts+1);
	    message_write_bit32(ibuf, body->subpart->header_offset);
	    message_write_bit32(ibuf, body->subpart->header_size);
	    message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
	    for (part = 0; part < body->subpart->numparts; part++) {
		message_write_bit32(ibuf, body->subpart->subpart[part].content_offset);
		if (strcmp(body->subpart->subpart[part].type, "MULTIPART") == 0) {
		    if (body->subpart->subpart[part].numparts) {
			/* Cannot fetch a multipart itself */
			message_write_bit32(ibuf, -1);
		    }
		    else {
			/* Treat 0-part multipart as 0-length text */
			message_write_bit32(ibuf, 0);
		    }
		    message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
		}
		else {
		    message_write_bit32(ibuf, body->subpart->subpart[part].content_size);
		    message_write_charset(ibuf, &body->subpart->subpart[part]);
		}
	    }
	    for (part = 0; part < body->subpart->numparts; part++) {
		message_write_section(ibuf, &body->subpart->subpart[part]);
	    }
	}
	else {
	    /*
	     * Part 0 of a message/rfc822 is the message header.
	     * Part 1 of a message/rfc822 containing a non-multipart
	     * is the message body.
	     */
	    message_write_bit32(ibuf, 2);
	    message_write_bit32(ibuf, body->subpart->header_offset);
	    message_write_bit32(ibuf, body->subpart->header_size);
	    message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
	    message_write_bit32(ibuf, body->subpart->content_offset);
	    if (strcmp(body->subpart->type, "MULTIPART") == 0) {
		/* Treat 0-part multipart as 0-length text */
		message_write_bit32(ibuf, 0);
		message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
	    }
	    else {
		message_write_bit32(ibuf, body->subpart->content_size);
		message_write_charset(ibuf, body->subpart);
	    }
	    message_write_section(ibuf, body->subpart);
	}
    }
    else if (body->numparts) {
	/*
	 * Cannot fetch part 0 of a multipart.
	 * Nested parts of a multipart are the sub-parts.
	 */
	message_write_bit32(ibuf, body->numparts+1);	
	message_write_bit32(ibuf, 0);
	message_write_bit32(ibuf, -1);
	message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
	for (part = 0; part < body->numparts; part++) {
	    message_write_bit32(ibuf, body->subpart[part].content_offset);
	    if (body->subpart[part].numparts) {
		/* Cannot fetch a multipart itself */
		message_write_bit32(ibuf, -1);
		message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
	    }
	    else if (strcmp(body->subpart[part].type, "MULTIPART") == 0) {
		/* Treat 0-part multipart as 0-length text */
		message_write_bit32(ibuf, 0);
		message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
	    }
	    else {
		message_write_bit32(ibuf, body->subpart[part].content_size);
		message_write_charset(ibuf, &body->subpart[part]);
	    }
	}
	for (part = 0; part < body->numparts; part++) {
	    message_write_section(ibuf, &body->subpart[part]);
	}
    }
    else {
	/*
	 * Leaf section--no part 0 or nested parts
	 */
	message_write_bit32(ibuf, 0);
    }
}

/*
 * Write the 32-bit charset/encoding value for section 'body' to 'ibuf'
 */
static
message_write_charset(ibuf, body)
struct ibuf *ibuf;
struct body *body;
{
    int encoding, charset;
    struct param *param;

    if (!body->encoding) encoding = ENCODING_NONE;
    else {
	switch (body->encoding[0]) {
	case '7':
	case '8':
	    if (!strcmp(body->encoding+1, "BIT")) encoding = ENCODING_NONE;
	    else encoding = ENCODING_UNKNOWN;
	    break;

	case 'B':
	    if (!strcmp(body->encoding, "BASE64")) encoding = ENCODING_BASE64;
	    else if (!strcmp(body->encoding, "BINARY"))
	      encoding = ENCODING_NONE;
	    else encoding = ENCODING_UNKNOWN;
	    break;

	case 'Q':
	    if (!strcmp(body->encoding, "QUOTED-PRINTABLE"))
	      encoding = ENCODING_QP;
	    else encoding = ENCODING_UNKNOWN;
	    break;

	default:
	    encoding = ENCODING_UNKNOWN;
	}
    }
	
    if (!body->type || !strcmp(body->type, "TEXT")) {
	charset = 0;		/* Default is us-ascii */
	for (param = body->params; param; param = param->next) {
	    if (!strcasecmp(param->attribute, "charset")) {
		charset = charset_lookupname(param->value);
		break;
	    }
	}
	message_write_bit32(ibuf, (charset<<16)|encoding);
    }
    else if (!strcmp(body->type, "MESSAGE")) {
	if (!strcmp(body->subtype, "RFC822")) {
	    message_write_bit32(ibuf, (-1<<16)|ENCODING_NONE);
	}
	else {
	    message_write_bit32(ibuf, (0<<16)|ENCODING_NONE);
	}
    }
    else {
	message_write_bit32(ibuf, (-1<<16)|encoding);
    }
}

/*
 * Write the 32-bit integer quantitiy 'val' to 'ibuf'
 */
static 
message_write_bit32(ibuf, val)
struct ibuf *ibuf;
int val;
{
    bit32 buf;
    int i;
    char *p = (char *)&buf;
    
    message_ibuf_ensure(ibuf, sizeof(bit32));
    buf = htonl(val);

    for (i=0; i < sizeof(bit32); i++) {
	*(ibuf->end)++ = *p++;
    }
}

/*
 * Unparse the address list 'addrlist' to 'ibuf'
 */
static 
message_write_searchaddr(ibuf, addrlist)
struct ibuf *ibuf;
PARSED_ADDRESS *addrlist;
{
    if (!addrlist) return;
    
    FOR_ALL_ADDRESSES(thisaddr, addrlist,
		      message_write_singlesearchaddr(ibuf, thisaddr,
				     thisaddr->Next->Kind == DUMMY_ADDRESS););
}

/*
 * Unparse the single addres 'addr' to 'ibuf'.
 */
static 
message_write_singlesearchaddr(ibuf, addr, last)
struct ibuf *ibuf;
PARSED_ADDRESS *addr;
int last;
{
    int nhosts=0, adllen=0;
    char *name = 0, *adl = 0;
    static char myhostname[128];

    /* Recursively handle RFC-822 group addresses */
    if (addr->Kind == GROUP_ADDRESS) {
	lcase(addr->LocalPart);
	message_write_text(ibuf, addr->LocalPart);
	PUTIBUF(ibuf, ':');
	
	FOR_ALL_GROUP_MEMBERS(thisaddr, addr,
			      message_write_singlesearchaddr(ibuf, thisaddr,
				     thisaddr->Next->Kind == DUMMY_ADDRESS););
	PUTIBUF(ibuf, ';');
	if (!last) PUTIBUF(ibuf, ',');
	return;
    }
    
    /* If no route phrase, use first RFC-822 comment (without parens) */
    name = addr->RoutePhrase;
    if (!name && addr->Comments) {
	name = addr->Comments->Text+1;
	name[strlen(name)-1] = '\0';
    }
	
    /* Fid out my hostname if necessary */
    if (!addr->Hosts->Next->Name && !myhostname[0]) {
	gethostname(myhostname, sizeof(myhostname)-1);
	lcase(myhostname);
    }

    /* Count number of hosts and build any necessary at-domain-list */
    FOR_ALL_REVERSE_HOSTS(h, addr, { nhosts++; adllen += 2+strlen(h->Name);});
    if (nhosts > 1) {
	adl = xmalloc(adllen);
	*adl = '\0';
	FOR_ALL_REVERSE_HOSTS(h, addr, {
	      if (--nhosts) {
		  if (*adl) strcat(adl, ",");
		  strcat(adl, "@");
		  strcat(adl, h->Name); }});
	nhosts = 1;
    }

    if (name) {
	message_write_text(ibuf, charset_decode1522(name));
	PUTIBUF(ibuf, ' ');
    }
    PUTIBUF(ibuf, '<');
    if (adl) {
	lcase(adl);
	message_write_text(ibuf, adl);
	PUTIBUF(ibuf, ':');
    }
    lcase(addr->LocalPart);
    message_write_text(ibuf, addr->LocalPart);
    PUTIBUF(ibuf, '@');
    if (nhosts) {
	lcase(addr->Hosts->Next->Name);
	message_write_text(ibuf, addr->Hosts->Next->Name);
    }
    else {
	message_write_text(ibuf, myhostname);
    }
    PUTIBUF(ibuf, '>');
    if (!last) PUTIBUF(ibuf, ',');


    /* If we used a comment for a name, put back the close parenthesis */
    if (!addr->RoutePhrase && addr->Comments) {
	name[strlen(name)] = ')';
    }

    if (adl) free(adl);
}

/*
 * Initialize 'ibuf'
 */
#define IBUFGROWSIZE 1000
static 
message_ibuf_init(ibuf)
struct ibuf *ibuf;
{
    char *s = xmalloc(IBUFGROWSIZE);

    ibuf->start = ibuf->end = s + sizeof(bit32);
    ibuf->last = ibuf->start + IBUFGROWSIZE - sizeof(bit32);
}

/*
 * Ensure 'ibuf' has enough free space to append 'len' bytes.
 */
static 
message_ibuf_ensure(ibuf, len)
struct ibuf *ibuf;
int len;
{
    char *s;
    int size;

    if (ibuf->last - ibuf->end >= len) return;
    if (len < IBUFGROWSIZE) len = IBUFGROWSIZE;

    s = ibuf->start - sizeof(bit32);
    size = len + (ibuf->last - ibuf->start);
    s = xrealloc(s, size + sizeof(bit32));
    s += sizeof(bit32);
    ibuf->end = (ibuf->end - ibuf->start) + s;
    ibuf->start = s;
    ibuf->last = s + size;
}

/*
 * Write 'ibuf' to the cache file 'outfile'
 */
static 
message_ibuf_write(outfile, ibuf)
FILE *outfile;
struct ibuf *ibuf;
{
    char *s;
    int len;

    len = (ibuf->end - ibuf->start);
    s = ibuf->start - sizeof(bit32);
    *((bit32 *)s) = htonl(len);
    fwrite(s, 1, len+sizeof(bit32), outfile);
    if (len & 3) {
	fwrite("\0\0\0", 1, 4 - (len & 3), outfile);
    }
}

/*
 * Free the space used by 'ibuf'
 */
static 
message_ibuf_free(ibuf)
struct ibuf *ibuf;
{
    free(ibuf->start - sizeof(bit32));
}

/*
 * Free the parsed body-part 'body'
 */
static 
message_free_body(body)
struct body *body;
{
    struct param *param, *nextparam;
    int part;

    if (body->type) {
	free(body->type);
	free(body->subtype);
	for (param = body->params; param; param = nextparam) {
	    nextparam = param->next;
	    free(param->attribute);
	    free(param->value);
	    free(param);
	}
    }
    if (body->id) free(body->id);
    if (body->description) free(body->description);
    if (body->encoding) free(body->encoding);
    if (body->md5) free(body->md5);
    if (body->date) free(body->date);
    if (body->subject) free(body->subject);
    if (body->from) FreeAddressList(body->from);
    if (body->sender) FreeAddressList(body->sender);
    if (body->reply_to) FreeAddressList(body->reply_to);
    if (body->to) FreeAddressList(body->to);
    if (body->cc) FreeAddressList(body->cc);
    if (body->bcc) FreeAddressList(body->bcc);
    if (body->in_reply_to) free(body->in_reply_to);
    if (body->message_id) free(body->message_id);

    if (body->subpart) {
	if (body->numparts) {
	    for (part=0; part < body->numparts; part++) {
		message_free_body(&body->subpart[part]);
	    }
	}
	else {
	    message_free_body(body->subpart);
	}
	free(body->subpart);
    }
    if (body->cacheheaders.start) {
	message_ibuf_free(&body->cacheheaders);
    }
}
