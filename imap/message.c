#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "folder.h"
#include "parseadd.h"
#include "xmalloc.h"

extern PARSED_ADDRESS *AppendAddresses();

struct body {
    char *type;
    char *subtype;
    struct param *params;
    char *id;
    char *description;
    char *encoding;
    char *md5;
    long header_offset;
    long content_offset;
    long header_size;
    long content_size;
    long linecount;
    long boundary_size;		/* Size of terminating boundary */

    int numparts;		/* For multipart types */
    struct body *subpart;	/* For message/rfc822 and multipart types */

    /* Only meaningful for bodies at top level or
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
};

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

/* Cache file item buffer */
struct ibuf {
    char *start, *end;
    int left;
};
    
/* (draft standard) MIME tspecials */
#define TSPECIALS "()<>@,;:\\\"/[]?="

char *message_fname(folder, uid)
struct folder *folder;
unsigned long uid;
{
    static char buf[64];

    sprintf(buf, "%lu%s", uid, folder->format == FOLDER_FORMAT_NETNEWS ? "" : ".");
    return buf;
}

message_copy_stream(from, to)
FILE *from, *to;
{
    char buf[4096], *p;

    while (fgets(buf, sizeof(buf)-1, from)) {
	p = buf + strlen(buf) - 1;
	if (*p == '\n') {
	    if (p == buf || p[-1] != '\r') {
		p[0] = '\r';
		p[1] = '\n';
		p[2] = '\0';
	    }
	}
	else if (*p == '\r') {
	    ungetc('\r', from);
	    *p = '\0';
	}
	fputs(buf, to);
    }
    if (ferror(from) || ferror(to)) return 1; /* XXX copy error */
    return 0;
}

message_parse(infile, folder, message_index)
FILE *infile;
struct folder *folder;
struct index_record *message_index;
{
    int r;
    struct body body;

    rewind(infile);
    message_parse_body(infile, folder->format, &body,
		       "TEXT/PLAIN; CHARSET=us-ascii", (struct boundary *)0);
    
    message_index->content_offset = body.content_offset;
    message_index->size = body.header_size + body.content_size;

    message_index->cache_offset = ftell(folder->cache);
    r = message_write_cache(folder, &body);

    message_free_body(&body);
    return r;
}

/*
 * Parse an RFC 822 message or MIME body-part
 */
static message_parse_body(infile, format, body, defaultContentType, boundaries)
FILE *infile;
int format;
struct body *body;
char *defaultContentType;
struct boundary *boundaries;
{
    struct boundary newboundaries;
    static struct body zerobody;

    *body = zerobody;
    newboundaries.id = 0;

    /* No passed-in boundary structure, create a new one */
    if (!boundaries) {
	boundaries = &newboundaries;
	boundaries->alloc = boundaries->count = 0;
    }

    message_parse_headers(infile, format, body,
			  defaultContentType, boundaries);

    if (strcmp(body->type, "MULTIPART") == 0) {
	message_parse_multipart(infile, format, body, boundaries);
    }
    else if (strcmp(body->type, "MESSAGE") == 0 &&
	strcmp(body->subtype, "RFC822") == 0) {
	body->subpart = (struct body *)xmalloc(sizeof(struct body));
	message_parse_body(infile, format, body->subpart,
			   defaultContentType, boundaries);
	body->content_size = body->subpart->header_size +
	  body->subpart->content_size;
    }
    else {
	message_parse_content(infile, format, body, boundaries);
    }

    if (newboundaries.id) free(newboundaries.id);
}

#define HEADGROWSIZE 1000
static
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

    body->header_offset = ftell(infile);

    if (!alloced) {
	headers = xmalloc(alloced = HEADGROWSIZE);
    }

    next = headers;
    *next++ = '\n';		/* Leading newline to prime the pump */
    left = alloced - 3;		/* Allow for leading newline, added CR */
				/*  and trailing NUL */

    while (fgets(next, left, infile) &&
	   (next[-1] != '\n' ||
	    (format == FOLDER_FORMAT_NETNEWS ?
	     (*next != '\n') : (*next != '\r' || next[1] != '\n')))) {

	if (next[-1] == '\n' && *next == '-' &&
	    PendingBoundary(next, boundaries->id, &boundaries->count)) {
	    body->boundary_size = strlen(next)+(format==FOLDER_FORMAT_NETNEWS);
	    if (next - 1 > headers) {
		body->boundary_size += 2;
		next[-2] = '\0';
	    }
	    else {
		*next = '\0';
	    }
	    break;
	}

	len = strlen(next);
	left -= len;
	next += len;

	if (format == FOLDER_FORMAT_NETNEWS) {
	    /* Convert LF to CRLF */
	    if (next[-1] == '\n' && next[-2] != '\r') {
		next[-1] = '\r';
		*next++ = '\n';
		*next = '\0';
		left--;
	    }
	}

	if (left < 100) {
	    len = next - headers;
	    alloced += HEADGROWSIZE;
	    left += HEADGROWSIZE;
	    headers = xrealloc(headers, alloced);
	    next = headers + len;
	}
    }
    
    body->content_offset = ftell(infile);
    body->header_size = strlen(headers+1);

    for (next = headers; *next; next++) {
	if (*next == '\n') {
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

	    case 'r':
	    case 'R':
		if (!strncasecmp(next+2, "eply-to:", 8)) {
		    message_parse_address(next+10, &body->reply_to);
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
    if (!body->type) {
	message_parse_type(defaultContentType, body);
    }
}

static message_parse_address(hdr, addrp)
char *hdr;
PARSED_ADDRESS **addrp;
{
    char *hdrend, hdrendchar;
    PARSED_ADDRESS *hdrlist;
    int r;

    hdrend = hdr;
    do {
	hdrend = strchr(hdrend+1, '\n');
    } while (hdrend && (hdrend[1] == ' ' || hdrend[1] == '\t'));

    if (hdrend) {
	if (hdrend > hdr && hdrend[-1] == '\r') hdrend--;
	hdrendchar = *hdrend;
	*hdrend = '\0';
    }

    r = ParseAddressList(hdr, &hdrlist);

    if (hdrend) *hdrend = hdrendchar;
    if (r) return;

    *addrp = AppendAddresses(*addrp, hdrlist);
}

static message_parse_encoding(hdr, hdrp)
char *hdr;
char **hdrp;
{
    int len;
    char *p;

    if (*hdrp) return;

    /* Skip leading whitespace, ignore header if blank */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    for (p = hdr; *p && !isspace(*p) && *p != '('; p++) {
	if (*p < ' ' || strchr(TSPECIALS, *p)) return;
    }
    len = p - hdr;

    /* Skip trailing whitespace, ignore header if trailing garbage */
    message_parse_rfc822space(&p);
    if (p) return;

    *hdrp = xmalloc(len + 1);
    strncpy(*hdrp, hdr, len);
    (*hdrp)[len] = '\0';
    for (p = *hdrp; *p; p++) {
	if (islower(*p)) *p = toupper(*p);
    }
}
	
static message_parse_string(hdr, hdrp)
char *hdr;
char **hdrp;
{
    int len;
    char *hdrend;

    if (*hdrp) return;

    /* Skip initial whitespace */
    while (*hdr == ' ' || *hdr == '\t') hdr++;

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

    len = hdrend - hdr;
    *hdrp = xmalloc(len + 1);
    strncpy(*hdrp, hdr, len);
    (*hdrp)[len] = '\0';
}

static message_parse_type(hdr, body)	    
char *hdr;
struct body *body;
{
    char *type;
    int typelen;
    char *subtype;
    int subtypelen;
    char *p;

    if (body->type) return;

    /* Skip leading whitespace, ignore header if blank */
    message_parse_rfc822space(&hdr);
    if (!hdr) return;

    /* Skip over type token */
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

    /* Skip over subtype token */
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

static message_parse_params(hdr, paramp)
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
	message_parse_rfc822space(&hdr);
	if (!hdr) return;

	/* Skip over attribute */
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
	if (hdr && *hdr != ';') return;
		  
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

	paramp = &param->next;
    }
}

static message_parse_rfc822space(s)
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

static message_parse_multipart(infile, format, body, boundaries)
FILE *infile;
int format;
struct body *body;
struct boundary *boundaries;
{
    struct body preamble, epilogue;
    static struct body zerobody;
    struct param *boundary;
    char *defaultContentType = "TEXT/PLAIN; CHARSET=us-ascii";
    int i, depth;

    preamble = epilogue = zerobody;
    if (strcmp(body->subtype, "DIGEST") == 0) {
	defaultContentType = "MESSAGE/RFC822";
    }

    boundary = body->params;
    while(boundary && strcmp(boundary->attribute, "BOUNDARY") != 0) {
	boundary = boundary->next;
    }
    
    if (!boundary) {
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

    /* Skip over preamble */
    message_parse_content(infile, format, &preamble, boundaries);

    /* Handle the component messages */
    while (boundaries->count == depth) {
	body->subpart = (struct body *)xrealloc((char *)body->subpart,
				 (body->numparts+1)*sizeof(struct body));
	message_parse_body(infile, format, &body->subpart[body->numparts++],
			   defaultContentType, boundaries);
    }

    /* Skip over epilogue */
    if (boundaries->count == depth-1) {
	message_parse_content(infile, format, &epilogue, boundaries);
    }
    else if (body->numparts) {
	body->boundary_size = body->subpart[body->numparts-1].boundary_size;
	body->subpart[body->numparts-1].boundary_size = 0;
    }
    else {
	body->boundary_size = preamble.boundary_size;
	preamble.boundary_size = 0;
    }

    body->content_size = preamble.content_size + preamble.boundary_size;
    for (i=0; i< body->numparts; i++) {
	body->content_size += body->subpart[i].content_size +
	  body->subpart[i].boundary_size;
    }
    body->content_size += epilogue.content_size;

    body->boundary_size += epilogue.boundary_size;
}

static message_parse_content(infile, format, body, boundaries)
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
	    body->boundary_size = strlen(buf)+(format==FOLDER_FORMAT_NETNEWS);
	    if (body->linecount) body->linecount--;
	    if (body->content_size) {
		body->content_size -= 2;
		body->boundary_size += 2;
	    }
	    return;
	}

	len = strlen(buf);
	body->content_size += len;

	if (line_boundary = (buf[len-1] == '\n')) {
	    body->linecount++;
	    if (format == FOLDER_FORMAT_NETNEWS) body->content_size++;
	}
    }
}

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

static int message_write_cache(folder, body)
struct folder *folder;
struct body *body;
{
    int r = 0;
    struct ibuf section, envelope, bodystructure, oldbody;

    message_ibuf_init(&section);
    message_write_section(&section, body);

    message_ibuf_init(&envelope);
    message_write_envelope(&envelope, body);

    message_ibuf_init(&bodystructure);
    message_write_body(&bodystructure, body, 1);

    message_ibuf_init(&oldbody);
    message_write_body(&oldbody, body, 0);

    message_ibuf_write(folder->cache, &section);
    message_ibuf_write(folder->cache, &envelope);
    message_ibuf_write(folder->cache, &bodystructure);
    message_ibuf_write(folder->cache, &oldbody);

    message_ibuf_free(&section);
    message_ibuf_free(&envelope);
    message_ibuf_free(&bodystructure);
    message_ibuf_free(&oldbody);

    if (ferror(folder->cache)) {
	r = 1;			/* XXX Write error */
    }

    return r;
}

#define PUTIBUF(ibuf,c) (((ibuf)->left || message_ibuf_ensure((ibuf),1)),(*((ibuf)->end)++ = (c)))

static message_write_envelope(ibuf, body)
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

static message_write_body(ibuf, body, newformat)
struct ibuf *ibuf;
struct body *body;
int newformat;
{
    struct param *param;

    PUTIBUF(ibuf, '(');

    if (strcmp(body->type, "MULTIPART") == 0) {
	int i;

	for (i = 0; i < body->numparts; i++) {
	    message_write_body(ibuf, &body->subpart[i], newformat);
	}
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, body->subtype);
	PUTIBUF(ibuf, ')');
	return;
    }

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
	PUTIBUF(ibuf, ' ');
	message_write_number(ibuf, body->linecount);
    }
    else if (strcmp(body->type, "MESSAGE") == 0
	     && strcmp(body->subtype, "RFC822") == 0) {
	PUTIBUF(ibuf, ' ');
	message_write_envelope(ibuf, body->subpart);
	PUTIBUF(ibuf, ' ');
	message_write_body(ibuf, body->subpart, newformat);
    }

    if (newformat) {
	PUTIBUF(ibuf, ' ');
	message_write_nstring(ibuf, body->md5);
    }

    PUTIBUF(ibuf, ')');
}

static message_write_address(ibuf, addrlist)
struct ibuf *ibuf;
PARSED_ADDRESS *addrlist;
{
    int len = 0;

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

static message_write_singleaddress(ibuf, addr)
struct ibuf *ibuf;
PARSED_ADDRESS *addr;
{
    int nhosts=0, adllen=0;
    char *name = 0, *adl = 0;
    static char myhostname[128];

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
    
    name = addr->RoutePhrase;
    if (!name && addr->Comments) name = addr->Comments->Text;
    if (!addr->Hosts->Next->Name && !myhostname[0]) {
	gethostname(myhostname, sizeof(myhostname)-1);
    }

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

    if (adl) free(adl);
}

static message_write_nstring(ibuf, s)
struct ibuf *ibuf;
char *s;
{
    char *p;

    if (!s) {
	message_ibuf_ensure(ibuf, 3);
	*(ibuf->end)++ = 'N';
	*(ibuf->end)++ = 'I';
	*(ibuf->end)++ = 'L';
	return;
    }

    for (p = s; *p; p++) {
	if (*p & 0x80 || *p == '\r' || *p == '\n'
	    || *p == '\"' || *p == '%' || *p == '\\') break;
    }
    if (*p) {
	char buf[100];
	sprintf(buf, "{%d}\r\n", strlen(s));
	message_ibuf_ensure(ibuf, strlen(s)+strlen(buf));
	for (p = buf; *p; p++) *(ibuf->end)++ = *p;
	for (p = s; *p; p++) *(ibuf->end)++ = *p;
    }
    else {
	message_ibuf_ensure(ibuf, strlen(s)+2);
	*(ibuf->end)++ = '\"';
	for (p = s; *p; p++) *(ibuf->end)++ = *p;
	*(ibuf->end)++ = '\"';
    }
}

static message_write_number(ibuf, n)
struct ibuf *ibuf;
int n;
{
    char buf[100], *p;

    sprintf(buf, "%d", n);

    message_ibuf_ensure(ibuf, strlen(buf));
    for (p = buf; *p; p++) *(ibuf->end)++ = *p;
}

static message_write_section(ibuf, body)
struct ibuf *ibuf;
struct body *body;
{
    int part;

    if (strcmp(body->type, "MESSAGE") == 0
	&& strcmp(body->subtype, "RFC822") == 0) {
	if (strcmp(body->subpart->type, "MULTIPART") == 0) {
	    message_write_bit32(ibuf, body->subpart->numparts+1);
	    message_write_bit32(ibuf, body->subpart->header_offset);
	    message_write_bit32(ibuf, body->subpart->header_size);
	    for (part = 0; part < body->subpart->numparts; part++) {
		message_write_bit32(ibuf, body->subpart->subpart[part].content_offset);
		if (strcmp(body->subpart->subpart[part].type, "MULTIPART") == 0) {
		    message_write_bit32(ibuf, -1);
		}
		else {
		    message_write_bit32(ibuf, body->subpart->subpart[part].content_size);
		}
	    }
	    for (part = 0; part < body->subpart->numparts; part++) {
		message_write_section(ibuf, &body->subpart->subpart[part]);
	    }
	}
	else {
	    message_write_bit32(ibuf, 2);
	    message_write_bit32(ibuf, body->subpart->header_offset);
	    message_write_bit32(ibuf, body->subpart->header_size);
	    message_write_bit32(ibuf, body->subpart->content_offset);
	    message_write_bit32(ibuf, body->subpart->content_size);
	    message_write_section(ibuf, body->subpart);
	}
    }
    else if (body->numparts) {
	message_write_bit32(ibuf, body->numparts+1);	
	message_write_bit32(ibuf, 0);
	message_write_bit32(ibuf, -1);
	for (part = 0; part < body->numparts; part++) {
	    message_write_bit32(ibuf, body->subpart[part].content_offset);
	    if (strcmp(body->subpart[part].type, "MULTIPART") == 0) {
		message_write_bit32(ibuf, -1);
	    }
	    else {
		message_write_bit32(ibuf, body->subpart[part].content_size);
	    }
	}
	for (part = 0; part < body->numparts; part++) {
	    message_write_section(ibuf, &body->subpart[part]);
	}
    }
    else {
	message_write_bit32(ibuf, 0);
    }
}

static message_write_bit32(ibuf, val)
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

#define IBUFGROWSIZE 100 /* XXX 1000 */
static message_ibuf_init(ibuf)
struct ibuf *ibuf;
{
    char *s = xmalloc(IBUFGROWSIZE);

    ibuf->start = ibuf->end = s + sizeof(bit32);
    ibuf->left = IBUFGROWSIZE - sizeof(bit32);
}

static message_ibuf_ensure(ibuf, len)
struct ibuf *ibuf;
int len;
{
    char *s;

    if (len >= ibuf->left) return;
    if (len < IBUFGROWSIZE) len = IBUFGROWSIZE;

    s = ibuf->start - sizeof(bit32);
    s = xrealloc(s, len + (ibuf->end - ibuf->start) + ibuf->left + sizeof(bit32));
    ibuf->left += len;
    s += sizeof(bit32);
    ibuf->end = (ibuf->end - ibuf->start) + s;
    ibuf->start = s;
}

static message_ibuf_write(outfile, ibuf)
FILE *outfile;
struct ibuf *ibuf;
{
    char *s;
    int len;

    len = (ibuf->end - ibuf->start);
    s = ibuf->start - sizeof(bit32);
    *((bit32 *)s) = htonl(len);
    fwrite(s, 1, len+sizeof(bit32), outfile);
}

static message_ibuf_free(ibuf)
struct ibuf *ibuf;
{
    free(ibuf->start - sizeof(bit32));
}

static message_free_body(body)
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
}
