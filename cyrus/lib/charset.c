/* charset.c -- International character set support
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
#include "assert.h"
#include "charset.h"
#include "xmalloc.h"

#include "charset/us-ascii.h"
#include "charset/iso-8859-1.h"
#include "charset/iso-8859-2.h"
#include "charset/iso-8859-3.h"
#include "charset/iso-8859-4.h"
#include "charset/iso-8859-5.h"
#include "charset/iso-8859-6.h"
#include "charset/iso-8859-7.h"
#include "charset/iso-8859-8.h"
#include "charset/iso-8859-9.h"

struct charset {
    char *name;
    char **table;
};

/*
 * Mapping of character sets to tables
 */
static struct charset charset_table[] = {
    { "us-ascii", us_ascii },	/* US-ASCII must be charset number 0 */
    { "iso-8859-1", iso_8859_1 },
    { "iso-8859-2", iso_8859_2 },
    { "iso-8859-3", iso_8859_3 },
    { "iso-8859-4", iso_8859_4 },
    { "iso-8859-5", iso_8859_5 },
    { "iso-8859-6", iso_8859_6 },
    { "iso-8859-7", iso_8859_7 },
    { "iso-8859-8", iso_8859_8 },
    { "iso-8859-9", iso_8859_9 },
};
#define NUM_CHARSETS (sizeof(charset_table)/sizeof(*charset_table))

#define GROWSIZE 100

/*
 * Table for decoding hexadecimal in quoted-printable
 */
static char index_hex[128] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
     0, 1, 2, 3,  4, 5, 6, 7,  8, 9,-1,-1, -1,-1,-1,-1,
    -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
};
#define HEXCHAR(c)  (((c) < 0 || (c) > 127) ? -1 : index_hex[(c)])

/*
 * Table for decoding base64
 */
static char index_64[128] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};
#define CHAR64(c)  (((c) < 0 || (c) > 127) ? -1 : index_64[(c)])

/*
 * "Short-form" character mapping table for converting
 * US-ASCII to canonical searching form.
 */
static char usascii_lcase[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
    EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR, EMPTY_CHAR,
};
#define USASCII(c) (usascii_lcase[(unsigned char)(c)])

/*
 * Lookup the character set 'name'.  Returns the character set number
 * or -1 if there is no matching character set.
 */
int charset_lookupname(name)
char *name;
{
    int i;

    for (i=0; i<NUM_CHARSETS; i++) {
	if (!strcasecmp(name, charset_table[i].name)) return i;
    }
    return -1;
}

/*
 * Convert the string 's' in the character set numbered 'charset'
 * into canonical searching form.  Returns a pointer to a static
 * buffer containing 's' in canonical searching form.
 */
char *charset_convert(s, charset)
char *s;
int charset;
{
    static char *retval = 0;
    static int alloced = 0;
    int pos = 0;
    char **table;
    char *translation;
    int len;

    if (!s) return 0;
    if (charset < 0 || charset >= NUM_CHARSETS) return EMPTY;

    table = charset_table[charset].table;
    
    if (!alloced) {
	alloced = GROWSIZE;
	retval = xmalloc(alloced);
    }
    *retval = '\0';

    while (*s) {
	translation = table[(unsigned char)*s];
	len = strlen(translation);
	if (pos + len >= alloced) {
	    alloced += len + GROWSIZE;
	    retval = xrealloc(retval, alloced);
	}
	strcpy(retval+pos, translation);
	pos += len;
	s++;
    }

    return retval;
}

/*
 * Decode 1522-strings in 's'.  Returns a pointer to a static buffer
 * contining 's' in canonical searching form.
 */
char *charset_decode1522(s)
char *s;
{
    int eatspace = 0;
    char *start, *encoding, *end;
    char *p;
    int i, c, c1, c2, c3, c4;
    char **table;
    static char *retval = 0;
    static int alloced = 0;
    char *translation;
    int pos = 0;
    int len;

    if (!s) return 0;

    start = s;
    while (start = strchr(start, '=')) {
	start++;
	if (*start != '?') continue;
	encoding = strchr(start+1, '?');
	if (!encoding) continue;
	if (encoding[1] != 'b' && encoding[1] != 'B' &&
	    encoding[1] != 'q' && encoding[1] != 'Q') continue;
	if (encoding[2] != '?') continue;
	end = strchr(encoding+3, '?');
	if (!end || end[1] != '=') continue;

	/*
	 * We have recognized a valid 1522-word.
	 * Copy over leading text, unless it consists entirely of 
	 * whitespace and is between two 1522-words.
	 */
	if (eatspace) {
	    for (p = s; p < (start-1) && isspace(*p); p++);
	    if (p < (start-1)) eatspace = 0;
	}
	if (!eatspace) {
	    len = start - s - 1;
	    if (pos + len >= alloced) {
		alloced += len + GROWSIZE;
		retval = xrealloc(retval, alloced);
	    }
	    while (len--) {
		retval[pos++] = USASCII(*s);
		s++;
	    }
	}

	/*
	 * Get the 1522-word's character set
	 */
	start++;
	for (i=0; i<NUM_CHARSETS; i++) {
	    if (strlen(charset_table[i].name) == encoding-start &&
		!strncasecmp(start, charset_table[i].name, encoding-start)) {
		table = charset_table[i].table;
		break;
	    }
	}

	if (i == NUM_CHARSETS) {
	    /* Unrecognized charset, nothing will match here */
	    if (pos + 2 >= alloced) {
		alloced += 2 + GROWSIZE;
		retval = xrealloc(retval, alloced);
	    }
	    strcpy(retval+pos, EMPTY);
	    pos += 1;
	}
	else if (encoding[1] == 'q' || encoding[1] == 'Q') {
	    /* Decode 'Q' encoding */
	    p = encoding+3;
	    while (p < end) {
		c = *p++;
		if (c == '=') {
		    c = HEXCHAR(*p);
		    p++;
		    i = HEXCHAR(*p);
		    p++;
		    if (c == -1 || i == -1) {
			c = '\0';
		    }
		    else {
			c = (c << 4) + i;
		    }
		}
		else if (c == '_') c = ' ';

		translation = table[(unsigned char)c];
		if (!c) {
		    translation = EMPTY;
		}
		len = strlen(translation);
		if (pos + len >= alloced) {
		    alloced += len + GROWSIZE;
		    retval = xrealloc(retval, alloced);
		}
		strcpy(retval+pos, translation);
		pos += len;
	    }
	}
	else {
	    /* Decode 'B' encoding */
	    p = encoding+3;
	    while (p < end) {
		c1 = CHAR64(p[0]);
		if (c1 == -1) break;
		c2 = CHAR64(p[1]);
		if (c2 == -1) break;
		translation = table[(unsigned char)((c1<<2) | ((c2&0x30)>>4))];
		len = strlen(translation);
		if (pos + len >= alloced) {
		    alloced += len + GROWSIZE;
		    retval = xrealloc(retval, alloced);
		}
		strcpy(retval+pos, translation);
		pos += len;

		c3 = CHAR64(p[2]);
		if (c3 == -1) break;
		translation = table[(unsigned char)(((c2&0XF) << 4) | ((c3&0x3C) >> 2))];
		len = strlen(translation);
		if (pos + len >= alloced) {
		    alloced += len + GROWSIZE;
		    retval = xrealloc(retval, alloced);
		}
		strcpy(retval+pos, translation);
		pos += len;

		c4 = CHAR64(p[3]);
		if (c4 == -1) break;
		translation = table[(unsigned char)(((c3&0x03) <<6) | c4)];
		len = strlen(translation);
		if (pos + len >= alloced) {
		    alloced += len + GROWSIZE;
		    retval = xrealloc(retval, alloced);
		}
		strcpy(retval+pos, translation);
		pos += len;

		p += 4;
	    }
	}

	/* Prepare for the next iteration */
	s = start = end+2;
	eatspace = 1;
    }

    /* Copy over the tail part of the input string */
    len = strlen(s);
    if (pos + len >= alloced) {
	alloced += len + 1;
	retval = xrealloc(retval, alloced);
    }
    while (len--) {
	retval[pos++] = USASCII(*s);
	s++;
    }
    retval[pos++] = '\0';
    return retval;
}

/*
 * The various charset_searchfile() helper functions
 */
static int charset_readconvert();
static int charset_readplain();
static int charset_readmapnl();
static int charset_readqp();
static int charset_readqpmapnl();
static int charset_readbase64();

/*
 * State for the various charset_searchfile() helper functions
 */
static int (*rawproc)();	/* Function to read and transfer-decode data */
static FILE *rawfile;		/* File to read raw data from */
static int rawlen;		/* # bytes raw data left to read from file */
static char rawbuf[4096];	/* Buffer of data read, but not decoded */
static int rawstart, rawleft;	/* Location/count of unprocessed raw data */
static char decodebuf[4096];	/* Buffer of data deocded, but not converted
				 * into canonical searching form */
static int decodestart, decodeleft; /* Location/count of decoded data */
static char **decodetable;	/* Charset table to convert decoded data
				 * into canonical searching form */

/*
 * Search for the string 'substr' in the next 'len' bytes of 
 * 'msgfile'.  If 'mapnl' is nonzero, then LF characters in the file
 * map to CR LF and count as 2 bytes w.r.t. the value of 'len'.
 * 'charset' and 'encoding' specify the character set and 
 * content transfer encoding of the data, respectively.
 * Returns nonzero iff the string was found.
 */
int
charset_searchfile(substr, msgfile, mapnl, len, charset, encoding)
char *substr;
FILE *msgfile;
int mapnl;
int len;
int charset;
int encoding;
{
    int substrlen = strlen(substr);
    char *buf, smallbuf[4096];
    int bufsize;
    char *p;
    int n;
    
    /* Initialize character set mapping */
    if (charset < 0 || charset >= NUM_CHARSETS) return 0;
    decodetable = charset_table[charset].table;
    decodeleft = 0;

    /* Initialize transfer-decoding */
    rawfile = msgfile;
    rawlen = len;
    rawleft = 0;
    switch (encoding) {
    case ENCODING_NONE:
	if (mapnl && !strchr(substr, '\n') && !strchr(substr, '\r')) {
	    /* Doesn't matter -- CRLF won't match anything */
	    mapnl = 0;
	}
	rawproc = mapnl ? charset_readmapnl : charset_readplain;
	break;

    case ENCODING_QP:
	rawproc = mapnl ? charset_readqpmapnl : charset_readqp;
	break;

    case ENCODING_BASE64:
	rawproc = charset_readbase64;
	/* XXX have to have nl-mapping base64 in order to
	 * properly count \n as 2 raw characters
	 */
	break;

    default:
	/* Don't know encoding--nothing can match */
	return 0;
    }

    /*
     * Select buffer to hold canonical searching fomat data to
     * search
     */
    if (substrlen < sizeof(smallbuf)/2) {
	bufsize = sizeof(smallbuf);
	buf = smallbuf;
    }
    else {
	bufsize = substrlen+sizeof(smallbuf);
	buf = xmalloc(bufsize);
    }

    /* Do the search */
    n = charset_readconvert(buf, bufsize);
    if (n < substrlen) {
	if (buf != smallbuf) free(buf);
	return 0;
    }
    n -= substrlen-1;
    do {
	p = buf;
	while (n-- > 0) {
	    if (*substr == *p && !strncmp(substr, p, substrlen)) {
		if (buf != smallbuf) free(buf);
		return 1;
	    }
	    p++;
	}
	strncpy(buf, p, substrlen-1);
    } while (n = charset_readconvert(buf+substrlen-1, bufsize-substrlen+1));

    if (buf != smallbuf) free(buf);
    return 0;
}

/*
 * Helper function to read at most 'size' bytes of converted
 * (into canonical searching format) data into 'buf'.  Returns
 * the number of converted bytes, or 0 for end-of-data.
 */
static int
charset_readconvert(buf, size)
char *buf;
int size;
{
    int retval = 0;
    char *translation;
    int len;

    if (decodeleft && decodestart != 0) {
	bcopy(decodebuf+decodestart, decodebuf, decodeleft);
    }
    decodestart = 0;

    decodeleft += (*rawproc)(decodebuf+decodeleft, sizeof(decodebuf)-decodeleft);

    while (decodeleft) {
	translation = decodetable[(unsigned char)(decodebuf[decodestart])];
	len = strlen(translation);
	if (len > size) {
	    return retval;
	}
	decodestart++;
	decodeleft--;
	while (len--) {
	    *buf++ = *translation++;
	    retval++;
	    size--;
	}
    }
    return retval;
}
    
/*
 * Helper function to read at most 'size' bytes of trivial
 * transfer-decoded data into 'buf'.  Returns the number of decoded
 * bytes, or 0 for end-of-data.
 */
static int
charset_readplain(buf, size)
char *buf;
int size;
{
    int n;

    if (size > rawlen) size = rawlen;
    if (!size) return 0;

    n = fread(buf, 1, size, rawfile);
    rawlen -= n;

    return n;
}

/*
 * Helper function to read at most 'size' bytes of trivial newline-mapped
 * transfer-decoded data into 'buf'.  Returns the number of decoded
 * bytes, or 0 for end-of-data.
 */
static int
charset_readmapnl(buf, size)
char *buf;
int size;
{
    int retval = 0;
    int n, limit;
    int c;

    if (rawleft && rawstart != 0) {
	bcopy(rawbuf+rawstart, rawbuf, rawleft);
    }
    rawstart = 0;

    limit = sizeof(rawbuf)-rawleft;
    if (limit > rawlen) limit = rawlen;
    n = fread(rawbuf+rawleft, 1, limit, rawfile);
    rawlen -= n;
    rawleft += n;

    while (size && rawleft > 0) {
	c = rawbuf[rawstart];
	if (c == '\n') {
	    if (size < 2) {
		return retval;
	    }
	    rawleft--;
	    *buf++ = '\r';
	    retval++;
	    size--;
	}
	rawstart++;
	rawleft--;
	*buf++ = c;
	retval++;
	size--;
    }
    return retval;
}

/*
 * Helper function to read at most 'size' bytes of quoted-printable
 * transfer-decoded data into 'buf'.  Returns the number of decoded
 * bytes, or 0 for end-of-data.
 */
static int
charset_readqp(buf, size)
char *buf;
int size;
{
    int retval = 0;
    int n, limit;
    int c, c1, c2;

    if (rawleft && rawstart != 0) {
	bcopy(rawbuf+rawstart, rawbuf, rawleft);
    }
    rawstart = 0;

    limit = sizeof(rawbuf)-rawleft;
    if (limit > rawlen) limit = rawlen;
    n = fread(rawbuf+rawleft, 1, limit, rawfile);
    rawlen -= n;
    rawleft += n;

    while (size && rawleft) {
	c = rawbuf[rawstart];
	if (c == '=') {
	    if (rawleft < 3) {
		return retval;
	    }
	    c1 = rawbuf[rawstart+1];
	    c2 = rawbuf[rawstart+2];
	    rawstart += 3;
	    rawleft -= 3;
	    c1 = HEXCHAR(c1);
	    c2 = HEXCHAR(c2);
	    /* Following line also takes care of soft line breaks */
	    if (c1 == -1 && c2 == -1) continue;
	    *buf++ = (c1 << 4) + c2;
	    retval++;
	    size--;
	}
	else {
	    rawstart++;
	    rawleft--;
	    *buf++ = c;
	    retval++;
	    size--;
	}
    }
    return retval;
}

/*
 * Helper function to read at most 'size' bytes of QP newline-mapped
 * transfer-decoded data into 'buf'.  Returns the number of decoded
 * bytes, or 0 for end-of-data.
 */
static int
charset_readqpmapnl(buf, size)
char *buf;
int size;
{
    int retval = 0;
    int n, limit;
    int c, c1, c2;

    if (rawleft && rawstart != 0) {
	bcopy(rawbuf+rawstart, rawbuf, rawleft);
    }
    rawstart = 0;

    limit = sizeof(rawbuf)-rawleft;
    if (limit > rawlen) limit = rawlen;
    n = fread(rawbuf+rawleft, 1, limit, rawfile);
    rawlen -= n;
    rawleft += n;

    while (size && rawleft > 0) {
	c = rawbuf[rawstart];
	if (c == '=') {
	    if (rawleft < 2) {
		return retval;
	    }
	    c1 = rawbuf[rawstart+1];
	    if (c1 == '\n') {
		rawstart += 2;
		rawleft -= 3;
		continue;
	    }
	    if (rawleft < 3) {
		return retval;
	    }
	    c2 = rawbuf[rawstart+2];
	    rawstart += 3;
	    rawleft -= 3;
	    c1 = HEXCHAR(c1);
	    c2 = HEXCHAR(c2);
	    if (c1 == -1 && c2 == -1) continue;
	    *buf++ = (c1 << 4) + c2;
	    retval++;
	    size--;
	}
	else if (c == '\n') {
	    if (size < 2) {
		return retval;
	    }
	    rawstart++;
	    rawleft -= 2;
	    *buf++ = '\r';
	    *buf++ = '\n';
	    retval += 2;
	    size -= 2;
	}
	else {
	    rawstart++;
	    rawleft--;
	    *buf++ = c;
	    retval++;
	    size--;
	}
    }
    return retval;
}

/*
 * Helper function to read at most 'size' bytes of base64
 * transfer-decoded data into 'buf'.  Returns the number of decoded
 * bytes, or 0 for end-of-data.
 */
static int
charset_readbase64(buf, size)
char *buf;
int size;
{
    int retval = 0;
    int n, limit;
    int c1, c2, c3, c4;

    if (rawleft && rawstart != 0) {
	bcopy(rawbuf+rawstart, rawbuf, rawleft);
    }
    rawstart = 0;

    limit = sizeof(rawbuf)-rawleft;
    if (limit > rawlen) limit = rawlen;
    n = fread(rawbuf+rawleft, 1, limit, rawfile);
    rawlen -= n;
    rawleft += n;

    while (size >= 3 && rawleft) {
	do {
	    c1 = rawbuf[rawstart++];
	    rawleft--;
	    if (c1 == '=') {
		rawlen = rawleft = 0;
		return retval;
	    }
	} while (rawleft && CHAR64(c1) == -1);
	if (!rawleft) {
	    rawbuf[--rawstart] = c1;
	    rawleft++;
	    return retval;
	}

	do {
	    c2 = rawbuf[rawstart++];
	    rawleft--;
	    if (c2 == '=') {
		rawlen = rawleft = 0;
		return retval;
	    }
	} while (rawleft && CHAR64(c2) == -1);
	if (!rawleft) {
	    rawbuf[--rawstart] = c2;
	    rawbuf[--rawstart] = c1;
	    rawleft += 2;
	    return retval;
	}

	do {
	    c3 = rawbuf[rawstart++];
	    rawleft--;
	    if (c3 == '=') {
		*buf++ = ((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
		retval++;
		rawlen = rawleft = 0;
		return retval;
	    }
	} while (rawleft && CHAR64(c3) == -1);
	if (!rawleft) {
	    rawbuf[--rawstart] = c3;
	    rawbuf[--rawstart] = c2;
	    rawbuf[--rawstart] = c1;
	    rawleft += 3;
	    return retval;
	}

	do {
	    c4 = rawbuf[rawstart++];
	    rawleft--;
	    if (c4 == '=') {
		*buf++ = ((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
		*buf++ = (((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
		retval += 2;
		rawlen = rawleft = 0;
		return retval;
	    }
	} while (rawleft && CHAR64(c4) == -1);
	if (CHAR64(c4) == -1) {
	    rawbuf[--rawstart] = c3;
	    rawbuf[--rawstart] = c2;
	    rawbuf[--rawstart] = c1;
	    rawleft += 3;
	    return retval;
	}

	*buf++ = ((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
	*buf++ = (((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
	*buf++ = (((CHAR64(c3)&0x3)<<6) | CHAR64(c4));
	retval += 3;
	size -= 3;
    }
    return retval;
}
