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

#include "chartables.h"

#define MAXTRANSLATION 3

struct charset {
    char *name;
    const unsigned char (*table)[256][4];
};

#define PATLEN(pat) ((pat)[256])
#define PATLASTCHAR(pat) ((pat)[257])
#define PATSIZE 258

/*
 * Mapping of character sets to tables
 */
static const struct charset charset_table[] = {
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
    { "koi8-r", koi8_r },
};
#define NUM_CHARSETS (sizeof(charset_table)/sizeof(*charset_table))

#define GROWSIZE 100

/*
 * Table for decoding hexadecimal in quoted-printable
 */
static const signed char index_hex[256] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
     0, 1, 2, 3,  4, 5, 6, 7,  8, 9,-1,-1, -1,-1,-1,-1,
    -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
};
#define HEXCHAR(c)  (index_hex[(unsigned char)(c)])

/*
 * Table for decoding base64
 */
static const signed char index_64[256] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
};
#define CHAR64(c)  (index_64[(unsigned char)(c)])

#define USASCII(c) (us_ascii[0][(unsigned char)(c)][0])

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
    const unsigned char (*table)[4];
    const unsigned char *translation;

    if (!s) return 0;
    if (charset < 0 || charset >= NUM_CHARSETS) return EMPTY_STRING;

    table = charset_table[charset].table[0];
    
    if (!alloced) {
	alloced = GROWSIZE;
	retval = xmalloc(alloced);
    }
    *retval = '\0';

    while (*s) {
	if (pos + MAXTRANSLATION >= alloced) {
	    alloced += GROWSIZE;
	    retval = xrealloc(retval, alloced);
	}
	translation = table[(unsigned char)*s];
	while (*translation) {
	    retval[pos++] = *translation++;
	}
	s++;
    }

    retval[pos] = '\0';
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
    const unsigned char (*table)[4];
    static char *retval = 0;
    static int alloced = 0;
    const unsigned char *translation;
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
		table = charset_table[i].table[0];
		break;
	    }
	}

	if (i == NUM_CHARSETS) {
	    /* Unrecognized charset, nothing will match here */
	    if (pos + 2 >= alloced) {
		alloced += 2 + GROWSIZE;
		retval = xrealloc(retval, alloced);
	    }
	    strcpy(retval+pos, EMPTY_STRING);
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

		if (pos + MAXTRANSLATION >= alloced) {
		    alloced += GROWSIZE;
		    retval = xrealloc(retval, alloced);
		}
		translation = table[(unsigned char)c];
		while (*translation) {
		    retval[pos++] = *translation++;
		}
	    }
	}
	else {
	    /* Decode 'B' encoding */
	    p = encoding+3;
	    while (p < end) {
		if (pos + MAXTRANSLATION*3 >= alloced) {
		    alloced += GROWSIZE;
		    retval = xrealloc(retval, alloced);
		}
		c1 = CHAR64(p[0]);
		if (c1 == -1) break;
		c2 = CHAR64(p[1]);
		if (c2 == -1) break;
		translation = table[(unsigned char)((c1<<2) | ((c2&0x30)>>4))];
		while (*translation) {
		    retval[pos++] = *translation++;
		}

		c3 = CHAR64(p[2]);
		if (c3 == -1) break;
		translation = table[(unsigned char)(((c2&0XF) << 4) | ((c3&0x3C) >> 2))];
		while (*translation) {
		    retval[pos++] = *translation++;
		}

		c4 = CHAR64(p[3]);
		if (c4 == -1) break;
		translation = table[(unsigned char)(((c3&0x03) <<6) | c4)];
		while (*translation) {
		    retval[pos++] = *translation++;
		}

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
    retval[pos] = '\0';
    return retval;
}

/*
 * Compile the pattern 's' and return a pointer to the compiled form
 */
comp_pat *
charset_compilepat(s)
char *s;
{
    comp_pat *pat;
    int i, len;

    pat = (comp_pat *)xmalloc(PATSIZE * sizeof(comp_pat));
    PATLEN(pat) = len = strlen(s);
    if (len) PATLASTCHAR(pat) = (unsigned char)s[len-1];
    for (i=0; i<256; i++) pat[i] = len;
    for (i=0; i<len; i++) {
	pat[(unsigned char)s[i]] = len-i-1;
    }
    return pat;
}

/*
 * Free the compiled pattern 'pat'
 */
void
charset_freepat(pat)
comp_pat *pat;
{
    free((char *)pat);
}

/*
 * Search for the string 'substr', with compiled pattern 'pat'
 * in the string 's', with length 'len'.  Return nonzero if match
 */
int
charset_searchstring(substr, pat, s, len)
char *substr;
comp_pat *pat;
char *s;
int len;
{
    int i, j, large;
    
    i = PATLEN(pat) - 1;
    if (i < 0) return 1;
    pat[PATLASTCHAR(pat)] = large = len + i + 2;
    for (;;) {
	/* Inner loop -- scan until last char match or end of string */
	while (i < len) {
	    i += pat[(unsigned char)s[i]];
	}

	/* End of string */
	if (i < large) return 0;

	/* Last char match--back up and do compare */
	i -= large + 1;
	j = PATLEN(pat) - 2;
	while (j >= 0 && s[i] == substr[j]) {
	    i--;
	    j--;
	}
	if (j < 0) return 1;	/* Found match */
	if (pat[(unsigned char)s[i]] == large ||
	    pat[(unsigned char)s[i]] < PATLEN(pat)-j) {
	    i += PATLEN(pat) - j;
	}
	else {
	    i += pat[(unsigned char)s[i]];
	}
    }
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
static const unsigned char (*decodetable)[4];	/* Charset table to convert decoded data
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
charset_searchfile(substr, pat, msgfile, mapnl, len, charset, encoding)
char *substr;
comp_pat *pat;
FILE *msgfile;
int mapnl;
int len;
int charset;
int encoding;
{
    int substrlen = PATLEN(pat);
    char *buf, smallbuf[4096];
    int bufsize;
    int n;
    int i, j, large;
    
    /* Initialize character set mapping */
    if (charset < 0 || charset >= NUM_CHARSETS) return 0;
    decodetable = charset_table[charset].table[0];
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

    if (substrlen == 0) return 1;

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
    i = substrlen - 1;
    pat[PATLASTCHAR(pat)] = large = bufsize + i + 2;
    for (;;) {
	/* Inner loop -- scan until last char match or end of buffer */
	while (i < n) {
	    i += pat[(unsigned char)buf[i]];
	}

	/* End of buffer */
	if (i < large) {
	    /* Read in more stuff */
	    j = i-n;
	    strncpy(buf, buf+i-(substrlen-1), substrlen-1-j);
	    n = charset_readconvert(buf+substrlen-1-j,
				    bufsize-substrlen+1+j);
	    i = substrlen-1;
	    if (n > 0) {
		n += i-j;
		continue;
	    }
	    if (buf != smallbuf) free(buf);
	    return 0;
	}

	/* Last char match--back up and do compare */
	i -= large + 1;
	j = PATLEN(pat) - 2;
	while (j >= 0 && buf[i] == substr[j]) {
	    i--;
	    j--;
	}
	if (j < 0) {
	    /* Found match */
	    if (buf != smallbuf) free(buf);
	    return 1;
	}
	if (pat[(unsigned char)buf[i]] == large ||
	    pat[(unsigned char)buf[i]] < PATLEN(pat)-j) {
	    i += PATLEN(pat) - j;
	}
	else {
	    i += pat[(unsigned char)buf[i]];
	}
    }
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
    const unsigned char *translation;
    int len;

    if (decodeleft && decodestart != 0) {
	bcopy(decodebuf+decodestart, decodebuf, decodeleft);
    }
    decodestart = 0;

    decodeleft += (*rawproc)(decodebuf+decodeleft, sizeof(decodebuf)-decodeleft);

    while (decodeleft) {
	if (MAXTRANSLATION > size) {
	    return retval;
	}
	translation = decodetable[(unsigned char)(decodebuf[decodestart])];
	decodestart++;
	decodeleft--;
	while (*translation) {
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
