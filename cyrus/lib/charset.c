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
#include "util.h"
#include "charset.h"
#include "xmalloc.h"

#define JSR 'T'
#define JMP 'U'
#define RET 'V'
#define END 'W'
#include "chartables.h"

#define MAXTRANSLATION 3
struct state {
    const unsigned char (*curtable)[256][4];
    const unsigned char (*lasttable)[256][4];
    const unsigned char (*initialtable)[256][4];
};
#define START(state,table) \
((state).curtable = (state.initialtable) = (table))

#define TRANSLATE(state,c,ptr,idx) \
{ \
    int _ch; \
    unsigned char *_translation = (state).curtable[0][(unsigned char)(c)]; \
    for (;;) { \
	switch (_ch = *_translation++) { \
	case JSR: \
	    (state).lasttable = (state).curtable; \
	    /* FALL THROUGH */ \
	case JMP: \
	    (state).curtable = (state).initialtable + \
	      (_translation[0]<<8) + (_translation[1]); \
	    break; \
 \
	case RET: \
	    (state).curtable = (state).lasttable; \
	    /* FALL THROUGH */ \
	case END: \
	    break; \
 \
	default: \
	    (ptr)[(idx)++] = _ch; \
	    continue; \
	} \
	break; \
    } \
}

struct charset {
    char *name;
    const unsigned char (*table)[256][4];
};

#define PATASCII(pat) (pat+256)
#define PATLEN(pat) ((pat)[512])
#define PATLASTCHAR(pat) ((pat)[513])
#define PATOTHERLASTCHAR(pat) ((pat)[514])
#define PATSIZE 515

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
    { "iso-2022-jp", iso_2022_jp },
};
#define NUM_CHARSETS (sizeof(charset_table)/sizeof(*charset_table))

#define GROWSIZE 100

#define XX 127
/*
 * Table for decoding hexadecimal in quoted-printable
 */
static const char index_hex[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
     0, 1, 2, 3,  4, 5, 6, 7,  8, 9,XX,XX, XX,XX,XX,XX,
    XX,10,11,12, 13,14,15,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,10,11,12, 13,14,15,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};
#define HEXCHAR(c)  (index_hex[(unsigned char)(c)])

/*
 * Table for decoding base64
 */
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
    struct state state;

    if (!s) return 0;
    if (charset < 0 || charset >= NUM_CHARSETS) return EMPTY_STRING;

    START(state,charset_table[charset].table);
    
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
	TRANSLATE(state, *s, retval, pos);
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
    struct state state;
    static char *retval = 0;
    static int alloced = 0;
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
		START(state,charset_table[i].table);
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
		    if (c == XX || i == XX) {
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
		TRANSLATE(state, c, retval, pos);
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
		if (c1 == XX) break;
		c2 = CHAR64(p[1]);
		if (c2 == XX) break;
		TRANSLATE(state,(c1<<2) | ((c2&0x30)>>4), retval, pos);

		c3 = CHAR64(p[2]);
		if (c3 == XX) break;
		TRANSLATE(state,((c2&0XF)<<4) | ((c3&0x3C)>>2), retval, pos);

		c4 = CHAR64(p[3]);
		if (c4 == XX) break;
		TRANSLATE(state,((c3&0x03) <<6) | c4, retval, pos);

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
    int i, c, len;

    pat = (comp_pat *)xmalloc(PATSIZE * sizeof(comp_pat));
    PATLEN(pat) = len = strlen(s);
    if (len) {
	PATLASTCHAR(pat) = c = (unsigned char)s[len-1];
	if (isupper(c)) PATOTHERLASTCHAR(pat) = tolower(c);
	else if (islower(c)) PATOTHERLASTCHAR(pat) = toupper(c);
	else PATOTHERLASTCHAR(pat) = c;
    }
    for (i=0; i<512; i++) pat[i] = len;
    for (i=0; i<len; i++) {
	c = (unsigned char)s[i];
	PATASCII(pat)[c] = pat[c] = len-i-1;
	if (c & 0x80) PATASCII(pat)[0x80] = 0;
    }
    for (i='A'; i<='Z'; i++) {
	PATASCII(pat)[i] = PATASCII(pat)[i-'A'+'a'];
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
static char *rawbase;		/* Location in mapped file of raw data */
static int rawlen;		/* # bytes raw data left to read from file */
static char decodebuf[4096];	/* Buffer of data deocded, but not converted
				 * into canonical searching form */
static int decodestart, decodeleft; /* Location/count of decoded data */
static struct state decodestate; /* Charset state to convert decoded data
				  * into canonical searching form */

/*
 * Search for the string 'substr' in the next 'len' bytes of 
 * 'msg_base'.  If 'mapnl' is nonzero, then LF characters in the file
 * map to CR LF and count as 2 bytes w.r.t. the value of 'len'.
 * 'charset' and 'encoding' specify the character set and 
 * content transfer encoding of the data, respectively.
 * Returns nonzero iff the string was found.
 */
int
charset_searchfile(substr, pat, msg_base, mapnl, len,
		   charset, encoding)
char *substr;
comp_pat *pat;
char *msg_base;
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
    START(decodestate, charset_table[charset].table);
    decodeleft = 0;

    /* Initialize transfer-decoding */
    rawbase = msg_base;
    rawlen = len;
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

    /* Optimized searching of us-ascii */
    if (charset == 0) {
	if (PATASCII(pat)[0x80] == 0) {
	    /* 8-bit chars in pattern--search must fail */
	    if (buf != smallbuf) free(buf);
	    return 0;
	}

	n = (*rawproc)(buf, bufsize);
	if (n < substrlen) {
	    if (buf != smallbuf) free(buf);
	    return 0;
	}
	i = substrlen - 1;
	PATASCII(pat)[PATLASTCHAR(pat)] =
	  PATASCII(pat)[PATOTHERLASTCHAR(pat)] = large = bufsize + i + 2;

	for (;;) {
	    /* Inner loop -- scan until last char match or end of buffer */
	    while (i < n) {
		i += PATASCII(pat)[(unsigned char)buf[i]];
	    }

	    /* End of buffer */
	    if (i < large) {
		/* Read in more stuff */
		j = i-n;
		strncpy(buf, buf+i-(substrlen-1), substrlen-1-j);
		n = (*rawproc)(buf+substrlen-1-j, bufsize-substrlen+1+j);
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
	    while (j >= 0 && TOLOWER(buf[i]) == TOLOWER(substr[j])) {
		i--;
		j--;
	    }
	    if (j < 0) {
		/* Found match */
		if (buf != smallbuf) free(buf);
		return 1;
	    }
	    if (PATASCII(pat)[(unsigned char)buf[i]] == large ||
		PATASCII(pat)[(unsigned char)buf[i]] < PATLEN(pat)-j) {
		i += PATLEN(pat) - j;
	    }
	    else {
		i += PATASCII(pat)[(unsigned char)buf[i]];
	    }
	}
	/* NOTREACHED */
    }

    /* Do the (generalized) search */
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

    if (decodeleft && decodestart != 0) {
	bcopy(decodebuf+decodestart, decodebuf, decodeleft);
    }
    decodestart = 0;

    decodeleft += (*rawproc)(decodebuf+decodeleft, sizeof(decodebuf)-decodeleft);

    while (decodeleft) {
	if (retval + MAXTRANSLATION > size) {
	    return retval;
	}
	TRANSLATE(decodestate, decodebuf[decodestart], buf, retval);
	decodestart++;
	decodeleft--;
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
    if (size > rawlen) size = rawlen;
    if (!size) return 0;

    memcpy(buf, rawbase, size);
    rawlen -= size;
    rawbase += size;

    return size;
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
    int c;

    while (size && rawlen > 0) {
	c = *rawbase;
	if (c == '\n') {
	    if (size < 2) {
		return retval;
	    }
	    *buf++ = '\r';
	    retval++;
	    size--;
	    rawlen--;
	}
	*buf++ = c;
	rawbase++;
	rawlen--;
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
    int c, c1, c2;
    char *nextline, *endline;

    nextline = endline = rawbase;

    while (size && rawlen) {
	if (rawbase >= nextline) {
	    /* Ignore trailing whitespace at end of line */

	    nextline = memchr(rawbase+1, '\r', rawlen-1);
	    if (!nextline) nextline = rawbase + rawlen;
	    endline = nextline;
	    while (endline > rawbase &&
		   (endline[-1] == ' ' || endline[-1] == '\t')) {
		endline--;
	    }
	}
	if (rawbase >= endline) {
	    rawbase += nextline - endline;
	    rawlen -= nextline - endline;
	    continue;
	}

	c = rawbase[0];
	if (c == '=') {
	    if (rawlen < 3) {
		return retval;
	    }
	    c1 = rawbase[1];
	    c2 = rawbase[2];
	    rawbase += 3;
	    rawlen -= 3;
	    c1 = HEXCHAR(c1);
	    c2 = HEXCHAR(c2);
	    /* Following line also takes care of soft line breaks */
	    if (c1 == XX && c2 == XX) continue;
	    *buf++ = (c1 << 4) + c2;
	    retval++;
	    size--;
	}
	else {
	    rawbase++;
	    rawlen--;
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
    int c, c1, c2;
    char *nextline, *endline;

    nextline = endline = rawbase;

    while (size && rawlen > 0) {
	if (rawbase >= nextline) {
	    /* Ignore trailing whitespace at end of line */

	    nextline = memchr(rawbase+1, '\n', rawlen - 1);
	    if (!nextline) nextline = rawbase + rawlen;
	    endline = nextline;
	    while (endline > rawbase &&
		   (endline[-1] == ' ' || endline[-1] == '\t')) {
		endline--;
	    }
	}
	if (rawbase >= endline) {
	    rawbase += nextline - endline;
	    rawlen -= nextline - endline;
	    continue;
	}

	c = rawbase[0];
	if (c == '=') {
	    if (rawbase+1 == endline) {
		rawbase = nextline + 1;
		rawlen -= 3 + (nextline - endline);

		continue;
	    }
	    if (rawlen < 3) {
		return retval;
	    }
	    c1 = rawbase[1];
	    c2 = rawbase[2];
	    rawbase += 3;
	    rawlen -= 3;
	    if (c2 == '\n') rawlen--;
	    c1 = HEXCHAR(c1);
	    c2 = HEXCHAR(c2);
	    if (c1 == XX && c2 == XX) continue;
	    *buf++ = (c1 << 4) + c2;
	    retval++;
	    size--;
	}
	else if (c == '\n') {
	    if (size < 2) {
		return retval;
	    }
	    rawbase++;
	    rawlen -= 2;
	    *buf++ = '\r';
	    *buf++ = '\n';
	    retval += 2;
	    size -= 2;
	}
	else {
	    rawbase++;
	    rawlen--;
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
    int c1, c2, c3, c4;

    while (size >= 3 && rawlen) {
	do {
	    c1 = *rawbase++;
	    rawlen--;
	    if (c1 == '=') {
		rawlen = 0;
		return retval;
	    }
	} while (rawlen && CHAR64(c1) == XX);
	if (!rawlen) {
	    return retval;
	}

	do {
	    c2 = *rawbase++;
	    rawlen--;
	    if (c2 == '=') {
		rawlen = 0;
		return retval;
	    }
	} while (rawlen && CHAR64(c2) == XX);
	if (!rawlen) {
	    return retval;
	}

	do {
	    c3 = *rawbase++;
	    rawlen--;
	    if (c3 == '=') {
		*buf++ = ((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
		retval++;
		rawlen = 0;
		return retval;
	    }
	} while (rawlen && CHAR64(c3) == XX);
	if (!rawlen) {
	    return retval;
	}

	do {
	    c4 = *rawbase++;
	    rawlen--;
	    if (c4 == '=') {
		*buf++ = ((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
		*buf++ = (((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
		retval += 2;
		rawlen = 0;
		return retval;
	    }
	} while (rawlen && CHAR64(c4) == XX);
	if (CHAR64(c4) == XX) {
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
