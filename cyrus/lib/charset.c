/* charset.c -- International character set support
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 */
/* $Id: charset.c,v 1.39.4.2 2002/12/27 14:07:13 ken3 Exp $
 */
#include <config.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "assert.h"
#include "charset.h"
#include "xmalloc.h"
#include "chartable.h"
#include "util.h"

extern const unsigned char chartables_long_translations[];
extern const int charset_max_translation;
extern const unsigned char chartables_unicode_block[256];
extern const unsigned char chartables_unicode[][256][4];
extern const unsigned char chartables_us_ascii[][256][4];
extern const struct charset chartables_charset_table[];
extern const int chartables_num_charsets;

struct decode_state {
    const unsigned char (*curtable)[256][4];
    const unsigned char (*lasttable)[256][4];
    const unsigned char (*initialtable)[256][4];
    unsigned utfcode;
    unsigned num_bits;
    unsigned b64_value;
};
#define START(state,table) \
    ((state).curtable = (state.initialtable) = (table)); \
    ((state).lasttable = NULL); \
    ((state).utfcode = 0); \
    ((state).num_bits = 0); \
    ((state).b64_value = 0);


static int xlate(int index, char *to);
static int writeutf8(unsigned utfcode, char *to);

#define TRANSLATE(state,c,ptr,idx) \
{ \
    unsigned char _ch; \
    const unsigned char *_translation = (state).curtable[0][(unsigned char)(c) & 0xff]; \
    for (;;) { \
	switch (_ch = *_translation++) { \
	case JSR: \
	    (state).lasttable = (state).curtable; \
	    /* FALL THROUGH */ \
	case JMP: \
	    (state).curtable = ((state).initialtable + \
	      (_translation[0]<<8) + (_translation[1])); \
	    break; \
 \
	case RET: \
	    (state).curtable = (state).lasttable; \
	    /* FALL THROUGH */ \
	case END: \
	    break; \
\
	case U7F: \
	    (state).b64_value = 0; \
	    (state).num_bits = 0; \
	    (state).curtable = ((state).initialtable + 1); \
	    /* FALL THROUGH */ \
	case U7N: \
	    (state).b64_value <<= 6; \
	    (state).b64_value += index_64[(unsigned char)(c) & 0xff]; \
	    (state).num_bits += 6; \
	    if ((state).num_bits >= 16) { \
		(state).num_bits -= 16; \
		(state).utfcode = \
		    ((state).b64_value >> (state).num_bits) & 0x7fff; \
		idx += writeutf8((state).utfcode, ptr+idx); \
	    } \
	    break; \
\
	case U83: \
	    (state).lasttable = (state).curtable; \
	    (state).utfcode = (c & 0x0f) << 12; \
	    (state).curtable = ((state).initialtable + 1); \
	    break; \
\
	case U83_2: \
	    (state).utfcode += (c & 0x3f) << 6; \
	    (state).curtable = ((state).initialtable + 2); \
	    break; \
\
	case U83_3: \
	    (state).utfcode += (c & 0x03f); \
	    (state).curtable = (state).initialtable; \
	    idx += writeutf8((state).utfcode, ptr+idx); \
	    break; \
 \
	case XLT: \
	    idx += xlate((_translation[0]<<8) + (_translation[1]), ptr+idx); \
	    _translation += 2; /* next translation is a RET or END */ \
	    continue; \
 \
	default: \
	    (ptr)[(idx)++] = _ch; \
	    continue; \
	} \
	break; \
    } \
}

/* for a comp_pat, ascii[0x80] == 0 if there are any non-ascii characters
   in the pattern */
struct comp_pat_s {
    int pat[256];		/* boyer-moore skip table */
    int ascii[256];		/* case-mapped version of table */
    int patlen;
    int patlastchar;		/* last character in the pattern */
    int patotherlastchar;	/* case-flip of the last character */
};

#define PATASCII(pat) (pat+256)
#define PATLEN(pat) ((pat)[512])
#define PATLASTCHAR(pat) ((pat)[513]) /* last character in the pattern */
#define PATOTHERLASTCHAR(pat) ((pat)[514]) /* case-flip of the pattern */
#define PATSIZE 515

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

#define USASCII(c) (chartables_us_ascii[0][(unsigned char)(c)][0])

/*
 * Lookup the character set 'name'.  Returns the character set number
 * or -1 if there is no matching character set.
 */
int charset_lookupname(const char *name)
{
    int i;

    for (i=0; i<chartables_num_charsets; i++) {
	if (!strcasecmp(name, chartables_charset_table[i].name)) return i;
    }
    return -1;
}

/*
 * Convert the string 's' in the character set numbered 'charset'
 * into canonical searching form.  Decodes into 'retval', which 
 * must be reallocable and currently at least size 'alloced'.
 */
char *charset_convert(const char *s, int charset, char *retval,
    int alloced)
{
    int pos = 0;
    struct decode_state state;

    if (!s) return 0;

    if (charset < 0 || charset >= chartables_num_charsets) return xstrdup(EMPTY_STRING);

    START(state,chartables_charset_table[charset].table);
    
    if (!alloced) {
	alloced = GROWSIZE;
	retval = xmalloc(alloced);
    }
    *retval = '\0';

    while (*s) {
	if (pos + charset_max_translation >= alloced) {
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
 * Decode 1522-strings in 's'.  It writes the decoded string to 'retval',
 * calling realloc() as needed. (Thus retval may be NULL.) Returns retval,
 * contining 's' in canonical searching form.
 */
char *charset_decode1522(const char *s, char *retval, int alloced)
{
    int eatspace = 0;
    const char *start, *endcharset, *encoding, *end;
    const char *p;
    int i, c, c1, c2, c3, c4;
    struct decode_state state;
    int pos = 0;
    int len;

    if (!s) return 0;

    START(state,chartables_charset_table[0].table);    /* just for msvc lint */
    start = s;
    while ((start = (const char*) strchr(start, '=')) != 0) {
	start++;
	if (*start != '?') continue;
	encoding = (const char*) strchr(start+1, '?');
	if (!encoding) continue;
	endcharset =
	    (const char*) strchr(start+1, '*'); /* Language code delimiter */
	if (!endcharset || endcharset > encoding) endcharset = encoding;
	if (encoding[1] != 'b' && encoding[1] != 'B' &&
	    encoding[1] != 'q' && encoding[1] != 'Q') continue;
	if (encoding[2] != '?') continue;
	end = (const char*) strchr(encoding+3, '?');
	if (!end || end[1] != '=') continue;

	/*
	 * We have recognized a valid 1522-word.
	 * Copy over leading text, unless it consists entirely of 
	 * whitespace and is between two 1522-words.
	 */
	if (eatspace) {
	    for (p = s; p < (start-1) && isspace((int) *p); p++);
	    if (p < (start-1)) eatspace = 0;
	}
	if (!eatspace) {
	    len = start - s - 1;
	    if (pos + len >= alloced) {
		alloced += len + GROWSIZE;
		retval = xrealloc(retval, alloced);
	    }
	    while (len--) {
		c = USASCII(*s);
		if (c != END) retval[pos++] = (char)c;
		s++;
	    }
	}

	/*
	 * Get the 1522-word's character set
	 */
	start++;
	for (i=0; i<chartables_num_charsets; i++) {
	    if ((int)strlen(chartables_charset_table[i].name) == endcharset-start &&
		!strncasecmp(start, chartables_charset_table[i].name, endcharset-start)) {
		START(state,chartables_charset_table[i].table);
		break;
	    }
	}

	if (i == chartables_num_charsets) {
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
			c = (char)((c << 4) + i);
		    }
		}
		else if (c == '_') c = ' ';

		if (pos + charset_max_translation >= alloced) {
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
		if (pos + charset_max_translation*3 >= alloced) {
		    alloced += GROWSIZE;
		    retval = xrealloc(retval, alloced);
		}
		c1 = CHAR64(p[0]);
		if (c1 == XX) break;
		c2 = CHAR64(p[1]);
		if (c2 == XX) break;
		TRANSLATE(state,((c1<<2) | ((c2&0x30)>>4)), retval, pos);

		c3 = CHAR64(p[2]);
		if (c3 == XX) break;
		TRANSLATE(state,(((c2&0XF)<<4) | ((c3&0x3C)>>2)), retval, pos);

		c4 = CHAR64(p[3]);
		if (c4 == XX) break;
		TRANSLATE(state,(((c3&0x03) <<6) | c4), retval, pos);

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
	c = USASCII(*s);
	if (c != END) retval[pos++] = (char)c;
	s++;
    }
    retval[pos] = '\0';
    return retval;
}

/*
 * Compile the pattern 's' and return a pointer to the compiled form
 */
comp_pat *charset_compilepat(const char *s)
{
    comp_pat *pat;
    int i, c, len;

    pat = (comp_pat *)xmalloc(PATSIZE * sizeof(comp_pat));
    PATLEN(pat) = len = strlen(s);
    if (len) {
	PATLASTCHAR(pat) = c = (unsigned char)s[len-1];
	if (isupper(c)) PATOTHERLASTCHAR(pat) = TOLOWER(c);
	else if (islower(c)) PATOTHERLASTCHAR(pat) = TOUPPER(c);
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
void charset_freepat(comp_pat *pat)
{
    free((char *)pat);
}

/*
 * Search for the string 'substr', with compiled pattern 'pat'
 * in the string 's', with length 'len'.  Return nonzero if match
 */
int charset_searchstring(const char *substr, comp_pat *pat,
    const char *s, int len)
{
    int i, j, large;
    
    assert(pat != NULL);
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

static int xlate(int index, char *to) {
    const unsigned char *from = chartables_long_translations + index;
    int i = 0;

    while ((*to++ = *from++) != END) i++;
    return i;
}

static int writeutf8(unsigned utfcode, char *to)
{
    int table = chartables_unicode_block[utfcode>>8];
    int idx = 0;
    struct decode_state state;

    if (table == 255) {
	/* No translations in this block */
	if (utfcode > 0x7ff) {
	    to[0] = (char)(0xE0 + (utfcode >> 12));
	    to[1] = (char)(0x80 + ((utfcode >> 6) & 0x3f));
	    to[2] = (char)(0x80 + (utfcode & 0x3f));
	    return 3;
	}
	if (utfcode > 0x7f) {
	    to[0] = (char)(0xC0 + (utfcode >> 6));
	    to[1] = (char)(0x80 + (utfcode & 0x3f));
	    return 2;
	}
	to[0] = (char)utfcode;
	return 1;
    }

    START(state, chartables_unicode + table);
    TRANSLATE(state, (utfcode & 0xff), to, idx);

    return idx;

}

/*
 * The various charset_searchfile() helper functions
 */
struct input_state;
typedef int rawproc_t(struct input_state *state, char *buf, int size);

static int charset_readconvert(struct input_state *state, char *buf, int size);
static rawproc_t charset_readplain;
static rawproc_t charset_readplain_nospc;
static rawproc_t charset_readmapnl;
static rawproc_t charset_readqp;
static rawproc_t charset_readqp_nospc;
static rawproc_t charset_readqpmapnl;
static rawproc_t charset_readbase64;
static rawproc_t charset_readbase64_nospc;

/*
 * State for the various charset_searchfile() helper functions
 */
struct input_state {
    rawproc_t *rawproc;	/* Function to read and transfer-decode data */
    const char *rawbase;	/* Location in mapped file of raw data */
    int rawlen;		/* # bytes raw data left to read from file */
    char decodebuf[2048];	/* Buffer of data deocded, but not converted
				 * into canonical searching form */
    int decodestart, decodeleft; /* Location/count of decoded data */
    struct decode_state decodestate; /* Charset state to convert decoded data
				  * into canonical searching form */
};


/*
 * Search for the string 'substr' in the next 'len' bytes of 
 * 'msg_base'.  If 'mapnl' is nonzero, then LF characters in the file
 * map to CR LF and count as 2 bytes w.r.t. the value of 'len'.
 * 'charset' and 'encoding' specify the character set and 
 * content transfer encoding of the data, respectively.
 * Returns nonzero iff the string was found.
 */
int charset_searchfile(const char *substr, comp_pat *pat,
    const char *msg_base, int mapnl, int len, int charset, int encoding)
{
    int substrlen = PATLEN(pat);
    char *buf, smallbuf[2048];
    int bufsize;
    int n;
    int i, j, large;
    struct input_state state;
    
    /* Initialize character set mapping */
    if (charset < 0 || charset >= chartables_num_charsets) return 0;
    START(state.decodestate, chartables_charset_table[charset].table);
    state.decodeleft = 0;

    /* check for trivial search */
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

    /* Optimized searching of us-ascii, using boyer-moore */
    if (charset == 0) {
	/* Initialize transfer-decoding */
	state.rawbase = msg_base;
	state.rawlen = len;
	/* don't need to special case mapnl since all such chars will
	   be ignored, anyway */
	switch (encoding) {
	case ENCODING_NONE:
	    state.rawproc = charset_readplain_nospc;
	    break;
	    
	case ENCODING_QP:
	    state.rawproc = charset_readqp_nospc;
	    break;
	    
	case ENCODING_BASE64:
	    state.rawproc = charset_readbase64_nospc;
	    /* XXX have to have nl-mapping base64 in order to
	     * properly count \n as 2 raw characters
	     */
	    break;
	    
	default:
	    /* Don't know encoding--nothing can match */
	    return 0;
	}
	
	if (PATASCII(pat)[0x80] == 0) {
	    /* 8-bit chars in pattern--search must fail */
	    if (buf != smallbuf) free(buf);
	    return 0;
	}

	n = (*state.rawproc)(&state, buf, bufsize);
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
		n = (*state.rawproc)(&state, buf+substrlen-1-j, bufsize-substrlen+1+j);
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

    /* Initialize transfer-decoding */
    state.rawbase = msg_base;
    state.rawlen = len;
    switch (encoding) {
    case ENCODING_NONE:
	state.rawproc = mapnl ? charset_readmapnl : charset_readplain;
	break;

    case ENCODING_QP:
	state.rawproc = mapnl ? charset_readqpmapnl : charset_readqp;
	break;

    case ENCODING_BASE64:
	state.rawproc = charset_readbase64;
	/* XXX have to have nl-mapping base64 in order to
	 * properly count \n as 2 raw characters
	 */
	break;

    default:
	/* Don't know encoding--nothing can match */
	return 0;
    }

    n = charset_readconvert(&state, buf, bufsize);
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
	    n = charset_readconvert(&state, buf+substrlen-1-j,
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

/* This is based on charset_searchfile above. */
int charset_extractfile(index_search_text_receiver_t receiver,
    void* rock, int uid, const char *msg_base, int mapnl, int len, int charset,
    int encoding) {
    char buf[2048];
    int n;
    struct input_state state;
    
    /* Initialize character set mapping */
    if (charset < 0 || charset >= chartables_num_charsets) return 0;
    START(state.decodestate, chartables_charset_table[charset].table);
    state.decodeleft = 0;

    /* Initialize transfer-decoding */
    state.rawbase = msg_base;
    state.rawlen = len;
    switch (encoding) {
    case ENCODING_NONE:
	state.rawproc = mapnl ? charset_readmapnl : charset_readplain;
	break;

    case ENCODING_QP:
	state.rawproc = mapnl ? charset_readqpmapnl : charset_readqp;
	break;

    case ENCODING_BASE64:
	state.rawproc = charset_readbase64;
	/* XXX have to have nl-mapping base64 in order to
	 * properly count \n as 2 raw characters
	 */
	break;

    default:
	/* Don't know encoding--nothing can match */
	return 0;
    }

    /* We don't need to do anything tricky. Just read and convert each block of the
       text, then hand the converted text down to the receiver. */
    do {
      n = charset_readconvert(&state, buf, sizeof(buf));
      if (n > 0) {
        receiver(uid, SEARCHINDEX_PART_BODY,
                 SEARCHINDEX_CMD_APPENDPART, buf, n, rock);
      }
    } while (n > 0);

    return 1;
}

/*
 * Helper function to read at most 'size' bytes of converted
 * (into canonical searching format) data into 'buf'.  Returns
 * the number of converted bytes, or 0 for end-of-data.
 */
static int charset_readconvert(struct input_state *state, char *buf, int size)
{
    int retval = 0;

    if (state->decodeleft && state->decodestart != 0) {
	memmove(state->decodebuf, state->decodebuf+state->decodestart,
		state->decodeleft);
    }
    state->decodestart = 0;

    state->decodeleft += (*state->rawproc)(state,
					   state->decodebuf+state->decodeleft,
					   sizeof(state->decodebuf)-state->decodeleft);

    while (state->decodeleft) {
	if (retval + charset_max_translation > size) {
	    return retval;
	}
	TRANSLATE(state->decodestate, state->decodebuf[state->decodestart], buf, retval);
	state->decodestart++;
	state->decodeleft--;
    }
    return retval;
}
    
/*
 * Helper function to read at most 'size' bytes of trivial
 * transfer-decoded data into 'buf'.  Returns the number of decoded
 * bytes, or 0 for end-of-data.
 */
static int charset_readplain(struct input_state *state, char *buf, int size)
{
    if (size > state->rawlen) size = state->rawlen;
    if (!size) return 0;

    memcpy(buf, state->rawbase, size);
    state->rawlen -= size;
    state->rawbase += size;

    return size;
}

/*
 * Helper function to read at most 'size' bytes of trivial
 * transfer-decoded data into 'buf'.  Removes any US-ASCII whitespace.
 * Returns the number of decoded bytes, or 0 for end-of-data.  
 */
static int charset_readplain_nospc(struct input_state *state, 
				   char *buf, int size)
{
    int i;

    for (i = 0; i < size; i++) {
	/* remove any whitespace at the beginning of rawbase */
	while (state->rawlen > 0 && USASCII(*state->rawbase) == END) {
	    state->rawlen--;
	    state->rawbase++;
	}

	if (state->rawlen == 0) break;

	/* copy a char */
	buf[i] = *state->rawbase++;
	state->rawlen--;
    }

    return i;
}

/*
 * Helper function to read at most 'size' bytes of trivial newline-mapped
 * transfer-decoded data into 'buf'.  Returns the number of decoded
 * bytes, or 0 for end-of-data.
 */
static int charset_readmapnl(struct input_state *state, char *buf, int size)
{
    int retval = 0;
    char c;

    while (size && state->rawlen > 0) {
	c = *state->rawbase;
	if (c == '\n') {
	    if (size < 2) {
		return retval;
	    }
	    *buf++ = '\r';
	    retval++;
	    size--;
	    state->rawlen--;
	}
	*buf++ = c;
	state->rawbase++;
	state->rawlen--;
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
static int charset_readqp(struct input_state *state, char *buf, int size)
{
    int retval = 0;
    int c, c1, c2;
    const char *nextline, *endline;

    nextline = endline = state->rawbase;

    while (size && state->rawlen) {
	if (state->rawbase >= nextline) {
	    /* Ignore trailing whitespace at end of line */

	    nextline =
		(const char*) memchr(state->rawbase+1, '\r', state->rawlen-1);
	    if (!nextline) nextline = state->rawbase + state->rawlen;
	    endline = nextline;
	    while (endline > state->rawbase &&
		   (endline[-1] == ' ' || endline[-1] == '\t')) {
		endline--;
	    }
	}
	if (state->rawbase >= endline) {
	    state->rawbase += nextline - endline;
	    state->rawlen -= nextline - endline;
	    continue;
	}

	c = state->rawbase[0];
	if (c == '=') {
	    if (state->rawlen < 3) {
		return retval;
	    }
	    c1 = state->rawbase[1];
	    c2 = state->rawbase[2];
	    state->rawbase += 3;
	    state->rawlen -= 3;
	    c1 = HEXCHAR(c1);
	    c2 = HEXCHAR(c2);
	    /* Following line also takes care of soft line breaks */
	    if (c1 == XX && c2 == XX) continue;
	    *buf++ = (char)((c1 << 4) + c2);
	    retval++;
	    size--;
	}
	else {
	    state->rawbase++;
	    state->rawlen--;
	    *buf++ = (char)c;
	    retval++;
	    size--;
	}
    }
    return retval;
}

/*
 * Helper function to read at most 'size' bytes of quoted-printable
 * transfer-decoded data into 'buf'.  Returns the number of decoded
 * bytes, or 0 for end-of-data.  Removes any US-ASCII whitespace.
 * Since it just throws out \r's anyway, it's simplier than paying
 * attention to them 
 */
static int charset_readqp_nospc(struct input_state *state, char *buf, int size)
{
    int retval = 0;
    int c, c1, c2;
    char dec;
    const char *nextline, *endline;

    nextline = endline = state->rawbase;

    while (size && state->rawlen) {
	if (state->rawbase >= nextline) {
	    /* Ignore trailing whitespace at end of line */

	    nextline =
		(const char*) memchr(state->rawbase+1, '\n', state->rawlen-1);
	    if (!nextline) nextline = state->rawbase + state->rawlen;
	    endline = nextline;
	    while (endline > state->rawbase && (USASCII(endline[-1]) == END)) {
		endline--;
	    }
	}
	if (state->rawbase >= endline) {
	    state->rawbase += nextline - endline;
	    state->rawlen -= nextline - endline;
	    continue;
	}

	c = state->rawbase[0];
	if (c == '=') {
	    if (state->rawlen < 3) {
		return retval;
	    }
	    c1 = state->rawbase[1];
	    c2 = state->rawbase[2];
	    state->rawbase += 3;
	    state->rawlen -= 3;
	    c1 = HEXCHAR(c1);
	    c2 = HEXCHAR(c2);
	    /* Following line also takes care of soft line breaks */
	    if (c1 == XX && c2 == XX) continue;
	    dec = (char)((c1 << 4) + c2);
	    if (USASCII(dec) != END) {
		/* non-whitespace, take it */
		*buf++ = (char)((c1 << 4) + c2);
		retval++;
		size--;
	    }
	}
	else {
	    state->rawbase++;
	    state->rawlen--;
	    if (USASCII(c) != END) {
		/* non-whitespace, grab it */
		*buf++ = (char)c;
		retval++;
		size--;
	    }
	}
    }
    return retval;
}

/*
 * Helper function to read at most 'size' bytes of QP newline-mapped
 * transfer-decoded data into 'buf'.  Returns the number of decoded
 * bytes, or 0 for end-of-data.
 */
static int charset_readqpmapnl(struct input_state *state, char *buf, int size)
{
    int retval = 0;
    int c, c1, c2;
    const char *nextline, *endline;

    nextline = endline = state->rawbase;

    while (size && state->rawlen > 0) {
	if (state->rawbase >= nextline) {
	    /* Ignore trailing whitespace at end of line */

	    nextline = (const char*)
		memchr(state->rawbase+1, '\n', state->rawlen - 1);
	    if (!nextline) nextline = state->rawbase + state->rawlen;
	    endline = nextline;
	    while (endline > state->rawbase &&
		   (endline[-1] == ' ' || endline[-1] == '\t')) {
		endline--;
	    }
	}
	if (state->rawbase >= endline) {
	    state->rawbase += nextline - endline;
	    state->rawlen -= nextline - endline;
	    continue;
	}

	c = state->rawbase[0];
	if (c == '=') {
	    if (state->rawbase+1 == endline) {
		state->rawbase = nextline + 1;
		state->rawlen -= 3 + (nextline - endline);

		continue;
	    }
	    if (state->rawlen < 3) {
		return retval;
	    }
	    c1 = state->rawbase[1];
	    c2 = state->rawbase[2];
	    state->rawbase += 3;
	    state->rawlen -= 3;
	    if (c2 == '\n') state->rawlen--;
	    c1 = HEXCHAR(c1);
	    c2 = HEXCHAR(c2);
	    if (c1 == XX && c2 == XX) continue;
	    *buf++ = (char)((c1 << 4) + c2);
	    retval++;
	    size--;
	}
	else if (c == '\n') {
	    if (size < 2) {
		return retval;
	    }
	    state->rawbase++;
	    state->rawlen -= 2;
	    *buf++ = '\r';
	    *buf++ = '\n';
	    retval += 2;
	    size -= 2;
	}
	else {
	    state->rawbase++;
	    state->rawlen--;
	    *buf++ = (char)c;
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
static int charset_readbase64(struct input_state *state, char *buf, int size)
{
    int retval = 0;
    int c1, c2, c3, c4;

    while (size >= 3 && state->rawlen) {
	do {
	    c1 = *state->rawbase++;
	    state->rawlen--;
	    if (c1 == '=') {
		state->rawlen = 0;
		return retval;
	    }
	} while (state->rawlen && CHAR64(c1) == XX);
	if (!state->rawlen) {
	    return retval;
	}

	do {
	    c2 = *state->rawbase++;
	    state->rawlen--;
	    if (c2 == '=') {
		state->rawlen = 0;
		return retval;
	    }
	} while (state->rawlen && CHAR64(c2) == XX);
	if (!state->rawlen) {
	    return retval;
	}

	do {
	    c3 = *state->rawbase++;
	    state->rawlen--;
	    if (c3 == '=') {
		*buf++ = (char)((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
		retval++;
		state->rawlen = 0;
		return retval;
	    }
	} while (state->rawlen && CHAR64(c3) == XX);
	if (!state->rawlen) {
	    return retval;
	}

	do {
	    c4 = *state->rawbase++;
	    state->rawlen--;
	    if (c4 == '=') {
		*buf++ = (char)((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
		*buf++ = (char)(((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
		retval += 2;
		state->rawlen = 0;
		return retval;
	    }
	} while (state->rawlen && CHAR64(c4) == XX);
	if (CHAR64(c4) == XX) {
	    return retval;
	}

	*buf++ = (char)((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
	*buf++ = (char)(((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
	*buf++ = (char)(((CHAR64(c3)&0x3)<<6) | CHAR64(c4));
	retval += 3;
	size -= 3;
    }
    return retval;
}

/*
 * Helper function to read at most 'size' bytes of base64
 * transfer-decoded data into 'buf'.  Returns the number of decoded
 * bytes, or 0 for end-of-data.  Removes any US-ASCII whitespace.
 */
static int charset_readbase64_nospc(struct input_state *state, 
				    char *buf, int size)
{
    int retval = 0;
    int c1, c2, c3, c4;
    char dec;

    while (size >= 3 && state->rawlen) {
	do {
	    c1 = *state->rawbase++;
	    state->rawlen--;
	    if (c1 == '=') {
		state->rawlen = 0;
		return retval;
	    }
	} while (state->rawlen && CHAR64(c1) == XX);
	if (!state->rawlen) {
	    return retval;
	}

	do {
	    c2 = *state->rawbase++;
	    state->rawlen--;
	    if (c2 == '=') {
		state->rawlen = 0;
		return retval;
	    }
	} while (state->rawlen && CHAR64(c2) == XX);
	if (!state->rawlen) {
	    return retval;
	}

	do {
	    c3 = *state->rawbase++;
	    state->rawlen--;
	    if (c3 == '=') {
		dec = (char)((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
		if (USASCII(dec) != END) {
		    *buf++ = dec;
		    retval++;
		}
		state->rawlen = 0;
		return retval;
	    }
	} while (state->rawlen && CHAR64(c3) == XX);
	if (!state->rawlen) {
	    return retval;
	}

	do {
	    c4 = *state->rawbase++;
	    state->rawlen--;
	    if (c4 == '=') {
		dec = (char)((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
		if (USASCII(dec) != END) {
		    *buf++ = dec;
		    retval++;
		}
		dec = (char)(((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
		if (USASCII(dec) != END) {
		    *buf++ = dec;
		    retval++;
		}
		state->rawlen = 0;
		return retval;
	    }
	} while (state->rawlen && CHAR64(c4) == XX);
	if (CHAR64(c4) == XX) {
	    return retval;
	}

	dec  = (char)((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
	if (USASCII(dec) != END) {
	    *buf++ = dec;
	    retval++;
	    size--;
	}
	dec = (char)(((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
	if (USASCII(dec) != END) {
	    *buf++ = dec;
	    retval++;
	    size--;
	}
	dec = (char)(((CHAR64(c3)&0x3)<<6) | CHAR64(c4));
	if (USASCII(dec) != END) {
	    *buf++ = dec;
	    retval++;
	    size--;
	}
    }
    return retval;
}
