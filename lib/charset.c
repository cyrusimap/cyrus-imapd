/* charset.c -- International character set support
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
#include <stdlib.h>
#include <string.h>

#include "charset.h"
#include "xmalloc.h"
#include "chartable.h"
#include "htmlchar.h"
#include "util.h"

#define U_REPLACEMENT	0xfffd

#define unicode_isvalid(c) \
	(!((c >= 0xd800 && c <= 0xdfff) || ((unsigned)c > 0x10ffff)))

char QPSAFECHAR[256] = {
/* control chars are unsafe */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* http://en.wikipedia.org/wiki/Quoted-printable */
/* All printable ASCII characters (decimal values between 33 and 126) */
/* may be represented by themselves, except "=" (decimal 61). */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
/* all high bits are unsafe */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

struct qp_state {
    int isheader;
    int bytesleft;
    unsigned char lastoctet;
};

struct b64_state {
    int bytesleft;
    int codepoint;
};

struct unfold_state {
    int state;
};

struct table_state {
    const struct charmap (*curtable)[256];
    const struct charmap (*initialtable)[256];
    int bytesleft;
    int codepoint;
    int mode;
    int num_bits;
};

struct canon_state {
    int flags;
    int seenspace;
};

struct comp_pat_s {
    int max_start;
    size_t patlen;
};

struct search_state {
    ssize_t *starts;
    int max_start;
    int havematch;
    unsigned char *substr;
    size_t patlen;
    size_t offset;
};

enum html_state {
    HDATA,
    HTAGOPEN,
    HENDTAGOPEN,
    HTAGNAME,
    HSCTAG,
    HTAGPARAMS,
    HCHARACTER,
    HCHARACTER2,
    HCHARACTERHASH,
    HCHARACTERHEX,
    HCHARACTERDEC,
    HSCRIPTDATA,
    HSCRIPTLT,
    HSTYLEDATA,
    HSTYLELT,
    HBOGUSCOMM,
    HMUDECOPEN,
    HCOMMSTART,
    HCOMMSTARTDASH,
    HCOMM,
    HCOMMENDDASH,
    HCOMMEND,
    HCOMMENDBANG
};

struct striphtml_state {
    struct buf name;
#define HBEGIN		(1<<0)
#define HEND		(1<<1)
    unsigned int ends;
    /* state stack */
    int depth;
    enum html_state stack[2];
};

struct convert_rock;

typedef void convertproc_t(struct convert_rock *rock, int c);
typedef void freeconvert_t(struct convert_rock *rock);

struct convert_rock {
    convertproc_t *f;
    freeconvert_t *cleanup;
    struct convert_rock *next;
    void *state;
};

#define GROWSIZE 100

int charset_debug;
static const char *convert_name(struct convert_rock *rock);

#define XX 127
/*
 * Table for decoding hexadecimal in quoted-printable
 */
static const unsigned char index_hex[256] = {
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

EXPORTED int encoding_lookupname(const char *s)
{
    switch (s[0]) {
    case '7':
	if (!strcasecmp(s, "7BIT"))
	    return ENCODING_NONE;
	break;
    case '8':
	if (!strcasecmp(s, "8BIT"))
	    return ENCODING_NONE;
	break;
    case 'B':
    case 'b':
	if (!strcasecmp(s, "BASE64"))
	    return ENCODING_BASE64;
	if (!strcasecmp(s, "BINARY"))
	    return ENCODING_NONE;
	break;
    case 'Q':
    case 'q':
	if (!strcasecmp(s, "QUOTED-PRINTABLE"))
	    return ENCODING_QP;
	break;
    }
    return ENCODING_UNKNOWN;
}

EXPORTED const char *encoding_name(int encoding)
{
    switch (encoding) {
    case ENCODING_NONE: return "NONE";
    case ENCODING_QP: return "QUOTED-PRINTABLE";
    case ENCODING_BASE64: return "BASE64";
    case ENCODING_UNKNOWN: return "UNKNOWN";
    default: return "WTF";
    }
}

static inline void convert_putc(struct convert_rock *rock, int c)
{
    if (charset_debug) {
	if ((unsigned)c < 0xff)
	    fprintf(stderr, "%s(0x%x = '%c')\n", convert_name(rock), c, c);
	else
	    fprintf(stderr, "%s(0x%x)\n", convert_name(rock), c);
    }
    rock->f(rock, c);
}

static void convert_cat(struct convert_rock *rock, const char *s)
{
    while (*s) {
	convert_putc(rock, (unsigned char)*s);
	s++;
    }
}

static void convert_catn(struct convert_rock *rock, const char *s, size_t len)
{
    while (len-- > 0) {
	convert_putc(rock, (unsigned char)*s);
	s++;
    }
}

/* convertproc_t conversion functions */

static void qp2byte(struct convert_rock *rock, int c)
{
    struct qp_state *s = (struct qp_state *)rock->state;
    int val;

    assert(c == U_REPLACEMENT || (unsigned)c <= 0xff);

    if (s->bytesleft) {
	s->bytesleft--;

	 /* the replacement char is not part of a valid sequence */
	if (c == U_REPLACEMENT) {
invalid:
	    /* RFC2045 says "...A reasonable approach by a robust
	     * implementation might be to include the "=" character
	     * and the following character in the decoded data without
	     * any transformation..." */
	    convert_putc(rock->next, '=');
	    if (!s->bytesleft)
		convert_putc(rock->next, s->lastoctet);
	    convert_putc(rock->next, c);
	    s->bytesleft = 0;
	    return;
	}

	/* detect and swallow soft line breaks */
	if (s->bytesleft == 1 && c == '\r') {
	    s->lastoctet = c;
	    return;
	}
	if (s->bytesleft == 0 && s->lastoctet == '\r') {
	    if (c == '\n')
		return;
	    goto invalid;
	}

	val = HEXCHAR(c);
	if (val == XX)
	    goto invalid;
	/* if we got this far, we have two valid hex chars */
	if (!s->bytesleft) {
	    val |= (HEXCHAR(s->lastoctet) << 4);
	    assert((unsigned)val <= 0xff);
	    convert_putc(rock->next, val);
	}
	s->lastoctet = c;
	return;
    }

    /* start an encoded byte */
    if (c == '=') {
	s->bytesleft = 2;
	s->lastoctet = 0;
	return;
    }

    /* underscores are space in headers */
    if (s->isheader && c == '_') c = ' ';

    convert_putc(rock->next, c);
}

static void b64_2byte(struct convert_rock *rock, int c)
{
    struct b64_state *s = (struct b64_state *)rock->state;
    char b = CHAR64(c);

    /* could just be whitespace, ignore it */
    if (b == XX) return;

    switch (s->bytesleft) {
    case 0:
        s->codepoint = b;
	s->bytesleft = 3;
	break;
    case 3:
	convert_putc(rock->next, ((s->codepoint << 2) | (b >> 4)) & 0xff);
	s->codepoint = b;
	s->bytesleft = 2;
	break;
    case 2:
	convert_putc(rock->next, ((s->codepoint << 4) | (b >> 2)) & 0xff);
	s->codepoint = b;
	s->bytesleft = 1;
	break;
    case 1:
	convert_putc(rock->next, ((s->codepoint << 6) | b) & 0xff);
	s->codepoint = 0;
	s->bytesleft = 0;
    }
}

/*
 * This filter unfolds folded RFC2822 header field lines, i.e. it strips
 * a CRLF pair only if the first character after the CRLF is LWS, and
 * leaves other CRLF or lone CR or LF alone.  In particular the CRLFs
 * which *separate* different header fields are preserved.  This allows
 * the 'keep' and 'merge' whitespace options to behave as expected when
 * the search engine is term-based, i.e. uses whitespace and punctuation
 * to find indexing terms.
 */
static void unfold2uni(struct convert_rock *rock, int c)
{
    struct unfold_state *s = (struct unfold_state *)rock->state;

    switch (s->state) {
    case 0:
	if (c == '\r')
	    s->state = 1;
	else
	    convert_putc(rock->next, c);
	break;
    case 1:
	if (c == '\n')
	    s->state = 2;
	else {
	    convert_putc(rock->next, '\r');
	    convert_putc(rock->next, c);
	    s->state = 0;
	}
	break;
    case 2:
	if (c != ' ' && c != '\t') {
	    convert_putc(rock->next, '\r');
	    convert_putc(rock->next, '\n');
	}
	convert_putc(rock->next, c);
	s->state = 0;
	break;
    }
}

/* Given an octet which is a codepoint in some 7bit or 8bit character
 * set, or the Unicode replacement character, emit the corresponding
 * Unicode codepoint. */
static void table2uni(struct convert_rock *rock, int c)
{
    struct table_state *s = (struct table_state *)rock->state;
    struct charmap *map;

    if (c == U_REPLACEMENT) {
	convert_putc(rock->next, c);
	return;
    }

    assert((unsigned)c <= 0xff);
    map = (struct charmap *)&s->curtable[0][c & 0xff];
    if (map->c)
	convert_putc(rock->next, map->c);

    s->curtable = s->initialtable + map->next;
}

/* Given an octet in a UTF-8 encoded string, possibly emit a Unicode
 * code point */
static void utf8_2uni(struct convert_rock *rock, int c)
{
    struct table_state *s = (struct table_state *)rock->state;

    if (c == U_REPLACEMENT) {
	convert_putc(rock->next, c);
	s->bytesleft = 0;
	s->codepoint = 0;
	return;
    }

    assert((unsigned)c <= 0xff);

    if ((c & 0xf8) == 0xf0) { /* 11110xxx */
	/* first of a 4 char sequence */
	s->bytesleft = 3;
	s->codepoint = c & 0x07; /* 00000111 */
    }
    else if ((c & 0xf0) == 0xe0) { /* 1110xxxx */
	/* first of a 3 char sequence */
	s->bytesleft = 2;
	s->codepoint = c & 0x0f; /* 00001111 */
    }
    else if ((c & 0xe0) == 0xc0) { /* 110xxxxx */
	/* first of a 2 char sequence */
	s->bytesleft = 1;
	s->codepoint = c & 0x1f; /* 00011111 */
    }
    else if ((c & 0xc0) == 0x80) { /* 10xxxxxx */
	/* continuation char, handle only if expected */
	if (s->bytesleft > 0) {
	    s->codepoint = (s->codepoint << 6) + (c & 0x3f); /* 00111111 */
	    s->bytesleft--;
	    if (!s->bytesleft) {
	        convert_putc(rock->next, s->codepoint);
		s->codepoint = 0;
	    }
	}
    }
    else { /* plain ASCII char */
	convert_putc(rock->next, c);
	s->bytesleft = 0;
	s->codepoint = 0;
    }
}

/* Given an octet in a UTF-7 encoded string, possibly emit a Unicode
 * code point */
static void utf7_2uni (struct convert_rock *rock, int c)
{
    struct table_state *s = (struct table_state *)rock->state;

    assert((unsigned)c <= 0xff);

    if (c & 0x80) { /* skip 8-bit chars */
	convert_putc(rock->next, U_REPLACEMENT);
	return;
    }

    /* Inside a base64 encoded unicode fragment */
    if (s->mode) {
	/* '-' marks the end of a fragment */
	if (c == '-') {
	    /* special case: sequence +- creates output '+' */
	    if (s->mode == 1)
		convert_putc(rock->next, '+');
	    /* otherwise no output for the '-' */
	    s->mode = 0;
	    s->num_bits = 0;
	    s->codepoint = 0;
	}
	/* a normal char drops us out of base64 mode */
	else if (CHAR64(c) == XX) {
	    /* pass on the char */
	    convert_putc(rock->next, c);
	    /* and switch back to ASCII mode */
	    s->mode = 0;
	    /* XXX: warn if num_bits > 4 or codepoint != 0 */
	    s->num_bits = 0;
	    s->codepoint = 0;
	}
	/* base64 char - process it into the state machine */
	else {
	    s->mode = 2; /* we have some content, so don't process special +- */
	    /* add the 6 bits of value from this character */
	    s->codepoint = (s->codepoint << 6) + CHAR64(c);
	    s->num_bits += 6;
	    /* if we've got a full character's worth of bits, send it down 
	     * the line and keep the remainder for the next character */
	    if (s->num_bits >= 16) {
		s->num_bits -= 16;
		convert_putc(rock->next, (s->codepoint >> s->num_bits) & 0x7fff);
		s->codepoint &= ((1 << s->num_bits) - 1); /* avoid overflow by trimming */
	    }
	}
    }

    /* regular ASCII mode */
    else {
	/* '+' switches to base64 unicode mode */
	if (c == '+') {
	    s->mode = 1; /* switch mode, but no content processed yet */
	    s->codepoint = 0;
	    s->num_bits = 0;
	}
	/* regular ASCII char */
	else {
	    convert_putc(rock->next, c);
	}
    }
}

/*
 * Given a Unicode codepoint, emit one or more Unicode codepoints in
 * search-normalised form (having applied recursive Unicode
 * decomposition, like U+2026 HORIZONTAL ELLIPSIS to the three
 * characters U+2E U+2E U+2E).
 */
static void uni2searchform(struct convert_rock *rock, int c)
{
    struct canon_state *s = (struct canon_state *)rock->state;
    int i;
    int code;
    unsigned char table16, table8;

    if (c == U_REPLACEMENT) {
	convert_putc(rock->next, c);
	return;
    }

    table16 = chartables_translation_block16[(c>>16) & 0xff];

    /* no translations */
    if (table16 == 255) {
	convert_putc(rock->next, c);
	return;
    }

    table8 = chartables_translation_block8[table16][(c>>8) & 0xff];

    /* no translations */
    if (table8 == 255) {
	convert_putc(rock->next, c);
	return;
    }

    /* use the xlate table */
    code = chartables_translation[table8][c & 0xff];

    /* case - zero length output */
    if (code == 0) {
	return;
    }

    /* special case: whitespace or control characters */
    if (code == ' ' || code == '\r' || code == '\n') {
	if (s->flags & CHARSET_SKIPSPACE) {
	    return;
	}
	if (s->flags & CHARSET_MERGESPACE) {
	    if (s->seenspace)
		return;
	    s->seenspace = 1;
	    code = ' '; /* one SPACE char */
	}
    }
    else
	s->seenspace = 0;

    /* case - one character output */
    if (code > 0) {
	convert_putc(rock->next, code);
	return;
    }

    /* case - multiple characters */
    for (i = -code; chartables_translation_multichar[i]; i++) {
	int c = chartables_translation_multichar[i];
	/* diacritical character range.  This duplicates the
	 * behaviour of Cyrus versions before 2.5 */
	if (s->flags & CHARSET_SKIPDIACRIT) {
	    if ((c & ~0xff) == 0x300)
		continue;
	}
	/* note: whitespace already stripped from multichar sequences... */
	convert_putc(rock->next, c);
    }
}

/* Given a Unicode codepoint, emit valid UTF-8 encoded octets */
static void uni2utf8(struct convert_rock *rock, int c)
{
    if (!unicode_isvalid(c))
	c = U_REPLACEMENT;

    /* UTF-8 can encode code points up to 0x7fffffff, but the currently
     * defined last valid codepoint is 0x10ffff so we only handle that
     * range. */

    if (c > 0xffff) {
	convert_putc(rock->next, 0xF0 + ((c >> 18) & 0x07));
	convert_putc(rock->next, 0x80 + ((c >> 12) & 0x3f));
	convert_putc(rock->next, 0x80 + ((c >>  6) & 0x3f));
	convert_putc(rock->next, 0x80 + ( c        & 0x3f));
    }
    else if (c > 0x7ff) {
	convert_putc(rock->next, 0xE0 + ((c >> 12) & 0x0f));
	convert_putc(rock->next, 0x80 + ((c >>  6) & 0x3f));
	convert_putc(rock->next, 0x80 + ( c        & 0x3f));
    }
    else if (c > 0x7f) {
	convert_putc(rock->next, 0xC0 + ((c >>  6) & 0x1f));
	convert_putc(rock->next, 0x80 + ( c        & 0x3f));
    }
    else {
	convert_putc(rock->next, c);
    }
}

static void byte2search(struct convert_rock *rock, int c)
{
    struct search_state *s = (struct search_state *)rock->state;
    int i, cur;
    unsigned char b = (unsigned char)c;

    if (c == U_REPLACEMENT) {
	c = 0xff; /* searchable by invalid character! */
    }

    /* check our "in_progress" matches to see if they're still valid */
    for (i = 0, cur = 0; i < s->max_start; i++) {
	/* no more active offsets */
	if (s->starts[i] == -1)
	    break;

	/* if we've passed one that's not ongoing, copy back */
	if (cur < i)
	    s->starts[cur] = s->starts[i];

	/* check that the substring is still maching */
	if (b == s->substr[s->offset - s->starts[i]]) {
	    if (s->offset - s->starts[i] == s->patlen - 1) {
		/* we're there! */
		s->havematch = 1;
	    }
	    else {
		/* keep this one, it's ongoing */
		cur++;
	    }
	}
    }
    /* starting a new one! */
    if (b == s->substr[0]) {
	/* have to treat this one specially! */
	if (s->patlen == 1)
	    s->havematch = 1;
	else
	    s->starts[cur++] = s->offset;
    }
    /* empty out any others that aren't being kept */
    while (cur < i) s->starts[cur++] = -1;

    /* increment the offset counter */
    s->offset++;
}

/* Given an octet, append it to a buffer */
static void byte2buffer(struct convert_rock *rock, int c)
{
    struct buf *buf = (struct buf *)rock->state;

    buf_putc(buf, c & 0xff);
}

/*
 * The HTML5 standard mandates that certain Unicode code points
 * cannot be generated using &#nnn; numerical character references,
 * and should generate a parse error.  This function detects them.
 */
static int html_uiserror(int c)
{
    static const struct {
	unsigned int mask, lo, hi;
    } ranges[] = {
	{ ~0U,    0x0001, 0x0008 },
	{ ~0U,    0x000b, 0x000b },
	{ ~0U,    0x000e, 0x001f },
	{ ~0U,    0x007f, 0x009f },
	{ ~0U,    0xfdd0, 0xfdef },
	{ 0xffff, 0xfffe, 0xffff }
    };
    unsigned int i;

    for (i = 0 ; i < VECTOR_SIZE(ranges) ; i++) {
	unsigned c2 = (unsigned)c & ranges[i].mask;
	if (c2 >= ranges[i].lo && c2 <= ranges[i].hi)
	    return 1;
    }
    return 0;
}

static void html_saw_character(struct convert_rock *rock)
{
    struct striphtml_state *s = (struct striphtml_state *)rock->state;
    const char *ent = buf_cstring(&s->name);
    int c;
    static const int compat_chars[] = {
	/* Mappings of old numeric character codepoints between 0x80 and
	 * 0x9f inclusive, defined for backwards compatibility by HTML5,
	 * to Unicode code points.  Note that some of these are mapped
	 * to codepoints which are mandated to be parse errors. */
	0x20AC, /* EURO SIGN (€) */
	0x0081, /* <control> */
	0x201A, /* SINGLE LOW-9 QUOTATION MARK (‚) */
	0x0192, /* LATIN SMALL LETTER F WITH HOOK (ƒ) */
	0x201E, /* DOUBLE LOW-9 QUOTATION MARK („) */
	0x2026, /* HORIZONTAL ELLIPSIS (…) */
	0x2020, /* DAGGER (†) */
	0x2021, /* DOUBLE DAGGER (‡) */
	0x02C6, /* MODIFIER LETTER CIRCUMFLEX ACCENT (ˆ) */
	0x2030, /* PER MILLE SIGN (‰) */
	0x0160, /* LATIN CAPITAL LETTER S WITH CARON (Š) */
	0x2039, /* SINGLE LEFT-POINTING ANGLE QUOTATION MARK (‹) */
	0x0152, /* LATIN CAPITAL LIGATURE OE (Œ) */
	0x008D, /* <control> */
	0x017D, /* LATIN CAPITAL LETTER Z WITH CARON (Ž) */
	0x008F, /* <control> */
	0x0090, /* <control> */
	0x2018, /* LEFT SINGLE QUOTATION MARK (‘) */
	0x2019, /* RIGHT SINGLE QUOTATION MARK (’) */
	0x201C, /* LEFT DOUBLE QUOTATION MARK (“) */
	0x201D, /* RIGHT DOUBLE QUOTATION MARK (”) */
	0x2022, /* BULLET (•) */
	0x2013, /* EN DASH (–) */
	0x2014, /* EM DASH (—) */
	0x02DC, /* SMALL TILDE (˜) */
	0x2122, /* TRADE MARK SIGN (™) */
	0x0161, /* LATIN SMALL LETTER S WITH CARON (š) */
	0x203A, /* SINGLE RIGHT-POINTING ANGLE QUOTATION MARK (›) */
	0x0153, /* LATIN SMALL LIGATURE OE (œ) */
	0x009D, /* <control> */
	0x017E, /* LATIN SMALL LETTER Z WITH CARON (ž) */
	0x0178  /* LATIN CAPITAL LETTER Y WITH DIAERESIS (Ÿ) */
    };

    if (charset_debug)
	fprintf(stderr, "html_saw_character(%s)\n", ent);

    if (ent[0] == '#') {
	if (ent[1] == 'x' || ent[1] == 'X')
	    c = strtoul(ent+2, NULL, 16);
	else
	    c = strtoul(ent+1, NULL, 10);
	/* no need for format error checking, the lexer did that */

	/* Perform character mapping and validation per
	 * http://dev.w3.org/html5/spec/tokenization.html#consume-a-character-reference
	 */
	if (c == 0)
	    c = U_REPLACEMENT;
	else if (c >= 0x80 && c <= 0x9f)
	    c = compat_chars[c-0x80];
	else if (!unicode_isvalid(c))
	    c = U_REPLACEMENT;	/* invalid Unicode codepoint */

	if (html_uiserror(c)) {
	    /* the HTML5 spec says this is a parse error, but it's
	     * unclear what that means for us; we choose to strip the
	     * character but could also emit the replacement character.  */
	    return;
	}
    }
    else {
	c = htmlchar_from_string(ent);
	if (c == -1) {
	    c = U_REPLACEMENT;	    /* unknown character */
	}
	else if (c > 0xffff) {
	    /* Hack to handle a small minority of named characters
	     * which map to a sequence of two Unicode codepoints. */
	    convert_putc(rock->next, (c>>16) & 0xffff);
	    convert_putc(rock->next, c & 0xffff);
	    return;
	}
    }
    convert_putc(rock->next, c);
}

static const char *html_state_as_string(enum html_state state)
{
    switch (state) {
    case HDATA: return "HDATA";
    case HTAGOPEN: return "HTAGOPEN";
    case HENDTAGOPEN: return "HENDTAGOPEN";
    case HTAGNAME: return "HTAGNAME";
    case HSCTAG: return "HSCTAG";
    case HTAGPARAMS: return "HTAGPARAMS";
    case HCHARACTER: return "HCHARACTER";
    case HCHARACTER2: return "HCHARACTER2";
    case HCHARACTERHASH: return "HCHARACTERHASH";
    case HCHARACTERHEX: return "HCHARACTERHEX";
    case HCHARACTERDEC: return "HCHARACTERDEC";
    case HSCRIPTDATA: return "HSCRIPTDATA";
    case HSCRIPTLT: return "HSCRIPTLT";
    case HSTYLEDATA: return "HSTYLEDATA";
    case HSTYLELT: return "HSTYLELT";
    case HBOGUSCOMM: return "HBOGUSCOMM";
    case HMUDECOPEN: return "HMUDECOPEN";
    case HCOMMSTART: return "HCOMMSTART";
    case HCOMMSTARTDASH: return "HCOMMSTARTDASH";
    case HCOMM: return "HCOMM";
    case HCOMMENDDASH: return "HCOMMENDDASH";
    case HCOMMEND: return "HCOMMEND";
    case HCOMMENDBANG: return "HCOMMENDBANG";
    }
    return "wtf?";
}

static void html_push(struct striphtml_state *s, enum html_state state)
{
    assert(s->depth < (int)(sizeof(s->stack)/sizeof(s->stack[0])));
    if (charset_debug)
	fprintf(stderr, "html_push(%s)\n", html_state_as_string(state));
    s->stack[s->depth++] = state;
}

static int html_pop(struct striphtml_state *s)
{
    assert(s->depth > 0);
    if (charset_debug)
	fprintf(stderr, "html_pop()\n");
    return s->stack[--s->depth];
}

static void html_go(struct striphtml_state *s, enum html_state state)
{
    assert(s->depth > 0);
    if (charset_debug)
	fprintf(stderr, "html_go(%s)\n", html_state_as_string(state));
    s->stack[s->depth-1] = state;
}

static enum html_state html_top(struct striphtml_state *s)
{
    assert(s->depth > 0);
    return s->stack[s->depth-1];
}

static void html_saw_tag(struct striphtml_state *s)
{
    const char *tag = buf_cstring(&s->name);
    enum html_state state = html_top(s);

    if (charset_debug)
	fprintf(stderr, "html_saw_tag() state=%s tag=\"%s\" ends=%s,%s\n",
		html_state_as_string(state), tag,
		(s->ends & HBEGIN ? "BEGIN" : "-"),
		(s->ends & HEND ? "END" : "-"));

    /* gnb:TODO: what are we supposed to do with a nested <script> tag? */

    if (!strcasecmp(tag, "script")) {
	if (state == HDATA && s->ends == HBEGIN)
	    html_go(s, HSCRIPTDATA);
	else if (state == HSCRIPTDATA && s->ends == HEND)
	    html_go(s, HDATA);
	/* BEGIN,END pair is doesn't affect state */
    }
    else if (!strcasecmp(tag, "style")) {
	if (state == HDATA && s->ends == HBEGIN)
	    html_go(s, HSTYLEDATA);
	else if (state == HSTYLEDATA && s->ends == HEND)
	    html_go(s, HDATA);
	/* BEGIN,END pair is doesn't affect state */
    }
    /* otherwise, no change */
}

/*
 * Note we don't use isalnum - the test has to be in US-ASCII always
 * regardless of the charset of the text or the locale of this process
 */
#define html_isalpha(c) \
    (((c) >= 'a' && (c) <= 'z') || \
     ((c) >= 'A' && (c) <= 'Z'))
#define html_isxdigit(c) \
    (((c) >= '0' && (c) <= '9') || \
     ((c) >= 'a' && (c) <= 'f') || \
     ((c) >= 'A' && (c) <= 'F'))
#define html_isdigit(c) \
    (((c) >= '0' && (c) <= '9'))
#define html_isspace(c) \
    ((c) == ' ' || (c) == '\t' || (c) == '\r' || (c) == '\n')

void striphtml2uni(struct convert_rock *rock, int c)
{
    struct striphtml_state *s = (struct striphtml_state *)rock->state;

restart:
    switch (html_top(s)) {
    case HDATA:
	if (c == '<') {
	    html_push(s, HTAGOPEN);
	    buf_reset(&s->name);
	}
	else if (c == '&') {
	    html_go(s, HCHARACTER);
	    buf_reset(&s->name);
	}
	else {
	    convert_putc(rock->next, c);
	}
	break;

    case HSCRIPTDATA:	    /* 8.2.4.6 Script data state */
	if (c == '<') {
	    html_push(s, HSCRIPTLT);
	}
	/* else, strip the character */
	break;

    case HSCRIPTLT:	    /* 8.2.4.17 Script data less-than sign state */
	/* TODO: deal with <! inside SCRIPT tags properly per
	 * http://dev.w3.org/html5/spec/tokenization.html#script-data-less-than-sign-state
	 */
	if (c == '/') {
	    s->ends = HEND;
	    html_go(s, HTAGNAME);
	    buf_reset(&s->name);
	}
	else {
	    /* naked <, emit it and restart with current character */
	    convert_putc(rock->next, c);
	    html_pop(s);
	    goto restart;
	}
	break;

    case HSTYLEDATA:
	if (c == '<') {
	    html_push(s, HSTYLELT);
	}
	/* else, strip the character */
	break;

    case HSTYLELT:
	if (c == '/') {
	    s->ends = HEND;
	    html_go(s, HTAGNAME);
	    buf_reset(&s->name);
	}
	else {
	    /* naked <, emit it and restart with current character */
	    convert_putc(rock->next, c);
	    html_pop(s);
	    goto restart;
	}
	break;

    case HCHARACTER:	/* 8.2.4.2 Character reference in data state */
	/* This is the "consume a character reference" algorithm
	 * rewritten to use additional lexical states */
	if (c == '#') {
	    buf_putc(&s->name, c);
	    html_go(s, HCHARACTERHASH);
	}
	else if (html_isalpha(c)) {
	    buf_putc(&s->name, c);
	    html_go(s, HCHARACTER2);
	}
	else {
	    /* naked & - emit the & and restart */
	    convert_putc(rock->next, '&');
	    html_go(s, HDATA);
	    goto restart;
	}
	break;

    case HCHARACTERHASH:
	/* '&' then '#' */
	if (c == 'x' || c == 'X') {
	    buf_putc(&s->name, c);
	    html_go(s, HCHARACTERHEX);
	}
	else if (html_isdigit(c)) {
	    buf_putc(&s->name, c);
	    html_go(s, HCHARACTERDEC);
	}
	else {
	    /* naked &# - emit the &# and restart */
	    convert_putc(rock->next, '&');
	    convert_putc(rock->next, '#');
	    html_go(s, HDATA);
	    goto restart;
	}
	break;

    case HCHARACTER2:
	if (html_isalpha(c)) {
	    buf_putc(&s->name, c);
	    /* TODO: we're supposed to look this up
	     * to see if it's an known character so that
	     * &notit; is parsed as the 4 chars
	     * '¬' 'i' 't' ';' */
	}
	else {
	    html_saw_character(rock);
	    html_go(s, HDATA);
	    if (c != ';') {
		/* character reference not correctly terminated -
		 * restart with the next character */
		goto restart;
	    }
	}
	break;

    case HCHARACTERHEX:
	if (html_isxdigit(c)) {
	    buf_putc(&s->name, c);
	}
	else {
	    html_saw_character(rock);
	    html_go(s, HDATA);
	    if (c != ';') {
		/* character reference not correctly terminated -
		 * restart with the next character */
		goto restart;
	    }
	}
	break;

    case HCHARACTERDEC:
	if (html_isdigit(c)) {
	    buf_putc(&s->name, c);
	}
	else {
	    html_saw_character(rock);
	    html_go(s, HDATA);
	    if (c != ';') {
		/* character reference not correctly terminated -
		 * restart with the next character */
		goto restart;
	    }
	}
	break;

    case HTAGOPEN:  /* 8.2.4.8 Tag open state */
	if (c == '!') {
	    /* markup declaration open delimiter - let's just assume
	     * it's a comment */
	    html_pop(s);
	    html_go(s, HMUDECOPEN);
	    buf_reset(&s->name);
	}
	else if (c == '/') {
	    html_go(s, HENDTAGOPEN);
	}
	else if (html_isalpha(c)) {
	    s->ends = HBEGIN;
	    buf_putc(&s->name, c);
	    html_go(s, HTAGNAME);
	}
	else {
	    /* apparently a naked <, emit the < and restart */
	    convert_putc(rock->next, '<');
	    html_pop(s);
	    goto restart;
	}
	break;

    case HENDTAGOPEN:	/* 8.2.4.9 End tag open state */
	if (html_isalpha(c)) {
	    s->ends = HEND;
	    buf_putc(&s->name, c);
	    html_go(s, HTAGNAME);
	}
	else {
	    /* error */
	    html_pop(s);
	}
	break;

    case HTAGNAME:  /* 8.2.4.10 Tag name state */
	/* gnb:TODO handle > embedded in "param" */
	if (html_isspace(c)) {
	    html_go(s, HTAGPARAMS);
	}
	else if (c == '/') {
	    html_go(s, HSCTAG);
	}
	else if (c == '>') {
	    html_pop(s);
	    html_saw_tag(s);
	}
	else if (html_isalpha(c)) {
	    buf_putc(&s->name, c);
	}
	else {
	    /* error */
	    html_pop(s);
	}
	break;

    case HSCTAG:    /* 8.2.4.43 Self-closing start tag state */
	if (c == '>') {
	    s->ends = HBEGIN|HEND;
	    html_pop(s);
	    html_saw_tag(s);
	}
	else {
	    /* whatever, keep stripping tag parameters */
	    html_go(s, HTAGPARAMS);
	}
	break;

    case HTAGPARAMS:	    /* ignores all text until next '>' */
	if (c == '>') {
	    html_pop(s);
	    html_saw_tag(s);
	}
	else if (c == '/') {
	    html_go(s, HSCTAG);
	}
	break;

    case HBOGUSCOMM:	    /* 8.2.4.44 Bogus comment state */
	/* strip all text until closing > */
	if (c == '>') {
	    html_go(s, HDATA);
	}
	break;

    case HMUDECOPEN:	    /* 8.2.4.45 Markup declaration open state */
	if (c == '-') {
	    buf_putc(&s->name, c);
	    if (s->name.len == 2)
		html_go(s, HCOMMSTART);
	}
	else {
	    /* ignore DOCTYPE or CDATA */
	    html_go(s, HBOGUSCOMM);
	    goto restart;   /* in case it's a > */
	}
	break;

    case HCOMMSTART:	    /* 8.2.4.46 Comment start state */
	if (c == '-')
	    html_go(s, HCOMMSTARTDASH);
	else if (c == '>')
	    html_go(s, HDATA);	/* very short comment <!-->  */
	else
	    html_go(s, HCOMM);
	break;

    case HCOMMSTARTDASH:    /* 8.2.4.47 Comment start dash state */
	if (c == '-')
	    html_go(s, HCOMMEND);
	else if (c == '>')
	    html_go(s, HDATA);	/* incorrectly formed -> comment end */
	else
	    html_go(s, HCOMM);
	/* else strip */
	break;

    case HCOMM:		    /* 8.2.4.48 Comment state */
	if (c == '-')
	    html_go(s, HCOMMENDDASH);
	/* else strip */
	break;

    case HCOMMENDDASH:	    /* 8.2.4.49 Comment end dash state */
	if (c == '-')
	    html_go(s, HCOMMEND);   /* -- pair in comment */
	else
	    html_go(s, HCOMM);	    /* lone - in comment */
	break;

    case HCOMMEND:	    /* 8.2.4.50 Comment end state */
	if (c == '>')
	    html_go(s, HDATA);	/* correctly formed --> comment end */
	else if (c == '!')
	    html_go(s, HCOMMENDBANG);	/* --! in a comment */
	else if (c != '-')
	    html_go(s, HCOMM);	/* -- in the middle of a comment */
	/* else, --- in comment, strip */
	break;

    case HCOMMENDBANG:	    /* 8.2.4.51 Comment end bang state */
	if (c == '-')
	    html_go(s, HCOMMENDDASH);	/* --!- in comment */
	else if (c == '>')
	    html_go(s, HDATA);	/* --!> at end of comment */
	else
	    html_go(s, HCOMM);	/* --! in the middle of a comment */
	break;

    }
}

static const char *convert_name(struct convert_rock *rock)
{
    if (rock->f == b64_2byte) return "b64_2byte";
    if (rock->f == byte2buffer) return "byte2buffer";
    if (rock->f == byte2search) return "byte2search";
    if (rock->f == qp2byte) return "qp2byte";
    if (rock->f == striphtml2uni) return "striphtml2uni";
    if (rock->f == unfold2uni) return "unfold2uni";
    if (rock->f == table2uni) return "table2uni";
    if (rock->f == uni2searchform) return "uni2searchform";
    if (rock->f == uni2utf8) return "uni2utf8";
    if (rock->f == utf7_2uni) return "utf7_2uni";
    if (rock->f == utf8_2uni) return "utf8_2uni";
    return "wtf";
}

/* convert_rock manipulation routines */

static void table_switch(struct convert_rock *rock, int charset_num)
{
    struct table_state *state = (struct table_state *)rock->state;

    /* wipe any current state */
    memset(state, 0, sizeof(struct table_state));

    /* it's a table based lookup */
    if (chartables_charset_table[charset_num].table) {
	/* set up the initial table */
	state->curtable = state->initialtable
	    = chartables_charset_table[charset_num].table;
	rock->f = table2uni;
    }

    /* special case UTF-8 */
    else if (strstr(chartables_charset_table[charset_num].name, "utf-8")) {
	rock->f = utf8_2uni;
    }

    /* special case UTF-7 */
    else if (strstr(chartables_charset_table[charset_num].name, "utf-7")) {
	rock->f = utf7_2uni;
    }

    /* should never happen */
    else {
	exit(1);
	/* do something fatal here! */
    }
}

/* Extract a cstring from a buffer.  NOTE: caller must free the memory
 * themselves once this is called.  Resets the state.  If you don't
 * call this function then buffer_free will clean up */
static char *buffer_cstring(struct convert_rock *rock)
{
    struct buf *buf = (struct buf *)rock->state;

    return buf_release(buf);
}

static inline int search_havematch(struct convert_rock *rock)
{
    struct search_state *s = (struct search_state *)rock->state;
    return s->havematch;
}

/* conversion cleanup routines */

static void basic_free(struct convert_rock *rock)
{
    if (rock) {
	if (rock->state) free(rock->state);
	free(rock);
    }
}

static void search_free(struct convert_rock *rock)
{
    if (rock && rock->state) {
	struct search_state *s = (struct search_state *)rock->state;
	if (s->starts) free(s->starts);
    }
    basic_free(rock);
}

static void buffer_free(struct convert_rock *rock)
{
    if (rock && rock->state) {
	struct buf *buf = (struct buf *)rock->state;
	buf_free(buf);
    }
    basic_free(rock);
}

static void striphtml_free(struct convert_rock *rock)
{
    if (rock && rock->state) {
	struct striphtml_state *s = (struct striphtml_state *)rock->state;
	buf_free(&s->name);
    }
    basic_free(rock);
}

static void convert_free(struct convert_rock *rock) {
    struct convert_rock *next;
    while (rock) {
	next = rock->next;
	if (rock->cleanup)
	    rock->cleanup(rock);
	else 
	    basic_free(rock);
	rock = next;
    }
}

/* converter initialisation routines */

static struct convert_rock *qp_init(int isheader, struct convert_rock *next)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    struct qp_state *s = xzmalloc(sizeof(struct qp_state));
    s->isheader = isheader;
    rock->state = (void *)s;
    rock->f = qp2byte;
    rock->next = next;
    return rock;
}

static struct convert_rock *b64_init(struct convert_rock *next)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    rock->state = xzmalloc(sizeof(struct b64_state));
    rock->f = b64_2byte;
    rock->next = next;
    return rock;
}

static struct convert_rock *unfold_init(struct convert_rock *next)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    rock->state = xzmalloc(sizeof(struct unfold_state));
    rock->f = unfold2uni;
    rock->next = next;
    return rock;
}

static struct convert_rock *canon_init(int flags, struct convert_rock *next)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    struct canon_state *s = xzmalloc(sizeof(struct canon_state));
    s->flags = flags;
    rock->f = uni2searchform;
    rock->state = s;
    rock->next = next;
    return rock;
}

static struct convert_rock *uni_init(struct convert_rock *next)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    rock->f = uni2utf8;
    rock->next = next;
    return rock;
}

static struct convert_rock *table_init(int charset_num, struct convert_rock *next)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    rock->state = xzmalloc(sizeof(struct table_state));
    rock->next = next;
    table_switch(rock, charset_num);
    return rock;
}

static struct convert_rock *search_init(const char *substr, comp_pat *pat) {
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    struct search_state *s = xzmalloc(sizeof(struct search_state));
    struct comp_pat_s *p = (struct comp_pat_s *)pat;
    int i;

    /* copy in tracking vars */
    s->max_start = p->max_start;
    s->patlen = p->patlen;
    s->substr = (unsigned char *)substr;

    /* allocate tracking space and initialise to "no match" */
    s->starts = xmalloc(s->max_start * sizeof(size_t));
    for (i = 0; i < s->max_start; i++) {
	s->starts[i] = -1;
    }

    /* set up the rock */
    rock->f = byte2search;
    rock->cleanup = search_free;
    rock->state = (void *)s;

    return rock;
}

static struct convert_rock *buffer_init(void)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    struct buf *buf = xzmalloc(sizeof(struct buf));

    rock->f = byte2buffer;
    rock->cleanup = buffer_free;
    rock->state = (void *)buf;

    return rock;
}

struct convert_rock *striphtml_init(struct convert_rock *next)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    struct striphtml_state *s = xzmalloc(sizeof(struct striphtml_state));
    /* gnb:TODO: if a DOCTYPE is present, sniff it to detect XHTML rules */
    html_push(s, HDATA);
    rock->state = (void *)s;
    rock->f = striphtml2uni;
    rock->cleanup = striphtml_free;
    rock->next = next;
    return rock;
}


/* API */

/*
 * Return the name of the given character set number, or NULL if
 * not known.
 */
EXPORTED const char *charset_name(charset_index i)
{
    return (i >= 0 && i < chartables_num_charsets ?
	    chartables_charset_table[i].name : "unknown");
}

/*
 * Lookup the character set 'name'.  Returns the character set number
 * or -1 if there is no matching character set.
 */
EXPORTED int charset_lookupname(const char *name)
{
    int i;

    /* translate to canonical name */
    for (i = 0; charset_aliases[i].name; i++) {
	if (!strcasecmp(name, charset_aliases[i].name)) {
	    name = charset_aliases[i].canon_name;
	    break;
	}
    }

    /* look up canonical name */
    for (i = 0; i < chartables_num_charsets; i++) {
	if (!strcasecmp(name, chartables_charset_table[i].name)) 
	    return i;
    }

    return -1;
}

static int lookup_buf(const char *buf, int len)
{
    char *name = xstrndup(buf, len);
    int res = charset_lookupname(name);
    free(name);
    return res;
}

/*
 * Convert the string 's' in the character set numbered 'charset'
 * into canonical searching form.  Returns a newly allocated string
 * which must be free()d by the caller.
 */
EXPORTED char *charset_convert(const char *s, int charset, int flags)
{
    struct convert_rock *input, *tobuffer;
    char *res;

    if (!s) return 0;

    if (charset < 0 || charset >= chartables_num_charsets) 
	return xstrdup("X");

    /* set up the conversion path */
    tobuffer = buffer_init();
    input = uni_init(tobuffer);
    input = canon_init(flags, input);
    input = table_init(charset, input);

    /* do the conversion */
    convert_cat(input, s);

    /* extract the result */
    res = buffer_cstring(tobuffer);

    /* clean up */
    convert_free(input);

    return res;
}

EXPORTED char *charset_utf8_to_searchform(const char *s, int flags)
{
    int charset = charset_lookupname("utf-8");
    return charset_convert(s, charset, flags);
}

/* Convert from a given charset and encoding into utf8 */
EXPORTED char *charset_to_utf8(const char *msg_base, size_t len, int charset, int encoding)
{
    struct convert_rock *input, *tobuffer;
    char *res;

    /* Initialize character set mapping */
    if (charset < 0 || charset >= chartables_num_charsets) 
	return 0;

    /* check for trivial search */
    if (len == 0)
	return xstrdup("");

    /* set up the conversion path */
    tobuffer = buffer_init();
    input = uni_init(tobuffer);
    input = table_init(charset, input);

    /* choose encoding extraction if needed */
    switch (encoding) {
    case ENCODING_NONE:
	break;

    case ENCODING_QP:
	input = qp_init(0, input);
	break;

    case ENCODING_BASE64:
	input = b64_init(input);
	/* XXX have to have nl-mapping base64 in order to
	 * properly count \n as 2 raw characters
	 */
	break;

    default:
	/* Don't know encoding--nothing can match */
	convert_free(input);
	return 0;
    }

    convert_catn(input, msg_base, len);
    res = buffer_cstring(tobuffer);
    convert_free(input);

    return res;
}

static void mimeheader_cat(struct convert_rock *target, const char *s)
{
    struct convert_rock *input, *unfold;
    int eatspace = 0;
    const char *start, *endcharset, *encoding, *end;
    int len;
    int charset;
    const char *p;

    if (!s) return;

    /* set up the conversion path */
    input = table_init(0, target);
    /* note: we assume the caller of this function has already 
     * determined that all newlines are followed by whitespace */
    unfold = unfold_init(input);

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
	    for (p = s; p < (start-1) && Uisspace(*p); p++);
	    if (p < (start-1)) eatspace = 0;
	}
	if (!eatspace) {
	    len = start - s - 1;
	    table_switch(input, 0); /* US_ASCII */
	    convert_catn(unfold, s, len);
	}

	/*
	 * Get the 1522-word's character set
	 */
	start++;
	charset = lookup_buf(start, endcharset-start);
	if (charset < 0) {
	    /* Unrecognized charset, nothing will match here */
	    convert_putc(input, U_REPLACEMENT); /* unknown character */
	}
	else {
	    struct convert_rock *extract;

	    table_switch(input, charset);

	    /* choose decoder */
	    if (encoding[1] == 'q' || encoding[1] == 'Q') {
		extract = qp_init(1, input);
	    }
	    else {
		extract = b64_init(input);
	    }
	    /* convert */
	    p = encoding+3;
	    convert_catn(extract, p, end - p);
	    /* clean up */
	    basic_free(extract);
	}

	/* Prepare for the next iteration */
	s = start = end+2;
	eatspace = 1;
    }

    /* Copy over the tail part of the input string */
    if (*s) {
	table_switch(input, 0); /* US_ASCII */
	convert_cat(unfold, s);
    }

    /* just free these ones, the rest can be cleaned up by the sender */
    basic_free(unfold);
    basic_free(input);
}

/*
 * Decode MIME strings (per RFC 2047) in 's'.  Returns a newly allocated
 * string, contining 's' in canonical searching form, which must be
 * free()d by the caller.
 */
EXPORTED char *charset_decode_mimeheader(const char *s, int flags)
{
    struct convert_rock *tobuffer, *input;
    char *res;

    if (!s) return NULL;

    tobuffer = buffer_init();
    input = uni_init(tobuffer);
    input = canon_init(flags, input);

    mimeheader_cat(input, s);
 
    res = buffer_cstring(tobuffer);

    convert_free(input);

    return res;
}

/*
 * Decode MIME strings (per RFC 2047) in 's'.  Returns a newly allocated
 * string, containing the decoded string, which must be free()d by the
 * caller.
 */
EXPORTED char *charset_parse_mimeheader(const char *s)
{
    struct convert_rock *tobuffer, *input;
    char *res;

    if (!s) return NULL;

    tobuffer = buffer_init();
    input = uni_init(tobuffer);

    mimeheader_cat(input, s);
 
    res = buffer_cstring(tobuffer);

    convert_free(input);

    return res;
}

EXPORTED int charset_search_mimeheader(const char *substr, comp_pat *pat,
			      const char *s, int flags)
{
    struct convert_rock *input, *tosearch;
    int res;

    tosearch = search_init(substr, pat);
    input = uni_init(tosearch);
    input = canon_init(flags, input);

    mimeheader_cat(input, s);
 
    res = search_havematch(tosearch);

    convert_free(input);

    return res;
}

/* Compile a search pattern for later comparison.  We just count
 * how long the string is, and how many times the first character
 * occurs.  Later optimisation could reduce the max_start by
 * deeper analysis of the possible paths through the string, but
 * this is a good absolute maximum, and it just means a few more
 * bytes get allocated... */
EXPORTED comp_pat *charset_compilepat(const char *s)
{
    struct comp_pat_s *pat = xzmalloc(sizeof(struct comp_pat_s));
    const char *p = s;
    /* count occurances */
    while (*p) {
	if (*p == *s) pat->max_start++; 
	pat->patlen++;
	p++;
    }
    return (comp_pat *)pat;
}

/*
 * Free the compiled pattern 'pat'
 */
EXPORTED void charset_freepat(comp_pat *pat)
{
    free((struct comp_pat_s *)pat);
}

/*
 * Search for the string 'substr', with compiled pattern 'pat'
 * in the string 's', with length 'len'.  Return nonzero if match
 *
 * Uses the to_search target directly.  Assumes 's' is already
 * in search normal form (i.e. from a cache file)
 */
EXPORTED int charset_searchstring(const char *substr, comp_pat *pat,
			 const char *s, size_t len, int flags)
{
    struct convert_rock *tosearch;
    struct convert_rock *input;
    int charset = charset_lookupname("utf-8");
    int res;

    if (!substr[0])
	return 1; /* zero length string always matches */

    /* set up the search handler */
    tosearch = search_init(substr, pat);

    /* and the input stream */
    input = uni_init(tosearch);
    input = canon_init(flags, input);
    input = table_init(charset, input);

    /* feed the handler */
    while (len-- > 0) {
	convert_putc(input, (unsigned char)*s++);
	if (search_havematch(tosearch)) break; /* shortcut if there's a match */
    }

    /* copy the value */
    res = search_havematch(tosearch);

    /* clean up */
    convert_free(input);

    return res;
}

/*
 * Search for the string 'substr' in the next 'len' bytes of 
 * 'msg_base'.  
 * 'charset' and 'encoding' specify the character set and 
 * content transfer encoding of the data, respectively.
 * Returns nonzero iff the string was found.
 */
EXPORTED int charset_searchfile(const char *substr, comp_pat *pat,
		       const char *msg_base, size_t len,
		       int charset, int encoding, int flags)
{
    struct convert_rock *input, *tosearch;
    size_t i;
    int res;

    /* Initialize character set mapping */
    if (charset < 0 || charset >= chartables_num_charsets) 
	return 0;

    /* check for trivial search */
    if (strlen(substr) == 0)
	return 1;

    /* set up the conversion path */
    tosearch = search_init(substr, pat);
    input = uni_init(tosearch);
    input = canon_init(flags, input);
    input = table_init(charset, input);

    /* choose encoding extraction if needed */
    switch (encoding) {
    case ENCODING_NONE:
	break;

    case ENCODING_QP:
	input = qp_init(0, input);
	break;

    case ENCODING_BASE64:
	input = b64_init(input);
	/* XXX have to have nl-mapping base64 in order to
	 * properly count \n as 2 raw characters
	 */
	break;

    default:
	/* Don't know encoding--nothing can match */
	convert_free(input);
	return 0;
    }

    /* implement the loop here so we can check on the search each time */
    for (i = 0; i < len; i++) {
	convert_putc(input, msg_base[i]);
	if (search_havematch(tosearch)) break;
    }

    res = search_havematch(tosearch); /* copy before we free it */

    convert_free(input);

    return res;
}

/* This is based on charset_searchfile above. */
EXPORTED int charset_extract(search_text_receiver_t *receiver,
			     const struct buf *data,
			     int charset, int encoding,
			     const char *subtype, int flags)
{
    struct convert_rock *input, *tobuffer;
    struct buf *out;
    size_t i;

    if (charset_debug)
	fprintf(stderr, "charset_extract()\n");

    /* Initialize character set mapping */
    if (charset < 0 || charset >= chartables_num_charsets) 
	return 0;

    /* set up the conversion path */
    tobuffer = buffer_init();
    input = uni_init(tobuffer);
    input = canon_init(flags, input);

    if (!strcmpsafe(subtype, "HTML")) {
	if ((flags & CHARSET_SKIPHTML)) {
	    /* silently pretend we indexed it, but actually ignore it */
	    convert_free(input);
	    return 1;
	}
	/* this is text/html data, so we can make ourselves useful by
	 * stripping html tags, css and js. */
	input = striphtml_init(input);
    }

    input = table_init(charset, input);

    switch (encoding) {
    case ENCODING_NONE:
	break;

    case ENCODING_QP:
	input = qp_init(0, input);
	break;

    case ENCODING_BASE64:
	input = b64_init(input);
	/* XXX have to have nl-mapping base64 in order to
	 * properly count \n as 2 raw characters
	 */
	break;

    default:
	/* Don't know encoding--nothing can match */
	convert_free(input);
	return 0;
    }

    /* point to the buffer for easy block sending */
    out = (struct buf *)tobuffer->state;

    for (i = 0; i < data->len; i++) {
	convert_putc(input, (unsigned char)data->s[i]);

	/* process a block of output every so often */
	if (buf_len(out) > 4096) {
	    receiver->append_text(receiver, out);
	    buf_reset(out);
	}
    }
    if (out->len) { /* finish it */
	receiver->append_text(receiver, out);
    }

    convert_free(input);

    return 1;
}

/*
 * Decode the MIME body part (per RFC 2045) of @len bytes located at
 * @msg_base having the content transfer @encoding.  Returns a pointer
 * to decoded bytes.  The number of decoded bytes is returned in
 * *@outlen.  Depending on the encoding, a newly allocated buffer may be
 * written to *@decbuf, which should be free()d by the caller if it not
 * zero.  Note that the return value may point to either @msg_base or
 * @decbuf, so @decbuf should not be free()d until the return value has
 * been used.
 */
EXPORTED const char *charset_decode_mimebody(const char *msg_base, size_t len, int encoding,
				    char **decbuf, size_t *outlen)
{
    struct convert_rock *input, *tobuffer;

    *decbuf = NULL;
    *outlen = 0;

    switch (encoding) {
    case ENCODING_NONE:
	*outlen = len;
	return msg_base;

    case ENCODING_QP:
	tobuffer = buffer_init();
	input = qp_init(0, tobuffer);
	break;

    case ENCODING_BASE64:
	tobuffer = buffer_init();
	input = b64_init(tobuffer);
	break;

    default:
	/* Don't know encoding--nothing can match */
	return NULL;
    }

    convert_catn(input, msg_base, len);

    /* extract the string from the buffer */
    {
	struct buf *buf = (struct buf *)tobuffer->state;
	*outlen = buf->len;
	*decbuf = buf_release(buf);
    }

    convert_free(input);

    if (!*decbuf) {
	/* didn't get a result - maybe blank input, don't return NULL */
	*outlen = len;
	return msg_base;
    }

    return *decbuf;
}

/*
 * Base64 encode the MIME body part (per RFC 2045) of 'len' bytes located at
 * 'msg_base'.  Encodes into 'retval' which must large enough to
 * accomodate the encoded data.  Returns the number of encoded bytes in
 * 'outlen' and the number of encoded lines in 'outlines'.
 *
 * May be called with 'msg_base' as NULL to get the number of encoded
 * bytes for allocating 'retval' of the proper size.
 */
#define BASE64_MAX_LINE_LEN  72

static char base_64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

EXPORTED char *charset_encode_mimebody(const char *msg_base, size_t len,
    char *retval, size_t *outlen, int *outlines)
{
    const unsigned char *s;
    unsigned char s0, s1, s2;
    char *d;
    int b64_len, b64_lines, cnt;

    b64_len = ((len + 2) / 3) * 4;
    b64_lines = (b64_len + BASE64_MAX_LINE_LEN - 1) / BASE64_MAX_LINE_LEN;

    /* account for CRLF added to each line */
    b64_len += 2 * b64_lines;

    if (outlen) *outlen = b64_len;
    if (outlines) *outlines = b64_lines;

    if (!msg_base) return NULL;

    for (s = (const unsigned char*) msg_base, d = retval, cnt = 0; len;
	 s += 3, d += 4, cnt += 4) { /* process tuplets */
	if (cnt == BASE64_MAX_LINE_LEN) {
	    /* reset line len count, add CRLF */
	    cnt = 0;
	    *d++ = '\r';
	    *d++ = '\n';
	}

	s0 = s[0];
	s1 = --len ? s[1] : 0;
	/* byte 1: high 6 bits (1) */
	d[0] = base_64[s0 >> 2];
	/* byte 2: low 2 bits (1), high 4 bits (2) */
	d[1] = base_64[((s0 & 0x3) << 4) | ((s1 & 0xf0) >> 4)];
	if (len) {
	    s2 = --len ? s[2] : 0;
	    /* byte 3: low 4 bits (2), high 2 bits (3) */
	    d[2] = base_64[((s1 & 0xf) << 2) | ((s2 & 0xc0) >> 6)];
	} else {
	    /* byte 3: pad */
	    d[2] = '=';
	}
	if (len) {
	    --len;
	    /* byte 4: low 6 bits (3) */
	    d[3] = base_64[s2 & 0x3f];
	} else {
	    /* byte 4: pad */
	    d[3] = '=';
	}
    }

    /* add final CRLF */
    *d++ = '\r';
    *d++ = '\n';

    return (b64_len ? retval : NULL);
}

/* returns a buffer which the caller must free */
EXPORTED char *charset_encode_mimeheader(const char *header, size_t len)
{
    struct buf buf = BUF_INITIALIZER;
    size_t n;
    int need_quote = 0;

    if (!header) return NULL;

    if (!len) len = strlen(header);

    for (n = 0; n < len; n++) {
	unsigned char this = header[n];
	if (QPSAFECHAR[this] || this == ' ') continue;
	need_quote = 1;
	break;
    }

    if (need_quote) {
	buf_printf(&buf, "=?UTF-8?Q?");
	for (n = 0; n < len; n++) {
	    unsigned char this = header[n];
	    if (QPSAFECHAR[this]) {
		buf_putc(&buf, (char)this);
	    }
	    else {
		buf_printf(&buf, "=%02X", this);
	    }
	}
	buf_printf(&buf, "?=");
    }
    else {
	buf_setmap(&buf, header, len);
    }

    return buf_release(&buf);
}

