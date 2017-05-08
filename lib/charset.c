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

#include "assert.h"
#include "charset.h"
#include "xmalloc.h"
#include "chartable.h"
#include "hash.h"
#include "htmlchar.h"
#include "util.h"

#define U_REPLACEMENT   0xfffd

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
    int len;
    unsigned char buf[1000];
};

struct b64_state {
    int bytesleft;
    int codepoint;
};

struct unfold_state {
    int state;
    int skipws;
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
#define HBEGIN          (1<<0)
#define HEND            (1<<1)
    unsigned int ends;
    /* state stack */
    int depth;
    enum html_state stack[2];
};

#define CHARSET_ICUBUF_BUFFER_SIZE 4096

struct charset_converter {
    /* An open ICU converter for ICU backed converters. Or NULL.  */
    UConverter *conv;

    /* The charset name for this converter. Might differ from ICU name. */
    char *name;

    /* The numeric charset identifier for table converters. Or -1 */
    int num;

    /* Table converter backend state */
    const struct charmap (*curtable)[256];
    const struct charmap (*initialtable)[256];
    int bytesleft;
    int codepoint;
    int mode;
    int num_bits;

    /* ICU converter backend state */
    short flush;      /* set if conv should be flushed */
    char *buf;        /* Target and source cache */
    size_t buf_size;
    char *tgt_base;
    char *tgt_top;
    char *tgt_next;
    char *src_base;
    char *src_top;
    char *src_next;
};

struct convert_rock;

static void icu_reset(struct convert_rock *rock, int to_uni);
static void icu_flush(struct convert_rock *rock);
static void icu_free(struct convert_rock *rock);

static void table_reset(struct convert_rock *rock, int to_uni);
static void table_free(struct convert_rock *rock);

typedef void convertproc_t(struct convert_rock *rock, uint32_t c);
typedef void freeconvert_t(struct convert_rock *rock);
typedef void flushproc_t(struct convert_rock *rock);

struct convert_rock {
    convertproc_t *f;
    freeconvert_t *cleanup;
    flushproc_t *flush;
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

static void convert_flush(struct convert_rock *rock)
{
    while (rock) {
        if (rock->flush) rock->flush(rock);
        rock = rock->next;
    }
}

static inline void convert_putc(struct convert_rock *rock, uint32_t c)
{
    if (charset_debug) {
        if (c < 0xff)
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
    convert_flush(rock);
}

static void convert_catn(struct convert_rock *rock, const char *s, size_t len)
{
    while (len-- > 0) {
        convert_putc(rock, (unsigned char)*s);
        s++;
    }
    convert_flush(rock);
}

/* convertproc_t conversion functions */
static void qp_flushline(struct convert_rock *rock, int endline)
{
    struct qp_state *s = (struct qp_state *)rock->state;
    int i;

    /* strip trailing whitespace: RFC2405 transport-padding */
    while (s->len && (s->buf[s->len-1] == ' ' || s->buf[s->len-1] == '\t'))
        s->len--;

    for (i = 0; i < s->len; i++) {
        switch(s->buf[i]) {
        case '=':
            if (i + 1 >= s->len) {
                /* soft linebreak */
                endline = 0;
                break;
            }
            if (i + 2 < s->len) {
                int val1 = HEXCHAR(s->buf[i+1]);
                int val2 = HEXCHAR(s->buf[i+2]);
                if (val1 != XX && val2 != XX) {
                    convert_putc(rock->next, (val1<<4) + val2);
                    i += 2;
                    break;
                }
            }
            /* otherwise too close to the end or invalid, just eject
             * a literal '=' and keep going */
            convert_putc(rock->next, '=');
            break;
        case '_':
            /* underscores are space in headers */
            convert_putc(rock->next, s->isheader ? ' ' : '_');
            break;
        default:
            convert_putc(rock->next, s->buf[i]);
            break;
        }
    }

    if (endline) {
        convert_putc(rock->next, '\r');
        convert_putc(rock->next, '\n');
    }

    s->len = 0;
}

static void qp_flush(struct convert_rock *rock)
{
    qp_flushline(rock, 0);
}

static void qp2byte(struct convert_rock *rock, uint32_t c)
{
    struct qp_state *s = (struct qp_state *)rock->state;

    assert(c == U_REPLACEMENT || (unsigned)c <= 0xff);

    switch(c) {
    case U_REPLACEMENT: /* just skip invalid characters */
        break;
    case '\r': // XXX - handle \r embedded in lines?
        break;
    case '\n':
        qp_flushline(rock, 1);
        break;
    default:
        s->buf[s->len++] = c;
        /* really overlength line? just flush now */
        if (s->len > 998)
            qp_flushline(rock, 0);
        break;
    }
}

static void b64_2byte(struct convert_rock *rock, uint32_t c)
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
static void unfold2uni(struct convert_rock *rock, uint32_t c)
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
            convert_putc(rock->next, c);
        } else if (!s->skipws) {
            convert_putc(rock->next, c);
        }
        s->state = 0;
        break;
    }
}

/*
 * Given a Unicode codepoint, emit one or more Unicode codepoints in
 * search-normalised form (having applied recursive Unicode
 * decomposition, like U+2026 HORIZONTAL ELLIPSIS to the three
 * characters U+2E U+2E U+2E).
 */
static void uni2searchform(struct convert_rock *rock, uint32_t c)
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
        /* diacritical character range.  This duplicates the
         * behaviour of Cyrus versions before 2.5 */
        if (s->flags & CHARSET_SKIPDIACRIT) {
            if (0x300 <= code && code <= 0x36f)
                return;
        }
        convert_putc(rock->next, code);
        return;
    }

    /* case - multiple characters */
    for (i = -code; chartables_translation_multichar[i]; i++) {
        int c = chartables_translation_multichar[i];
        /* diacritical character range.  This duplicates the
         * behaviour of Cyrus versions before 2.5 */
        if (s->flags & CHARSET_SKIPDIACRIT) {
            /* XXX combining diacritical marks only range from 0x300 to 0x36f
             * but this would break backwards compatibility */
            if ((c & ~0xff) == 0x300)
                continue;
        }
        /* note: whitespace already stripped from multichar sequences... */
        convert_putc(rock->next, c);
    }
}

/*
 * Given a Unicode codepoint, emit one or more Unicode codepoints in
 * HTML form, suitable for generating search snippets.
 */
static void uni2html(struct convert_rock *rock, uint32_t c)
{
    struct canon_state *s = (struct canon_state *)rock->state;

    if (c == U_REPLACEMENT) {
        convert_putc(rock->next, c);
        return;
    }

    if (s->flags & CHARSET_ESCAPEHTML) {
        if (c == '<') {
            convert_cat(rock->next, "&lt;");
            return;
        }

        if (c == '>') {
            convert_cat(rock->next, "&gt;");
            return;
        }

        if (c == '&') {
            convert_cat(rock->next, "&amp;");
            return;
        }
    }

    /* special case: whitespace or control characters */
    if (c == ' ' || c == '\r' || c == '\n') {
        if (s->flags & CHARSET_SKIPSPACE) {
            return;
        }
        if (s->flags & CHARSET_MERGESPACE) {
            if (s->seenspace)
                return;
            s->seenspace = 1;
            c = ' '; /* one SPACE char */
        }
    }
    else
        s->seenspace = 0;

    convert_putc(rock->next, c);
}

static void byte2search(struct convert_rock *rock, uint32_t c)
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

        /* check that the substring is still matching */
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
static void byte2buffer(struct convert_rock *rock, uint32_t c)
{
    struct buf *buf = (struct buf *)rock->state;

    buf_putc(buf, c & 0xff);
}

/* Given an octet c and an icu converter, convert c to
 * its Unicode codepoint. During a flush, c is ignored.
 */
static void icu2uni(struct convert_rock *rock, uint32_t c)
{
    struct charset_converter *s = (struct charset_converter*) rock->state;
    UErrorCode err;

    /* Assert a sane state. */
    assert(s->flush || ((unsigned)c) <= 0xff || c == U_REPLACEMENT);

    /* Fill up the buffer until its either full or we are flushing. */
    if (!s->flush && c <= 0xff) {
        *s->src_next++ = c;
        /* Is there still space in the buffer? */
        if (s->src_next < s->src_top) return;
    }

    do {
        size_t n;
        UChar32 cp;

        /* Set up the target buffer. */
        const UChar *tgt_limit = (const UChar*) s->tgt_top;
        UChar *tgt = (UChar *) s->tgt_next;

        /* Set up the source buffer */
        const char *src = s->src_base;
        const char *src_limit = s->src_next;

        /* Convert the source buffer to Unicode. */
        err = U_ZERO_ERROR;
        ucnv_toUnicode(s->conv, &tgt, tgt_limit, &src, src_limit, NULL,
                s->flush || c == U_REPLACEMENT, &err); 

        /* Keep any bytes left in the source buffer. */
        n = src_limit - src;
        if (n) memmove(s->src_base, src, n);
        s->src_next = s->src_base + n;

        /* Bail out on errors. */
        if (U_FAILURE(err) && err != U_BUFFER_OVERFLOW_ERROR) {
            convert_putc(rock->next, U_REPLACEMENT);
            return;
        }

        /* Emit any complete codepoints. */
        UChar *t = (UChar *) s->tgt_base;
        while (t < tgt && (U16_IS_SINGLE(*t) || t < tgt-1)) {
            ssize_t i = 0;
            U16_NEXT(t, i, tgt - t, cp);
            convert_putc(rock->next, cp);
            t += i;
        }

        /* Keep any incomplete codepoints and reset the target buffer. */
        n = (tgt - t) * sizeof(UChar);
        if (n) memmove(s->tgt_base, t, n);
        s->tgt_next = s->tgt_base + n;

    } while (err == U_BUFFER_OVERFLOW_ERROR);

    /* Pass any errors down the pipeline. */
    if (c == U_REPLACEMENT) {
        convert_putc(rock->next, c);
    }

}

/* Given Unicode codepoint c and an icu converter, convert c and emit
 * its octets. During a flush, c is ignored. */
static void uni2icu(struct convert_rock *rock, uint32_t c)
{
    struct charset_converter *s = (struct charset_converter*) rock->state;
    UErrorCode err;

    UChar *src_next = (UChar*) s->src_next;

    /* Fill up the buffer until its either full or we are flushing. */
    if (!s->flush) {
        if (U16_LENGTH(c) == 1) {
            *src_next++ = c;
        } else {
            *src_next++ = U16_LEAD(c);
            *src_next++ = U16_TRAIL(c);
        }
        s->src_next = (char *) src_next;
        /* Can we buffer at least one more 32-bit codepoint. */
        if (s->src_next < (s->src_top - 2*sizeof(UChar))) return;
    }

    do {
        size_t n;
        char *t;

        /* Set up the target buffer. */
        char *tgt = s->tgt_base;
        const char *tgt_limit = s->tgt_top;

        /* Set up the source buffer */
        const UChar *src = (const UChar *) s->src_base;
        const UChar *src_limit = (const UChar *) s->src_next;

        /* Convert the source buffer from Unicode. */
        err = U_ZERO_ERROR;
        ucnv_fromUnicode(s->conv, &tgt, tgt_limit, &src, src_limit, NULL,
                s->flush, &err);

        /* Keep any bytes left in the source buffer. */
        n = (src_limit - src) * sizeof(UChar);
        if (n) memmove(s->src_base, src, n);
        s->src_next = s->src_base + n;

        /* Bail out on errors. */
        if (U_FAILURE(err) && err != U_BUFFER_OVERFLOW_ERROR) {
            convert_putc(rock->next, U_REPLACEMENT);
            return;
        }

        /* Emit any converted octets. */
        for (t = s->tgt_base; t < tgt; t++)
            convert_putc(rock->next, *t);

        /* Reset the target buffer. */
        s->tgt_next = s->tgt_base;

    } while (err == U_BUFFER_OVERFLOW_ERROR);
}

/* Given an octet in a UTF-8 encoded string, possibly emit a Unicode
 * code point */
static void utf8_2uni(struct convert_rock *rock, uint32_t c)
{
    struct charset_converter *s = (struct charset_converter *)rock->state;

    if (c == U_REPLACEMENT) {
emit_replacement:
        convert_putc(rock->next, U_REPLACEMENT);
        s->bytesleft = 0;
        s->codepoint = 0;
        return;
    }

    assert((unsigned)c <= 0xff);

    /*
     * The following bytes are never valid in UTF-8 streams:
     *
     * C0-C1    could only be used for overlong encoding of
     *          basic ASCII characters
     * F5-FD    start bytes of sequences that could only encode
     *          numbers larger than the 0x10FFFF limit of Unicode
     * FE-FF    not valid start bytes or anything else
     *
     * Thanks to http://en.wikipedia.org/wiki/UTF-8
     *
     * These checks are interspersed with bitwise checks below.
     *
     * When we see a valid leading character but a sequence has
     * not finished, we have detected an ill-formed sequence.  The
     * correct thing to do according to Section 3.9 of the Unicode
     * standard 6.0 is to jettison the current sequence, emit the
     * Replacement character and begin a new sequence with the new
     * character.  From the standard:
     *
     *      For example, with the input UTF-8 code unit sequence
     *      <C2 41 42>, such a UTF-8 conversion process must not
     *      return <U+FFFD> or <U+FFFD, U+0042>, because either of
     *      those outputs would be the result of misinterpreting
     *      a well-formed subsequence as being part of the ill-formed
     *      subsequence. The expected return value for such a process
     *      would instead be <U+FFFD, U+0041, U+0042>.
     */

    if ((c & 0xf8) == 0xf0) { /* 11110xxx */
        /* first of a 4 char sequence */
        if (s->bytesleft)       /* incomplete sequence */
            convert_putc(rock->next, U_REPLACEMENT);
        if (c >= 0xf5 && c <= 0xf7) goto emit_replacement;
        s->bytesleft = 3;
        s->codepoint = c & 0x07; /* 00000111 */
    }
    else if ((c & 0xf0) == 0xe0) { /* 1110xxxx */
        /* first of a 3 char sequence */
        if (s->bytesleft)       /* incomplete sequence */
            convert_putc(rock->next, U_REPLACEMENT);
        s->bytesleft = 2;
        s->codepoint = c & 0x0f; /* 00001111 */
    }
    else if ((c & 0xe0) == 0xc0) { /* 110xxxxx */
        /* first of a 2 char sequence */
        if (s->bytesleft)       /* incomplete sequence */
            convert_putc(rock->next, U_REPLACEMENT);
        if (c == 0xc0 || c == 0xc1) goto emit_replacement;
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
        else
            goto emit_replacement;
    }
    else if (c >= 0xf8 && c <= 0xff) {
        goto emit_replacement;
    }
    else { /* plain ASCII char */
        if (s->bytesleft)       /* incomplete sequence */
            convert_putc(rock->next, U_REPLACEMENT);
        convert_putc(rock->next, c);
        s->bytesleft = 0;
        s->codepoint = 0;
    }
}

/* Given a Unicode codepoint, emit valid UTF-8 encoded octets */
static void uni2utf8(struct convert_rock *rock, uint32_t c)
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

/* Given an octet which is a codepoint in some 7bit or 8bit character
 * set, or the Unicode replacement character, emit the corresponding
 * Unicode codepoint. */
static void table2uni(struct convert_rock *rock, uint32_t c)
{
    struct charset_converter *s = (struct charset_converter *)rock->state;
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

/*
 * The HTML5 standard mandates that certain Unicode code points
 * cannot be generated using &#nnn; numerical character references,
 * and should generate a parse error.  This function detects them.
 */
static int html_uiserror(uint32_t c)
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
            c = U_REPLACEMENT;  /* invalid Unicode codepoint */

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
            c = U_REPLACEMENT;      /* unknown character */
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

static int is_phrasing(char *tag)
{
    static const char * const phrasing_tags[] = {
        "a", "q", "cite", "em", "strong", "small",
        "mark", "dfn", "abbr", "time", "progress",
        "meter", "code", "var", "samp", "kbd",
        "sub", "sup", "span", "i", "b", "bdo",
        "ruby", "ins", "del"
    };
    static struct hash_table hash = HASH_TABLE_INITIALIZER;

    if (hash.table == NULL) {
        unsigned int i;
        construct_hash_table(&hash, VECTOR_SIZE(phrasing_tags), 0);
        for (i = 0 ; i < VECTOR_SIZE(phrasing_tags) ; i++)
            hash_insert(phrasing_tags[i], (void *)1, &hash);
    }

    return (hash_lookup(lcase(tag), &hash) == (void *)1);
}

static void html_saw_tag(struct convert_rock *rock)
{
    struct striphtml_state *s = (struct striphtml_state *)rock->state;
    char *tag;
    enum html_state state = html_top(s);

    buf_cstring(&s->name);
    tag = s->name.s;

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
    else if (!is_phrasing(tag)) {
        convert_putc(rock->next, ' ');
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

void striphtml2uni(struct convert_rock *rock, uint32_t c)
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

    case HSCRIPTDATA:       /* 8.2.4.6 Script data state */
        if (c == '<') {
            html_push(s, HSCRIPTLT);
        }
        /* else, strip the character */
        break;

    case HSCRIPTLT:         /* 8.2.4.17 Script data less-than sign state */
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

    case HCHARACTER:    /* 8.2.4.2 Character reference in data state */
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

    case HENDTAGOPEN:   /* 8.2.4.9 End tag open state */
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
            html_saw_tag(rock);
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
            html_saw_tag(rock);
        }
        else {
            /* whatever, keep stripping tag parameters */
            html_go(s, HTAGPARAMS);
        }
        break;

    case HTAGPARAMS:        /* ignores all text until next '>' */
        if (c == '>') {
            html_pop(s);
            html_saw_tag(rock);
        }
        else if (c == '/') {
            html_go(s, HSCTAG);
        }
        break;

    case HBOGUSCOMM:        /* 8.2.4.44 Bogus comment state */
        /* strip all text until closing > */
        if (c == '>') {
            html_go(s, HDATA);
        }
        break;

    case HMUDECOPEN:        /* 8.2.4.45 Markup declaration open state */
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

    case HCOMMSTART:        /* 8.2.4.46 Comment start state */
        if (c == '-')
            html_go(s, HCOMMSTARTDASH);
        else if (c == '>')
            html_go(s, HDATA);  /* very short comment <!-->  */
        else
            html_go(s, HCOMM);
        break;

    case HCOMMSTARTDASH:    /* 8.2.4.47 Comment start dash state */
        if (c == '-')
            html_go(s, HCOMMEND);
        else if (c == '>')
            html_go(s, HDATA);  /* incorrectly formed -> comment end */
        else
            html_go(s, HCOMM);
        /* else strip */
        break;

    case HCOMM:             /* 8.2.4.48 Comment state */
        if (c == '-')
            html_go(s, HCOMMENDDASH);
        /* else strip */
        break;

    case HCOMMENDDASH:      /* 8.2.4.49 Comment end dash state */
        if (c == '-')
            html_go(s, HCOMMEND);   /* -- pair in comment */
        else
            html_go(s, HCOMM);      /* lone - in comment */
        break;

    case HCOMMEND:          /* 8.2.4.50 Comment end state */
        if (c == '>')
            html_go(s, HDATA);  /* correctly formed --> comment end */
        else if (c == '!')
            html_go(s, HCOMMENDBANG);   /* --! in a comment */
        else if (c != '-')
            html_go(s, HCOMM);  /* -- in the middle of a comment */
        /* else, --- in comment, strip */
        break;

    case HCOMMENDBANG:      /* 8.2.4.51 Comment end bang state */
        if (c == '-')
            html_go(s, HCOMMENDDASH);   /* --!- in comment */
        else if (c == '>')
            html_go(s, HDATA);  /* --!> at end of comment */
        else
            html_go(s, HCOMM);  /* --! in the middle of a comment */
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
    if (rock->f == uni2searchform) return "uni2searchform";
    if (rock->f == uni2html) return "uni2html";
    if (rock->f == table2uni) return "table2uni";
    if (rock->f == uni2utf8) return "uni2utf8";
    if (rock->f == utf8_2uni) return "utf8_2uni";
    if (rock->f == uni2icu) return "uni2icu";
    if (rock->f == icu2uni) return "icu2uni";
    return "wtf";
}

/* convert_rock manipulation routines */

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

static void icu_flush(struct convert_rock *rock)
{
    struct charset_converter *s = (struct charset_converter *) rock->state;
    s->flush = 1;
    if (rock->f == icu2uni) {
        icu2uni(rock, -1);
    }
    else if (rock->f == uni2icu) {
        uni2icu(rock, U_REPLACEMENT);
    }
    s->flush = 0;
}

static void icu_free(struct convert_rock *rock)
{
    if (rock) {
        if (rock->state) icu_reset(rock, -1 /*don't care*/);
        free(rock);
    }
}

static void icu_reset(struct convert_rock *rock, int to_uni)
{
    struct charset_converter *s = (struct charset_converter *)rock->state;
    size_t buf_size = CHARSET_ICUBUF_BUFFER_SIZE;

    if (s->buf_size < buf_size) {
        s->buf = xrealloc(s->buf, buf_size * 2);
        s->buf_size = buf_size;
    }

    ucnv_reset(s->conv);
    s->tgt_base = s->buf;
    s->tgt_top = s->tgt_base + s->buf_size;
    s->tgt_next = s->tgt_base;
    s->src_base = s->buf + s->buf_size;
    s->src_top = s->src_base + s->buf_size;
    s->src_next = s->src_base;

    rock->f = to_uni ? icu2uni : uni2icu;
    rock->flush = icu_flush;
    rock->cleanup = icu_free;
}

static void table_free(struct convert_rock *rock)
{
    if (rock) free(rock);
}

static void table_reset(struct convert_rock *rock, int to_uni)
{
    struct charset_converter *s = (struct charset_converter *)rock->state;

    if (chartables_charset_table[s->num].table) {
        s->initialtable = chartables_charset_table[s->num].table;
        s->curtable = s->initialtable;
    }
    if (strstr(chartables_charset_table[s->num].name, "utf-8")) {
        rock->f = to_uni ? utf8_2uni : uni2utf8;
    } else {
        /* A truly table-based converter may never convert from Unicode
         * to its charmap. This has been implicitly assumed in the existing
         * code, but let's be explicit here. */
        assert(to_uni);
        rock->f = table2uni;
    }
    s->bytesleft = 0;
    s->codepoint = 0;
    s->mode = 0;
    s->num_bits = 0;

    rock->cleanup = table_free;
}

static void convert_switch(struct convert_rock *rock, charset_t to, int to_uni)
{
    struct charset_converter *s = (struct charset_converter *) rock->state;

    /* make sure that the new state is sane */
    assert((to->conv == NULL) != (to->num == -1));

    /* flush any cached bytes in the ICU converter */
    if (s->conv) {
        icu_flush(rock);
        icu_reset(rock, to_uni);
    } else {
        table_reset(rock, to_uni);
    }

    /* how the new state in the pipeline */
    rock->state = to;
    if (to->conv) {
        icu_reset(rock, to_uni);
    } else {
        table_reset(rock, to_uni);
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

static void dont_free(struct convert_rock *rock)
{
    /* NULL out state owned by caller, so we won't free in basic_free */
    if (rock) rock->state = NULL;
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

static void convert_nfree(struct convert_rock *rock, int n) {
    struct convert_rock *next;
    int i = 0;
    while (rock && (!n || (i++ < n))) {
        next = rock->next;
        if (rock->cleanup)
            rock->cleanup(rock);
        else
            basic_free(rock);
        rock = next;
    }
}
#define convert_free(rock) convert_nfree(rock, 0)

/* converter initialisation routines */

static struct convert_rock *qp_init(int isheader, struct convert_rock *next)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    struct qp_state *s = xzmalloc(sizeof(struct qp_state));
    s->isheader = isheader;
    rock->state = (void *)s;
    rock->f = qp2byte;
    rock->flush = qp_flush;
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

static struct convert_rock *unfold_init(int skipws, struct convert_rock *next)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    struct unfold_state *s = xzmalloc(sizeof(struct unfold_state));
    s->skipws = skipws;
    rock->state = s;
    rock->f = unfold2uni;
    rock->next = next;
    return rock;
}

static struct convert_rock *canon_init(int flags, struct convert_rock *next)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    struct canon_state *s = xzmalloc(sizeof(struct canon_state));
    s->flags = flags;
    if ((flags & CHARSET_SNIPPET))
        rock->f = uni2html;
    else
        rock->f = uni2searchform;
    rock->state = s;
    rock->next = next;
    return rock;
}

static struct convert_rock *convert_init(struct charset_converter *s,
                                         int to_uni,
                                         struct convert_rock *next)
{
    struct convert_rock *rock;
    rock = xzmalloc(sizeof(struct convert_rock));
    rock->state = s;
    rock->next = next;

    /* Assert a sane state */
    assert((s->conv == NULL) != (s->num == -1));

    /* Initialize rock based on the converter type */
    if (s->conv) {
        icu_reset(rock, to_uni);
    } else {
        table_reset(rock, to_uni);
    } 

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
    s->starts = xmalloc(s->max_start * sizeof(s->starts[0]));
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

static void buffer_setbuf(struct convert_rock *rock, struct buf *dst)
{
    if (rock->state) {
        buf_free(rock->state);
        free(rock->state);
    }
    rock->state = dst;
    rock->cleanup = dont_free;
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

static char* convert_to_name(const char *to, charset_t charset,
                             const char *src, size_t len)
{
    UErrorCode err = U_ZERO_ERROR;
    const char *from;
    char *res = NULL;
    size_t n;

    /* determine the name of the source encoding */
    from = charset_name(charset);

    /* allocate the target buffer */
    /* we preflight to compromise between memory and runtime efficiency */
    n = ucnv_convert(to, from, res, 0, src, len, &err) + 1;
    if (err != U_BUFFER_OVERFLOW_ERROR) return NULL;
    res = xmalloc(n);

    /* run the conversion */
    err = U_ZERO_ERROR;
    ucnv_convert(to, from, res, n, src, len, &err);
    if (U_FAILURE(err)) {
        free(res);
        return NULL;
    }

    return res;
}

static charset_t lookup_buf(const char *buf, size_t len)
{
    char *name = xstrndup(buf, len);
    charset_t cs = charset_lookupname(name);
    free(name);
    return cs;
}


/* API */

/*
 * Return the name of the given character set number, or "unknown" if
 * not known.
 */
EXPORTED const char *charset_name(charset_t charset)
{
    const char *name;

    if (charset->name)
        return charset->name;

    if (charset->conv) {
        UErrorCode err = U_ZERO_ERROR;
        name = ucnv_getName(charset->conv, &err);
        if (U_SUCCESS(err))
            return name;
    } else if (charset->num >= 0 && charset->num < chartables_num_charsets) {
        return chartables_charset_table[charset->num].name;
    }

    return "unknown";
}

/*
 * Lookup the character set 'name'.  Returns the character set
 * or CHARSET_UNKNOWN_CHARSET if there is no matching character set.
 */
EXPORTED charset_t charset_lookupname(const char *name)
{
    int i;
    struct charset_converter *s;
    UErrorCode err;
    UConverter *conv;

    /* create the converter */
    s = xzmalloc(sizeof(struct charset_converter));
    s->num = -1;

    if (!name) {
        s->num = 0; // us-ascii
        return s;
    }

    /* translate to canonical name */
    for (i = 0; charset_aliases[i].name; i++) {
        if (!strcasecmp(name, charset_aliases[i].name) ||
            !strcasecmp(name, charset_aliases[i].canon_name)) {
            name = charset_aliases[i].canon_name;
            s->name = xstrdup(name);
            break;
        }
    }

    /* Is it a table based lookup, or UTF-8? */
    for (i = 0; i < chartables_num_charsets; i++) {
        if (!strcasecmp(name, chartables_charset_table[i].name)) {
            if ((chartables_charset_table[i].table) || !strcmp(name, "utf-8")) {
                s->num = i;
                return s;
            }
        }
    }

    /* Otherwise, let's see if we can fallback to ICU */
    err = U_ZERO_ERROR;
    conv = ucnv_open(name, &err);
    if (U_SUCCESS(err)) {
        s->conv = conv;
        return s;
    }

    /* Still here? This means we don't know this charset name */
    free(s);
    return CHARSET_UNKNOWN_CHARSET;
}

EXPORTED void charset_free(charset_t *charsetp)
{
    if (charsetp && *charsetp != CHARSET_UNKNOWN_CHARSET) {
        struct charset_converter *s = *charsetp;
        /* Close the ICU converter */
        if (s->conv) ucnv_close(s->conv);
        /* Free up memory. */
        if (s->buf) free(s->buf);
        if (s->name) free(s->name);
        /* Release the converter */
        free(s);
        *charsetp = CHARSET_UNKNOWN_CHARSET;
    }
}

/* Lookup charset for the legacy numeric charset identifier id */
EXPORTED charset_t charset_lookupnumid(int id)
{
    if (id < 0 || id >= chartables_num_charsets)
        return CHARSET_UNKNOWN_CHARSET;
    if (!chartables_charset_table[id].name)
        return CHARSET_UNKNOWN_CHARSET;
    return charset_lookupname(chartables_charset_table[id].name);
}

/*
 * Convert the string 's' in the character set numbered 'charset'
 * into canonical searching form.  Returns a newly allocated string
 * which must be free()d by the caller.
 */
EXPORTED char *charset_convert(const char *s, charset_t charset, int flags)
{
    struct convert_rock *input, *tobuffer;
    char *res;
    charset_t utf8;

    if (!s) return 0;

    if (charset == CHARSET_UNKNOWN_CHARSET) return xstrdup("X");

    utf8 = charset_lookupname("utf-8");

    /* set up the conversion path */
    tobuffer = buffer_init();
    input = convert_init(utf8, 0/*to_uni*/, tobuffer);
    input = canon_init(flags, input);
    input = convert_init(charset, 1/*to_uni*/, input);

    /* do the conversion */
    convert_cat(input, s);

    /* extract the result */
    res = buffer_cstring(tobuffer);

    /* clean up */
    convert_free(input);
    charset_free(&utf8);

    return res;
}

/* Convert from a given charset and encoding into IMAP UTF-7 */
EXPORTED char *charset_to_imaputf7(const char *msg_base, size_t len, charset_t charset, int encoding)
{
    struct convert_rock *input, *tobuffer;
    char *res;
    charset_t imaputf7;

    /* Initialize character set mapping */
    if (charset == CHARSET_UNKNOWN_CHARSET) return 0;

    /* check for trivial search */
    if (len == 0)
        return xstrdup("");

    /* check if we can convert the whole block at once */
    if (encoding == ENCODING_NONE)
        return convert_to_name("imap-mailbox-name", charset, msg_base, len);

    /* set up the conversion path */
    imaputf7 = charset_lookupname("imap-mailbox-name");
    tobuffer = buffer_init();
    input = convert_init(imaputf7, 0/*to_uni*/, tobuffer);
    input = convert_init(charset, 1/*to_uni*/, input);

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
            charset_free(&imaputf7);
            return 0;
    }

    /* do the conversion */
    convert_catn(input, msg_base, len);

    /* extract the result */
    res = buffer_cstring(tobuffer);

    /* clean up */
    convert_free(input);
    charset_free(&imaputf7);

    return res;
}

EXPORTED char *charset_utf8_to_searchform(const char *s, int flags)
{
    charset_t utf8 = charset_lookupname("utf-8");
    char *ret = charset_convert(s, utf8, flags);
    charset_free(&utf8);
    return ret;
}

/* Convert from a given charset and encoding into utf8 */
EXPORTED char *charset_to_utf8(const char *msg_base, size_t len, charset_t charset, int encoding)
{
    struct convert_rock *input, *tobuffer;
    char *res;
    charset_t utf8;

    /* Initialize character set mapping */
    if (charset == CHARSET_UNKNOWN_CHARSET) return NULL;

    /* check for trivial search */
    if (len == 0)
        return xstrdup("");

    /* check if we can convert the whole block at once */
    if (encoding == ENCODING_NONE)
        return convert_to_name("utf-8", charset, msg_base, len);

    /* set up the conversion path */
    utf8 = charset_lookupname("utf-8");
    tobuffer = buffer_init();
    input = convert_init(utf8, 0/*to_uni*/, tobuffer);
    input = convert_init(charset, 1/*to_uni*/, input);

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
        charset_free(&utf8);
        return 0;
    }

    convert_catn(input, msg_base, len);
    res = buffer_cstring(tobuffer);
    convert_free(input);
    charset_free(&utf8);

    return res;
}

/* Decode bytes from src into buffer dst */
EXPORTED int charset_decode(struct buf *dst, const char *src, size_t len, int encoding)
{
    struct convert_rock *input;

    buf_reset(dst);

    /* check for trivial decode */
    if (len == 0 || encoding == ENCODING_NONE) {
        buf_setmap(dst, src, len);
        return 0;
    }

    /* set up the conversion path */
    input = buffer_init();
    buffer_setbuf(input, dst);

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
        return -1;
    }

    convert_catn(input, src, len);
    convert_free(input);

    return 0;
}

static void mimeheader_cat(struct convert_rock *target, const char *s, int flags)
{
    struct convert_rock *input, *unfold;
    int eatspace = 0;
    const char *start, *endcharset, *encoding, *end;
    int len;
    const char *p;
    charset_t defaultcs, cs;

    if (!s) return;

    /* set up the conversion path */
    if (flags & CHARSET_MIME_UTF8) {
        defaultcs = charset_lookupname("utf-8");
    } else {
        defaultcs = charset_lookupname("us-ascii");
    }
    input = convert_init(defaultcs, 1/*to_uni*/, target);

    /* note: we assume the caller of this function has already
     * determined that all newlines are followed by whitespace */
    unfold = unfold_init(0 /*skipws*/, input);

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
            convert_switch(input, defaultcs, 1/*to_uni*/);
            convert_catn(unfold, s, len);
        }

        /*
         * Get the 1522-word's character set
         */
        start++;
        cs = lookup_buf(start, endcharset-start);
        if (cs == CHARSET_UNKNOWN_CHARSET) {
            /* Unrecognized charset, nothing will match here */
            convert_putc(input, U_REPLACEMENT); /* unknown character */
        }
        else {
            struct convert_rock *extract;
            convert_switch(input, cs, 1/*to_uni*/);

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
        convert_switch(input, defaultcs, 1 /*to_uni*/);
        charset_free(&cs);

        /* Prepare for the next iteration */
        s = start = end+2;
        eatspace = 1;
    }

    /* Copy over the tail part of the input string */
    if (*s) {
        convert_switch(input, defaultcs, 1/*to_uni*/); /* US_ASCII */
        convert_cat(unfold, s);
    }

    /* just free the first two items, the rest can be cleaned up by the sender */
    basic_free(unfold);
    convert_nfree(input, 1);
    charset_free(&defaultcs);
}

/*
 * Decode MIME strings (per RFC 2047) in 's'.  Returns a newly allocated
 * string, containing 's' in canonical searching form, which must be
 * free()d by the caller.
 */
EXPORTED char *charset_decode_mimeheader(const char *s, int flags)
{
    struct convert_rock *tobuffer, *input;
    char *res;
    charset_t utf8;

    if (!s) return NULL;

    utf8 = charset_lookupname("utf-8");
    tobuffer = buffer_init();
    input = convert_init(utf8, 0/*to_uni*/, tobuffer);
    input = canon_init(flags, input);

    mimeheader_cat(input, s, flags);

    res = buffer_cstring(tobuffer);

    convert_free(input);
    charset_free(&utf8);

    return res;
}

/*
 * Unfold len bytes of string s into a new string, which must be freed()
 * by the caller. Unfolding removes any CRLF that is immediately followed
 * by a tab or space character. If flags sets CHARSET_UNFOLD_SKIPWS, then
 * the whitespace character is also omitted.
 */
EXPORTED char *charset_unfold(const char *s, size_t len, int flags)
{
    struct convert_rock *tobuffer, *input;
    char *res;

    if (!s) return NULL;

    tobuffer = buffer_init();
    input = unfold_init(flags&CHARSET_UNFOLD_SKIPWS, tobuffer);

    convert_catn(input, s, len);

    res = buffer_cstring(tobuffer);

    convert_free(input);

    return res;
}

/*
 * Decode MIME strings (per RFC 2047) in 's'.  Returns a newly allocated
 * string, containing the decoded string, which must be free()d by the
 * caller.
 */
EXPORTED char *charset_parse_mimeheader(const char *s, int flags)
{
    struct convert_rock *tobuffer, *input;
    char *res;
    charset_t utf8;

    if (!s) return NULL;

    utf8 = charset_lookupname("utf-8");
    tobuffer = buffer_init();
    input = convert_init(utf8, 0/*to_uni*/, tobuffer);

    mimeheader_cat(input, s, flags);

    res = buffer_cstring(tobuffer);

    convert_free(input);
    charset_free(&utf8);

    return res;
}

EXPORTED int charset_search_mimeheader(const char *substr, comp_pat *pat,
                              const char *s, int flags)
{
    struct convert_rock *input, *tosearch;
    int res;
    charset_t utf8 = charset_lookupname("utf-8");

    tosearch = search_init(substr, pat);
    input = convert_init(utf8, 0/*to_uni*/, tosearch);
    input = canon_init(flags, input);

    mimeheader_cat(input, s, flags);

    res = search_havematch(tosearch);

    convert_free(input);
    charset_free(&utf8);

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
    /* count occurrences */
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
    if (!substr[0])
        return 1; /* zero length string always matches */

    struct convert_rock *tosearch;
    struct convert_rock *input;
    int res;
    charset_t utf8from, utf8to;
    utf8from = charset_lookupname("utf-8");
    utf8to = charset_lookupname("utf-8");

    /* set up the search handler */
    tosearch = search_init(substr, pat);

    /* and the input stream */
    input = convert_init(utf8to, 0/*to_uni*/, tosearch);
    input = canon_init(flags, input);
    input = convert_init(utf8from, 1/*to_uni*/, input);

    /* feed the handler */
    while (len-- > 0) {
        convert_putc(input, (unsigned char)*s++);
        if (search_havematch(tosearch)) break; /* shortcut if there's a match */
    }

    /* copy the value */
    res = search_havematch(tosearch);

    /* clean up */
    convert_free(input);
    charset_free(&utf8from);
    charset_free(&utf8to);

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
                       charset_t charset, int encoding, int flags)
{
    struct convert_rock *input, *tosearch;
    size_t i;
    int res;
    charset_t utf8;

    /* Initialize character set mapping */
    if (charset == CHARSET_UNKNOWN_CHARSET) return 0;

    /* check for trivial search */
    if (strlen(substr) == 0)
        return 1;

    /* set up the conversion path */
    utf8 = charset_lookupname("utf-8");
    tosearch = search_init(substr, pat);
    input = convert_init(utf8, 0/*to_uni*/, tosearch);
    input = canon_init(flags, input);
    input = convert_init(charset, 1/*to_uni*/, input);

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
        charset_free(&utf8);
        return 0;
    }

    /* implement the loop here so we can check on the search each time */
    for (i = 0; i < len; i++) {
        convert_putc(input, (unsigned char)msg_base[i]);
        if (search_havematch(tosearch)) break;
    }

    res = search_havematch(tosearch); /* copy before we free it */

    convert_free(input);
    charset_free(&utf8);

    return res;
}

/* This is based on charset_searchfile above. */
EXPORTED int charset_extract(void (*cb)(const struct buf *, void *),
                             void *rock,
                             const struct buf *data,
                             charset_t charset, int encoding,
                             const char *subtype, int flags)
{
    struct convert_rock *input, *tobuffer;
    struct buf *out;
    size_t i;
    charset_t utf8;
    
    if (charset_debug)
        fprintf(stderr, "charset_extract()\n");

    /* Initialize character set mapping */
    if (charset == CHARSET_UNKNOWN_CHARSET) return 0;

    /* set up the conversion path */
    utf8 = charset_lookupname("utf-8");
    tobuffer = buffer_init();
    input = convert_init(utf8, 0/*to_uni*/, tobuffer);
    input = canon_init(flags, input);

    if (!strcmpsafe(subtype, "HTML")) {
        if ((flags & CHARSET_SKIPHTML)) {
            /* silently pretend we indexed it, but actually ignore it */
            convert_free(input);
            charset_free(&utf8);
            return 1;
        }
        /* this is text/html data, so we can make ourselves useful by
         * stripping html tags, css and js. */
        input = striphtml_init(input);
    }

    input = convert_init(charset, 1/*to_uni*/, input);

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
        charset_free(&utf8);
        return 0;
    }

    /* point to the buffer for easy block sending */
    out = (struct buf *)tobuffer->state;

    for (i = 0; i < data->len; i++) {
        convert_putc(input, (unsigned char)data->s[i]);

        /* process a block of output every so often */
        if (buf_len(out) > 4096) {
            cb(out, rock);
            buf_reset(out);
        }
    }
    /* finish it */
    convert_flush(input);
    if (out->len) { 
        cb(out, rock);
    }

    convert_free(input);
    charset_free(&utf8);

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


/*
 * If 'isheader' is non-zero "Q" encode (per RFC 2047), otherwise
 * quoted-printable encode (per RFC 2045), the 'data' of 'len' bytes.
 * Returns a buffer which the caller must free.
 * Returns the number of encoded bytes in 'outlen'.
 */
static char *qp_encode(const char *data, size_t len, int isheader,
                       size_t *outlen)
{
    struct buf buf = BUF_INITIALIZER;
    size_t n;
    int need_quote = 0;

    for (n = 0; n < len; n++) {
        unsigned char this = data[n];
        unsigned char next = (n < len - 1) ? data[n+1] : '\0';

        if (QPSAFECHAR[this] || this == '=' || this == ' ' || this == '\t') {
            /* per RFC 5322: printable ASCII (decimal 33 - 126), SP, HTAB */
            continue;
        }
        else if (!isheader && this == '\r' && next == '\n') {
            /* line break (CRLF) */
            n++;
            continue;
        }
        need_quote = 1;
        break;
    }

    if (need_quote) {
        int cnt = 0;

        if (isheader) {
            buf_appendcstr(&buf, "=?UTF-8?Q?");
            cnt = 10;
        }

        for (n = 0; n < len; n++) {
            unsigned char this = data[n];
            unsigned char next = (n < len - 1) ? data[n+1] : '\0';

            if (cnt >= BASE64_MAX_LINE_LEN) {
                if (isheader) {
                    /* split encoded token with fold */
                    buf_appendcstr(&buf, "?=");
                    buf_appendcstr(&buf, "\r\n ");
                    buf_appendcstr(&buf, "=?UTF-8?Q?");
                    cnt = 11;
                }
                else {
                    /* add soft line break to body */
                    buf_appendcstr(&buf, "=\r\n");
                    cnt = 0;
                }
            }

            if ((QPSAFECHAR[this]
                 /* per RFC 2047: '?' and '_' in header aren't safe */
                 && !(isheader && (this == '?' || this == '_')))

                /* per RFC 2045: non-trailing whitespace in body is safe */
                || (!isheader && (this == ' ' || this == '\t') &&
                    !(next == '\0' || next == '\r' || next == '\n'))) {

                /* literal representation */
                buf_putc(&buf, (char)this);
                cnt++;
            }
            else if (isheader && this == ' ') {
                /* per RFC 2047: represent SP in header as '_' for legibility */
                buf_putc(&buf, '_');
                cnt++;
            }
            else if (this == '\r' && next == '\n') {
                if (isheader) {
                    /* folded header, split encoded token */
                    if (n < len - 2) {
                        /* only if actually a folding character, skip it */
                        if (data[n+2] == ' ' || data[n+2] == '\t')
                            n++;
                        buf_appendcstr(&buf, "?=\r\n =?UTF-8?Q?");
                        cnt = 12;
                    }
                }
                else {
                    /* line break (CRLF) in body */
                    buf_appendcstr(&buf, "\r\n");
                    cnt = 0;
                }
                n++;
            }
            else {
                /* 8-bit representation */
                buf_printf(&buf, "=%02X", this);
                cnt += 3;
            }
        }

        if (isheader) buf_appendcstr(&buf, "?=");
    }
    else {
        buf_setmap(&buf, data, len);
    }

    if (outlen) *outlen = buf_len(&buf);

    return buf_release(&buf);
}

/*
 * Quoted-Printable encode the MIME body part (per RFC 2045) of 'len' bytes
 * located at 'msg_base'.
 * Returns a buffer which the caller must free.
 * Returns the number of encoded bytes in 'outlen'.
 */
EXPORTED char *charset_qpencode_mimebody(const char *msg_base, size_t len,
                                         size_t *outlen)
{
    if (!msg_base) return NULL;

    return qp_encode(msg_base, len, 0, outlen);
}


/* "Q" encode the header field body (per RFC 2047) of 'len' bytes
 * located at 'header'.
 * Returns a buffer which the caller must free.
 */
EXPORTED char *charset_encode_mimeheader(const char *header, size_t len)
{
    if (!header) return NULL;

    if (!len) len = strlen(header);

    return qp_encode(header, len, 1, NULL);
}

