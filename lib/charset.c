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
#include <syslog.h>

#include "unicode/ucnv.h"

#include "assert.h"
#include "charset.h"
#include "xmalloc.h"
#include "chartable.h"
#include "hash.h"
#include "htmlchar.h"
#include "util.h"
#include "xsha1.h"

#include <unicode/ustring.h>
#include <unicode/unorm2.h>
#include <unicode/utf8.h>

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
    const char *index;
    int invalid;
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

struct sha1_state {
    SHA_CTX ctx;
    uint8_t buf[4096];
    size_t len;
    size_t *outlen;
    uint8_t *dest;
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

struct charset_charset {
    /* An open ICU converter for ICU backed converters. Or NULL.  */
    UConverter *conv;

    /* Cyrus-canonical charset name for this converter.
     * Might differ from ICU name.*/
    char *canon_name;

    /* Alias name of as provided by caller in charset_lookupname */
    char *alias_name;

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
static int icu_flush(struct convert_rock *rock);
static void icu_cleanup(struct convert_rock *rock, int is_free);

static void table_reset(struct convert_rock *rock, int to_uni);
static void table_cleanup(struct convert_rock *rock, int is_free);

typedef void convertproc_t(struct convert_rock *rock, uint32_t c);
typedef void cleanupconvert_t(struct convert_rock *rock, int is_free);
typedef int flushproc_t(struct convert_rock *rock);

struct convert_rock {
    convertproc_t *f;
    cleanupconvert_t *cleanup;
    flushproc_t *flush;
    struct convert_rock *next;
    void *state;
    int dont_free_state;  /* flag for basic_free */
};

#define GROWSIZE 100

int charset_debug;
static const char *convert_name(struct convert_rock *rock);

#define XS 126 // whitespace character
#define XX 127 // unknown character

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
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XS,XS,XX, XX,XS,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XS,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,64,XX,XX,
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

/*
 * Table for decoding base64url
 */
static const char index_64url[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XS,XS,XX, XX,XS,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XS,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,62,XX,XX,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,64,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,63,
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
#define CHAR64(c, index)  (index[(unsigned char)(c)])

EXPORTED int encoding_lookupname(const char *s)
{
    if (!s) return ENCODING_NONE;

    switch (s[0]) {
    case '7':
        if (!strcasecmp(s, "7BIT"))
            return ENCODING_NONE;
        // non-standard stuff seen in the wild
        if (!strcasecmp(s, "7-BIT"))
            return ENCODING_NONE;
        break;
    case '8':
        if (!strcasecmp(s, "8BIT"))
            return ENCODING_NONE;
        // non-standard stuff seen in the wild
        if (!strcasecmp(s, "8-BIT"))
            return ENCODING_NONE;
        break;
    case 'B':
    case 'b':
        if (!strcasecmp(s, "BASE64"))
            return ENCODING_BASE64;
        if (!strcasecmp(s, "BASE64URL"))
            return ENCODING_BASE64URL;
        if (!strcasecmp(s, "BINARY"))
            return ENCODING_NONE;
        break;
    case 'N':
        if (!strcasecmp(s, "NONE"))
            return ENCODING_NONE;
        break;
    case 'Q':
    case 'q':
        if (!strcasecmp(s, "QUOTED-PRINTABLE"))
            return ENCODING_QP;
        break;
    case 'u':
    case 'U':
        // this is rubbish, but it's been seen in the wild
        if (!strcasecmp(s, "UTF-8"))
            return ENCODING_NONE;
        if (!strcasecmp(s, "UTF8"))
            return ENCODING_NONE;
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
    case ENCODING_BASE64URL: return "BASE64URL";
    case ENCODING_UNKNOWN: return "UNKNOWN";
    default: return "WTF";
    }
}

static int convert_flush(struct convert_rock *rock)
{
    int r = 0;
    while (rock) {
        if (rock->flush) {
            int r2 = rock->flush(rock);
            if (!r) r = r2;
        }
        rock = rock->next;
    }
    return r;
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

static int convert_catn(struct convert_rock *rock, const char *s, size_t len)
{
    while (len-- > 0) {
        convert_putc(rock, (unsigned char)*s);
        s++;
    }
    return convert_flush(rock);
}

/* convertproc_t conversion functions */
static void qp_flushline(struct convert_rock *rock, int endline)
{
    struct qp_state *s = (struct qp_state *)rock->state;
    int i;

    /* strip trailing whitespace: RFC 2405 transport-padding */
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

static int qp_flush(struct convert_rock *rock)
{
    qp_flushline(rock, 0);
    return 0;
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
    char b = CHAR64(c, s->index);

    if (b >= XS) {
        /* ignore whitespace */
        s->invalid = s->invalid || b == XX;
        return;
    }

    /* the padding character, reset state */
    if (b == 64) {
        s->codepoint = 0;
        s->bytesleft = 0;
        return;
    }

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

static int b64_flush(struct convert_rock *rock)
{
    struct b64_state *s = (struct b64_state *)rock->state;
    if (s->invalid) {
        if (s->index == index_64url)
            return -1;
        else
            xsyslog(LOG_WARNING, "ignoring invalid base64 characters", NULL);
    }
    return 0;
}

/*
 * This filter unfolds folded RFC 2822 header field lines, i.e. it strips
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

static void byte2sha1(struct convert_rock *rock, uint32_t c)
{
    struct sha1_state *state = (struct sha1_state *)rock->state;

    /* batch if needed.  Testing showed that calling SHA1_Update
     * for every char was prohibitive, and even doing 64 chars
     * at a time (the internal block size) had overhead due to
     * to the upfront checks, so this is a good compromise size */
    if (state->len == 4096) {
        SHA1_Update(&state->ctx, state->buf, state->len);
        if (state->outlen) *state->outlen += state->len;
        state->len = 0;
    }

    state->buf[state->len++] = c & 0xff;
}

/* Given an octet c and an icu converter, convert c to
 * its Unicode codepoint. During a flush, c is ignored.
 */
static void icu2uni(struct convert_rock *rock, uint32_t c)
{
    struct charset_charset *s = (struct charset_charset*) rock->state;
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
    struct charset_charset *s = (struct charset_charset*) rock->state;
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
    struct charset_charset *s = (struct charset_charset *)rock->state;

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
    struct charset_charset *s = (struct charset_charset *)rock->state;
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
    if (rock->f == byte2sha1) return "byte2sha1";
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
 * call this function then buffer_cleanup will clean up */
static char *buffer_cstring(struct convert_rock *rock)
{
    struct buf *buf = (struct buf *)rock->state;

    return buf_release(buf);
}

static void buffer_trim(struct convert_rock *rock)
{
    struct buf *buf = (struct buf *)rock->state;

    buf_trim(buf);
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
        if (!rock->dont_free_state) free(rock->state);
        free(rock);
    }
}

static int icu_flush(struct convert_rock *rock)
{
    struct charset_charset *s = (struct charset_charset *) rock->state;
    s->flush = 1;
    if (rock->f == icu2uni) {
        icu2uni(rock, -1);
    }
    else if (rock->f == uni2icu) {
        uni2icu(rock, U_REPLACEMENT);
    }
    s->flush = 0;
    return 0;
}

static void icu_cleanup(struct convert_rock *rock, int is_free)
{
    if (rock) {
        if (rock->state) icu_reset(rock, -1 /*don't care*/);
        if (is_free) free(rock);
    }
}

static void sha1_cleanup(struct convert_rock *rock, int do_free)
{
    struct sha1_state *state = (struct sha1_state *)rock->state;

    if (state->len) {
        SHA1_Update(&state->ctx, state->buf, state->len);
        if (state->outlen) *state->outlen += state->len;
    }

    SHA1_Final(state->dest, &state->ctx);

    if (do_free) basic_free(rock);
}

static void icu_reset(struct convert_rock *rock, int to_uni)
{
    struct charset_charset *s = (struct charset_charset *)rock->state;
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
    rock->cleanup = icu_cleanup;
}

static void table_cleanup(struct convert_rock *rock, int is_free)
{
    if (is_free) free(rock);
}

static void table_reset(struct convert_rock *rock, int to_uni)
{
    struct charset_charset *s = (struct charset_charset *)rock->state;

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

    rock->cleanup = table_cleanup;
}

static void convert_switch(struct convert_rock *rock, charset_t to, int to_uni)
{
    struct charset_charset *s = (struct charset_charset *) rock->state;

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

static void search_cleanup(struct convert_rock *rock, int is_free)
{
    if (rock && rock->state) {
        struct search_state *s = (struct search_state *)rock->state;
        if (s->starts && !is_free) {
            int i;
            for (i = 0; i < s->max_start; i++) {
                s->starts[i] = -1;
            }
        }
        else free(s->starts);
    }
    if (is_free) basic_free(rock);
}

static void buffer_cleanup(struct convert_rock *rock, int is_free)
{
    if (rock && rock->state) {
        struct buf *buf = (struct buf *)rock->state;
        if (is_free)
            buf_free(buf);
        else
            buf_reset(buf);
    }
    if (is_free) basic_free(rock);
}

static void dont_free(struct convert_rock *rock, int is_free)
{
    if (!rock || !is_free) return;
    /* NULL out state owned by caller, so we won't free in basic_free */
    if (rock) rock->state = NULL;
    basic_free(rock);
}

static void striphtml_cleanup(struct convert_rock *rock, int is_free)
{
    if (rock && rock->state) {
        struct striphtml_state *s = (struct striphtml_state *)rock->state;
        if (is_free)
            buf_free(&s->name);
        else
            buf_reset(&s->name);
    }
    if (is_free) basic_free(rock);
}

static void convert_ncleanup(struct convert_rock *rock, int n, int is_free) {
    struct convert_rock *next;
    int i = 0;
    while (rock && (!n || (i++ < n))) {
        next = rock->next;
        if (rock->cleanup)
            rock->cleanup(rock, is_free);
        else if (is_free)
            basic_free(rock);
        rock = next;
    }
}
#define convert_free(rock) convert_ncleanup(rock, 0, 1)

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

static struct convert_rock *b64_init(struct convert_rock *next, int enc)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    struct b64_state *state = xzmalloc(sizeof(struct b64_state));
    state->index = enc == ENCODING_BASE64URL ? index_64url : index_64;
    rock->state = state;
    rock->f = b64_2byte;
    rock->flush = b64_flush;
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
    if ((flags & CHARSET_KEEPCASE))
        rock->f = uni2html;
    else
        rock->f = uni2searchform;
    rock->state = s;
    rock->next = next;
    return rock;
}

static struct convert_rock *convert_init(struct charset_charset *s,
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
    rock->cleanup = search_cleanup;
    rock->state = (void *)s;

    return rock;
}

static struct convert_rock *buffer_init(size_t hint)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    struct buf *buf = xzmalloc(sizeof(struct buf));

    if (hint) buf_ensure(buf, hint);

    rock->f = byte2buffer;
    rock->cleanup = buffer_cleanup;
    rock->state = (void *)buf;

    return rock;
}

static struct convert_rock *sha1_init(uint8_t *dest, size_t *outlen)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));
    struct sha1_state *state = xzmalloc(sizeof(struct sha1_state));

    SHA1_Init(&state->ctx);
    state->dest = dest;
    state->outlen = outlen;

    rock->f = byte2sha1;
    rock->cleanup = sha1_cleanup;
    rock->state = (void *)state;

    return rock;
}

static struct convert_rock *buffer_initm(size_t hint, struct buf *buf)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));

    if (hint) buf_ensure(buf, hint);

    rock->f = byte2buffer;
    rock->cleanup = buffer_cleanup;
    rock->state = (void *)buf;
    rock->dont_free_state = 1;

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
    rock->cleanup = striphtml_cleanup;
    rock->next = next;
    return rock;
}

struct unorm_state {
    const UNormalizer2 *unorm;
    UChar *u16buf;
    int32_t u16cap;
    UChar32 *u32buf;
    int32_t u32cap;
    int32_t u32len;
    int32_t spanlen;
};

static void unorm_append(struct unorm_state *st, uint32_t c)
{
    if (st->u32len == st->u32cap) {
        st->u32cap += 8;
        st->u32buf = xrealloc(st->u32buf, sizeof(UChar32) * st->u32cap);
    }
    if (!st->spanlen && !unorm2_getCombiningClass(st->unorm, c)) {
        /* End of the first span of composable codepoints */
        st->spanlen = st->u32len;
    }
    st->u32buf[st->u32len++] = c;
}

static void unorm_drain(struct convert_rock *rock, int is_flush)
{
    struct unorm_state *st = rock->state;

    /* Have we reached the end of a composable span? */
    if (!st->spanlen) {
        if (!is_flush) {
            return;
        }
        st->spanlen = st->u32len;
    }
    if (!st->spanlen) return;

    /* Insertion-sort span by combining class */
    int i;
    for (i = 1; i < st->spanlen; i++) {
        UChar32 c = st->u32buf[i];
        int j = i - 1;
        while (j >= 0) {
            if (unorm2_getCombiningClass(st->unorm, st->u32buf[j]) <=
                    unorm2_getCombiningClass(st->unorm, c)) {
                break;
            }
            st->u32buf[j+1] = st->u32buf[j];
            j = j - 1;
        }
        st->u32buf[j+1] = c;
    }

    /* Emit composed codepoints in span */
    UChar32 u1 = st->u32buf[0];
    for (i = 1; i < st->spanlen; i++) {
        UChar32 u2 = unorm2_composePair(st->unorm, u1, st->u32buf[i]);
        if (u2 < 0) {
            convert_putc(rock->next, u1);
            u1 = st->u32buf[i];
        }
        else u1 = u2;
    }
    convert_putc(rock->next, u1);

    /* Keep any remaining code points */
    int j;
    for (i = 0, j = st->spanlen; j < st->u32len; j++) {
        st->u32buf[i++] = st->u32buf[j];
    }
    st->u32len -= st->spanlen;
    st->spanlen = 0;
    for (i = 0; i < st->u32len; i++) {
        if (!unorm2_getCombiningClass(st->unorm, st->u32buf[i])) {
            st->spanlen = i;
            break;
        }
    }

    /* In case of flush, drain all we got */
    if (is_flush && st->u32len) {
        unorm_drain(rock, is_flush);
    }
}

static void unorm_cleanup(struct convert_rock *rock, int is_free)
{
    if (!rock || !rock->state) return;

    struct unorm_state *st = rock->state;
    if (is_free) {
        free(st->u16buf);
        free(st->u32buf);
        free(st);
        free(rock);
    }
    else {
        int32_t i;
        for (i = 0; i < st->u16cap; i++) {
            st->u16buf[i] = 0;
        }
        for (i = 0; i < st->u32cap; i++) {
            st->u32buf[i] = 0;
        }
        st->u32len = 0;
    }
}

static int unorm_flush(struct convert_rock *rock)
{
    unorm_drain(rock, 1);
    return 0;
}

static void unorm_convert(struct convert_rock *rock, uint32_t c)
{
    struct unorm_state *st = rock->state;
    UErrorCode err = U_ZERO_ERROR;

    int32_t len = unorm2_getDecomposition(st->unorm, c, NULL, 0, &err);

    if (len > 0) {
        /* Decompose c into NFD */
        if (len > st->u16cap) {
            st->u16buf = xrealloc(st->u16buf, sizeof(UChar) * len);
            st->u16cap = len;
        }
        err = U_ZERO_ERROR;
        unorm2_getDecomposition(st->unorm, c, st->u16buf, st->u16cap, &err);
        /* Append NFD codepoints */
        if (U_SUCCESS(err)) {
            int32_t i = 0;
            while (i < len) {
                U16_NEXT(st->u16buf, i, len, c);
                unorm_append(st, c);
            }
        }
    }

    if (len < 0 || U_FAILURE(err)) {
        /* Append verbatim */
        unorm_append(st, c);
    }

    unorm_drain(rock, 0);
}

static struct convert_rock *unorm_init(struct convert_rock *next)
{
    struct convert_rock *rock = xzmalloc(sizeof(struct convert_rock));

    struct unorm_state *st = xzmalloc(sizeof(struct unorm_state));
    UErrorCode err = U_ZERO_ERROR;
    st->unorm = unorm2_getNFCInstance(&err);
    assert(U_SUCCESS(err));

    st->u16cap = 8;
    st->u16buf = xmalloc(sizeof(UChar) * st->u16cap);
    st->u32cap = 8;
    st->u32buf = xmalloc(sizeof(UChar32) * st->u32cap);

    rock->f = unorm_convert;
    rock->flush = unorm_flush;
    rock->cleanup = unorm_cleanup;
    rock->next = next;
    rock->state = st;
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
    from = charset_canon_name(charset);

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

/* RFC 2047: In this case the set of characters that may be used in a “Q”-encoded
  ‘encoded-word’ is restricted to: <upper and lower case ASCII
  letters, decimal digits, "!", "*", "+", "-", "/", "=", and "_" */
/* of course = and _ are not included in the set, because they themselves
   need to be quoted it’s just saying they can be present in the Q wordi
   itself, because they’re part of the quoting system */
char QPMIMEPHRASESAFECHAR[256] = {
/* control chars are unsafe */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* ASCII map... */
/*     !  "  #  $  %  &  '  (  )  *  +  ,  -  .  /  */
    0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1,
/*  0  1  2  3  4  5  6  7  8  9  :  ;  <  =  >  ?  */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
/*  @  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
/*  P  Q  R  S  T  U  V  W  X  Y  Z  [ \\  ]  ^  _  */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
/*  `  a  b  c  d  e  f  g  h  i  j  k  l  m  n  o  */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
/*  p  q  r  s  t  u  v  w  x  y  z  {  |  }  ~ DEL */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
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


/* API */

EXPORTED const char *charset_alias_name(charset_t cs) {
    if (cs && cs->alias_name) {
        return cs->alias_name;
    }
    return charset_canon_name(cs);
}

/*
 * Return the name of the given character set number, or "unknown" if
 * not known.
 */
EXPORTED const char *charset_canon_name(charset_t cs)
{
    if (!cs)
            goto done;

    if (cs->canon_name)
        return cs->canon_name;

    if (cs->conv) {
        UErrorCode err = U_ZERO_ERROR;
        const char *name = ucnv_getName(cs->conv, &err);
        if (U_SUCCESS(err))
            return name;
    } else if (cs->num >= 0 && cs->num < chartables_num_charsets) {
        return chartables_charset_table[cs->num].name;
    }

done:
    return "unknown";
}

/*
 * Lookup the character set 'name'.  Returns the character set
 * or CHARSET_UNKNOWN_CHARSET if there is no matching character set.
 */
EXPORTED charset_t charset_lookupname(const char *name)
{
    int i;
    struct charset_charset *cs;
    UErrorCode err;
    UConverter *conv;

    /* create the converter */
    cs = xzmalloc(sizeof(struct charset_charset));
    cs->num = -1;

    if (!name) {
        cs->num = 0; // us-ascii
        return cs;
    }
    cs->alias_name = xstrdup(name);

    /* translate alias to canonical name */
    for (i = 0; charset_aliases[i].name; i++) {
        if (!strcasecmp(name, charset_aliases[i].name)) {
            cs->canon_name = xstrdup(charset_aliases[i].canon_name);
            break;
        }
    }
    if (!cs->canon_name) {
        /* otherwise use canonical name, if defined */
        for (i = 0; charset_aliases[i].name; i++) {
            if (!strcasecmp(name, charset_aliases[i].canon_name)) {
                cs->canon_name = xstrdup(charset_aliases[i].canon_name);
                break;
            }
        }
    }

    /* Is it a table based lookup, or UTF-8? */
    if (cs->canon_name) {
        for (i = 0; i < chartables_num_charsets; i++) {
            if (!strcasecmp(cs->canon_name, chartables_charset_table[i].name)) {
                if ((chartables_charset_table[i].table) || !strcmp(cs->canon_name, "utf-8")) {
                    cs->num = i;
                    return cs;
                }
            }
        }
    }

    /* Otherwise, let's see if we can fallback to ICU */
    err = U_ZERO_ERROR;
    conv = ucnv_open(cs->canon_name ? cs->canon_name : name, &err);
    if (U_SUCCESS(err)) {
        cs->conv = conv;
        return cs;
    }

    /* Still here? This means we don't know this charset name */
    free(cs->alias_name);
    free(cs->canon_name);
    free(cs);
    return CHARSET_UNKNOWN_CHARSET;
}

EXPORTED void charset_free(charset_t *charsetp)
{
    if (charsetp && *charsetp != CHARSET_UNKNOWN_CHARSET) {
        struct charset_charset *s = *charsetp;
        /* Close the ICU converter */
        if (s->conv) ucnv_close(s->conv);
        /* Free up memory. */
        if (s->buf) free(s->buf);
        free(s->alias_name);
        free(s->canon_name);
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

struct charset_conv {
    struct convert_rock *input;
    charset_t charset;
    charset_t utf8;
    struct buf dst;
};

EXPORTED charset_conv_t *charset_conv_new(charset_t charset, int flags)
{
    struct charset_conv *conv = xzmalloc(sizeof(struct charset_conv));

    conv->charset = charset;
    conv->utf8 = charset_lookupname("utf-8");

    /* set up the conversion path */
    struct convert_rock *input, *tobuffer;
    tobuffer = buffer_initm(0, &conv->dst);
    input = convert_init(conv->utf8, 0/*to_uni*/, tobuffer);
    input = canon_init(flags, input);
    if (flags & CHARSET_UNORM_NFC) {
        input = unorm_init(input);
    }
    input = convert_init(conv->charset, 1/*to_uni*/, input);

    conv->input = input;

    return conv;
}

EXPORTED const char *charset_conv_convert(charset_conv_t *conv, const char *s)
{
    if (!s) return NULL;

    convert_ncleanup(conv->input, 0, 0);
    buf_reset(&conv->dst);

    if (conv->charset == CHARSET_UNKNOWN_CHARSET)
        buf_setcstr(&conv->dst, "X");
    else
        convert_cat(conv->input, s);

    return buf_cstring(&conv->dst);
}

EXPORTED void charset_conv_free(charset_conv_t **convp)
{
    if (!convp || !*convp) return;

    charset_conv_t *conv = *convp;
    convert_free(conv->input);
    charset_free(&conv->utf8);
    buf_free(&conv->dst);
    free(conv);
    *convp = NULL;
}

/*
 * Convert the string 's' in the character set numbered 'charset'
 * into canonical searching form.  Returns a newly allocated string
 * which must be free()d by the caller.
 */
EXPORTED char *charset_convert(const char *s, charset_t charset, int flags)
{
    charset_conv_t *conv = charset_conv_new(charset, flags);
    char *ret = NULL;
    if (charset_conv_convert(conv, s)) {
        ret = buf_release(&conv->dst);
    }
    charset_conv_free(&conv);
    return ret;
}

/* Convert from a given charset and encoding into IMAP UTF-7 */
EXPORTED char *charset_to_imaputf7(const char *msg_base, size_t len, charset_t charset, int encoding)
{
    struct convert_rock *input, *tobuffer;
    char *res = NULL;
    charset_t imaputf7;

    /* Initialize character set mapping */
    if (charset == CHARSET_UNKNOWN_CHARSET) return 0;

    /* check for trivial case */
    if (len == 0)
        return xstrdup("");

    /* check if we can convert the whole block at once */
    if (encoding == ENCODING_NONE)
        return convert_to_name("imap-mailbox-name", charset, msg_base, len);

    /* set up the conversion path */
    imaputf7 = charset_lookupname("imap-mailbox-name");
    tobuffer = buffer_init(len);
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
        case ENCODING_BASE64URL:
            input = b64_init(input, encoding);
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
    if (!convert_catn(input, msg_base, len)) {
        /* extract the result */
        res = buffer_cstring(tobuffer);
    }

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

EXPORTED char *charset_utf8_normalize(const char *src)
{
    int32_t srclen = strlen(src);
    UChar *uni = NULL;
    int32_t unilen = 0;
    UChar *nfc = NULL;
    int32_t nfclen = 0;
    char *ret = NULL;
    int32_t retlen = 0;

    /* Fast-path for ASCII.
     * Unicode Standard Annex #15, section 1.3: "Text exclusively
     * containing ASCII characters (U+0000..U+007F) is left
     * unaffected by all of the Normalization Forms."
     * See http://www.unicode.org/reports/tr15/#Description_Norm
     * */
    const char *p;
    for (p = src; *p && isascii(*p); p++) {}
    if (*p == '\0') {
        return xstrdup(src);
    }

    /* Convert the UTF-8 string to UChar */
    UErrorCode err = U_ZERO_ERROR;
    u_strFromUTF8(uni, unilen, &unilen, src, srclen, &err);
    if (U_FAILURE(err) && err != U_BUFFER_OVERFLOW_ERROR) {
        goto done;
    }
    err = U_ZERO_ERROR;
    unilen++;
    uni = xzmalloc(unilen * sizeof(UChar));
    u_strFromUTF8(uni, unilen, &unilen, src, srclen, &err);
    if (U_FAILURE(err)) {
        goto done;
    }

    /* Normalize the UChars to NFC */
    err = U_ZERO_ERROR;
    const UNormalizer2 *norm = unorm2_getNFCInstance(&err);
    if (!norm || U_FAILURE(err)) {
        goto done;
    }
    /* Quick-check if the Unicode string requires normalization.
     * Skip normalization only if libicu is certain not to need
     * to do anything. */
    if (unorm2_quickCheck(norm, uni, unilen, &err) == UNORM_YES) {
        nfc = uni;
        nfclen = unilen;
        uni = NULL;
    }
    else {
        err = U_ZERO_ERROR;
        nfclen = unorm2_normalize(norm, uni, unilen, nfc, 0, &err) + 1;
        if (U_FAILURE(err) && err != U_BUFFER_OVERFLOW_ERROR) {
            goto done;
        }
        err = U_ZERO_ERROR;
        nfclen++;
        nfc = xzmalloc(nfclen * sizeof(UChar));
        unorm2_normalize(norm, uni, unilen, nfc, nfclen, &err);
        if (U_FAILURE(err)) {
            goto done;
        }
        free(uni);
        uni = NULL;
    }

    /* Convert the NFC UChars back to UTF-8 */
    err = U_ZERO_ERROR;
    u_strToUTF8(ret, 0, &retlen, nfc, nfclen, &err);
    if (U_FAILURE(err) && err != U_BUFFER_OVERFLOW_ERROR) {
        goto done;
    }
    err = U_ZERO_ERROR;
    retlen++;
    ret = xzmalloc(retlen);
    u_strToUTF8(ret, retlen, &retlen, nfc, nfclen, &err);
    if (U_FAILURE(err) && err != U_BUFFER_OVERFLOW_ERROR) {
        goto done;
    }

done:
    free(uni);
    free(nfc);
    return ret;
}

/* Convert from a given charset and encoding into utf8 */
EXPORTED char *charset_to_utf8(const char *msg_base, size_t len, charset_t charset, int encoding)
{
    struct convert_rock *input, *tobuffer;
    char *res = NULL;
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
    tobuffer = buffer_init(len);
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
    case ENCODING_BASE64URL:
        input = b64_init(input, encoding);
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

    if (!convert_catn(input, msg_base, len))
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
    input = buffer_init(len);
    buffer_setbuf(input, dst);

    /* choose encoding extraction if needed */
    switch (encoding) {
    case ENCODING_NONE:
        break;

    case ENCODING_QP:
        input = qp_init(0, input);
        break;

    case ENCODING_BASE64:
    case ENCODING_BASE64URL:
        input = b64_init(input, encoding);
        /* XXX have to have nl-mapping base64 in order to
         * properly count \n as 2 raw characters
         */
        break;

    default:
        /* Don't know encoding--nothing can match */
        convert_free(input);
        return -1;
    }

    int r = convert_catn(input, src, len);
    convert_free(input);
    return r;
}

static void encode_b64(struct buf *dst, const char *src, size_t len, int encoding)
{
    static const char b64std[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char b64url[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const char *b64 = encoding == ENCODING_BASE64URL ? b64url : b64std;
    char pad = encoding == ENCODING_BASE64URL ? '\0' : '=';

    const uint8_t *s = (uint8_t*)src;
    size_t r = len;
    if (len >= 3) {
        size_t i;
        for (i = 0; i < len - 2; i += 3) {
            buf_putc(dst, b64[s[i+0] >> 2]);
            buf_putc(dst, b64[((s[i+0] & 0x03) << 4) | (s[i+1] >> 4)]);
            buf_putc(dst, b64[((s[i+1] & 0x0f) << 2) | (s[i+2] >> 6)]);
            buf_putc(dst, b64[s[i+2] & 0x3f]);
        }
        r = len - i;
    }
    if (r) {
        buf_putc(dst, b64[s[len-r] >> 2]);
        if (r == 1) {
            buf_putc(dst, b64[(s[len-1] & 0x03) << 4]);
            if (pad) buf_putc(dst, pad);
        }
        else {
            buf_putc(dst, b64[((s[len-2] & 0x03) << 4) | (s[len-1] >> 4)]);
            buf_putc(dst, b64[(s[len-1] & 0x0f) << 2]);
        }
        if (pad) buf_putc(dst, pad);
    }
}

EXPORTED int charset_encode(struct buf *dst, const char *src, size_t len, int encoding)
{
    if (encoding == ENCODING_NONE) {
        buf_setmap(dst, src, len);
        return 0;
    }
    else if (encoding == ENCODING_BASE64 || encoding == ENCODING_BASE64URL) {
        encode_b64(dst, src, len, encoding);
        return 0;
    }
    else if (encoding == ENCODING_QP) {
        size_t outlen = 0;
        char *val = charset_qpencode_mimebody(src, len, 0, &outlen);
        if (val && outlen)
            buf_setmap(dst, val, outlen);
        free(val);
        return 0;
    }
    else return -1;
}

/* Decode bytes from src to sha1 of bytes */
EXPORTED int charset_decode_sha1(uint8_t dest[SHA1_DIGEST_LENGTH], size_t *decodedlen,
                                 const char *src, size_t len, int encoding)
{
    struct convert_rock *input;

    if (encoding == ENCODING_NONE) {
        // short circuit to xsha1
        xsha1((unsigned char *)src, len, dest);
        if (decodedlen) *decodedlen = len;
        return 0;
    }

    /* set up the conversion path */
    input = sha1_init(dest, decodedlen);

    /* choose encoding extraction if needed */
    switch (encoding) {
    case ENCODING_NONE:
        break;

    case ENCODING_QP:
        input = qp_init(0, input);
        break;

    case ENCODING_BASE64:
    case ENCODING_BASE64URL:
        input = b64_init(input, encoding);
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

    /* Keep track of the decoding pipeline before the current
     * encoded-word. This allows to share decoding state for
     * multi-octet characters that are broken across words. */
    int lastenc = ENCODING_UNKNOWN;
    charset_t lastcs = CHARSET_UNKNOWN_CHARSET;
    struct convert_rock *extract = NULL;

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
        endcharset = NULL;
        for (p = start + 1; *p && *p != '=' && *p != '?'; ++p)
            if ('*' == *p && !endcharset) endcharset = p;
        if (*p != '?') {
            start = p;
            continue;
        }
        encoding = p;
        if (!endcharset) endcharset = p;
        if ((encoding[1] != 'b' && encoding[1] != 'B' &&
             encoding[1] != 'q' && encoding[1] != 'Q')
            || (encoding[2] != '?')) {
            start = p;
            continue;
        }
        for (p = encoding + 3; *p && *p != '?'; ++p)
            if ('=' == *p && '?' == p[1] && '=' != p[2]) break;
        if (*p != '?' || p[1] != '=') {
            start = p;
            continue;
        }
        end = p;
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

            /* Reset decoder pipeline */
            charset_free(&lastcs);
            lastenc = ENCODING_UNKNOWN;
            basic_free(extract);
            extract = NULL;
        }

        /*
         * Get the 1522-word's character set
         */
        start++;
        cs = lookup_buf(start, endcharset-start);
        int enc = encoding[1] == 'q' || encoding[1] == 'Q' ? ENCODING_QP : ENCODING_BASE64;

        if (cs == CHARSET_UNKNOWN_CHARSET) {
            /* Unrecognized charset, nothing will match here */
            convert_putc(input, U_REPLACEMENT); /* unknown character */
            charset_free(&cs);
            convert_switch(input, defaultcs, 1 /*to_uni*/);

            /* Reset decoder pipeline */
            charset_free(&lastcs);
            lastcs = CHARSET_UNKNOWN_CHARSET;
            lastenc = ENCODING_UNKNOWN;
            basic_free(extract);
            extract = NULL;
        }
        else if (!strcmp(charset_canon_name(cs), charset_canon_name(lastcs)) &&
                  enc == lastenc && enc) {
            /* Reuse the previous decoder */
            charset_free(&cs);
            p = encoding+3;
            convert_catn(extract, p, end - p);
        }
        else {
            /* Reset the previous decoder and start a new decoding pipeline */
            convert_switch(input, cs, 1/*to_uni*/);
            charset_free(&lastcs);
            lastcs = CHARSET_UNKNOWN_CHARSET;
            lastenc = ENCODING_UNKNOWN;
            basic_free(extract);
            extract = NULL;
            /* choose decoder */
            if (enc == ENCODING_QP) {
                extract = qp_init(1, input);
            }
            else {
                extract = b64_init(input, ENCODING_BASE64);
            }
            /* convert */
            p = encoding+3;
            convert_catn(extract, p, end - p);
            lastcs = cs;
            lastenc = enc;
        }

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
    convert_ncleanup(input, 1, 1);
    charset_free(&defaultcs);
    charset_free(&lastcs);
    basic_free(extract);
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
    tobuffer = buffer_init(0);
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
    char *res = NULL;

    if (!s) return NULL;

    tobuffer = buffer_init(len);
    input = unfold_init(flags&CHARSET_UNFOLD_SKIPWS, tobuffer);

    if (!convert_catn(input, s, len))
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
    tobuffer = buffer_init(0);
    input = convert_init(utf8, 0/*to_uni*/, tobuffer);

    mimeheader_cat(input, s, flags);

    if (flags & CHARSET_TRIMWS)
        buffer_trim(tobuffer);

    res = buffer_cstring(tobuffer);

    convert_free(input);
    charset_free(&utf8);

    return res;
}

/* Decode extended MIME values (per RFC 2231). Returns a newly allocated UTF-8
 * encoded string, containing the decoded string, which must be free()d by the
 * caller.
 *
 * If lang is not NULL, sets the buffer contents to the 'language' * field as
 * encoded in the MIME value.
 *
 * If s can't be decoded to an extended value as defined in RFC 2231, then
 * return NULL. E.g. it does not attempt to decode the value as RFC 2047 MIME
 * header, nor returns the value verbatim. */
EXPORTED char *charset_parse_mimexvalue(const char *s, struct buf *lang)
{
    if (!s) return NULL;
    const char *p, *q;
    struct buf buf = BUF_INITIALIZER;
    charset_t cs;
    char *ret = NULL;

    /* Determine charset */
    p = s;
    q = strchr(p, '\'');
    if (!q) return NULL;

    buf_setmap(&buf, p, q - p);
    cs = charset_lookupname(buf_cstring(&buf));
    if (cs == CHARSET_UNKNOWN_CHARSET) goto done;

    /* Determine language */
    p = q + 1;
    q = strchr(p, '\'');
    if (!q) goto done;
    if (lang) {
        buf_setmap(lang, p, q - p);
    }

    /* Decode octects */
    buf_reset(&buf);
    p = q + 1;
    while (*p) {
        if (*p == '%') {
            char c;
            if (*(p+1) == 0 || *(p+2) == 0)
                goto done;
            if (hex_to_bin(p+1, 2, &c) == -1)
                goto done;
            buf_appendmap(&buf, &c, 1);
            p += 3;
        } else {
            buf_appendmap(&buf, p++, 1);
        }
    }
    ret = charset_to_utf8(buf_base(&buf), buf_len(&buf), cs, 0);

done:
    charset_free(&cs);
    buf_free(&buf);
    return ret;
}

/* Encode UTF-8 encoded string s as extended MIME RFC 2231 value.
 * If lang is non-NULL, set the extended value language property
 * accordingly. The returned string must be free()d by caller. */
EXPORTED char *charset_encode_mimexvalue(const char *s, const char *lang)
{
    const unsigned char *p;
    struct buf buf = BUF_INITIALIZER;

    if (!s) return NULL;

    buf_printf(&buf, "utf-8'%s'", lang ? lang : "");
    for (p = (const unsigned char*) s; *p; p++) {
        if ((*p >= '0' && *p <= '9') ||
            (*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            (strchr("!#$&+-.^_`|~", *p))) {
            // Safe attr char
            buf_putc(&buf, *p);
        }
        else buf_printf(&buf, "%%%X%X", *p >> 4, *p & 0xf);
    }

    return buf_release(&buf);
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
    case ENCODING_BASE64URL:
        input = b64_init(input, encoding);
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
EXPORTED int charset_extract(int (*cb)(const struct buf *, void *),
                             void *rock,
                             const struct buf *data,
                             charset_t charset, int encoding,
                             const char *subtype, int flags)
{
    struct convert_rock *input, *tobuffer;
    struct buf *out;
    size_t i;
    charset_t utf8;
    int r = 0;
    
    if (charset_debug)
        fprintf(stderr, "charset_extract()\n");

    /* Initialize character set mapping */
    if (charset == CHARSET_UNKNOWN_CHARSET) return 0;

    /* set up the conversion path */
    utf8 = charset_lookupname("utf-8");
    tobuffer = buffer_init(buf_len(data));
    input = convert_init(utf8, 0/*to_uni*/, tobuffer);
    input = canon_init(flags, input);

    if (!strcmpsafe(subtype, "HTML")) {
        if ((flags & CHARSET_SKIPHTML)) {
            /* silently pretend we indexed it, but actually ignore it */
            convert_free(input);
            charset_free(&utf8);
            return 0;
        }
        /* this is text/html data, so we can make ourselves useful by
         * stripping html tags, css and js. */
        if (!(flags & CHARSET_KEEPHTML)) {
            input = striphtml_init(input);
        }
    }

    input = convert_init(charset, 1/*to_uni*/, input);

    switch (encoding) {
    case ENCODING_NONE:
        break;

    case ENCODING_QP:
        input = qp_init(0, input);
        break;

    case ENCODING_BASE64:
    case ENCODING_BASE64URL:
        input = b64_init(input, encoding);
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
            r = cb(out, rock);
            buf_reset(out);
            if (r) break;
        }
    }
    if (!r) {
        /* finish it */
        convert_flush(input);
        if (out->len) {
            r = cb(out, rock);
        }
    }

    convert_free(input);
    charset_free(&utf8);

    return r;
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
        tobuffer = buffer_init(len);
        input = qp_init(0, tobuffer);
        break;

    case ENCODING_BASE64:
    case ENCODING_BASE64URL:
        tobuffer = buffer_init(len);
        input = b64_init(tobuffer, encoding);
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

/* Maximum octect length of base64 or QP-encoded text lines, excluding
 * terminating CR LF and encoding-specific padding/footer. */
#define ENCODED_MAX_LINE_LEN  72

/*
 * Base64 encode the MIME body part (per RFC 2045) of 'len' bytes located at
 * 'msg_base'.  Encodes into 'retval' which must large enough to
 * accomodate the encoded data.  Returns the number of encoded bytes in
 * 'outlen' and the number of encoded lines in 'outlines'.
 *
 * May be called with 'msg_base' as NULL to get the number of encoded
 * bytes for allocating 'retval' of the proper size.
 */
static const char base_64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

EXPORTED char *charset_encode_mimebody(const char *msg_base, size_t len,
                                       char *retval, size_t *outlen,
                                       int *outlines, int wrap)
{
    const unsigned char *s;
    unsigned char s0, s1, s2;
    char *d;
    int b64_len, b64_lines, cnt;

    b64_len = ((len + 2) / 3) * 4;
    if (wrap) {
        b64_lines = (b64_len + ENCODED_MAX_LINE_LEN - 1) / ENCODED_MAX_LINE_LEN;

        /* account for CRLF added to each line */
        b64_len += 2 * b64_lines;
    }
    else b64_lines = 1;

    if (outlen) *outlen = b64_len;
    if (outlines) *outlines = b64_lines;

    if (!msg_base) return NULL;

    for (s = (const unsigned char*) msg_base, d = retval, cnt = 0; len;
         s += 3, d += 4, cnt += 4) { /* process tuplets */
        if (wrap && cnt == ENCODED_MAX_LINE_LEN) {
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
            if (len) {
                --len;
                /* byte 4: low 6 bits (3) */
                d[3] = base_64[s2 & 0x3f];
            } else {
                /* byte 4: pad */
                d[3] = '=';
            }
        } else {
            /* byte 3: pad */
            d[2] = '=';
            /* byte 4: pad */
            d[3] = '=';
        }
    }

    if (wrap) {
        /* add final CRLF */
        *d++ = '\r';
        *d++ = '\n';
    }

    return (b64_len ? retval : NULL);
}


#define ATOM_SPECIALS  "()<>[]:;@\\,.\" \t"

/* Find the first email address (addr-spec) in data */
static const char *find_addr(const char *data, size_t datalen, size_t *addrlen)
{
    const char *end = data + datalen;
    const char *s, *e, *at;
    int angle_addr = 0;

    if (datalen < 3) return NULL;

    at = strchr(data + 1, '@');

    if (!at || at >= end - 1) return NULL;

    /* find end of domain */
    e = at + 1;

    if (*e == '[') {
        /* find end of domain-literal */
        while (++e < end && !(*e == '[' || *e == ']'|| *e == '\\'));

        /* domain-literal MUST end with ']' */
        if (*e++ != ']') return NULL;
    }
    else if (!isspace(*e) && !strchr(ATOM_SPECIALS, *e)) {
        /* find end of dot-atom */
        while (++e < end && (*e == '.' || !strchr(ATOM_SPECIALS, *e)));

        /* atom MUST NOT end with '.' */
        if (*(e-1) == '.') return NULL;
    }
    else return NULL;

    if (e < end) {
        /* gobble trailing data */
        if (*e == '>') {
            angle_addr = 1;
            e++;
        }

        /* gobble trailing whitespace */
        while (e < end && isspace(*e)) e++;

        /* multiple addresses MUST only be separated with ',' */
        if (e < end && *e++ != ',') return NULL;

        /* gobble trailing whitespace */
        while (e < end && isspace(*e)) e++;
    }


    /* find start of localpart */
    s = at - 1;

    if (*s == '\"') {
        /* find start of quoted-string */
        while (--s >= data && (*s != '"' || (--s >= data && *s == '\\')));

        /* quoted-string must start with '"' */
        if (*(s+1) != '"') return NULL;
    }
    else if (!isspace(*s) && !strchr(ATOM_SPECIALS, *s)) {
        /* find start of dot-atom */
        while (--s >= data && (*s == '.' || !strchr(ATOM_SPECIALS, *s)));

        /* atom MUST NOT start with '.' */
        if (*(s+1) == '.') return NULL;
    }
    else return NULL;

    if (s < data) s = data;
    else if (angle_addr) {
        /* angle-addr MUST start with '<' */
        if (*s != '<') return NULL;

        /* gobble leading whitespace */
        while (s > data && isspace(*(s-1))) s--;
    }
    else if (!(isspace(*s) || *s == ',')) {
        /* invalid separator */
        return NULL;
    }

    /* found a valid address */
    *addrlen = e - s;

    return s;
}

/*
 * If 'isheader' is non-zero "Q" encode (per RFC 2047), otherwise
 * quoted-printable encode (per RFC 2045), the 'data' of 'len' bytes.
 * Returns a buffer which the caller must free.
 * Returns the number of encoded bytes in 'outlen'.
 */
static char *qp_encode(const char *data, size_t len, int isheader,
                       int force_quote, size_t *outlen)
{
    struct buf buf = BUF_INITIALIZER;
    size_t n;
    int need_quote = 0, need_fold = 0;

    if (!force_quote) {
        size_t prev_lf = 0;
        size_t last_sp = 0;
        for (n = 0; n < len; n++) {
            unsigned char this = data[n];
            unsigned char next = (n < len - 1) ? data[n+1] : '\0';

            if (QPSAFECHAR[this] || this == '=' || this == ' ' || this == '\t') {
                /* per RFC 5322: printable ASCII (decimal 33 - 126), SP, HTAB */
                /* but only if the line doesn't exceed the 76 octet limit */

                if (this == ' ' || this == '\t')
                    last_sp = n;

                if (n - prev_lf <= 74) continue;

                if (isheader) {
                    if (n - last_sp > 74)
                        need_quote = 1;
                    else
                        need_fold = 1;
                    continue;
                }
            }
            else if (!isheader && this == '\r' && next == '\n') {
                /* line break (CRLF) */
                n++;
                prev_lf = n;
                continue;
            }
            need_quote = 1;
            break;
        }
    }
    else {
        need_quote = 1;
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

            /* Insert line break before exceeding line length limits */
            if (isheader) {
                /* RFC 2047 forbids splitting multi-octet characters */
                int needbytes;
                if (this < 0x80) needbytes = 0;
                else if (this < 0xc0) needbytes = 0; // UTF-8 continuation
                else if (this < 0xe0) needbytes = 3;
                else if (this < 0xf0) needbytes = 6;
                else if (this < 0xf8) needbytes = 9;
                else needbytes = 0; // impossible UTF-8 encoding
                if (cnt + needbytes >= ENCODED_MAX_LINE_LEN) {
                    buf_appendcstr(&buf, "?=\r\n =?UTF-8?Q?");
                    cnt = 11;
                }
            }
            else if (cnt >= ENCODED_MAX_LINE_LEN && next != '\r' && next != '\n') {
                /* add soft line break to body */
                buf_appendcstr(&buf, "=\r\n");
                cnt = 0;
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
    else if (need_fold) {
        /* fold header every 78 characters (if possible) */
        size_t i = 0, j = 0, last_wsp = 0;

        while ((len - i > 78) && (j < len)) {
            j += strcspn(data + j, " \t");

            if (last_wsp && (j - i > 78)) {
                buf_appendmap(&buf, data + i, last_wsp - i);
                buf_appendcstr(&buf, "\r\n");
                i = last_wsp;
            }
            last_wsp = j++;
        }
        buf_appendcstr(&buf, data + i);
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
                                         int force_quote, size_t *outlen)
{
    if (!msg_base) return NULL;

    return qp_encode(msg_base, len, 0, force_quote, outlen);
}


static void encode_mimephrase(const char *data, size_t len,
                              struct buf *buf, int *cnt);

static char *encode_addrheader(const char *header, size_t len, int force_quote,
                               const char *addr, size_t addr_len)
{
    struct buf buf = BUF_INITIALIZER;
    size_t n = 0;
    int cnt = 0;

    do {
        size_t phrase_len = addr ? (size_t) (addr - (header + n)) : len - n;

        if (phrase_len) {
            /* display-name precedes address */
            const char *phrase = header + n;
            int need_encode = 0, need_bytes = phrase_len;
            const char *c;

            for (c = phrase; c < addr; c++) {
                if (force_quote || (*c & 0x80)) {
                    need_encode = 1;
                    need_bytes = 3 * phrase_len + 12;  // assume max size
                    break;
                }
            }

            /* don't fold in the middle of a phrase */
            if (cnt + need_bytes >= ENCODED_MAX_LINE_LEN) {
                buf_appendcstr(&buf, "\r\n ");
                cnt = 1;
            }

            if (need_encode) {
                encode_mimephrase(phrase, phrase_len, &buf, &cnt);
            }
            else {
                buf_appendmap(&buf, phrase, phrase_len);
                cnt += phrase_len;
            }
        }

        if (addr) {
            /* don't fold in the middle of an address */
            if (cnt + addr_len >= ENCODED_MAX_LINE_LEN) {
                buf_appendcstr(&buf, "\r\n ");
                cnt = 1;
            }

            buf_appendmap(&buf, addr, addr_len);
            cnt += addr_len;
        }

        /* jump to end of address */
        n += phrase_len + addr_len;

    } while ((addr = find_addr(header + n , len - n, &addr_len)) || n < len);

    return buf_release(&buf);
}

/* "Q" encode the header field body (per RFC 2047) of 'len' bytes
 * located at 'header'.
 * Returns a buffer which the caller must free.
 */
EXPORTED char *charset_encode_mimeheader(const char *header, size_t len, int force_quote)
{
    if (!header) return NULL;

    if (!len) len = strlen(header);

    size_t addr_len = 0;
    const char *addr = find_addr(header, len, &addr_len);

    if (addr) {
        /* "Q" encode as an address header */
        return encode_addrheader(header, len, force_quote, addr, addr_len);
    }
    
    return qp_encode(header, len, 1, force_quote, NULL);
}

/*
 * If 'isheader' is non-zero "Q" encode (per RFC 2047), otherwise
 * quoted-printable encode (per RFC 2045), the 'data' of 'len' bytes.
 * Returns a buffer which the caller must free.
 * Returns the number of encoded bytes in 'outlen'.
 */
static void encode_mimephrase(const char *data, size_t len,
                              struct buf *buf, int *cnt)
{
    size_t n;

    buf_appendcstr(buf, "=?UTF-8?Q?");
    *cnt += 10;

    for (n = 0; n < len; n++) {
        unsigned char this = data[n];

        /* RFC 2047 forbids splitting multi-octet characters */
        int needbytes;
        if (this < 0x80) needbytes = 0;
        else if (this < 0xc0) needbytes = 0; // UTF-8 continuation
        else if (this < 0xe0) needbytes = 3;
        else if (this < 0xf0) needbytes = 6;
        else if (this < 0xf8) needbytes = 9;
        else needbytes = 0; // impossible UTF-8 encoding
        if (*cnt + needbytes >= ENCODED_MAX_LINE_LEN) {
            buf_appendcstr(buf, "?=\r\n =?UTF-8?Q?");
            *cnt = 11;
        }

        if (QPMIMEPHRASESAFECHAR[this]) {
            /* literal representation */
            buf_putc(buf, (char)this);
            *cnt += 1;
        }
        else if (this == ' ') {
            /* per RFC 2047: represent SP in header as '_' for legibility */
            buf_putc(buf, '_');
            *cnt += 1;
        }
        else {
            /* 8-bit representation */
            buf_printf(buf, "=%02X", this);
            *cnt += 3;
        }
    }

    buf_appendcstr(buf, "?=");
}

EXPORTED char *charset_encode_mimephrase(const char *data)
{
    struct buf buf = BUF_INITIALIZER;
    int cnt = 0;

    encode_mimephrase(data, strlen(data), &buf, &cnt);

    return buf_release(&buf);
}

static int extract_plain_cb(const struct buf *buf, void *rock)
{
    struct buf *dst = (struct buf*) rock;
    const char *p;
    int seenspace = 0;

    /* Just merge multiple space into one. That's similar to
     * charset_extract's MERGE_SPACE but since we don't want
     * it to canonify the text into search form */
    for (p = buf_base(buf); p < buf_base(buf) + buf_len(buf) && *p; p++) {
        if (*p == ' ') {
            if (seenspace) continue;
            seenspace = 1;
        } else {
            seenspace = 0;
        }
        buf_appendmap(dst, p, 1);
    }

    return 0;
}

EXPORTED char *charset_extract_plain(const char *html) {
    struct buf src = BUF_INITIALIZER;
    struct buf dst = BUF_INITIALIZER;
    charset_t utf8 = charset_lookupname("utf8");
    char *text;
    char *tmp, *q;
    const char *p;

    /* Replace <br> and <p> with newlines */
    q = tmp = xstrdup(html);
    p = html;
    while (*p) {
        if (!strncmp(p, "<br>", 4) || !strncmp(p, "</p>", 4)) {
            *q++ = '\n';
            p += 4;
        }
        else if (!strncmp(p, "p>", 3)) {
            p += 3;
        } else {
            *q++ = *p++;
        }
    }
    *q = 0;

    /* Strip html tags */
    buf_init_ro(&src, tmp, q - tmp);
    buf_setcstr(&dst, "");
    charset_extract(&extract_plain_cb, &dst,
            &src, utf8, ENCODING_NONE, "HTML", CHARSET_KEEPCASE);
    buf_cstring(&dst);

    /* Trim text */
    buf_trim(&dst);
    text = buf_releasenull(&dst);
    if (!strlen(text)) {
        free(text);
        text = NULL;
    }

    buf_free(&src);
    free(tmp);
    charset_free(&utf8);

    return text;
}

EXPORTED struct char_counts charset_count_validutf8(const char *data, size_t datalen)
{

    if (datalen > INT32_MAX) {
        datalen = INT32_MAX;
    }

    struct char_counts counts = { 0, 0, 0 };
    int32_t i = 0;
    int32_t length = (int32_t) datalen;
    const uint8_t *data8 = (const uint8_t *) data;

    while (i < length) {
        UChar32 c;
        U8_NEXT(data8, i, length, c);
        if (c == 0xfffd)
            counts.replacement++;
        else if (c >= 0)
            counts.valid++;
        else
            counts.invalid++;
    }

    return counts;
}
