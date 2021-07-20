/*
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

#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <sysexits.h>

#include "global.h"
#include "imparse.h"
#include "search_expr.h"
#include "imapd.h"      /* for struct searchargs */
#include "prot.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/*
 * Parse a word
 * (token not containing whitespace, parens, or double quotes)
 */
EXPORTED int getword(struct protstream *in, struct buf *buf)
{
    int c;

    buf_reset(buf);
    for (;;) {
        c = prot_getc(in);
        if (c == EOF || isspace(c) || c == '(' || c == ')' || c == '\"') {
            buf_cstring(buf); /* appends a '\0' */
            return c;
        }
        buf_putc(buf, c);
        if (config_maxword && buf_len(buf) > config_maxword) {
            fatal("word too long", EX_IOERR);
        }
    }
}

/*
 * Parse an xstring
 * (astring, nstring or string based on type)
 */
#ifdef HAVE_DECLARE_OPTIMIZE
EXPORTED int getxstring(struct protstream *pin, struct protstream *pout,
                        struct buf *buf, enum getxstring_flags flags)
    __attribute__((optimize("-O3")));
#endif
EXPORTED int getxstring(struct protstream *pin, struct protstream *pout,
                        struct buf *buf, enum getxstring_flags flags)
{
    int c;
    int i;
    int isnowait;
    int len;
    static int lminus = -1;

    if (lminus == -1) lminus = config_getswitch(IMAPOPT_LITERALMINUS);

    buf_reset(buf);

    c = prot_getc(pin);
    switch (c) {
    case EOF:
    case ' ':
    case '(':
    case ')':
    case '\r':
    case '\n':
        /* Invalid starting character */
        goto fail;

    case '\"':
        if (!(flags & GXS_QUOTED)) {
            /* Invalid starting character */
            goto fail;
        }

        /*
         * Quoted-string.  Server is liberal in accepting qspecials
         * other than double-quote, CR, and LF.
         */
        for (;;) {
            c = prot_getc(pin);
            if (c == '\\') {
                c = prot_getc(pin);
            }
            else if (c == '\"') {
                buf_cstring(buf);
                return prot_getc(pin);
            }
            else if (c == EOF || c == '\r' || c == '\n') {
                buf_cstring(buf);
                if (c != EOF) prot_ungetc(c, pin);
                return EOF;
            }
            buf_putc(buf, c);
            if (config_maxquoted && buf_len(buf) > config_maxquoted) {
                fatal("quoted value too long", EX_IOERR);
            }
        }

    case '{':
        if (!(flags & GXS_LITERAL)) {
            /* Invalid starting character */
            goto fail;
        }

        /* Literal */
        isnowait = pin->isclient;
        buf_reset(buf);
        c = getint32(pin, &len);
        if (c == '+') {
            // LITERAL- says maximum size is 4096!
            if (lminus && len > 4096) return EOF;
            isnowait++;
            c = prot_getc(pin);
        }
        if (len == -1 || c != '}') {
            buf_cstring(buf);
            if (c != EOF) prot_ungetc(c, pin);
            return EOF;
        }
        c = prot_getc(pin);
        if (c != '\r') {
            buf_cstring(buf);
            if (c != EOF) prot_ungetc(c, pin);
            return EOF;
        }
        c = prot_getc(pin);
        if (c != '\n') {
            buf_cstring(buf);
            if (c != EOF) prot_ungetc(c, pin);
            return EOF;
        }

        if (!isnowait) {
            prot_printf(pout, "+ go ahead\r\n");
            prot_flush(pout);
        }
        for (i = 0; i < len; i++) {
            c = prot_getc(pin);
            if (c == EOF) {
                buf_cstring(buf);
                return EOF;
            }
            buf_putc(buf, c);
        }
        buf_cstring(buf);
        /* n.b. we've consumed an exact number of bytes according to the literal, do
         * not unget anything even if we don't like the literal */
        if (!(flags & GXS_BINARY) && strlen(buf_cstring(buf)) != (unsigned)buf_len(buf))
            return EOF; /* Disallow imbedded NUL */
        return prot_getc(pin);

    default:
        if ((flags & GXS_ATOM)) {
            /*
             * Atom -- server is liberal in accepting specials other
             * than whitespace, parens, or double quotes
             */
            for (;;) {
                if (c == EOF || isspace(c) || c == '(' ||
                          c == ')' || c == '\"') {
                    /* gotta handle NIL here too */
                    if ((flags & GXS_NIL) && buf->len == 3 && !memcmp(buf->s, "NIL", 3))
                        buf_free(buf);
                    else
                        buf_cstring(buf);
                    return c;
                }
                buf_putc(buf, c);
                c = prot_getc(pin);
            }
            /* never gets here */
        }
        else if ((flags & GXS_NIL)) {
            /*
             * Look carefully for "NIL"
             */
            if (c == 'N') {
                int sep = 0;
                int matched;

                matched = prot_lookahead(pin, "IL", strlen("IL"), &sep);
                if (matched == strlen("IL") + 1) {
                    if (isspace(sep) || sep == '(' || sep == ')' || sep == '\"') {
                        /* found NIL and a separator, consume it */
                        prot_ungetc(c, pin);
                        c = getword(pin, buf);
                        /* indicate NIL with a NULL buf.s pointer */
                        buf_free(buf);
                        return c;
                    }
                }
                else if (matched > 0) {
                    /* partially matched NIL, but not enough buffer to be sure:
                     * fall back to old behaviour */
                    prot_ungetc(c, pin);
                    c = getword(pin, buf);
                    if (buf->len == 3 && !memcmp(buf->s, "NIL", 3)) {
                        /* indicated NIL with a NULL buf.s pointer */
                        buf_free(buf);
                        return c;
                    }
                }
            }
        }
        goto fail;
    }

    /* XXX i think we can never get to this line? */
    return EOF;

fail:
    buf_cstring(buf);
    if (c != EOF) prot_ungetc(c, pin);
    return EOF;
}

EXPORTED int getint32(struct protstream *pin, int32_t *num)
{
    int32_t result = 0;
    int c = EOF;
    int gotchar = 0;

    /* INT_MAX == 2147483647 */
    while ((c = prot_getc(pin)) != EOF && cyrus_isdigit(c)) {
        if (result > 214748364 || (result == 214748364 && (c > '7')))
            fatal("num too big", EX_IOERR);
        result = result * 10 + c - '0';
        gotchar = 1;
    }

    if (!gotchar) {
        if (c != EOF) prot_ungetc(c, pin);
        return EOF;
    }

    *num = result;

    return c;
}

/* Like getint32() but explicitly signed, i.e. negative numbers
 * are accepted */
EXPORTED int getsint32(struct protstream *pin, int32_t *num)
{
    int c;
    int sgn = 1;

    c = prot_getc(pin);
    if (c == EOF)
        return EOF;

    if (c == '-')
        sgn = -1;
    else if (c == '+')
        sgn = 1;
    else
        prot_ungetc(c, pin);

    c = getint32(pin, num);
    if (c == EOF)
        return EOF;
    /* this is slightly buggy: the number INT_MIN = -2147483648
     * is a valid signed 32b int but is not accepted */
    if (sgn < 0)
        *num = - (*num);
    return c;
}

/* can't flag with -1 if there is no number here, so return EOF */
EXPORTED int getuint32(struct protstream *pin, uint32_t *num)
{
    uint32_t result = 0;
    int c = EOF;
    int gotchar = 0;

    /* UINT_MAX == 4294967295U */
    while ((c = prot_getc(pin)) != EOF && cyrus_isdigit(c)) {
        if (result > 429496729 || (result == 429496729 && (c > '5')))
            fatal("num too big", EX_IOERR);
        result = result * 10 + c - '0';
        gotchar = 1;
    }

    if (!gotchar) {
        if (c != EOF) prot_ungetc(c, pin);
        return EOF;
    }

    *num = result;

    return c;
}

EXPORTED int getint64(struct protstream *pin, int64_t *num)
{
    int64_t result = 0;
    int c = EOF;
    int gotchar = 0;

    /* LLONG_MAX == 9223372036854775807LL */
    while ((c = prot_getc(pin)) != EOF && cyrus_isdigit(c)) {
        if (result > 922337203685477580LL || (result == 922337203685477580LL && (c > '7')))
            fatal("num too big", EX_IOERR);
        result = result * 10 + c - '0';
        gotchar = 1;
    }

    if (!gotchar) {
        if (c != EOF) prot_ungetc(c, pin);
        return EOF;
    }

    *num = result;

    return c;
}

/* Like getint64() but explicitly signed, i.e. negative numbers
 * are accepted */
EXPORTED int getsint64(struct protstream *pin, int64_t *num)
{
    int c;
    int sgn = 1;

    c = prot_getc(pin);
    if (c == EOF)
        return EOF;

    if (c == '-')
        sgn = -1;
    else if (c == '+')
        sgn = 1;
    else
        prot_ungetc(c, pin);

    c = getint64(pin, num);
    if (c == EOF)
        return EOF;
    /* this is slightly buggy: the number LLONG_MIN == -9223372036854775808LL
     * is a valid signed 64b int but is not accepted */
    if (sgn < 0)
        *num = - (*num);
    return c;
}

/* can't flag with -1 if there is no number here, so return EOF */
EXPORTED int getuint64(struct protstream *pin, uint64_t *num)
{
    uint64_t result = 0;
    int c = EOF;
    int gotchar = 0;

    /* ULLONG_MAX == 18446744073709551615ULL */
    while ((c = prot_getc(pin)) != EOF && cyrus_isdigit(c)) {
        if (result > 1844674407370955161ULL || (result == 1844674407370955161ULL && (c > '5')))
            fatal("num too big", EX_IOERR);
        result = result * 10 + c - '0';
        gotchar = 1;
    }

    if (!gotchar) {
        if (c != EOF) prot_ungetc(c, pin);
        return EOF;
    }

    *num = result;

    return c;
}

/* This would call getuint64() if
 * all were right with the world */
EXPORTED int getmodseq(struct protstream *pin, modseq_t *num)
{
    int c = EOF;
    unsigned int i = 0;
    char buf[32];
    int gotchar = 0;

    while (i < sizeof(buf) &&
           (c = prot_getc(pin)) != EOF &&
           cyrus_isdigit(c)) {
        buf[i++] = c;
        gotchar = 1;
    }

    if (!gotchar || i == sizeof(buf)) {
        if (c != EOF) prot_ungetc(c, pin);
        return EOF;
    }

    buf[i] = '\0';
    *num = strtoull(buf, NULL, 10);

    return c;
}

/*
 * Eat characters up to and including the next newline
 * Also look for and eat non-synchronizing literals.
 */
EXPORTED void eatline(struct protstream *pin, int c)
{
    for (;;) {
        if (c == '\n') return;

        /* Several of the parser helper functions return EOF
           even if an unexpected character (other than EOF) is received. 
           We need to confirm that the stream is actually at EOF. */
        if (c == EOF && (prot_IS_EOF(pin) || prot_IS_ERROR(pin))) return;

        /* see if it's a literal */
        if (c == '{') {
            c = prot_getc(pin);
            uint64_t size = 0;
            while (cyrus_isdigit(c)) {
                if (size > 429496729 || (size == 429496729 && (c > '5')))
                    break; /* don't fatal, just drop out of literal parsing */
                size = size * 10 + c - '0';
                c = prot_getc(pin);
            }
            if (c != '+') continue;
            c = prot_getc(pin);
            if (c != '}') continue;
            c = prot_getc(pin);
            /* optional \r */
            if (c == '\r') c = prot_getc(pin);
            if (c != '\n') continue;
            /* successful literal, consume it */
            while (size--) {
                c = prot_getc(pin);
                if (c == EOF) return;
            }
        }
        c = prot_getc(pin);
    }
}

/*
 * Parse a "date", for SEARCH criteria
 * The time_t's pointed to by 'start' and 'end' are set to the
 * times of the start and end of the parsed date.
 */
static int get_search_date(struct protstream *pin, time_t *start, time_t *end)
{
    int c;
    struct tm tm;
    int quoted = 0;
    char month[4];
    static const char *monthname[] = {
        "jan", "feb", "mar", "apr", "may", "jun",
        "jul", "aug", "sep", "oct", "nov", "dec"
    };

    memset(&tm, 0, sizeof tm);

    c = prot_getc(pin);
    if (c == '\"') {
        quoted++;
        c = prot_getc(pin);
    }

    /* Day of month */
    if (!isdigit(c)) goto baddate;
    tm.tm_mday = c - '0';
    c = prot_getc(pin);
    if (isdigit(c)) {
        tm.tm_mday = tm.tm_mday * 10 + c - '0';
        c = prot_getc(pin);
    }

    if (c != '-') goto baddate;
    c = prot_getc(pin);

    /* Month name */
    if (!isalpha(c)) goto baddate;
    month[0] = c;
    c = prot_getc(pin);
    if (!isalpha(c)) goto baddate;
    month[1] = c;
    c = prot_getc(pin);
    if (!isalpha(c)) goto baddate;
    month[2] = c;
    c = prot_getc(pin);
    month[3] = '\0';
    lcase(month);

    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
        if (!strcmp(month, monthname[tm.tm_mon])) break;
    }
    if (tm.tm_mon == 12) goto baddate;

    if (c != '-') goto baddate;
    c = prot_getc(pin);

    /* Year */
    if (!isdigit(c)) goto baddate;
    tm.tm_year = c - '0';
    c = prot_getc(pin);
    if (!isdigit(c)) goto baddate;
    tm.tm_year = tm.tm_year * 10 + c - '0';
    c = prot_getc(pin);
    if (isdigit(c)) {
        if (tm.tm_year < 19) goto baddate;
        tm.tm_year -= 19;
        tm.tm_year = tm.tm_year * 10 + c - '0';
        c = prot_getc(pin);
        if (!isdigit(c)) goto baddate;
        tm.tm_year = tm.tm_year * 10 + c - '0';
        c = prot_getc(pin);
    }

    if (quoted) {
        if (c != '\"') goto baddate;
        c = prot_getc(pin);
    }

    tm.tm_isdst = -1;
    *start = mktime(&tm);

    tm.tm_hour = 24;
    tm.tm_isdst = -1;
    *end = mktime(&tm);

    return c;

 baddate:
    prot_ungetc(c, pin);
    return EOF;
}

/*
 * Parse search return options
 */
EXPORTED int get_search_return_opts(struct protstream *pin,
                                    struct protstream *pout,
                                    struct searchargs *searchargs)
{
    int c;
    static struct buf opt;

    c = prot_getc(pin);
    if (c != '(') {
        prot_printf(pout,
                    "%s BAD Missing return options in Search\r\n", searchargs->tag);
        goto bad;
    }

    do {
        c = getword(pin, &opt);
        if (!opt.s[0]) break;

        lcase(opt.s);
        if (!strcmp(opt.s, "min")) {
            searchargs->returnopts |= SEARCH_RETURN_MIN;
        }
        else if (!strcmp(opt.s, "max")) {
            searchargs->returnopts |= SEARCH_RETURN_MAX;
        }
        else if (!strcmp(opt.s, "all")) {
            searchargs->returnopts |= SEARCH_RETURN_ALL;
        }
        else if (!strcmp(opt.s, "count")) {
            searchargs->returnopts |= SEARCH_RETURN_COUNT;
        }
        else if (!strcmp(opt.s, "relevancy")) { /* RFC 6203 */
            searchargs->returnopts |= SEARCH_RETURN_RELEVANCY;
        }
        else {
            prot_printf(pout,
                        "%s BAD Invalid Search return option %s\r\n",
                        searchargs->tag, opt.s);
            goto bad;
        }

    } while (c == ' ');

    /* RFC 4731:
     * If the list of result options is empty, that requests the server to
     * return an ESEARCH response instead of the SEARCH response.  This is
     * equivalent to "(ALL)".
     */
    if (!searchargs->returnopts)
        searchargs->returnopts = SEARCH_RETURN_ALL;

    if (c != ')') {
        prot_printf(pout,
                    "%s BAD Missing close parenthesis in Search\r\n",
                    searchargs->tag);
        goto bad;
    }

    c = prot_getc(pin);

    return c;

bad:
    if (c != EOF) prot_ungetc(c, pin);
    return EOF;
}

/*
 * Parse a ANNOTATION item for SEARCH (RFC 5257) into a struct
 * searchannot and append it to the chain of such structures at *lp.
 * Returns the next character.
 */
static int get_search_annotation(struct protstream *pin,
                                 struct protstream *pout,
                                 struct searchargs *base,
                                 int c, struct searchannot **lp)
{
    struct searchannot *sa;
    struct buf entry = BUF_INITIALIZER;
    struct buf attrib = BUF_INITIALIZER;
    struct buf value = BUF_INITIALIZER;

    if (c != ' ')
        goto bad;

    /* parse the entry */
    c = getastring(pin, pout, &entry);
    if (!entry.len || c != ' ') {
        goto bad;
    }

    /* parse the attrib */
    c = getastring(pin, pout, &attrib);
    if (!attrib.len || c != ' ') {
        goto bad;
    }
    if (strcmp(attrib.s, "value") &&
        strcmp(attrib.s, "value.shared") &&
        strcmp(attrib.s, "value.priv")) {
        goto bad;
    }

    /* parse the value */
    c = getbnstring(pin, pout, &value);
    if (c == EOF)
        goto bad;

    sa = xzmalloc(sizeof(*sa));
    sa->entry = buf_release(&entry);
    sa->attrib = buf_release(&attrib);
    sa->namespace = base->namespace;
    sa->isadmin = base->isadmin;
    sa->userid = base->userid;
    sa->auth_state = base->authstate;
    buf_move(&sa->value, &value);

    *lp = sa;

    return c;

bad:
    buf_free(&entry);
    buf_free(&attrib);
    buf_free(&value);

    if (c != EOF) prot_ungetc(c, pin);
    return EOF;
}


static void string_match(search_expr_t *parent, const char *val,
                         const char *aname, struct searchargs *base)
{
    search_expr_t *e;
    const search_attr_t *attr = search_attr_find(aname);
    enum search_op op = SEOP_MATCH;
    char *searchval;

    if (base->fuzzy_depth > 0 &&
        search_attr_is_fuzzable(attr)) {
        op = SEOP_FUZZYMATCH;
        searchval = xstrdup(val); // keep search value as-is
    }
    else searchval = charset_convert(val, base->charset, charset_flags|CHARSET_KEEPCASE);

    e = search_expr_new(parent, op);
    e->attr = attr;
    e->value.s = searchval;
    if (!e->value.s) {
        e->op = SEOP_FALSE;
        e->attr = NULL;
    }
}

static void bytestring_match(search_expr_t *parent, const char *val,
                             const char *aname,
                             struct searchargs *base __attribute__((unused)))
{
    search_expr_t *e;
    const search_attr_t *attr = search_attr_find(aname);
    enum search_op op = SEOP_MATCH;

    e = search_expr_new(parent, op);
    e->attr = attr;
    e->value.s = xstrdupnull(val);
    if (!e->value.s) {
        e->op = SEOP_FALSE;
        e->attr = NULL;
    }
}

static void systemflag_match(search_expr_t *parent, unsigned int flag, int not)
{
    search_expr_t *e;

    if (not)
        parent = search_expr_new(parent, SEOP_NOT);
    e = search_expr_new(parent, SEOP_MATCH);
    e->attr = search_attr_find("systemflags");
    e->value.u = flag;
}

static void indexflag_match(search_expr_t *parent, unsigned int flag, int not)
{
    search_expr_t *e;

    if (not)
        parent = search_expr_new(parent, SEOP_NOT);
    e = search_expr_new(parent, SEOP_MATCH);
    e->attr = search_attr_find("indexflags");
    e->value.u = flag;
}

static void convflag_match(search_expr_t *parent, const char *flagname, int not,
                           int matchall)
{
    search_expr_t *e;

    if (not)
        parent = search_expr_new(parent, SEOP_NOT);
    e = search_expr_new(parent, SEOP_MATCH);
    e->attr = search_attr_find(matchall ? "allconvflags" : "convflags");
    e->value.s = xstrdup(flagname);
}

static void date_range(search_expr_t *parent, const char *aname,
                       time_t start, time_t end)
{
    search_expr_t *e;
    const search_attr_t *attr = search_attr_find(aname);

    parent = search_expr_new(parent, SEOP_AND);

    e = search_expr_new(parent, SEOP_LT);
    e->attr = attr;
    e->value.t = end;

    e = search_expr_new(parent, SEOP_GE);
    e->attr = attr;
    e->value.t = start;
}

/*
 * Parse a single search criterion
 */
static int get_search_criterion(struct protstream *pin,
                                struct protstream *pout,
                                search_expr_t *parent,
                                struct searchargs *base)
{
    static struct buf criteria, arg, arg2;
    search_expr_t *e;
    int c;
    int keep_charset = 0;
    time_t start, end, now = time(0);
    uint32_t u;
    int hasconv = config_getswitch(IMAPOPT_CONVERSATIONS);

    if (base->state & GETSEARCH_CHARSET_FIRST) {
        c = getcharset(pin, pout, &arg);
        if (c != ' ') goto missingcharset;
        lcase(arg.s);
        charset_free(&base->charset);
        base->charset = charset_lookupname(arg.s);
        if (base->charset == CHARSET_UNKNOWN_CHARSET) goto badcharset;
        base->state &= ~GETSEARCH_CHARSET_FIRST;
    }

    c = getword(pin, &criteria);
    lcase(criteria.s);
    switch (criteria.s[0]) {
    case '\0':
        if (c != '(') goto badcri;
        e = search_expr_new(parent, SEOP_AND);
        do {
            c = get_search_criterion(pin, pout, e, base);
        } while (c == ' ');
        if (c == EOF) return EOF;
        if (c != ')') {
            prot_printf(pout, "%s BAD Missing required close paren in Search command\r\n",
                   base->tag);
            if (c != EOF) prot_ungetc(c, pin);
            return EOF;
        }
        c = prot_getc(pin);
        break;

    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case '*':                                           /* RFC 3501 */
        if (imparse_issequence(criteria.s)) {
            seqset_t *seq;
            e = search_expr_new(parent, SEOP_MATCH);
            e->attr = search_attr_find("msgno");
            seq = seqset_parse(criteria.s, NULL, /*maxval*/0);
            if (!seq) goto badcri;
            seqset_free(&seq);
            e->value.s = xstrdup(criteria.s);
        }
        else goto badcri;
        break;

    case 'a':
        if (!strcmp(criteria.s, "answered")) {          /* RFC 3501 */
            systemflag_match(parent, FLAG_ANSWERED, /*not*/0);
        }
        else if (!strcmp(criteria.s, "all")) {          /* RFC 3501 */
            search_expr_new(parent, SEOP_TRUE);
            break;
        }
        else if (!strcmp(criteria.s, "annotation")) {   /* RFC 5257 */
            struct searchannot *annot = NULL;
            c = get_search_annotation(pin, pout, base, c, &annot);
            if (c == EOF)
                goto badcri;
            e = search_expr_new(parent, SEOP_MATCH);
            e->attr = search_attr_find("annotation");
            e->value.annot = annot;
        }
        else goto badcri;
        break;

    case 'b':
        if (!strcmp(criteria.s, "before")) {        /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = get_search_date(pin, &start, &end);
            if (c == EOF) goto baddate;
            e = search_expr_new(parent, SEOP_LT);
            e->attr = search_attr_find("internaldate");
            e->value.t = start;
        }
        else if (!strcmp(criteria.s, "bcc")) {      /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            string_match(parent, arg.s, criteria.s, base);
        }
        else if (!strcmp(criteria.s, "body")) {     /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            string_match(parent, arg.s, criteria.s, base);
        }
        else if (!strcmp(criteria.s, "fuzzy")) {
            if (c != ' ') goto missingarg;
            base->fuzzy_depth++;
            c = get_search_criterion(pin, pout, parent, base);
            base->fuzzy_depth--;
            if (c == EOF) return EOF;
            break;
        }
        else goto badcri;
        break;

    case 'c':
        if (!strcmp(criteria.s, "cc")) {            /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            string_match(parent, arg.s, criteria.s, base);
        }
        else if (hasconv && !strcmp(criteria.s, "convflag")) {  /* nonstandard */
            if (c != ' ') goto missingarg;
            c = getword(pin, &arg);
            lcase(arg.s);
            convflag_match(parent, arg.s, /*not*/0, /*all*/0);
        }
        else if (hasconv && !strcmp(criteria.s, "convread")) {  /* nonstandard */
            convflag_match(parent, "\\Seen", /*not*/0, /*all*/0);
        }
        else if (hasconv && !strcmp(criteria.s, "convunread")) {    /* nonstandard */
            convflag_match(parent, "\\Seen", /*not*/1, /*all*/1);
        }
        else if (hasconv && !strcmp(criteria.s, "convseen")) {  /* nonstandard */
            convflag_match(parent, "\\Seen", /*not*/0, /*all*/0);
        }
        else if (hasconv && !strcmp(criteria.s, "convunseen")) {    /* nonstandard */
            convflag_match(parent, "\\Seen", /*not*/1, /*all*/1);
        }
        else if (hasconv && !strcmp(criteria.s, "convmodseq")) {    /* nonstandard */
            modseq_t ms;
            if (c != ' ') goto missingarg;
            c = getmodseq(pin, &ms);
            if (c == EOF) goto badnumber;
            e = search_expr_new(parent, SEOP_GE);
            e->attr = search_attr_find("convmodseq");
            e->value.u = ms;
        }
        else if ((base->state & GETSEARCH_CHARSET_KEYWORD)
              && !strcmp(criteria.s, "charset")) {      /* RFC 3501 */
            if (c != ' ') goto missingcharset;
            c = getcharset(pin, pout, &arg);
            if (c != ' ') goto missingcharset;
            lcase(arg.s);
            charset_free(&base->charset);
            base->charset = charset_lookupname(arg.s);
            if (base->charset == CHARSET_UNKNOWN_CHARSET) goto badcharset;
        }
        else if (!strcmp(criteria.s, "cid")) {          /* nonstandard */
            conversation_id_t cid;
            if (c != ' ') goto missingarg;
            c = getword(pin, &arg);
            if (c == EOF) goto badnumber;
            if (!conversation_id_decode(&cid, arg.s)) goto badnumber;
            e = search_expr_new(parent, SEOP_MATCH);
            e->attr = search_attr_find("cid");
            e->value.u = cid;
        }
        else goto badcri;
        break;

    case 'd':
        if (!strcmp(criteria.s, "deleted")) {           /* RFC 3501 */
            systemflag_match(parent, FLAG_DELETED, /*not*/0);
        }
        else if (!strcmp(criteria.s, "draft")) {        /* RFC 3501 */
            systemflag_match(parent, FLAG_DRAFT, /*not*/0);
        }
        else if (!strcmp(criteria.s, "deliveredto")) {  /* nonstandard */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            string_match(parent, arg.s, criteria.s, base);
        }
        else goto badcri;
        break;

    case 'e':
        if (!strcmp(criteria.s, "emailid")) {   /* RFC 8474 */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            bytestring_match(parent, arg.s, criteria.s, base);
        }
        else goto badcri;
        break;

    case 'f':
        if (!strcmp(criteria.s, "flagged")) {           /* RFC 3501 */
            systemflag_match(parent, FLAG_FLAGGED, /*not*/0);
        }
        else if (!strcmp(criteria.s, "folder")) {       /* nonstandard */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            e = search_expr_new(parent, SEOP_MATCH);
            e->attr = search_attr_find("folder");
            e->value.s = mboxname_from_external(arg.s, base->namespace, base->userid);
        }
        else if (!strcmp(criteria.s, "from")) {         /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            string_match(parent, arg.s, criteria.s, base);
        }
        else if (!strcmp(criteria.s, "fuzzy")) {        /* RFC 6203 */
            if (c != ' ') goto missingarg;
            base->fuzzy_depth++;
            c = get_search_criterion(pin, pout, parent, base);
            base->fuzzy_depth--;
            if (c == EOF) return EOF;
        }
        else goto badcri;
        break;

    case 'h':
        if (!strcmp(criteria.s, "header")) {            /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg2);
            if (c == EOF) goto missingarg;

            e = search_expr_new(parent, SEOP_MATCH);
            e->attr = search_attr_find_field(arg.s);
            e->value.s = charset_convert(arg2.s, base->charset, charset_flags|CHARSET_KEEPCASE);
            if (!e->value.s) {
                e->op = SEOP_FALSE;
                e->attr = NULL;
            }
        }
        else goto badcri;
        break;

    case 'k':
        if (!strcmp(criteria.s, "keyword")) {           /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = getword(pin, &arg);
            if (!imparse_isatom(arg.s)) goto badflag;
            e = search_expr_new(parent, SEOP_MATCH);
            e->attr = search_attr_find("keyword");
            e->value.s = xstrdup(arg.s);
        }
        else goto badcri;
        break;

    case 'l':
        if (!strcmp(criteria.s, "larger")) {            /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = getint32(pin, (int32_t *)&u);
            if (c == EOF) goto badnumber;
            e = search_expr_new(parent, SEOP_GT);
            e->attr = search_attr_find("size");
            e->value.u = u;
        }
        else goto badcri;
        break;

    case 'm':
        if (!strcmp(criteria.s, "modseq")) {            /* RFC 4551 */
            modseq_t modseq;
            if (c != ' ') goto missingarg;
            /* Check for optional search-modseq-ext */
            c = getqstring(pin, pout, &arg);
            if (c != EOF) {
                if (c != ' ') goto missingarg;
                c = getword(pin, &arg);
                if (c != ' ') goto missingarg;
            }
            c = getmodseq(pin, &modseq);
            if (c == EOF) goto badnumber;
            e = search_expr_new(parent, SEOP_GE);
            e->attr = search_attr_find("modseq");
            e->value.u = modseq;
        }
        else goto badcri;
        break;

    case 'n':
        if (!strcmp(criteria.s, "not")) {       /* RFC 3501 */
            if (c != ' ') goto missingarg;
            e = search_expr_new(parent, SEOP_NOT);
            c = get_search_criterion(pin, pout, e, base);
            if (c == EOF) return EOF;
        }
        else if (!strcmp(criteria.s, "new")) {  /* RFC 3501 */
            e = search_expr_new(parent, SEOP_AND);
            indexflag_match(e, MESSAGE_SEEN, /*not*/1);
            indexflag_match(e, MESSAGE_RECENT, /*not*/0);
        }
        else goto badcri;
        break;

    case 'o':
        if (!strcmp(criteria.s, "or")) {        /* RFC 3501 */
            if (c != ' ') goto missingarg;
            e = search_expr_new(parent, SEOP_OR);
            c = get_search_criterion(pin, pout, e, base);
            if (c == EOF) return EOF;
            if (c != ' ') goto missingarg;
            c = get_search_criterion(pin, pout, e, base);
            if (c == EOF) return EOF;
        }
        else if (!strcmp(criteria.s, "old")) {  /* RFC 3501 */
            indexflag_match(parent, MESSAGE_RECENT, /*not*/1);
        }
        else if (!strcmp(criteria.s, "older")) {    /* RFC 5032 */
#if SIZEOF_TIME_T >= 8
            int64_t uu;
#endif
            if (c != ' ') goto missingarg;
#if SIZEOF_TIME_T >= 8
            c = getint64(pin, (int64_t *)&uu);
#else
            c = getint32(pin, (int32_t *)&u);
#endif
            if (c == EOF) goto badinterval;
            e = search_expr_new(parent, SEOP_LE);
            e->attr = search_attr_find("internaldate");
#if SIZEOF_TIME_T >= 8
            e->value.t = now - uu;
#else
            e->value.t = now - u;
#endif
        }
        else if (!strcmp(criteria.s, "on")) {   /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = get_search_date(pin, &start, &end);
            if (c == EOF) goto baddate;
            date_range(parent, "internaldate", start, end);
        }
        else goto badcri;
        break;

    case 'r':
        if (!strcmp(criteria.s, "recent")) {    /* RFC 3501 */
            indexflag_match(parent, MESSAGE_RECENT, /*not*/0);
        }
        else if ((base->state & GETSEARCH_RETURN) &&
                 !strcmp(criteria.s, "return")) {   /* RFC 4731 */
            c = get_search_return_opts(pin, pout, base);
            if (c == EOF) return EOF;
            keep_charset = 1;
        }
        else goto badcri;
        break;

    case 's':
        if (!strcmp(criteria.s, "savedatesupported")) {   /* RFC 8514 */
            // savedate is supported in index version 15+
            e = search_expr_new(parent, SEOP_GE);
            e->attr = search_attr_find("indexversion");
            e->value.u = 15;
        }
        else if (!strcmp(criteria.s, "savedbefore")) {   /* RFC 8514 */
            if (c != ' ') goto missingarg;
            c = get_search_date(pin, &start, &end);
            if (c == EOF) goto baddate;
            e = search_expr_new(parent, SEOP_LT);
            e->attr = search_attr_find("savedate");
            e->value.u = start;
        }
        else if (!strcmp(criteria.s, "savedon")) {   /* RFC 8514 */
            if (c != ' ') goto missingarg;
            c = get_search_date(pin, &start, &end);
            if (c == EOF) goto baddate;
            date_range(parent, "savedate", start, end);
        }
        else if (!strcmp(criteria.s, "savedsince")) {    /* RFC 8514 */
            if (c != ' ') goto missingarg;
            c = get_search_date(pin, &start, &end);
            if (c == EOF) goto baddate;
            e = search_expr_new(parent, SEOP_GE);
            e->attr = search_attr_find("savedate");
            e->value.u = start;
        }
        else if (!strcmp(criteria.s, "seen")) {              /* RFC 3501 */
            indexflag_match(parent, MESSAGE_SEEN, /*not*/0);
        }
        else if (!strcmp(criteria.s, "sentbefore")) {   /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = get_search_date(pin, &start, &end);
            if (c == EOF) goto baddate;
            e = search_expr_new(parent, SEOP_LT);
            e->attr = search_attr_find("sentdate");
            e->value.t = start;
        }
        else if (!strcmp(criteria.s, "senton")) {       /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = get_search_date(pin, &start, &end);
            if (c == EOF) goto baddate;
            date_range(parent, "sentdate", start, end);
        }
        else if (!strcmp(criteria.s, "sentsince")) {    /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = get_search_date(pin, &start, &end);
            if (c == EOF) goto baddate;
            e = search_expr_new(parent, SEOP_GE);
            e->attr = search_attr_find("sentdate");
            e->value.t = start;
        }
        else if (!strcmp(criteria.s, "since")) {    /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = get_search_date(pin, &start, &end);
            if (c == EOF) goto baddate;
            e = search_expr_new(parent, SEOP_GE);
            e->attr = search_attr_find("internaldate");
            e->value.t = start;
        }
        else if (!strcmp(criteria.s, "smaller")) {  /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = getint32(pin, (int32_t *)&u);
            if (c == EOF) goto badnumber;
            e = search_expr_new(parent, SEOP_LT);
            e->attr = search_attr_find("size");
            e->value.u = u;
        }
        else if (!strcmp(criteria.s, "spamabove")) {  /* nonstandard */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto badnumber;
            e = search_expr_new(parent, SEOP_GE);
            e->attr = search_attr_find("spamscore");
            e->value.u = (int)((atof(buf_cstring(&arg)) * 100) + 0.5);
        }
        else if (!strcmp(criteria.s, "spambelow")) {  /* nonstandard */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto badnumber;
            e = search_expr_new(parent, SEOP_LT);
            e->attr = search_attr_find("spamscore");
            e->value.u = (int)((atof(buf_cstring(&arg)) * 100) + 0.5);
        }
        else if (!strcmp(criteria.s, "subject")) {  /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            string_match(parent, arg.s, criteria.s, base);
        }
        else goto badcri;
        break;

    case 't':
        if (!strcmp(criteria.s, "to")) {            /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            string_match(parent, arg.s, criteria.s, base);
        }
        else if (!strcmp(criteria.s, "text")) {     /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            string_match(parent, arg.s, criteria.s, base);
        }
        else if (!strcmp(criteria.s, "threadid")) {   /* RFC 8474 */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            bytestring_match(parent, arg.s, criteria.s, base);
        }
        else goto badcri;
        break;

    case 'u':
        if (!strcmp(criteria.s, "uid")) {           /* RFC 3501 */
            seqset_t *seq;
            if (c != ' ') goto missingarg;
            c = getword(pin, &arg);
            if (!imparse_issequence(arg.s)) goto badcri;
            e = search_expr_new(parent, SEOP_MATCH);
            e->attr = search_attr_find(criteria.s);
            seq = seqset_parse(arg.s, NULL, /*maxval*/0);
            if (!seq) goto badcri;
            seqset_free(&seq);
            e->value.s = xstrdup(arg.s);
        }
        else if (!strcmp(criteria.s, "unseen")) {       /* RFC 3501 */
            indexflag_match(parent, MESSAGE_SEEN, /*not*/1);
        }
        else if (!strcmp(criteria.s, "unanswered")) {   /* RFC 3501 */
            systemflag_match(parent, FLAG_ANSWERED, /*not*/1);
        }
        else if (!strcmp(criteria.s, "undeleted")) {    /* RFC 3501 */
            systemflag_match(parent, FLAG_DELETED, /*not*/1);
        }
        else if (!strcmp(criteria.s, "undraft")) {      /* RFC 3501 */
            systemflag_match(parent, FLAG_DRAFT, /*not*/1);
        }
        else if (!strcmp(criteria.s, "unflagged")) {    /* RFC 3501 */
            systemflag_match(parent, FLAG_FLAGGED, /*not*/1);
        }
        else if (!strcmp(criteria.s, "unkeyword")) {    /* RFC 3501 */
            if (c != ' ') goto missingarg;
            c = getword(pin, &arg);
            if (!imparse_isatom(arg.s)) goto badflag;
            e = search_expr_new(parent, SEOP_NOT);
            e = search_expr_new(e, SEOP_MATCH);
            e->attr = search_attr_find("keyword");
            e->value.s = xstrdup(arg.s);
        }
        else goto badcri;
        break;

    case 'x':
        if (!strcmp(criteria.s, "xattachmentname")) {  /* nonstandard */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            string_match(parent, arg.s, "attachmentname", base);
        }
        else if (!strcmp(criteria.s, "xattachmentbody")) {  /* nonstandard */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            string_match(parent, arg.s, "attachmentbody", base);
        }
        else if (!strcmp(criteria.s, "xlistid")) {           /* nonstandard */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            string_match(parent, arg.s, "listid", base);
        }
        else if (!strcmp(criteria.s, "xcontenttype")) { /* nonstandard */
            if (c != ' ') goto missingarg;
            c = getastring(pin, pout, &arg);
            if (c == EOF) goto missingarg;
            string_match(parent, arg.s, "contenttype", base);
        }
        else goto badcri;
        break;

    case 'y':
        if (!strcmp(criteria.s, "younger")) {           /* RFC 5032 */
#if SIZEOF_TIME_T >= 8
            int64_t uu;
#endif
            if (c != ' ') goto missingarg;
#if SIZEOF_TIME_T >= 8
            c = getint64(pin, (int64_t *)&uu);
#else
            c = getint32(pin, (int32_t *)&u);
#endif
            if (c == EOF) goto badinterval;
            e = search_expr_new(parent, SEOP_GE);
            e->attr = search_attr_find("internaldate");
#if SIZEOF_TIME_T >= 8
            e->value.t = now - uu;
#else
            e->value.t = now - u;
#endif
        }
        else goto badcri;
        break;

    default:
    badcri:
        prot_printf(pout, "%s BAD Invalid Search criteria\r\n", base->tag);
        if (c != EOF) prot_ungetc(c, pin);
        return EOF;
    }

    if (!keep_charset)
        base->state &= ~GETSEARCH_CHARSET_KEYWORD;
    base->state &= ~GETSEARCH_RETURN;

    return c;

 missingarg:
    prot_printf(pout, "%s BAD Missing required argument to Search %s\r\n",
                base->tag, criteria.s);
    if (c != EOF) prot_ungetc(c, pin);
    return EOF;

 badflag:
    prot_printf(pout, "%s BAD Invalid flag name %s in Search command\r\n",
                base->tag, arg.s);
    if (c != EOF) prot_ungetc(c, pin);
    return EOF;

 baddate:
    prot_printf(pout, "%s BAD Invalid date in Search command\r\n",
                base->tag);
    if (c != EOF) prot_ungetc(c, pin);
    return EOF;

 badnumber:
    prot_printf(pout, "%s BAD Invalid number in Search command\r\n",
                base->tag);
    if (c != EOF) prot_ungetc(c, pin);
    return EOF;

 badinterval:
    prot_printf(pout, "%s BAD Invalid interval in Search command\r\n",
                base->tag);
    if (c != EOF) prot_ungetc(c, pin);
    return EOF;

 missingcharset:
    prot_printf(pout, "%s BAD Missing charset\r\n",
                base->tag);
    if (c != EOF) prot_ungetc(c, pin);
    return EOF;

 badcharset:
    prot_printf(pout, "%s BAD %s\r\n", base->tag,
               error_message(IMAP_UNRECOGNIZED_CHARSET));
    if (c != EOF) prot_ungetc(c, pin);
    return EOF;
}

/*
 * Parse a search program
 */
EXPORTED int get_search_program(struct protstream *pin,
                                struct protstream *pout,
                                struct searchargs *searchargs)
{
    int c;

    searchargs->root = search_expr_new(NULL, SEOP_AND);

    do {
        c = get_search_criterion(pin, pout, searchargs->root, searchargs);
    } while (c == ' ');

    return c;
}

