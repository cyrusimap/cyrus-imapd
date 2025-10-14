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
 *
 * derived from chris newman's code
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#include "imapurl.h"
#include "xmalloc.h"
#include "times.h"
#include "util.h"

/* URL unsafe printable characters */
static const char urlunsafe[] = " \"#%&+:;<=>?@[\\]^`{|}";

/* UTF7 modified base64 alphabet */
static const char base64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
#define UNDEFINED 64

/* UTF16 definitions */
#define UTF16MASK 0x03FFUL
#define UTF16SHIFT 10
#define UTF16BASE 0x10000UL
#define UTF16HIGHSTART 0xD800UL
#define UTF16HIGHEND 0xDBFFUL
#define UTF16LOSTART 0xDC00UL
#define UTF16LOEND 0xDFFFUL

/* Convert an IMAP mailbox to a URL path
 *    Hex encoding can triple the size of the input
 *    UTF-7 can be slightly denser than UTF-8
 *     (worst case: 8 octets UTF-7 becomes 9 octets UTF-8)
 */
static void MailboxToURL(struct buf *dst, const char *src)
{
    unsigned char c, i, bitcount;
    unsigned long ucs4, utf16, bitbuf;
    unsigned char base64[256], utf8[6];

    /* initialize modified base64 decoding table */
    memset(base64, UNDEFINED, sizeof(base64));
    for (i = 0; i < sizeof(base64chars); ++i) {
        base64[(int) base64chars[i]] = i;
    }

    /* loop until end of string */
    while (*src != '\0') {
        c = *src++;
        /* deal with literal characters and &- */
        if (c != '&' || *src == '-') {
            if (c < ' ' || c > '~' || strchr(urlunsafe, c) != NULL) {
                /* hex encode if necessary */
                buf_putc(dst, '%');
                buf_bin_to_hex(dst, &c, 1, BH_UPPER);
            }
            else {
                /* encode literally */
                buf_putc(dst, c);
            }
            /* skip over the '-' if this is an &- sequence */
            if (c == '&') {
                ++src;
            }
        }
        else {
            /* convert modified UTF-7 -> UTF-16 -> UCS-4 -> UTF-8 -> HEX */
            bitbuf = 0;
            bitcount = 0;
            ucs4 = 0;
            while ((c = base64[(unsigned char) *src]) != UNDEFINED) {
                ++src;
                bitbuf = (bitbuf << 6) | c;
                bitcount += 6;
                /* enough bits for a UTF-16 character? */
                if (bitcount >= 16) {
                    bitcount -= 16;
                    utf16 = (bitcount ? bitbuf >> bitcount : bitbuf) & 0xffff;
                    /* convert UTF16 to UCS4 */
                    if (utf16 >= UTF16HIGHSTART && utf16 <= UTF16HIGHEND) {
                        ucs4 = (utf16 - UTF16HIGHSTART) << UTF16SHIFT;
                        continue;
                    }
                    else if (utf16 >= UTF16LOSTART && utf16 <= UTF16LOEND) {
                        ucs4 += utf16 - UTF16LOSTART + UTF16BASE;
                    }
                    else {
                        ucs4 = utf16;
                    }
                    /* convert UTF-16 range of UCS4 to UTF-8 */
                    if (ucs4 <= 0x7fUL) {
                        utf8[0] = ucs4;
                        i = 1;
                    }
                    else if (ucs4 <= 0x7ffUL) {
                        utf8[0] = 0xc0 | (ucs4 >> 6);
                        utf8[1] = 0x80 | (ucs4 & 0x3f);
                        i = 2;
                    }
                    else if (ucs4 <= 0xffffUL) {
                        utf8[0] = 0xe0 | (ucs4 >> 12);
                        utf8[1] = 0x80 | ((ucs4 >> 6) & 0x3f);
                        utf8[2] = 0x80 | (ucs4 & 0x3f);
                        i = 3;
                    }
                    else {
                        utf8[0] = 0xf0 | (ucs4 >> 18);
                        utf8[1] = 0x80 | ((ucs4 >> 12) & 0x3f);
                        utf8[2] = 0x80 | ((ucs4 >> 6) & 0x3f);
                        utf8[3] = 0x80 | (ucs4 & 0x3f);
                        i = 4;
                    }
                    /* convert utf8 to hex.
                     * RFC3986 says: For consistency, URI producers and
                     * normalizers should use uppercase hexadecimal digits
                     * for all percent-encodings. */
                    buf_putc(dst, '%');
                    buf_bin_to_hex(dst, utf8, i, BH_UPPER | BH_SEPARATOR('%'));
                }
            }
            /* skip over trailing '-' in modified UTF-7 encoding */
            if (*src == '-') {
                ++src;
            }
        }
    }
    /* terminate destination string */
    buf_cstring(dst);
}

/* Convert hex coded UTF-8 URL path to modified UTF-7 IMAP mailbox
 *  dst should be about twice the length of src to deal with non-hex
 *  coded URLs
 */
EXPORTED int URLtoMailbox(char *dst, const char *src)
{
    unsigned char c;
    unsigned int utf8pos = 0, utf8total, utf7mode, bitstogo, utf16flag;
    unsigned long ucs4 = 0, bitbuf = 0;

    utf7mode = 0;  /* is the output UTF7 currently in base64 mode? */
    utf8total = 0; /* how many octets is the current input UTF-8 char;
                      0 == between characters */
    bitstogo = 0;  /* bits that need to be encoded into base64; if
                      bitstogo != 0 then utf7mode == 1 */
    while ((c = (unsigned char) *src) != '\0') {
        ++src;
        /* undo hex-encoding */
        if (c == '%' && src[0] != '\0' && src[1] != '\0') {
            if (hex_to_bin(src, 2, &c) != 1) {
                return -1;
            }
            src += 2;
        }

        /* normal character? */
        if (c >= ' ' && c <= '~') {
            /* switch out of UTF-7 mode */
            if (utf7mode) {
                if (bitstogo) {
                    *dst++ = base64chars[(bitbuf << (6 - bitstogo)) & 0x3F];
                }
                *dst++ = '-';
                utf7mode = 0;
                bitstogo = bitbuf = 0;
            }
            *dst++ = c;
            /* encode '&' as '&-' */
            if (c == '&') {
                *dst++ = '-';
            }
            continue;
        }

        /* switch to UTF-7 mode */
        if (!utf7mode) {
            *dst++ = '&';
            utf7mode = 1;
        }

        /* Encode US-ASCII characters as themselves */
        if (c < 0x80) {
            ucs4 = c;
            utf8total = 1;
        }
        else if (utf8total) {
            /* this is a subsequent octet of a multi-octet character */

            /* save UTF8 bits into UCS4 */
            ucs4 = (ucs4 << 6) | (c & 0x3FUL);
            if (++utf8pos < utf8total) {
                continue;
            }
        }
        else {
            /* this is the first octet of a multi-octet character */

            utf8pos = 1;
            if (c < 0xE0) {
                utf8total = 2;
                ucs4 = c & 0x1F;
            }
            else if (c < 0xF0) {
                utf8total = 3;
                ucs4 = c & 0x0F;
            }
            else {
                /* NOTE: can't convert UTF8 sequences longer than 4 */
                utf8total = 4;
                ucs4 = c & 0x03;
            }
            continue;
        }

        /* finished with UTF-8 character. make sure it isn't an
           overlong sequence. if it is, drop that character */
        if ((ucs4 < 0x80 && utf8total > 1) || (ucs4 < 0x0800 && utf8total > 2)
            || (ucs4 < 0x00010000 && utf8total > 3)
            || (ucs4 < 0x00200000 && utf8total > 4)
            || (ucs4 < 0x04000000 && utf8total > 5)
            || (ucs4 < 0x80000000 && utf8total > 6))
        {
            utf8total = 0;
            continue;
        }
        utf8total = 0;

        /* loop to split ucs4 into two utf16 chars if necessary */
        do {
            if (ucs4 >= UTF16BASE) {
                ucs4 -= UTF16BASE;
                bitbuf =
                    (bitbuf << 16) | ((ucs4 >> UTF16SHIFT) + UTF16HIGHSTART);
                ucs4 = (ucs4 & UTF16MASK) + UTF16LOSTART;
                utf16flag = 1;
            }
            else {
                bitbuf = (bitbuf << 16) | ucs4;
                utf16flag = 0;
            }
            bitstogo += 16;
            /* spew out base64 */
            while (bitstogo >= 6) {
                bitstogo -= 6;
                *dst++ = base64chars[(bitstogo ? (bitbuf >> bitstogo) : bitbuf)
                                     & 0x3F];
            }
        } while (utf16flag);
    }

    /* if in UTF-7 mode, finish in ASCII */
    if (utf7mode) {
        if (bitstogo) {
            *dst++ = base64chars[(bitbuf << (6 - bitstogo)) & 0x3F];
        }
        *dst++ = '-';
    }

    /* tie off string */
    *dst = '\0';

    return 0;
}

/* Decode hex coded url
 *  dst can be the same location as src,
 *  since the decoded length will be shorter than the encoded length
 */
static int decode_url(char *dst, const char *src)
{
    unsigned char c;

    while ((c = (unsigned char) *src) != '\0') {
        ++src;
        /* undo hex-encoding */
        if (c == '%' && src[0] != '\0' && src[1] != '\0') {
            if (hex_to_bin(src, 2, &c) != 1) {
                return -1;
            }
            src += 2;
        }
        *dst++ = (char) c;
    }

    /* tie off string */
    *dst = '\0';

    return 0;
}

EXPORTED int imapurl_fromURL(struct imapurl *url, const char *s)
{
    char *src;
    int step = 0; /* used to force correct ordering of url parts */

    memset(url, 0, sizeof(struct imapurl));
    url->freeme = xmalloc(6 * strlen(s) + 3); /* space for copy of URL +
                                                 decoded mailbox */
    src = strcpy(url->freeme, s);

    if (src[0] == '{') { /* c-client style */
        char *se;

        src++;
        se = strchr(src, '}');
        if (se == NULL) {
            return -1;
        }
        *se = '\0';
        url->server = src;
        url->mailbox = se + 1;
    }
    else { /* IMAP URL */
        int r;
        char *se;
        char *at;
        char *mbox = NULL;

        if (!strncmp(src, "imap://", 7)) { /* absolute URL */
            src += 7;                      /* skip imap:// */
            se = strchr(src, '/');
            if (se == NULL) {
                return -1;
            }
            at = strchr(src, '@');

            if (at) {
                *at = '\0';
                r = decode_url(src, src);
                url->user = src;
                if (r) {
                    return r;
                }
                src = at + 1;
            }
            *se = '\0';
            url->server = src;
            src = mbox = ++se;
        }
        else { /* relative URL */
            if (*src == '/') {
                src++;
            }
            mbox = src;
        }

        /* parse options */
        errno = 0;
        while (src && (src = strchr(src, ';'))) {
            unsigned long ul;
            char *endp;

            if (src[-1] == '/') {
                src[-1] = '\0'; /* trim mailbox at /; */
            }
            *src++ = '\0'; /* break url at ; */
            if (step == 0 && !strncasecmp(src, "uidvalidity=", 12)) {
                src += 12;                    /* skip uidvalidity= */
                ul = strtoul(src, &endp, 10); /* ends at '/' or '\0' */
                if (errno || endp == src) {
                    return -1;
                }
                url->uidvalidity = ul;
                step = 1;
            }
            else if (step <= 1 && !strncasecmp(src, "uid=", 4)) {
                src += 4;                     /* skip uid= */
                ul = strtoul(src, &endp, 10); /* ends at '/' or '\0' */
                if (errno || endp == src) {
                    return -1;
                }
                url->uid = ul;
                step = 2;
            }
            else if (step == 2 && !strncasecmp(src, "section=", 8)) {
                src += 8;           /* skip section= */
                url->section = src; /* ends at ';' (next pass) or '\0' */
                step = 3;
            }
            else if (step >= 2 && step <= 3 && !strncasecmp(src, "partial=", 8))
            {
                src += 8;                     /* skip partial= */
                ul = strtoul(src, &endp, 10); /* ends at '.', '/' or '\0' */
                if (errno || endp == src) {
                    return -1;
                }
                url->start_octet = ul;
                if (*endp == '.') {
                    src = endp + 1;               /* skip . */
                    ul = strtoul(src, &endp, 10); /* ends at '/' or '\0' */
                    if (errno || endp == src) {
                        return -1;
                    }
                    url->octet_count = ul;
                }
                step = 4;
            }
            else if (step >= 2 && step < 5 && !strncasecmp(src, "expire=", 7)) {
                int n;

                src += 7; /* skip expire= */
                n = time_from_iso8601(src, &url->urlauth.expire);
                if (n < 0) {
                    return -1;
                }
                src += n;
                step = 5;
            }
            else if (step >= 2 && step < 6 && !strncasecmp(src, "urlauth=", 8))
            {
                char *u;

                src += 8; /* skip urlauth= */
                url->urlauth.access = src;
                if ((u = strchr(src, ':'))) {
                    url->urlauth.rump_len = (u - url->freeme);

                    *u++ = '\0'; /* break urlauth at : */
                    url->urlauth.mech = u;
                    if ((u = strchr(u, ':'))) {
                        *u++ = '\0'; /* break urlauth at : */
                        url->urlauth.token = u;
                    }
                    src = u;
                }
                else {
                    url->urlauth.rump_len = strlen(s);
                }
                step = 6;
            }
            else {
                return -1;
            }
        }

        if (mbox && *mbox) {
            url->mailbox = url->freeme + strlen(s) + 1;
            return URLtoMailbox((char *) url->mailbox, mbox);
        }
    }
    return 0;
}

EXPORTED void imapurl_toURL(struct buf *dst, const struct imapurl *url)
{

    if (url->server) {
        buf_appendcstr(dst, "imap://");
        if (url->user) {
            buf_appendcstr(dst, url->user);
        }
        if (url->auth) {
            buf_printf(dst, ";AUTH=%s", url->auth);
        }
        if (url->user || url->auth) {
            buf_putc(dst, '@');
        }
        buf_appendcstr(dst, url->server);
    }
    if (url->mailbox) {
        buf_putc(dst, '/');
        MailboxToURL(dst, url->mailbox);
    }

    if (url->uidvalidity) {
        buf_printf(dst, ";UIDVALIDITY=%lu", url->uidvalidity);
    }
    if (url->uid) {
        buf_printf(dst, "/;UID=%lu", url->uid);
        if (url->section) {
            buf_printf(dst, "/;SECTION=%s", url->section);
        }
        if (url->start_octet || url->octet_count) {
            buf_printf(dst, "/;PARTIAL=%lu", url->start_octet);
            if (url->octet_count) {
                buf_printf(dst, ".%lu", url->octet_count);
            }
        }
    }
    if (url->urlauth.access) {
        if (url->urlauth.expire) {
            buf_appendcstr(dst, ";EXPIRE=");
            char buf[RFC3339_DATETIME_MAX + 1] = { 0 };
            time_to_iso8601(url->urlauth.expire, buf, RFC3339_DATETIME_MAX, 1);
            buf_appendcstr(dst, buf);
        }
        buf_printf(dst, ";URLAUTH=%s", url->urlauth.access);
        if (url->urlauth.mech) {
            buf_printf(dst, ":%s", url->urlauth.mech);
            if (url->urlauth.token) {
                buf_printf(dst, ":%s", url->urlauth.token);
            }
        }
    }
}
