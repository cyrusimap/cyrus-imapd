/*
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
 *
 * derived from chris newman's code */

/* $Id: imapurl.c,v 1.7 2002/02/01 19:43:36 rjs3 Exp $ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* hexadecimal lookup table */
static const char hex[] = "0123456789ABCDEF";

/* URL unsafe printable characters */
static const char urlunsafe[] = " \"#%&+:;<=>?@[\\]^`{|}";

/* UTF7 modified base64 alphabet */
static const char base64chars[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
#define UNDEFINED 64

/* UTF16 definitions */
#define UTF16MASK       0x03FFUL
#define UTF16SHIFT      10
#define UTF16BASE       0x10000UL
#define UTF16HIGHSTART  0xD800UL
#define UTF16HIGHEND    0xDBFFUL
#define UTF16LOSTART    0xDC00UL
#define UTF16LOEND      0xDFFFUL

/* Convert an IMAP mailbox to a URL path
 *  dst needs to have roughly 4 times the storage space of src
 *    Hex encoding can triple the size of the input
 *    UTF-7 can be slightly denser than UTF-8
 *     (worst case: 8 octets UTF-7 becomes 9 octets UTF-8)
 */
static void MailboxToURL(char *dst, const char *src)
{
    unsigned char c, i, bitcount;
    unsigned long ucs4, utf16, bitbuf;
    unsigned char base64[256], utf8[6];

    /* initialize modified base64 decoding table */
    memset(base64, UNDEFINED, sizeof (base64));
    for (i = 0; i < sizeof (base64chars); ++i) {
        base64[(int) base64chars[i]] = i;
    }

    /* loop until end of string */
    while (*src != '\0') {
        c = *src++;
        /* deal with literal characters and &- */
        if (c != '&' || *src == '-') {
            if (c < ' ' || c > '~' || strchr(urlunsafe, c) != NULL) {
                /* hex encode if necessary */
                dst[0] = '%';
                dst[1] = hex[c >> 4];
                dst[2] = hex[c & 0x0f];
                dst += 3;
            } else {
                /* encode literally */
                *dst++ = c;
            }
            /* skip over the '-' if this is an &- sequence */
            if (c == '&') ++src;
        } else {
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
                    utf16 = (bitcount ? bitbuf >> bitcount
                             : bitbuf) & 0xffff;
                    /* convert UTF16 to UCS4 */
                    if
                    (utf16 >= UTF16HIGHSTART && utf16 <= UTF16HIGHEND) {
                        ucs4 = (utf16 - UTF16HIGHSTART) << UTF16SHIFT;
                        continue;
                    } else if
                    (utf16 >= UTF16LOSTART && utf16 <= UTF16LOEND) {
                        ucs4 += utf16 - UTF16LOSTART + UTF16BASE;
                    } else {
                        ucs4 = utf16;
                    }
                    /* convert UTF-16 range of UCS4 to UTF-8 */
                    if (ucs4 <= 0x7fUL) {
                        utf8[0] = ucs4;
                        i = 1;
                    } else if (ucs4 <= 0x7ffUL) {
                        utf8[0] = 0xc0 | (ucs4 >> 6);
                        utf8[1] = 0x80 | (ucs4 & 0x3f);
                        i = 2;
                    } else if (ucs4 <= 0xffffUL) {
                        utf8[0] = 0xe0 | (ucs4 >> 12);
                        utf8[1] = 0x80 | ((ucs4 >> 6) & 0x3f);
                        utf8[2] = 0x80 | (ucs4 & 0x3f);
                        i = 3;
                    } else {
                        utf8[0] = 0xf0 | (ucs4 >> 18);
                        utf8[1] = 0x80 | ((ucs4 >> 12) & 0x3f);
                        utf8[2] = 0x80 | ((ucs4 >> 6) & 0x3f);
                        utf8[3] = 0x80 | (ucs4 & 0x3f);
                        i = 4;
                    }
                    /* convert utf8 to hex */
                    for (c = 0; c < i; ++c) {
                        dst[0] = '%';
                        dst[1] = hex[utf8[c] >> 4];
                        dst[2] = hex[utf8[c] & 0x0f];
                        dst += 3;
                    }
                }
            }
            /* skip over trailing '-' in modified UTF-7 encoding */
            if (*src == '-') ++src;
        }
    }
    /* terminate destination string */
    *dst = '\0';
}

/* Convert hex coded UTF-8 URL path to modified UTF-7 IMAP mailbox
 *  dst should be about twice the length of src to deal with non-hex
 *  coded URLs
 */
static void URLtoMailbox(char *dst, char *src)
{
    unsigned int utf8pos = 0, utf8total, i, c, utf7mode, bitstogo, utf16flag;
    unsigned long ucs4 = 0, bitbuf = 0;
    unsigned char hextab[256];
    
    /* initialize hex lookup table */
    memset(hextab, 0, sizeof (hextab));
    for (i = 0; i < sizeof (hex); ++i) {
        hextab[(int) hex[i]] = i;
        if (isupper((unsigned char) hex[i])) hextab[tolower(hex[i])] = i;
    }
    
    utf7mode = 0;
    utf8total = 0;
    bitstogo = 0;
    while ((c = *src) != '\0') {
        ++src;
        /* undo hex-encoding */
        if (c == '%' && src[0] != '\0' && src[1] != '\0') {
            c = (hextab[(int) src[0]] << 4) | hextab[(int) src[1]];
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
        } else if (utf8total) {
            /* save UTF8 bits into UCS4 */
            ucs4 = (ucs4 << 6) | (c & 0x3FUL);
            if (++utf8pos < utf8total) {
                continue;
            }
        } else {
            utf8pos = 1;
            if (c < 0xE0) {
                utf8total = 2;
                ucs4 = c & 0x1F;
            } else if (c < 0xF0) {
                utf8total = 3;
                ucs4 = c & 0x0F;
            } else {
                /* NOTE: can't convert UTF8 sequences longer than 4 */
                utf8total = 4;
                ucs4 = c & 0x03;
            }
            continue;
        }
        /* loop to split ucs4 into two utf16 chars if necessary */
        utf8total = 0;
        do {
            if (ucs4 >= UTF16BASE) {
                ucs4 -= UTF16BASE;
                bitbuf = (bitbuf << 16) | ((ucs4 >> UTF16SHIFT)
                                           + UTF16HIGHSTART);
                ucs4 = (ucs4 & UTF16MASK) + UTF16LOSTART;
                utf16flag = 1;
            } else {
                bitbuf = (bitbuf << 16) | ucs4;
                utf16flag = 0;
            }
            bitstogo += 16;
            /* spew out base64 */
            while (bitstogo >= 6) {
                bitstogo -= 6;
                *dst++ = base64chars[(bitstogo ? (bitbuf >> bitstogo)
                               : bitbuf)
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
}

void imapurl_fromURL(char *server, char *mailbox, const char *src)
{
    if (server) server[0] = '\0';
    if (mailbox) mailbox[0] = '\0';
    if (src[0] == '{') {	/* c-client style */
	char *se;

	src++;
	se = strchr(src, '}');
	if (se == NULL) return;
	if (server) {
	    strncpy(server, src, se - src);
	    server[se - src] = '\0';
	}
	se += 1;
	if (mailbox) strcpy(mailbox, se);
    } else if (!strncmp(src, "imap://", 7)) { /* IMAP URL */
	char *se;
	char *at;
	
	src += 7; /* skip imap:// */
	se = strchr(src, '/');
	if (se == NULL) return;
	at = strchr(src, '@');
	
	if (at) {
	    /* xxx we discard the username for now */
	    src = at + 1; 
	}
	*se = '\0';
	if (server) {
	    strncpy(server, src, se - src);
	    server[se - src] = '\0';
	}
	se += 1;
	if (mailbox) URLtoMailbox(mailbox, se);
    }
}

void imapurl_toURL(char *dst, const char *server, const char *mailbox,
		   const char *mechname)
{
    if(mechname) sprintf(dst, "imap://;AUTH=%s@%s/",mechname,server);
    else sprintf(dst, "imap://%s/", server);
    MailboxToURL(dst + strlen(dst), mailbox);
}
