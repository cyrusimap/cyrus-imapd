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

#ifndef INCLUDED_CHARSET_H
#define INCLUDED_CHARSET_H

#define ENCODING_NONE 0
#define ENCODING_QP 1
#define ENCODING_BASE64 2
#define ENCODING_BASE64URL 3
#define ENCODING_UNKNOWN 255

#define CHARSET_SKIPDIACRIT (1<<0)
#define CHARSET_SKIPSPACE (1<<1)
#define CHARSET_MERGESPACE (1<<2)
#define CHARSET_SKIPHTML (1<<3)
#define CHARSET_KEEPCASE (1<<4)
#define CHARSET_UNFOLD_SKIPWS (1<<5)
#define CHARSET_MIME_UTF8 (1<<6)
#define CHARSET_ESCAPEHTML (1<<8)
#define CHARSET_KEEPHTML (1<<9)
#define CHARSET_TRIMWS (1<<10)
#define CHARSET_UNORM_NFC (1<<11)

#define CHARSET_UNKNOWN_CHARSET (NULL)

#include "util.h"
#include "xsha1.h"

#define charset_base64_len_unpadded(n) \
    ((n) * 4 / 3)

#define charset_base64_len_padded(n) \
    (charset_base64_len_unpadded(n) + 4)

typedef int comp_pat;
/*
 * Charset identifies a character encoding.
 * Use charset_lookupname to create an instance, and release it
 * using charset_free.
 *
 * Caveats:
 * * Two instances for the same character encoding are not pointer-equal.
 *   Use string comparison of the charset_canon_name to test for equality.
 * * Instances are not safe to use for two simultaneous conversions. It is safe
 *   (and recommended) to reuse an instance for consecutive conversions.
 */
typedef struct charset_charset* charset_t;

extern int encoding_lookupname(const char *name);
extern const char *encoding_name(int);

/* Converter converts to UTF-8 search form as parametrized by flags.
 * It is safe (and recommended) to reuse an instance for consecutive
 * conversions. */
typedef struct charset_conv charset_conv_t;
extern charset_conv_t *charset_conv_new(charset_t fromcharset, int flags);
extern const char *charset_conv_convert(charset_conv_t *conv, const char *s);
extern void charset_conv_free(charset_conv_t **convp);

extern char *charset_convert(const char *s, charset_t charset, int flags);
extern char *charset_decode_mimeheader(const char *s, int flags);
extern char *charset_parse_mimeheader(const char *s, int flags);
extern char *charset_parse_mimexvalue(const char *s, struct buf *language);
extern char *charset_encode_mimexvalue(const char *s,const char *language);
extern char *charset_utf8_to_searchform(const char *s, int flags);

/* Normalize the zero-terminted UTF-8 string s to Unicode NFC
 * normal form.
 *
 * Does not enforce CR LF line ending or omission of control
 * characters as defined in RFC 5198.
 *
 * Also see http://www.unicode.org/reports/tr15/ and RFC 5198 */
extern char *charset_utf8_normalize(const char *s);

extern charset_t charset_lookupname(const char *name);
extern charset_t charset_lookupnumid(int id);
extern void charset_free(charset_t *charset);

/* Return the canonical charset name. */
extern const char *charset_canon_name(charset_t);

/* Returns the name as provided in lookupname, if any.
 * Falls back to returning the canonical name. */
extern const char *charset_alias_name(charset_t);

extern comp_pat *charset_compilepat(const char *s);
extern void charset_freepat(comp_pat *pat);
extern int charset_searchstring(const char *substr, comp_pat *pat,
                                const char *s, size_t len, int flags);
extern int charset_searchfile(const char *substr, comp_pat *pat,
                              const char *msg_base, size_t len,
                              charset_t charset, int encoding, int flags);
extern const char *charset_decode_mimebody(const char *msg_base, size_t len,
                                           int encoding, char **retval,
                                           size_t *outlen);
extern char *charset_encode_mimebody(const char *msg_base, size_t len,
                                     char *retval, size_t *outlen,
                                     int *outlines, int wrap);
extern char *charset_qpencode_mimebody(const char *msg_base, size_t len,
                                       int force_quote, size_t *outlen);
extern char *charset_to_utf8(const char *msg_base, size_t len, charset_t charset, int encoding);
extern char *charset_to_imaputf7(const char *msg_base, size_t len, charset_t charset, int encoding);

extern int charset_search_mimeheader(const char *substr, comp_pat *pat, const char *s, int flags);

extern char *charset_encode_mimeheader(const char *header, size_t len, int force_quote);
extern char *charset_encode_mimephrase(const char *header);

extern char *charset_unfold(const char *s, size_t len, int flags);

extern int charset_decode(struct buf *dst, const char *src, size_t len, int encoding);
extern int charset_encode(struct buf *dst, const char *src, size_t len, int encoding);

extern int charset_decode_sha1(uint8_t dest[SHA1_DIGEST_LENGTH], size_t *decodedlen, const char *src, size_t len, int encoding);

extern int charset_decode_percent(struct buf *dst, const char *val);

/* Extract the body text contained in 'data' and with character encoding
 * 'charset' and body-part encoding 'encoding'. The 'subtype' argument
 * defines the MIME subtype (assuming that the main type is 'text').
 * Extraction is done by a series of invocations of the callback 'cb'.
 * Extraction stops when either the body text is fully extracted, or
 * 'cb' returns a non-zero value, which is then returned to the caller.
 * If 'charset' is unknown, then the function returns early without
 * error and never calls 'cb'.
 * Note: This function is called by index_getsearchtext to extract
 * the MIME body parts. */
extern int charset_extract(int (*cb)(const struct buf *text, void *rock),
                           void *rock,
                           const struct buf *data,
                           charset_t charset, int encoding,
                           const char *subtype, int flags);

/* Extract plain text from HTML, converting <p> and <br>
 * to newlines and trimming space left by HTML-only lines. */
EXPORTED char *charset_extract_plain(const char *html);

struct char_counts {
    size_t total;
    size_t valid;
    size_t replacement;
    size_t invalid;
    size_t cntrl;
};

/* Count the number of valid, invalid and replacement UTF-8 characters
 * in the first INT32_MAX bytes of data. */
extern struct char_counts charset_count_validutf8(const char *data, size_t datalen);

#endif /* INCLUDED_CHARSET_H */
