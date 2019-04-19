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
#define ENCODING_UNKNOWN 255

#define CHARSET_SKIPDIACRIT (1<<0)
#define CHARSET_SKIPSPACE (1<<1)
#define CHARSET_MERGESPACE (1<<2)
#define CHARSET_SKIPHTML (1<<3)
#define CHARSET_SNIPPET (1<<4)
#define CHARSET_UNFOLD_SKIPWS (1<<5)
#define CHARSET_MIME_UTF8 (1<<6)
#define CHARSET_ESCAPEHTML (1<<8)

#define CHARSET_UNKNOWN_CHARSET (NULL)

#include "unicode/ucnv.h"

#include "util.h"

typedef int comp_pat;
/*
 * Charset identifies a character encoding.
 * Use charset_lookupname to create an instance, and release it
 * using charset_free.
 *
 * Caveats:
 * * Two instances for the same character encoding are not pointer-equal.
 *   Use string comparison of the charset_name to test for equality.
 * * Instances are not safe to use for two simultaneous conversions. It is safe
 *   (and recommended) to reuse an instance for consecutive conversions.
 */
typedef struct charset_converter* charset_t;

extern int encoding_lookupname(const char *name);
extern const char *encoding_name(int);

/* ensure up to MAXTRANSLATION times expansion into buf */
extern char *charset_convert(const char *s, charset_t charset, int flags);
extern char *charset_decode_mimeheader(const char *s, int flags);
extern char *charset_parse_mimeheader(const char *s, int flags);
extern char *charset_utf8_to_searchform(const char *s, int flags);


extern charset_t charset_lookupname(const char *name);
extern charset_t charset_lookupnumid(int id);
extern void charset_free(charset_t *charset);

extern const char *charset_name(charset_t);
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
                                     int *outlines);
extern char *charset_qpencode_mimebody(const char *msg_base, size_t len,
                                       size_t *outlen);
extern char *charset_to_utf8(const char *msg_base, size_t len, charset_t charset, int encoding);
extern char *charset_to_imaputf7(const char *msg_base, size_t len, charset_t charset, int encoding);

extern int charset_search_mimeheader(const char *substr, comp_pat *pat, const char *s, int flags);

extern char *charset_encode_mimeheader(const char *header, size_t len);

extern char *charset_unfold(const char *s, size_t len, int flags);

extern int charset_decode(struct buf *dst, const char *src, size_t len, int encoding);

/* Extract the body text for the message denoted by 'uid', convert its
   text to the canonical form for searching, and pass the converted text
   down in a series of invocations of the callback 'cb'.  This is
   called by index_getsearchtext to extract the MIME body parts. */
extern int charset_extract(void (*cb)(const struct buf *text, void *rock),
                           void *rock,
                           const struct buf *data,
                           charset_t charset, int encoding,
                           const char *subtype, int flags);

/* If input does not return special characters in terms of RFC 5322 section
 * 3.2.4, the function returns NULL, otherwise does the quoting described there.
 * The caller frees the return value */
char* mime_quote_string(const char* input);
#endif /* INCLUDED_CHARSET_H */
