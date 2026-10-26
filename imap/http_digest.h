/* http_digest.h - Digests of HTTP message content */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/**
 * @file
 * Digests of HTTP message content:
 * Content-Digest and Want-Content-Digest (RFC 9530),
 * Unencoded-Digest and Want-Unencoded-Digest
 * (draft-ietf-httpbis-unencoded-digest),
 * and the deprecated Content-MD5 (RFC 2616 Section 14.15).
 *
 * Content-Digest is of the content as sent, with any content coding
 * applied; Unencoded-Digest is of the whole selected representation with
 * none applied, even in a 206 response.
 *
 * Only the algorithms RFC 9530 lists as active, sha-256 and sha-512, are
 * supported for either field.  A digest using any other algorithm is
 * ignored, and one is never sent.
 */

#ifndef HTTP_DIGEST_H
#define HTTP_DIGEST_H

#include <stddef.h>

#include "spool.h"
#include "util.h"

/** A digest of message content, being computed or final. */
struct http_digest;

/**
 * Start a Content-Digest of response content, if the request asks for one.
 *
 * The algorithm is the most preferred supported one in Want-Content-Digest.
 * If that names no supported algorithm, a supported one it doesn't rule out
 * (with a preference of 0) is used anyway, as RFC 9530 Appendix C.2 does.
 *
 * @param req_hdrs  the request's header fields
 * @return a digest to feed with http_digest_update() and free with
 *         http_digest_free(), or NULL if none is wanted
 */
extern struct http_digest *http_digest_want(hdrcache_t req_hdrs);

/**
 * Start an Unencoded-Digest of a response's representation, if the request
 * asks for one with Want-Unencoded-Digest.  The algorithm is chosen as for
 * http_digest_want().
 *
 * @param req_hdrs  the request's header fields
 * @return a digest to feed with http_digest_update() and free with
 *         http_digest_free(), or NULL if none is wanted
 */
extern struct http_digest *http_digest_want_unencoded(hdrcache_t req_hdrs);

/**
 * Start a Content-MD5 digest, whose value is the bare base64 MD5 of the
 * content.
 *
 * @return a digest to feed with http_digest_update() and free with
 *         http_digest_free()
 */
extern struct http_digest *http_digest_content_md5(void);

/**
 * Add the next part of the content to a digest that isn't final yet.
 */
extern void http_digest_update(struct http_digest *d,
                               const void *data, size_t len);

/**
 * Finish a digest.
 *
 * @return the field value, such as "sha-256=:...:" for Content-Digest,
 *         which lives as long as @p d
 */
extern const char *http_digest_final(struct http_digest *d);

/**
 * @return the name of the field the digest belongs in, "Content-Digest",
 *         "Unencoded-Digest" or "Content-MD5", or NULL if @p d is NULL
 */
extern const char *http_digest_field(const struct http_digest *d);

/**
 * @return the field value of a final digest, or NULL if @p d is NULL or
 *         isn't final yet
 */
extern const char *http_digest_value(const struct http_digest *d);

/**
 * Free a digest and set @p *dp to NULL.  @p *dp may be NULL.
 */
extern void http_digest_free(struct http_digest **dp);

/**
 * Check content against the Content-Digest field in @p hdrs, which may
 * have come in a trailer section.
 *
 * Each supported algorithm in the field is checked.  A field that is
 * absent, malformed, or uses only unsupported algorithms passes.
 *
 * @param hdrs     the message's header (and trailer) fields
 * @param content  the content, with any transfer coding removed but its
 *                 content coding intact
 * @param errstr   set to a description of a mismatch
 * @return 0, or HTTP_BAD_REQUEST if a digest doesn't match
 */
extern int http_digest_verify(hdrcache_t hdrs, const struct buf *content,
                              const char **errstr);

/**
 * Check a representation against the Unencoded-Digest field in @p hdrs,
 * as http_digest_verify() does for Content-Digest.
 *
 * @param hdrs            the message's header (and trailer) fields
 * @param representation  the content with its content coding removed
 * @param errstr          set to a description of a mismatch
 * @return 0, or HTTP_BAD_REQUEST if a digest doesn't match
 */
extern int http_digest_verify_unencoded(hdrcache_t hdrs,
                                        const struct buf *representation,
                                        const char **errstr);

#endif /* HTTP_DIGEST_H */
