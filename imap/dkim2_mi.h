/* dkim2_mi.h - DKIM2 Message-Instance calculation */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef DKIM2_MI_H
#define DKIM2_MI_H

#include <stdbool.h>

#include "util.h"

/**
 * @file dkim2_mi.h
 *
 * DKIM2 Message-Instance calculation.
 *
 * Cyrus documents its own modifications but never signs: everything here
 * produces a Message-Instance header field for some other hop to sign.
 * Section numbers cited throughout are draft-ietf-dkim-dkim2-spec-06.
 */

/** Outcome of dkim2_mi_calculate() */
enum dkim2_mi_result {
    DKIM2_MI_NONE = 0,        /**< no Message-Instance is needed */
    DKIM2_MI_ADDED,           /**< mi_out holds the new header field value */
    DKIM2_MI_CHAIN_MISMATCH,  /**< incoming message doesn't match its own MI */
};

/**
 * Build a Message-Instance value documenting the change from @a before_hdrs
 * to @a after_hdrs, with hashes over @a after_hdrs and @a body.  The body is
 * hashed but never diffed: a caller that alters the body must not use this.
 *
 * @param before_hdrs header block as it arrived
 * @param beforelen length of @a before_hdrs
 * @param after_hdrs header block as it stands now
 * @param afterlen length of @a after_hdrs
 * @param body message body, unchanged between the two blocks
 * @param bodylen length of @a body
 * @param verify hash @a before_hdrs too and check it against the
 *        highest-numbered Message-Instance already on the message, so that
 *        an earlier hop's undeclared change isn't attributed to this one
 * @param[out] mi_out the header field value, set only on DKIM2_MI_ADDED
 * @return what was decided; DKIM2_MI_CHAIN_MISMATCH means @a verify failed
 */
extern enum dkim2_mi_result dkim2_mi_calculate(const char *before_hdrs,
                                               size_t beforelen,
                                               const char *after_hdrs,
                                               size_t afterlen,
                                               const char *body,
                                               size_t bodylen,
                                               bool verify,
                                               struct buf *mi_out);

/**
 * §6.1 body hash: base64 of the sha256.
 *
 * @param body message body
 * @param bodylen length of @a body
 * @param[out] b64 the encoded hash
 */
extern void dkim2_body_hash(const char *body, size_t bodylen, struct buf *b64);

/**
 * §6.2 header fields hash: base64 of the sha256.
 *
 * @param hdrs header block, canonicalised and ordered internally
 * @param len length of @a hdrs
 * @param[out] b64 the encoded hash
 */
extern void dkim2_header_hash(const char *hdrs, size_t len, struct buf *b64);

/**
 * §5.1 Recipes to turn @a after_hdrs back into @a before_hdrs.  Any
 * difference that exists can always be expressed, since a "d" step can emit
 * any value in any order.
 *
 * @param before_hdrs header block to be reconstructed
 * @param beforelen length of @a before_hdrs
 * @param after_hdrs header block to reconstruct it from
 * @param afterlen length of @a after_hdrs
 * @return a JSON string the caller frees, or NULL if no signed header field
 *         differs
 */
extern char *dkim2_gen_recipes(const char *before_hdrs, size_t beforelen,
                               const char *after_hdrs, size_t afterlen);

#endif /* DKIM2_MI_H */
