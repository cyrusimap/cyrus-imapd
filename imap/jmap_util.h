/* jmap_util.h -- Helper routines for JMAP
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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
 */

#ifndef JMAP_UTIL_H
#define JMAP_UTIL_H

#include <jansson.h>

#include "hash.h"
#include "ical_support.h"
#include "message.h"
#include "mboxlist.h"
#include "parseaddr.h"
#include "smtpclient.h"

#define JMAP_SUBMISSION_HDR "Content-Description"

#define jmap_wantprop(props, name) \
    ((props) ? (hash_lookup(name, props) != NULL) : 1)

#define jmap_readprop(root, name,  mandatory, invalid, fmt, dst) \
    jmap_readprop_full((root), NULL, (name), (mandatory), (invalid), (fmt), (dst))

extern int jmap_readprop_full(json_t *root, const char *prefix, const char *name,
                              int mandatory, json_t *invalid, const char *fmt,
                              void *dst);

#define PATCH_NO_REMOVE   (1<<0) // only relevant for create
#define PATCH_ALLOW_ARRAY (1<<1)

/* Apply patch to a deep copy of val and return the result.
 * Return NULL on error. If invalid is a JSON array, then
 * the erroneous path in patch is appended as JSON string */
extern json_t* jmap_patchobject_apply(json_t *val, json_t *patch,
                                      json_t *invalid, unsigned flags);

/* Create a patch-object that transforms src into dst. */
extern json_t *jmap_patchobject_create(json_t *src, json_t *dst, unsigned flags);

/* Return non-zero src and its RFC 6901 encoding differ */
extern int jmap_pointer_needsencode(const char *src);

/* Encode src according to RFC 6901 */
extern char *jmap_pointer_encode(const char *src);

/* Decode src according to RFC 6901 */
extern char *jmap_pointer_decode(const char *src, size_t len);

/* Remove all properties in jobj that have no key in props */
extern void jmap_filterprops(json_t *jobj, hash_table *props);

extern void jmap_emailsubmission_envelope_to_smtp(smtp_envelope_t *smtpenv,
                                                  json_t *env);

extern json_t *jmap_fetch_snoozed(const char *mbox, uint32_t uid);

extern int jmap_email_keyword_is_valid(const char *keyword);
extern const char *jmap_keyword_to_imap(const char *keyword);

extern char *jmap_role_to_specialuse(const char *role);

/* JMAP request parser */
struct jmap_parser {
    struct buf buf;
    strarray_t path;
    json_t *invalid;
    json_t *serverset;
};

#define JMAP_PARSER_INITIALIZER { \
    BUF_INITIALIZER, \
    STRARRAY_INITIALIZER, \
    json_array(), \
    json_object() \
}

extern void jmap_parser_fini(struct jmap_parser *parser);
extern void jmap_parser_push(struct jmap_parser *parser, const char *prop);
extern void jmap_parser_push_index(struct jmap_parser *parser,
                                   const char *prop, size_t index, const char *name);
extern void jmap_parser_pop(struct jmap_parser *parser);
extern const char* jmap_parser_path(struct jmap_parser *parser, struct buf *buf);
extern void jmap_parser_invalid(struct jmap_parser *parser, const char *prop);
HIDDEN void jmap_parser_invalid_path(struct jmap_parser *parser, const char *path);
extern void jmap_parser_serverset(struct jmap_parser *parser, const char *prop, json_t *val);

extern json_t *jmap_server_error(int r);

extern char *jmap_encode_base64_nopad(const char *data, size_t len);
extern char *jmap_decode_base64_nopad(const char *b64, size_t b64len);

/* Decode the text in data of datalen bytes to UTF-8.
 *
 * Attempts to detect the right character encoding if conversion to
 * UTF-8 yields any invalid or replacement characters.
 * UTF-8 input with replacement characters is considered valid input.
 *
 * Parameters:
 * - charset indicates the presumed character encoding.
 * - encoding must be one of the encodings defined in charset.h
 * - data points to the encoded bytes
 * - datalen indicates the byte length of data
 * - confidence indicates the threshold for charset detection (0 to 1.0)
 * - dst points to a buffer for the decoded output. This buffer is reset
 * - (optional) is_encoding_problem is set for invalid byte sequences
 *
 */
extern void jmap_decode_to_utf8(const char *charset, int encoding,
                                const char *data, size_t datalen,
                                float confidence,
                                struct buf *dst,
                                int *is_encoding_problem);

extern const char *jmap_encode_rawdata_blobid(const char prefix,
                                              const char *mboxid,
                                              uint32_t uid,
                                              const char *partid,
                                              const char *userid,
                                              const char *subpart,
                                              const struct message_guid *guid,
                                              struct buf *dst);
extern int jmap_decode_rawdata_blobid(const char *blobid,
                                      char **mboxidptr,
                                      uint32_t *uidptr,
                                      char **partidptr,
                                      char **useridptr,
                                      char **subpartptr,
                                      struct message_guid *guid);

enum header_form {
    HEADER_FORM_UNKNOWN          = 0, /* MUST be zero so we can cast to void* */
    HEADER_FORM_RAW              = 1 << 0,
    HEADER_FORM_TEXT             = 1 << 1,
    HEADER_FORM_DATE             = 1 << 2,
    HEADER_FORM_URLS             = 1 << 3,
    HEADER_FORM_MESSAGEIDS       = 1 << 4,
    HEADER_FORM_ADDRESSES        = 1 << 5,
    HEADER_FORM_GROUPEDADDRESSES = 1 << 6
};

extern json_t *jmap_header_as_raw(const char *raw);
extern json_t *jmap_header_as_text(const char *raw);
extern json_t *jmap_header_as_date(const char *raw);
extern json_t *jmap_header_as_urls(const char *raw);
extern json_t *jmap_header_as_messageids(const char *raw);
extern json_t *jmap_header_as_addresses(const char *raw);
extern json_t *jmap_header_as_groupedaddresses(const char *raw);
extern json_t *jmap_emailaddresses_from_addr(struct address *addr,
                                             enum header_form form);

extern int jmap_is_valid_id(const char *id);

#define JMAP_BLOBID_SIZE 42
extern void jmap_set_blobid(const struct message_guid *guid, char *buf);

#define JMAP_LEGACY_EMAILID_PREFIX 'M'
#define JMAP_LEGACY_EMAILID_SIZE 26  // 24 chars of encoded GUID + prefix and NUL

#define JMAP_EMAILID_PREFIX 'S'
#define JMAP_EMAILID_SIZE (CONV_JMAPID_SIZE + 2)  // +2 for prefix and NUL

#define JMAP_MAX_EMAILID_SIZE MAX(JMAP_EMAILID_SIZE, JMAP_LEGACY_EMAILID_SIZE)

extern void jmap_set_emailid(struct conversations_state *cstate,
                             const struct message_guid *guid,
                             uint64_t nanosec, struct timespec *ts,
                             char *emailid);

#define JMAP_MAILBOXID_PREFIX 'P'
#define JMAP_MAILBOXID_SIZE (CONV_JMAPID_SIZE + 2)  // +2 for prefix and NUL

#define JMAP_MAX_MAILBOXID_SIZE MAX(JMAP_MAILBOXID_SIZE, UUID_STR_LEN)

extern void jmap_set_mailboxid(struct conversations_state *cstate,
                               const mbentry_t *mbentry, char *mboxid);

#define JMAP_LEGACY_THREADID_PREFIX 'T'
#define JMAP_THREADID_PREFIX 'A'
#define JMAP_THREADID_SIZE 18
extern void jmap_set_threadid(struct conversations_state *cstate,
                              conversation_id_t cid, char *thrid);

#ifdef HAVE_ICAL
struct jmap_caleventid {
    const char *raw; /* as requested by client */
    const char *ical_uid;
    const char *ical_recurid;
    char *_alloced[2];
};

extern struct jmap_caleventid *jmap_caleventid_decode(const char *id) __attribute__((nonnull, returns_nonnull, warn_unused_result));

extern const char *jmap_caleventid_encode(const struct jmap_caleventid *eid, struct buf *buf);

extern void jmap_caleventid_free(struct jmap_caleventid **eidptr);

extern void jmap_alertid_encode(icalcomponent *valarm, struct buf *buf);
#endif /* HAVE_ICAL */

#endif /* JMAP_UTIL_H */
