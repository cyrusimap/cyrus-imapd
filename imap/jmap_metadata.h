/* jmap_metadata.h -- JMAP Object Metadata (draft-ietf-jmap-metadata) */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/**
 * @file
 * Support for the metadata and privateMetadata properties that
 * draft-ietf-jmap-metadata adds to JMAP data types.
 *
 * Both values are stored in the annotation entry
 * `/vendor/cmu/cyrus-jmap/metadata` of the object they belong to: a
 * mailbox annotation for Mailbox, Calendar and AddressBook, and a message
 * annotation on each index record for Email, CalendarEvent, ContactCard and
 * SieveScript.  Shared metadata is the shared value; a user's
 * privateMetadata is that user's private value.  Annotation storage counts
 * against the ANNOTATION-STORAGE quota of the object's mailbox.
 *
 * The shared value also records the modseqs needed to tell metadata-only
 * changes apart in Foo/changes.  A private write advances the related
 * type's state for every user, but is reported in Foo/changes only to the
 * user who made it.
 */

#ifndef JMAP_METADATA_H
#define JMAP_METADATA_H

#include <stdbool.h>

#include "jmap_api.h"
#include "mailbox.h"
#include "mboxlist.h"

/** Maximum depth of a namespace value, advertised as maxDepth. */
#define JMAP_METADATA_MAXDEPTH 8

/**
 * Register the metadata capability with the JMAP server.
 */
extern void jmap_metadata_init(jmap_settings_t *settings);

/**
 * Add the metadata account capability, listing every data type whose own
 * capability is already in @p account_capabilities.  Call this after all
 * other capabilities have been added.
 */
extern void jmap_metadata_capabilities(json_t *account_capabilities);

/**
 * Return the data type of the method in @p req if that type carries
 * metadata, else NULL.  "Email/get" yields "Email".
 */
extern const char *jmap_metadata_datatype(jmap_req_t *req);

/**
 * Return whether @p ns is a well-formed namespace identifier: a registered
 * name (lowercase letters, digits, '-' and '_') or a lowercase domain name
 * in A-label form.
 */
extern bool jmap_metadata_valid_namespace(const char *ns);

/** The stored metadata of one object, as seen by one user. */
struct jmap_metadata
{
    json_t *shared;             /**< metadata, never NULL after a lookup */
    json_t *private;            /**< the user's privateMetadata, never NULL */
    modseq_t shared_modseq;     /**< modseq of the last metadata write */
    modseq_t private_modseq;    /**< modseq of the user's last private write */
    modseq_t chain_modseq;      /**< modseq of the last write of either kind */
    modseq_t base_modseq;       /**< object modseq before that run of writes */
    modseq_t items_base_modseq; /**< for a mailbox, its highestmodseq
                                     before that run of writes */
};

#define JMAP_METADATA_INITIALIZER { NULL, NULL, 0, 0, 0, 0, 0 }

extern void jmap_metadata_fini(struct jmap_metadata *md);

/**
 * Look up the metadata of a mailbox (@p uid 0) or of message @p uid in it,
 * with the privateMetadata of the authenticated user.  Pass @p mailbox if
 * it is open, so that changes in the current transaction are seen;
 * otherwise @p mbentry.
 */
extern int jmap_metadata_lookup(jmap_req_t *req,
                                const struct mailbox *mailbox,
                                const mbentry_t *mbentry,
                                uint32_t uid,
                                struct jmap_metadata *md);

/**
 * Add one stored annotation value, written by @p userid ("" for shared),
 * to @p md as seen by @p viewer.  For callers that scan annotations
 * themselves.
 */
extern void jmap_metadata_load(struct jmap_metadata *md,
                               const char *viewer,
                               const char *userid,
                               const struct buf *value);

/** As jmap_metadata_lookup(), with the privateMetadata of @p userid. */
extern int jmap_metadata_lookup_userid(const char *userid,
                                       const struct mailbox *mailbox,
                                       const mbentry_t *mbentry,
                                       uint32_t uid,
                                       struct jmap_metadata *md);

/**
 * Store new metadata and/or privateMetadata on a mailbox (@p uid 0) or
 * on message @p uid.  The mailbox must be locked for writing.  A NULL
 * value is left unchanged.  The write advances the object's modseq: the
 * record is rewritten, or the mailbox's foldermodseq bumped.
 *
 * Set @p content_changed if other properties of the object change in the
 * same mailbox transaction, so the change is not reported as
 * metadata-only.
 *
 * Returns IMAP_QUOTA_EXCEEDED if the annotation quota would be exceeded.
 * On failure the mailbox's uncommitted changes are aborted.
 */
extern int jmap_metadata_write(jmap_req_t *req,
                               struct mailbox *mailbox,
                               uint32_t uid,
                               const json_t *shared,
                               const json_t *private,
                               bool content_changed);

/**
 * Check that writing @p shared and @p private (either may be NULL) over the
 * values in @p cur (NULL for a new object) fits the annotation quota of
 * mailbox @p mboxname.  For callers that must check before committing the
 * object the metadata belongs to.  Returns IMAP_QUOTA_EXCEEDED if not.
 */
extern int jmap_metadata_check_quota(const char *mboxname,
                                     const json_t *shared,
                                     const json_t *private,
                                     const struct jmap_metadata *cur);

/**
 * Copy the metadata and the authenticated user's privateMetadata of
 * message @p uid in @p src to message @p dstuid in @p dst, which must be
 * locked for writing.  Values in @p override replace the copied ones.
 */
extern int jmap_metadata_copy(jmap_req_t *req,
                              const struct mailbox *src,
                              uint32_t uid,
                              struct mailbox *dst,
                              uint32_t dstuid,
                              const json_t *override_shared,
                              const json_t *override_private);

/* Foo/get */

/**
 * Return whether @p props asks for metadata or privateMetadata, in full
 * or by namespace.
 */
extern bool jmap_metadata_wanted(hash_table *props);

/**
 * Add the requested metadata and privateMetadata of @p md to @p obj.
 */
extern void jmap_metadata_get(hash_table *props,
                              json_t *obj,
                              const struct jmap_metadata *md);

/* Foo/set */

/** The metadata part of one create or update. */
struct jmap_metadata_set
{
    json_t *shared;        /**< complete metadata value, or NULL */
    json_t *shared_patch;  /**< "ns/key/..." -> value, or NULL */
    json_t *private;       /**< complete privateMetadata, or NULL */
    json_t *private_patch; /**< "ns/key/..." -> value, or NULL */
};

#define JMAP_METADATA_SET_INITIALIZER { NULL, NULL, NULL, NULL }

extern void jmap_metadata_set_fini(struct jmap_metadata_set *ms);

/**
 * Move the metadata and privateMetadata members out of the create or
 * update @p jobj into @p ms, and check what the request alone determines.
 * Return a SetError, or NULL.
 */
extern json_t *jmap_metadata_set_parse(jmap_req_t *req,
                                       json_t *jobj,
                                       bool is_create,
                                       struct jmap_metadata_set *ms);

/** Return whether @p ms changes anything. */
extern bool jmap_metadata_set_isempty(const struct jmap_metadata_set *ms);

/** Return whether @p ms writes shared metadata. */
extern bool jmap_metadata_set_isshared(const struct jmap_metadata_set *ms);

/**
 * Validate @p ms against the current values in @p cur and compute the new
 * ones.  @p may_write says whether the user may write shared metadata on
 * the object.  On success return NULL and set @p new_shared and
 * @p new_private to the new values, or to NULL where unchanged; otherwise
 * return a SetError.
 */
extern json_t *jmap_metadata_set_apply(jmap_req_t *req,
                                       const struct jmap_metadata_set *ms,
                                       bool may_write,
                                       const struct jmap_metadata *cur,
                                       json_t **new_shared,
                                       json_t **new_private);

/** Map an error from jmap_metadata_write() to a SetError. */
extern json_t *jmap_metadata_set_error(int r);

/* Foo/changes */

enum {
    JMAP_METADATA_CHANGED_SHARED = (1 << 0),
    JMAP_METADATA_CHANGED_PRIVATE = (1 << 1),
    JMAP_METADATA_CHANGED_OTHER = (1 << 2),
};

/**
 * Classify what changed on an object since @p since, from the viewpoint
 * of the authenticated user.  @p objmodseq is the object's current
 * modseq: the record modseq, or the mailbox's foldermodseq.  Returns a
 * mask of JMAP_METADATA_CHANGED_* bits; 0 means the only change is
 * another user's privateMetadata.
 */
extern unsigned jmap_metadata_changed(const struct jmap_metadata *md,
                                      modseq_t objmodseq,
                                      modseq_t since);

/**
 * Look up and classify a mailbox (@p uid 0) or a message, as
 * jmap_metadata_changed().  An object without metadata reports
 * JMAP_METADATA_CHANGED_OTHER.
 */
extern unsigned jmap_metadata_changed_lookup(jmap_req_t *req,
                                             const mbentry_t *mbentry,
                                             uint32_t uid,
                                             modseq_t objmodseq,
                                             modseq_t since);

/* Foo/query */

/** Return whether @p field is one of the metadata FilterCondition fields. */
extern bool jmap_metadata_is_filter(const char *field);

/**
 * Validate the metadata fields of FilterCondition @p filter, reporting
 * malformed ones, or any if the request doesn't use the metadata
 * capability, to @p parser.
 */
extern void jmap_metadata_filter_validate(jmap_req_t *req,
                                          struct jmap_parser *parser,
                                          json_t *filter);

/** Return whether @p filter or any condition below it uses metadata. */
extern bool jmap_metadata_filter_uses(const json_t *filter);

/**
 * Return whether @p md satisfies every metadata field of FilterCondition
 * @p cond.  Other fields are ignored.
 */
extern bool jmap_metadata_filter_match(const json_t *cond,
                                       const struct jmap_metadata *md);

#endif /* JMAP_METADATA_H */
