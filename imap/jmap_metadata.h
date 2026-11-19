/* jmap_metadata.h -- JMAP Object Metadata (draft-ietf-jmap-metadata) */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/**
 * @file
 * Support for the metadata and privateMetadata properties that
 * draft-ietf-jmap-metadata adds to JMAP data types.
 *
 * Each namespace is stored as the annotation entry
 * `/vendor/cmu/cyrus-imapd/jmapmetadata/<namespace>` of the object it
 * belongs to, its value the namespace's JSON: a mailbox annotation for
 * Mailbox, Calendar and AddressBook, and a message annotation on each
 * index record for Email, CalendarEvent, ContactCard and SieveScript.
 * metadata is the shared value of these entries, and a user's
 * privateMetadata that user's private value, as for IMAP METADATA.
 * Annotation storage counts against the ANNOTATION-STORAGE quota of the
 * object's mailbox.
 *
 * A write advances the object's modseq, so every user with access to it
 * sees the object as updated in Foo/changes.  Metadata-only changes are
 * not tracked: updatedProperties is null, and ignoreMetadataOnlyChanges
 * leaves nothing out.
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
    json_t *shared;  /**< metadata, never NULL after a lookup */
    json_t *private; /**< the user's privateMetadata, never NULL */
};

#define JMAP_METADATA_INITIALIZER { NULL, NULL }

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
 * Add the annotation @p entry, with the value written by @p userid (""
 * for shared), to @p md as seen by @p viewer.  Other entries are ignored.
 * For callers that scan annotations themselves.
 */
extern void jmap_metadata_load(struct jmap_metadata *md,
                               const char *viewer,
                               const char *entry,
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
 * value is left unchanged.  Only namespaces that differ from the stored
 * ones are written.  The write advances the object's modseq: the record
 * is rewritten, or the mailbox's foldermodseq bumped.
 *
 * Returns IMAP_QUOTA_EXCEEDED, having changed nothing, if the annotation
 * quota would be exceeded.  Any other failure may leave a partial write
 * in the mailbox's transaction, for the caller to abort.
 */
extern int jmap_metadata_write(jmap_req_t *req,
                               struct mailbox *mailbox,
                               uint32_t uid,
                               const json_t *shared,
                               const json_t *private);

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
 * Remove the metadata and privateMetadata members, whole or patched, from
 * @p obj, and return them in a new object.  A copy uses this to keep them
 * out of the patch it applies to the source object.
 */
extern json_t *jmap_metadata_take_props(json_t *obj);

/**
 * For a copy, fill in the new values @p shared and @p private (see
 * jmap_metadata_set_apply()) that the create left NULL with those
 * @p copied from the source object, privateMetadata only if the request
 * uses the capability.  Copied values are not revalidated.  @p copied
 * may be NULL.
 */
extern void jmap_metadata_add_copied(jmap_req_t *req,
                                     const struct jmap_metadata *copied,
                                     json_t **shared,
                                     json_t **private);

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
extern json_t *jmap_metadata_set_apply(const struct jmap_metadata_set *ms,
                                       bool may_write,
                                       const struct jmap_metadata *cur,
                                       json_t **new_shared,
                                       json_t **new_private);

/** Map an error from jmap_metadata_write() to a SetError. */
extern json_t *jmap_metadata_set_error(int r);

/* Rights */

/**
 * Check that the rights set in @p shareWith for each sharee that names
 * maySetMetadata can be stored: patching the sharee's rights on
 * @p mbentry (none if NULL or @p overwrite) with @p patchrights must give
 * rights that @p tojmap reads back as requested, with no other right
 * changed.  Return the first sharee whose rights can't be, else NULL.
 */
extern const char *jmap_metadata_sharewith_conflict(
    const mbentry_t *mbentry,
    json_t *shareWith,
    bool overwrite,
    int (*patchrights)(int, json_t *),
    json_t *(*tojmap)(int) );

/**
 * As jmap_metadata_sharewith_conflict(), reporting a conflict as invalid
 * property shareWith/<sharee>/maySetMetadata to @p parser.
 */
extern void jmap_metadata_sharewith_validate(struct jmap_parser *parser,
                                             const mbentry_t *mbentry,
                                             json_t *shareWith,
                                             bool overwrite,
                                             int (*patchrights)(int, json_t *),
                                             json_t *(*tojmap)(int) );

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
 * As jmap_metadata_lookup_userid(), but load only the namespaces that the
 * metadata fields of FilterCondition @p cond name, which is all that
 * jmap_metadata_filter_match() needs.
 */
extern int jmap_metadata_lookup_filter(const char *userid,
                                       const struct mailbox *mailbox,
                                       const mbentry_t *mbentry,
                                       uint32_t uid,
                                       const json_t *cond,
                                       struct jmap_metadata *md);

/**
 * Return whether @p md satisfies every metadata field of FilterCondition
 * @p cond.  Other fields are ignored.
 */
extern bool jmap_metadata_filter_match(const json_t *cond,
                                       const struct jmap_metadata *md);

#endif /* JMAP_METADATA_H */
