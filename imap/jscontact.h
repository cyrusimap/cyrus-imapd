/* jscontact.h -- Routines for converting JSContact and vCard */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef JSCONTACT_H
#define JSCONTACT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include <libical/vcard.h>

#include "jmap_util.h"
#include "mailbox.h"
#include "util.h"

#define JSCONTACT_MAJOR_VERSION 1 /**< The current JSContact major version. */
#define JSCONTACT_MINOR_VERSION 0 /**< The current JSContact minor version. */

/** @brief Read the contents of a blob.
 *
 *  @param rock       Callback data, as set in jscontact_ctx_t.
 *  @param accountid  Account to read the blob from, or NULL for the
 *                    account of the current request.
 *  @param blobid     Blob identifier, as provided by the client.
 *  @param mediatype  Media type the value is wanted as, or NULL for any.
 *  @param data       Set to the blob contents on success.
 *  @param type       Set to the media type of the blob on success.
 *  @return           Zero on success, HTTP_NOT_ACCEPTABLE if the blob is
 *                    not available as the wanted media type, or another
 *                    HTTP error code. */
typedef int (*jscontact_getblob_cb)(void *rock,
                                    const char *accountid,
                                    const char *blobid,
                                    const char *mediatype,
                                    struct buf *data,
                                    struct buf *type);

/** @brief Add a blob for the contents that a vCard property embeds.
 *
 *  Called for each JSContact object that converts to a vCard property
 *  holding its contents inline, as a data: URI. This does not change the
 *  conversion, which writes that property either way.
 *
 *  @param rock       Callback data, as set in jscontact_ctx_t.
 *  @param id         Identifier of the JSContact object holding the value.
 *  @param propname   Name of the vCard property the value converts to.
 *  @param mediatype  Media type of the contents, or NULL if unknown.
 *  @param data       The contents, decoded. */
typedef void (*jscontact_addblob_cb)(void *rock,
                                     const char *id,
                                     const char *propname,
                                     const char *mediatype,
                                     const struct buf *data);

/** @brief Context for JSContact/vCard conversion */
typedef struct {
    /* vCard to JSContact */

    /** The record holding the vCard. If both are set, the values embedded
        in the vCard convert to blob ids rather than to data: URIs. */
    struct mailbox *mailbox;
    struct index_record *record;

    /** Skip properties marked as derived. */
    bool ignore_derived_props;

    /** Emit vCardName, vCardParams and vCardProps for lossless round-trip. */
    bool set_vcard_convprops;

    /* JSContact to vCard */

    /** UID of the vCard to create, or NULL to read it from the Card. */
    const char *uid;

    /** The UID property to set in the vCard, or NULL to create it from
        the uid. The conversion clones it. */
    vcardproperty *uid_prop;

    /* TODO Resolving blobs is JMAP, not conversion. These callbacks keep
     * jmap_req and jmap_getblob() out of this interface, but the blob
     * handling should move out of the conversion entirely. */
    jscontact_getblob_cb getblob;
    jscontact_addblob_cb addblob;
    void *blob_rock;

    /* Conversion results */

    /** Version of the vCard as converted by jscontact_from_vcard(),
        or VCARD_VERSION_NONE if it had none. */
    vcardproperty_version version;

    /** Last error a getblob callback returned, or zero if none did. */
    int blob_error;
} jscontact_ctx_t;

/** @brief Convert a JSContact Card to a vCard.
 *
 *  @param ctx     Conversion context, or NULL for defaults.
 *  @param jcard   JSON object representing a JSContact Card.
 *  @param parser  JMAP parser used to report property errors.
 *  @return        A newly allocated vCard component, or NULL on error. */
vcardcomponent *jscontact_to_vcard(jscontact_ctx_t *ctx,
                                   json_t *jcard,
                                   struct jmap_parser *parser);

/** @brief Convert a vCard to a JSContact Card.
 *
 *  @param ctx    Conversion context, or NULL for defaults.
 *  @param vcard  A vCard component.
 *  @return       A newly allocated JSON object representing a JSContact Card,
 *                or NULL on error. */
json_t *jscontact_from_vcard(jscontact_ctx_t *ctx, vcardcomponent *vcard);

#ifdef __cplusplus
}
#endif

#endif
